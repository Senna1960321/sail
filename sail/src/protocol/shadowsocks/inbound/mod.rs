use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::Blocks;
use serde_derive::Deserialize;

mod datagram;
mod ss2022;
mod stream;

use crate::runtime::resource::HotResource;
pub use datagram::Handler as DatagramHandler;
pub(crate) use datagram::Sessions;
pub(crate) use ss2022::Resources;

pub(crate) struct LegacyResources {
    cipher: String,
    password: String,
    datagram: shadow::ShadowedDatagram,
}
pub use stream::Handler as StreamHandler;

use super::shadow;
use super::sip022;

pub(crate) fn register(registry: &mut InboundRegistry) {
    // `multiplex`, to serve sing-mux as sing-box's does when it is enabled.
    registry.register(
        "shadowsocks",
        InboundFactory::standalone(build).with_blocks(Blocks {
            multiplex: true,
            ..Blocks::NONE
        }),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowsocksInboundOptions {
    method: String,
    /// The PSK with a 2022 method; with `users`, the server's identity PSK.
    password: String,
    /// Shadowsocks 2022 users, told apart by identity headers.
    #[serde(default)]
    users: Option<Vec<ShadowsocksUser>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowsocksUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    /// The user's base64 PSK.
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: ShadowsocksInboundOptions = ctx.options()?;
    if sip022::is_2022(&options.method) {
        return build_2022(ctx, options);
    }
    shadow::check_method("inbound", ctx.tag, &options.method)?;
    if options.users.is_some() {
        return Err(anyhow!(
            "[{}] inbound: users: only the 2022 methods have users",
            ctx.tag
        ));
    }
    let candidate = Arc::new(LegacyResources {
        datagram: shadow::ShadowedDatagram::new(&options.method, &options.password)?,
        cipher: options.method,
        password: options.password,
    });
    let resource = ctx.resource(&ctx.state.shadowsocks_legacy, candidate);
    let stream = Arc::new(stream::ReloadableStream(resource.clone()));
    let datagram = Arc::new(DatagramHandler {
        resource,
        sessions: ctx
            .state
            .shadowsocks_sessions
            .get_or_init(Default::default)
            .clone(),
    });
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        Some(datagram),
    )))
}

fn build_2022(
    ctx: &InboundContext<'_>,
    options: ShadowsocksInboundOptions,
) -> Result<AnyInboundHandler> {
    let tag = ctx.tag;
    let method = sip022::Method::from_name(&options.method)
        .map_err(|e| anyhow!("[{}] inbound: method: {}", tag, e))?;
    let psk = sip022::decode_psk(method, &options.password)
        .map_err(|e| anyhow!("[{}] inbound: password: {}", tag, e))?;
    let users = match options.users {
        None => None,
        Some(users) => {
            if !method.supports_eih() {
                return Err(anyhow!(
                    "[{}] inbound: users: {} has no identity headers, users need an AES method",
                    tag,
                    options.method
                ));
            }
            let users = users
                .into_iter()
                .enumerate()
                .map(|(i, u)| {
                    let psk = sip022::decode_psk(method, &u.password)
                        .map_err(|e| anyhow!("[{}] inbound: users[{}]: password: {}", tag, i, e))?;
                    Ok(sip022::User {
                        name: match &ctx.env.admission {
                            Some(admission) => admission.bind_credential(
                                &ctx.env.users,
                                "shadowsocks",
                                ctx.tag,
                                u.name.as_deref(),
                                &u.password,
                            )?,
                            None => ctx.env.users.bind_named(u.name.as_deref()),
                        },
                        psk,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Some(
                sip022::Users::new(users)
                    .map_err(|e| anyhow!("[{}] inbound: users: {}", tag, e))?,
            )
        }
    };
    let previous = ctx.state.shadowsocks.get().map(|r| r.load());
    let udp = match &previous {
        Some(previous) => previous.server.with_users(users.clone()),
        None => sip022::udp::Server::new(method, psk.clone(), users.clone())?,
    };
    let resource = ctx.resource(
        &ctx.state.shadowsocks,
        Arc::new(Resources {
            config: sip022::stream::ServerConfig {
                method,
                psk,
                users,
                salts: previous.map(|r| r.config.salts.clone()).unwrap_or_default(),
            },
            server: udp,
        }),
    );
    let stream = Arc::new(ss2022::StreamHandler {
        resource: resource.clone(),
    });
    let datagram = Arc::new(ss2022::DatagramHandler { resource });
    Ok(Arc::new(Handler::new(
        tag.to_owned(),
        Some(stream),
        Some(datagram),
    )))
}

/// The most a client that fails to authenticate is read of before its
/// connection is closed.
pub(crate) const REFUSED_READ_LIMIT: u64 = 64 * 1024;

/// Ends a connection refused for `error`: it is read, and what comes
/// discarded, until the client closes it, `REFUSED_READ_LIMIT` bytes came,
/// or the inbound's handshake deadline, which bounds this as the rest of
/// the handshake. Closed at once, the connection would tell a prober that
/// varies how much it sends the length of the header it failed at, which
/// is how Shadowsocks servers are found (Frolov, Wampler and Wustrow, "How
/// China Detects and Blocks Shadowsocks", IMC 2020). Outline's ss-server
/// and Xray read on likewise; sing-box resets at once.
pub(crate) async fn refuse<S>(mut stream: S, error: std::io::Error) -> std::io::Error
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut limited = (&mut stream).take(REFUSED_READ_LIMIT);
    let _ = tokio::io::copy(&mut limited, &mut tokio::io::sink()).await;
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::registry::{build_inbounds, InboundState};
    use base64::Engine;
    use std::collections::HashMap;

    #[tokio::test]
    async fn prepared_users_preserve_tcp_replay_and_only_publish_on_commit() {
        let psk = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let user = base64::engine::general_purpose::STANDARD.encode([2u8; 16]);
        let config = |users: serde_json::Value| {
            serde_json::from_value(serde_json::json!({
                "type":"shadowsocks","tag":"ss","method":"2022-blake3-aes-128-gcm",
                "password":psk,"users":users
            }))
            .unwrap()
        };
        let users = serde_json::json!([{"name":"alice","password":user}]);
        let mut states: HashMap<String, Arc<InboundState>> = HashMap::new();
        let prepare = |inbound, states: &mut HashMap<_, _>| {
            build_inbounds(
                &crate::include::INBOUNDS,
                &[inbound],
                crate::include::LISTENER_INBOUNDS,
                &Default::default(),
                &Default::default(),
                &mut HashMap::new(),
                &mut HashMap::new(),
                states,
            )
            .unwrap()
        };
        drop(prepare(config(users.clone()), &mut states));
        let resource = states["ss"].shadowsocks.get().unwrap().clone();
        let first = resource.load();
        first.config.salts.check_and_insert(&[7; 16]).unwrap();
        let discarded = prepare(config(serde_json::json!([])), &mut states);
        assert!(Arc::ptr_eq(&first, &resource.load()));
        drop(discarded);
        assert!(Arc::ptr_eq(&first, &resource.load()));
        for update in prepare(config(serde_json::json!([])), &mut states) {
            update();
        }
        assert!(!Arc::ptr_eq(&first, &resource.load()));
        assert!(Arc::ptr_eq(
            &first.config.salts,
            &resource.load().config.salts
        ));
        for update in prepare(config(users), &mut states) {
            update();
        }
        assert!(resource
            .load()
            .config
            .salts
            .check_and_insert(&[7; 16])
            .is_err());
        assert!(first.config.salts.check_and_insert(&[7; 16]).is_err());
    }
}
