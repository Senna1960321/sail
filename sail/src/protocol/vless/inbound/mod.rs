use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{InboundContext, InboundFactory, InboundRegistry, Options};
use crate::adapter::AnyInboundHandler;
use crate::transport::layers::{Blocks, InboundBlocks};
use serde_derive::Deserialize;

use super::request::{Flow, FLOW_VISION};

// Fallback as the Trojan inbound has it, which sing-box's VLESS lacks: the
// same fields, the same code.
mod stream;

use crate::protocol::fallback::{self, FallbackServer};

pub use stream::{Handler as StreamHandler, User};

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register(
        "vless",
        InboundFactory::standalone(build)
            .with_blocks(Blocks {
                tls: true,
                transport: true,
                multiplex: true,
                ..Blocks::NONE
            })
            .checked_by(check),
    );
}

/// Vision reads the TLS records of the connection it runs on, and may
/// switch to copying the raw TLS stream: a Vision user needs TLS (or
/// REALITY) directly under VLESS, with no transport between.
fn check(tag: &str, options: &Options, blocks: &InboundBlocks) -> Result<()> {
    let vision = options
        .get("users")
        .and_then(|u| u.as_array())
        .into_iter()
        .flatten()
        .position(|u| u.get("flow").and_then(|f| f.as_str()) == Some(FLOW_VISION));
    match vision {
        Some(i) if !blocks.has_tls() || blocks.transport.is_some() => Err(anyhow!(
            "[{}] inbound: users[{}].flow: {} needs tls directly under vless, with no transport",
            tag,
            i,
            FLOW_VISION
        )),
        _ => Ok(()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessInboundOptions {
    users: Vec<VlessUser>,
    /// Where a connection that fails to authenticate is relayed.
    #[serde(default)]
    fallback: Option<FallbackServer>,
    /// The same, by the ALPN the connection's TLS negotiated; the ones it
    /// does not name go to `fallback`.
    #[serde(default)]
    fallback_for_alpn: HashMap<String, FallbackServer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    uuid: String,
    /// `""` or `xtls-rprx-vision`.
    #[serde(default)]
    flow: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let options: VlessInboundOptions = ctx.options()?;
    // An empty table intentionally revokes every user for new sessions.
    let mut users = HashMap::new();
    for (i, user) in options.users.into_iter().enumerate() {
        let uuid = *uuid::Uuid::parse_str(&user.uuid)
            .map_err(|e| anyhow!("[{}] inbound: users[{}].uuid: {}", ctx.tag, i, e))?
            .as_bytes();
        let flow = Flow::parse(&user.flow)
            .map_err(|e| anyhow!("[{}] inbound: users[{}].flow: {}", ctx.tag, i, e))?;
        let user = User {
            name: match &ctx.env.admission {
                Some(admission) => admission.bind_credential(
                    &ctx.env.users,
                    "vless",
                    ctx.tag,
                    user.name.as_deref(),
                    &user.uuid,
                )?,
                None => ctx.env.users.bind_named(user.name.as_deref()),
            },
            flow,
        };
        if users.insert(uuid, user).is_some() {
            return Err(anyhow!(
                "[{}] inbound: users[{}].uuid: used by another user",
                ctx.tag,
                i
            ));
        }
    }
    let fallback = fallback::Fallback::new(
        ctx.tag,
        options.fallback,
        options.fallback_for_alpn,
        ctx.dial.default_dialer(),
        ctx.env.options.relay.clone(),
    )?;
    if fallback.is_none() {
        crate::protocol::fallback::note_without(ctx.tag, "vless", ctx.env);
    }
    let stream = Arc::new(StreamHandler::new(users, fallback));
    Ok(Arc::new(Handler::new(
        ctx.tag.to_owned(),
        Some(stream),
        None,
    )))
}

#[cfg(test)]
mod check_tests {
    use super::*;

    fn check_json(users: serde_json::Value, blocks: serde_json::Value) -> Result<()> {
        let options: Options =
            serde_json::from_value(serde_json::json!({ "users": users })).unwrap();
        let blocks = InboundBlocks::parse("v", &serde_json::from_value(blocks).unwrap()).unwrap();
        check("v", &options, &blocks)
    }

    #[test]
    fn a_vision_user_needs_tls_directly_under_it() {
        let users = serde_json::json!([
            { "uuid": "a", "flow": "" },
            { "uuid": "b", "flow": FLOW_VISION },
        ]);
        let tls = serde_json::json!({ "enabled": true });
        assert!(check_json(users.clone(), serde_json::json!({ "tls": tls })).is_ok());
        let err = check_json(
            users.clone(),
            serde_json::json!({ "tls": tls, "transport": { "type": "ws" } }),
        )
        .unwrap_err();
        assert!(err.to_string().contains("users[1].flow"), "{}", err);
        assert!(check_json(users, serde_json::json!({})).is_err());
    }
}
