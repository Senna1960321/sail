//! The AnyTLS inbound.
//!
//! One TLS connection is one session, and every stream on it is a
//! connection of its own to route, so the handler hands back the session as
//! `InboundTransport::Incoming`, as `multiplex` does.
//!
//! A connection whose password is not a user's is relayed to `fallback`
//! (or the one of `fallback_for_alpn` for its ALPN), starting with the
//! bytes read of it, as `sing-anytls` does; without one it is closed. The
//! bytes read are the password's SHA-256 and no more: whether it is a
//! user's is known once it is in, before the padding that follows it.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_derive::Deserialize;
use sha2::{Digest, Sha256};

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{parse_options, InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::AnyInboundHandler;
use crate::protocol::fallback::{Fallback, FallbackServer};
use crate::transport::layers::{self, Blocks, InboundBlocks, Listable};

use super::padding::PaddingScheme;

mod stream;

pub use stream::Handler as StreamHandler;

/// The shared block the inbound applies itself, so that it can insist on
/// it: AnyTLS is meant to look like TLS.
const CONNECTION_BLOCKS: Blocks = Blocks {
    tls: true,
    ..Blocks::NONE
};

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("anytls", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnyTlsInboundOptions {
    users: Vec<AnyTlsUser>,
    /// The padding scheme, as lines. Unset, the default. A scheme that
    /// pads past write 1024, gives a write more than 64 sizes or asks for
    /// more than 1 MiB of padding in all is refused.
    #[serde(default)]
    padding_scheme: Option<Listable>,
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
struct AnyTlsUser {
    /// Who the user is to routing (`auth_user`), statistics and logs.
    #[serde(default)]
    name: Option<String>,
    password: String,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let tag = ctx.tag;
    let (protocol, blocks) = CONNECTION_BLOCKS.split(ctx.options);
    let blocks = InboundBlocks::parse(tag, &blocks)?;
    if !blocks.tls.as_ref().is_some_and(|t| t.enabled) {
        return Err(anyhow!("[{}] inbound: tls: anytls needs it enabled", tag));
    }
    let options: AnyTlsInboundOptions = parse_options("inbound", tag, &protocol)?;
    // An empty table intentionally revokes every user for new sessions.
    let padding = match options.padding_scheme {
        Some(scheme) => PaddingScheme::parse_strict(&scheme.joined())
            .map_err(|e| anyhow!("[{}] inbound: padding_scheme: {}", tag, e))?,
        None => PaddingScheme::default_scheme(),
    };
    let fallback = Fallback::new(
        tag,
        options.fallback,
        options.fallback_for_alpn,
        ctx.dial.default_dialer(),
        ctx.env.options.relay.clone(),
    )?;
    if fallback.is_none() {
        crate::protocol::fallback::note_without(tag, "anytls", ctx.env);
    }
    let mut users = HashMap::new();
    for user in options.users {
        let hash: [u8; 32] = Sha256::digest(user.password.as_bytes()).into();
        if users
            .insert(
                hash,
                match &ctx.env.admission {
                    Some(admission) => admission.bind_credential(
                        &ctx.env.users,
                        "anytls",
                        ctx.tag,
                        user.name.as_deref(),
                        &user.password,
                    )?,
                    None => ctx.env.users.bind_named(user.name.as_deref()),
                },
            )
            .is_some()
        {
            return Err(anyhow!(
                "[{}] inbound: users: a password is used more than once",
                tag
            ));
        }
    }
    let stream = Arc::new(StreamHandler::new(
        users,
        Arc::new(padding),
        ctx.env.options.inbound.handshake_timeout,
        fallback,
        (&ctx.env.options).into(),
    ));
    let core: AnyInboundHandler = Arc::new(Handler::new(tag.to_owned(), Some(stream), None));
    layers::inbound(core, &blocks, ctx)
}
