//! The Sail/1 inbound.
//!
//! One TLS connection is one session, and every stream on it a connection
//! of its own to route, handed back as `InboundTransport::Incoming`.
//!
//! The prelude's head is read within `fallback::HEADER_TIMEOUT` when there
//! is a fallback, and no further than its 43 bytes before the token is
//! known: short of them, past the time, of another version or with a token
//! that is no user's, the connection goes to the fallback with the bytes
//! read of it, as AnyTLS's does. Nothing is written before then. The
//! padding after the head is a user's to send, and the handshake's deadline
//! bounds it.
//!
//! Tokens are looked up by their SHA-256. What a lookup's timing could tell
//! is about the hash of what was sent, not about any user's token.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::stream::Stream as FuturesStream;
use serde_derive::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::debug;

use crate::adapter::inbound::Handler;
use crate::adapter::registry::{parse_options, InboundContext, InboundFactory, InboundRegistry};
use crate::adapter::reply::{Reply, ReplyStream};
use crate::adapter::*;
use crate::common::secret::Secret;
use crate::protocol::anytls::padding::PaddingScheme;
use crate::protocol::fallback::{Fallback, FallbackServer, HEADER_TIMEOUT};
use crate::session::{Session as ProxySession, StreamId};
use crate::transport::layers::{self, Blocks, InboundBlocks, Listable};
use crate::transport::muxcore::{self, Tuning};

use super::codec::{self, Role, Sail};
use super::{read_stream_header, Head, Status, NETWORK_TCP, PRELUDE_HEAD, VERSION};

/// Streams handshaken and waiting for the listener to take them.
const INCOMING_QUEUE: usize = 64;
/// The most users an inbound takes.
const MAX_USERS: usize = 4096;

/// Sail/1 is meant to look like TLS: the inbound insists on it.
const CONNECTION_BLOCKS: Blocks = Blocks {
    tls: true,
    ..Blocks::NONE
};

pub(crate) fn register(registry: &mut InboundRegistry) {
    registry.register("sail", InboundFactory::standalone(build));
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    users: Vec<User>,
    /// The padding scheme, as lines, AnyTLS's syntax. Unset, the default.
    #[serde(default)]
    padding_scheme: Option<Listable>,
    #[serde(default)]
    fallback: Option<FallbackServer>,
    #[serde(default)]
    fallback_for_alpn: HashMap<String, FallbackServer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct User {
    #[serde(default)]
    name: Option<String>,
    token: Secret<String>,
}

fn build(ctx: &InboundContext<'_>) -> Result<AnyInboundHandler> {
    let tag = ctx.tag;
    let (protocol, blocks) = CONNECTION_BLOCKS.split(ctx.options);
    let blocks = InboundBlocks::parse(tag, &blocks)?;
    if !blocks.tls.as_ref().is_some_and(|t| t.enabled) {
        return Err(anyhow!("[{}] inbound: tls: sail needs it enabled", tag));
    }
    let options: Options = parse_options("inbound", tag, &protocol)?;
    if options.users.len() > MAX_USERS {
        return Err(anyhow!("[{}] inbound: users: at most {}", tag, MAX_USERS));
    }
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
        crate::protocol::fallback::note_without(tag, "sail", ctx.env);
    }
    let mut users = HashMap::new();
    for (i, user) in options.users.into_iter().enumerate() {
        let token = super::token(&user.token)
            .map_err(|e| anyhow!("[{}] inbound: users[{}].token: {}", tag, i, e))?;
        let hash: [u8; 32] = Sha256::digest(token).into();
        let bound = match &ctx.env.admission {
            Some(admission) => admission.bind_credential(
                &ctx.env.users,
                "sail",
                tag,
                user.name.as_deref(),
                &user.token,
            )?,
            None => ctx.env.users.bind_named(user.name.as_deref()),
        };
        if users.insert(hash, bound).is_some() {
            return Err(anyhow!(
                "[{}] inbound: users: a token is used more than once",
                tag
            ));
        }
    }
    let stream = Arc::new(StreamHandler {
        users,
        digest: codec::digest(&padding),
        padding: Arc::new(padding),
        handshake_timeout: ctx.env.options.inbound.handshake_timeout,
        fallback,
        tuning: (&ctx.env.options).into(),
    });
    let core: AnyInboundHandler = Arc::new(Handler::new(tag.to_owned(), Some(stream), None));
    layers::inbound(core, &blocks, ctx)
}

pub struct StreamHandler {
    /// Users by the SHA-256 of their token.
    users: HashMap<[u8; 32], Option<crate::user::UserRef>>,
    padding: Arc<PaddingScheme>,
    digest: [u8; 8],
    /// How long a stream has to name its destination, and a user to send
    /// the prelude's padding.
    handshake_timeout: Duration,
    fallback: Option<Fallback>,
    tuning: Tuning,
}

#[async_trait]
impl InboundStreamHandler for StreamHandler {
    async fn handle<'a>(
        &'a self,
        mut sess: ProxySession,
        mut stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        // The head, and no more: what is read here is what the fallback is
        // given if it is not a user's.
        let mut head = [0u8; PRELUDE_HEAD];
        let mut read = 0;
        let reading = async {
            while read < PRELUDE_HEAD {
                let n = stream.read(&mut head[read..]).await?;
                if n == 0 {
                    return Ok(false);
                }
                read += n;
            }
            Ok::<_, io::Error>(true)
        };
        let complete = match self.fallback {
            // A peer that sends part of a head and waits is not a client.
            Some(_) => timeout(HEADER_TIMEOUT, reading)
                .await
                .unwrap_or(Ok(false))?,
            None => timeout(self.handshake_timeout, reading)
                .await
                .unwrap_or(Ok(false))?,
        };
        let found = match complete {
            false => Err("sail: not a Sail/1 prelude"),
            true => {
                let parsed = Head::parse(&head);
                let hash: [u8; 32] = Sha256::digest(parsed.token).into();
                match self.users.get(&hash) {
                    _ if parsed.version != VERSION => Err("sail: another version"),
                    Some(user) if !crate::user::shut_out(user) => Ok((parsed, user.clone())),
                    _ => Err("sail: unknown token"),
                }
            }
        };
        let (parsed, user) = match found {
            Ok(found) => found,
            Err(why) => {
                return Err(match &self.fallback {
                    Some(fallback) => fallback.relay(&sess, stream, head[..read].to_vec(), why),
                    None => io::Error::new(io::ErrorKind::PermissionDenied, why),
                })
            }
        };
        let mut padding = vec![0u8; parsed.pad];
        timeout(self.handshake_timeout, stream.read_exact(&mut padding))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "sail: prelude padding"))??;
        // A client holding another scheme is sent this one, for its next
        // sessions.
        if parsed.digest != self.digest {
            stream
                .write_all(&codec::scheme_frame(&self.padding))
                .await?;
            stream.flush().await?;
        }
        sess.user = user;
        let label = format!(
            "inbound={} user={}",
            sess.inbound_tag,
            crate::user::name(&sess.user).unwrap_or("-")
        );
        let codec = Arc::new(Sail {
            role: Role::Server(self.padding.clone()),
        });
        let (session, accepted) = muxcore::Session::new(stream, codec, true, self.tuning, label);
        let mut accepted = accepted.unwrap_or_else(|| mpsc::unbounded_channel().1);
        let carrier = sess.user.as_ref().map(|user| {
            let close = session.closer();
            user.carry(&sess.inbound_tag, close)
        });
        let (tx, rx) = mpsc::channel(INCOMING_QUEUE);
        let handshake_timeout = self.handshake_timeout;
        crate::runtime::scope::spawn("sail inbound session", async move {
            while let Some(stream) = accepted.recv().await {
                crate::runtime::scope::spawn(
                    "sail inbound stream",
                    accept(stream, sess.clone(), tx.clone(), handshake_timeout),
                );
            }
        });
        Ok(InboundTransport::Incoming(Box::new(Incoming {
            rx,
            _session: session,
            _carrier: carrier,
        })))
    }
}

/// Reads what a new stream asks for, and passes it on to be routed, its
/// status to be written once the dispatcher knows.
async fn accept(
    stream: muxcore::Stream,
    mut sess: ProxySession,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
    handshake_timeout: Duration,
) {
    let id = stream.id();
    let mut stream = ServerStream::new(stream);
    let header = match timeout(handshake_timeout, read_stream_header(&mut stream)).await {
        Ok(Ok(header)) => header,
        Ok(Err(e)) => {
            debug!("sail stream {}: {}", id, e);
            return;
        }
        Err(_) => {
            debug!("sail stream {}: no header in time", id);
            return;
        }
    };
    let (network, destination) = header;
    if network != NETWORK_TCP {
        // UDP comes with sail#60's second phase.
        stream.fail(Status::Unsupported);
        return;
    }
    sess.stream_id = Some(StreamId::U64(id.into()));
    sess.destination = destination;
    let reply = Reply::new(vec![Status::Connected as u8], |e| vec![Status::of(e) as u8]);
    sess.reply = Some(reply.clone());
    let _ = tx
        .send(AnyBaseInboundTransport::Stream(
            Box::new(ReplyStream::new(stream, reply)),
            sess,
        ))
        .await;
}

/// A server's stream. A failure status, the first byte written, goes out
/// ahead of the reset the stream's drop sends, and the stream is not
/// finished: the client sees the status, then the reset.
struct ServerStream {
    inner: muxcore::Stream,
    first: bool,
    failed: bool,
}

impl ServerStream {
    fn new(inner: muxcore::Stream) -> Self {
        ServerStream {
            inner,
            first: true,
            failed: false,
        }
    }

    /// Answers `status`, which is not `Connected`; the drop that follows
    /// resets the stream.
    fn fail(&mut self, status: Status) {
        self.first = false;
        self.failed = true;
        let _ = self
            .inner
            .send_control(codec::data_frame(self.inner.id(), &[status as u8]));
    }
}

impl AsyncRead for ServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if self.first && !buf.is_empty() {
            self.first = false;
            // The reply writes its status alone: a failure's goes as a
            // control frame, so that the reset cannot overtake it.
            if buf[0] != Status::Connected as u8 {
                let status = buf[0];
                self.failed = true;
                let id = self.inner.id();
                self.inner.send_control(codec::data_frame(id, &[status]))?;
                return Poll::Ready(Ok(1));
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// After a failure, not a FIN: the drop resets the stream.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The streams of one session, as they are opened.
struct Incoming {
    rx: mpsc::Receiver<AnyBaseInboundTransport>,
    /// Kept for as long as streams may come.
    _session: muxcore::Session,
    _carrier: Option<crate::user::Carrier>,
}

impl FuturesStream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}
