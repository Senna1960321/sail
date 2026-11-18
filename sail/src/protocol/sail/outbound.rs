//! The Sail/1 outbound.
//!
//! Its sessions outlive the streams on them, so its blocks (dial fields,
//! `detour`, `tls`) make its connections: a new session's connection is
//! dialled through the `Connector` they make, its prelude written, and its
//! streams opened at once. A stream does not wait for the server: its
//! header and data go right away, and its first read takes the server's
//! status, failing with it where the server could not connect.
//!
//! Sessions are kept and shared by streams, up to `STREAMS_PER_SESSION` at
//! once each, and closed once they have had none for the profile's carrier
//! idle timeout.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_derive::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::*;
use crate::common::secret::Secret;
use crate::protocol::anytls::padding::PaddingScheme;
use crate::protocol::anytls::session::PaddingCell;
use crate::session::{Session, SocksAddr};
use crate::transport::idle::{self, Idle};
use crate::transport::layers::{Blocks, Connector};
use crate::transport::muxcore::{self, Tuning};

use super::codec::{self, Role, Sail};
use super::{prelude, stream_header, Status, NETWORK_TCP};

/// The streams one session carries at once; a stream past them opens a new
/// session. Judgment, to be measured against AnyTLS in sail#60's third
/// phase: windows keep one stream from holding the others back, and fewer
/// sessions are fewer TLS handshakes.
const STREAMS_PER_SESSION: usize = 32;

/// The shared blocks that make its connections.
const CONNECTION_BLOCKS: Blocks = Blocks {
    dial: true,
    detour: true,
    tls: true,
    ..Blocks::NONE
};

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "sail",
        OutboundFactory::standalone(build)
            .with_blocks(CONNECTION_BLOCKS)
            // A browser's, unless `tls.alpn` says otherwise: the server
            // answers what does not authenticate as a web server would.
            .with_alpn(|_| &["h2", "http/1.1"])
            .over_connector(),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    /// May be left out, with `server_port`, by an outbound with a
    /// `detour` that dials its own server.
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    token: Secret<String>,
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let tag = ctx.tag;
    let connector = ctx.connector()?;
    if !connector.tls() {
        return Err(anyhow!("[{}] outbound: tls: sail needs it enabled", tag));
    }
    let options: Options = ctx.options()?;
    let token =
        super::token(&options.token).map_err(|e| anyhow!("[{}] outbound: token: {}", tag, e))?;
    let (server, server_port) = ctx.server(options.server, options.server_port)?;
    let client = Arc::new(Client {
        server: SocksAddr::try_from((&server, server_port))?,
        token: Secret(token),
        connector,
        padding: Arc::new(RwLock::new(Arc::new(PaddingScheme::default_scheme()))),
        tuning: (&ctx.env.options).into(),
        label: format!("outbound={}", tag),
        sessions: Mutex::new(Vec::new()),
        check: Mutex::new(None),
    });
    Ok(HandlerBuilder::default()
        .tag(tag.to_owned())
        .stream_handler(Arc::new(StreamHandler { client }))
        .build())
}

/// A session, and since when it has had no streams.
struct Pooled {
    /// The pool's handle: dropped, the session takes no more streams and
    /// ends with its last.
    session: Arc<muxcore::Session>,
    idle: Idle,
}

pub(crate) struct Client {
    server: SocksAddr,
    token: Secret<[u8; 32]>,
    connector: Connector,
    /// The scheme the sessions pad with, which the server may replace.
    padding: PaddingCell,
    tuning: Tuning,
    label: String,
    sessions: Mutex<Vec<Pooled>>,
    /// The idle check, started with the first session.
    check: Mutex<Option<idle::Check>>,
}

impl Client {
    /// Drops the sessions that take no more streams, and closes those that
    /// have had none for the idle timeout.
    fn check(&self, now: tokio::time::Instant) {
        let timeout = self.tuning.idle_timeout;
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain_mut(|p| {
            if !p.session.is_reusable() {
                return false;
            }
            if p.idle.expired(p.session.num_streams(), now, timeout) {
                p.session.close();
                return false;
            }
            true
        });
    }

    /// A session with room for another stream, if one is kept.
    fn kept(&self) -> Option<Arc<muxcore::Session>> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions
            .iter()
            .find(|p| p.session.is_reusable() && p.session.num_streams() < STREAMS_PER_SESSION)
            .map(|p| p.session.clone())
    }

    /// A new session, kept for the streams after this one.
    async fn dial(self: &Arc<Self>, sess: &Session) -> io::Result<Arc<muxcore::Session>> {
        let mut sess = sess.clone();
        sess.destination = self.server.clone();
        sess.forget_sniffed();
        let mut conn = self.connector.connect(&sess).await?;
        let scheme = self
            .padding
            .read()
            .map(|s| s.clone())
            .unwrap_or_else(|e| e.into_inner().clone());
        // The prelude goes out with the stream's first frames: nothing
        // waits for the server.
        conn.write_all(&prelude(
            &self.token,
            &codec::digest(&scheme),
            scheme.auth_padding(),
        ))
        .await?;
        let codec = Arc::new(Sail {
            role: Role::Client(self.padding.clone()),
        });
        let (session, _) =
            muxcore::Session::new(conn, codec, false, self.tuning, self.label.as_str());
        let session = Arc::new(session);
        let mut check = self.check.lock().unwrap_or_else(|e| e.into_inner());
        if check.is_none() && !self.tuning.idle_timeout.is_zero() {
            *check = Some(idle::spawn_check(
                "sail idle check",
                Arc::downgrade(self) as Weak<Client>,
                self.tuning.idle_timeout,
                |client: &Client, now| client.check(now),
            ));
        }
        drop(check);
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Pooled {
                session: session.clone(),
                idle: Idle::default(),
            });
        Ok(session)
    }

    /// A stream to `sess.destination`, its header written.
    pub(crate) async fn open(self: &Arc<Self>, sess: &Session) -> io::Result<ClientStream> {
        let header = stream_header(NETWORK_TCP, &sess.destination)?;
        let reused = match sess.new_conn_once {
            true => None,
            false => self.kept(),
        };
        let mut stream = match reused {
            Some(session) => match session.open().await {
                Ok(stream) => stream,
                // Gone since it was found: a new one.
                Err(_) => self.dial(sess).await?.open().await?,
            },
            None => self.dial(sess).await?.open().await?,
        };
        stream.write_all(&header).await?;
        Ok(ClientStream {
            inner: stream,
            status: false,
        })
    }
}

struct StreamHandler {
    client: Arc<Client>,
}

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        Ok(Box::new(self.client.open(sess).await?))
    }
}

/// A client's stream: its first read takes the server's status.
pub(crate) struct ClientStream {
    inner: muxcore::Stream,
    /// Whether the status has been read.
    status: bool,
}

impl AsyncRead for ClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.status {
            let mut byte = [0u8; 1];
            let mut status = ReadBuf::new(&mut byte);
            futures::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut status))?;
            if status.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "sail: the stream ended before the server's status",
                )));
            }
            if byte[0] != Status::Connected as u8 {
                return Poll::Ready(Err(Status::error(byte[0])));
            }
            self.status = true;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
