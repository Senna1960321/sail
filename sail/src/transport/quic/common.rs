//! The QUIC glue everything on quinn shares: the quic transport, Hysteria2,
//! TUIC and the DNS upstreams over QUIC.
//!
//! TLS configurations from the `tls` blocks, transport parameters, the
//! endpoint and the socket under it, and a proxied stream. What a protocol
//! does on top, such as Hysteria2's Brutal and Salamander or TUIC's
//! heartbeats, stays with the protocol.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use quinn::congestion::ControllerFactory;
use quinn::{AsyncUdpSocket, Runtime};
use serde_derive::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::recv_backoff::RecvBackoff;
use crate::app::SyncDnsClient;
use crate::net::Dialer;
use crate::runtime::options::Quic as Tuning;
use crate::runtime::options::UdpBuffers;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::{trusted_certificate, InboundTls, Listable, OutboundTls};
use crate::transport::muxcore::stall::{Guarded, Stallable, STALL_TIMEOUT};
use crate::transport::tls::client::{load_certificates, load_private_key, Identity};
use crate::transport::tls::ech::decode_ech_config_list;

/// The ALPNs of a `tls` block's `alpn`, or `default` when it lists none.
pub fn alpn_protocols(alpn: Option<&Listable>, default: &[&str]) -> Vec<Vec<u8>> {
    match alpn.map(|a| a.clone().into_vec()) {
        Some(list) if !list.is_empty() => list.into_iter().map(String::into_bytes).collect(),
        _ => default.iter().map(|a| a.as_bytes().to_vec()).collect(),
    }
}

/// A client TLS configuration trusting `certificate` (inline PEM or a
/// path) instead of the bundled roots, or any server if `insecure`, and
/// offering `alpns`, if any.
pub fn client_crypto(
    certificate: Option<&str>,
    insecure: bool,
    alpns: &[Vec<u8>],
    roots: &crate::transport::tls::roots::Roots,
) -> Result<quinn_btls::ClientConfig> {
    use quinn_btls::QuicSslContext;
    let mut crypto =
        quinn_btls::ClientConfig::new().map_err(|e| anyhow!("quic client config: {}", e))?;
    if insecure {
        crypto.verify_peer(false);
    } else {
        crate::transport::tls::configure_quic(
            &mut crypto,
            crate::transport::tls::verify_at_instance_time,
        );
        let certs = match certificate {
            Some(certificate) => load_certificates(certificate)?,
            None => roots.certs().to_vec(),
        };
        let store = crypto.ctx_mut().cert_store_mut();
        for cert in certs {
            store.add_cert(cert)?;
        }
    }
    if !alpns.is_empty() {
        crypto
            .set_alpn(alpns)
            .map_err(|e| anyhow!("quic alpn: {}", e))?;
    }
    Ok(crypto)
}

/// What a client dials with, from its `tls` block.
pub struct ClientTls {
    /// The name the server is verified by: `server_name`, or the server's
    /// address.
    pub server_name: String,
    /// Offering ECH with `tls.ech.config`, if set.
    pub crypto: quinn_btls::ClientConfig,
    /// Whether each connection offers ECH with the ECHConfigList DNS has
    /// for `server_name`: `tls.ech` is on, with no `config`.
    pub ech_lookup: bool,
}

impl ClientTls {
    /// From `tls`, for the server at `server`, offering `default_alpn`
    /// unless `alpn` is set, presenting the client certificate if set,
    /// taking the server by the pinned keys if set, and offering ECH if
    /// `tls.ech` is on. A version range without TLS 1.3 is an error: QUIC
    /// is TLS 1.3 only. Whatever `unsupported` finds is the caller's to
    /// refuse; this reads none of it.
    pub fn new(
        tls: &OutboundTls,
        server: &str,
        default_alpn: &[&str],
        env: &RuntimeEnv,
    ) -> Result<Self> {
        // quinn-btls sets the SNI of every name but an IP address.
        if tls.disable_sni {
            return Err(anyhow!("disable_sni: not over QUIC yet"));
        }
        let ech = tls.ech.as_ref().filter(|e| e.enabled);
        // As over TCP: a configured list is the only one used, and DNS is
        // asked only without one.
        if ech.is_some_and(|e| e.disable_dns_lookup && e.config.is_none()) {
            return Err(anyhow!("ech.disable_dns_lookup: needs ech.config"));
        }
        let mut crypto = client_crypto(
            trusted_certificate(tls, env).as_deref(),
            tls.insecure,
            &alpn_protocols(tls.alpn.as_ref(), default_alpn),
            &env.tls_roots.get()?,
        )?;
        if let Some(identity) = tls.client_identity(env)? {
            present(&mut crypto, &identity)?;
        }
        tls.client_options()?.apply_quic(&mut crypto)?;
        if let Some(config) = ech.and_then(|e| e.config.as_ref()) {
            let config = config.clone().into_vec().join("\n");
            let list = decode_ech_config_list(&config).map_err(|e| anyhow!("ech.config: {}", e))?;
            if list.is_empty() {
                return Err(anyhow!("ech.config: cannot be empty"));
            }
            crypto
                .set_ech_config_list(Some(&list))
                .map_err(|e| anyhow!("ech.config: not an ECHConfigList: {}", e))?;
        }
        Ok(Self {
            server_name: tls.server_name.clone().unwrap_or_else(|| server.to_owned()),
            crypto,
            ech_lookup: ech.is_some_and(|e| e.config.is_none()),
        })
    }

    /// The TLS configuration of a new connection: `crypto`, offering the
    /// ECHConfigList DNS has for `server_name` with `ech_lookup`. As over
    /// TCP and in sing-box, a lookup that fails or finds none fails the
    /// connection, rather than making it without ECH. Unlike over TCP, it
    /// is made for the DNS client's own queries too: the connection is
    /// every session's.
    ///
    /// A server that rejects ECH fails the handshake, as over TCP and in
    /// sing-box: there is no retry with the configs it sends.
    pub async fn connection_crypto(
        &self,
        dns_client: &SyncDnsClient,
    ) -> io::Result<Arc<quinn_btls::ClientConfig>> {
        let mut crypto = self.crypto.clone();
        if self.ech_lookup {
            let name = &self.server_name;
            let list = dns_client
                .load_full()
                .lookup_ech_config_list(name)
                .await
                .map_err(|e| io::Error::other(format!("ech fetch failed for {}: {}", name, e)))?;
            let list = decode_ech_config_list(&list)?;
            crypto.set_ech_config_list(Some(&list)).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid ech config list for {}: {}", name, e),
                )
            })?;
            tracing::trace!("ech source for {}: https/svcb dns record", name);
        }
        Ok(Arc::new(crypto))
    }
}

/// A client's quinn configuration, made for each connection: the TLS
/// configuration is the connection's ([`ClientTls::connection_crypto`]),
/// the transport configuration and the address validation tokens are
/// shared by all of them.
pub struct ClientConfigs {
    tls: ClientTls,
    transport: Arc<quinn::TransportConfig>,
    tokens: Arc<dyn quinn::TokenStore>,
}

impl ClientConfigs {
    pub fn new(tls: ClientTls, transport: quinn::TransportConfig) -> Self {
        Self {
            tls,
            transport: Arc::new(transport),
            tokens: Arc::new(quinn::TokenMemoryCache::default()),
        }
    }

    /// The name the server is verified by.
    pub fn server_name(&self) -> &str {
        &self.tls.server_name
    }

    /// The configuration of a new connection.
    pub async fn connection(&self, dns_client: &SyncDnsClient) -> io::Result<quinn::ClientConfig> {
        let mut config = quinn::ClientConfig::new(self.tls.connection_crypto(dns_client).await?);
        config
            .transport_config(self.transport.clone())
            .token_store(self.tokens.clone());
        Ok(config)
    }
}

/// Presents `identity` to a server that asks for a certificate.
pub fn present(crypto: &mut quinn_btls::ClientConfig, identity: &Identity) -> Result<()> {
    use quinn_btls::QuicSslContext;
    let ctx = crypto.ctx_mut();
    let mut chain = identity.chain().iter();
    if let Some(cert) = chain.next() {
        ctx.set_certificate(cert.clone())?;
    }
    for cert in chain {
        ctx.add_to_cert_chain(cert.clone())?;
    }
    ctx.set_private_key(identity.key().clone())?;
    ctx.check_private_key()
        .map_err(|e| anyhow!("client_key: not the certificate's: {}", e))?;
    Ok(())
}

/// The first of `tls.reality`, `tls.utls`, `tls.fragment` and
/// `tls.record_fragment` that the block enables: none works over QUIC,
/// whose ClientHello goes in Initial packets, not TCP.
pub fn unsupported(tls: &OutboundTls) -> Option<&'static str> {
    [
        ("reality", tls.reality.as_ref().is_some_and(|r| r.enabled)),
        ("utls", tls.utls.as_ref().is_some_and(|u| u.enabled)),
        ("fragment", tls.fragment),
        ("record_fragment", tls.record_fragment),
    ]
    .into_iter()
    .find_map(|(field, on)| on.then_some(field))
}

/// A server TLS configuration presenting `certificate` with `key`, each
/// inline PEM or a path, and accepting `alpns`, if any.
pub fn server_crypto(
    certificate: &str,
    key: &str,
    alpns: &[Vec<u8>],
) -> Result<quinn_btls::ServerConfig> {
    use quinn_btls::QuicSslContext;
    let mut certs = load_certificates(certificate)?.into_iter();
    let key = load_private_key(key)?;

    let mut crypto =
        quinn_btls::ServerConfig::new().map_err(|e| anyhow!("quic server config: {}", e))?;
    let ctx = crypto.ctx_mut();
    let leaf = certs
        .next()
        .ok_or_else(|| anyhow!("no certificate found"))?;
    ctx.set_certificate(leaf)?;
    for cert in certs {
        ctx.add_to_cert_chain(cert)?;
    }
    ctx.set_private_key(key)?;
    ctx.check_private_key()
        .map_err(|e| anyhow!("private key does not match the certificate: {}", e))?;
    if !alpns.is_empty() {
        crypto
            .set_alpn(alpns)
            .map_err(|e| anyhow!("quic alpn: {}", e))?;
    }
    Ok(crypto)
}

/// [`server_crypto`] from an inbound's `tls` block, its errors as the
/// inbound `tag`'s, clients' certificates checked as the block says. A
/// version range without TLS 1.3 is an error: QUIC is
/// TLS 1.3 only. So is REALITY, which is TCP-only: sing-box takes it in the
/// configuration and refuses it at start ("unsupported usage for
/// reality", its REALITY server's STDConfig); here, at once. With
/// `self_signed`, the certificate presented is the one `self_signed` holds.
pub fn inbound_crypto(
    tag: &str,
    tls: &InboundTls,
    env: &RuntimeEnv,
    alpns: &[Vec<u8>],
    self_signed: &crate::transport::tls::self_signed::Slot,
) -> Result<quinn_btls::ServerConfig> {
    if tls.reality.as_ref().is_some_and(|r| r.enabled) {
        return Err(anyhow!(
            "[{}] inbound: tls.reality: REALITY is TCP-only, not for QUIC",
            tag
        ));
    }
    // Only REALITY and `self_signed` use `server_name`; as over TCP, it is
    // ignored aloud.
    if tls.server_name.is_some() && !tls.self_signed {
        tracing::warn!(
            "[{}] inbound: tls.server_name: a server does not use it; ignored, as sing-box",
            tag
        );
    }
    tls.versions(tag)?
        .require_tls13("QUIC")
        .map_err(|e| anyhow!("[{}] inbound: tls.{}", tag, e))?;
    let client_auth = tls.client_auth(tag, env)?;
    let (certificate, key) = tls.identity(tag, env, self_signed)?;
    let mut crypto = server_crypto(&certificate, &key, alpns)
        .map_err(|e| anyhow!("[{}] inbound: tls: {}", tag, e))?;
    // By sail's own verification, as over TCP: quinn-btls's would verify by
    // the context's store, which holds the system's roots.
    if let Some(client_auth) = client_auth {
        client_auth
            .apply_quic(&mut crypto)
            .map_err(|e| anyhow!("[{}] inbound: tls: {}", tag, e))?;
    }
    Ok(crypto)
}

/// The server configuration of `crypto`, with quinn's transport defaults.
pub fn server_config(crypto: quinn_btls::ServerConfig) -> Result<quinn::ServerConfig> {
    quinn_btls::helpers::server_config(Arc::new(crypto))
        .map_err(|e| anyhow!("quic server config: {}", e))
}

/// The congestion controllers quinn has, named as in sing-box.
#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CongestionControl {
    /// sing-box's default.
    #[default]
    Cubic,
    NewReno,
    Bbr,
}

impl CongestionControl {
    pub fn factory(self) -> Arc<dyn ControllerFactory + Send + Sync> {
        match self {
            Self::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
            Self::NewReno => Arc::new(quinn::congestion::NewRenoConfig::default()),
            Self::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
        }
    }
}

/// Which end of connections a transport configuration is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// The transport parameters the `quic` options set for `side`: concurrent
/// bidirectional streams, the idle timeout and keep-alives, none if the
/// interval is zero. Congestion is controlled as `congestion` makes it:
/// [`CongestionControl::factory`], or a protocol's own.
pub fn transport_config(
    tuning: &Tuning,
    side: Side,
    congestion: Arc<dyn ControllerFactory + Send + Sync>,
) -> quinn::TransportConfig {
    let (idle, keep_alive) = match side {
        Side::Client => (
            tuning.client_idle_timeout,
            tuning.client_keep_alive_interval,
        ),
        Side::Server => (
            tuning.server_idle_timeout,
            tuning.server_keep_alive_interval,
        ),
    };
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(tuning.max_concurrent_streams))
        .max_idle_timeout(quinn::IdleTimeout::try_from(idle).ok())
        .keep_alive_interval((!keep_alive.is_zero()).then_some(keep_alive))
        .congestion_controller_factory(congestion);
    config
}

/// The flow-control windows of a Hysteria2 or TUIC connection, as the
/// `quic` options set them, in place of quinn's fixed 1.25 MB a stream:
/// they start small and grow while they are read about as fast as data
/// arrives, within the process's
/// [`transfer_budget`](crate::runtime::transfer_budget).
#[cfg(any(
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
    feature = "inbound-tuic",
    feature = "outbound-tuic"
))]
pub fn proxy_windows(config: &mut quinn::TransportConfig, tuning: &Tuning) {
    let kib = |n: usize| quinn::VarInt::from_u64(n as u64 * 1024).unwrap_or(quinn::VarInt::MAX);
    config
        .stream_receive_window(kib(tuning.stream_window))
        .receive_window(kib(tuning.receive_window))
        .send_window(tuning.send_window as u64 * 1024)
        .window_tuning(Some(
            quinn::WindowTuning::new(
                kib(tuning.stream_window_max),
                kib(tuning.receive_window_max),
                tuning.send_window_max as u64 * 1024,
            )
            .budget(std::sync::Arc::new(Budget))
            .credit_on_receipt(tuning.credit_on_receipt),
        ));
}

/// The process's transfer budget, as quinn asks it.
#[cfg(any(
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
    feature = "inbound-tuic",
    feature = "outbound-tuic"
))]
struct Budget;

#[cfg(any(
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
    feature = "inbound-tuic",
    feature = "outbound-tuic"
))]
impl quinn::WindowBudget for Budget {
    fn try_grow(&self, bytes: u64) -> bool {
        crate::runtime::transfer_budget::global().try_grow(bytes)
    }

    fn release(&self, bytes: u64) {
        crate::runtime::transfer_budget::global().release(bytes)
    }
}

/// The bytes of unfinished UDP packets, fragments waiting for the rest, a
/// Hysteria2 or TUIC connection holds across all of its UDP sessions.
/// Judgment: 64 packets of the largest size; fragments of one packet
/// travel back to back, so a connection seldom holds more than a few.
#[cfg(any(
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
    feature = "inbound-tuic",
    feature = "outbound-tuic"
))]
pub const MAX_FRAGMENT_BYTES: usize = 64 * (u16::MAX as usize + 1);

/// What one connection's UDP sessions hold of unfinished packets, bounded
/// by `MAX_FRAGMENT_BYTES` together. A fragment past the bound is dropped,
/// and its packet with it, as UDP may drop any packet.
#[cfg(any(
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
    feature = "inbound-tuic",
    feature = "outbound-tuic"
))]
#[derive(Debug)]
pub struct FragmentBudget {
    held: std::sync::atomic::AtomicUsize,
    max: usize,
}

#[cfg(any(
    feature = "inbound-hysteria2",
    feature = "outbound-hysteria2",
    feature = "inbound-tuic",
    feature = "outbound-tuic"
))]
impl FragmentBudget {
    pub fn new(max: usize) -> Arc<FragmentBudget> {
        Arc::new(FragmentBudget {
            held: Default::default(),
            max,
        })
    }

    /// Takes `n` bytes, unless that would pass the bound.
    pub fn take(&self, n: usize) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        self.held
            .fetch_update(Relaxed, Relaxed, |held| {
                held.checked_add(n).filter(|total| *total <= self.max)
            })
            .is_ok()
    }

    /// Gives back `n` bytes taken.
    pub fn give(&self, n: usize) {
        self.held.fetch_sub(n, std::sync::atomic::Ordering::Relaxed);
    }

    /// The bytes held now.
    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.held.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// The streams of each kind a Hysteria2 or TUIC client may open at once
/// before it authenticates: quinn's default, and what HTTP/3 servers
/// commonly allow, so that a client that has not authenticated cannot
/// hold more. More wait their turn rather than fail.
pub const STREAMS_BEFORE_AUTH: u32 = 100;

/// The most streams of one kind an authenticated client may hold open at
/// once on one connection.
pub const STREAMS_CEILING: u64 = 65536;

/// How many streams of one kind a client of a Hysteria2 or TUIC server may
/// hold open at once: `STREAMS_BEFORE_AUTH` until it authenticates, then
/// twice as many each time three quarters are open, up to
/// `STREAMS_CEILING`. sing-box's servers allow 1<<60 (sing-quic's
/// services), but quinn sets aside room for every stream it allows, so
/// the limit follows the streams actually open; it counts those open at
/// once, not how many a connection has had. A client past it waits for
/// one to close, as for any QUIC credit; `user_limits.max_connections`
/// bounds a user. Making quinn allocate as quic-go does, lazily, would
/// do without it.
pub struct StreamLimit {
    open: portable_atomic::AtomicU64,
    limit: portable_atomic::AtomicU64,
    grows: std::sync::atomic::AtomicBool,
    raise: Box<dyn Fn(u64) + Send + Sync>,
}

impl StreamLimit {
    /// A limit of `STREAMS_BEFORE_AUTH`, which `raise` raises to the value
    /// it is given.
    pub fn new(raise: impl Fn(u64) + Send + Sync + 'static) -> Arc<StreamLimit> {
        Arc::new(StreamLimit {
            open: Default::default(),
            limit: u64::from(STREAMS_BEFORE_AUTH).into(),
            grows: Default::default(),
            raise: Box::new(raise),
        })
    }

    /// The bidirectional streams of `conn`.
    pub fn bidi(conn: &quinn::Connection) -> Arc<StreamLimit> {
        let conn = conn.clone();
        Self::new(move |n| {
            conn.set_max_concurrent_bi_streams(quinn::VarInt::from_u32(
                u32::try_from(n).unwrap_or(u32::MAX),
            ))
        })
    }

    /// The unidirectional streams of `conn`.
    pub fn uni(conn: &quinn::Connection) -> Arc<StreamLimit> {
        let conn = conn.clone();
        Self::new(move |n| {
            conn.set_max_concurrent_uni_streams(quinn::VarInt::from_u32(
                u32::try_from(n).unwrap_or(u32::MAX),
            ))
        })
    }

    /// The client authenticated: the limit grows from now on.
    pub fn authenticated(&self) {
        self.grows.store(true, std::sync::atomic::Ordering::Relaxed);
        self.grow();
    }

    /// A stream the client opened, counted until the guard is dropped.
    pub fn opened(self: &Arc<Self>) -> StreamGuard {
        self.open.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.grow();
        StreamGuard(self.clone())
    }

    /// The limit now.
    pub fn limit(&self) -> u64 {
        self.limit.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn grow(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        if !self.grows.load(Relaxed) {
            return;
        }
        let open = self.open.load(Relaxed);
        let mut limit = self.limit.load(Relaxed);
        while open * 4 >= limit * 3 && limit < STREAMS_CEILING {
            let next = (limit * 2).min(STREAMS_CEILING);
            match self.limit.compare_exchange(limit, next, Relaxed, Relaxed) {
                Ok(_) => {
                    (self.raise)(next);
                    limit = next;
                }
                Err(now) => limit = now,
            }
        }
    }
}

/// A stream counted as open until dropped.
pub struct StreamGuard(Arc<StreamLimit>);

/// `S`, counted as an open stream for as long as it lives.
pub struct Counted<S> {
    inner: S,
    _guard: StreamGuard,
}

impl<S> Counted<S> {
    pub fn new(inner: S, guard: StreamGuard) -> Self {
        Counted {
            inner,
            _guard: guard,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Counted<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0
            .open
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A UDP socket for talking to `peer`, opened by `dialer`.
pub async fn bind(peer: IpAddr, dialer: &Dialer) -> io::Result<std::net::UdpSocket> {
    let unspecified = match peer {
        IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    dialer.udp_socket(&unspecified).await?.into_std()
}

/// `socket` as quinn takes it, for wrapping further, with the buffers
/// `buffers` asks the system for. Every QUIC socket of the system's passes
/// here; a detour's datagrams have no socket to size.
pub fn wrap_socket(
    socket: std::net::UdpSocket,
    buffers: UdpBuffers,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    socket.set_nonblocking(true)?;
    size_buffers(&socket, buffers);
    let socket = quinn::TokioRuntime.wrap_udp_socket(socket)?;
    Ok(match buffers.receive_batch {
        0 => socket,
        batch => Arc::new(Batched {
            inner: socket,
            batch,
        }),
    })
}

/// `inner`, whose endpoint takes at most `batch` datagrams a receive
/// (`quic.udp_receive_batch`), and keeps room for that many.
#[derive(Debug)]
struct Batched {
    inner: Arc<dyn AsyncUdpSocket>,
    batch: usize,
}

impl AsyncUdpSocket for Batched {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn max_receive_batch(&self) -> usize {
        self.batch.min(self.inner.max_receive_batch())
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Asks the system for `buffers` on `socket`, a zero leaving what it has.
/// What the system gives is its own to decide (Linux doubles the number
/// and stops at `net.core.rmem_max` and `wmem_max` without an error, past
/// which only a privileged process is given more), so it is read back and
/// logged; a refusal is no reason not to connect.
///
/// The buffers and no more. Windows' receive coalescing (URO,
/// `UDP_RECV_MAX_COALESCED_SIZE`) is left out on purpose: on some
/// Windows 11 systems it corrupts datagrams silently (quinn's issue 2041).
fn size_buffers(socket: &std::net::UdpSocket, buffers: UdpBuffers) {
    type Set = fn(&socket2::SockRef<'_>, usize) -> io::Result<()>;
    type Get = fn(&socket2::SockRef<'_>) -> io::Result<usize>;
    let socket = socket2::SockRef::from(socket);
    let sizes: [(&str, usize, Set, Get); 2] = [
        (
            "receive",
            buffers.receive,
            |s, n| s.set_recv_buffer_size(n),
            |s| s.recv_buffer_size(),
        ),
        (
            "send",
            buffers.send,
            |s, n| s.set_send_buffer_size(n),
            |s| s.send_buffer_size(),
        ),
    ];
    for (which, asked, set, get) in sizes {
        if asked == 0 {
            continue;
        }
        if let Err(e) = set(&socket, asked) {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| {
                tracing::warn!(
                    "quic: the UDP {} buffer of {} bytes was refused ({}); the system's is kept",
                    which,
                    asked,
                    e
                )
            });
            continue;
        }
        // Linux stops a plain request at `net.core.rmem_max` or `wmem_max`
        // without an error; a process with CAP_NET_ADMIN may go past them.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(reported) = get(&socket).ok().filter(|got| cut_short(asked, *got)) {
            if let Err(e) = force_buffer(&socket, which == "receive", asked) {
                // Said once, and where it is seen: what is lost to a
                // buffer too small shows nowhere else.
                static SAID: std::sync::Once = std::sync::Once::new();
                SAID.call_once(|| tracing::info!("{}", held_short(which, asked, reported, &e)));
            }
        }
        match get(&socket) {
            Ok(got) => tracing::debug!(
                "quic: UDP {} buffer: asked {} bytes, the system reports {}",
                which,
                asked,
                got
            ),
            Err(e) => tracing::debug!(
                "quic: UDP {} buffer: asked {} bytes, not read back ({})",
                which,
                asked,
                e
            ),
        }
    }
}

/// Whether Linux kept less than the `asked` bytes of a buffer: it reports
/// twice what it kept, the half being its own bookkeeping.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn cut_short(asked: usize, reported: usize) -> bool {
    reported < asked.saturating_mul(2)
}

/// What is said of a buffer the system's limit kept short of the `asked`
/// bytes, `e` being why sail could not pass the limit.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn held_short(which: &str, asked: usize, reported: usize, e: &io::Error) -> String {
    format!(
        "quic: the UDP {} buffer is {} KiB of the {} asked, the system's limit (net.core.{}), \
         and sail may not pass it ({}); raise the limit for links of some hundred Mbit/s",
        which,
        reported / 2 / 1024,
        asked / 1024,
        if which == "receive" {
            "rmem_max"
        } else {
            "wmem_max"
        },
        e
    )
}

/// Sets `socket`'s receive or send buffer to `bytes` past the system's
/// limit (`SO_RCVBUFFORCE`, `SO_SNDBUFFORCE`), as quic-go does for its
/// sockets. It takes CAP_NET_ADMIN, which a server run as root or a client
/// that sets up a TUN has; without it the buffer stays as the plain
/// request left it, at `net.core.rmem_max` or `wmem_max`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn force_buffer(socket: &socket2::SockRef<'_>, receive: bool, bytes: usize) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let name = if receive {
        libc::SO_RCVBUFFORCE
    } else {
        libc::SO_SNDBUFFORCE
    };
    let value = libc::c_int::try_from(bytes).unwrap_or(libc::c_int::MAX);
    // SAFETY: the descriptor is the socket's, open for as long as the
    // reference; the option takes an int, and its size is passed.
    let done = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if done == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// An endpoint on `socket`, serving with `server` if set.
pub fn endpoint(
    socket: std::net::UdpSocket,
    server: Option<quinn::ServerConfig>,
    buffers: UdpBuffers,
) -> io::Result<quinn::Endpoint> {
    endpoint_on(wrap_socket(socket, buffers)?, server)
}

/// [`endpoint`] on a socket of quinn's. Every endpoint is made here: its
/// socket waits out transient receive errors, which would otherwise end
/// the endpoint and every connection on it ([`RecvBackoff`]).
pub fn endpoint_on(
    socket: Arc<dyn AsyncUdpSocket>,
    server: Option<quinn::ServerConfig>,
) -> io::Result<quinn::Endpoint> {
    quinn::Endpoint::new_with_abstract_socket(
        quinn_btls::helpers::default_endpoint_config(),
        server,
        Arc::new(RecvBackoff::new(socket)),
        Arc::new(ScopedRuntime(crate::runtime::scope::here())),
    )
}

/// tokio, as quinn runs on it, but what quinn spawns (an endpoint's driver,
/// each connection's) is in the scope of the instance that made the
/// endpoint: ended by its stop and named in its report, on the host's
/// runtime too, where no runtime shutdown would end it.
#[derive(Debug)]
struct ScopedRuntime(Option<crate::runtime::scope::TaskScope>);

impl Runtime for ScopedRuntime {
    fn new_timer(&self, i: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::TokioRuntime.new_timer(i)
    }

    fn spawn(&self, future: Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        drop(match &self.0 {
            Some(scope) => scope.spawn("quic driver", future),
            None => crate::runtime::scope::spawn("quic driver", future),
        });
    }

    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(t)
    }

    fn now(&self) -> std::time::Instant {
        quinn::TokioRuntime.now()
    }
}

/// A proxied TCP connection: one bidirectional QUIC stream, and `G`, kept
/// as long as the stream (TUIC counts its relays by it).
///
/// Reads and writes are quinn's own: the peer's FIN reads as the end of
/// the stream, a reset or a STOP_SENDING fails with `ConnectionReset`, a
/// lost connection with `NotConnected`. Shutting down finishes our side,
/// and so does dropping the stream.
///
/// A stream whose reader has not come back for data for the stall timeout
/// (`mux.stall_timeout`, the multiplexers' own) is reset both ways, alone
/// (`muxcore::stall`): what it holds would otherwise count against its
/// connection's window, or with `quic.credit_on_receipt` against the
/// transfer budget, for as long.
pub struct QuicStream<G = ()> {
    io: Guarded<Halves>,
    _guard: G,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self::guarded(send, recv, ())
    }
}

impl<G> QuicStream<G> {
    pub fn guarded(send: quinn::SendStream, recv: quinn::RecvStream, guard: G) -> Self {
        Self {
            io: Guarded::new(Halves { send, recv }, "quic", stall_timeout(), "".into()),
            _guard: guard,
        }
    }
}

/// The stall timeout of the process's QUIC streams, `mux.stall_timeout`
/// once the runtime options are in.
static STALL: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();

/// Takes the stall timeout from the runtime options; the first call holds.
pub fn configure_stall_timeout(timeout: std::time::Duration) {
    let _ = STALL.set(timeout);
}

fn stall_timeout() -> std::time::Duration {
    STALL.get().copied().unwrap_or(STALL_TIMEOUT)
}

/// A QUIC stream's two halves.
struct Halves {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Stallable for Halves {
    fn id(&mut self) -> u64 {
        self.send.id().index()
    }

    /// quinn does not say.
    fn buffered(&mut self) -> Option<usize> {
        None
    }

    /// STOP_SENDING and RESET_STREAM: what the stream holds is dropped,
    /// and its credit goes back to the connection.
    fn reset(&mut self) {
        let _ = self.recv.stop(0u32.into());
        let _ = self.send.reset(0u32.into());
    }
}

impl AsyncRead for Halves {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Halves {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // quinn's own `poll_write` fails with a `WriteError`.
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(io::Error::from)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

impl<G: Unpin> AsyncRead for QuicStream<G> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<G: Unpin> AsyncWrite for QuicStream<G> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_defaults_when_unset_or_empty() {
        let h3 = vec![b"h3".to_vec()];
        assert_eq!(alpn_protocols(None, &["h3"]), h3);
        assert_eq!(alpn_protocols(Some(&Listable::Many(vec![])), &["h3"]), h3);
        assert!(alpn_protocols(None, &[]).is_empty());
        assert_eq!(
            alpn_protocols(Some(&Listable::One("doq".into())), &["h3"]),
            vec![b"doq".to_vec()]
        );
    }

    /// The buffers of a fresh socket, as the system made it, and of one
    /// sized as `buffers`: (receive, send) each.
    fn buffers_of(buffers: UdpBuffers) -> ((usize, usize), (usize, usize)) {
        let sizes = |socket: &std::net::UdpSocket| {
            let socket = socket2::SockRef::from(socket);
            (
                socket.recv_buffer_size().unwrap(),
                socket.send_buffer_size().unwrap(),
            )
        };
        let bind = || std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let sized = bind();
        size_buffers(&sized, buffers);
        (sizes(&bind()), sizes(&sized))
    }

    /// What was asked for, or what the system stopped at: Linux gives
    /// twice its `rmem_max` or `wmem_max` at most, which is still more
    /// than a socket starts with.
    const ASKED: usize = 1 << 20;

    #[test]
    fn a_receive_buffer_is_asked_of_the_system() {
        let (system, sized) = buffers_of(UdpBuffers {
            receive: ASKED,
            send: 0,
            ..UdpBuffers::default()
        });
        assert!(
            sized.0 >= ASKED || sized.0 > system.0,
            "{:?} from {:?}",
            sized,
            system
        );
        assert_eq!(sized.1, system.1, "the send buffer was not asked for");
    }

    #[test]
    fn a_send_buffer_is_asked_of_the_system() {
        let (system, sized) = buffers_of(UdpBuffers {
            receive: 0,
            send: ASKED,
            ..UdpBuffers::default()
        });
        assert!(
            sized.1 >= ASKED || sized.1 > system.1,
            "{:?} from {:?}",
            sized,
            system
        );
        assert_eq!(sized.0, system.0, "the receive buffer was not asked for");
    }

    /// Linux reports twice what it kept: a request it stopped at its
    /// limit shows as less than twice what was asked.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_request_the_system_cut_short_is_told_from_one_kept() {
        assert!(cut_short(7168 << 10, 2 * 212_992));
        assert!(cut_short(300 << 10, 2 * 212_992));
        assert!(!cut_short(7168 << 10, 2 * (7168 << 10)));
        assert!(!cut_short(100 << 10, 2 * (100 << 10)));
    }

    /// A buffer held short names what it is, what was asked and the
    /// limit to raise, in KiB as the option is set.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn a_buffer_held_short_names_the_limit_to_raise() {
        let e = io::Error::from_raw_os_error(libc::EPERM);
        let said = held_short("receive", 7168 << 10, 2 * 212_992, &e);
        assert!(
            said.contains("receive buffer is 208 KiB of the 7168 asked"),
            "{}",
            said
        );
        assert!(said.contains("net.core.rmem_max"), "{}", said);
        let said = held_short("send", 1 << 20, 2 * 212_992, &e);
        assert!(said.contains("net.core.wmem_max"), "{}", said);
    }

    /// Past `net.core.rmem_max` a plain request is cut short; with
    /// CAP_NET_ADMIN the socket gets what was asked all the same, and
    /// without it what the limit allows.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_receive_buffer_past_the_systems_limit_is_forced_where_permitted() {
        // Only the initial network namespace shows the limit.
        let Some(limit) = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
            .ok()
            .and_then(|text| text.trim().parse::<usize>().ok())
        else {
            return;
        };
        let asked = limit * 4;
        let bind = || std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let probe = bind();
        let permitted = force_buffer(&socket2::SockRef::from(&probe), true, asked).is_ok();
        let sized = bind();
        size_buffers(
            &sized,
            UdpBuffers {
                receive: asked,
                send: 0,
                ..UdpBuffers::default()
            },
        );
        let reported = socket2::SockRef::from(&sized).recv_buffer_size().unwrap();
        if permitted {
            assert!(!cut_short(asked, reported), "{} of {}", reported, asked);
        } else {
            assert_eq!(reported, limit * 2);
        }
    }

    #[test]
    fn no_buffer_asked_leaves_the_systems() {
        let (system, sized) = buffers_of(UdpBuffers::default());
        assert_eq!(sized, system);
    }

    /// The endpoint is told the batch asked for, through the receive
    /// errors' wrapper as well; zero leaves quinn's.
    #[tokio::test]
    async fn a_wrapped_socket_has_the_receive_batch_asked() {
        for (asked, batch) in [(0, quinn::udp::BATCH_SIZE), (1, 1)] {
            let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let wrapped = wrap_socket(
                socket,
                UdpBuffers {
                    receive_batch: asked,
                    ..UdpBuffers::default()
                },
            )
            .unwrap();
            assert_eq!(wrapped.max_receive_batch(), batch);
            assert_eq!(RecvBackoff::new(wrapped).max_receive_batch(), batch);
        }
    }

    // Not on Windows: a duplicate made before the sizing went on reporting
    // the size the socket had then (131072 after 1048576 was asked and, by
    // the tests above, given), so it tells nothing of the socket there.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn a_wrapped_socket_has_the_buffers_asked() {
        // Through wrap_socket, where every real QUIC socket passes: the
        // socket is quinn's from there, so a duplicate tells its size.
        let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let system = socket2::SockRef::from(&socket).recv_buffer_size().unwrap();
        let ours = socket.try_clone().unwrap();
        let _wrapped = wrap_socket(
            socket,
            UdpBuffers {
                receive: ASKED,
                send: ASKED,
                ..UdpBuffers::default()
            },
        )
        .unwrap();
        let ours = socket2::SockRef::from(&ours);
        let receive = ours.recv_buffer_size().unwrap();
        assert!(receive >= ASKED || receive > system, "{}", receive);
        assert!(ours.send_buffer_size().unwrap() > 0);
    }

    #[test]
    fn congestion_controls_are_named_as_in_sing_box() {
        let parse = |s: &str| serde_json::from_str::<CongestionControl>(&format!("\"{}\"", s));
        assert_eq!(parse("new_reno").unwrap(), CongestionControl::NewReno);
        assert_eq!(parse("bbr").unwrap(), CongestionControl::Bbr);
        assert_eq!(parse("cubic").unwrap(), CongestionControl::Cubic);
        assert!(parse("reno").is_err());
    }

    /// A server whose certificate has only the IP SAN 127.0.0.1, and a
    /// client trusting that certificate.
    fn ip_san_pair() -> (quinn::Endpoint, quinn_btls::ClientConfig) {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let pem = cert.cert.pem();
        let server = server_crypto(&pem, &cert.key_pair.serialize_pem(), &[]).unwrap();
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(server).unwrap()),
            Default::default(),
        )
        .unwrap();
        (
            server,
            client_crypto(
                Some(&pem),
                false,
                &[],
                &crate::transport::tls::tests::test_roots(),
            )
            .unwrap(),
        )
    }

    /// Dials `server` as `server_name`: the SNI the server saw, if the
    /// handshake succeeds.
    async fn dial(
        server: &quinn::Endpoint,
        crypto: quinn_btls::ClientConfig,
        server_name: &str,
    ) -> Result<Option<String>> {
        Ok(handshake(server, Arc::new(crypto), server_name)
            .await?
            .server_name)
    }

    /// Dials `server` as `server_name`: what the server saw of the
    /// handshake, if it succeeds.
    async fn handshake(
        server: &quinn::Endpoint,
        crypto: Arc<quinn_btls::ClientConfig>,
        server_name: &str,
    ) -> Result<quinn_btls::HandshakeData> {
        let client = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            None,
            Default::default(),
        )
        .unwrap();
        let config = quinn::ClientConfig::new(crypto);
        let accept = async {
            let conn = server.accept().await.unwrap().await?;
            let data = conn.handshake_data().unwrap();
            let data = data.downcast::<quinn_btls::HandshakeData>().unwrap();
            Ok::<_, quinn::ConnectionError>(*data)
        };
        let connect = async {
            let connecting =
                client.connect_with(config, server.local_addr().unwrap(), server_name)?;
            Ok::<_, anyhow::Error>(connecting.await?)
        };
        let (served, conn) = tokio::join!(accept, connect);
        conn?;
        Ok(served?)
    }

    /// A server for `sans` that decrypts ECH with `ech`.
    fn ech_server(
        sans: &[&str],
        ech: &crate::transport::tls::tests::EchKeys,
    ) -> (quinn::Endpoint, String) {
        let cert = rcgen::generate_simple_self_signed(
            sans.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        let pem = cert.cert.pem();
        let crypto = server_crypto(&pem, &cert.key_pair.serialize_pem(), &[]).unwrap();
        ech.serve(crypto.ctx());
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(crypto).unwrap()),
            Default::default(),
        )
        .unwrap();
        (server, pem)
    }

    fn ech_client(pem: &str, ech: serde_json::Value) -> Result<ClientTls> {
        let tls: OutboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true, "server_name": "secret.example", "certificate": pem, "ech": ech,
        }))
        .unwrap();
        ClientTls::new(&tls, "127.0.0.1", &[], &RuntimeEnv::default())
    }

    fn no_dns() -> SyncDnsClient {
        crate::app::dns::DnsClient::new(
            &Default::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared()
    }

    /// A DNS client of a server on loopback answering every query
    /// NXDOMAIN.
    async fn nxdomain_dns() -> SyncDnsClient {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let mut reply = buf[..n].to_vec();
                reply[2] |= 0x80;
                reply[3] = (reply[3] & 0xf0) | 3;
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": { "timeout": "2s", "servers": [
                { "type": "udp", "tag": "u", "server": "127.0.0.1", "server_port": port },
            ] } })
            .to_string(),
        )
        .unwrap();
        crate::app::dns::DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared()
    }

    /// With `tls.ech.config`, the ClientHello the server answers is the
    /// encrypted one, with the server name: the outer one has the
    /// config's public name.
    #[tokio::test]
    async fn ech_over_quic_hides_the_server_name() {
        let ech = crate::transport::tls::tests::EchKeys::new("public.example", &[7; 32]);
        let (server, pem) = ech_server(&["secret.example"], &ech);
        let tls = ech_client(
            &pem,
            serde_json::json!({"enabled": true, "config": ech.config}),
        )
        .unwrap();
        assert!(!tls.ech_lookup);
        let crypto = tls.connection_crypto(&no_dns()).await.unwrap();
        let served = handshake(&server, crypto, &tls.server_name).await.unwrap();
        assert!(served.ech_accepted);
        assert_eq!(served.server_name.as_deref(), Some("secret.example"));

        // PEM, as sing-box writes it, is taken too.
        let pem_config = format!(
            "-----BEGIN ECH CONFIGS-----\n{}\n-----END ECH CONFIGS-----",
            ech.config
        );
        let tls = ech_client(
            &pem,
            serde_json::json!({"enabled": true, "config": [pem_config]}),
        )
        .unwrap();
        let crypto = tls.connection_crypto(&no_dns()).await.unwrap();
        assert!(
            handshake(&server, crypto, &tls.server_name)
                .await
                .unwrap()
                .ech_accepted
        );

        // Without it, there is none.
        let tls = ech_client(
            &pem,
            serde_json::json!({"enabled": false, "config": ech.config}),
        )
        .unwrap();
        let crypto = tls.connection_crypto(&no_dns()).await.unwrap();
        assert!(
            !handshake(&server, crypto, &tls.server_name)
                .await
                .unwrap()
                .ech_accepted
        );
    }

    /// A server that cannot decrypt the ECHConfig fails the handshake, as
    /// over TCP and in sing-box: no retry, nor a connection without ECH.
    #[tokio::test]
    async fn a_rejected_ech_over_quic_fails_the_handshake() {
        let ech = crate::transport::tls::tests::EchKeys::new("public.example", &[7; 32]);
        let stale = crate::transport::tls::tests::EchKeys::new("public.example", &[8; 32]);
        let (server, pem) = ech_server(&["secret.example", "public.example"], &ech);
        let tls = ech_client(
            &pem,
            serde_json::json!({"enabled": true, "config": stale.config}),
        )
        .unwrap();
        let crypto = tls.connection_crypto(&no_dns()).await.unwrap();
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handshake(&server, crypto, &tls.server_name),
        )
        .await
        .expect("the handshake fails, not hangs")
        .unwrap_err();
        assert!(err.to_string().contains("ECH"), "{}", err);
    }

    /// Without `config`, each connection asks DNS for the server name's
    /// ECHConfigList, and one DNS does not give fails the connection.
    #[tokio::test]
    async fn without_a_configured_ech_config_a_failed_lookup_fails_over_quic() {
        let pem = crate::transport::tls::tests::self_signed_pem();
        let tls = ech_client(&pem, serde_json::json!({"enabled": true})).unwrap();
        assert!(tls.ech_lookup);
        let err = tls
            .connection_crypto(&nxdomain_dns().await)
            .await
            .err()
            .expect("the lookup fails");
        assert!(
            err.to_string()
                .contains("ech fetch failed for secret.example"),
            "{}",
            err
        );
    }

    #[test]
    fn ech_configs_over_quic_are_checked_at_start() {
        let pem = crate::transport::tls::tests::self_signed_pem();
        let err =
            |ech: serde_json::Value| ech_client(&pem, ech).map(|_| ()).unwrap_err().to_string();
        assert_eq!(
            err(serde_json::json!({"enabled": true, "disable_dns_lookup": true})),
            "ech.disable_dns_lookup: needs ech.config"
        );
        assert_eq!(
            err(serde_json::json!({"enabled": true, "config": "   "})),
            "ech.config: cannot be empty"
        );
        assert!(
            err(serde_json::json!({"enabled": true, "config": "$$$"})).starts_with("ech.config: ")
        );
        // A list BoringSSL cannot parse: its one ECHConfig is cut short.
        assert!(
            err(serde_json::json!({"enabled": true, "config": "AAT+DQBB"}))
                .starts_with("ech.config: not an ECHConfigList")
        );
    }

    /// A client that sends its Initial and falls silent is dropped once the
    /// handshake's time is up, not held until the idle timeout.
    #[tokio::test]
    async fn a_silent_client_is_dropped_at_the_handshake_timeout() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(
                server_config(server_crypto(&pem, &cert.key_pair.serialize_pem(), &[]).unwrap())
                    .unwrap(),
            ),
            Default::default(),
        )
        .unwrap();
        // The path: the client's first datagram gets through, nothing after.
        let path = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let path_addr = path.local_addr().unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (n, _) = path.recv_from(&mut buf).await.unwrap();
            path.send_to(&buf[..n], server_addr).await.unwrap();
            while path.recv_from(&mut buf).await.is_ok() {}
        });
        let client = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            None,
            Default::default(),
        )
        .unwrap();
        let roots = crate::transport::tls::tests::test_roots();
        let crypto = client_crypto(Some(&pem), false, &[b"h3".to_vec()], &roots).unwrap();
        let _connecting = client
            .connect_with(
                quinn::ClientConfig::new(Arc::new(crypto)),
                path_addr,
                "localhost",
            )
            .unwrap();
        let incoming = tokio::time::timeout(std::time::Duration::from_secs(5), server.accept())
            .await
            .expect("the Initial reaches the server")
            .unwrap();
        let started = std::time::Instant::now();
        let handshake = crate::transport::quic::server_handshake(
            incoming.accept().unwrap(),
            std::time::Duration::from_millis(300),
        )
        .await;
        let error = handshake.expect_err("a silent client completed a handshake");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the handshake waited {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn client_certificate_when_the_server_asks() {
        use quinn_btls::QuicSslContext;
        let pki = crate::transport::tls::tests::client_pki();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = cert.cert.pem();
        let mut server = server_crypto(&pem, &cert.key_pair.serialize_pem(), &[]).unwrap();
        let ctx = server.ctx_mut();
        ctx.cert_store_mut()
            .add_cert(btls::x509::X509::from_pem(pki.ca.as_bytes()).unwrap())
            .unwrap();
        ctx.verify_peer(true);
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(server).unwrap()),
            Default::default(),
        )
        .unwrap();
        let roots = crate::transport::tls::tests::test_roots();
        let tls: OutboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true, "certificate": pem,
            "client_certificate": pki.cert, "client_key": pki.key
        }))
        .unwrap();
        let env = RuntimeEnv::default();
        let with = ClientTls::new(&tls, "localhost", &["h3"], &env).unwrap();
        assert_eq!(
            dial(&server, with.crypto, "localhost").await.unwrap(),
            Some("localhost".into())
        );
        let without = client_crypto(Some(&pem), false, &[b"h3".to_vec()], &roots).unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dial(&server, without, "localhost"),
        )
        .await
        .expect("the handshake fails, not hangs");
        assert!(result.is_err(), "{:?}", result);
    }

    // The pins take a server as over TCP: by its key, in place of the
    // roots, the name and `insecure`.
    #[tokio::test]
    async fn pinned_keys_over_quic() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = server_crypto(&cert.cert.pem(), &cert.key_pair.serialize_pem(), &[]).unwrap();
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(server).unwrap()),
            Default::default(),
        )
        .unwrap();
        let pin = crate::transport::tls::tests::spki_pin(&cert.key_pair.public_key_der());
        let other = btls::base64::encode_block(&[9; 32]);
        let env = RuntimeEnv::default();
        let crypto = |pins: &[&str], insecure: bool| {
            let tls: OutboundTls = serde_json::from_value(serde_json::json!({
                "enabled": true, "insecure": insecure,
                "certificate_public_key_sha256": pins,
            }))
            .unwrap();
            ClientTls::new(&tls, "example.com", &["h3"], &env)
                .unwrap()
                .crypto
        };
        for insecure in [false, true] {
            let sni = dial(&server, crypto(&[&other, &pin], insecure), "example.com").await;
            assert_eq!(sni.unwrap(), Some("example.com".into()));
            let refused = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                dial(&server, crypto(&[&other], insecure), "example.com"),
            )
            .await
            .expect("the handshake fails, not hangs");
            assert!(refused.is_err(), "insecure {}: {:?}", insecure, refused);
        }
    }

    // As over TCP, a certificate's validity is checked at the instance's
    // time: the handshake is run by the tasks quinn spawns, which are the
    // instance's (`ScopedRuntime`).
    #[tokio::test]
    async fn a_certificate_is_valid_at_the_instance_s_time() {
        use crate::transport::tls::tests::{scope_at, valid_in_2100, IN_2100};
        let (pem, key) = valid_in_2100();
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(server_crypto(&pem, &key, &[]).unwrap()).unwrap()),
            Default::default(),
        )
        .unwrap();
        let roots = crate::transport::tls::tests::test_roots();
        let crypto = || client_crypto(Some(&pem), false, &[], &roots).unwrap();
        let today = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dial(&server, crypto(), "localhost"),
        )
        .await
        .expect("the handshake fails, not hangs");
        assert!(today.is_err(), "{:?}", today);
        // The client's endpoint is made in the scope: what quinn spawns
        // for it is the scope's.
        let then = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            scope_at(IN_2100).enter(dial(&server, crypto(), "localhost")),
        )
        .await
        .expect("the handshake ends");
        assert_eq!(then.unwrap(), Some("localhost".into()));
    }

    // Pinned certificates take a server as over TCP: the leaf's for any
    // name, a CA's for the name the leaf is for; `insecure` or not.
    #[tokio::test]
    async fn pinned_certificates_over_quic() {
        let chain = crate::transport::tls::tests::cert_chain();
        let pem = format!("{}{}{}", chain.leaf, chain.intermediate, chain.root);
        let server = server_crypto(&pem, &chain.leaf_key, &[]).unwrap();
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(server).unwrap()),
            Default::default(),
        )
        .unwrap();
        let env = RuntimeEnv::default();
        let crypto = |pins: &[&str], insecure: bool, name: &str| {
            let tls: OutboundTls = serde_json::from_value(serde_json::json!({
                "enabled": true, "insecure": insecure, "certificate_sha256": pins,
            }))
            .unwrap();
            ClientTls::new(&tls, name, &["h3"], &env).unwrap().crypto
        };
        for insecure in [false, true] {
            for (pin, name, taken) in [
                (&chain.leaf_pin, "localhost", true),
                (&chain.leaf_pin, "example.com", true),
                (&chain.root_pin, "localhost", true),
                (&chain.root_pin, "example.com", false),
                (&chain.unrelated_pin, "localhost", false),
            ] {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    dial(&server, crypto(&[pin.as_str()], insecure, name), name),
                )
                .await
                .expect("the handshake ends, not hangs");
                assert_eq!(
                    result.is_ok(),
                    taken,
                    "{} {} {}: {:?}",
                    pin,
                    name,
                    insecure,
                    result
                );
            }
        }
    }

    #[test]
    fn versions_over_quic() {
        let client = |json: serde_json::Value| {
            let tls: OutboundTls = serde_json::from_value(json).unwrap();
            ClientTls::new(&tls, "localhost", &[], &RuntimeEnv::default())
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        assert!(client(serde_json::json!({"enabled": true, "min_version": "1.3"})).is_ok());
        assert!(client(serde_json::json!({"enabled": true, "min_version": "1.0"})).is_ok());
        assert_eq!(
            client(serde_json::json!({"enabled": true, "max_version": "1.2"})),
            Err("max_version: QUIC is TLS 1.3 only, and 1.2 leaves it out".into())
        );
        let tls: InboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true, "max_version": "1.2", "certificate": "x", "key": "y",
        }))
        .unwrap();
        let err = inbound_crypto("i", &tls, &RuntimeEnv::default(), &[], &Default::default())
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "[i] inbound: tls.max_version: QUIC is TLS 1.3 only, and 1.2 leaves it out"
        );
    }

    /// How a server of `tls`, an inbound's block, takes a client presenting
    /// `identity`, if any: `None` if taken, or the code the client is
    /// closed with.
    async fn served_over_quic(
        crypto: quinn_btls::ServerConfig,
        server_pem: &str,
        identity: Option<&Identity>,
    ) -> Option<quinn::TransportErrorCode> {
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(crypto).unwrap()),
            Default::default(),
        )
        .unwrap();
        let mut crypto = client_crypto(
            Some(server_pem),
            false,
            &[],
            &crate::transport::tls::tests::test_roots(),
        )
        .unwrap();
        if let Some(identity) = identity {
            present(&mut crypto, identity).unwrap();
        }
        let client = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            None,
            Default::default(),
        )
        .unwrap();
        let config = quinn::ClientConfig::new(Arc::new(crypto));
        let accept = async { server.accept().await.unwrap().await.map(|_| ()) };
        let connect = async {
            client
                .connect_with(config, server.local_addr().unwrap(), "localhost")
                .unwrap()
                .await
        };
        let (served, connected) = tokio::join!(accept, connect);
        if served.is_ok() {
            return None;
        }
        let closed = match connected {
            Ok(conn) => conn.closed().await,
            Err(e) => e,
        };
        match closed {
            quinn::ConnectionError::ConnectionClosed(close) => Some(close.error_code),
            other => panic!("closed otherwise: {:?}", other),
        }
    }

    /// A QUIC inbound checks clients' certificates as over TCP, by sail's
    /// own verification: a certificate its CA issued is taken, a client
    /// without one is refused under require-and-verify, and one the
    /// context's own store trusts, as the system's roots would a public
    /// CA's, is refused when it is not of the configured CA, with the
    /// bad_certificate alert sail's check sends.
    #[tokio::test]
    async fn a_quic_inbound_checks_clients_certificates_by_its_own_cas() {
        use crate::transport::tls::tests::ClientCa;
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = server.cert.pem();
        let (ca, public) = (
            ClientCa::new("sail test client CA"),
            ClientCa::new("sail test public CA"),
        );
        let crypto = || {
            let tls: InboundTls = serde_json::from_value(serde_json::json!({
                "enabled": true,
                "certificate": pem,
                "key": server.key_pair.serialize_pem(),
                "client_authentication": "require-and-verify",
                "client_certificate": ca.pem,
            }))
            .unwrap();
            let mut crypto =
                inbound_crypto("i", &tls, &RuntimeEnv::default(), &[], &Default::default())
                    .unwrap();
            // The public CA is in the context's store.
            let public = btls::x509::X509::from_pem(public.pem.as_bytes()).unwrap();
            crate::transport::tls::configure_quic_server(&mut crypto, |builder| {
                builder.cert_store_mut().add_cert(public).unwrap()
            });
            crypto
        };
        let identity = |cert: &crate::transport::tls::tests::ClientCert| cert.identity(&[]);
        let valid = identity(&ca.issue());
        let by_public = identity(&public.issue());
        assert_eq!(served_over_quic(crypto(), &pem, Some(&valid)).await, None);
        assert!(served_over_quic(crypto(), &pem, None).await.is_some());
        assert_eq!(
            served_over_quic(crypto(), &pem, Some(&by_public)).await,
            Some(quinn::TransportErrorCode::crypto(42))
        );
        // Which the context's own verification takes: it is sail's that
        // refuses it.
        let mut own = server_crypto(&pem, &server.key_pair.serialize_pem(), &[]).unwrap();
        let public_ca = btls::x509::X509::from_pem(public.pem.as_bytes()).unwrap();
        crate::transport::tls::configure_quic_server(&mut own, |builder| {
            builder.cert_store_mut().add_cert(public_ca).unwrap()
        });
        own.verify_peer(true);
        assert_eq!(served_over_quic(own, &pem, Some(&by_public)).await, None);
    }

    /// Pins over QUIC, and verify-if-given taking a client without a
    /// certificate.
    #[tokio::test]
    async fn a_quic_inbound_takes_clients_by_pins() {
        use crate::transport::tls::tests::ClientCa;
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = server.cert.pem();
        let cert = ClientCa::new("sail test client CA").issue();
        let other = ClientCa::new("sail test other CA").issue();
        let tls: InboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "certificate": pem,
            "key": server.key_pair.serialize_pem(),
            "client_authentication": "verify-if-given",
            "client_certificate_sha256": [cert.pin()],
        }))
        .unwrap();
        let crypto =
            || inbound_crypto("i", &tls, &RuntimeEnv::default(), &[], &Default::default()).unwrap();
        assert_eq!(
            served_over_quic(crypto(), &pem, Some(&cert.identity(&[]))).await,
            None
        );
        assert_eq!(served_over_quic(crypto(), &pem, None).await, None);
        assert_eq!(
            served_over_quic(crypto(), &pem, Some(&other.identity(&[]))).await,
            Some(quinn::TransportErrorCode::crypto(42))
        );
    }

    /// Whether a client of `client` connects to a server of `crypto` asking
    /// for `name`, and the server takes it.
    async fn connects_over_quic(
        crypto: quinn_btls::ServerConfig,
        client: quinn_btls::ClientConfig,
        name: &str,
    ) -> bool {
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config(crypto).unwrap()),
            Default::default(),
        )
        .unwrap();
        let client_endpoint = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            None,
            Default::default(),
        )
        .unwrap();
        let config = quinn::ClientConfig::new(Arc::new(client));
        // Each connection is held until both ends are done.
        let accept = async { server.accept().await.unwrap().await };
        let connect = async {
            client_endpoint
                .connect_with(config, server.local_addr().unwrap(), name)
                .unwrap()
                .await
        };
        // A refused handshake ends both, not hangs.
        let (served, connected) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(accept, connect)
        })
        .await
        .expect("the handshake ends");
        served.is_ok() && connected.is_ok()
    }

    /// A QUIC inbound with `self_signed` (Hysteria2's, TUIC's, the quic
    /// transport's) serves the certificate it made for `server_name`, made
    /// once: a client skipping verification takes it, and so does one
    /// trusting that certificate alone, by the name.
    #[tokio::test]
    async fn a_self_signed_quic_inbound_serves_its_own_certificate() {
        let tls: InboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true, "self_signed": true, "server_name": "example.com",
        }))
        .unwrap();
        let made = crate::transport::tls::self_signed::Slot::default();
        let crypto = || inbound_crypto("i", &tls, &RuntimeEnv::default(), &[], &made).unwrap();
        let first = crypto();
        let pem = made.certificate().unwrap();
        let insecure =
            client_crypto(None, true, &[], &crate::transport::tls::tests::test_roots()).unwrap();
        assert!(connects_over_quic(first, insecure, "example.com").await);
        let trusting = || {
            client_crypto(
                Some(&pem),
                false,
                &[],
                &crate::transport::tls::tests::test_roots(),
            )
            .unwrap()
        };
        assert!(connects_over_quic(crypto(), trusting(), "example.com").await);
        assert!(!connects_over_quic(crypto(), trusting(), "other.example").await);
        assert_eq!(made.certificate(), Some(pem.clone()));
        let names: Vec<String> = btls::x509::X509::from_pem(pem.as_bytes())
            .unwrap()
            .subject_alt_names()
            .unwrap()
            .iter()
            .filter_map(|n| n.dnsname().map(str::to_owned))
            .collect();
        assert_eq!(names, ["example.com"]);
        // With a key of its own, an error.
        let tls: InboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true, "self_signed": true, "key_path": "key.pem",
        }))
        .unwrap();
        let err = inbound_crypto("i", &tls, &RuntimeEnv::default(), &[], &made)
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "[i] inbound: tls.self_signed: not with tls.key_path: the certificate is made, not \
             given"
        );
    }

    /// REALITY on a QUIC inbound is an error, which sing-box only finds at
    /// start.
    #[test]
    fn no_reality_over_quic() {
        let tls: InboundTls = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "reality": {
                "enabled": true,
                "private_key": "x",
                "short_id": ["0123"],
                "handshake": { "server": "example.com", "server_port": 443 },
            },
        }))
        .unwrap();
        let err = inbound_crypto("i", &tls, &RuntimeEnv::default(), &[], &Default::default())
            .err()
            .unwrap();
        assert_eq!(
            err.to_string(),
            "[i] inbound: tls.reality: REALITY is TCP-only, not for QUIC"
        );
    }

    /// The limit grows with the streams open at once after authentication,
    /// not before, and not with how many have come and gone.
    #[test]
    fn the_limit_follows_the_streams_open_at_once() {
        use std::sync::Mutex;
        let raised = Arc::new(Mutex::new(Vec::new()));
        let limit = {
            let raised = raised.clone();
            StreamLimit::new(move |n| raised.lock().unwrap().push(n))
        };
        // Before authentication, however many are open.
        let held: Vec<_> = (0..STREAMS_BEFORE_AUTH).map(|_| limit.opened()).collect();
        assert_eq!(limit.limit(), u64::from(STREAMS_BEFORE_AUTH));
        drop(held);
        limit.authenticated();
        // One at a time, far more than any limit: it stays.
        for _ in 0..10_000 {
            drop(limit.opened());
        }
        assert_eq!(limit.limit(), u64::from(STREAMS_BEFORE_AUTH));
        assert!(raised.lock().unwrap().is_empty());
        // Many at once: it doubles as three quarters are open, to the
        // ceiling and no further.
        let held: Vec<_> = (0..100_000).map(|_| limit.opened()).collect();
        assert_eq!(limit.limit(), STREAMS_CEILING);
        assert_eq!(
            *raised.lock().unwrap(),
            [200, 400, 800, 1600, 3200, 6400, 12800, 25600, 51200, 65536]
        );
        drop(held);
    }

    /// Not a test: what one server connection costs with
    /// `SAIL_MEASURE_STREAMS` streams of each kind allowed (100 unset),
    /// 200 connections from clients that allow none, in RSS.
    /// `cargo test -p sail --lib measure_connection_memory -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn measure_connection_memory() {
        const CONNECTIONS: u64 = 200;
        let rss_kb = || {
            let out = std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u64>()
                .unwrap()
        };
        let streams: u32 = std::env::var("SAIL_MEASURE_STREAMS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = server_config(
            server_crypto(&cert.cert.pem(), &cert.key_pair.serialize_pem(), &[]).unwrap(),
        )
        .unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(streams.into())
            .max_concurrent_uni_streams(streams.into());
        server_config.transport_config(Arc::new(transport));
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config),
            Default::default(),
        )
        .unwrap();
        let client = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            None,
            Default::default(),
        )
        .unwrap();
        let roots = crate::transport::tls::tests::test_roots();
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(client_crypto(None, true, &[], &roots).unwrap()));
        let mut none = quinn::TransportConfig::default();
        none.max_concurrent_bidi_streams(0u32.into())
            .max_concurrent_uni_streams(0u32.into());
        client_config.transport_config(Arc::new(none));
        let before = rss_kb();
        let mut held = Vec::new();
        for _ in 0..CONNECTIONS {
            let connecting = client
                .connect_with(
                    client_config.clone(),
                    server.local_addr().unwrap(),
                    "localhost",
                )
                .unwrap();
            let (accepted, connected) = tokio::join!(
                async { server.accept().await.unwrap().await.unwrap() },
                connecting
            );
            held.push((accepted, connected.unwrap()));
        }
        let after = rss_kb();
        println!(
            "MEASURE streams={} rss_before={}KB rss_after={}KB per_connection={}KB",
            streams,
            before,
            after,
            (after.saturating_sub(before)) / CONNECTIONS
        );
    }

    /// Bytes held, out of no limit.
    #[derive(Default)]
    struct Held(std::sync::Mutex<u64>);

    impl quinn::WindowBudget for Held {
        fn try_grow(&self, bytes: u64) -> bool {
            *self.0.lock().unwrap() += bytes;
            true
        }

        fn release(&self, bytes: u64) {
            *self.0.lock().unwrap() -= bytes;
        }
    }

    #[tokio::test]
    async fn a_stalled_stream_is_reset_at_the_stall_timeout_and_repays_its_loan() {
        let budget = Arc::new(Held::default());
        let held = || *budget.0.lock().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server_config = server_config(
            server_crypto(&cert.cert.pem(), &cert.key_pair.serialize_pem(), &[]).unwrap(),
        )
        .unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport
            .receive_window((96u32 << 10).into())
            .stream_receive_window((64u32 << 10).into())
            .window_tuning(Some(
                quinn::WindowTuning::new((64u32 << 10).into(), (96u32 << 10).into(), 1 << 20)
                    .budget(budget.clone())
                    .credit_on_receipt(true),
            ));
        server_config.transport_config(Arc::new(transport));
        let server = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            Some(server_config),
            Default::default(),
        )
        .unwrap();
        let client = endpoint(
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
            None,
            Default::default(),
        )
        .unwrap();
        let roots = crate::transport::tls::tests::test_roots();
        let client_config =
            quinn::ClientConfig::new(Arc::new(client_crypto(None, true, &[], &roots).unwrap()));
        let connecting = client
            .connect_with(client_config, server.local_addr().unwrap(), "localhost")
            .unwrap();
        let (accepted, connected) = tokio::join!(
            async { server.accept().await.unwrap().await.unwrap() },
            connecting
        );
        let connected = connected.unwrap();
        let (mut send, _recv) = connected.open_bi().await.unwrap();
        let writer = tokio::spawn(async move {
            let _ = send.write_all(&vec![0; 1 << 20]).await;
            send
        });
        let (send, recv) = accepted.accept_bi().await.unwrap();
        // Accepted and never read, as by a relay whose client stopped reading
        let timeout = std::time::Duration::from_millis(800);
        let _stream = Guarded::new(Halves { send, recv }, "quic", timeout, "".into());
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(held(), 64 << 10, "the stream's window, lent");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(held(), 64 << 10, "not reset before the timeout");
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        assert_eq!(held(), 0, "reset, and the loan repaid");
        writer.abort();
    }

    #[test]
    fn no_disable_sni_over_quic_yet() {
        let tls: OutboundTls =
            serde_json::from_value(serde_json::json!({"enabled": true, "disable_sni": true}))
                .unwrap();
        let err = ClientTls::new(&tls, "localhost", &[], &RuntimeEnv::default())
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "disable_sni: not over QUIC yet");
    }

    #[tokio::test]
    async fn ip_server_name_sends_no_sni_and_verifies_ip_san() {
        let (server, crypto) = ip_san_pair();
        // RFC 6066 forbids IP literals in SNI.
        assert_eq!(dial(&server, crypto, "127.0.0.1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn ip_server_name_not_in_certificate_fails() {
        let (server, crypto) = ip_san_pair();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dial(&server, crypto, "127.0.0.2"),
        )
        .await
        .expect("the handshake fails, not hangs");
        assert!(result.is_err(), "{:?}", result);
    }
}
