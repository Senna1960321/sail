//! Encrypted DNS servers: DNS over TLS (`tls`, RFC 7858), over HTTPS
//! (`https`, RFC 8484), over QUIC (`quic`, RFC 9250) and over HTTP/3
//! (`h3`, RFC 8484 on HTTP/3).
//!
//! Each server keeps its connections for the next query, so that the
//! handshake is paid once, not per query: DoT pipelines queries on a
//! bounded pool, DoH keeps one HTTP/2 connection, or idle HTTP/1.1 ones when
//! the server does not speak HTTP/2, and DoQ and DoH3 keep one QUIC
//! connection and open a stream per query on it.

use std::fmt;
use std::sync::Arc;
#[cfg(feature = "tls")]
use std::time::Duration;
use std::time::Instant;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::server::{Address, Dialer};
use crate::adapter::AnyStream;
use crate::runtime::RuntimeEnv;
use crate::transport::layers::OutboundTls;

#[cfg(feature = "dns-doh")]
mod doh;
#[cfg(feature = "tls")]
mod dot;
#[cfg(all(feature = "dns-doh", feature = "dns-h3"))]
mod hybrid;
#[cfg(feature = "quic")]
mod quic;

/// The largest DNS message: its length is a 16-bit field in DoT and DoQ,
/// and DoH answers are held to it too.
#[cfg(any(feature = "quic", feature = "dns-doh"))]
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

tokio::task_local! {
    /// What an attempt of a `sequential` server allows a kept connection,
    /// within it: see `kept_wait` and `kept_timed_out`.
    pub(super) static ATTEMPT: Attempt;
}

/// An attempt of a `sequential` server on one member.
pub(super) struct Attempt {
    /// How long a kept connection may take to answer; `None` requires a
    /// replacement. Pipelined DoT retries share one that a sibling opened.
    pub reuse: Option<std::time::Duration>,
    /// Set when a kept connection timed out, which ends the attempt: the
    /// server is asked again on a new connection, with a whole attempt's
    /// time, rather than with what the kept one left.
    pub kept_timed_out: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// How long a kept connection may take to answer, `default` outside a
/// sequential attempt; `None` when none is to be taken.
pub(super) fn kept_wait(default: std::time::Duration) -> Option<std::time::Duration> {
    ATTEMPT.try_with(|a| a.reuse).unwrap_or(Some(default))
}

/// Says that a kept connection timed out; whether the query is to end
/// there, as in a sequential attempt, rather than go on to a new one.
pub(super) fn kept_timed_out() -> bool {
    ATTEMPT
        .try_with(|a| {
            a.kept_timed_out
                .store(true, std::sync::atomic::Ordering::Relaxed)
        })
        .is_ok()
}

/// Idle connections kept per server: as many as queries that ran at once,
/// up to this.
const MAX_IDLE: usize = 4;
/// How long a connection is kept idle. Servers close theirs after some
/// seconds (RFC 7766 §6.2.3 suggests 10), and a connection they closed
/// costs a failed query before a new one.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The task that drives a connection queries take streams on (HTTP/2,
/// HTTP/3), shared by the pool and each query on it: stopped when the last
/// of them lets go, so that the pool can give a connection up without
/// cutting the queries still on it, or at once with `stop`.
#[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
pub(super) struct Driver(tokio::task::AbortHandle);

#[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
impl Driver {
    pub(super) fn new(handle: tokio::task::AbortHandle) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Driver(handle))
    }

    pub(super) fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    /// Stops it now, the queries on it too.
    pub(super) fn stop(&self) {
        self.0.abort();
    }
}

#[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The idle connections of a server that sends its messages on a stream:
/// TCP and DoH on HTTP/1.1.
#[derive(Default)]
pub(super) struct StreamPool {
    idle: std::sync::Mutex<Vec<(AnyStream, Instant)>>,
}

impl StreamPool {
    /// The connection idle for the least time, if one is still fresh.
    pub(super) fn take(&self) -> Option<AnyStream> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        idle.retain(|(_, since)| now.saturating_duration_since(*since) < IDLE_TIMEOUT);
        idle.pop().map(|(stream, _)| stream)
    }

    /// Drops every connection kept: those of a network gone.
    pub(super) fn clear(&self) {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub(super) fn put(&self, stream: AnyStream) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() >= MAX_IDLE {
            idle.remove(0);
        }
        idle.push((stream, Instant::now()));
    }
}

/// Writes `request` and reads the answer that follows, each prefixed with
/// its length (RFC 1035 §4.2.2).
pub(super) async fn exchange_framed(stream: &mut AnyStream, request: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(request.len()).map_err(|_| anyhow!("dns query too long"))?;
    let mut buf = Vec::with_capacity(2 + request.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(request);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    let len = stream.read_u16().await? as usize;
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Protocol {
    /// DNS over TLS.
    Tls,
    /// DNS over HTTPS, on HTTP/2 or HTTP/1.1.
    Https,
    /// DNS over QUIC.
    Quic,
    /// DNS over HTTP/3.
    H3,
}

impl Protocol {
    /// The protocol of a server type, which the caller has matched.
    pub fn of(kind: &str) -> Self {
        match kind {
            "tls" => Self::Tls,
            "https" => Self::Https,
            "quic" => Self::Quic,
            _ => Self::H3,
        }
    }

    fn scheme(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
            Self::H3 => "h3",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Tls | Self::Quic => 853,
            Self::Https | Self::H3 => 443,
        }
    }
}

/// One encrypted server, and the connections it keeps.
pub(super) struct Upstream {
    pub protocol: Protocol,
    pub address: Address,
    /// The name the server's certificate is checked against, and sent as
    /// SNI: `tls.server_name`, or else the server's address.
    pub server_name: String,
    /// The request path, for DoH and DoH3.
    pub path: String,
    /// DoH and DoH3: queries as GETs, the message in the URI's `dns`
    /// parameter, rather than POSTs of it (RFC 8484 §4.1).
    #[cfg_attr(not(any(feature = "dns-doh", feature = "dns-h3")), allow(dead_code))]
    get: bool,
    /// DoH and DoH3: the headers each request carries, but `Host`.
    #[cfg_attr(not(any(feature = "dns-doh", feature = "dns-h3")), allow(dead_code))]
    headers: Vec<(String, String)>,
    /// DoH and DoH3: the host a `Host` header names, which the requests
    /// name instead of the server's.
    #[cfg_attr(not(any(feature = "dns-doh", feature = "dns-h3")), allow(dead_code))]
    host: Option<String>,
    #[cfg_attr(not(any(feature = "tls", feature = "quic")), allow(dead_code))]
    pub dialer: Dialer,
    /// The certificates trusted instead of the bundled roots: inline PEM,
    /// or a path.
    #[cfg_attr(not(any(feature = "tls", feature = "quic")), allow(dead_code))]
    pub(super) certificate: Option<String>,
    #[cfg_attr(not(any(feature = "tls", feature = "quic")), allow(dead_code))]
    pub(super) insecure: bool,
    /// The roots of the instance, for no `certificate` of its own.
    #[cfg(feature = "tls")]
    pub(super) roots: crate::transport::tls::roots::Roots,
    /// The ClientHello of DoT and DoH, `tls.utls`: none for DoT and Chrome's
    /// for DoH when unset.
    #[cfg(feature = "tls")]
    fingerprint: Option<crate::transport::tls::Fingerprint>,
    /// The client certificate presented to a server that asks for one,
    /// `tls.client_certificate` and `tls.client_key`.
    #[cfg(feature = "tls")]
    pub(super) identity: Option<Arc<crate::transport::tls::client::Identity>>,
    /// DoT and DoH: no SNI in the ClientHello, `tls.disable_sni`; the
    /// certificate is verified against `server_name` all the same.
    #[cfg(feature = "tls")]
    disable_sni: bool,
    /// The versions offered and the keys pinned, `tls.min_version`,
    /// `tls.max_version`, `tls.certificate_public_key_sha256` and
    /// `tls.certificate_sha256`.
    #[cfg(feature = "tls")]
    pub(super) tls_options: crate::transport::tls::ClientOptions,
    /// The TLS client of DoT and DoH, built on first use.
    #[cfg(feature = "tls")]
    tls_client: std::sync::OnceLock<std::result::Result<crate::transport::tls::TlsClient, String>>,
    state: State,
}

/// The connections an upstream keeps between queries.
enum State {
    #[cfg(feature = "tls")]
    Tls(dot::Pool),
    #[cfg(feature = "dns-doh")]
    Https(doh::Pool),
    #[cfg(feature = "quic")]
    Quic(quic::Pool),
    #[cfg(feature = "dns-h3")]
    H3(quic::Pool),
    /// `https` with `prefer_h3`.
    #[cfg(all(feature = "dns-doh", feature = "dns-h3"))]
    Hybrid(hybrid::Hybrid),
}

impl fmt::Debug for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Upstream({})", self)
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.protocol.scheme(), self.address)?;
        if self.has_path() {
            write!(f, "{}", self.path)?;
        }
        if self.server_name != self.address.host {
            write!(f, " ({})", self.server_name)?;
        }
        Ok(())
    }
}

impl Upstream {
    pub fn new(
        protocol: Protocol,
        address: Address,
        dialer: Dialer,
        path: Option<String>,
        headers: &std::collections::BTreeMap<String, crate::config::model::HeaderValues>,
        tls: Option<&OutboundTls>,
        env: &RuntimeEnv,
    ) -> Result<Self> {
        if !headers.is_empty() && !matches!(protocol, Protocol::Https | Protocol::H3) {
            return Err(anyhow!("headers: only https and h3 servers take them"));
        }
        crate::config::model::check_headers(headers)?;
        let mut host = None;
        let mut lines = Vec::new();
        for (name, value) in crate::config::model::header_lines(headers) {
            if name.eq_ignore_ascii_case("host") {
                host = Some(value);
            } else if ["content-length", "transfer-encoding"]
                .iter()
                .any(|n| name.eq_ignore_ascii_case(n))
            {
                return Err(anyhow!("headers: {} is sail's to set", name));
            } else {
                lines.push((name, value));
            }
        }
        let path = match path {
            Some(path) => {
                Self::check_path(&path)?;
                path
            }
            None if matches!(protocol, Protocol::Https | Protocol::H3) => "/dns-query".into(),
            None => String::new(),
        };
        let mut server_name = address.host.clone();
        let mut certificate = None;
        let mut insecure = false;
        #[cfg(feature = "tls")]
        let mut identity = None;
        #[cfg(feature = "tls")]
        let mut disable_sni = false;
        #[cfg(feature = "tls")]
        let mut tls_options = crate::transport::tls::ClientOptions::default();
        #[allow(unused_mut)]
        let mut utls = None;
        if let Some(tls) = tls {
            if tls.reality.is_some() {
                return Err(anyhow!("tls.reality: not for a dns server"));
            }
            if tls.ech.is_some() {
                return Err(anyhow!("tls.ech: not for a dns server"));
            }
            if tls.disable_sni && matches!(protocol, Protocol::Quic | Protocol::H3) {
                // As for QUIC outbounds: quinn-btls sends the SNI of every
                // name but an IP address.
                return Err(anyhow!("tls.disable_sni: not over QUIC yet"));
            }
            #[cfg(feature = "tls")]
            {
                identity = tls
                    .client_identity(env)
                    .map_err(|e| anyhow!("tls.{}", e))?
                    .map(Arc::new);
                disable_sni = tls.disable_sni;
                tls_options = tls.client_options().map_err(|e| anyhow!("tls.{}", e))?;
                // Browsers send the name of a domain: a ClientHello without
                // it is one no browser sends, as for TLS outbounds.
                if disable_sni && tls.utls.as_ref().is_some_and(|u| u.enabled) {
                    tracing::warn!(
                        "tls.disable_sni: the ClientHello, with no SNI, is no longer the one \
                         tls.utls's browser sends"
                    );
                }
            }
            #[cfg(not(feature = "tls"))]
            if tls.disable_sni
                || tls.has_client_certificate()
                || tls.min_version.is_some()
                || tls.max_version.is_some()
                || tls.certificate_public_key_sha256.is_some()
                || tls.certificate_sha256.is_some()
            {
                return Err(anyhow!(
                    "tls: needs the tls feature, which is not compiled in"
                ));
            }
            if tls.alpn.is_some() {
                return Err(anyhow!(
                    "tls.alpn: a {} server offers its own",
                    protocol.scheme()
                ));
            }
            if let Some(name) = tls.server_name.as_ref().filter(|n| !n.is_empty()) {
                server_name = name.clone();
            }
            certificate = crate::transport::layers::trusted_certificate(tls, env);
            insecure = tls.insecure;
            utls = tls.utls.as_ref();
        }
        if matches!(protocol, Protocol::Quic | Protocol::H3) && utls.is_some() {
            return Err(anyhow!("tls.utls: not for a {} server", protocol.scheme()));
        }
        #[cfg(feature = "tls")]
        let fingerprint = match utls {
            Some(utls) if !utls.enabled => None,
            Some(utls) => Some(
                crate::transport::tls::Fingerprint::from_name(&utls.fingerprint)
                    .map_err(|e| anyhow!("tls.utls.fingerprint: {}", e))?,
            ),
            None if protocol == Protocol::Https => Some(crate::transport::tls::Fingerprint::Chrome),
            None => None,
        };
        // A browser's ClientHello offers the browser's versions, as for TLS
        // outbounds; QUIC is TLS 1.3 only.
        #[cfg(feature = "tls")]
        if fingerprint.is_some() {
            if let Some(tls) = tls {
                let context = format!("dns server {}://{}", protocol.scheme(), address);
                tls_options = tls
                    .stream_options(&context)
                    .map_err(|e| anyhow!("tls.{}", e))?;
            }
        } else if matches!(protocol, Protocol::Quic | Protocol::H3) {
            tls_options
                .versions
                .require_tls13(protocol.scheme())
                .map_err(|e| anyhow!("tls.{}", e))?;
        }
        #[cfg(feature = "tls")]
        if let Some(certificate) = &certificate {
            crate::transport::tls::client::load_certificates(certificate)
                .map_err(|e| anyhow!("tls.certificate: {}", e))?;
        }
        let state = State::new(protocol)?;
        Ok(Self {
            protocol,
            address,
            server_name,
            path,
            get: false,
            headers: lines,
            host,
            dialer,
            certificate,
            insecure,
            #[cfg(feature = "tls")]
            fingerprint,
            #[cfg(feature = "tls")]
            identity,
            #[cfg(feature = "tls")]
            disable_sni,
            #[cfg(feature = "tls")]
            tls_options,
            #[cfg(feature = "tls")]
            tls_client: Default::default(),
            #[cfg(feature = "tls")]
            roots: env.tls_roots.get()?,
            state,
        })
    }

    /// Drops the connections it keeps, as the network they were made on is
    /// gone: the next query makes one on the network there is now.
    #[cfg(any(feature = "tls", feature = "quic", feature = "dns-h3"))]
    pub(super) async fn reset(&self) {
        match &self.state {
            #[cfg(feature = "tls")]
            State::Tls(pool) => pool.clear().await,
            #[cfg(feature = "dns-doh")]
            State::Https(pool) => pool.clear().await,
            #[cfg(feature = "quic")]
            State::Quic(pool) => pool.clear().await,
            #[cfg(feature = "dns-h3")]
            State::H3(pool) => pool.clear().await,
            #[cfg(all(feature = "dns-doh", feature = "dns-h3"))]
            State::Hybrid(hybrid) => hybrid.clear().await,
        }
    }

    /// Without the tls and quic features no encrypted server builds.
    #[cfg(not(any(feature = "tls", feature = "quic", feature = "dns-h3")))]
    pub(super) async fn reset(&self) {}

    /// Gives up the connections no query is on now: those of a stream
    /// pool, and a kept HTTP/2, QUIC or HTTP/3 connection, which goes once
    /// the queries on it end. The cache, and prefer_h3's choice, stay.
    #[cfg(any(feature = "tls", feature = "quic", feature = "dns-h3"))]
    pub(super) async fn close_idle(&self) {
        match &self.state {
            #[cfg(feature = "tls")]
            State::Tls(pool) => pool.close_idle().await,
            #[cfg(feature = "dns-doh")]
            State::Https(pool) => pool.close_idle().await,
            #[cfg(feature = "quic")]
            State::Quic(pool) => pool.close_idle().await,
            #[cfg(feature = "dns-h3")]
            State::H3(pool) => pool.close_idle().await,
            #[cfg(all(feature = "dns-doh", feature = "dns-h3"))]
            State::Hybrid(hybrid) => {
                hybrid.h2.close_idle().await;
                hybrid.h3.close_idle().await;
            }
        }
    }

    #[cfg(not(any(feature = "tls", feature = "quic", feature = "dns-h3")))]
    pub(super) async fn close_idle(&self) {}

    /// The TLS client of DoT and DoH.
    #[cfg(feature = "tls")]
    fn tls_client(&self) -> Result<&crate::transport::tls::TlsClient> {
        self.tls_client
            .get_or_init(|| {
                crate::transport::tls::TlsClient::with_options(
                    &[],
                    self.certificate.as_deref(),
                    self.insecure,
                    self.fingerprint,
                    &self.roots,
                    self.identity.as_deref(),
                    &self.tls_options,
                )
                .map(|client| {
                    if self.disable_sni {
                        client.without_sni()
                    } else {
                        client
                    }
                })
                .map_err(|e| e.to_string())
            })
            .as_ref()
            .map_err(|e| anyhow!("tls client: {}", e))
    }

    fn has_path(&self) -> bool {
        matches!(self.protocol, Protocol::Https | Protocol::H3)
    }

    /// The URI a DoH or DoH3 query is posted to.
    #[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
    fn uri(&self) -> String {
        format!("https://{}{}", self.authority(), self.path)
    }

    /// `host[:port]` as an HTTP request names the server: the port only
    /// when it is not 443. A `Host` header names it instead.
    #[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
    fn authority(&self) -> String {
        if let Some(host) = &self.host {
            return host.clone();
        }
        let host = match self.server_name.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(ip)) => format!("[{}]", ip),
            _ => self.server_name.clone(),
        };
        if self.address.port == 443 {
            host
        } else {
            format!("{}:{}", host, self.address.port)
        }
    }

    /// Asks with GETs, `method: GET`.
    pub(super) fn with_get(mut self, get: bool) -> Self {
        self.get = get;
        self
    }

    /// `prefer_h3`, a sail extension, as Mihomo's: an `https` server asked
    /// over HTTP/3 beside HTTP/2, and kept to HTTP/3 once that answers
    /// (see `hybrid`).
    pub(super) fn with_prefer_h3(self, prefer: bool) -> Result<Self> {
        if !prefer {
            return Ok(self);
        }
        if self.protocol != Protocol::Https {
            return Err(anyhow!(
                "prefer_h3: only https servers take it, not {}",
                self.protocol.scheme()
            ));
        }
        #[cfg(all(feature = "dns-doh", feature = "dns-h3"))]
        {
            let mut this = self;
            // As an h3 server's: QUIC is TLS 1.3 only, and sends the SNI.
            if this.disable_sni {
                return Err(anyhow!("prefer_h3: tls.disable_sni is not over QUIC yet"));
            }
            this.tls_options
                .versions
                .require_tls13("prefer_h3's HTTP/3")
                .map_err(|e| anyhow!("tls.{}", e))?;
            this.state = State::Hybrid(hybrid::Hybrid::default());
            Ok(this)
        }
        #[cfg(not(all(feature = "dns-doh", feature = "dns-h3")))]
        Err(anyhow!(
            "prefer_h3: needs the dns-doh and dns-h3 features, which are not both compiled in"
        ))
    }

    /// Whether queries are GETs, with no body.
    #[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
    pub(super) fn get(&self) -> bool {
        self.get
    }

    /// `path`, and for a GET the message in its `dns` parameter,
    /// base64url without padding (RFC 8484 §4.1).
    #[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
    fn target(&self, path: &str, request: &[u8]) -> String {
        use base64::Engine;
        if self.get {
            format!(
                "{}?dns={}",
                path,
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request)
            )
        } else {
            path.to_string()
        }
    }

    /// The request of an HTTP/2 or HTTP/3 query `request`: its own headers
    /// over sail's; a POST of it, or a GET with it in the URI.
    #[cfg(any(feature = "dns-doh", feature = "dns-h3"))]
    pub(super) fn http_request(&self, request: &[u8]) -> Result<http::Request<()>> {
        use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
        const DNS_MESSAGE: &str = "application/dns-message";
        let uri = self.target(&self.uri(), request);
        let mut request = if self.get {
            http::Request::get(uri)
        } else {
            http::Request::post(uri).header(CONTENT_LENGTH, request.len())
        };
        let sent = if self.get {
            &[(ACCEPT, DNS_MESSAGE)][..]
        } else {
            &[(CONTENT_TYPE, DNS_MESSAGE), (ACCEPT, DNS_MESSAGE)][..]
        };
        for (name, value) in sent.iter().cloned() {
            if !self
                .headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(name.as_str()))
            {
                request = request.header(name, value);
            }
        }
        for (name, value) in &self.headers {
            request = request.header(name.as_str(), value.as_str());
        }
        request
            .body(())
            .map_err(|e| anyhow!("invalid request: {}", e))
    }

    /// The head of an HTTP/1.1 query `request`: its own headers over
    /// sail's; a POST's, whose body is it, or a GET's with it in the URI.
    #[cfg(feature = "dns-doh")]
    pub(super) fn http1_head(&self, request: &[u8]) -> String {
        const DNS_MESSAGE: &str = "application/dns-message";
        let mut head = if self.get {
            format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\n",
                self.target(&self.path, request),
                self.authority()
            )
        } else {
            format!(
                "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n",
                self.path,
                self.authority(),
                request.len()
            )
        };
        let sent = if self.get {
            &[("Accept", DNS_MESSAGE)][..]
        } else {
            &[("Content-Type", DNS_MESSAGE), ("Accept", DNS_MESSAGE)][..]
        };
        for &(name, value) in sent {
            if !self
                .headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(name))
            {
                head.push_str(&format!("{}: {}\r\n", name, value));
            }
        }
        for (name, value) in &self.headers {
            head.push_str(&format!("{}: {}\r\n", name, value));
        }
        head.push_str("\r\n");
        head
    }

    /// A path as a request carries it: no query, since the message goes in
    /// the body of a POST, and nothing to escape.
    fn check_path(path: &str) -> Result<()> {
        let valid = path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:%/".contains(&b));
        if !valid {
            return Err(anyhow!("invalid path {:?}", path));
        }
        Ok(())
    }

    /// The query's ID, which DoH, DoQ and DoH3 send as 0 and give back.
    #[cfg(any(feature = "tls", feature = "quic", feature = "dns-h3"))]
    fn message_id(request: &[u8]) -> Result<[u8; 2]> {
        match request {
            [a, b, ..] if request.len() >= 12 => Ok([*a, *b]),
            _ => Err(anyhow!("dns query too short")),
        }
    }
}

impl State {
    fn new(protocol: Protocol) -> Result<Self> {
        match protocol {
            #[cfg(feature = "tls")]
            Protocol::Tls => Ok(Self::Tls(dot::Pool::default())),
            #[cfg(feature = "dns-doh")]
            Protocol::Https => Ok(Self::Https(doh::Pool::default())),
            #[cfg(feature = "quic")]
            Protocol::Quic => Ok(Self::Quic(quic::Pool::new(quic::Kind::Doq))),
            #[cfg(feature = "dns-h3")]
            Protocol::H3 => Ok(Self::H3(quic::Pool::new(quic::Kind::H3))),
            #[allow(unreachable_patterns)]
            _ => Err(anyhow!(
                "a {} server is not supported by this build",
                protocol.scheme()
            )),
        }
    }
}

impl super::DnsClient {
    /// Sends `request` to `upstream` and returns the answer, as it came, but
    /// with the query's ID.
    #[cfg(any(feature = "tls", feature = "quic", feature = "dns-h3"))]
    pub(super) async fn exchange_upstream(
        &self,
        upstream: &Arc<Upstream>,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let id = Upstream::message_id(request)?;
        let addr = self.server_addr(&upstream.address).await?;
        let response: Vec<u8> = match &upstream.state {
            #[cfg(feature = "tls")]
            State::Tls(pool) => self.exchange_dot(upstream, pool, addr, request).await?,
            #[cfg(feature = "dns-doh")]
            State::Https(pool) => self.exchange_doh(upstream, pool, addr, request).await?,
            #[cfg(feature = "quic")]
            State::Quic(pool) => self.exchange_quic(upstream, pool, addr, request).await?,
            #[cfg(feature = "dns-h3")]
            State::H3(pool) => self.exchange_quic(upstream, pool, addr, request).await?,
            #[cfg(all(feature = "dns-doh", feature = "dns-h3"))]
            State::Hybrid(hybrid) => {
                self.exchange_hybrid(upstream, hybrid, addr, request)
                    .await?
            }
        };
        if response.len() < 12 {
            return Err(anyhow!("dns response too short"));
        }
        if response[..2] != id {
            return Err(anyhow!("dns response for another query"));
        }
        Ok(response)
    }

    /// Without the tls and quic features no encrypted server builds, so
    /// there is never one to send to.
    #[cfg(not(any(feature = "tls", feature = "quic", feature = "dns-h3")))]
    pub(super) async fn exchange_upstream(
        &self,
        upstream: &Arc<Upstream>,
        _request: &[u8],
    ) -> Result<Vec<u8>> {
        match upstream.state {}
    }

    /// How long a query may take on a connection kept from before, which
    /// may have died without a word: the rest of the query's time is left
    /// for a new connection.
    #[cfg(feature = "tls")]
    fn reused_connection_timeout(&self) -> Duration {
        self.timeout / 2
    }
}

#[cfg(all(test, any(feature = "dns-doh", feature = "dns-h3")))]
mod tests {
    use super::*;

    /// A connection given up by its pool goes on while a query holds it,
    /// and stops when the last lets go, or at once when stopped.
    #[tokio::test]
    async fn a_driver_runs_while_a_query_holds_it() {
        let task = || tokio::spawn(std::future::pending::<()>()).abort_handle();
        let pool = Driver::new(task());
        let query = pool.clone();
        drop(pool);
        tokio::task::yield_now().await;
        assert!(!query.is_finished());
        let watch = query.0.clone();
        drop(query);
        tokio::task::yield_now().await;
        assert!(watch.is_finished());

        let stopped = Driver::new(task());
        let held = stopped.clone();
        stopped.stop();
        tokio::task::yield_now().await;
        assert!(held.is_finished());
    }
}
