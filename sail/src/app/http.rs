//! A GET over HTTP/1.1, through an outbound or directly: what downloading a
//! remote rule-set or an outbound provider takes, and no more. It is what
//! `crate::fetch` downloads with too, without an instance where it dials
//! directly.
// With fetch alone, the conditional GET and the per-download clients
// go unused.
#![cfg_attr(not(feature = "rule-set"), allow(dead_code))]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::adapter::AnyStream;
use crate::app::dispatcher::Dispatcher;
use crate::app::SyncDnsClient;
use crate::config::model::{HttpClient, HttpClientRef};
use crate::net::{DialDefaults, Dialer};
use crate::runtime::RuntimeEnv;
use crate::session::{Network, Session, SocksAddr};

/// The most a download may be, as written to the cache (sail asks for no
/// encoding, so as it came): judged, well past the largest published
/// rule-sets and subscriptions; Mihomo has no cap but a provider's
/// `size-limit`, sing-box none.
pub(crate) const MAX_BODY: usize = 64 << 20;
/// The most a response's head may be: judged.
const MAX_HEAD: usize = 64 << 10;
/// Judged; Go's client, and so Mihomo's and sing-box's, follows 10.
const MAX_REDIRECTS: usize = 5;
/// How long a download may take, redirects and all: judged, as one may
/// go through a proxy; Mihomo gives 20s, sing-box no limit.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(60);

/// What a download is made with: an HTTP client, or `download_detour`.
#[derive(Clone, Default)]
pub(crate) struct Client {
    /// None: through the default outbound.
    pub via: Option<Via>,
    pub headers: Vec<(String, String)>,
}

/// How a download connects.
#[derive(Clone)]
pub(crate) enum Via {
    /// Through the outbound of this tag.
    Outbound(String),
    /// With a dialer: an HTTP client's, which goes straight to the server
    /// or through its detour.
    Dialer(Dialer),
}

pub(crate) enum Response {
    /// Unchanged since the ETag given.
    NotModified,
    Body {
        data: Vec<u8>,
        etag: Option<String>,
        /// `subscription-userinfo`, what a subscription says of its
        /// traffic and expiry.
        #[cfg_attr(not(feature = "outbound-provider"), allow(dead_code))]
        userinfo: Option<String>,
    },
}

/// What a GET connects with: the instance's dispatcher, where there is
/// one, else what a direct connection takes.
pub(crate) struct Conn<'a> {
    /// Needed to go through an outbound.
    pub dispatcher: Option<&'a Dispatcher>,
    pub dns: SyncDnsClient,
    pub env: &'a RuntimeEnv,
}

/// How long a GET may take, redirects and all, and how large its body may
/// be.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub timeout: Duration,
    pub max_body: usize,
    /// What `max_body` is, for the error that tells it was passed.
    pub max_body_is: &'static str,
}

/// A rule-set's.
const LIMITS: Limits = Limits {
    timeout: TIMEOUT,
    max_body: MAX_BODY,
    max_body_is: "the most a download may be",
};

/// GETs `url` `via` an outbound or directly, following redirects; with
/// `etag`, asks for it only if changed; no larger than `size_limit`, the
/// download's own (Mihomo's `size-limit`), within the cap of all.
pub(crate) async fn get(
    dispatcher: &Dispatcher,
    via: &Via,
    headers: &[(String, String)],
    url: &str,
    etag: Option<&str>,
    size_limit: Option<u64>,
) -> Result<Response> {
    let conn = Conn {
        dispatcher: Some(dispatcher),
        dns: dispatcher.dns_client(),
        env: dispatcher.env(),
    };
    let limits = match size_limit {
        Some(limit) if (limit as usize) < MAX_BODY => Limits {
            max_body: limit as usize,
            max_body_is: "its size_limit",
            ..LIMITS
        },
        _ => LIMITS,
    };
    get_with(&conn, via, headers, url, etag, limits).await
}

/// `get`, with `conn` and within `limits`.
pub(crate) async fn get_with(
    conn: &Conn<'_>,
    via: &Via,
    headers: &[(String, String)],
    url: &str,
    etag: Option<&str>,
    limits: Limits,
) -> Result<Response> {
    tokio::time::timeout(
        limits.timeout,
        get_following(conn, via, headers, url, etag, limits),
    )
    .await
    .map_err(|_| anyhow!("timed out after {:?}", limits.timeout))?
}

async fn get_following(
    conn: &Conn<'_>,
    via: &Via,
    headers: &[(String, String)],
    url: &str,
    etag: Option<&str>,
    limits: Limits,
) -> Result<Response> {
    let mut url = url::Url::parse(url).map_err(|e| anyhow!("url: {}", e))?;
    for _ in 0..=MAX_REDIRECTS {
        match get_once(conn, via, headers, &url, etag, limits).await? {
            Step::Done(response) => return Ok(response),
            Step::Redirect(location) => {
                // Neither the location nor the URL is named: either may carry
                // a secret path (a Sub-Store backend's).
                let next = url
                    .join(&location)
                    .map_err(|e| anyhow!("redirect: bad Location: {}", e))?;
                redirect_allowed(&url, &next)?;
                url = next;
            }
        }
    }
    Err(anyhow!("more than {} redirects", MAX_REDIRECTS))
}

/// Whether a redirect from `from` to `to` is followed: to http or https
/// alone, and never from https down to http, which Go's client, and so
/// Mihomo's and sing-box's, does: what the request carries (a
/// subscription's token, in its path or headers) would go in the clear.
fn redirect_allowed(from: &url::Url, to: &url::Url) -> Result<()> {
    match (from.scheme(), to.scheme()) {
        ("https", "http") => Err(anyhow!("redirect from https to http refused")),
        (_, "http" | "https") => Ok(()),
        (_, scheme) => Err(anyhow!("redirect to a {}: URL refused", scheme)),
    }
}

/// That a body passed `limits.max_body`: what that is, and its bytes.
fn too_large(limits: Limits) -> anyhow::Error {
    anyhow!(
        "larger than {}, {} bytes",
        limits.max_body_is,
        limits.max_body
    )
}

enum Step {
    Done(Response),
    Redirect(String),
}

async fn get_once(
    conn: &Conn<'_>,
    via: &Via,
    headers: &[(String, String)],
    url: &url::Url,
    etag: Option<&str>,
    limits: Limits,
) -> Result<Step> {
    let max_body = limits.max_body;
    let tls = match url.scheme() {
        "https" => true,
        "http" => false,
        other => return Err(anyhow!("{}: not an http(s) URL", other)),
    };
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("url: no host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let destination = match host.parse::<IpAddr>() {
        Ok(ip) => SocksAddr::Ip((ip, port).into()),
        Err(_) => SocksAddr::Domain(host.clone(), port),
    };
    let sess = Session {
        network: Network::Tcp,
        destination,
        inbound_tag: "rule-set".to_string(),
        ..Default::default()
    };
    let stream = match via {
        Via::Outbound(detour) => conn
            .dispatcher
            .ok_or_else(|| anyhow!("connect {} through [{}]: no instance runs", host, detour))?
            .stream_via(detour, sess)
            .await
            .map_err(|e| anyhow!("connect {} through [{}]: {}", host, detour, e))?,
        Via::Dialer(dialer) => dialer
            .stream(&conn.dns, Some(&sess), &sess.destination)
            .await
            .map_err(|e| anyhow!("connect {}: {}", host, e))?,
    };
    let mut stream = if tls {
        handshake(&host, stream, conn.env).await?
    } else {
        stream
    };

    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let authority = match url.port() {
        Some(port) => format!("{}:{}", url.host_str().unwrap_or_default(), port),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    let mut request = format!("GET {} HTTP/1.1\r\nConnection: close\r\n", path);
    let user_agent = format!("sail/{}", env!("CARGO_PKG_VERSION"));
    for (name, value) in [
        ("Host", authority.as_str()),
        ("User-Agent", user_agent.as_str()),
        ("Accept", "*/*"),
    ] {
        if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
            request.push_str(&format!("{}: {}\r\n", name, value));
        }
    }
    for (name, value) in headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    if let Some(etag) = etag {
        request.push_str(&format!("If-None-Match: {}\r\n", etag));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let (head, mut rest) = read_head(&mut stream).await?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    response
        .parse(&head)
        .map_err(|e| anyhow!("invalid response: {}", e))?;
    let code = response.code.unwrap_or_default();
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    match code {
        200 => {}
        304 => return Ok(Step::Done(Response::NotModified)),
        301 | 302 | 303 | 307 | 308 => {
            let location =
                header("location").ok_or_else(|| anyhow!("{} without Location", code))?;
            return Ok(Step::Redirect(location.to_string()));
        }
        _ => return Err(anyhow!("http status {}", code)),
    }
    let etag = header("etag").map(str::to_string);
    let userinfo = header("subscription-userinfo")
        .filter(|v| !v.trim().is_empty())
        .map(str::to_string);
    let chunked = header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let length = header("content-length")
        .map(|v| {
            v.parse::<usize>()
                .map_err(|_| anyhow!("invalid Content-Length"))
        })
        .transpose()?;
    if length.is_some_and(|l| l > max_body) {
        return Err(too_large(limits));
    }
    let data = if chunked {
        read_chunked(&mut stream, rest, limits).await?
    } else {
        read_rest(&mut stream, &mut rest, limits).await?;
        if let Some(length) = length {
            if rest.len() < length {
                return Err(anyhow!(
                    "body cut short: {} of {} bytes",
                    rest.len(),
                    length
                ));
            }
            rest.truncate(length);
        }
        rest
    };
    Ok(Step::Done(Response::Body {
        data,
        etag,
        userinfo,
    }))
}

#[cfg(feature = "tls")]
async fn handshake(
    host: &str,
    stream: AnyStream,
    env: &crate::runtime::RuntimeEnv,
) -> Result<AnyStream> {
    use crate::transport::tls::{Fingerprint, TlsClient};
    let client = TlsClient::new(
        &["http/1.1".to_string()],
        None,
        false,
        Some(Fingerprint::Chrome),
        &env.tls_roots.get()?,
    )?;
    let stream = client
        .connect(host, stream, None, None)
        .await
        .map_err(|e| anyhow!("tls handshake with {}: {}", host, e))?;
    Ok(Box::new(stream))
}

#[cfg(not(feature = "tls"))]
async fn handshake(
    _host: &str,
    _stream: AnyStream,
    _env: &crate::runtime::RuntimeEnv,
) -> Result<AnyStream> {
    Err(anyhow!(
        "https: not supported, the tls feature is not compiled in"
    ))
}

/// The response head, up to the blank line, and what came after it.
async fn read_head(stream: &mut AnyStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD {
            return Err(anyhow!("response head longer than {} bytes", MAX_HEAD));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(anyhow!("connection closed before a response"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Reads to the end, which `Connection: close` puts at the body's.
async fn read_rest(stream: &mut AnyStream, buf: &mut Vec<u8>, limits: Limits) -> Result<()> {
    let max_body = limits.max_body;
    let mut chunk = [0u8; 16384];
    loop {
        if buf.len() > max_body {
            return Err(too_large(limits));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The longest chunk size line, extensions and all.
const MAX_CHUNK_LINE: usize = 4096;

/// A chunked body (RFC 9112 §7.1), `buf` holding what was read already.
async fn read_chunked(stream: &mut AnyStream, mut buf: Vec<u8>, limits: Limits) -> Result<Vec<u8>> {
    let max_body = limits.max_body;
    let mut body = Vec::new();
    let mut at = 0;
    loop {
        // The size line.
        let line_end = loop {
            if let Some(i) = buf[at..].windows(2).position(|w| w == b"\r\n") {
                break at + i;
            }
            if buf.len() - at > MAX_CHUNK_LINE {
                return Err(anyhow!(
                    "chunk size line longer than {} bytes",
                    MAX_CHUNK_LINE
                ));
            }
            more(stream, &mut buf).await?;
        };
        let line = std::str::from_utf8(&buf[at..line_end]).map_err(|_| anyhow!("bad chunk"))?;
        let digits = line.split(';').next().unwrap_or("").trim();
        // The size is the peer's: more digits than a u64 has is no size.
        if digits.len() > 16 {
            return Err(anyhow!("bad chunk size {:?}", line));
        }
        let size =
            usize::from_str_radix(digits, 16).map_err(|_| anyhow!("bad chunk size {:?}", line))?;
        at = line_end + 2;
        if size == 0 {
            return Ok(body);
        }
        if body.len().checked_add(size).is_none_or(|n| n > max_body) {
            return Err(too_large(limits));
        }
        while buf.len() < at + size + 2 {
            more(stream, &mut buf).await?;
        }
        body.extend_from_slice(&buf[at..at + size]);
        at += size + 2;
        // Keeps the buffer from holding the whole body twice.
        buf.drain(..at);
        at = 0;
    }
}

async fn more(stream: &mut AnyStream, buf: &mut Vec<u8>) -> Result<()> {
    let mut chunk = [0u8; 16384];
    let n = stream.read(&mut chunk).await?;
    if n == 0 {
        return Err(anyhow!("connection closed in the body"));
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

/// Writes `data` to `path` whole or not at all: a download's cache.
pub(crate) fn write_atomically(path: &std::path::Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let partial = path.with_extension("partial");
    std::fs::write(&partial, data)?;
    std::fs::rename(&partial, path)?;
    Ok(())
}

/// A tag as a file name: what could leave the directory, or trouble a
/// file system, becomes `_`.
#[cfg(any(feature = "outbound-provider", test))]
pub(crate) fn file_name(tag: &str) -> String {
    let name: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    match name.trim_start_matches('.') {
        "" => "_".to_string(),
        name => name.to_string(),
    }
}

/// What downloads go with: `http_clients`, and the defaults the dialers of
/// those that dial directly are built over. Remote rule-sets and outbound providers take theirs
/// from it.
#[derive(Default)]
pub(crate) struct HttpClients {
    clients: Vec<HttpClient>,
    default: Option<String>,
    dial: Arc<DialDefaults>,
}

impl HttpClients {
    pub(crate) fn new(config: &crate::config::Config, dial: Arc<DialDefaults>) -> Self {
        Self {
            clients: config.http_clients.clone(),
            default: config.route.default_http_client.clone(),
            dial,
        }
    }

    fn get(&self, tag: &str) -> Result<&HttpClient> {
        self.clients
            .iter()
            .find(|c| c.tag == tag)
            .ok_or_else(|| anyhow!("http client [{}] does not exist", tag))
    }

    /// How what names `http_client` and `download_detour` is downloaded,
    /// a remote rule-set or outbound provider, as sing-box has it: with its
    /// `http_client`, or through its `download_detour`, or with the default
    /// client; none, through the default outbound.
    pub(crate) fn client(
        &self,
        http_client: Option<&HttpClientRef>,
        download_detour: Option<&str>,
    ) -> Result<Client> {
        let client = match http_client {
            Some(HttpClientRef::Tag(tag)) => self.get(tag)?,
            Some(HttpClientRef::Inline(client)) => client,
            None => {
                if let Some(detour) = download_detour {
                    return Ok(Client {
                        via: Some(Via::Outbound(detour.to_string())),
                        headers: Vec::new(),
                    });
                }
                match &self.default {
                    Some(tag) => self.get(tag)?,
                    None => match self.clients.first() {
                        Some(client) => client,
                        None => return Ok(Client::default()),
                    },
                }
            }
        };
        let via = Via::Dialer(
            client
                .dialer(&self.dial)
                .map_err(|e| anyhow!("http_client: {}", e))?,
        );
        Ok(Client {
            via: Some(via),
            headers: client.header_lines(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A redirect stays on http or https, and never goes from https down
    /// to http, which Go's client, and so Mihomo's and sing-box's, follows.
    #[test]
    fn a_redirect_keeps_its_security() {
        let url = |s: &str| url::Url::parse(s).unwrap();
        let ok = |from: &str, to: &str| redirect_allowed(&url(from), &url(to)).is_ok();
        assert!(ok("http://a.example/x", "https://b.example/y"));
        assert!(ok("https://a.example/x", "https://b.example/y"));
        assert!(ok("http://a.example/x", "http://b.example/y"));
        let err = redirect_allowed(&url("https://a.example/x"), &url("http://b.example/y"))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "redirect from https to http refused");
        assert!(!ok("https://a.example/x", "file:///etc/passwd"));
    }
}
