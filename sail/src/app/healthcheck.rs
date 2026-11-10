use std::time::Duration;

use anyhow::{anyhow, Context};
use tokio::time::Instant;

use crate::{
    adapter::AnyOutboundHandler,
    app::SyncDnsClient,
    session::{Session, SocksAddr},
};

pub async fn tcp(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> anyhow::Result<Duration> {
    let sess = Session {
        destination: SocksAddr::Domain("healthcheck.sail".to_string(), 80),
        new_conn_once: true,
        ..Default::default()
    };
    let start = Instant::now();
    let stream = crate::net::connect_stream_outbound(&sess, dns_client, &handler).await?;
    let mut stream = handler.stream()?.handle(&sess, None, stream).await?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"PING").await?;
    let mut buf = [0u8; 4];
    stream
        .read_exact(&mut buf)
        .await
        .with_context(|| format!("reading TCP health check response from [{}]", handler.tag()))?;
    if &buf == b"PONG" {
        Ok(Instant::now().duration_since(start))
    } else {
        Err(anyhow!(
            "Unexpected TCP health check response from [{}]: {}",
            handler.tag(),
            String::from_utf8_lossy(&buf)
        ))
    }
}

pub async fn udp(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> anyhow::Result<Duration> {
    let addr = SocksAddr::Domain("healthcheck.sail".to_string(), 80);
    let sess = Session {
        destination: addr.clone(),
        new_conn_once: true,
        ..Default::default()
    };
    let start = Instant::now();
    let dgram = crate::net::connect_datagram_outbound(&sess, dns_client, &handler).await?;
    let dgram = handler.datagram()?.handle(&sess, dgram).await?;
    let (mut recv, mut send) = dgram.split();
    send.send_to(b"PING", &addr).await?;
    let mut buf = [0u8; 2 * 1024];
    let (n, _src_addr) = recv.recv_from(&mut buf).await?;
    if &buf[..n] == b"PONG" {
        Ok(Instant::now().duration_since(start))
    } else {
        Err(anyhow!(
            "Unexpected UDP health check response from [{}]",
            handler.tag()
        ))
    }
}

/// What groups request through their members to test them, by default:
/// sing-box's.
pub const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";

/// The HTTP statuses a test expects, as Mihomo's `expected-status` gives
/// them (common/utils/ranges.go, `NewUnsignedRanges`): codes and ranges
/// of codes, `200/204/401-429`, `,` as good as `/`, at most 28; empty or
/// `*` for any.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatusRanges(Vec<(u16, u16)>);

impl StatusRanges {
    pub fn parse(expected: &str) -> anyhow::Result<Self> {
        let expected = expected.trim();
        if expected.is_empty() || expected == "*" {
            return Ok(Self::default());
        }
        let expected = expected.replace(',', "/");
        let list: Vec<&str> = expected.split('/').collect();
        if list.len() > 28 {
            return Err(anyhow!("{} ranges; 28 at most", list.len()));
        }
        let code = |s: &str| {
            s.trim_matches(|c| c == '[' || c == ']' || c == ' ')
                .parse::<u16>()
                .map_err(|_| anyhow!("invalid range: {}", s))
        };
        let mut ranges = Vec::new();
        for item in list.into_iter().filter(|s| !s.is_empty()) {
            let item = item.trim();
            let range = match item.split('-').collect::<Vec<_>>()[..] {
                [one] => (code(one)?, code(one)?),
                [start, end] => (code(start)?, code(end)?),
                _ => return Err(anyhow!("invalid range: {}", item)),
            };
            ranges.push(range);
        }
        Ok(Self(ranges))
    }

    /// Whether `status` is one expected.
    pub fn check(&self, status: u16) -> bool {
        self.0.is_empty() || self.0.iter().any(|(s, e)| (*s..=*e).contains(&status))
    }
}

impl std::fmt::Display for StatusRanges {
    /// As Mihomo shows them: `*` for any.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("*");
        }
        let terms: Vec<String> = self
            .0
            .iter()
            .map(|(s, e)| match s == e {
                true => s.to_string(),
                false => format!("{}-{}", s, e),
            })
            .collect();
        f.write_str(&terms.join("/"))
    }
}

/// An HTTP request made through an outbound to measure it, as sing-box's
/// URL tests do: the latency is the time to the response's status line,
/// connecting and any TLS handshake included.
pub struct HttpProbe {
    url: String,
    /// The statuses that pass; any by default.
    expected: StatusRanges,
    destination: SocksAddr,
    /// The `Host` header: the URL's authority.
    host: String,
    /// The path and query.
    path: String,
    #[cfg(feature = "outbound-tls")]
    tls: Option<crate::transport::tls::outbound::StreamHandler>,
    /// Whether the latency is that of a second request on the connection
    /// the first opened, without the connect and handshakes: Mihomo's
    /// `unified-delay`.
    unified: bool,
}

impl HttpProbe {
    /// A probe of `url`, `http://` or `https://`.
    /// Its TLS trusts the roots of `env`.
    pub fn new(
        url: &str,
        dns_client: SyncDnsClient,
        #[cfg_attr(not(feature = "outbound-tls"), allow(unused_variables))]
        env: &crate::runtime::RuntimeEnv,
    ) -> anyhow::Result<Self> {
        let invalid = |why: &str| anyhow!("invalid URL \"{}\": {}", url, why);
        let (https, rest) = if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else {
            return Err(invalid("expected http:// or https://"));
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) if rest[i..].starts_with('/') => (&rest[..i], rest[i..].to_string()),
            Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
            None => (rest, "/".to_string()),
        };
        if authority.contains('@') {
            return Err(invalid("credentials are not supported"));
        }
        let default_port = if https { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (ip, after) = v6.split_once(']').ok_or_else(|| invalid("unclosed ["))?;
            let port = match after.strip_prefix(':') {
                Some(port) => Some(port),
                None if after.is_empty() => None,
                None => return Err(invalid("bad port")),
            };
            (ip, port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        let port = match port {
            Some(port) => port.parse::<u16>().map_err(|_| invalid("bad port"))?,
            None => default_port,
        };
        if host.is_empty() {
            return Err(invalid("no host"));
        }
        let destination = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => SocksAddr::Ip(std::net::SocketAddr::new(ip, port)),
            Err(_) => SocksAddr::Domain(host.to_string(), port),
        };
        #[cfg(feature = "outbound-tls")]
        let tls = if https {
            Some(crate::transport::tls::outbound::StreamHandler::new(
                host.to_string(),
                vec!["http/1.1".to_string()],
                None,
                false,
                None,
                false,
                None,
                false,
                false,
                None,
                dns_client,
                &env.tls_roots.get()?,
                &Default::default(),
            )?)
        } else {
            None
        };
        #[cfg(not(feature = "outbound-tls"))]
        {
            let _ = dns_client;
            if https {
                return Err(invalid("https needs a build with outbound-tls"));
            }
        }
        Ok(Self {
            url: url.to_string(),
            expected: StatusRanges::default(),
            destination,
            host: authority.to_string(),
            path,
            #[cfg(feature = "outbound-tls")]
            tls,
            unified: false,
        })
    }

    /// The probe, timing a second request on the first's connection when
    /// `unified` (Mihomo's `unified-delay`).
    pub fn unified(mut self, unified: bool) -> Self {
        self.unified = unified;
        self
    }

    /// The probe, passing only the statuses `expected`.
    pub fn expecting(mut self, expected: StatusRanges) -> Self {
        self.expected = expected;
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The statuses that pass, as Mihomo shows them.
    pub fn expected_status(&self) -> String {
        self.expected.to_string()
    }

    /// Whether it tests as `other` does: the same URL, the same statuses
    /// passing.
    pub fn tests_as(&self, other: &HttpProbe) -> bool {
        self.url == other.url && self.expected == other.expected && self.unified == other.unified
    }

    /// The time the request through `handler` took to be answered with a
    /// status expected, within `timeout`, which the caller holds it to:
    /// what a unified delay's second request does fits in it. `timeout`
    /// must be the very one the caller wraps the test in: a longer one
    /// lets the second request outlive the test.
    pub async fn run(
        &self,
        dns_client: SyncDnsClient,
        handler: &AnyOutboundHandler,
        timeout: Duration,
    ) -> anyhow::Result<Duration> {
        use tokio::io::AsyncWriteExt;

        let sess = Session {
            destination: self.destination.clone(),
            new_conn_once: true,
            ..Default::default()
        };
        let start = Instant::now();
        let stream = crate::net::connect_stream_outbound(&sess, dns_client, handler).await?;
        let stream = handler.stream()?.handle(&sess, None, stream).await?;
        #[cfg(feature = "outbound-tls")]
        let mut stream = match &self.tls {
            Some(tls) => {
                use crate::adapter::OutboundStreamHandler;
                tls.handle(&sess, None, Some(stream)).await?
            }
            None => stream,
        };
        #[cfg(not(feature = "outbound-tls"))]
        let mut stream = stream;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: sail\r\nConnection: {}\r\n\r\n",
            self.path,
            self.host,
            if self.unified { "keep-alive" } else { "close" }
        );
        stream.write_all(request.as_bytes()).await?;
        // Timed to the status line, unified or not.
        let (status, mut head) = read_head(&mut stream, handler).await?;
        let mut elapsed = Instant::now().duration_since(start);
        self.check(status, handler)?;
        // Unified, as Mihomo's (adapter/adapter.go, `URLTest`): the same
        // request again on the connection, timed alone. It never fails a
        // test the first request passed: where it cannot be made (a head
        // too long, a body of a length not known or too long, the
        // connection closed), fails, or takes longer than the first did (a
        // second at least) or than what is left of `timeout`, the first
        // request's time stands.
        // What is left of `timeout`, less a margin for the caller to see the
        // answer before it fires.
        let left = timeout
            .saturating_sub(start.elapsed())
            .saturating_sub(Duration::from_millis(50));
        if self.unified && !left.is_zero() {
            let budget = elapsed.max(Duration::from_secs(1)).min(left);
            let again = async {
                rest_of_head(&mut stream, &mut head).await?;
                self.again(&mut stream, &head, &request, handler).await
            };
            if let Ok(Some(again)) = tokio::time::timeout(budget, again).await {
                elapsed = again;
            }
        }
        let _ = stream.shutdown().await;
        Ok(elapsed)
    }

    /// Fails a test whose `status` is not one expected, as in Mihomo
    /// (adapter/adapter.go, `URLTest`).
    fn check(&self, status: u16, handler: &AnyOutboundHandler) -> anyhow::Result<()> {
        if !self.expected.check(status) {
            return Err(anyhow!(
                "status {} through [{}] is not one expected ({})",
                status,
                handler.tag(),
                self.expected
            ));
        }
        Ok(())
    }

    /// The time `request`, sent again on `stream` once the body of the
    /// response whose head is `head` is read, took to be answered with a
    /// status expected; none where that cannot be told.
    async fn again(
        &self,
        stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        head: &[u8],
        request: &str,
        handler: &AnyOutboundHandler,
    ) -> Option<Duration> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (end, length) = body_length(head)?;
        // A probe's URL answers with none, or little: more is no probe's.
        if length > MAX_BODY {
            return None;
        }
        // What came after the head belongs to the body.
        let mut left = length.checked_sub(head.len() - end)?;
        let mut chunk = [0u8; 1024];
        while left > 0 {
            let n = stream.read(&mut chunk[..left.min(1024)]).await.ok()?;
            if n == 0 {
                return None;
            }
            left -= n;
        }
        let start = Instant::now();
        stream.write_all(request.as_bytes()).await.ok()?;
        let (status, _) = read_head(stream, handler).await.ok()?;
        let elapsed = Instant::now().duration_since(start);
        self.check(status, handler).ok()?;
        Some(elapsed)
    }
}

/// The longest body `again` reads to go on on a connection.
const MAX_BODY: usize = 64 * 1024;

/// Reads the rest of the head whose start is `head` from `stream`; none
/// where it is too long or the stream ends first.
async fn rest_of_head(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    head: &mut Vec<u8>,
) -> Option<()> {
    use tokio::io::AsyncReadExt;

    let mut chunk = [0u8; 256];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        if head.len() > 8192 {
            return None;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        head.extend_from_slice(&chunk[..n]);
    }
    Some(())
}

/// Reads a response from `stream` up to its status line: its status, and
/// what was read.
async fn read_head(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    handler: &AnyOutboundHandler,
) -> anyhow::Result<(u16, Vec<u8>)> {
    use tokio::io::AsyncReadExt;

    // The status line is enough to time it: the rest of the response says
    // nothing more about the path to the server.
    let done = |buf: &[u8]| buf.contains(&b'\n');
    let mut buf = Vec::with_capacity(64);
    let mut chunk = [0u8; 64];
    while !done(&buf) {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(anyhow!(
                "EOF before an HTTP response through [{}]",
                handler.tag()
            ));
        }
        if buf.len() > 1024 {
            return Err(anyhow!("no HTTP response through [{}]", handler.tag()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let status = buf
        .strip_prefix(b"HTTP/1.")
        .and_then(|rest| rest.get(1..5))
        .filter(|code| code[0] == b' ' && code[1..].iter().all(u8::is_ascii_digit))
        .and_then(|code| std::str::from_utf8(&code[1..]).ok()?.parse::<u16>().ok());
    let Some(status) = status else {
        return Err(anyhow!(
            "not an HTTP response through [{}]: {}",
            handler.tag(),
            String::from_utf8_lossy(&buf[..buf.len().min(32)])
        ));
    };
    Ok((status, buf))
}

/// Where the head `head` ends, and how long the body after it is: none
/// when that is not known (chunked, or until the connection closes), or
/// the server closes the connection after it.
fn body_length(head: &[u8]) -> Option<(usize, usize)> {
    let end = head.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let text = std::str::from_utf8(&head[..end]).ok()?;
    let status: u16 = text.get(9..12)?.parse().ok()?;
    let mut length = None;
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => length = Some(value.parse::<usize>().ok()?),
            "transfer-encoding" => return None,
            "connection" if value.eq_ignore_ascii_case("close") => return None,
            _ => {}
        }
    }
    // No body: 1xx, 204 and 304 (RFC 9112, 6.3). An interim 1xx, which a
    // final response follows, is not told apart: what probes ask for is
    // answered without one.
    if status == 204 || status == 304 || (100..200).contains(&status) {
        return Some((end, 0));
    }
    Some((end, length?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The public health-check utility uses the normal redirect outbound
    /// against a loopback server. TCP replies are deliberately fragmented;
    /// UDP stays healthy so that only the TCP outcome is under test.
    #[cfg(feature = "outbound-redirect")]
    async fn tcp_reply(chunks: Vec<Vec<u8>>) -> anyhow::Result<Duration> {
        tcp_reply_with_stall(chunks, false).await
    }

    #[cfg(feature = "outbound-redirect")]
    #[allow(clippy::disallowed_methods)] // The test owns its loopback servers.
    async fn tcp_reply_with_stall(chunks: Vec<Vec<u8>>, stall: bool) -> anyhow::Result<Duration> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let udp = tokio::net::UdpSocket::bind(("127.0.0.1", port)).await?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"PING");
            for (i, chunk) in chunks.iter().enumerate() {
                if i > 0 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                if stream.write_all(chunk).await.is_err() {
                    return;
                }
            }
            if stall {
                std::future::pending::<()>().await;
            }
        });
        let udp_server = tokio::spawn(async move {
            let mut request = [0; 4];
            let (n, from) = udp.recv_from(&mut request).await.unwrap();
            assert_eq!(&request[..n], b"PING");
            udp.send_to(b"PONG", from).await.unwrap();
        });
        let config = crate::config::Config::from_json(&format!(
            r#"{{ "outbounds": [{{ "type": "redirect", "tag": "probe", "server": "127.0.0.1", "server_port": {port} }}] }}"#,
        ))?;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            crate::util::health_check_outbound(
                "probe",
                &config,
                Some(Duration::from_millis(500)),
                &Default::default(),
            ),
        )
        .await;
        if stall {
            server.abort();
        } else {
            tokio::time::timeout(Duration::from_secs(1), server).await??;
        }
        tokio::time::timeout(Duration::from_secs(1), udp_server).await??;
        let (tcp, udp) = result??;
        assert!(udp.is_ok(), "the UDP control failed: {udp:?}");
        tcp
    }

    #[cfg(feature = "outbound-redirect")]
    #[tokio::test]
    async fn tcp_healthcheck_accepts_a_whole_reply() {
        tcp_reply(vec![b"PONG".to_vec()]).await.unwrap();
    }

    #[cfg(feature = "outbound-redirect")]
    #[tokio::test]
    async fn tcp_healthcheck_accepts_every_fragment_boundary() {
        for split in 1..4 {
            let reply = b"PONG";
            let result = tcp_reply(vec![reply[..split].to_vec(), reply[split..].to_vec()]).await;
            assert!(result.is_ok(), "split at {split}: {result:?}");
        }
    }

    #[cfg(feature = "outbound-redirect")]
    #[tokio::test]
    async fn tcp_healthcheck_accepts_a_byte_at_a_time() {
        tcp_reply(b"PONG".iter().map(|b| vec![*b]).collect())
            .await
            .unwrap();
    }

    #[cfg(feature = "outbound-redirect")]
    #[tokio::test]
    async fn tcp_healthcheck_rejects_eof_before_a_complete_reply() {
        for prefix in [b"".as_slice(), b"P", b"PO", b"PON"] {
            assert!(tcp_reply(vec![prefix.to_vec()]).await.is_err());
        }
    }

    #[cfg(feature = "outbound-redirect")]
    #[tokio::test]
    async fn tcp_healthcheck_obeys_the_caller_timeout_after_a_partial_reply() {
        let start = Instant::now();
        let result = tcp_reply_with_stall(vec![b"P".to_vec()], true).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .downcast_ref::<tokio::time::error::Elapsed>()
            .is_some());
        assert!(start.elapsed() >= Duration::from_millis(450));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[cfg(feature = "outbound-redirect")]
    #[tokio::test]
    async fn tcp_healthcheck_rejects_wrong_replies() {
        assert!(tcp_reply(vec![b"PING".to_vec()]).await.is_err());
        assert!(tcp_reply(vec![b"PO".to_vec(), b"NO".to_vec()])
            .await
            .is_err());
    }

    #[test]
    fn a_body_s_length_is_read_where_the_connection_can_go_on() {
        let len = |head: &str| body_length(head.as_bytes()).map(|(_, n)| n);
        assert_eq!(len("HTTP/1.1 204 No Content\r\n\r\n"), Some(0));
        assert_eq!(
            len("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"),
            Some(12)
        );
        assert_eq!(
            len("HTTP/1.1 200 OK\r\ncontent-length:3\r\n\r\nabc"),
            Some(3)
        );
        // Not told, chunked, or the connection closing: it cannot go on.
        assert_eq!(len("HTTP/1.1 200 OK\r\n\r\n"), None);
        assert_eq!(
            len("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
            None
        );
        assert_eq!(
            len("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"),
            None
        );
        assert_eq!(len("HTTP/1.1 204 No Content\r\n"), None);
    }

    /// A server whose first answer on a connection takes `first`, and the
    /// next ones on it none: what a connect and a handshake cost, which a
    /// unified delay leaves out.
    #[cfg(feature = "outbound-direct")]
    #[allow(clippy::disallowed_methods)] // A test's server, outside any instance.
    async fn slow_first(first: Duration) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let mut answered = 0;
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if answered == 0 {
                            tokio::time::sleep(first).await;
                        }
                        answered += 1;
                        let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                    }
                });
            }
        });
        port
    }

    #[cfg(feature = "outbound-direct")]
    fn direct() -> AnyOutboundHandler {
        let config = crate::config::Config::from_json(
            r#"{ "outbounds": [{ "type": "direct", "tag": "d" }] }"#,
        )
        .unwrap();
        let dial = crate::net::DialDefaults::default();
        crate::app::outbound::manager::OutboundManager::with_endpoints(
            &config.outbounds,
            &config.endpoints,
            #[cfg(feature = "outbound-provider")]
            Default::default(),
            &dial,
            &Default::default(),
            dns(),
        )
        .unwrap()
        .get("d")
        .unwrap()
    }

    /// A server that answers the first request on a connection at once,
    /// and never the next ones.
    #[cfg(feature = "outbound-direct")]
    #[allow(clippy::disallowed_methods)] // A test's server, outside any instance.
    async fn first_only(after: Duration) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {
                        tokio::time::sleep(after).await;
                        let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                    }
                    // Holds the connection, answering nothing more.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                });
            }
        });
        port
    }

    /// Unified, a second request that is never answered leaves the first's
    /// time, the test passing within its timeout: the second's budget is
    /// what is left of it, however slow the first was.
    #[cfg(feature = "outbound-direct")]
    #[tokio::test]
    async fn a_second_request_not_answered_leaves_the_first_time() {
        for (first, timeout) in [(Duration::ZERO, 5), (Duration::from_millis(1200), 2)] {
            let port = first_only(first).await;
            let url = format!("http://127.0.0.1:{}/generate_204", port);
            let probe = HttpProbe::new(&url, dns(), &Default::default())
                .unwrap()
                .unified(true);
            let timeout = Duration::from_secs(timeout);
            let started = Instant::now();
            let took = tokio::time::timeout(timeout, probe.run(dns(), &direct(), timeout))
                .await
                .expect("within the timeout")
                .unwrap();
            assert!(
                took >= first && took < first + Duration::from_secs(1),
                "{:?}",
                took
            );
            assert!(started.elapsed() < timeout, "{:?}", started.elapsed());
        }
    }

    /// Unified, the latency is the second request's, on the connection
    /// the first opened; else it is the first's, connect and all.
    #[cfg(feature = "outbound-direct")]
    #[tokio::test]
    async fn a_unified_delay_leaves_the_first_answer_out() {
        let first = Duration::from_millis(400);
        let port = slow_first(first).await;
        let url = format!("http://127.0.0.1:{}/generate_204", port);
        let handler = direct();
        let plain = HttpProbe::new(&url, dns(), &Default::default()).unwrap();
        let took = plain
            .run(dns(), &handler, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(took >= first, "{:?}", took);
        let unified = plain.unified(true);
        let took = unified
            .run(dns(), &handler, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(took < first / 2, "{:?}", took);
    }

    fn dns() -> SyncDnsClient {
        crate::app::dns_client::DnsClient::new(
            &Default::default(),
            std::sync::Arc::new(crate::net::DialDefaults::default()),
            &Default::default(),
        )
        .unwrap()
        .into_shared()
    }

    #[test]
    fn a_url_is_split_into_what_the_request_needs() {
        let p = HttpProbe::new(
            "http://example.com/generate_204",
            dns(),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(p.destination, SocksAddr::Domain("example.com".into(), 80));
        assert_eq!(
            (p.host.as_str(), p.path.as_str()),
            ("example.com", "/generate_204")
        );

        let p = HttpProbe::new("http://127.0.0.1:8080", dns(), &Default::default()).unwrap();
        assert_eq!(
            p.destination,
            SocksAddr::Ip("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!((p.host.as_str(), p.path.as_str()), ("127.0.0.1:8080", "/"));

        let p = HttpProbe::new("http://[::1]:81?x=1", dns(), &Default::default()).unwrap();
        assert_eq!(p.destination, SocksAddr::Ip("[::1]:81".parse().unwrap()));
        assert_eq!(p.path, "/?x=1");
    }

    #[test]
    fn expected_statuses_are_read_as_mihomo_reads_them() {
        let any = StatusRanges::parse(" * ").unwrap();
        assert!(any.check(500));
        assert_eq!(any.to_string(), "*");
        assert_eq!(StatusRanges::parse("").unwrap(), any);

        let r = StatusRanges::parse("200/204, 401-429/").unwrap();
        assert!(r.check(200) && r.check(204) && r.check(401) && r.check(429));
        assert!(!r.check(201) && !r.check(430) && !r.check(302));
        assert_eq!(r.to_string(), "200/204/401-429");
        assert!(StatusRanges::parse("[200]").unwrap().check(200));

        for bad in ["2xx", "200-", "1-2-3", "70000"] {
            assert!(StatusRanges::parse(bad).is_err(), "{}", bad);
        }
        let many = vec!["200"; 29].join("/");
        assert!(StatusRanges::parse(&many).is_err());
    }

    #[test]
    fn a_bad_url_is_an_error() {
        for url in [
            "ftp://x/",
            "http://",
            "http://x:port/",
            "http://u@x/",
            "http://[::1/",
        ] {
            assert!(
                HttpProbe::new(url, dns(), &Default::default()).is_err(),
                "{}",
                url
            );
        }
    }
}
