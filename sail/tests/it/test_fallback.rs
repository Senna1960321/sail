//! Fallback on the Trojan, VLESS, AnyTLS and Sail/1 inbounds: what fails to
//! authenticate is relayed, byte for byte, to a fallback server chosen by
//! the TLS ALPN, and clients that do authenticate are not affected.
//!
//! The sing-box tests need `sing-box` on the PATH or in /opt/homebrew/bin,
//! and are ignored unless asked for:
//! `cargo test -p sail --test it test_fallback:: -- --ignored`.

#![cfg(all(
    feature = "inbound-trojan",
    feature = "outbound-trojan",
    feature = "inbound-vless",
    feature = "outbound-vless",
    feature = "inbound-tls",
    feature = "outbound-tls",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::json;
use sha2::Digest;

const PASSWORD: &str = "password";
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
/// What the partial-header tests are waited on for: the inbound's
/// `HEADER_TIMEOUT`, which is 2s.
const HEADER_TIMEOUT: Duration = Duration::from_secs(2);

/// A self-signed certificate for localhost, as files.
struct Cert {
    dir: common::TempDir,
}

impl Cert {
    fn new(name: &str) -> anyhow::Result<Self> {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let dir = common::TempDir::new(&format!("fallback-{}", name))?;
        let cert_files = Cert { dir };
        std::fs::write(cert_files.cert_path(), cert.pem())?;
        std::fs::write(cert_files.key_path(), key_pair.serialize_pem())?;
        Ok(cert_files)
    }

    fn cert_path(&self) -> PathBuf {
        self.dir.join("cert.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("key.pem")
    }
}

/// A stand-in for a web server, on a thread: for each connection it reads
/// until the peer has been quiet for a moment, then answers with its name, a
/// newline and every byte it received, and closes. Returns its port.
fn run_web_server(name: &'static str) -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            std::thread::spawn(move || {
                let mut received = Vec::new();
                let mut buf = [0u8; 4096];
                // Until the first bytes: long; after them: until a pause.
                let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            received.extend_from_slice(&buf[..n]);
                            let _ = conn.set_read_timeout(Some(Duration::from_millis(300)));
                        }
                    }
                }
                let mut answer = format!("{}\n", name).into_bytes();
                answer.extend_from_slice(&received);
                let _ = conn.write_all(&answer);
            });
        }
    });
    Ok(port)
}

/// What `run_web_server` named `name` answers to `sent`.
fn answer(name: &str, sent: &[u8]) -> Vec<u8> {
    let mut answer = format!("{}\n", name).into_bytes();
    answer.extend_from_slice(sent);
    answer
}

/// A TLS connection to `port` offering `alpn`, in wire format.
fn tls_connect(port: u16, alpn: &[u8]) -> anyhow::Result<btls::ssl::SslStream<TcpStream>> {
    use btls::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let tcp = TcpStream::connect(("127.0.0.1", port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);
    if !alpn.is_empty() {
        connector.set_alpn_protos(alpn)?;
    }
    connector
        .build()
        .connect("localhost", tcp)
        .map_err(|e| anyhow::anyhow!("TLS connect: {}", e))
}

/// Sends `sent` over TLS to `port` offering `alpn`, and checks that the
/// web server `name` got exactly that; returns how long the answer took.
fn probe(port: u16, alpn: &[u8], sent: &[u8], name: &str) -> anyhow::Result<Duration> {
    let mut tls = tls_connect(port, alpn)?;
    let start = Instant::now();
    tls.write_all(sent)?;
    let expected = answer(name, sent);
    let mut got = vec![0u8; expected.len()];
    tls.read_exact(&mut got)
        .map_err(|e| anyhow::anyhow!("no answer from the fallback: {}", e))?;
    anyhow::ensure!(
        got == expected,
        "the fallback answered {:?}, not {:?}",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&expected)
    );
    Ok(start.elapsed())
}

fn server_tls(cert: &Cert) -> serde_json::Value {
    json!({
        "enabled": true,
        "certificate_path": cert.cert_path(),
        "key_path": cert.key_path(),
        "alpn": ["h2", "http/1.1"],
    })
}

/// The fallbacks every server here has: `http1` by default, `h2` for h2.
fn fallbacks(inbound: &mut serde_json::Value, http1: u16, h2: u16) {
    inbound["fallback"] = json!({ "server": "127.0.0.1", "server_port": http1 });
    inbound["fallback_for_alpn"] = json!({ "h2": { "server": "127.0.0.1", "server_port": h2 } });
}

fn trojan_server(cert: &Cert, port: u16, fallback: Option<(u16, u16)>) -> String {
    let mut inbound = json!({
        "type": "trojan",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "password": PASSWORD }],
        "tls": server_tls(cert),
    });
    if let Some((http1, h2)) = fallback {
        fallbacks(&mut inbound, http1, h2);
    }
    json!({ "inbounds": [inbound], "outbounds": [{ "type": "direct" }] }).to_string()
}

fn vless_server(cert: &Cert, port: u16, fallback: Option<(u16, u16)>) -> String {
    let mut inbound = json!({
        "type": "vless",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "uuid": UUID }],
        "tls": server_tls(cert),
    });
    if let Some((http1, h2)) = fallback {
        fallbacks(&mut inbound, http1, h2);
    }
    json!({ "inbounds": [inbound], "outbounds": [{ "type": "direct" }] }).to_string()
}

fn client_tls(cert: &Cert, alpn: &str) -> serde_json::Value {
    json!({
        "enabled": true,
        "server_name": "localhost",
        "certificate_path": cert.cert_path(),
        "alpn": [alpn],
    })
}

fn sail_client(outbound: serde_json::Value, socks_port: u16) -> String {
    json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [outbound],
    })
    .to_string()
}

fn trojan_outbound(cert: &Cert, server_port: u16, alpn: &str) -> serde_json::Value {
    json!({
        "type": "trojan",
        "server": "127.0.0.1",
        "server_port": server_port,
        "password": PASSWORD,
        "tls": client_tls(cert, alpn),
    })
}

fn vless_outbound(cert: &Cert, server_port: u16, alpn: &str) -> serde_json::Value {
    json!({
        "type": "vless",
        "server": "127.0.0.1",
        "server_port": server_port,
        "uuid": UUID,
        "tls": client_tls(cert, alpn),
    })
}

/// Runs `configs`, then `check` on a thread of its own.
fn with_sail<F>(configs: Vec<String>, check: F) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<()> + Send + 'static,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let ids = common::run_sail_instances(&rt, configs)?;
    let result = std::thread::spawn(check)
        .join()
        .map_err(|_| anyhow::anyhow!("the check panicked"))
        .and_then(|r| r);
    for id in ids {
        sail::shutdown(id);
    }
    result
}

/// Echoes a few kilobytes through the socks server on `socks_port`, to an
/// echo server of its own.
fn echo_through_socks(socks_port: u16) -> anyhow::Result<()> {
    let echo = TcpListener::bind("127.0.0.1:0")?;
    let echo_port = echo.local_addr()?.port();
    std::thread::spawn(move || {
        if let Ok((mut conn, _)) = echo.accept() {
            let mut buf = [0u8; 4096];
            while let Ok(n) = conn.read(&mut buf) {
                if n == 0 || conn.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    });
    let mut tcp = TcpStream::connect(("127.0.0.1", socks_port))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.write_all(&[5, 1, 0])?;
    let mut reply = [0u8; 2];
    tcp.read_exact(&mut reply)?;
    anyhow::ensure!(reply == [5, 0], "socks method {:?}", reply);
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend_from_slice(&echo_port.to_be_bytes());
    tcp.write_all(&request)?;
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply)?;
    anyhow::ensure!(reply[1] == 0, "socks connect failed: {}", reply[1]);
    let data: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
    tcp.write_all(&data)?;
    let mut echoed = vec![0u8; data.len()];
    tcp.read_exact(&mut echoed)
        .map_err(|e| anyhow::anyhow!("no echo through the proxy: {}", e))?;
    anyhow::ensure!(echoed == data, "the echo differs");
    Ok(())
}

const HTTP1_REQUEST: &[u8] =
    b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: probe\r\nAccept: */*\r\n\r\n";
/// The HTTP/2 connection preface and an empty SETTINGS frame.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// A VLESS request header for `uuid`: TCP to 127.0.0.1:80.
fn vless_header(uuid: &str) -> Vec<u8> {
    let mut header = vec![0u8];
    header.extend_from_slice(uuid::Uuid::parse_str(uuid).unwrap().as_bytes());
    header.extend_from_slice(&[0, 1, 0, 80, 1, 127, 0, 0, 1]);
    header
}

// ---------------------------------------------------------------------------
// Trojan
// ---------------------------------------------------------------------------

#[test]
fn test_trojan_fallback() -> anyhow::Result<()> {
    let cert = Cert::new("trojan")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let [port, socks_h2, socks_http1] = common::free_ports();
        let configs = vec![
            trojan_server(&cert, port, Some((http1, h2))),
            sail_client(trojan_outbound(&cert, port, "h2"), socks_h2),
            sail_client(trojan_outbound(&cert, port, "http/1.1"), socks_http1),
        ];
        with_sail(configs, move || {
            // A web client gets the web server, whichever ALPN it speaks.
            probe(port, b"\x08http/1.1", HTTP1_REQUEST, "http1")?;
            probe(port, b"", HTTP1_REQUEST, "http1")?;
            probe(port, b"\x02h2", H2_PREFACE, "h2")?;
            // A well-formed header with a wrong password.
            let mut wrong = hex::encode(sha2::Sha224::digest(b"wrong")).into_bytes();
            wrong.extend_from_slice(
                b"\r\n\x01\x01\x7f\x00\x00\x01\x00\x50\r\nGET / HTTP/1.1\r\n\r\n",
            );
            probe(port, b"\x08http/1.1", &wrong, "http1")?;
            // Trojan clients still get through, on either ALPN.
            echo_through_socks(socks_h2)?;
            echo_through_socks(socks_http1)?;
            Ok(())
        })
    })
}

#[test]
fn test_trojan_fallback_after_partial_header() -> anyhow::Result<()> {
    let cert = Cert::new("trojan-partial")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let configs = vec![trojan_server(&cert, port, Some((http1, h2)))];
        with_sail(configs, move || {
            // Hex, as a key starts: the inbound waits for the rest, then gives up.
            let took = probe(port, b"\x08http/1.1", b"0123456789abcdef", "http1")?;
            anyhow::ensure!(
                took >= HEADER_TIMEOUT - Duration::from_millis(100),
                "fell back after {:?}, before the header timeout",
                took
            );
            // Not hex: no waiting.
            let took = probe(port, b"\x08http/1.1", b"GET /", "http1")?;
            anyhow::ensure!(took < HEADER_TIMEOUT, "waited {:?} for a non-key", took);
            Ok(())
        })
    })
}

#[test]
fn test_trojan_without_fallback_closes() -> anyhow::Result<()> {
    let cert = Cert::new("trojan-none")?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let configs = vec![trojan_server(&cert, port, None)];
        with_sail(configs, move || {
            let mut tls = tls_connect(port, b"\x08http/1.1")?;
            tls.write_all(HTTP1_REQUEST)?;
            let mut buf = [0u8; 64];
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => Ok(()),
                Ok(n) => Err(anyhow::anyhow!("got {} bytes without a fallback", n)),
            }
        })
    })
}

// ---------------------------------------------------------------------------
// VLESS
// ---------------------------------------------------------------------------

#[test]
fn test_vless_fallback() -> anyhow::Result<()> {
    let cert = Cert::new("vless")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let [port, socks_h2, socks_http1] = common::free_ports();
        let configs = vec![
            vless_server(&cert, port, Some((http1, h2))),
            sail_client(vless_outbound(&cert, port, "h2"), socks_h2),
            sail_client(vless_outbound(&cert, port, "http/1.1"), socks_http1),
        ];
        with_sail(configs, move || {
            probe(port, b"\x08http/1.1", HTTP1_REQUEST, "http1")?;
            probe(port, b"\x02h2", H2_PREFACE, "h2")?;
            // A wrong UUID: the header, then whatever follows it.
            let mut wrong = vless_header("00000000-0000-0000-0000-000000000001");
            wrong.extend_from_slice(HTTP1_REQUEST);
            probe(port, b"\x02h2", &wrong, "h2")?;
            // A bad version.
            let mut bad_version = vless_header(UUID);
            bad_version[0] = 1;
            probe(port, b"\x08http/1.1", &bad_version, "http1")?;
            // A flow the user does not have.
            let mut vision = vec![0u8];
            vision.extend_from_slice(uuid::Uuid::parse_str(UUID)?.as_bytes());
            vision.extend_from_slice(b"\x12\x0a\x10xtls-rprx-vision");
            vision.extend_from_slice(&[1, 0, 80, 1, 127, 0, 0, 1]);
            probe(port, b"\x08http/1.1", &vision, "http1")?;
            // VLESS clients still get through, on either ALPN.
            echo_through_socks(socks_h2)?;
            echo_through_socks(socks_http1)?;
            Ok(())
        })
    })
}

#[test]
fn test_vless_fallback_after_partial_header() -> anyhow::Result<()> {
    let cert = Cert::new("vless-partial")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let configs = vec![vless_server(&cert, port, Some((http1, h2)))];
        with_sail(configs, move || {
            let header = vless_header(UUID);
            let took = probe(port, b"\x08http/1.1", &header[..10], "http1")?;
            anyhow::ensure!(
                took >= HEADER_TIMEOUT - Duration::from_millis(100),
                "fell back after {:?}, before the header timeout",
                took
            );
            Ok(())
        })
    })
}

#[test]
fn test_fallback_config_mistakes() -> anyhow::Result<()> {
    let cert = Cert::new("config")?;
    let bad = |inbound: fn(&Cert, u16, Option<(u16, u16)>) -> String,
               patch: &dyn Fn(&mut serde_json::Value)| {
        let [port, http1, h2] = common::free_ports();
        let mut config: serde_json::Value =
            serde_json::from_str(&inbound(&cert, port, Some((http1, h2)))).unwrap();
        patch(&mut config["inbounds"][0]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        match common::run_sail_instances(&rt, vec![config.to_string()]) {
            Ok(ids) => {
                for id in ids {
                    sail::shutdown(id);
                }
                false
            }
            Err(_) => true,
        }
    };
    type Server = fn(&Cert, u16, Option<(u16, u16)>) -> String;
    #[allow(unused_mut)]
    let mut inbounds: Vec<Server> = vec![trojan_server, vless_server];
    #[cfg(all(feature = "inbound-anytls", feature = "outbound-anytls"))]
    inbounds.push(anytls_server);
    #[cfg(all(feature = "inbound-sail", feature = "outbound-sail"))]
    inbounds.push(sail_server);
    for inbound in inbounds {
        anyhow::ensure!(bad(inbound, &|i| i["fallback_for_alpn"] =
            json!({ "": { "server": "127.0.0.1", "server_port": 80 } })));
        anyhow::ensure!(bad(inbound, &|i| i["fallback"]["port"] = json!(80)));
        anyhow::ensure!(bad(inbound, &|i| i["fallback"]["server_port"] = json!(0)));
        anyhow::ensure!(bad(inbound, &|i| i["fallback"]["server"] = json!("")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// AnyTLS
// ---------------------------------------------------------------------------

#[cfg(all(feature = "inbound-anytls", feature = "outbound-anytls"))]
fn anytls_server(cert: &Cert, port: u16, fallback: Option<(u16, u16)>) -> String {
    let mut inbound = json!({
        "type": "anytls",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "password": PASSWORD }],
        "tls": server_tls(cert),
    });
    if let Some((http1, h2)) = fallback {
        fallbacks(&mut inbound, http1, h2);
    }
    json!({ "inbounds": [inbound], "outbounds": [{ "type": "direct" }] }).to_string()
}

#[cfg(all(feature = "inbound-anytls", feature = "outbound-anytls"))]
fn anytls_outbound(cert: &Cert, server_port: u16, alpn: &str) -> serde_json::Value {
    json!({
        "type": "anytls",
        "server": "127.0.0.1",
        "server_port": server_port,
        "password": PASSWORD,
        "tls": client_tls(cert, alpn),
    })
}

/// How an AnyTLS client starts, with the SHA-256 of `password`: the hash,
/// then `padding` bytes of padding and their length.
#[cfg(all(feature = "inbound-anytls", feature = "outbound-anytls"))]
fn anytls_auth(password: &str, padding: u16) -> Vec<u8> {
    let mut auth = sha2::Sha256::digest(password.as_bytes()).to_vec();
    auth.extend_from_slice(&padding.to_be_bytes());
    auth.resize(auth.len() + padding as usize, 0);
    auth
}

#[cfg(all(feature = "inbound-anytls", feature = "outbound-anytls"))]
#[test]
fn test_anytls_fallback() -> anyhow::Result<()> {
    let cert = Cert::new("anytls")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let [port, socks_h2, socks_http1] = common::free_ports();
        let configs = vec![
            anytls_server(&cert, port, Some((http1, h2))),
            sail_client(anytls_outbound(&cert, port, "h2"), socks_h2),
            sail_client(anytls_outbound(&cert, port, "http/1.1"), socks_http1),
        ];
        with_sail(configs, move || {
            // A web client gets the web server, byte for byte, whichever
            // ALPN it speaks.
            probe(port, b"\x08http/1.1", HTTP1_REQUEST, "http1")?;
            probe(port, b"", HTTP1_REQUEST, "http1")?;
            probe(port, b"\x02h2", H2_PREFACE, "h2")?;
            // A well-formed start with a wrong password: its padding and what
            // follows it go to the fallback too.
            let mut wrong = anytls_auth("wrong", 30);
            wrong.extend_from_slice(HTTP1_REQUEST);
            probe(port, b"\x08http/1.1", &wrong, "http1")?;
            // Shorter than a hash: relayed once the header timeout is up.
            probe(port, b"\x02h2", b"GET / HTTP/1.1\r\n\r\n", "h2")?;
            // AnyTLS clients still get through, on either ALPN.
            echo_through_socks(socks_h2)?;
            echo_through_socks(socks_http1)?;
            Ok(())
        })
    })
}

#[cfg(all(feature = "inbound-anytls", feature = "outbound-anytls"))]
#[test]
fn test_anytls_fallback_after_partial_header() -> anyhow::Result<()> {
    let cert = Cert::new("anytls-partial")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let configs = vec![anytls_server(&cert, port, Some((http1, h2)))];
        with_sail(configs, move || {
            // Part of a user's hash: the inbound waits for the rest, then
            // gives up.
            let auth = anytls_auth(PASSWORD, 0);
            let took = probe(port, b"\x08http/1.1", &auth[..16], "http1")?;
            anyhow::ensure!(
                took >= HEADER_TIMEOUT - Duration::from_millis(100),
                "fell back after {:?}, before the header timeout",
                took
            );
            Ok(())
        })
    })
}

#[cfg(all(feature = "inbound-anytls", feature = "outbound-anytls"))]
#[test]
fn test_anytls_without_fallback_closes() -> anyhow::Result<()> {
    let cert = Cert::new("anytls-none")?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let configs = vec![anytls_server(&cert, port, None)];
        with_sail(configs, move || {
            let mut tls = tls_connect(port, b"\x08http/1.1")?;
            tls.write_all(HTTP1_REQUEST)?;
            let mut buf = [0u8; 64];
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => Ok(()),
                Ok(n) => Err(anyhow::anyhow!("got {} bytes without a fallback", n)),
            }
        })
    })
}

// ---------------------------------------------------------------------------
// Sail/1
// ---------------------------------------------------------------------------

/// The 32 bytes 0x5a, as a Sail/1 token.
#[cfg(all(feature = "inbound-sail", feature = "outbound-sail"))]
const SAIL_TOKEN: &str = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo";

#[cfg(all(feature = "inbound-sail", feature = "outbound-sail"))]
fn sail_server(cert: &Cert, port: u16, fallback: Option<(u16, u16)>) -> String {
    let mut inbound = json!({
        "type": "sail",
        "listen": "127.0.0.1",
        "listen_port": port,
        "users": [{ "token": SAIL_TOKEN }],
        "tls": server_tls(cert),
    });
    if let Some((http1, h2)) = fallback {
        fallbacks(&mut inbound, http1, h2);
    }
    json!({ "inbounds": [inbound], "outbounds": [{ "type": "direct" }] }).to_string()
}

#[cfg(all(feature = "inbound-sail", feature = "outbound-sail"))]
fn sail_outbound(cert: &Cert, server_port: u16, alpn: &str) -> serde_json::Value {
    json!({
        "type": "sail",
        "server": "127.0.0.1",
        "server_port": server_port,
        "token": SAIL_TOKEN,
        "tls": client_tls(cert, alpn),
    })
}

/// A Sail/1 prelude: `version`, the token of 32 `token` bytes, a digest,
/// and `padding` bytes of padding.
#[cfg(all(feature = "inbound-sail", feature = "outbound-sail"))]
fn sail_prelude(version: u8, token: u8, padding: u16) -> Vec<u8> {
    let mut prelude = vec![version];
    prelude.extend_from_slice(&[token; 32]);
    prelude.extend_from_slice(&[0; 8]);
    prelude.extend_from_slice(&padding.to_be_bytes());
    prelude.resize(prelude.len() + padding as usize, 0);
    prelude
}

/// What fails to open with a user's prelude goes to the web server, byte
/// for byte: a web client on either ALPN, a wrong token or version (its
/// padding and what follows too), random bytes, and what is short of a
/// prelude's head once the header timeout is up. Sail/1 clients get
/// through on either ALPN meanwhile.
#[cfg(all(feature = "inbound-sail", feature = "outbound-sail"))]
#[test]
fn test_sail_fallback() -> anyhow::Result<()> {
    let cert = Cert::new("sail")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let [port, socks_h2, socks_http1] = common::free_ports();
        let configs = vec![
            sail_server(&cert, port, Some((http1, h2))),
            sail_client(sail_outbound(&cert, port, "h2"), socks_h2),
            sail_client(sail_outbound(&cert, port, "http/1.1"), socks_http1),
        ];
        with_sail(configs, move || {
            probe(port, b"\x08http/1.1", HTTP1_REQUEST, "http1")?;
            probe(port, b"", HTTP1_REQUEST, "http1")?;
            probe(port, b"\x02h2", H2_PREFACE, "h2")?;
            let mut wrong = sail_prelude(1, 0x33, 30);
            wrong.extend_from_slice(HTTP1_REQUEST);
            probe(port, b"\x08http/1.1", &wrong, "http1")?;
            let mut version = sail_prelude(2, 0x5a, 0);
            version.extend_from_slice(HTTP1_REQUEST);
            probe(port, b"\x02h2", &version, "h2")?;
            let random: Vec<u8> = (0..300u32).map(|i| (i * 7919 % 251) as u8).collect();
            probe(port, b"\x08http/1.1", &random, "http1")?;
            probe(port, b"\x02h2", b"GET / HTTP/1.1\r\n\r\n", "h2")?;
            echo_through_socks(socks_h2)?;
            echo_through_socks(socks_http1)?;
            Ok(())
        })
    })
}

/// Part of a user's prelude, then nothing: the inbound waits for the rest
/// up to the header timeout, then gives the fallback what it read.
#[cfg(all(feature = "inbound-sail", feature = "outbound-sail"))]
#[test]
fn test_sail_fallback_after_truncated_prelude() -> anyhow::Result<()> {
    let cert = Cert::new("sail-truncated")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let configs = vec![sail_server(&cert, port, Some((http1, h2)))];
        with_sail(configs, move || {
            let prelude = sail_prelude(1, 0x5a, 0);
            let took = probe(port, b"\x08http/1.1", &prelude[..20], "http1")?;
            anyhow::ensure!(
                took >= HEADER_TIMEOUT - Duration::from_millis(100),
                "fell back after {:?}, before the header timeout",
                took
            );
            Ok(())
        })
    })
}

/// A user's prelude sent a byte at a time, slower than the header timeout
/// allows: the fallback gets every byte, those read before the timeout
/// and those after.
#[cfg(all(feature = "inbound-sail", feature = "outbound-sail"))]
#[test]
fn test_sail_fallback_slow_bytes() -> anyhow::Result<()> {
    let cert = Cert::new("sail-slow")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let configs = vec![sail_server(&cert, port, Some((http1, h2)))];
        with_sail(configs, move || {
            let prelude = sail_prelude(1, 0x5a, 0);
            let mut tls = tls_connect(port, b"\x08http/1.1")?;
            for byte in &prelude {
                tls.write_all(std::slice::from_ref(byte))?;
                tls.flush()?;
                std::thread::sleep(Duration::from_millis(60));
            }
            let expected = answer("http1", &prelude);
            let mut got = vec![0u8; expected.len()];
            tls.read_exact(&mut got)
                .map_err(|e| anyhow::anyhow!("no answer from the fallback: {}", e))?;
            anyhow::ensure!(got == expected, "the fallback got other bytes");
            Ok(())
        })
    })
}

#[cfg(all(feature = "inbound-sail", feature = "outbound-sail"))]
#[test]
fn test_sail_without_fallback_closes() -> anyhow::Result<()> {
    let cert = Cert::new("sail-none")?;
    common::retry_port_clash(|| {
        let port = common::free_port();
        let configs = vec![sail_server(&cert, port, None)];
        with_sail(configs, move || {
            let mut tls = tls_connect(port, b"\x08http/1.1")?;
            tls.write_all(HTTP1_REQUEST)?;
            let mut buf = [0u8; 64];
            match tls.read(&mut buf) {
                Ok(0) | Err(_) => Ok(()),
                Ok(n) => Err(anyhow::anyhow!("got {} bytes without a fallback", n)),
            }
        })
    })
}

// ---------------------------------------------------------------------------
// sing-box
// ---------------------------------------------------------------------------

fn sing_box_client(outbound: serde_json::Value, socks_port: u16) -> serde_json::Value {
    json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [outbound],
    })
}

#[test]
#[ignore]
fn test_trojan_fallback_sing_box_client() -> anyhow::Result<()> {
    let cert = Cert::new("sb-trojan")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let [port, socks_h2, socks_http1] = common::free_ports();
        let configs = vec![trojan_server(&cert, port, Some((http1, h2)))];
        let mut sing_box = Vec::new();
        for (alpn, socks) in [("h2", socks_h2), ("http/1.1", socks_http1)] {
            let config = sing_box_client(trojan_outbound(&cert, port, alpn), socks);
            sing_box.push(common::Daemon::sing_box(
                cert.dir.path(),
                &format!("client-{}", socks),
                config,
            )?);
        }
        with_sail(configs, move || {
            echo_through_socks(socks_h2)?;
            echo_through_socks(socks_http1)?;
            probe(port, b"\x02h2", H2_PREFACE, "h2")?;
            Ok(())
        })
    })
}

#[test]
#[ignore]
fn test_vless_fallback_sing_box_client() -> anyhow::Result<()> {
    let cert = Cert::new("sb-vless")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let [port, socks_h2, socks_http1] = common::free_ports();
        let configs = vec![vless_server(&cert, port, Some((http1, h2)))];
        let mut sing_box = Vec::new();
        for (alpn, socks) in [("h2", socks_h2), ("http/1.1", socks_http1)] {
            let config = sing_box_client(vless_outbound(&cert, port, alpn), socks);
            sing_box.push(common::Daemon::sing_box(
                cert.dir.path(),
                &format!("client-{}", socks),
                config,
            )?);
        }
        with_sail(configs, move || {
            echo_through_socks(socks_h2)?;
            echo_through_socks(socks_http1)?;
            probe(port, b"\x08http/1.1", HTTP1_REQUEST, "http1")?;
            Ok(())
        })
    })
}

#[cfg(all(feature = "inbound-anytls", feature = "outbound-anytls"))]
#[test]
#[ignore]
fn test_anytls_fallback_sing_box_client() -> anyhow::Result<()> {
    let cert = Cert::new("sb-anytls")?;
    let http1 = run_web_server("http1")?;
    let h2 = run_web_server("h2")?;
    common::retry_port_clash(|| {
        let [port, socks_h2, socks_http1] = common::free_ports();
        let configs = vec![anytls_server(&cert, port, Some((http1, h2)))];
        let mut sing_box = Vec::new();
        for (alpn, socks) in [("h2", socks_h2), ("http/1.1", socks_http1)] {
            let config = sing_box_client(anytls_outbound(&cert, port, alpn), socks);
            sing_box.push(common::Daemon::sing_box(
                cert.dir.path(),
                &format!("client-{}", socks),
                config,
            )?);
        }
        with_sail(configs, move || {
            echo_through_socks(socks_h2)?;
            echo_through_socks(socks_http1)?;
            probe(port, b"\x08http/1.1", HTTP1_REQUEST, "http1")?;
            Ok(())
        })
    })
}
