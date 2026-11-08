//! A retained DoH connection goes silent, while its replacement is slow
//! enough to require its own complete sequential attempt.

use super::*;
use sail::adapter::{AnyStream, InboundStreamHandler, InboundTransport};
use sail::session::Session;
use sail::transport::tls::inbound::stream::Handler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn sequential_client(port: u16, fallback: u16, cert: &Cert) -> DnsClient {
    let config = config::Config::from_json(
        &serde_json::json!({ "dns": {
            "timeout": "30s", "strategy": "ipv4_only", "final": "seq",
            "servers": [
                { "type": "https", "tag": "doh", "server": "127.0.0.1",
                  "server_port": port, "tls": { "server_name": "localhost",
                  "certificate": cert.cert_pem } },
                { "type": "udp", "tag": "fallback", "server": "127.0.0.1",
                  "server_port": fallback },
                { "type": "sequential", "tag": "seq", "servers": ["doh", "fallback"],
                  "attempt_timeout": "2s", "budget": "6s" }
            ]
        } })
        .to_string(),
    )
    .unwrap();
    // Keep the production default of four retries inside ask().
    DnsClient::new(
        &config.dns,
        Arc::new(DialDefaults::default()),
        &Default::default(),
    )
    .unwrap()
}

async fn http1_query(stream: &mut AnyStream) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.ok()?);
        assert!(head.len() < 16 * 1024);
    }
    let head = String::from_utf8(head).unwrap();
    let len = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    let mut query = vec![0; len];
    stream.read_exact(&mut query).await.ok()?;
    Some(query)
}

async fn stale_then_slow(alpn: &str, batch: usize, slow_handshake: bool, cold: bool) {
    let cert = cert();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fallback = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = sequential_client(port, fallback.local_addr().unwrap().port(), &cert);
    let handler = Arc::new(
        Handler::new(
            cert.cert_pem,
            cert.key_pem,
            vec![alpn.into()],
            Default::default(),
        )
        .unwrap(),
    );
    let counters = Arc::new(Counters::default());
    let replacement_batch = Arc::new(tokio::sync::Barrier::new(batch));
    let h2 = alpn == "h2";
    let c = counters.clone();
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        while let Ok((tcp, _)) = listener.accept().await {
            let handler = handler.clone();
            let c = c.clone();
            let replacement_batch = replacement_batch.clone();
            connections.spawn(async move {
                let first = c.connections.fetch_add(1, Ordering::SeqCst) == 0;
                if !first && slow_handshake {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                }
                let InboundTransport::Stream(mut stream, _) = handler.handle(Session::default(), Box::new(tcp)).await.unwrap() else { panic!("TLS stream") };
                if h2 {
                    let mut conn = h2::server::handshake(stream).await.unwrap();
                    let mut queries = tokio::task::JoinSet::new();
                    let mut number = 0;
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        number += 1;
                        let silent = first && number > 1 && !cold;
                        let c = c.clone();
                        let barrier = replacement_batch.clone();
                        queries.spawn(async move {
                            let mut body = req.into_body();
                            let mut query = Vec::new();
                            while let Some(Ok(chunk)) = body.data().await {
                                body.flow_control().release_capacity(chunk.len()).unwrap();
                                query.extend_from_slice(&chunk);
                            }
                            c.count(&query);
                            if silent {
                                // Hold the stream open, without a response or RST.
                                std::future::pending::<()>().await;
                            }
                            if !first || cold {
                                barrier.wait().await;
                                if !slow_handshake {
                                    tokio::time::sleep(Duration::from_millis(1200)).await;
                                }
                            }
                            let head = http::Response::builder().status(200).body(()).unwrap();
                            if let Ok(mut send) = respond.send_response(head, false) {
                                let _ = send.send_data(Bytes::from(answer(&query).unwrap()), true);
                            }
                        });
                    }
                } else {
                    let mut number = 0;
                    while let Some(query) = http1_query(&mut stream).await {
                        number += 1;
                        c.count(&query);
                        if first && number > 1 {
                            std::future::pending::<()>().await;
                        }
                        if !first {
                            tokio::time::sleep(Duration::from_millis(1200)).await;
                        }
                        let response = answer(&query).unwrap();
                        let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", response.len());
                        if stream.write_all(head.as_bytes()).await.is_err() || stream.write_all(&response).await.is_err() || stream.flush().await.is_err() { break; }
                    }
                }
            });
        }
    });
    if !cold {
        assert_eq!(
            lookup(&client, "prime.example").await.unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
    }
    let hosts: Vec<_> = (0..batch).map(|i| format!("retry-{i}.example")).collect();
    let answers = tokio::time::timeout(
        Duration::from_secs(10),
        futures::future::join_all(hosts.iter().map(|host| lookup(&client, host))),
    )
    .await
    .unwrap();
    server.abort();
    let _ = server.await;
    for answer in answers {
        assert_eq!(answer.unwrap(), vec![IpAddr::V4(ANSWER)], "{alpn}");
    }
    assert_eq!(
        counters.connections.load(Ordering::SeqCst),
        if cold { 1 } else { 2 },
        "{alpn}"
    );
    assert_eq!(
        counters.queries.load(Ordering::SeqCst),
        if cold { batch } else { 1 + 2 * batch },
        "{alpn}"
    );
    let mut packet = [0; 512];
    assert!(
        matches!(fallback.try_recv(&mut packet), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_http1_stale_probe_retries_with_a_full_attempt() {
    stale_then_slow("http/1.1", 1, false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_http2_stale_batch_shares_a_full_replacement_attempt() {
    stale_then_slow("h2", 8, false, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_http2_sibling_timeouts_do_not_wait_for_a_replacement_handshake() {
    stale_then_slow("h2", 8, true, false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_http2_cold_batch_uses_one_connection_and_the_full_attempt() {
    stale_then_slow("h2", 8, false, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_sequential_nxdomain_is_an_answer_not_a_reconnect() {
    let cert = cert();
    for alpn in ["h2", "http/1.1"] {
        let (port, counters) =
            super::doh::start_server(&cert, &[alpn], super::doh::Reply::NxDomain);
        let fallback = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = sequential_client(port, fallback.local_addr().unwrap().port(), &cert);
        for host in ["first.example", "kept.example"] {
            assert!(lookup(&client, host)
                .await
                .unwrap_err()
                .to_string()
                .contains("does not exist"));
        }
        assert_eq!(counters.connections.load(Ordering::SeqCst), 1);
        assert_eq!(counters.queries.load(Ordering::SeqCst), 2);
        let mut packet = [0; 512];
        assert!(
            matches!(fallback.try_recv(&mut packet), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}
