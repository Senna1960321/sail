use super::*;

#[derive(Clone, Copy, PartialEq)]
enum H3Reply {
    Answer,
    Silent,
    NxDomain,
    Slow,
    HttpError,
}

fn delayed_h2(cert: &Cert, listener: TcpListener) -> Arc<Counters> {
    use sail::adapter::{InboundStreamHandler, InboundTransport};
    use sail::session::Session;
    use sail::transport::tls::inbound::stream::Handler;

    let handler = Arc::new(
        Handler::new(
            cert.cert_pem.clone(),
            cert.key_pem.clone(),
            vec!["h2".into()],
            Default::default(),
        )
        .unwrap(),
    );
    listener.set_nonblocking(true).unwrap();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let counters = Arc::new(Counters::default());
    let c = counters.clone();
    tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        while let Ok((tcp, _)) = listener.accept().await {
            let handler = handler.clone();
            let c = c.clone();
            connections.spawn(async move {
                let Ok(InboundTransport::Stream(stream, _)) =
                    handler.handle(Session::default(), Box::new(tcp)).await
                else {
                    return;
                };
                c.connections.fetch_add(1, Ordering::SeqCst);
                let Ok(mut connection) = h2::server::handshake(stream).await else {
                    return;
                };
                let mut requests = tokio::task::JoinSet::new();
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let c = c.clone();
                    requests.spawn(async move {
                        let mut body = request.into_body();
                        let mut query = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                            query.extend_from_slice(&chunk);
                        }
                        c.count(&query);
                        tokio::time::sleep(Duration::from_millis(1200)).await;
                        let Some(response) = answer(&query) else {
                            return;
                        };
                        let head = http::Response::builder().status(200).body(()).unwrap();
                        if let Ok(mut send) = respond.send_response(head, false) {
                            let _ = send.send_data(Bytes::from(response), true);
                        }
                    });
                }
            });
        }
    });
    counters
}

fn controlled_h3(endpoint: quinn::Endpoint, mode: Arc<AtomicUsize>) -> Arc<Counters> {
    let counters = Arc::new(Counters::default());
    let c = counters.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let c = c.clone();
            let mode = mode.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                c.connections.fetch_add(1, Ordering::SeqCst);
                let Ok(mut h3_conn) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = h3_conn.accept().await {
                    let c = c.clone();
                    let mode = mode.clone();
                    tokio::spawn(async move {
                        let Ok((_req, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let mut query = Vec::new();
                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                            while chunk.has_remaining() {
                                let part = chunk.chunk().to_vec();
                                chunk.advance(part.len());
                                query.extend_from_slice(&part);
                            }
                        }
                        c.count(&query);
                        let mode = mode.load(Ordering::SeqCst);
                        if mode == H3Reply::Silent as usize {
                            std::future::pending::<()>().await;
                        }
                        if mode == H3Reply::Slow as usize {
                            tokio::time::sleep(Duration::from_millis(1200)).await;
                        }
                        let rcode = if mode == H3Reply::NxDomain as usize {
                            ResponseCode::NXDomain
                        } else {
                            ResponseCode::NoError
                        };
                        let Some(resp) = answer_with(&query, rcode) else {
                            return;
                        };
                        let head = http::Response::builder()
                            .status(if mode == H3Reply::HttpError as usize {
                                500
                            } else {
                                200
                            })
                            .header("content-type", "application/dns-message")
                            .body(())
                            .unwrap();
                        if stream.send_response(head).await.is_err() {
                            return;
                        }
                        let _ = stream.send_data(Bytes::from(resp)).await;
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    counters
}

async fn selected_h3_case(reply: H3Reply, batch: usize, sequential: bool) {
    let cert = cert();
    let (listener, socket) = (0..20)
        .find_map(|_| {
            let port = crate::common::free_port();
            let listener = TcpListener::bind(("127.0.0.1", port)).ok()?;
            let socket = std::net::UdpSocket::bind(("127.0.0.1", port)).ok()?;
            Some((listener, socket))
        })
        .expect("shared TCP/UDP port");
    let port = listener.local_addr().unwrap().port();
    let h2 = delayed_h2(&cert, listener);
    // Let both TLS handshakes finish before checking connection sharing.
    let mode = Arc::new(AtomicUsize::new(H3Reply::Slow as usize));
    let endpoint = quic_endpoint_on(quic_server_config(&cert, b"h3", None), socket);
    let h3 = controlled_h3(endpoint.clone(), mode.clone());
    let fallback = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config = config::Config::from_json(&serde_json::json!({
        "dns": { "timeout": if sequential { "30s" } else { "4s" }, "strategy": "ipv4_only", "final": if sequential { "seq" } else { "hybrid" }, "servers": [
            { "type": "https", "tag": "hybrid", "server": "127.0.0.1", "server_port": port,
              "prefer_h3": true, "tls": { "server_name": "localhost", "certificate": cert.cert_pem } },
            { "type": "udp", "tag": "unused", "server": "127.0.0.1", "server_port": fallback.local_addr().unwrap().port() },
            { "type": "sequential", "tag": "seq", "servers": ["hybrid", "unused"], "attempt_timeout": "2s", "budget": if sequential { "6s" } else { "3s" } }
        ] }
    }).to_string()).unwrap();
    let client = DnsClient::new(
        &config.dns,
        Arc::new(DialDefaults::default()),
        &Default::default(),
    )
    .unwrap()
    .into_arc();
    let mut h3_only = 0;
    for n in 0..20 {
        let before = h2.queries.load(Ordering::SeqCst);
        assert_eq!(
            lookup(&client, &format!("warm-{n}.example")).await.unwrap(),
            vec![IpAddr::V4(ANSWER)]
        );
        mode.store(H3Reply::Answer as usize, Ordering::SeqCst);
        if h2.queries.load(Ordering::SeqCst) == before {
            h3_only += 1;
        } else {
            h3_only = 0;
        }
        if h3_only == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(h3_only, 2, "must establish that the client chose H3");
    mode.store(reply as usize, Ordering::SeqCst);
    let before = h2.queries.load(Ordering::SeqCst);
    let hosts: Vec<_> = (0..batch)
        .map(|n| format!("after-h3-change-{n}.example"))
        .collect();
    let results = futures::future::join_all(hosts.iter().map(|host| lookup(&client, host))).await;
    let h2_new = h2.queries.load(Ordering::SeqCst) - before;
    endpoint.close(0u32.into(), b"test complete");
    for result in results {
        if reply == H3Reply::NxDomain {
            assert!(result.unwrap_err().to_string().contains("does not exist"));
        } else {
            assert_eq!(result.unwrap(), vec![IpAddr::V4(ANSWER)]);
        }
    }
    assert_eq!(
        h2_new,
        if matches!(reply, H3Reply::Silent | H3Reply::HttpError) {
            batch
        } else {
            0
        }
    );
    assert_eq!(h2.connections.load(Ordering::SeqCst), 1);
    assert!(h3.queries.load(Ordering::SeqCst) >= batch + 2);
    let mut packet = [0; 512];
    assert!(
        matches!(fallback.try_recv(&mut packet), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn selected_silent_h3_gives_slow_h2_a_full_sequential_attempt() {
    selected_h3_case(H3Reply::Silent, 1, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn selected_silent_h3_queries_share_the_h2_fallback() {
    selected_h3_case(H3Reply::Silent, 8, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn selected_h3_nxdomain_is_an_answer_without_fallback() {
    selected_h3_case(H3Reply::NxDomain, 1, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn selected_h3_http_error_still_falls_back_to_h2() {
    selected_h3_case(H3Reply::HttpError, 1, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nonsequential_h3_keeps_its_normal_timeout() {
    selected_h3_case(H3Reply::Slow, 1, false).await;
}
