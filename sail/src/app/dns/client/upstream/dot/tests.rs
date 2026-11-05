use super::*;
use std::future::Future;
use tokio::io::{duplex, DuplexStream};

async fn scoped(test: impl Future<Output = ()>) {
    let scope = crate::runtime::scope::TaskScope::default();
    timeout(Duration::from_secs(5), scope.enter(test))
        .await
        .expect("DoT test did not finish");
    assert!(scope.stop(Duration::from_secs(1)).await.clean());
}

fn message(id: u16, marker: u8) -> Vec<u8> {
    let mut message = vec![0; 13];
    message[..2].copy_from_slice(&id.to_be_bytes());
    message[12] = marker;
    message
}

async fn read_frame(peer: &mut DuplexStream) -> Vec<u8> {
    let len = peer.read_u16().await.unwrap() as usize;
    let mut message = vec![0; len];
    peer.read_exact(&mut message).await.unwrap();
    message
}

async fn reply(peer: &mut DuplexStream, message: &[u8]) {
    peer.write_u16(message.len() as u16).await.unwrap();
    peer.write_all(message).await.unwrap();
    peer.flush().await.unwrap();
}

async fn connection(
    slots: &Arc<Semaphore>,
    capacity: usize,
    write_timeout: Duration,
) -> (Arc<Connection>, DuplexStream) {
    let (stream, peer) = duplex(capacity);
    let permit = slots.clone().acquire_owned().await.unwrap();
    (
        Connection::new(Box::new(stream), permit, write_timeout),
        peer,
    )
}

async fn kept(pool: &Pool, connection: &Arc<Connection>) {
    let mut state = pool.state.lock().await;
    state.live.push(Arc::downgrade(connection));
    state.kept = Some(connection.clone());
}

fn client() -> (DnsClient, Arc<Upstream>) {
    let config = crate::config::Config::from_json(
        &serde_json::json!({ "dns": {
            "timeout": "30s",
            "servers": [{ "type": "tls", "tag": "dot", "server": "127.0.0.1" }]
        } })
        .to_string(),
    )
    .unwrap();
    let client = DnsClient::new(&config.dns, Default::default(), &Default::default()).unwrap();
    let crate::app::dns::client::server::Kind::Upstream(upstream) = &client.servers["dot"].kind
    else {
        panic!("not a DoT upstream");
    };
    let upstream = upstream.clone();
    (client, upstream)
}

#[tokio::test]
async fn duplicate_original_ids_receive_their_own_out_of_order_answers() {
    scoped(async {
        let slots = Arc::new(Semaphore::new(1));
        let (connection, mut peer) = connection(&slots, 1024, Duration::from_secs(1)).await;
        let requests: Vec<_> = (0..8).map(|marker| message(42, marker)).collect();
        let queries = requests
            .iter()
            .map(|request| connection.reserve(request).unwrap().exchange());
        let server = async {
            let mut frames = Vec::new();
            for _ in 0..8 {
                frames.push(read_frame(&mut peer).await);
            }
            let ids: std::collections::HashSet<_> =
                frames.iter().map(|frame| [frame[0], frame[1]]).collect();
            assert_eq!(ids.len(), frames.len(), "wire IDs must be distinct");
            for frame in frames.iter().rev() {
                reply(&mut peer, frame).await;
            }
        };
        let (answers, ()) = tokio::join!(futures::future::join_all(queries), server);
        for (answer, request) in answers.into_iter().zip(requests) {
            assert_eq!(answer.unwrap(), request);
        }
    })
    .await;
}

#[tokio::test]
async fn a_late_cancelled_answer_cannot_answer_the_next_query() {
    scoped(async {
        let slots = Arc::new(Semaphore::new(1));
        let (connection, mut peer) = connection(&slots, 1024, Duration::from_secs(1)).await;
        let first = connection.reserve(&message(42, 1)).unwrap();
        let first = crate::runtime::scope::spawn("cancelled DoT test query", first.exchange());
        let old = read_frame(&mut peer).await;
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        let next_request = message(42, 2);
        let next = connection.reserve(&next_request).unwrap();
        let next = crate::runtime::scope::spawn("next DoT test query", next.exchange());
        let current = read_frame(&mut peer).await;
        assert_ne!(&old[..2], &current[..2]);
        reply(&mut peer, &old).await;
        tokio::task::yield_now().await;
        assert!(!next.is_finished(), "a stale answer completed a new query");
        reply(&mut peer, &current).await;
        assert_eq!(next.await.unwrap().unwrap(), next_request);
    })
    .await;
}

#[tokio::test]
async fn cancelling_a_partial_write_keeps_the_next_frame_aligned() {
    scoped(async {
        // Four bytes force a frame to be written over several polls.
        let slots = Arc::new(Semaphore::new(1));
        let (connection, mut peer) = connection(&slots, 4, Duration::from_secs(1)).await;
        let mut first_request = message(42, 1);
        first_request.resize(128, 17);
        let first = connection.reserve(&first_request).unwrap();
        let first = crate::runtime::scope::spawn("partial DoT test query", first.exchange());
        let len = peer.read_u16().await.unwrap() as usize;
        let id = peer.read_u16().await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());

        // A queued query cancelled before its write must be skipped.
        let cancelled = connection.reserve(&message(42, 2)).unwrap();
        let cancelled = crate::runtime::scope::spawn("queued DoT test query", cancelled.exchange());
        tokio::task::yield_now().await;
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        let next_request = message(42, 3);
        let next = connection.reserve(&next_request).unwrap();
        let next = crate::runtime::scope::spawn("aligned DoT test query", next.exchange());

        let mut tail = vec![0; len - 2];
        peer.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, first_request[2..]);
        let current = read_frame(&mut peer).await;
        assert_ne!(id.to_be_bytes(), current[..2]);
        assert_eq!(&current[2..], &next_request[2..]);
        reply(&mut peer, &current).await;
        assert_eq!(next.await.unwrap().unwrap(), next_request);
    })
    .await;
}

#[tokio::test]
async fn malformed_or_truncated_replies_fail_all_queries_and_release_the_slot() {
    scoped(async {
        for short in [true, false] {
            let slots = Arc::new(Semaphore::new(1));
            let (connection, mut peer) = connection(&slots, 1024, Duration::from_secs(1)).await;
            let first = connection.reserve(&message(1, 1)).unwrap();
            let second = connection.reserve(&message(2, 2)).unwrap();
            let first = crate::runtime::scope::spawn("first broken DoT query", first.exchange());
            let second = crate::runtime::scope::spawn("second broken DoT query", second.exchange());
            read_frame(&mut peer).await;
            read_frame(&mut peer).await;
            if short {
                peer.write_u16(11).await.unwrap();
            } else {
                peer.write_u16(128).await.unwrap();
                peer.write_all(&[0; 5]).await.unwrap();
                peer.shutdown().await.unwrap();
            }
            assert!(first.await.unwrap().is_err());
            assert!(second.await.unwrap().is_err());
            assert!(connection.reserve(&message(3, 3)).is_none());
            assert_eq!(slots.available_permits(), 1);
        }
    })
    .await;
}

#[tokio::test]
async fn a_write_timeout_closes_the_connection_and_wakes_every_waiter() {
    scoped(async {
        let slots = Arc::new(Semaphore::new(1));
        let (connection, _peer) = connection(&slots, 1, Duration::from_millis(10)).await;
        let first = connection.reserve(&message(1, 1)).unwrap().exchange();
        let second = connection.reserve(&message(2, 2)).unwrap().exchange();
        let (first, second) = tokio::join!(first, second);
        assert!(first.is_err());
        assert!(second.is_err());
        assert_eq!(slots.available_permits(), 1);
    })
    .await;
}

#[tokio::test]
async fn aborting_before_the_driver_is_polled_releases_its_slot() {
    scoped(async {
        let slots = Arc::new(Semaphore::new(1));
        let (connection, _peer) = connection(&slots, 1024, Duration::from_secs(1)).await;
        let query = connection.reserve(&message(1, 1)).unwrap();
        connection.driver.abort();
        assert!(query.exchange().await.is_err());
        assert_eq!(slots.available_permits(), 1);
    })
    .await;
}

#[tokio::test]
async fn id_exhaustion_retires_new_queries_but_finishes_the_last_one() {
    scoped(async {
        let slots = Arc::new(Semaphore::new(1));
        let (connection, mut peer) = connection(&slots, 1024, Duration::from_secs(1)).await;
        connection.shared.lock().unwrap().next_id = u16::MAX as u32;
        let request = message(42, 1);
        let last = connection.reserve(&request).unwrap();
        assert!(connection.reserve(&message(42, 2)).is_none());
        let last = crate::runtime::scope::spawn("last DoT ID query", last.exchange());
        let frame = read_frame(&mut peer).await;
        assert_eq!(&frame[..2], &u16::MAX.to_be_bytes());
        reply(&mut peer, &frame).await;
        assert_eq!(last.await.unwrap().unwrap(), request);
        assert!(connection.reserve(&message(42, 3)).is_none());
    })
    .await;
}

#[tokio::test]
async fn idle_expiry_does_not_retire_a_connection_with_active_queries() {
    scoped(async {
        let slots = Arc::new(Semaphore::new(1));
        let (connection, _peer) = connection(&slots, 1024, Duration::from_secs(1)).await;
        let query = connection.reserve(&message(1, 1)).unwrap();
        connection.shared.lock().unwrap().used = Instant::now() - IDLE_TIMEOUT;
        let another = connection.reserve(&message(2, 2)).unwrap();
        drop(query);
        drop(another);
        connection.shared.lock().unwrap().used = Instant::now() - IDLE_TIMEOUT;
        assert!(connection.reserve(&message(3, 3)).is_none());
    })
    .await;
}

#[tokio::test]
async fn close_idle_leaves_an_active_query_alive_then_releases_the_connection() {
    scoped(async {
        let pool = Pool::default();
        let (connection, mut peer) =
            connection(&pool.connections, 1024, Duration::from_secs(1)).await;
        kept(&pool, &connection).await;
        let request = message(42, 1);
        let query = connection.reserve(&request).unwrap();
        let query = crate::runtime::scope::spawn("retired DoT query", query.exchange());
        let frame = read_frame(&mut peer).await;
        drop(connection);
        pool.close_idle().await;
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS - 1);
        reply(&mut peer, &frame).await;
        assert_eq!(query.await.unwrap().unwrap(), request);
        let all = pool
            .connections
            .clone()
            .acquire_many_owned(MAX_CONNECTIONS as u32)
            .await
            .unwrap();
        drop(all);
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS);
    })
    .await;
}

#[tokio::test]
async fn reset_aborts_retired_connections_as_well_as_the_kept_one() {
    scoped(async {
        let pool = Pool::default();
        let mut peers = Vec::new();
        let mut queries = Vec::new();
        for marker in 0..MAX_CONNECTIONS {
            let (connection, mut peer) =
                connection(&pool.connections, 1024, Duration::from_secs(1)).await;
            kept(&pool, &connection).await;
            let query = connection.reserve(&message(42, marker as u8)).unwrap();
            queries.push(crate::runtime::scope::spawn(
                "reset DoT query",
                query.exchange(),
            ));
            read_frame(&mut peer).await;
            peers.push(peer);
        }
        assert!(pool.connections.clone().try_acquire_owned().is_err());
        pool.clear().await;
        for query in queries {
            assert!(query.await.unwrap().is_err());
        }
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS);
        for mut peer in peers {
            let mut byte = [0];
            assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        }
    })
    .await;
}

#[tokio::test]
async fn the_in_flight_limit_is_enforced_before_reserving_a_wire_id() {
    scoped(async {
        let pool = Pool::default();
        let (connection, mut peer) =
            connection(&pool.connections, 4096, Duration::from_secs(1)).await;
        kept(&pool, &connection).await;
        let (client, upstream) = client();
        let addr = "127.0.0.1:853".parse().unwrap();
        let requests: Vec<_> = (0..=MAX_IN_FLIGHT)
            .map(|marker| message(42, marker as u8))
            .collect();
        let queries = requests
            .iter()
            .map(|request| client.exchange_dot(&upstream, &pool, addr, request));
        let server = async {
            let mut frames = Vec::new();
            for _ in 0..MAX_IN_FLIGHT {
                frames.push(read_frame(&mut peer).await);
            }
            assert_eq!(
                connection.shared.lock().unwrap().pending.len(),
                MAX_IN_FLIGHT
            );
            assert!(timeout(Duration::from_millis(10), peer.read_u16())
                .await
                .is_err());
            reply(&mut peer, &frames.remove(0)).await;
            frames.push(read_frame(&mut peer).await);
            for frame in frames {
                reply(&mut peer, &frame).await;
            }
        };
        let (answers, ()) = tokio::join!(futures::future::join_all(queries), server);
        for (answer, request) in answers.into_iter().zip(requests) {
            assert_eq!(answer.unwrap(), request);
        }
    })
    .await;
}

#[tokio::test]
async fn query_length_limits_reject_invalid_messages_and_preserve_the_largest_frame() {
    scoped(async {
        let pool = Pool::default();
        let (client, upstream) = client();
        let addr = "127.0.0.1:853".parse().unwrap();
        for len in [0, 11, u16::MAX as usize + 1] {
            let error = client
                .exchange_dot(&upstream, &pool, addr, &vec![0; len])
                .await
                .unwrap_err();
            assert!(error.to_string().contains("invalid DNS query length"));
        }
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS);
        let (connection, mut peer) =
            connection(&pool.connections, 1024, Duration::from_secs(1)).await;
        kept(&pool, &connection).await;
        let mut request = message(42, 1);
        request.resize(u16::MAX as usize, 7);
        let query = client.exchange_dot(&upstream, &pool, addr, &request);
        let server = async {
            let frame = read_frame(&mut peer).await;
            assert_eq!(frame.len(), u16::MAX as usize);
            assert_eq!(&frame[2..], &request[2..]);
            reply(&mut peer, &frame).await;
        };
        let (answer, ()) = tokio::join!(query, server);
        assert_eq!(answer.unwrap(), request);
    })
    .await;
}

#[tokio::test]
async fn a_sequential_reuse_timeout_yields_to_the_outer_retry_budget() {
    scoped(async {
        let pool = Pool::default();
        let (connection, _peer) = connection(&pool.connections, 1024, Duration::from_secs(1)).await;
        kept(&pool, &connection).await;
        let (client, upstream) = client();
        let timed_out = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let attempt = super::super::Attempt {
            reuse: Some(Duration::from_millis(10)),
            kept_timed_out: timed_out.clone(),
        };
        let request = message(42, 1);
        let error = super::super::ATTEMPT
            .scope(
                attempt,
                client.exchange_dot(&upstream, &pool, "127.0.0.1:853".parse().unwrap(), &request),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("kept connection timed out"));
        assert!(timed_out.load(std::sync::atomic::Ordering::Relaxed));
        assert!(connection.shared.lock().unwrap().pending.is_empty());
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS - 1);
    })
    .await;
}

#[tokio::test]
async fn reset_cancels_a_stalled_handshake_before_it_can_repopulate_the_pool() {
    scoped(async {
        let pool = Arc::new(Pool::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let dialing_pool = pool.clone();
        let mut dial = crate::runtime::scope::spawn("stalled DoT handshake", async move {
            let (client, upstream) = client();
            dialing_pool
                .query(&client, &upstream, addr, &message(42, 1), true, None)
                .await
                .map(|_| ())
        });
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        peer.read_exact(&mut byte).await.unwrap();
        // TCP is connected and the ClientHello is being sent, but this
        // server never answers the handshake.
        let reset = timeout(Duration::from_millis(100), pool.clear()).await;
        if reset.is_err() {
            dial.abort();
        }
        let result = timeout(Duration::from_millis(100), &mut dial).await;
        if result.is_err() {
            dial.abort();
            let _ = dial.await;
        }
        pool.clear().await;
        assert!(reset.is_ok(), "network reset waited for the TLS handshake");
        assert!(
            result.unwrap().unwrap().is_err(),
            "a pre-reset dial survived"
        );
        assert!(pool.state.lock().await.kept.is_none());
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS);
    })
    .await;
}

#[tokio::test]
async fn reset_is_not_blocked_by_a_query_waiting_for_a_connection_slot() {
    scoped(async {
        let pool = Arc::new(Pool::default());
        let mut retained = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let (connection, peer) =
                connection(&pool.connections, 1024, Duration::from_secs(1)).await;
            kept(&pool, &connection).await;
            let query = connection.reserve(&message(42, 1)).unwrap();
            retained.push((query, peer));
        }
        pool.close_idle().await;
        let (client, upstream) = client();
        let request = message(42, 1);
        let mut waiter = Box::pin(pool.query(
            &client,
            &upstream,
            "127.0.0.1:853".parse().unwrap(),
            &request,
            true,
            None,
        ));
        // Poll through connection creation to the exhausted semaphore.
        assert!(futures::poll!(waiter.as_mut()).is_pending());
        let reset = timeout(Duration::from_millis(100), pool.clear()).await;
        drop(waiter);
        pool.clear().await;
        assert!(
            reset.is_ok(),
            "network reset waited on exhausted connection slots"
        );
    })
    .await;
}

// Quota waiters have not entered Pool::query yet, so its generation
// subscription alone cannot cancel them.
#[tokio::test]
async fn reset_cancels_a_query_waiting_for_the_in_flight_quota() {
    scoped(async {
        let pool = Pool::default();
        let occupied = pool
            .queries
            .acquire_many(MAX_IN_FLIGHT as u32)
            .await
            .unwrap();
        let (client, upstream) = client();
        let request = message(42, 1);
        let mut waiter = Box::pin(client.exchange_dot(
            &upstream,
            &pool,
            "127.0.0.1:853".parse().unwrap(),
            &request,
        ));
        assert!(futures::poll!(waiter.as_mut()).is_pending());
        pool.clear().await;
        let error = timeout(Duration::from_millis(100), waiter)
            .await
            .expect("reset must wake the query quota waiter")
            .unwrap_err();
        assert_eq!(error.to_string(), "DoT network changed");
        drop(occupied);
        assert_eq!(pool.queries.available_permits(), MAX_IN_FLIGHT);
        assert_eq!(pool.connections.available_permits(), MAX_CONNECTIONS);
        assert!(pool.state.lock().await.kept.is_none());
    })
    .await;
}

#[tokio::test]
async fn cancelling_an_exchange_releases_its_query_quota_and_pending_id() {
    scoped(async {
        let pool = Pool::default();
        let (connection, mut peer) =
            connection(&pool.connections, 1024, Duration::from_secs(1)).await;
        kept(&pool, &connection).await;
        let (client, upstream) = client();
        let request = message(42, 1);
        let mut exchange = Box::pin(client.exchange_dot(
            &upstream,
            &pool,
            "127.0.0.1:853".parse().unwrap(),
            &request,
        ));
        assert!(futures::poll!(exchange.as_mut()).is_pending());
        let old = read_frame(&mut peer).await;
        assert_eq!(pool.queries.available_permits(), MAX_IN_FLIGHT - 1);
        drop(exchange);
        assert_eq!(pool.queries.available_permits(), MAX_IN_FLIGHT);
        assert!(connection.shared.lock().unwrap().pending.is_empty());
        let next_request = message(42, 2);
        let next = client.exchange_dot(
            &upstream,
            &pool,
            "127.0.0.1:853".parse().unwrap(),
            &next_request,
        );
        let server = async {
            let current = read_frame(&mut peer).await;
            assert_ne!(&old[..2], &current[..2]);
            reply(&mut peer, &old).await;
            reply(&mut peer, &current).await;
            // A duplicate response must not be delivered to any later query.
            reply(&mut peer, &current).await;
        };
        let (answer, ()) = tokio::join!(next, server);
        assert_eq!(answer.unwrap(), next_request);
        assert_eq!(pool.queries.available_permits(), MAX_IN_FLIGHT);
    })
    .await;
}
