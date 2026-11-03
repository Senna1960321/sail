//! A host's own admission (`Options::admit`, `Options::admit_source`):
//! what it rejects is never routed and counted by its reason; it is never
//! awaited, so a slow check holds back its own connection alone; one that
//! panics rejects and sail serves on; and the check of a connection's
//! addresses runs before its handshake.
#![cfg(all(feature = "outbound-direct", feature = "inbound-socks"))]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use sail::embed::{Config, Event, Instance, Kinds, Options, RecordKind, Threads, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::common;

/// An instance with a SOCKS inbound and `options`; its port.
async fn start(options: Options) -> (Instance, u16) {
    let port = common::free_port();
    let instance = Instance::new(options.threads(Threads::Workers(2, 2 << 20))).unwrap();
    let config = serde_json::json!({
        "log": { "level": "debug" },
        "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    });
    instance
        .start(Config::Json(config.to_string()))
        .await
        .unwrap();
    (instance, port)
}

/// An echo server that counts the connections it accepts.
async fn counted_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counted = accepted.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, accepted)
}

/// Connects through the SOCKS inbound on `port` to `to` and echoes a few
/// bytes; whether that went through.
async fn through(port: u16, to: SocketAddr) -> bool {
    let attempt = async {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
        s.write_all(&[5, 1, 0]).await?;
        let mut method = [0u8; 2];
        s.read_exact(&mut method).await?;
        let SocketAddr::V4(to) = to else {
            unreachable!("an IPv4 server")
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&to.ip().octets());
        request.extend_from_slice(&to.port().to_be_bytes());
        s.write_all(&request).await?;
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await?;
        if reply[1] != 0 {
            return Ok(false);
        }
        s.write_all(b"ping").await?;
        let mut back = [0u8; 4];
        s.read_exact(&mut back).await?;
        std::io::Result::Ok(&back == b"ping")
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(10), attempt).await,
        Ok(Ok(true))
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_the_host_rejects_is_never_routed_and_is_counted() {
    let (open, _) = counted_echo().await;
    let (blocked, blocked_accepts) = counted_echo().await;
    let blocked_port = blocked.port();
    let options =
        Options::new().admit(
            move |session| match session.destination.port() == blocked_port {
                true => Verdict::reject("blocked"),
                false => Verdict::Accept,
            },
        );
    let (instance, port) = start(options).await;
    let mut events = Box::pin(instance.events(Kinds::CONNECTION));

    assert!(through(port, open).await);
    assert!(!through(port, blocked).await);
    assert!(!through(port, blocked).await);
    assert_eq!(blocked_accepts.load(Ordering::Relaxed), 0, "never dialled");
    let info = instance
        .admission()
        .unwrap()
        .expect("on for the host's checks");
    assert_eq!(info.host_refused.get("blocked"), Some(&2), "{:?}", info);
    assert_eq!(info.host_panics, 0);

    // The one that went through has its record; those rejected none.
    let mut closed = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(2), events.next()).await {
        if let Event::ConnectionRecord(record) = event {
            if matches!(record.kind, RecordKind::Closed(_)) {
                closed.push(record);
            }
        }
    }
    assert!(
        closed.iter().all(|r| r.destination.port() != blocked_port),
        "{:?}",
        closed
    );
    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_check_holds_back_its_own_connection_alone() {
    let (slow, _) = counted_echo().await;
    let (fast, _) = counted_echo().await;
    let slow_port = slow.port();
    let options = Options::new().admit(move |session| {
        if session.destination.port() == slow_port {
            // Blocks its thread, as a check never should.
            std::thread::sleep(Duration::from_secs(2));
        }
        Verdict::Accept
    });
    let (instance, port) = start(options).await;
    let slowly = tokio::spawn(async move { through(port, slow).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    assert!(through(port, fast).await);
    let took = started.elapsed();
    assert!(took < Duration::from_millis(1500), "{:?}", took);
    assert!(
        slowly.await.unwrap(),
        "the slow one gets through in the end"
    );
    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_check_that_panics_rejects_and_sail_serves_on() {
    let (open, _) = counted_echo().await;
    let (doomed, doomed_accepts) = counted_echo().await;
    let doomed_port = doomed.port();
    let options = Options::new().admit(move |session| {
        if session.destination.port() == doomed_port {
            panic!("a host's check that panics");
        }
        Verdict::Accept
    });
    let (instance, port) = start(options).await;
    assert!(!through(port, doomed).await);
    assert!(through(port, open).await);
    assert_eq!(doomed_accepts.load(Ordering::Relaxed), 0);
    let info = instance.admission().unwrap().unwrap();
    assert_eq!(info.host_panics, 1, "{:?}", info);
    assert_eq!(instance.faults().unwrap(), 0, "the panic reached no task");
    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sources_check_runs_before_the_handshake() {
    let (open, _) = counted_echo().await;
    let refusing = Arc::new(AtomicBool::new(true));
    let sessions = Arc::new(AtomicUsize::new(0));
    let seen: Arc<std::sync::Mutex<Vec<(SocketAddr, SocketAddr)>>> = Default::default();
    let options = {
        let (refusing, sessions, seen) = (refusing.clone(), sessions.clone(), seen.clone());
        Options::new()
            .admit_source(move |source, local| {
                seen.lock().unwrap().push((source, local));
                match refusing.load(Ordering::Relaxed) {
                    true => Verdict::reject("source"),
                    false => Verdict::Accept,
                }
            })
            .admit(move |_| {
                sessions.fetch_add(1, Ordering::Relaxed);
                Verdict::Accept
            })
    };
    let (instance, port) = start(options).await;

    // Closed before the SOCKS greeting is answered.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let _ = s.write_all(&[5, 1, 0]).await;
    let mut buf = [0u8; 2];
    let read = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("closed in time");
    assert!(matches!(read, Ok(0) | Err(_)), "{:?}", read);
    assert_eq!(sessions.load(Ordering::Relaxed), 0);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{:?}", seen);
        assert_eq!(seen[0].0, s.local_addr().unwrap());
        assert_eq!(seen[0].1, SocketAddr::from(([127, 0, 0, 1], port)));
    }
    let info = instance.admission().unwrap().unwrap();
    assert_eq!(info.host_refused.get("source"), Some(&1), "{:?}", info);

    refusing.store(false, Ordering::Relaxed);
    assert!(through(port, open).await);
    assert_eq!(sessions.load(Ordering::Relaxed), 1);
    instance.stop().await.unwrap();
}
