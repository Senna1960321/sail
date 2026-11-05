//! A host's own admission (`Options::admit`, `Options::admit_source`):
//! what it rejects is never routed, counted by its reason and has a
//! closed record that tells the reason; one that panics rejects and sail
//! serves on; and the check of a connection's addresses runs before its
//! handshake.
#![cfg(all(feature = "outbound-direct", feature = "inbound-socks"))]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use sail::embed::{
    ClosedBy, Config, End, Event, Instance, Kinds, Options, Outcome, RecordKind, Threads, Verdict,
};
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

    // Each has one closed record: those rejected for the host's reason,
    // with no bytes.
    let mut closed = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(2), events.next()).await {
        if let Event::ConnectionRecord(record) = event {
            if matches!(record.kind, RecordKind::Closed(_)) {
                closed.push(record);
            }
        }
    }
    let (rejected, passed): (Vec<_>, Vec<_>) = closed
        .iter()
        .partition(|r| r.destination.port() == blocked_port);
    assert_eq!(passed.len(), 1, "{:?}", closed);
    assert_eq!(passed[0].outcome, Some(Outcome::Ok));
    assert_eq!(passed[0].reason, None);
    assert_eq!(rejected.len(), 2, "{:?}", closed);
    for r in rejected {
        assert_eq!(r.kind, RecordKind::Closed(End::Closed(ClosedBy::Host)));
        assert_eq!(r.outcome, Some(Outcome::Rejected));
        assert_eq!(r.reason.as_deref(), Some("blocked"));
        assert_eq!((r.up_total, r.down_total), (0, 0));
        assert!(r.chain.is_empty(), "never routed: {:?}", r);
    }
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

// A real host-submitted UDP association and memory-only outbound. No
// external resolver, port, or backend policy implementation is involved.
struct AdmissionPackets(tokio::sync::mpsc::Receiver<(Vec<u8>, sail::embed::Address)>);
struct AdmissionSend(tokio::sync::mpsc::Sender<(Vec<u8>, sail::embed::Address)>);

impl sail::embed::DatagramRecv for AdmissionPackets {
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> futures::future::BoxFuture<'a, std::io::Result<(usize, sail::embed::Address)>> {
        Box::pin(async move {
            let (data, address) = self
                .0
                .recv()
                .await
                .ok_or(std::io::ErrorKind::UnexpectedEof)?;
            buf[..data.len()].copy_from_slice(&data);
            Ok((data.len(), address))
        })
    }
}
impl sail::embed::DatagramSend for AdmissionSend {
    fn send_to<'a>(
        &'a mut self,
        data: &'a [u8],
        address: &'a sail::embed::Address,
    ) -> futures::future::BoxFuture<'a, std::io::Result<()>> {
        Box::pin(async move {
            self.0
                .send((data.to_vec(), address.clone()))
                .await
                .map_err(|_| std::io::ErrorKind::BrokenPipe.into())
        })
    }
}
struct AdmissionEcho(Arc<AtomicUsize>);
impl sail::embed::HostOutbound for AdmissionEcho {
    fn datagrams<'a>(
        &'a self,
        _: &'a sail::embed::SessionInfo,
        _: &'a sail::embed::Via,
    ) -> futures::future::BoxFuture<'a, std::io::Result<sail::embed::Datagrams>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            let (send, recv) = tokio::sync::mpsc::channel(64);
            Ok(sail::embed::Datagrams {
                recv: Box::new(AdmissionPackets(recv)),
                send: Box::new(AdmissionSend(send)),
            })
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_rechecks_a_new_destination_without_spending_another_session_place() {
    use sail::embed::{Address, Datagrams, NewSession};
    let blocked = Arc::new(AtomicBool::new(false));
    let policy = blocked.clone();
    let checked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = checked.clone();
    let dials = Arc::new(AtomicUsize::new(0));
    let echo = dials.clone();
    let options = Options::new()
        .connection_records_lossless(64)
        .admit(move |session| {
            seen.lock()
                .unwrap()
                .push((session.destination.clone(), session.id));
            if policy.load(Ordering::SeqCst)
                && session.destination == Address::Domain("blocked.example".into(), 53)
            {
                Verdict::reject("domain_blocked")
            } else {
                Verdict::Accept
            }
        })
        .outbound_kind("admission-echo", move |_| {
            Ok(Arc::new(AdmissionEcho(echo.clone())))
        })
        .unwrap();
    let instance = Instance::new(options.threads(Threads::Workers(2, 2 << 20))).unwrap();
    let mut records = instance.connection_records().unwrap();
    instance.start(Config::Json(serde_json::json!({
        "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": common::free_port(),
            "users": [{"username": "alice", "password": "test-password"}] }],
        "outbounds": [{"type": "admission-echo", "tag": "echo"}],
        "route": {"final": "echo"}, "user_limits": {"alice": {"max_connections": 1}}
    }).to_string())).await.unwrap();
    let (send, recv) = tokio::sync::mpsc::channel(64);
    let (answer, mut answers) = tokio::sync::mpsc::channel(64);
    let open = Address::Domain("open.example".into(), 53);
    let id = instance
        .sessions("in")
        .unwrap()
        .udp(
            NewSession::new(open.clone()).user(instance.user("alice").unwrap()),
            Datagrams {
                recv: Box::new(AdmissionPackets(recv)),
                send: Box::new(AdmissionSend(answer)),
            },
        )
        .await
        .unwrap();
    send.send((b"first".to_vec(), open.clone())).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), answers.recv())
            .await
            .unwrap()
            .unwrap(),
        (b"first".to_vec(), open.clone())
    );
    blocked.store(true, Ordering::SeqCst);
    let denied = Address::Domain("blocked.example".into(), 53);
    send.send((b"blocked".to_vec(), denied.clone()))
        .await
        .unwrap();
    let rejected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                response = answers.recv() => panic!("denied UDP destination reached the outbound: {response:?}"),
                record = records.next() => {
                    if record.destination == denied && matches!(record.kind, RecordKind::Closed(_)) { break record; }
                }
            }
        }
    }).await.unwrap();
    assert_ne!(
        rejected.id, id,
        "a rejected target cannot close the association's record"
    );
    assert_eq!(
        rejected.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Host))
    );
    assert_eq!(rejected.outcome, Some(Outcome::Rejected));
    assert_eq!(rejected.reason.as_deref(), Some("domain_blocked"));
    assert_eq!((rejected.up_total, rejected.down_total), (0, 0));
    assert!(rejected.chain.is_empty());
    // A different port is a new target. It uses the association's one
    // user/session place, even while max_connections is already full.
    for to in [Address::Domain("blocked.example".into(), 54), open.clone()] {
        send.send((b"next".to_vec(), to.clone())).await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), answers.recv())
                .await
                .unwrap()
                .unwrap(),
            (b"next".to_vec(), to)
        );
    }
    assert_eq!(
        dials.load(Ordering::SeqCst),
        1,
        "reuse the original outbound"
    );
    let connections = instance.connections().await.unwrap();
    assert_eq!(connections.len(), 1);
    let live = &connections[0];
    assert_eq!(live.id, id);
    assert_eq!((live.upload, live.download), (13, 13));
    let calls = checked.lock().unwrap().clone();
    assert_eq!(calls.iter().filter(|(to, _)| *to == open).count(), 1);
    assert!(calls.contains(&(denied, rejected.id)));
    drop(send);
    instance.stop().await.unwrap();
}
