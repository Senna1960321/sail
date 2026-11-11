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
type AdmissionPacket = (Vec<u8>, sail::embed::Address);
type AdmissionSender = tokio::sync::mpsc::Sender<AdmissionPacket>;
type AdmissionReceiver = tokio::sync::mpsc::Receiver<AdmissionPacket>;
struct AdmissionPackets(AdmissionReceiver);
struct AdmissionSend(AdmissionSender);

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
struct FrozenAdmissionContext(u64);
impl sail::embed::HostOutbound for AdmissionEcho {
    fn stream<'a>(
        &'a self,
        _: &'a sail::embed::SessionInfo,
        _: &'a sail::embed::Via,
    ) -> futures::future::BoxFuture<'a, std::io::Result<sail::embed::HostStream>> {
        Box::pin(async { Err(std::io::ErrorKind::Unsupported.into()) })
    }
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
    let binding = Arc::new(std::sync::Mutex::new(None));
    let hook_binding = binding.clone();
    async fn next_bound(
        records: &mut sail::embed::RecordStream,
        binding: &std::sync::Mutex<Option<sail::embed::RecordContext>>,
    ) -> Arc<sail::embed::ConnectionRecord> {
        let envelope = records.next_envelope().await;
        assert_eq!(envelope.context.as_ref(), binding.lock().unwrap().as_ref());
        assert_eq!(envelope.context.as_ref().unwrap().get::<u64>(), Some(&7));
        envelope.record
    }
    let blocked = Arc::new(AtomicBool::new(false));
    let policy = blocked.clone();
    let checked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = checked.clone();
    let dials = Arc::new(AtomicUsize::new(0));
    let echo = dials.clone();
    let options = Options::new()
        .settings_json(r#"{"set":["inbound.max_connections=1"]}"#)
        .unwrap()
        .connection_records_lossless(1)
        .record_context(8, |session| {
            session
                .extensions
                .get::<FrozenAdmissionContext>()
                .unwrap()
                .0
        })
        .unwrap()
        .admit(move |session| {
            if session.parent_id.is_some() {
                assert_eq!(
                    session.record_context.as_ref(),
                    hook_binding.lock().unwrap().as_ref()
                );
            } else {
                *hook_binding.lock().unwrap() = session.record_context.clone();
            }
            seen.lock().unwrap().push((
                session.destination.clone(),
                session.id,
                session.parent_id,
                session.run,
            ));
            assert_eq!(
                session
                    .extensions
                    .get::<FrozenAdmissionContext>()
                    .unwrap()
                    .0,
                7
            );
            if session.destination == Address::Domain("panic.example".into(), 53) {
                panic!("target admission test panic");
            }
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
    let config = serde_json::json!({
        "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": common::free_port(),
            "users": [{"username": "alice", "password": "test-password"}] }],
        "outbounds": [{"type": "admission-echo", "tag": "echo"}],
        "route": {"rules": [{"domain": ["blocked.example"], "action": "reject"}], "final": "echo"},
        "user_limits": {"alice": {"max_connections": 1}}
    }).to_string();
    instance.start(Config::Json(config.clone())).await.unwrap();
    let (send, recv) = tokio::sync::mpsc::channel(64);
    let (answer, mut answers) = tokio::sync::mpsc::channel(64);
    let open = Address::Domain("open.example".into(), 53);
    let id = instance
        .sessions("in")
        .unwrap()
        .udp(
            NewSession::new(open.clone())
                .user(instance.user("alice").unwrap())
                .extension(FrozenAdmissionContext(7)),
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
                record = next_bound(&mut records, &binding) => {
                    if record.destination == denied && matches!(record.kind, RecordKind::Closed(_)) { break record; }
                }
            }
        }
    }).await.unwrap();
    assert_eq!(rejected.parent_id, Some(id));
    let json = serde_json::to_value(sail::control::json::ConnectionRecord::of(&rejected)).unwrap();
    assert_eq!(json["parent_id"], id);
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
    assert!(
        calls.contains(&(open.clone(), id, None, Some(rejected.run))),
        "the callback run is exactly the records' run, not an instance timestamp"
    );
    assert_eq!(calls.iter().filter(|(to, _, _, _)| *to == open).count(), 1);
    assert!(calls.contains(&(denied.clone(), rejected.id, Some(id), Some(rejected.run))));
    // Fill the lossless sink, using an already authorized packet as a
    // FIFO barrier. Backlog refusal precedes host admission and is
    // publicly counted, without creating more rejection records.
    for round in 0..2 {
        send.send((b"blocked".to_vec(), denied.clone()))
            .await
            .unwrap();
        send.send((b"pressure".to_vec(), open.clone()))
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), answers.recv())
                .await
                .unwrap()
                .unwrap(),
            (b"pressure".to_vec(), open.clone())
        );
        assert_eq!(records.queued(), 1);
        assert_eq!(records.refused(), round);
    }
    assert_eq!(
        checked
            .lock()
            .unwrap()
            .iter()
            .filter(|(to, _, _, _)| *to == denied)
            .count(),
        2
    );
    let pressure_rejection = next_bound(&mut records, &binding).await;
    assert_eq!(pressure_rejection.reason.as_deref(), Some("domain_blocked"));
    assert_eq!(
        (pressure_rejection.up_total, pressure_rejection.down_total),
        (0, 0)
    );
    assert_eq!(
        pressure_rejection.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Host))
    );
    assert_eq!(pressure_rejection.parent_id, Some(id));
    let panic_to = Address::Domain("panic.example".into(), 53);
    send.send((b"panic".to_vec(), panic_to.clone()))
        .await
        .unwrap();
    let panicked = tokio::time::timeout(Duration::from_secs(5), next_bound(&mut records, &binding))
        .await
        .unwrap();
    assert_eq!(panicked.destination, panic_to);
    assert_eq!(panicked.parent_id, Some(id));
    assert_eq!(
        panicked.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Host))
    );
    assert_eq!(panicked.outcome, Some(Outcome::Rejected));
    assert_eq!(panicked.reason, None);
    assert_eq!((panicked.up_total, panicked.down_total), (0, 0));
    assert!(panicked.chain.is_empty());
    // IP and port are both part of the cache key. Queue concurrently on
    // one source, and require every allowed packet to return correctly.
    for port in 1000u16..1065 {
        send.send((
            port.to_be_bytes().to_vec(),
            Address::Ip(([192, 0, 2, 1], port).into()),
        ))
        .await
        .unwrap();
    }
    for _ in 1000..1065 {
        let (data, from) = tokio::time::timeout(Duration::from_secs(5), answers.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data, from.port().to_be_bytes());
    }
    // The first target was evicted, so its next packet must be checked
    // again. Refusing a target never caches that refusal: it can recover.
    send.send((b"again".to_vec(), open.clone())).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), answers.recv())
            .await
            .unwrap()
            .unwrap(),
        (b"again".to_vec(), open.clone())
    );
    assert_eq!(
        checked
            .lock()
            .unwrap()
            .iter()
            .filter(|(to, _, _, _)| *to == open)
            .count(),
        2
    );
    blocked.store(false, Ordering::SeqCst);
    send.send((b"recovered".to_vec(), denied.clone()))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), answers.recv())
            .await
            .unwrap()
            .unwrap(),
        (b"recovered".to_vec(), denied)
    );
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    let connections = instance.connections().await.unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].id, id);
    assert_eq!((connections[0].upload, connections[0].download), (173, 173));
    drop(send);
    instance.stop().await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), next_bound(&mut records, &binding))
        .await
        .unwrap();
    assert_eq!(closed.id, id);
    assert_eq!(closed.parent_id, None);
    assert_eq!(closed.run, rejected.run);
    let json = serde_json::to_value(sail::control::json::ConnectionRecord::of(&closed)).unwrap();
    assert!(json["parent_id"].is_null());
    assert_eq!((closed.up_total, closed.down_total), (173, 173));
    assert_ne!(closed.outcome, Some(Outcome::Rejected));
    assert!(
        records.try_next().is_none(),
        "accepted target checks must not invent closed records"
    );
    // The reader spans runs, but parent metadata and authorization do
    // not. The same submitted source/user starts a new root in a new run.
    blocked.store(true, Ordering::SeqCst);
    instance.start(Config::Json(config)).await.unwrap();
    let (new_send, new_recv) = tokio::sync::mpsc::channel(8);
    let (new_back, mut new_answers) = tokio::sync::mpsc::channel(8);
    let new_id = instance
        .sessions("in")
        .unwrap()
        .udp(
            NewSession::new(open.clone())
                .user(instance.user("alice").unwrap())
                .extension(FrozenAdmissionContext(7)),
            Datagrams {
                recv: Box::new(AdmissionPackets(new_recv)),
                send: Box::new(AdmissionSend(new_back)),
            },
        )
        .await
        .unwrap();
    new_send.send((b"new run".to_vec(), open)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), new_answers.recv())
            .await
            .unwrap()
            .unwrap()
            .0,
        b"new run"
    );
    new_send
        .send((
            b"denied".to_vec(),
            Address::Domain("blocked.example".into(), 53),
        ))
        .await
        .unwrap();
    let new_rejection =
        tokio::time::timeout(Duration::from_secs(5), next_bound(&mut records, &binding))
            .await
            .unwrap();
    assert_eq!(new_rejection.parent_id, Some(new_id));
    assert_ne!(new_rejection.run, rejected.run);
    assert!(checked.lock().unwrap().contains(&(
        Address::Domain("blocked.example".into(), 53),
        new_rejection.id,
        Some(new_id),
        Some(new_rejection.run)
    )));
    assert_eq!((new_rejection.up_total, new_rejection.down_total), (0, 0));
    assert_eq!(dials.load(Ordering::SeqCst), 2);
    drop(new_send);
    instance.stop().await.unwrap();
    let new_closed =
        tokio::time::timeout(Duration::from_secs(5), next_bound(&mut records, &binding))
            .await
            .unwrap();
    assert_eq!(new_closed.id, new_id);
    assert_eq!(new_closed.parent_id, None);
    assert_eq!(new_closed.run, new_rejection.run);
    assert!(records.try_next().is_none());
}

#[cfg(feature = "inbound-direct")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_checks_the_restored_fake_ip_domain_of_each_target() {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use sail::embed::{Address, Datagrams, DomainSource, NewSession};
    let dials = Arc::new(AtomicUsize::new(0));
    let counted = dials.clone();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let checks = seen.clone();
    let options = Options::new()
        .threads(Threads::Workers(2, 2 << 20))
        .connection_records_lossless(64)
        .admit(move |session| {
            if session.inbound_tag != "in" {
                return Verdict::Accept;
            }
            checks.lock().unwrap().push((
                session.destination.clone(),
                session.domain.clone(),
                session.domain_source,
            ));
            match session.domain.as_deref() {
                Some("blocked.example") => Verdict::reject("fake_domain_blocked"),
                _ => Verdict::Accept,
            }
        })
        .outbound_kind("admission-echo", move |_| {
            Ok(Arc::new(AdmissionEcho(counted.clone())))
        })
        .unwrap();
    let instance = Instance::new(options).unwrap();
    let mut records = instance.connection_records().unwrap();
    let dns_port = common::free_port();
    instance.start(Config::Json(serde_json::json!({
        "dns": {"servers": [{"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15"}]},
        "inbounds": [
            {"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": common::free_port()},
            {"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": dns_port}
        ],
        "outbounds": [{"type": "admission-echo", "tag": "echo"}],
        "route": {"rules": [{"inbound": ["dns-in"], "action": "hijack-dns"}], "final": "echo"}
    }).to_string())).await.unwrap();
    let fake = |name: &'static str| async move {
        let mut query = Message::new(42, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&query.to_vec().unwrap(), ("127.0.0.1", dns_port))
            .await
            .unwrap();
        let mut buf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let reply = Message::from_vec(&buf[..n]).unwrap();
        let Some(RData::A(ip)) = reply.answers.first().map(|r| &r.data) else {
            panic!("fake IP answer: {reply:?}")
        };
        Address::Ip((ip.0, 5353).into())
    };
    let open = fake("open.example").await;
    let blocked = fake("blocked.example").await;
    let (send, recv) = tokio::sync::mpsc::channel(8);
    let (back, mut answers) = tokio::sync::mpsc::channel(8);
    instance
        .sessions("in")
        .unwrap()
        .udp(
            NewSession::new(open.clone()),
            Datagrams {
                recv: Box::new(AdmissionPackets(recv)),
                send: Box::new(AdmissionSend(back)),
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
        (
            b"first".to_vec(),
            Address::Domain("open.example".into(), 5353)
        )
    );
    send.send((b"blocked".to_vec(), blocked)).await.unwrap();
    let rejected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                response = answers.recv() => panic!("blocked fake IP reached outbound: {response:?}"),
                record = records.next() => if record.reason.as_deref() == Some("fake_domain_blocked") { break record; },
            }
        }
    }).await.unwrap();
    assert_eq!(
        rejected.destination,
        Address::Domain("blocked.example".into(), 5353)
    );
    assert_eq!((rejected.up_total, rejected.down_total), (0, 0));
    assert!(rejected.chain.is_empty());
    assert_eq!(
        rejected.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Host))
    );
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    let checks = seen.lock().unwrap().clone();
    assert!(checks.contains(&(
        Address::Domain("blocked.example".into(), 5353),
        Some("blocked.example".into()),
        Some(DomainSource::Request)
    )));
    send.send((b"still open".to_vec(), open)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), answers.recv())
            .await
            .unwrap()
            .unwrap()
            .0,
        b"still open"
    );
    instance.stop().await.unwrap();
}

// Always unblock a deliberately stalled hook, including when an assertion
// fails: the instance's worker must not be left waiting during teardown.
struct ReleaseAdmissionGate(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
impl Drop for ReleaseAdmissionGate {
    fn drop(&mut self) {
        let (released, changed) = &*self.0;
        *released.lock().unwrap() = true;
        changed.notify_all();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_udp_target_check_does_not_lock_other_associations() {
    use sail::embed::{Address, Datagrams, NewSession};
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let waiting = Arc::new(AtomicBool::new(false));
    let refused = Arc::new(AtomicBool::new(false));
    let (hook_gate, entered, blocked) = (gate.clone(), waiting.clone(), refused.clone());
    let dials = Arc::new(AtomicUsize::new(0));
    let echo = dials.clone();
    let options = Options::new()
        .threads(Threads::Workers(2, 2 << 20))
        .connection_records_lossless(64)
        .admit(move |session| {
            if session.destination == Address::Domain("wait.example".into(), 5353) {
                if blocked.load(Ordering::SeqCst) {
                    assert_eq!(session.parent_id, None, "a new association is its own root");
                    return Verdict::reject("updated_policy");
                }
                assert!(
                    session.parent_id.is_some(),
                    "a later target identifies its root"
                );
                assert_ne!(session.parent_id, Some(session.id));
                entered.store(true, Ordering::SeqCst);
                let (released, changed) = &*hook_gate;
                let mut released = released.lock().unwrap();
                while !*released {
                    released = changed.wait(released).unwrap();
                }
            }
            Verdict::Accept
        })
        .outbound_kind("admission-echo", move |_| {
            Ok(Arc::new(AdmissionEcho(echo.clone())))
        })
        .unwrap();
    let instance = Instance::new(options).unwrap();
    let release = ReleaseAdmissionGate(gate);
    let mut records = instance.connection_records().unwrap();
    instance.start(Config::Json(serde_json::json!({
        "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": common::free_port()}],
        "outbounds": [{"type": "admission-echo", "tag": "echo"}], "route": {"final": "echo"}
    }).to_string())).await.unwrap();
    async fn submit(instance: &Instance, to: Address) -> (AdmissionSender, AdmissionReceiver) {
        let (send, recv) = tokio::sync::mpsc::channel(8);
        let (back, answers) = tokio::sync::mpsc::channel(8);
        instance
            .sessions("in")
            .unwrap()
            .udp(
                NewSession::new(to),
                Datagrams {
                    recv: Box::new(AdmissionPackets(recv)),
                    send: Box::new(AdmissionSend(back)),
                },
            )
            .await
            .unwrap();
        (send, answers)
    }
    let open = Address::Domain("open.example".into(), 5353);
    let wait = Address::Domain("wait.example".into(), 5353);
    let (first, mut first_answers) = submit(&instance, open.clone()).await;
    first.send((b"open".to_vec(), open.clone())).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), first_answers.recv())
            .await
            .unwrap()
            .unwrap()
            .0,
        b"open"
    );
    first
        .send((b"waiting".to_vec(), wait.clone()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !waiting.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the new target reached its hook");
    // The first source's callback is still blocked. A different source
    // must be able to create a NAT and complete its own echo meanwhile.
    let (second, mut second_answers) = submit(&instance, open.clone()).await;
    second.send((b"independent".to_vec(), open)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), second_answers.recv())
            .await
            .unwrap()
            .unwrap()
            .0,
        b"independent"
    );
    drop(release);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), first_answers.recv())
            .await
            .unwrap()
            .unwrap(),
        (b"waiting".to_vec(), wait.clone())
    );
    assert_eq!(dials.load(Ordering::SeqCst), 2);
    // A fresh association does not inherit an earlier association's
    // accepted-target cache, even with the same submitted source address.
    refused.store(true, Ordering::SeqCst);
    let (third, mut third_answers) = submit(&instance, wait.clone()).await;
    third
        .send((b"denied".to_vec(), wait.clone()))
        .await
        .unwrap();
    drop(third);
    let rejected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                Some(response) = third_answers.recv() => panic!("a fresh association bypassed admission: {response:?}"),
                record = records.next() => if record.reason.as_deref() == Some("updated_policy") { break record; },
            }
        }
    }).await.unwrap();
    assert_eq!(rejected.destination, wait);
    assert_eq!(rejected.parent_id, None);
    assert_eq!(
        rejected.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Host))
    );
    assert_eq!((rejected.up_total, rejected.down_total), (0, 0));
    assert!(rejected.chain.is_empty());
    assert_eq!(dials.load(Ordering::SeqCst), 2);
    assert_eq!(instance.connections().await.unwrap().len(), 2);
    drop((first, second));
    instance.stop().await.unwrap();
}

/// Negative control for root-index consumers: a legal metadata clone can
/// keep a rejected target alive beyond its root's accounting close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retained_udp_attempt_can_close_after_its_root() {
    use sail::embed::{Address, Datagrams, NewSession};
    let drops = Arc::new(AtomicUsize::new(0));
    let captured_drops = drops.clone();
    struct Frozen {
        version: usize,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for Frozen {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    let current = Arc::new(AtomicUsize::new(7));
    let capture = current.clone();
    let held = Arc::new(std::sync::Mutex::new(None));
    let slot = held.clone();
    let checked = Arc::new(tokio::sync::Notify::new());
    let signal = checked.clone();
    let instance = Instance::new(
        Options::new()
            .connection_records_lossless(4)
            .record_context(2, move |_| Frozen {
                version: capture.load(Ordering::SeqCst),
                drops: captured_drops.clone(),
            })
            .unwrap()
            .admit(move |info| {
                if info.parent_id.is_some() {
                    assert_eq!(
                        info.record_context
                            .as_ref()
                            .unwrap()
                            .get::<Frozen>()
                            .unwrap()
                            .version,
                        7
                    );
                    *slot.lock().unwrap() = Some(info.clone());
                    signal.notify_one();
                    Verdict::reject("late-target")
                } else {
                    Verdict::Accept
                }
            })
            .outbound_kind("admission-echo", |_| {
                Ok(Arc::new(AdmissionEcho(Arc::default())))
            })
            .unwrap()
            .threads(Threads::Workers(2, 2 << 20)),
    )
    .unwrap();
    let mut records = instance.connection_records().unwrap();
    let config = serde_json::json!({
        "inbounds": [{"type":"socks", "tag":"in", "listen":"127.0.0.1", "listen_port":0}],
        "outbounds": [{"type":"admission-echo", "tag":"echo"}]
    })
    .to_string();
    instance.start(Config::Json(config.clone())).await.unwrap();
    let (send, recv) = tokio::sync::mpsc::channel(1);
    let (answer, mut answers) = tokio::sync::mpsc::channel(1);
    let open = Address::Domain("open.example".into(), 53);
    let id = instance
        .sessions("in")
        .unwrap()
        .udp(
            NewSession::new(open.clone()),
            Datagrams {
                recv: Box::new(AdmissionPackets(recv)),
                send: Box::new(AdmissionSend(answer)),
            },
        )
        .await
        .unwrap();
    send.send((b"first".to_vec(), open)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), answers.recv())
        .await
        .unwrap()
        .unwrap();
    current.store(99, Ordering::SeqCst);
    send.send((
        b"denied".to_vec(),
        Address::Domain("blocked.example".into(), 53),
    ))
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), checked.notified())
        .await
        .unwrap();
    instance.stop().await.unwrap();
    let root_envelope = records.try_next_envelope().expect("root closed on stop");
    let root = root_envelope.record.clone();
    assert_eq!(
        root_envelope
            .context
            .as_ref()
            .unwrap()
            .get::<Frozen>()
            .unwrap()
            .version,
        7
    );
    drop(root_envelope); // root cursor/context may be retired independently
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(root.id, id);
    assert_eq!(root.parent_id, None);
    assert!(matches!(root.kind, RecordKind::Closed(_)));
    assert!(
        records.try_next().is_none(),
        "child is retained by metadata"
    );
    // Restart while the old attempt is still held. IDs may repeat, but
    // its captured run and binding are independent of the new run.
    instance.start(Config::Json(config)).await.unwrap();
    let (new_send, new_recv) = tokio::sync::mpsc::channel(1);
    let (new_answer, mut new_answers) = tokio::sync::mpsc::channel(1);
    let new_open = Address::Domain("open.example".into(), 53);
    let new_id = instance
        .sessions("in")
        .unwrap()
        .udp(
            NewSession::new(new_open.clone()),
            Datagrams {
                recv: Box::new(AdmissionPackets(new_recv)),
                send: Box::new(AdmissionSend(new_answer)),
            },
        )
        .await
        .unwrap();
    new_send.send((b"new".to_vec(), new_open)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), new_answers.recv())
        .await
        .unwrap()
        .unwrap();
    instance.stop().await.unwrap();
    let new_root = records.try_next_envelope().unwrap();
    assert_eq!(new_id, root.id, "run-local numbering restarts");
    assert_eq!(new_root.record.id, root.id);
    assert_ne!(new_root.record.run, root.run);
    assert_eq!(
        new_root
            .context
            .as_ref()
            .unwrap()
            .get::<Frozen>()
            .unwrap()
            .version,
        99
    );
    drop(new_root);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    let info = held.lock().unwrap().take().unwrap();
    let child_key = (info.run.unwrap(), info.id);
    drop(info);
    let envelope = records
        .try_next_envelope()
        .expect("releasing metadata publishes late child");
    let child = &envelope.record;
    assert_eq!(
        envelope
            .context
            .as_ref()
            .unwrap()
            .get::<Frozen>()
            .unwrap()
            .version,
        7
    );
    assert_ne!(child.destination, root.destination);
    assert_eq!((child.run, child.id), child_key);
    assert_eq!(child.parent_id, Some(root.id));
    assert_eq!(child.run, root.run);
    assert_eq!((child.up_total, child.down_total), (0, 0));
    assert!(records.try_next().is_none());
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "pending spool owns the old binding"
    );
    drop(envelope); // simulate successful durable spool handoff
    assert_eq!(
        drops.load(Ordering::SeqCst),
        2,
        "no root tombstone or hidden lease"
    );
}

/// Reload after authentication but before binding capture: a same-name
/// replacement cannot change the authenticated row's immutable snapshot.
#[cfg(feature = "inbound-vless")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_binding_survives_auth_capture_reload_and_reader_backpressure() {
    #[derive(Debug)]
    struct Credential {
        generation: usize,
        key: String,
    }
    let generation = Arc::new(AtomicUsize::new(1));
    let build_generation = generation.clone();
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = entered.clone();
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let blocked = gate.clone();
    let captured = Arc::new(AtomicUsize::new(0));
    let captures = captured.clone();
    let port = common::free_port();
    let old = "00112233-4455-6677-8899-aabbccddeeff";
    let new = "10112233-4455-6677-8899-aabbccddeeff";
    let config =
        |uuid: &str| {
            Config::Json(serde_json::json!({
        "inbounds": [{"type":"vless", "tag":"v", "listen":"127.0.0.1", "listen_port":port,
            "users":[{"name":"alice", "uuid":uuid}]}],
        "outbounds": [{"type":"direct", "tag":"direct"}]
    }).to_string())
        };
    let instance = Instance::new(
        Options::new()
            .connection_records_lossless(16)
            .credential_context(8, move |row| {
                assert_eq!(
                    (row.protocol, row.inbound, row.name),
                    ("vless", "v", "alice")
                );
                Credential {
                    generation: build_generation.load(Ordering::SeqCst),
                    key: row.credential.into(),
                }
            })
            .unwrap()
            .record_context(1, move |info| {
                if captures.fetch_add(1, Ordering::SeqCst) == 0 {
                    signal.notify_one();
                    let (lock, changed) = &*blocked;
                    let _guard = changed
                        .wait_while(lock.lock().unwrap(), |open| !*open)
                        .unwrap();
                }
                // Deliberately read AFTER the reload: this is the reference
                // captured in the authenticated row, not the current username.
                info.credential_context
                    .clone()
                    .expect("named VLESS credential snapshot")
            })
            .unwrap()
            .admit(|_| Verdict::reject("policy"))
            .threads(Threads::Workers(2, 2 << 20)),
    )
    .unwrap();
    let _release_on_failure = ReleaseAdmissionGate(gate.clone());
    let mut records = instance.connection_records().unwrap();
    instance.start(config(old)).await.unwrap();
    async fn request(port: u16, uuid: &str) -> TcpStream {
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut wire = vec![0];
        wire.extend_from_slice(uuid::Uuid::parse_str(uuid).unwrap().as_bytes());
        wire.extend_from_slice(&[0, 1, 0, 80, 1, 127, 0, 0, 1]);
        client.write_all(&wire).await.unwrap();
        client
    }
    let _old_client = request(port, old).await;
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    generation.store(2, Ordering::SeqCst);
    instance.reload(Some(config(new))).await.unwrap();
    // Revoked after authentication: the early user refusal must already
    // own the old credential binding, without entering the host check.
    let mut limits = sail::embed::UserLimits::default();
    limits.expire_at = Some(std::time::UNIX_EPOCH);
    instance.set_user_limits("alice", limits).unwrap();
    {
        let (lock, changed) = &*gate;
        *lock.lock().unwrap() = true;
        changed.notify_one();
    }
    let first = tokio::time::timeout(Duration::from_secs(5), records.next_envelope())
        .await
        .unwrap();
    let identity = first
        .context
        .as_ref()
        .unwrap()
        .get::<sail::embed::RecordContext>()
        .unwrap()
        .get::<Credential>()
        .unwrap();
    assert_eq!((identity.generation, identity.key.as_str()), (1, old));
    assert_eq!(
        first.record.kind,
        RecordKind::Closed(End::Closed(ClosedBy::User))
    );
    assert_eq!(first.record.outcome, Some(Outcome::Rejected));
    assert_eq!(first.record.reason, None);
    instance
        .set_user_limits("alice", Default::default())
        .unwrap();
    let _capacity_client = request(port, new).await;
    let full = tokio::time::timeout(Duration::from_secs(5), records.next_envelope())
        .await
        .unwrap();
    assert!(
        full.context.is_none(),
        "exhaustion does not fabricate an identity"
    );
    assert_eq!(
        full.record.reason.as_deref(),
        Some("record_context_capacity")
    );
    assert_eq!(
        captured.load(Ordering::SeqCst),
        1,
        "full pool never calls provider"
    );
    assert_eq!(
        instance
            .admission()
            .unwrap()
            .unwrap()
            .host_refused
            .get("record_context_capacity"),
        Some(&1)
    );
    drop(first); // reader completed durable handoff; one session slot is free
    let _new_client = request(port, new).await;
    let next = tokio::time::timeout(Duration::from_secs(5), records.next_envelope())
        .await
        .unwrap();
    let identity = next
        .context
        .as_ref()
        .unwrap()
        .get::<sail::embed::RecordContext>()
        .unwrap()
        .get::<Credential>()
        .unwrap();
    assert_eq!((identity.generation, identity.key.as_str()), (2, new));
    assert_eq!(captured.load(Ordering::SeqCst), 2);
    let json =
        serde_json::to_string(&sail::control::json::ConnectionRecord::of(&next.record)).unwrap();
    assert!(
        !json.contains(new),
        "private credentials are never record JSON"
    );
    drop(next);
    // More credential rows than the snapshot pool can hold: the reload
    // must fail atomically and release all candidate snapshots.
    let too_many = (1..=9_u128)
        .map(|id| {
            serde_json::json!({
                "name":"alice", "uuid":uuid::Uuid::from_u128(id).to_string()
            })
        })
        .collect::<Vec<_>>();
    let rejected_config = Config::Json(serde_json::json!({
        "inbounds":[{"type":"vless","tag":"v","listen":"127.0.0.1","listen_port":port,"users":too_many}],
        "outbounds":[{"type":"direct","tag":"direct"}]
    }).to_string());
    assert!(instance.reload(Some(rejected_config)).await.is_err());
    let _still_old_row = request(port, new).await;
    let kept = tokio::time::timeout(Duration::from_secs(5), records.next_envelope())
        .await
        .unwrap();
    let identity = kept
        .context
        .as_ref()
        .unwrap()
        .get::<sail::embed::RecordContext>()
        .unwrap()
        .get::<Credential>()
        .unwrap();
    assert_eq!((identity.generation, identity.key.as_str()), (2, new));
    drop(kept);
    // Candidate rollback returned its slots: another legitimate replacement fits.
    instance.reload(Some(config(old))).await.unwrap();
    instance.stop().await.unwrap();
}

/// Host submission tells a number before dispatcher binding. Even a
/// successful unlisted health association must record the bound snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unlisted_submitted_healthcheck_keeps_its_binding() {
    use sail::embed::{Address, Datagrams, NewSession};
    let instance = Instance::new(
        Options::new()
            .connection_records_lossless(4)
            .record_context(1, |_| 77_u64)
            .unwrap()
            .threads(Threads::Workers(2, 2 << 20)),
    )
    .unwrap();
    let mut records = instance.connection_records().unwrap();
    instance
        .start(Config::Json(
            serde_json::json!({
                "inbounds":[{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":0}],
                "outbounds":[{"type":"direct","tag":"direct"}]
            })
            .to_string(),
        ))
        .await
        .unwrap();
    let (send, recv) = tokio::sync::mpsc::channel(1);
    let (answer, mut answers) = tokio::sync::mpsc::channel(1);
    let health = Address::Domain("healthcheck.sail".into(), 53);
    let id = instance
        .sessions("in")
        .unwrap()
        .udp(
            NewSession::new(health.clone()),
            Datagrams {
                recv: Box::new(AdmissionPackets(recv)),
                send: Box::new(AdmissionSend(answer)),
            },
        )
        .await
        .unwrap();
    send.send((b"probe".to_vec(), health)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), answers.recv())
        .await
        .unwrap()
        .unwrap();
    drop(send);
    instance.stop().await.unwrap();
    let envelope = records
        .try_next_envelope()
        .expect("a submitted, told number closes once");
    assert_eq!(envelope.record.id, id);
    assert!(matches!(envelope.record.kind, RecordKind::Closed(_)));
    assert_eq!(
        envelope.context.as_ref().and_then(|c| c.get::<u64>()),
        Some(&77),
        "binding must update the earlier told snapshot"
    );
    assert!(records.try_next_envelope().is_none());
}
