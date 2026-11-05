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
        "route": {"rules": [{"domain": ["blocked.example"], "action": "reject"}], "final": "echo"},
        "user_limits": {"alice": {"max_connections": 1}}
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
    assert!(calls.contains(&(denied.clone(), rejected.id)));
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
            .filter(|(to, _)| *to == denied)
            .count(),
        2
    );
    let pressure_rejection = records.next().await;
    assert_eq!(pressure_rejection.reason.as_deref(), Some("domain_blocked"));
    assert_eq!(
        (pressure_rejection.up_total, pressure_rejection.down_total),
        (0, 0)
    );
    assert_eq!(
        pressure_rejection.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Host))
    );
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
            .filter(|(to, _)| *to == open)
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
    let closed = tokio::time::timeout(Duration::from_secs(5), records.next())
        .await
        .unwrap();
    assert_eq!(closed.id, id);
    assert_eq!((closed.up_total, closed.down_total), (173, 173));
    assert_ne!(closed.outcome, Some(Outcome::Rejected));
    assert!(
        records.try_next().is_none(),
        "accepted target checks must not invent closed records"
    );
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
                    return Verdict::reject("updated_policy");
                }
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
    let rejected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                response = third_answers.recv() => panic!("a fresh association bypassed admission: {response:?}"),
                record = records.next() => if record.reason.as_deref() == Some("updated_policy") { break record; },
            }
        }
    }).await.unwrap();
    assert_eq!(rejected.destination, wait);
    assert_eq!(
        rejected.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Host))
    );
    assert_eq!((rejected.up_total, rejected.down_total), (0, 0));
    assert!(rejected.chain.is_empty());
    assert_eq!(dials.load(Ordering::SeqCst), 2);
    assert_eq!(instance.connections().await.unwrap().len(), 2);
    drop((first, second, third));
    instance.stop().await.unwrap();
}
