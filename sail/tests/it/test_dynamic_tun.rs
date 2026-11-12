//! Rebased dynamic attachment contract regressions. Every result must be
//! established on this source; historical runs are not acceptance here.
//! Packet cases use loopback only; the real-device case is explicitly ignored.
#![cfg(all(
    feature = "inbound-tun",
    feature = "inbound-mixed",
    feature = "outbound-direct"
))]
#![allow(clippy::disallowed_methods)]
use sail::embed::{Config, ErrorKind, Instance, Options, Runtime, TunState};
use sail_netstack::{emit_udp_packet, parse_ip_packet, parse_udp_datagram};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TUN: &str = r#"{"type":"tun","tag":"capture","address":["10.19.0.1/24"],"mtu":1500}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_reservation_drop_cannot_clear_a_newer_capture() {
    let (i, _) = start(true).await;
    let (old, mut old_flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    assert!(i.detach_tun().await.unwrap().clean());
    let (current, mut current_flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    drop(old);
    assert!(
        matches!(i.tun_state().unwrap(), TunState::Prepared { .. }),
        "stale drop must not clear the current reservation"
    );
    current.commit().await.unwrap();
    assert!(matches!(i.tun_state().unwrap(), TunState::Attached { .. }));
    assert!(old_flow.uplink.send(vec![0x45]).await.is_err());
    assert!(old_flow.downlink.recv().await.is_none());
    assert!(i.detach_tun().await.unwrap().clean());
    assert!(current_flow.downlink.recv().await.is_none());
    i.stop().await.unwrap();
}
fn config(port: u16) -> String {
    serde_json::json!({"log":{"level":"warn"}, "inbounds":[{"type":"mixed","tag":"mixed","listen":"127.0.0.1","listen_port":port,"users":[{"username":"u","password":"p"}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}).to_string()
}
async fn start_config(i: &Instance) -> u16 {
    for _ in 0..10 {
        let port = crate::common::free_port();
        match i.start(Config::Json(config(port))).await {
            Ok(()) => return port,
            Err(e) if e.message().contains("Address already in use") => continue,
            Err(e) => panic!("start: {e}"),
        }
    }
    panic!("could not reserve a proxy listener port");
}
async fn start(enabled: bool) -> (Instance, u16) {
    let i = Instance::new(
        Options::new()
            .dynamic_tun(enabled)
            .runtime(Runtime::Host(tokio::runtime::Handle::current())),
    )
    .unwrap();
    let port = start_config(&i).await;
    (i, port)
}
async fn socks(port: u16, command: u8, target: SocketAddr) -> (tokio::net::TcpStream, SocketAddr) {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut r = [0; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 2]);
    s.write_all(&[1, 1, b'u', 1, b'p']).await.unwrap();
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [1, 0]);
    let SocketAddr::V4(v4) = target else {
        unreachable!()
    };
    let mut req = vec![5, command, 0, 1];
    req.extend(v4.ip().octets());
    req.extend(v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut r = [0; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0);
    (
        s,
        SocketAddr::from(([r[4], r[5], r[6], r[7]], u16::from_be_bytes([r[8], r[9]]))),
    )
}
async fn roundtrip(s: &mut tokio::net::TcpStream, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    let mut r = vec![0; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut r))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r, msg);
}
async fn tcp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let t = tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (a, t)
}
async fn udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    (
        a,
        tokio::spawn(async move {
            let mut b = [0; 2048];
            loop {
                let (n, a) = s.recv_from(&mut b).await.unwrap();
                s.send_to(&b[..n], a).await.unwrap();
            }
        }),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_authenticated_tcp_http_and_udp_survive_three_tun_generations() {
    let (i, port) = start(true).await;
    let original = i.manager().unwrap();
    let (tcp, task) = tcp_echo().await;
    let (udp, utask) = udp_echo().await;
    let (mut s, _) = socks(port, 1, tcp).await;
    let mut http = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    http.write_all(
        format!("CONNECT {tcp} HTTP/1.1\r\nHost: {tcp}\r\nProxy-Authorization: Basic dTpw\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut head = Vec::new();
    loop {
        let b = http.read_u8().await.unwrap();
        head.push(b);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let (_association, relay) = socks(port, 3, "0.0.0.0:0".parse().unwrap()).await;
    let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(v4) = udp else {
        unreachable!()
    };
    let mut udp_req = vec![0, 0, 0, 1];
    udp_req.extend(v4.ip().octets());
    udp_req.extend(v4.port().to_be_bytes());
    udp_req.extend(b"mixed-udp");
    for n in 0..3 {
        roundtrip(&mut s, b"before").await;
        roundtrip(&mut http, b"before-http").await;
        let (p, mut flow) = i.prepare_tun_packets(TUN, 2).await.unwrap();
        assert!(matches!(i.tun_state().unwrap(), TunState::Prepared { .. }));
        p.commit().await.unwrap();
        assert!(original.has_tun());
        let source = "10.19.0.2:41000".parse().unwrap();
        flow.uplink
            .send(emit_udp_packet(source, udp, b"captured-udp", 64, n).unwrap())
            .await
            .unwrap();
        let wire = tokio::time::timeout(Duration::from_secs(5), flow.downlink.recv())
            .await
            .unwrap()
            .unwrap();
        let ip = parse_ip_packet(&wire, true).unwrap();
        let parsed = parse_udp_datagram(ip, true).unwrap();
        assert_eq!(parsed.destination, source);
        assert_eq!(parsed.payload, b"captured-udp");
        roundtrip(&mut s, b"attached").await;
        roundtrip(&mut http, b"attached-http").await;
        u.send_to(&udp_req, relay).await.unwrap();
        let mut b = [0; 256];
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), u.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[10..len], b"mixed-udp");
        assert!(i.detach_tun().await.unwrap().clean());
        assert!(!original.has_tun());
        assert!(flow.uplink.send(vec![0x45]).await.is_err());
        assert!(flow.downlink.recv().await.is_none());
        assert!(i.detach_tun().await.unwrap().clean());
        roundtrip(&mut s, b"after").await;
        roundtrip(&mut http, b"after-http").await;
        u.send_to(&udp_req, relay).await.unwrap();
        let (len, _) = tokio::time::timeout(Duration::from_secs(5), u.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[10..len], b"mixed-udp");
        assert!(Arc::ptr_eq(&original, &i.manager().unwrap()));
        let mut denied = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        denied.write_all(&[5, 1, 0]).await.unwrap();
        let mut r = [0; 2];
        denied.read_exact(&mut r).await.unwrap();
        assert_eq!(r, [5, 255]);
    }
    i.stop().await.unwrap();
    task.abort();
    utask.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepare_drop_backpressure_stale_handle_and_opt_in() {
    let (i, _) = start(false).await;
    assert_eq!(
        i.prepare_tun_packets(TUN, 1).await.unwrap_err().kind(),
        ErrorKind::Unsupported
    );
    i.stop().await.unwrap();
    let (i, _) = start(true).await;
    let (p, mut f) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    f.uplink.send(vec![0x45]).await.unwrap();
    assert!(futures::poll!(std::pin::pin!(f.uplink.send(vec![0x45]))).is_pending());
    assert_eq!(
        i.prepare_tun_packets(TUN, 1).await.unwrap_err().kind(),
        ErrorKind::State
    );
    drop(p);
    assert!(f.uplink.send(vec![0x45]).await.is_err());
    assert!(f.downlink.recv().await.is_none());
    let old_manager = i.manager().unwrap();
    let (old, mut flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    i.stop().await.unwrap();
    assert!(flow.downlink.recv().await.is_none());
    start_config(&i).await;
    assert!(!Arc::ptr_eq(&old_manager, &i.manager().unwrap()));
    assert!(old.commit().await.is_err());
    assert_eq!(i.tun_state().unwrap(), TunState::Detached);
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    assert!(i.detach_tun().await.unwrap().clean());
    i.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_default_compatibility_and_dynamic_conflicts() {
    let (i, port) = start(true).await;
    let mut static_config: serde_json::Value = serde_json::from_str(&config(port)).unwrap();
    static_config["inbounds"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::from_str(TUN).unwrap());
    assert_eq!(
        i.reload(Some(Config::Json(static_config.to_string())))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NeedsRestart
    );
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    assert_eq!(
        i.reload(Some(Config::Json(static_config.to_string())))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NeedsRestart
    );
    p.commit().await.unwrap();
    assert_eq!(
        i.reload(Some(Config::Json(static_config.to_string())))
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NeedsRestart
    );
    i.reload(Some(Config::Json(config(port)))).await.unwrap();
    assert!(i.manager().unwrap().has_tun());
    assert!(i.detach_tun().await.unwrap().clean());
    i.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_prepares_and_cancelled_host_awaits_reconcile_by_detach() {
    let (i, _) = start(true).await;
    let (a, b) = tokio::join!(i.prepare_tun_packets(TUN, 1), i.prepare_tun_packets(TUN, 1));
    let (p, mut flow) = match (a, b) {
        (Ok(p), Err(e)) | (Err(e), Ok(p)) => {
            assert_eq!(e.kind(), ErrorKind::State);
            p
        }
        _ => panic!("exactly one reservation"),
    };
    // First poll transfers execution to Sail. Cancelling the host await
    // cannot lose an attachment: idempotent detach reconciles either outcome.
    let mut commit = Box::pin(p.commit());
    let _ = futures::poll!(&mut commit);
    drop(commit);
    let mut detach = Box::pin(i.detach_tun());
    let _ = futures::poll!(&mut detach);
    drop(detach);
    assert!(i.detach_tun().await.unwrap().clean());
    assert_eq!(i.tun_state().unwrap(), TunState::Detached);
    assert!(flow.downlink.recv().await.is_none());
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    i.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_joins_a_captured_tcp_stream_without_ending_the_proxy_stream() {
    use sail_netstack::{emit_tcp_segment, parse_tcp_segment, SendControl, SeqNumber, TcpFlags};
    let (i, port) = start(true).await;
    let (echo, task) = tcp_echo().await;
    let (mut proxy, _) = socks(port, 1, echo).await;
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = target.local_addr().unwrap();
    let source = "10.19.0.2:42000".parse().unwrap();
    let (received_tx, received) = tokio::sync::oneshot::channel();
    let closed = tokio::spawn(async move {
        let (mut s, _) = target.accept().await.unwrap();
        let mut payload = [0; 7];
        s.read_exact(&mut payload).await.unwrap();
        received_tx.send(payload).unwrap();
        let mut byte = [0];
        s.read(&mut byte).await.unwrap()
    });
    let (p, mut flow) = i.prepare_tun_packets(TUN, 4).await.unwrap();
    p.commit().await.unwrap();
    let packet = |sequence, acknowledgment, flags, payload: &[u8]| {
        emit_tcp_segment(
            source,
            destination,
            SendControl {
                sequence: SeqNumber::new(sequence),
                acknowledgment: SeqNumber::new(acknowledgment),
                flags,
                window: 32000,
            },
            payload,
            64,
            1,
        )
        .unwrap()
    };
    flow.uplink
        .send(packet(100, 0, TcpFlags::SYN, &[]))
        .await
        .unwrap();
    let wire = tokio::time::timeout(Duration::from_secs(5), flow.downlink.recv())
        .await
        .unwrap()
        .unwrap();
    let syn = parse_tcp_segment(parse_ip_packet(&wire, true).unwrap(), true).unwrap();
    let next = syn.meta.sequence.wrapping_add(1).get();
    flow.uplink
        .send(packet(101, next, TcpFlags::ACK, b"tun-tcp"))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), received)
            .await
            .unwrap()
            .unwrap(),
        *b"tun-tcp"
    );
    roundtrip(&mut proxy, b"proxy during capture").await;
    assert!(i.detach_tun().await.unwrap().clean());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), closed)
            .await
            .unwrap()
            .unwrap(),
        0
    );
    roundtrip(&mut proxy, b"proxy after captured EOF").await;
    i.stop().await.unwrap();
    task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packet_transport_failure_is_local_and_requires_explicit_detach() {
    let (i, port) = start(true).await;
    let (echo, task) = tcp_echo().await;
    let (mut proxy, _) = socks(port, 1, echo).await;
    let (p, flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    drop(flow);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(i.tun_state().unwrap(), TunState::Failed { .. }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    roundtrip(&mut proxy, b"proxy after packet transport failure").await;
    assert!(i.prepare_tun_packets(TUN, 1).await.is_err());
    assert!(i.detach_tun().await.unwrap().clean());
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    i.stop().await.unwrap();
    task.abort();
}

#[cfg(unix)]
#[derive(Debug)]
struct RefusingDeviceHost {
    calls: std::sync::atomic::AtomicUsize,
    panic: bool,
}
#[cfg(unix)]
impl sail::embed::Platform for RefusingDeviceHost {
    fn log(&self, _: &str) {}
    fn opens_tun(&self) -> bool {
        true
    }
    fn open_tun(&self, _: &sail::embed::TunRequest) -> std::io::Result<i32> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(!self.panic, "test host open failure by panic");
        Err(std::io::Error::other("test host refuses the device"))
    }
}
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_prepare_has_no_os_effect_and_failed_or_panicked_commit_rolls_back() {
    for panic in [false, true] {
        let host = Arc::new(RefusingDeviceHost {
            calls: Default::default(),
            panic,
        });
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let i = Instance::new(
            Options::new()
                .dynamic_tun(true)
                .platform(host.clone())
                .runtime(Runtime::Host(tokio::runtime::Handle::current())),
        )
        .unwrap();
        i.start(Config::Json(config(port))).await.unwrap();
        let (echo, task) = tcp_echo().await;
        let (mut proxy, _) = socks(port, 1, echo).await;
        let prepared = i.prepare_tun_device(TUN).await.unwrap();
        assert_eq!(host.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(prepared);
        assert_eq!(i.tun_state().unwrap(), TunState::Detached);
        let routed = TUN.replace("\"mtu\":1500", "\"mtu\":1500,\"auto_route\":true");
        assert!(i.prepare_tun_device(&routed).await.is_err());
        assert_eq!(host.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        let prepared = i.prepare_tun_device(TUN).await.unwrap();
        let error = prepared.commit().await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Failed);
        assert!(error.left().is_empty());
        assert_eq!(host.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(i.detach_tun().await.unwrap().clean());
        assert_eq!(i.tun_state().unwrap(), TunState::Detached);
        roundtrip(&mut proxy, b"proxy survives failed device transaction").await;
        let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
        p.commit().await.unwrap();
        assert!(i.detach_tun().await.unwrap().clean());
        i.stop().await.unwrap();
        task.abort();
    }
}

/// Run only in a disposable network namespace with CAP_NET_ADMIN. It never
/// changes a machine's default route or touches an active VPN.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an isolated network namespace and /dev/net/tun"]
async fn a_real_linux_device_is_released_at_each_detach() {
    let (i, port) = start(true).await;
    let (echo, task) = tcp_echo().await;
    let (mut proxy, _) = socks(port, 1, echo).await;
    let name = format!("sdyn{}", std::process::id());
    let cname = std::ffi::CString::new(name.clone()).unwrap();
    let exists = || {
        // SAFETY: a live, NUL-terminated interface name.
        unsafe { libc::if_nametoindex(cname.as_ptr()) != 0 }
    };
    let json = serde_json::json!({"type":"tun","tag":"capture","interface_name":name,"address":["10.66.0.1/24"],"mtu":1500}).to_string();
    assert!(!exists());
    for _ in 0..3 {
        let p = i.prepare_tun_device(&json).await.unwrap();
        assert!(!exists());
        p.commit().await.unwrap();
        assert!(exists());
        roundtrip(&mut proxy, b"proxy with real TUN").await;
        assert!(i.detach_tun().await.unwrap().clean());
        assert!(!exists());
        roundtrip(&mut proxy, b"proxy after real TUN").await;
    }
    i.stop().await.unwrap();
    task.abort();
}

#[cfg(target_os = "linux")]
struct OwnedFdHost {
    original: std::os::fd::OwnedFd,
    last: std::sync::atomic::AtomicI32,
}
#[cfg(target_os = "linux")]
impl sail::embed::Platform for OwnedFdHost {
    fn log(&self, _: &str) {}
    fn opens_tun(&self) -> bool {
        true
    }
    fn open_tun(&self, _: &sail::embed::TunRequest) -> std::io::Result<i32> {
        use std::os::fd::AsRawFd;
        // A high, otherwise unused descriptor makes closure checks immune
        // to unrelated low-FD socket allocation by parallel tests.
        // SAFETY: a live source descriptor; a successful duplicate transfers
        // exactly that new descriptor to Sail, never the host's original.
        let fd = unsafe { libc::fcntl(self.original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10000) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.last.store(fd, std::sync::atomic::Ordering::SeqCst);
        Ok(fd)
    }
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transferred_fd_closes_on_commit_failure_and_detach_but_host_original_survives() {
    use std::os::fd::AsRawFd;
    for regular_file in [true, false] {
        let (original, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let owned: std::os::fd::OwnedFd = if regular_file {
            std::fs::File::open("/dev/null").unwrap().into()
        } else {
            original.try_clone().unwrap().into()
        };
        let host = Arc::new(OwnedFdHost {
            original: owned,
            last: std::sync::atomic::AtomicI32::new(-1),
        });
        let i = Instance::new(
            Options::new()
                .dynamic_tun(true)
                .platform(host.clone())
                .runtime(Runtime::Host(tokio::runtime::Handle::current())),
        )
        .unwrap();
        i.start(Config::Json(
            r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#.into(),
        ))
        .await
        .unwrap();
        for _ in 0..3 {
            let p = i.prepare_tun_device(TUN).await.unwrap();
            let result = p.commit().await;
            if regular_file {
                assert!(result.is_err(), "epoll must refuse /dev/null");
            } else {
                result.unwrap();
                assert!(i.detach_tun().await.unwrap().clean());
            }
            let fd = host.last.load(std::sync::atomic::Ordering::SeqCst);
            assert!(fd >= 10000);
            // SAFETY: F_GETFD only queries the numeric descriptor, no pointer.
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
            assert!(unsafe { libc::fcntl(host.original.as_raw_fd(), libc::F_GETFD) } >= 0);
            assert_eq!(i.tun_state().unwrap(), TunState::Detached);
        }
        if !regular_file {
            peer.send(b"host-original").unwrap();
            let mut bytes = [0; 32];
            let n = original.recv(&mut bytes).unwrap();
            assert_eq!(&bytes[..n], b"host-original");
        }
        i.stop().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_releases_a_proxy_listener_even_with_a_retained_old_manager() {
    // Outside Linux's normal ephemeral client-port range; no accepted
    // connection here can put the listening address into TIME_WAIT.
    let port = (20000..21000)
        .find(|port| std::net::TcpListener::bind(("127.0.0.1", *port)).is_ok())
        .unwrap();
    let i = Instance::new(
        Options::new()
            .dynamic_tun(true)
            .runtime(Runtime::Host(tokio::runtime::Handle::current())),
    )
    .unwrap();
    i.start(Config::Json(config(port))).await.unwrap();
    let manager = i.manager().unwrap();
    let (old, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    i.stop().await.unwrap();
    let rebound = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    assert!(!manager.has_tun());
    drop(rebound);
    drop(old);
}

#[cfg(all(
    feature = "mux",
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks"
))]
async fn shared_lazy_carrier(first_udp: bool) {
    use sail_netstack::{emit_tcp_segment, parse_tcp_segment, SendControl, SeqNumber, TcpFlags};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let ss_port = crate::common::free_port();
    let upstream =
        Instance::new(Options::new().runtime(Runtime::Host(tokio::runtime::Handle::current())))
            .unwrap();
    upstream.start(Config::Json(serde_json::json!({
        "log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","tag":"server","listen":"127.0.0.1","listen_port":ss_port,
        "method":"2022-blake3-aes-128-gcm","password":"a8C5QncIl9HvTmenrEb7aw==","multiplex":{"enabled":true}}],
        "outbounds":[{"type":"direct","tag":"direct"}]
    }).to_string())).await.unwrap();
    let forwarder = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let forward_port = forwarder.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    let forward = tokio::spawn(async move {
        loop {
            let (mut incoming, _) = forwarder.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut out = tokio::net::TcpStream::connect(("127.0.0.1", ss_port))
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut incoming, &mut out).await;
            });
        }
    });
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut cfg: serde_json::Value = serde_json::from_str(&config(port)).unwrap();
    cfg["outbounds"] = serde_json::json!([{"type":"shadowsocks","tag":"direct","server":"127.0.0.1","server_port":forward_port,
        "method":"2022-blake3-aes-128-gcm","password":"a8C5QncIl9HvTmenrEb7aw==","multiplex":{"enabled":true,"protocol":"smux","max_connections":1}}]);
    let i = Instance::new(
        Options::new()
            .dynamic_tun(true)
            .runtime(Runtime::Host(tokio::runtime::Handle::current())),
    )
    .unwrap();
    i.start(Config::Json(cfg.to_string())).await.unwrap();
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    let (p, mut flow) = i.prepare_tun_packets(TUN, 8).await.unwrap();
    p.commit().await.unwrap();
    let source = "10.19.0.2:43000".parse().unwrap();
    if first_udp {
        flow.uplink
            .send(emit_udp_packet(source, udp, b"first-udp", 64, 1).unwrap())
            .await
            .unwrap();
        let wire = tokio::time::timeout(Duration::from_secs(5), flow.downlink.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            parse_udp_datagram(parse_ip_packet(&wire, true).unwrap(), true)
                .unwrap()
                .payload,
            b"first-udp"
        );
    } else {
        let packet = |sequence, acknowledgment, flags, bytes: &[u8]| {
            emit_tcp_segment(
                source,
                tcp,
                SendControl {
                    sequence: SeqNumber::new(sequence),
                    acknowledgment: SeqNumber::new(acknowledgment),
                    flags,
                    window: 32000,
                },
                bytes,
                64,
                1,
            )
            .unwrap()
        };
        flow.uplink
            .send(packet(100, 0, TcpFlags::SYN, &[]))
            .await
            .unwrap();
        let wire = tokio::time::timeout(Duration::from_secs(5), flow.downlink.recv())
            .await
            .unwrap()
            .unwrap();
        let next = parse_tcp_segment(parse_ip_packet(&wire, true).unwrap(), true)
            .unwrap()
            .meta
            .sequence
            .wrapping_add(1)
            .get();
        flow.uplink
            .send(packet(101, next, TcpFlags::ACK, b"first-tcp"))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let wire = flow.downlink.recv().await.unwrap();
                let tcp = parse_tcp_segment(parse_ip_packet(&wire, true).unwrap(), true).unwrap();
                if !tcp.payload.is_empty() {
                    assert_eq!(tcp.payload, b"first-tcp");
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "TUN created the carrier first"
    );
    let (mut proxy, _) = socks(port, 1, tcp).await;
    roundtrip(&mut proxy, b"proxy reused the TUN-created carrier").await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "same physical mux carrier before detach"
    );
    assert!(i.detach_tun().await.unwrap().clean());
    let message = b"same proxy survives detaching carrier creator";
    proxy.write_all(message).await.unwrap();
    let mut back = vec![0; message.len()];
    let after_detach =
        tokio::time::timeout(Duration::from_secs(5), proxy.read_exact(&mut back)).await;
    let final_connections = connections.load(Ordering::SeqCst);
    i.stop().await.unwrap();
    upstream.stop().await.unwrap();
    forward.abort();
    tcp_task.abort();
    udp_task.abort();
    after_detach
        .expect("the existing mixed stream timed out AFTER detach")
        .expect("the existing mixed stream closed AFTER detach");
    assert_eq!(back, message);
    assert_eq!(
        final_connections, 1,
        "no reconnect can hide a killed carrier"
    );
}

#[cfg(all(
    feature = "mux",
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_lazy_carrier_created_by_tun_tcp_survives_detach() {
    shared_lazy_carrier(false).await;
}
#[cfg(all(
    feature = "mux",
    feature = "inbound-shadowsocks",
    feature = "outbound-shadowsocks"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_lazy_carrier_created_by_tun_udp_survives_detach() {
    shared_lazy_carrier(true).await;
}

#[cfg(unix)]
struct BlockingOpenHost {
    started: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    gate: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}
#[cfg(unix)]
impl sail::embed::Platform for BlockingOpenHost {
    fn log(&self, _: &str) {}
    fn opens_tun(&self) -> bool {
        true
    }
    fn open_tun(&self, _: &sail::embed::TunRequest) -> std::io::Result<i32> {
        self.started
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        let mut released = self.gate.0.lock().unwrap();
        while !*released {
            released = self.gate.1.wait(released).unwrap();
        }
        Err(std::io::Error::other(
            "host eventually refused after cancellation",
        ))
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_polled_commit_await_does_not_cancel_the_owned_open() {
    let (entered_tx, entered) = tokio::sync::oneshot::channel();
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    let release = Release(gate.clone());
    let i = Instance::new(
        Options::new()
            .dynamic_tun(true)
            .runtime(Runtime::Host(tokio::runtime::Handle::current()))
            .platform(Arc::new(BlockingOpenHost {
                started: std::sync::Mutex::new(Some(entered_tx)),
                gate,
            })),
    )
    .unwrap();
    let port = start_config(&i).await;
    let (echo, echo_task) = tcp_echo().await;
    let (mut proxy, _) = socks(port, 1, echo).await;
    let prepared = i.prepare_tun_device(TUN).await.unwrap();
    let awaiting = tokio::spawn(prepared.commit());
    tokio::time::timeout(Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    awaiting.abort();
    assert!(awaiting.await.unwrap_err().is_cancelled());
    assert!(
        matches!(i.tun_state().unwrap(), TunState::Committing { .. }),
        "cancelling only the await must not release an in-flight open"
    );
    assert!(i.prepare_tun_packets(TUN, 1).await.is_err());
    roundtrip(
        &mut proxy,
        b"original proxy survives cancelled commit await",
    )
    .await;
    drop(release); // this controlled host finishes with a refusal
    tokio::time::timeout(Duration::from_secs(5), async {
        while !matches!(i.tun_state().unwrap(), TunState::Detached) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the owned controller must reconcile the completed failure");
    let (current, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    current.commit().await.unwrap();
    assert!(i.detach_tun().await.unwrap().clean());
    roundtrip(
        &mut proxy,
        b"proxy still original after replacement generation",
    )
    .await;
    i.stop().await.unwrap();
    echo_task.abort();
}
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_device_open_leaves_one_worker_proxy_running_and_detach_reports_it() {
    let (started_tx, started) = tokio::sync::oneshot::channel();
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    let release = Release(gate.clone());
    let host = Arc::new(BlockingOpenHost {
        started: std::sync::Mutex::new(Some(started_tx)),
        gate,
    });
    let i = Instance::new(
        Options::new()
            .dynamic_tun(true)
            .platform(host)
            .threads(sail::embed::Threads::One)
            .stop_within(Duration::from_millis(100)),
    )
    .unwrap();
    let port = start_config(&i).await;
    let (echo, task) = tcp_echo().await;
    let (mut proxy, _) = socks(port, 1, echo).await;
    let p = i.prepare_tun_device(TUN).await.unwrap();
    let commit = tokio::spawn(p.commit());
    tokio::time::timeout(Duration::from_secs(5), started)
        .await
        .unwrap()
        .unwrap();
    roundtrip(
        &mut proxy,
        b"single worker still serves while host open blocks",
    )
    .await;
    let report = tokio::time::timeout(Duration::from_secs(2), i.detach_tun())
        .await
        .unwrap()
        .unwrap();
    assert!(!report.clean());
    assert!(report
        .tasks
        .iter()
        .any(|(name, _)| *name == "dynamic TUN open"));
    assert!(matches!(i.tun_state().unwrap(), TunState::Draining { .. }));
    assert!(i.prepare_tun_packets(TUN, 1).await.is_err());
    roundtrip(&mut proxy, b"proxy remains after bounded incomplete detach").await;
    drop(release);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), commit)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        ErrorKind::Cancelled
    );
    assert!(i.detach_tun().await.unwrap().clean());
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    roundtrip(&mut proxy, b"new generation after late open rollback").await;
    i.stop().await.unwrap();
    task.abort();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instance_stop_is_bounded_and_reports_a_host_open_that_has_not_returned() {
    let (started_tx, started) = tokio::sync::oneshot::channel();
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    let release = Release(gate.clone());
    let host = Arc::new(BlockingOpenHost {
        started: std::sync::Mutex::new(Some(started_tx)),
        gate,
    });
    let i = Instance::new(
        Options::new()
            .dynamic_tun(true)
            .platform(host)
            .threads(sail::embed::Threads::One)
            .stop_within(Duration::from_millis(100)),
    )
    .unwrap();
    start_config(&i).await;
    let p = i.prepare_tun_device(TUN).await.unwrap();
    let commit = tokio::spawn(p.commit());
    tokio::time::timeout(Duration::from_secs(5), started)
        .await
        .unwrap()
        .unwrap();
    let stopped = tokio::time::timeout(Duration::from_secs(3), i.stop())
        .await
        .unwrap();
    assert!(
        stopped.is_err(),
        "a live uninterruptible host callback must be reported"
    );
    assert!(!i.stop_report().unwrap().clean());
    drop(release);
    assert!(tokio::time::timeout(Duration::from_secs(5), commit)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    // The cancelled controller's receiver can finish before the blocking
    // callback and its returned resource. Restart waits for their real end.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match i
                .start(Config::Json(config(crate::common::free_port())))
                .await
            {
                Ok(()) => break,
                Err(error)
                    if error.kind() == ErrorKind::State
                        && error
                            .message()
                            .contains("previous dynamic TUN run still owns") =>
                {
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("restart after callback release: {error}"),
            }
        }
    })
    .await
    .unwrap();
    let (p, _flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    p.commit().await.unwrap();
    assert!(i.detach_tun().await.unwrap().clean());
    i.stop().await.unwrap();
}

#[cfg(target_os = "linux")]
struct BlockingOwnedFdHost {
    wait: BlockingOpenHost,
    fd: OwnedFdHost,
}
#[cfg(target_os = "linux")]
impl sail::embed::Platform for BlockingOwnedFdHost {
    fn log(&self, _: &str) {}
    fn opens_tun(&self) -> bool {
        true
    }
    fn open_tun(&self, request: &sail::embed::TunRequest) -> std::io::Result<i32> {
        let _ = sail::embed::Platform::open_tun(&self.wait, request);
        sail::embed::Platform::open_tun(&self.fd, request)
    }
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_successful_host_fd_is_closed_after_detach_or_instance_stop() {
    use std::os::fd::AsRawFd;
    for stop_instance in [false, true] {
        let (original, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let (started_tx, started) = tokio::sync::oneshot::channel();
        let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
        impl Drop for Release {
            fn drop(&mut self) {
                *self.0 .0.lock().unwrap() = true;
                self.0 .1.notify_all();
            }
        }
        let release = Release(gate.clone());
        let host = Arc::new(BlockingOwnedFdHost {
            wait: BlockingOpenHost {
                started: std::sync::Mutex::new(Some(started_tx)),
                gate,
            },
            fd: OwnedFdHost {
                original: original.try_clone().unwrap().into(),
                last: std::sync::atomic::AtomicI32::new(-1),
            },
        });
        let i = Instance::new(
            Options::new()
                .dynamic_tun(true)
                .platform(host.clone())
                .threads(sail::embed::Threads::One)
                .stop_within(Duration::from_millis(100)),
        )
        .unwrap();
        start_config(&i).await;
        let p = i.prepare_tun_device(TUN).await.unwrap();
        let commit = tokio::spawn(p.commit());
        tokio::time::timeout(Duration::from_secs(5), started)
            .await
            .unwrap()
            .unwrap();
        if stop_instance {
            assert!(tokio::time::timeout(Duration::from_secs(3), i.stop())
                .await
                .unwrap()
                .is_err());
        } else {
            assert!(
                !tokio::time::timeout(Duration::from_secs(2), i.detach_tun())
                    .await
                    .unwrap()
                    .unwrap()
                    .clean()
            );
        }
        drop(release);
        assert!(tokio::time::timeout(Duration::from_secs(5), commit)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let fd = host.fd.last.load(std::sync::atomic::Ordering::SeqCst);
                if fd >= 10000 {
                    // SAFETY: F_GETFD only queries the descriptor number.
                    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
                    {
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late transferred FD released even without a live commit receiver");
        assert!(unsafe { libc::fcntl(host.fd.original.as_raw_fd(), libc::F_GETFD) } >= 0);
        peer.send(b"original still owned by host").unwrap();
        let mut b = [0; 64];
        let n = original.recv(&mut b).unwrap();
        assert_eq!(&b[..n], b"original still owned by host");
        if !stop_instance {
            assert!(i.detach_tun().await.unwrap().clean());
            i.stop().await.unwrap();
        }
    }
}

#[cfg(feature = "rule-set")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instance_stop_does_not_wait_for_a_hung_reload_in_any_dynamic_slot_state() {
    // Disabled, enabled-but-empty, and active: none may make ordinary stop
    // depend on a reload that still owns the update lock.
    for mode in 0..3 {
        let (i, port) = start(mode != 0).await;
        let mut flow = if mode == 2 {
            let (p, flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
            p.commit().await.unwrap();
            Some(flow)
        } else {
            None
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rule_port = listener.local_addr().unwrap().port();
        let (accepted_tx, accepted) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (_held, _) = listener.accept().await.unwrap();
            accepted_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        let mut cfg: serde_json::Value = serde_json::from_str(&config(port)).unwrap();
        cfg["route"] = serde_json::json!({"final":"direct","rule_set":[{"type":"remote","tag":"hang","format":"source","url":format!("http://127.0.0.1:{rule_port}/rules.json")}],"rules":[{"rule_set":"hang","action":"reject"}]});
        let reloading_instance = i.clone();
        let reload = tokio::spawn(async move {
            reloading_instance
                .reload(Some(Config::Json(cfg.to_string())))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), accepted)
            .await
            .unwrap()
            .unwrap();
        let stopped = tokio::time::timeout(Duration::from_secs(3), i.stop()).await;
        // Release the fixture even on failure; do not leave a hanging server.
        server.abort();
        stopped
            .expect("stop waited for the hanging reload's update lock")
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(5), reload)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        if let Some(flow) = flow.as_mut() {
            assert!(flow.downlink.recv().await.is_none());
        }
    }
}

/// A callback may not read the host's mutable staged resource until after
/// native stop has returned. Reusing this instance must wait for that read
/// and the old owned-resource barrier, not just for the run thread to exit.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_refuses_an_old_callback_before_its_first_host_slot_read() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct SlotHost {
        wait: BlockingOpenHost,
        slot: AtomicUsize,
        observed: AtomicUsize,
    }
    impl sail::embed::Platform for SlotHost {
        fn log(&self, _: &str) {}
        fn opens_tun(&self) -> bool {
            true
        }
        fn open_tun(&self, request: &sail::embed::TunRequest) -> std::io::Result<i32> {
            let _ = sail::embed::Platform::open_tun(&self.wait, request);
            // This is the first read of the staged host resource, deliberately
            // after the callback-entry barrier rather than before it.
            self.observed
                .store(self.slot.load(Ordering::SeqCst), Ordering::SeqCst);
            Err(std::io::Error::other(
                "staged device refused after first read",
            ))
        }
    }
    struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            *self.0 .0.lock().unwrap() = true;
            self.0 .1.notify_all();
        }
    }
    let (entered_tx, entered) = tokio::sync::oneshot::channel();
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let release = Release(gate.clone());
    let host = Arc::new(SlotHost {
        wait: BlockingOpenHost {
            started: std::sync::Mutex::new(Some(entered_tx)),
            gate,
        },
        slot: AtomicUsize::new(1),
        observed: AtomicUsize::new(0),
    });
    let i = Instance::new(
        Options::new()
            .dynamic_tun(true)
            .platform(host.clone())
            .threads(sail::embed::Threads::One)
            .stop_within(Duration::from_millis(50)),
    )
    .unwrap();
    start_config(&i).await;
    let prepared = i.prepare_tun_device(TUN).await.unwrap();
    let commit = tokio::spawn(prepared.commit());
    tokio::time::timeout(Duration::from_secs(5), entered)
        .await
        .unwrap()
        .unwrap();
    assert!(i.stop().await.is_err());
    assert_eq!(host.observed.load(Ordering::SeqCst), 0);
    let prior_report = i
        .stop_report()
        .expect("the prior resource remains reported");
    assert!(!prior_report.clean());
    let restart = i
        .start(Config::Json(config(crate::common::free_port())))
        .await;
    assert_eq!(i.stop_report(), Some(prior_report));
    // Cleanup before asserting so the negative control cannot strand a host
    // callback or a successfully (but incorrectly) restarted instance.
    let refused = restart.is_err();
    drop(release);
    assert!(tokio::time::timeout(Duration::from_secs(5), commit)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    tokio::time::timeout(Duration::from_secs(5), async {
        while host.observed.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(host.observed.load(Ordering::SeqCst), 1);
    if !refused {
        let _ = i.stop().await;
    }
    assert!(
        refused,
        "restart must refuse while an old callback can still read a replaced host slot"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match i
                .start(Config::Json(config(crate::common::free_port())))
                .await
            {
                Ok(()) => break,
                Err(error) if error.kind() == ErrorKind::State => tokio::task::yield_now().await,
                Err(error) => panic!("restart after old resource ended: {error}"),
            }
        }
    })
    .await
    .unwrap();
    host.slot.store(2, Ordering::SeqCst);
    let (current, mut flow) = i.prepare_tun_packets(TUN, 1).await.unwrap();
    current.commit().await.unwrap();
    assert!(i.detach_tun().await.unwrap().clean());
    assert!(flow.downlink.recv().await.is_none());
    i.stop().await.unwrap();
    assert_eq!(host.observed.load(Ordering::SeqCst), 1);
}
