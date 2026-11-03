//! sail embedded (`sail::embed`): an instance driven from the host's own
//! runtime, as an in-process engine drives it.
#![cfg(all(feature = "outbound-direct", feature = "inbound-socks"))]

use std::time::Duration;

use sail::embed::{Address, Config, ErrorKind, Instance, Options, State, Threads};
use sail::session::Session;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

fn config(socks_port: u16, dns_port: u16) -> String {
    serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "upstream", "type": "udp", "server": "127.0.0.1", "server_port": dns_port }],
        },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks_port,
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "final": "direct" },
    })
    .to_string()
}

fn options() -> Options {
    Options::new().threads(Threads::One).log_lines(100)
}

async fn round_trip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    s: &mut S,
    what: &[u8],
) {
    s.write_all(what).await.unwrap();
    let mut back = vec![0u8; what.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back))
        .await
        .expect("an echo in time")
        .unwrap();
    assert_eq!(back, what);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_instance_runs_from_the_hosts_runtime_and_stops_clean() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let (udp_echo, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let socks_port = common::free_port();

    let instance = Instance::new(options()).unwrap();
    assert_eq!(instance.state(), State::Idle);
    // Taken before the start: it sees the start.
    let mut states = instance.states();
    instance
        .start(Config::Json(config(socks_port, 53)))
        .await
        .unwrap();
    assert!(matches!(*states.borrow_and_update(), State::Running { .. }));
    assert!(matches!(instance.state(), State::Running { .. }));

    // A start while it runs is refused, and changes nothing.
    let again = instance.start(Config::Json(config(socks_port, 53))).await;
    assert_eq!(again.unwrap_err().kind(), ErrorKind::State);

    // Queries.
    let tags: Vec<String> = instance
        .outbounds()
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.tag)
        .collect();
    assert_eq!(tags, ["direct"]);
    assert_eq!(
        instance
            .dial_tcp("nowhere", Address::from(echo), Duration::from_secs(5))
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::NotFound)
    );

    // A stream and datagrams through the outbound named, used from this
    // runtime.
    let mut stream = instance
        .dial_tcp("direct", Address::from(echo), Duration::from_secs(5))
        .await
        .unwrap();
    round_trip(&mut stream, b"through direct").await;
    let connections = instance.connections().await.unwrap();
    assert!(
        connections.iter().any(|c| c.inbound_type == "control"),
        "the dialled connection is listed: {:?}",
        connections
    );
    let datagram = instance
        .dial_udp("direct", Address::from(udp_echo), Duration::from_secs(5))
        .await
        .unwrap();
    datagram.send(b"a datagram").await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), datagram.recv_from(&mut buf))
        .await
        .expect("a datagram back in time")
        .unwrap();
    assert_eq!(&buf[..n], b"a datagram");
    assert_eq!(from, Address::from(udp_echo));

    // Stopped: the stream fails rather than hangs, the port is free, and
    // calls say it does not run.
    let mut stopping = instance.states();
    instance.stop().await.unwrap();
    assert_eq!(*stopping.borrow_and_update(), State::Stopped);
    assert_eq!(instance.state(), State::Stopped);
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("the stream ends with the instance");
    assert!(matches!(read, Ok(0) | Err(_)));
    std::net::TcpListener::bind(("127.0.0.1", socks_port)).expect("the inbound's port is free");
    assert_eq!(
        instance.traffic().await.unwrap_err().kind(),
        ErrorKind::NotRunning
    );

    // And it starts again.
    instance
        .start(Config::Json(config(socks_port, 53)))
        .await
        .unwrap();
    instance.stop().await.unwrap();
}

/// What a reload that only changes `dns.servers` keeps: the inbound's
/// listener, and a connection held through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reload_of_the_dns_servers_keeps_a_connection_held() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let socks_port = common::free_port();

    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(socks_port, 53)))
        .await
        .unwrap();

    let sess = Session {
        destination: echo.into(),
        ..Default::default()
    };
    let mut held = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut held, b"before the reload").await;
    let before: Vec<u64> = instance
        .connections()
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(before.len(), 1);

    instance
        .reload(Some(Config::Json(config(socks_port, 5353))))
        .await
        .unwrap();

    round_trip(&mut held, b"after the reload").await;
    let after: Vec<u64> = instance
        .connections()
        .await
        .unwrap()
        .iter()
        .map(|c| c.id)
        .collect();
    assert_eq!(after, before, "the same connection, not a new one");
    // The listener too: a new connection comes in.
    let mut new = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut new, b"a new one").await;

    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configuration_that_fails_says_why_and_the_log_says_it_too() {
    let instance = Instance::new(options()).unwrap();
    let err = instance
        .start(Config::Json(
            r#"{"outbounds": [{"type": "nonesuch"}]}"#.into(),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Config, "{}", err);
    assert!(matches!(instance.state(), State::Failed(ref e) if e.kind() == ErrorKind::Config));
    assert_eq!(
        instance.reload(None).await.unwrap_err().kind(),
        ErrorKind::NotRunning
    );
}

/// A configuration checked as a start would build it: its warnings, or why
/// it does not build; from the host's runtime, nothing started.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_configuration_is_checked_without_an_instance() {
    let port = common::free_port();
    let warned = serde_json::json!({
        "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct", "tcp_multi_path": true }],
    })
    .to_string();
    let warnings = sail::embed::check(&Config::Json(warned), &options()).unwrap();
    assert_eq!(
        warnings,
        ["outbounds[0].tcp_multi_path: sail does not implement this field; ignored"]
    );
    // Nothing listens: the port is free.
    std::net::TcpListener::bind(("127.0.0.1", port)).expect("check binds nothing");

    let wrong = r#"{"outbounds": [{"type": "nonesuch"}]}"#.to_string();
    assert_eq!(
        sail::embed::check(&Config::Json(wrong), &options())
            .unwrap_err()
            .kind(),
        ErrorKind::Config
    );
}

/// The build names its release and its commit: in a git checkout of sail,
/// HEAD's short hash, unless the release build said which.
#[test]
fn the_build_names_its_release_and_commit() {
    let build = sail::embed::BUILD;
    assert_eq!(build.version, env!("CARGO_PKG_VERSION"));
    assert!(!build.commit.is_empty());
    if option_env!("SAIL_COMMIT").is_some() || option_env!("CFG_COMMIT_HASH").is_some() {
        return;
    }
    let head = std::process::Command::new("git")
        .args(["-C", concat!(env!("CARGO_MANIFEST_DIR"), "/..")])
        .args(["rev-parse", "--short", "HEAD"])
        .output();
    if let Some(head) = head.ok().filter(|o| o.status.success()) {
        assert_eq!(build.commit, String::from_utf8_lossy(&head.stdout).trim());
    }
}

/// Network changes, as a host pushes them, come as events in order, each
/// named, and pair with the snapshot by generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_changes_come_as_events_that_pair_with_the_snapshot() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds, NetworkChangeKind};

    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    let wifi = r#"{"interface": "en0", "type": "wifi", "gateway": "192.168.1.1",
                   "addresses": ["192.168.1.2/24"]}"#;
    instance.set_network_state(wifi).unwrap();

    // Subscribe, then read: the events after the snapshot's generation.
    let mut events = Box::pin(instance.events(Kinds::NETWORK));
    let snapshot = instance.network().unwrap();
    assert_eq!(
        snapshot.interface.as_ref().map(|i| i.name.as_str()),
        Some("en0")
    );
    assert!(!snapshot.offline());

    let moved = r#"{"interface": "en0", "type": "wifi", "gateway": "10.0.0.1",
                    "addresses": ["10.0.0.2/24"]}"#;
    let ethernet = r#"{"interface": "en1", "type": "ethernet", "gateway": "10.0.0.1",
                       "addresses": ["10.0.0.3/24"]}"#;
    for state in [moved, "{}", wifi, ethernet] {
        instance.set_network_state(state).unwrap();
    }
    let mut seen = Vec::new();
    while seen.len() < 4 {
        let event = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("an event in time")
            .expect("the stream goes on");
        match event {
            Event::Network(e) if e.generation <= snapshot.generation => {}
            Event::Network(e) => seen.push((e.generation, e.change)),
            other => panic!("unexpected {:?}", other),
        }
    }
    let g = snapshot.generation;
    assert_eq!(
        seen,
        [
            (g + 1, NetworkChangeKind::Moved),
            (g + 2, NetworkChangeKind::Offline),
            (g + 3, NetworkChangeKind::Restored),
            (g + 4, NetworkChangeKind::InterfaceChanged),
        ]
    );
    let now = instance.network().unwrap();
    assert_eq!(now.generation, g + 4);
    assert_eq!(now.interface.map(|i| i.name), Some("en1".to_string()));

    // A subscriber that falls behind is told how far.
    let mut slow = Box::pin(instance.events(Kinds::NETWORK));
    for i in 0..70 {
        instance
            .set_network_state(if i % 2 == 0 { wifi } else { ethernet })
            .unwrap();
    }
    let first = tokio::time::timeout(Duration::from_secs(5), slow.next())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(first, Event::Lagged { kind, missed } if kind == Kinds::NETWORK && missed > 0),
        "{:?}",
        first
    );
    instance.stop().await.unwrap();
}

/// Network events subscribed before a start, and read only after two
/// runs, miss nothing either run told.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn network_events_subscribed_before_a_start_miss_nothing() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds, NetworkChangeKind};

    let instance = Instance::new(options()).unwrap();
    let mut events = Box::pin(instance.events(Kinds::NETWORK));
    let wifi = r#"{"interface": "en0", "type": "wifi", "gateway": "192.168.1.1",
                   "addresses": ["192.168.1.2/24"]}"#;
    let moved = r#"{"interface": "en0", "type": "wifi", "gateway": "10.0.0.1",
                    "addresses": ["10.0.0.2/24"]}"#;
    let ethernet = r#"{"interface": "en1", "type": "ethernet", "gateway": "10.0.0.1",
                       "addresses": ["10.0.0.3/24"]}"#;
    for last in [moved, ethernet] {
        instance
            .start(Config::Json(config(common::free_port(), 53)))
            .await
            .unwrap();
        instance.set_network_state(wifi).unwrap();
        instance.set_network_state(last).unwrap();
        instance.stop().await.unwrap();
    }

    // The first run's move, then the second run's change of interface
    // (each run's first state may be told too, or not: a settling).
    let mut seen = Vec::new();
    let done = |seen: &[NetworkChangeKind]| {
        let moved = seen.iter().position(|c| *c == NetworkChangeKind::Moved);
        let changed = seen
            .iter()
            .rposition(|c| *c == NetworkChangeKind::InterfaceChanged);
        matches!((moved, changed), (Some(m), Some(c)) if c > m)
    };
    while !done(&seen) {
        let event = tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("each run's changes, told before the stream was read")
            .expect("the stream goes on");
        match event {
            Event::Network(e) => seen.push(e.change),
            other => panic!("unexpected {:?}", other),
        }
    }
}

/// An instance that changes nothing in the system writes no ledger: its
/// run directory is not even made. A sweep of an empty one undoes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_instance_that_changes_nothing_leaves_its_run_dir_unmade() {
    let dir = std::env::temp_dir().join(format!("sail-run-dir-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let instance = Instance::new(options().run_dir(sail::embed::RunDir::Dir(dir.clone()))).unwrap();
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    instance.stop().await.unwrap();
    assert!(!dir.exists(), "no ledger, no directory");
    assert!(sail::embed::sweep(&sail::embed::RunDir::Dir(dir.clone())).is_empty());
    assert!(sail::embed::sweep(&sail::embed::RunDir::Off).is_empty());
}

/// An IPv6 link-local address of this machine, with its interface as the
/// scope: lo0's fe80::1 on macOS, the runner's Ethernet's on Linux. None
/// where there is none.
#[cfg(unix)]
fn link_local() -> Option<std::net::SocketAddrV6> {
    let mut found = None;
    // SAFETY: getifaddrs's list is read, then freed once.
    unsafe {
        let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut addrs) != 0 {
            return None;
        }
        let mut cur = addrs;
        while !cur.is_null() {
            let a = &*cur;
            if !a.ifa_addr.is_null()
                && i32::from((*a.ifa_addr).sa_family) == libc::AF_INET6
                && a.ifa_flags & libc::IFF_UP as u32 != 0
            {
                let sin6 = &*(a.ifa_addr as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let index = libc::if_nametoindex(a.ifa_name);
                if ip.segments()[0] & 0xffc0 == 0xfe80 && index != 0 {
                    found = Some(std::net::SocketAddrV6::new(ip, 0, 0, index));
                    break;
                }
            }
            cur = a.ifa_next;
        }
        libc::freeifaddrs(addrs);
    }
    found
}

/// A datagram to a link-local address goes out with its zone: the scope id
/// a host gives reaches the kernel unchanged, through the direct outbound.
/// Runs wherever an interface has an IPv6 link-local address, which needs
/// no root: lo0 on macOS, the runner's Ethernet on Linux CI.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_datagram_to_a_link_local_address_keeps_its_zone() {
    let Some(local) = link_local() else {
        eprintln!("no IPv6 link-local address here: nothing to test");
        return;
    };
    let echo = tokio::net::UdpSocket::bind(std::net::SocketAddr::V6(local))
        .await
        .unwrap();
    let to = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = crate::common::recv_past_errors(&echo, &mut buf).await;
            let _ = echo.send_to(&buf[..n], from).await;
        }
    });

    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    let datagram = instance
        .dial_udp("direct", Address::from(to), Duration::from_secs(5))
        .await
        .unwrap();
    datagram.send(b"scoped").await.unwrap();
    let mut buf = [0u8; 64];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), datagram.recv_from(&mut buf))
        .await
        .expect("an answer over the link-local address")
        .unwrap();
    assert_eq!(&buf[..n], b"scoped");
    match from {
        Address::Ip(std::net::SocketAddr::V6(v6)) => assert_eq!(*v6.ip(), *local.ip()),
        other => panic!("from {:?}", other),
    }
    instance.stop().await.unwrap();
}

/// The state's changes come as events, and the status as a stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_state_comes_as_events_and_the_status_as_a_stream() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds};

    let instance = Instance::new(options()).unwrap();
    let mut events = Box::pin(instance.events(Kinds::STATE));
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    let mut status = Box::pin(instance.status(Duration::from_millis(100)));
    let first = tokio::time::timeout(Duration::from_secs(5), status.next())
        .await
        .expect("a status in time")
        .unwrap();
    assert_eq!(first.up, 0, "no rate before a second item");
    instance.stop().await.unwrap();
    let mut seen = Vec::new();
    while !matches!(seen.last(), Some(State::Stopped)) {
        match tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("a state in time")
            .unwrap()
        {
            Event::State(state) => seen.push(state),
            other => panic!("unexpected {:?}", other),
        }
    }
    assert!(
        seen.iter().any(|s| matches!(s, State::Running { .. })),
        "{:?}",
        seen
    );
}

/// An inbound added and removed while the instance runs: removing it closes
/// its own connections at once, frees its port, and leaves the other
/// inbounds' connections as they are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_an_inbound_closes_its_connections_only() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [kept_port, removed_port] = common::free_ports::<2>();
    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(kept_port, 53)))
        .await
        .unwrap();
    let proxy = serde_json::json!({
        "type": "socks", "tag": "system-proxy", "listen": "127.0.0.1", "listen_port": removed_port,
    });
    instance.add_inbound(proxy.clone()).await.unwrap();

    let sess = Session {
        destination: echo.into(),
        ..Default::default()
    };
    let mut kept = common::new_socks_stream("127.0.0.1", kept_port, &sess, None, None)
        .await
        .unwrap();
    let mut removed = common::new_socks_stream("127.0.0.1", removed_port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut kept, b"kept").await;
    round_trip(&mut removed, b"removed").await;

    assert_eq!(instance.remove_inbound("system-proxy").await.unwrap(), 1);
    // Closed on return, not a moment later: a connection is refused now.
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", removed_port)).is_err(),
        "the removed inbound still listens once the removal returned"
    );
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), removed.read(&mut buf))
        .await
        .expect("the removed inbound's connection ends at once");
    assert!(matches!(read, Ok(0) | Err(_)));
    round_trip(&mut kept, b"still here").await;
    std::net::TcpListener::bind(("127.0.0.1", removed_port)).expect("its port is free");
    assert_eq!(
        instance
            .remove_inbound("system-proxy")
            .await
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );

    // And back again.
    instance.add_inbound(proxy).await.unwrap();
    let mut again = common::new_socks_stream("127.0.0.1", removed_port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut again, b"again").await;
    instance.stop().await.unwrap();
}

/// A host's sleep and a short wake: told as a network event of reason
/// wake, and no connection closed by it, as sing-box keeps them across a
/// sleep under 2 minutes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_sleep_closes_no_connection() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds, NetworkChangeReason};

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let port = common::free_port();
    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(port, 53)))
        .await
        .unwrap();
    let sess = Session {
        destination: echo.into(),
        ..Default::default()
    };
    let mut stream = common::new_socks_stream("127.0.0.1", port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut stream, b"before").await;

    let mut events = Box::pin(instance.events(Kinds::NETWORK));
    instance.sleep().unwrap();
    instance.wake().unwrap();
    let woke = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.next().await.expect("the stream goes on") {
                Event::Network(e) if e.reason == NetworkChangeReason::Wake => break e,
                _ => {}
            }
        }
    })
    .await
    .expect("the wake told in time");
    assert_eq!(
        woke.old.interface, woke.new.interface,
        "nothing different: {:?}",
        woke
    );
    // What a wake would close is closed by now if it were: the follower
    // handled the event before the next one is told. Give it a moment.
    tokio::time::sleep(Duration::from_millis(200)).await;
    round_trip(&mut stream, b"after").await;
    // A wake with no sleep before it is nothing.
    instance.wake().unwrap();
    instance.stop().await.unwrap();
}

/// A wake after a long sleep closes only what is idle: a connection in use
/// goes on, and the log says the idle carriers were closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_sleep_keeps_the_connections_in_use() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds, NetworkChangeReason};

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let port = common::free_port();
    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(port, 53)))
        .await
        .unwrap();
    let sess = Session {
        destination: echo.into(),
        ..Default::default()
    };
    let mut stream = common::new_socks_stream("127.0.0.1", port, &sess, None, None)
        .await
        .unwrap();
    round_trip(&mut stream, b"before").await;

    let mut events = Box::pin(instance.events(Kinds::NETWORK));
    let manager = sail::runtime_manager(instance.id()).expect("the instance runs");
    // As sail's own detection would see a 5 minute sleep.
    manager.network().detected_wake(Duration::from_secs(300));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Event::Network(e) = events.next().await.expect("the stream goes on") {
                if e.reason == NetworkChangeReason::Wake {
                    break;
                }
            }
        }
    })
    .await
    .expect("the wake told in time");
    tokio::time::sleep(Duration::from_millis(200)).await;
    round_trip(&mut stream, b"after").await;
    instance.stop().await.unwrap();
}

/// The network is settled when start returns: the interface (or an
/// explicit offline) at generation 1, before any change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_network_is_settled_when_start_returns() {
    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    let network = instance.network().unwrap();
    assert!(network.generation >= 1, "{:?}", network);
    // CI's runners and a developer's machine have a default route.
    assert!(network.interface.is_some(), "{:?}", network);
    instance.stop().await.unwrap();
}

/// A stop ends the instance's tasks within its bound and says so; a run
/// with no panic has no faults; test builds catch panics.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_reports_its_tasks_ended() {
    const { assert!(sail::embed::PANICS_ARE_CAUGHT) };
    let instance = Instance::new(options().stop_within(Duration::from_secs(2))).unwrap();
    assert!(instance.stop_report().is_none(), "no stop yet");
    instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap();
    assert_eq!(instance.faults().unwrap(), 0);
    instance.stop().await.unwrap();
    let report = instance.stop_report().expect("a report after a stop");
    assert!(report.clean(), "{:?}", report);
    assert!(report.waited <= Duration::from_secs(2));
}

/// A SOCKS5 connection through `proxy` asking for 127.0.0.1:`port`, its
/// greeting answered and its request sent, the reply not read.
async fn socks_asked(proxy: u16, port: u16) -> tokio::net::TcpStream {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", proxy))
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeted = [0u8; 2];
    s.read_exact(&mut greeted).await.unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend(port.to_be_bytes());
    s.write_all(&request).await.unwrap();
    s
}

/// The reply's code: 0 when connected.
async fn socks_reply(s: &mut tokio::net::TcpStream) -> u8 {
    let mut reply = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut reply))
        .await
        .expect("a SOCKS reply in time")
        .unwrap();
    reply[1]
}

/// `Kinds::ROUTE` tells every connection once: one that is over before
/// any poll of the connections open, a dial that fails, a reject and a
/// hijacked DNS query, none of which such a poll shows. While no one
/// subscribes, none is built.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_connection_is_told_once_and_none_is_built_unheard() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds, RouteAction, RoutedConnection};
    use sail::session::{Network, SocksAddr};
    use std::sync::Arc;

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [socks, rejected, hijacked, dead] = common::free_ports();
    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "upstream", "type": "udp", "server": "127.0.0.1", "server_port": 53 }],
        },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks,
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": {
            "rules": [
                { "port": [rejected], "action": "reject" },
                // One entry of the list, whatever it holds.
                { "type": "logical", "mode": "or",
                  "rules": [{ "port": [1] }, { "port": [2] }], "outbound": "direct" },
                { "port": [hijacked], "action": "hijack-dns" },
                { "port": [echo.port()], "outbound": "direct" },
            ],
            "final": "direct",
        },
    })
    .to_string();
    let instance = Instance::new(options()).unwrap();
    instance.start(Config::Json(config)).await.unwrap();

    // A connection over at once: asked for, a byte each way, closed.
    async fn short(socks: u16, port: u16) {
        let mut s = socks_asked(socks, port).await;
        assert_eq!(socks_reply(&mut s).await, 0);
        round_trip(&mut s, b"x").await;
    }

    // No one listens: nothing is built.
    for _ in 0..3 {
        short(socks, echo.port()).await;
    }
    assert_eq!(instance.routes_built().unwrap(), 0);

    let mut events = Box::pin(instance.events(Kinds::ROUTE));
    async fn next(
        events: &mut (impl futures::Stream<Item = Event> + Unpin),
    ) -> Arc<RoutedConnection> {
        match tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("a routed connection in time")
            .unwrap()
        {
            Event::Routed(routed) => routed,
            other => panic!("unexpected {:?}", other),
        }
    }
    let to = |port: u16| SocksAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], port)));

    // One that is over before any poll would see it.
    short(socks, echo.port()).await;
    let told = next(&mut events).await;
    assert_eq!(told.action, RouteAction::Outbound, "{:?}", told);
    assert_eq!(told.network, Network::Tcp);
    assert_eq!(told.inbound, "socks-in");
    assert_eq!(told.destination, to(echo.port()));
    assert_eq!(told.request_destination, Some(to(echo.port())));
    assert_eq!(told.rule, Some(3), "its index in route.rules as written");
    assert!(told.rule_text.is_some());
    assert_eq!(told.chain, ["direct"]);
    assert_eq!(told.target, Some(echo));
    assert!(matches!(told.connect, Some(Ok(_))), "{:?}", told);
    assert!(told.id.is_some());
    assert_eq!(told.domain, None);

    // A dial that fails: nothing listens there. `final` decided.
    let mut s = socks_asked(socks, dead).await;
    assert_ne!(socks_reply(&mut s).await, 0);
    let told = next(&mut events).await;
    assert_eq!(told.action, RouteAction::Outbound, "{:?}", told);
    assert_eq!(told.rule, None);
    assert_eq!(told.chain, ["direct"]);
    assert_eq!(
        told.connect,
        Some(Err(std::io::ErrorKind::ConnectionRefused)),
        "{:?}",
        told
    );
    assert_eq!(told.id, None, "it never opened");

    // A reject.
    let mut s = socks_asked(socks, rejected).await;
    assert_ne!(socks_reply(&mut s).await, 0);
    let told = next(&mut events).await;
    assert_eq!(told.action, RouteAction::Reject, "{:?}", told);
    assert_eq!(told.rule, Some(0));
    assert_eq!(told.connect, None);
    assert!(told.chain.is_empty());

    // A hijacked DNS query: told when the rules decide, whatever it asks.
    let s = socks_asked(socks, hijacked).await;
    let told = next(&mut events).await;
    assert_eq!(told.action, RouteAction::HijackDns, "{:?}", told);
    assert_eq!(told.rule, Some(2));
    assert_eq!(told.destination, to(hijacked));
    drop(s);

    // Each exactly once: four built, and no fifth event.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), events.next())
            .await
            .is_err(),
        "a connection was told twice"
    );
    assert_eq!(instance.routes_built().unwrap(), 4);

    // The subscription dropped, nothing is built again.
    drop(events);
    short(socks, echo.port()).await;
    assert_eq!(instance.routes_built().unwrap(), 4);
    instance.stop().await.unwrap();
}

/// `Kinds::DNS` tells the queries the instance makes to dial a domain,
/// and a rule's answer; none is built while no one subscribes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_queries_are_told_and_none_is_built_unheard() {
    use futures::StreamExt;
    use sail::embed::{DnsExchange, DnsOutcome, DnsSource, Event, Kinds};
    use sail::session::SocksAddr;
    use std::sync::Arc;

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "home", "type": "hosts",
                          "predefined": { "echo.test": "127.0.0.1" } }],
            "rules": [{ "domain": "blocked.test", "action": "reject" }],
        },
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    })
    .to_string();
    let instance = Instance::new(options()).unwrap();
    instance.start(Config::Json(config)).await.unwrap();
    let dial = |name: &str| {
        let instance = &instance;
        let to = SocksAddr::Domain(name.into(), echo.port());
        async move {
            instance
                .dial_tcp("direct", to, Duration::from_secs(5))
                .await
        }
    };

    dial("echo.test").await.unwrap();
    assert_eq!(instance.dns_built().unwrap(), 0);

    let mut events = Box::pin(instance.events(Kinds::DNS));
    // Every event until `name`'s A query is told.
    async fn until_a(
        events: &mut (impl futures::Stream<Item = Event> + Unpin),
        name: &str,
    ) -> Arc<DnsExchange> {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), events.next())
                .await
                .expect("a DNS event in time")
                .unwrap()
            {
                Event::DnsExchange(e) if e.name == name && e.qtype == "A" => return e,
                // The other family, or the query before's.
                Event::DnsExchange(_) => {}
                other => panic!("unexpected {:?}", other),
            }
        }
    }

    let mut s = dial("echo.test").await.unwrap();
    let told = until_a(&mut events, "echo.test").await;
    assert_eq!(told.server.as_deref(), Some("home"), "{:?}", told);
    assert_eq!(told.answers, ["127.0.0.1"]);
    assert!(told.for_instance);
    assert!(
        matches!(told.outcome, DnsOutcome::Answered { .. }),
        "{:?}",
        told
    );
    round_trip(&mut s, b"x").await;

    assert!(dial("blocked.test").await.is_err());
    let told = until_a(&mut events, "blocked.test").await;
    assert_eq!(told.source, DnsSource::Rule, "{:?}", told);
    assert_eq!(told.server, None);
    assert!(told.for_instance);

    let built = instance.dns_built().unwrap();
    assert!(built >= 2, "{}", built);
    drop(events);
    dial("echo.test").await.unwrap();
    assert_eq!(instance.dns_built().unwrap(), built);
    instance.stop().await.unwrap();
}

/// The outbounds a connection went through are told outermost first, the
/// one that carried it last, by `Event::Routed` and `Event::DialFailed`
/// alike, for a rule that names a group whose member is a group; the
/// connections list has them the other way round, as the Clash API does.
#[cfg(feature = "outbound-select")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chain_is_told_outermost_first_by_routed_and_dial_failed_alike() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds};

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [socks, dead] = common::free_ports();
    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "upstream", "type": "udp", "server": "127.0.0.1", "server_port": 53 }],
        },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks,
        }],
        "outbounds": [
            { "type": "direct", "tag": "m" },
            { "type": "selector", "tag": "G", "outbounds": ["m"] },
            { "type": "selector", "tag": "F", "outbounds": ["G"] },
        ],
        "route": {
            "rules": [{ "port": [echo.port(), dead], "outbound": "F" }],
            "final": "m",
        },
    })
    .to_string();
    let instance = Instance::new(options()).unwrap();
    instance.start(Config::Json(config)).await.unwrap();
    let mut events = Box::pin(instance.events(Kinds::ROUTE | Kinds::DIAL));
    async fn next(events: &mut (impl futures::Stream<Item = Event> + Unpin)) -> Event {
        tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("an event in time")
            .unwrap()
    }

    // One that connects, held open: listed, and told.
    let mut held = socks_asked(socks, echo.port()).await;
    assert_eq!(socks_reply(&mut held).await, 0);
    round_trip(&mut held, b"x").await;
    match next(&mut events).await {
        Event::Routed(routed) => {
            assert_eq!(routed.chain, ["F", "G", "m"], "{:?}", routed);
            assert!(matches!(routed.connect, Some(Ok(_))), "{:?}", routed);
        }
        other => panic!("unexpected {:?}", other),
    }
    let listed = instance.connections().await.unwrap();
    let listed = listed
        .iter()
        .find(|c| c.inbound_tag == "socks-in")
        .expect("the connection held is listed");
    assert_eq!(listed.chains, ["m", "G", "F"], "the Clash API's order");

    // One whose dial fails: both events, in whichever order they come.
    let mut refused = socks_asked(socks, dead).await;
    assert_ne!(socks_reply(&mut refused).await, 0);
    let (mut routed, mut failed) = (None, None);
    while routed.is_none() || failed.is_none() {
        match next(&mut events).await {
            Event::Routed(event) => routed = Some(event),
            Event::DialFailed { failure, .. } => failed = Some(failure),
            other => panic!("unexpected {:?}", other),
        }
    }
    let (routed, failed) = (routed.unwrap(), failed.unwrap());
    assert_eq!(routed.chain, ["F", "G", "m"], "{:?}", routed);
    assert!(matches!(routed.connect, Some(Err(_))), "{:?}", routed);
    assert_eq!(failed.chain, "F>G>m", "{:?}", failed);
    assert_eq!(failed.chain, routed.chain.join(">"));
    drop(held);
    instance.stop().await.unwrap();
}

/// A DNS answer to `query`: 127.0.0.1 for an A question, none for any
/// other.
#[cfg(feature = "rule-set")]
fn dns_answer(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    // The question's end: its name, its type and class.
    let mut at = 12;
    while answer[at] != 0 {
        at += 1 + answer[at] as usize;
    }
    let a = answer[at + 1..at + 3] == [0, 1];
    answer.truncate(at + 5);
    // A response, recursion available; one answer or none, nothing else.
    answer[2] = 0x81;
    answer[3] = 0x80;
    answer[6..12].copy_from_slice(&[0, u8::from(a), 0, 0, 0, 0]);
    if a {
        answer.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
    }
    answer
}

/// A host's own DNS service, which the configuration names, is asked
/// while the instance starts, for the name of a remote rule-set the start
/// waits for. It answers by dialling back through the instance, and reads
/// the network first: both work in `Starting`, so the start succeeds.
/// A dial made as the start begins waits rather than being refused; once
/// the run has ended, both say it does not run.
#[cfg(feature = "rule-set")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_service_asked_during_the_start_dials_back_and_reads_the_network() {
    use std::sync::{Arc, Mutex};

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);

    // What the host's service asks in its turn: answers every name.
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = common::recv_past_errors(&upstream, &mut buf).await;
            let _ = upstream.send_to(&dns_answer(&buf[..n]), from).await;
        }
    });

    // The rule-set, at a name only that DNS knows.
    let rules = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rules_port = rules.local_addr().unwrap().port();
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, Write};
        for stream in rules.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                line.clear();
            }
            let body = r#"{ "version": 3, "rules": [{ "ip_cidr": "192.0.2.0/24" }] }"#;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });

    let instance = Arc::new(Instance::new(options()).unwrap());

    // The host's DNS service: for each query, the network and the state
    // as it sees them, then the answer fetched through the instance.
    struct Asked {
        starting: bool,
        interface: Result<bool, ErrorKind>,
        dialled: Result<(), ErrorKind>,
    }
    let asked: Arc<Mutex<Vec<Asked>>> = Arc::default();
    let service = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let service_port = service.local_addr().unwrap().port();
    tokio::spawn({
        let (instance, asked, service) = (instance.clone(), asked.clone(), service.clone());
        async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, from) = common::recv_past_errors(&service, &mut buf).await;
                let query = buf[..n].to_vec();
                let (instance, asked, service) = (instance.clone(), asked.clone(), service.clone());
                tokio::spawn(async move {
                    let starting = instance.state() == State::Starting;
                    let interface = instance
                        .network()
                        .map(|network| network.interface.is_some())
                        .map_err(|e| e.kind());
                    let answered = async {
                        let upstream = instance
                            .dial_udp(
                                "direct",
                                Address::from(upstream_addr),
                                Duration::from_secs(2),
                            )
                            .await
                            .map_err(|e| e.kind())?;
                        upstream.send(&query).await.map_err(|_| ErrorKind::Io)?;
                        let mut answer = [0u8; 1500];
                        let (n, _) = tokio::time::timeout(
                            Duration::from_secs(2),
                            upstream.recv_from(&mut answer),
                        )
                        .await
                        .map_err(|_| ErrorKind::Timeout)?
                        .map_err(|_| ErrorKind::Io)?;
                        Ok(answer[..n].to_vec())
                    };
                    let answer: Result<Vec<u8>, ErrorKind> = answered.await;
                    // Recorded before the answer goes: the start it lets
                    // finish is followed at once by the checks of what
                    // was asked.
                    asked.lock().unwrap().push(Asked {
                        starting,
                        interface,
                        dialled: answer.as_ref().map(|_| ()).map_err(|e| *e),
                    });
                    if let Ok(answer) = answer {
                        let _ = service.send_to(&answer, from).await;
                    }
                });
            }
        }
    });

    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "host", "type": "udp", "server": "127.0.0.1", "server_port": service_port }],
        },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": common::free_port(),
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": {
            "rule_set": [{
                "type": "remote", "tag": "s", "format": "source",
                "url": format!("http://rules.test:{}/s.json", rules_port),
            }],
            "rules": [{ "rule_set": "s", "action": "reject" }],
            "final": "direct",
        },
    })
    .to_string();

    // Not started: a dial is refused, and so is the network.
    let idle = instance
        .dial_tcp("direct", Address::from(echo), Duration::from_secs(5))
        .await;
    assert_eq!(idle.err().map(|e| e.kind()), Some(ErrorKind::NotRunning));
    assert_eq!(
        instance.network().unwrap_err().kind(),
        ErrorKind::NotRunning
    );

    // A dial made as the start begins waits for the outbounds, and dials.
    let (started, early) = tokio::join!(
        instance.start(Config::Json(config)),
        instance.dial_tcp("direct", Address::from(echo), Duration::from_secs(5)),
    );
    // The start waited for the rule-set, whose name the host's service
    // resolved by dialling back: a refusal there fails the start.
    started.expect("the start, which needs the rule-set's name resolved");
    let mut early = early.expect("a dial made while it starts");
    round_trip(&mut early, b"dialled while it started").await;

    {
        let asked = asked.lock().unwrap();
        assert!(
            !asked.is_empty(),
            "the host's DNS was asked during the start"
        );
        for asked in asked.iter() {
            assert_eq!(asked.dialled, Ok(()), "a dial back was refused");
            assert_eq!(asked.interface, Ok(true), "the network was not settled");
        }
        assert!(
            asked.iter().any(|asked| asked.starting),
            "none was asked while it started"
        );
    }

    // The run ended: what dialled through it dials no more.
    instance.stop().await.unwrap();
    let after = instance
        .dial_udp(
            "direct",
            Address::from(upstream_addr),
            Duration::from_secs(2),
        )
        .await;
    assert_eq!(after.err().map(|e| e.kind()), Some(ErrorKind::NotRunning));
    assert_eq!(
        instance.network().unwrap_err().kind(),
        ErrorKind::NotRunning
    );
}

/// A group's health check, spawned while the instance is built, on no
/// task, is the instance's: in its scope while it runs, ended by its stop.
#[cfg(feature = "outbound-urltest")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_groups_checks_built_at_start_are_the_instances() {
    let mut config: serde_json::Value =
        serde_json::from_str(&config(common::free_port(), 53)).unwrap();
    config["outbounds"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "type": "urltest", "tag": "auto", "outbounds": ["direct"],
            "url": "http://127.0.0.1:9/", "interval": "1m",
        }));
    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config.to_string()))
        .await
        .unwrap();
    let tasks = instance.tasks().unwrap();
    assert!(
        tasks.iter().any(|(name, _)| *name == "group health check"),
        "{:?}",
        tasks
    );
    instance.stop().await.unwrap();
    let report = instance.stop_report().expect("a report after a stop");
    assert!(report.clean(), "{:?}", report);
}

/// Two instances on the host's runtime at once, as a desktop app's UI and
/// service in one process: each carries its connections; stopped in the
/// order other than started, they leave nothing on the runtime. (Their
/// logs: test_embed_host_subscriber.rs.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn instances_on_the_hosts_runtime_carry_and_leave_nothing() {
    let host = tokio::runtime::Handle::current();
    let (echo_a, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let (echo_b, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let alive_before = host.metrics().num_alive_tasks();

    let on_host = || {
        // `threads` is ignored under the host's runtime.
        options().runtime(sail::embed::Runtime::Host(host.clone()))
    };
    let (a, b) = (
        Instance::new(on_host()).unwrap(),
        Instance::new(on_host()).unwrap(),
    );
    let (a_port, b_port) = (common::free_port(), common::free_port());
    a.start(Config::Json(config(a_port, 53))).await.unwrap();
    b.start(Config::Json(config(b_port, 53))).await.unwrap();
    assert!(
        host.metrics().num_alive_tasks() > alive_before,
        "the instances' tasks run on the host's runtime"
    );

    for (port, echo) in [(a_port, echo_a), (b_port, echo_b)] {
        let mut s = socks_asked(port, echo.port()).await;
        assert_eq!(socks_reply(&mut s).await, 0);
        round_trip(&mut s, b"on the host's runtime").await;
    }
    b.stop().await.unwrap();
    assert!(matches!(a.state(), State::Running { .. }), "a goes on");
    let mut s = socks_asked(a_port, echo_a.port()).await;
    assert_eq!(socks_reply(&mut s).await, 0);
    round_trip(&mut s, b"after b stopped").await;
    drop(s);
    a.stop().await.unwrap();
    for instance in [&a, &b] {
        let report = instance.stop_report().expect("a report after a stop");
        assert!(report.clean(), "{:?}", report);
    }
    std::net::TcpListener::bind(("127.0.0.1", a_port)).expect("a's port is free");
    std::net::TcpListener::bind(("127.0.0.1", b_port)).expect("b's port is free");

    // Not one task of theirs left on the host's runtime: a task's last
    // drop may finish just after the stop.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while host.metrics().num_alive_tasks() > alive_before && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(host.metrics().num_alive_tasks(), alive_before);

    // And one starts again on it.
    a.start(Config::Json(config(a_port, 53))).await.unwrap();
    a.stop().await.unwrap();
}

/// A current-thread runtime is refused at start, saying so: the instance's
/// own thread blocks on it, which such a runtime does not serve.
#[tokio::test(flavor = "current_thread")]
async fn a_current_thread_host_runtime_is_refused() {
    let instance = Instance::new(
        options().runtime(sail::embed::Runtime::Host(tokio::runtime::Handle::current())),
    )
    .unwrap();
    let err = instance
        .start(Config::Json(config(common::free_port(), 53)))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument, "{}", err);
    assert!(err.to_string().contains("current-thread"), "{}", err);
    assert!(
        matches!(instance.state(), State::Failed(ref e) if e.kind() == ErrorKind::InvalidArgument)
    );
}

/// A runtime without timers is refused at start, saying what to build it
/// with, rather than the first timer panicking in a task.
#[test]
fn a_host_runtime_without_timers_is_refused() {
    let host = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_io()
        .build()
        .unwrap();
    let instance =
        Instance::new(options().runtime(sail::embed::Runtime::Host(host.handle().clone())))
            .unwrap();
    let err =
        futures::executor::block_on(instance.start(Config::Json(config(common::free_port(), 53))))
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidArgument, "{}", err);
    assert!(err.to_string().contains("enable_all()"), "{}", err);
}

/// A connection through an inbound with users: its routed event names the
/// user, and its closed record tells the user, what it sent and received
/// (the same the user's counts went up by), and how it ended: finished
/// both ways, or closed by the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_s_record_tells_its_user_bytes_and_end() {
    use futures::StreamExt;
    use sail::embed::{ClosedBy, ConnectionRecord, End, Event, Kinds, Outcome, RecordKind};
    use std::sync::Arc;

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let socks = common::free_port();
    let config = serde_json::json!({
        "log": { "level": "info" },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks,
            "users": [{ "username": "alice", "password": "secret" }],
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "final": "direct" },
    })
    .to_string();
    let instance = Instance::new(options()).unwrap();
    instance.start(Config::Json(config)).await.unwrap();
    let mut events = Box::pin(instance.events(Kinds::CONNECTION | Kinds::ROUTE));

    // SOCKS5 as alice, to the echo server.
    async fn as_alice(socks: u16, port: u16) -> tokio::net::TcpStream {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks))
            .await
            .unwrap();
        s.write_all(&[5, 1, 2]).await.unwrap();
        let mut chosen = [0u8; 2];
        s.read_exact(&mut chosen).await.unwrap();
        assert_eq!(chosen, [5, 2]);
        let mut auth = vec![1, 5];
        auth.extend(b"alice");
        auth.push(6);
        auth.extend(b"secret");
        s.write_all(&auth).await.unwrap();
        let mut authed = [0u8; 2];
        s.read_exact(&mut authed).await.unwrap();
        assert_eq!(authed, [1, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(port.to_be_bytes());
        s.write_all(&request).await.unwrap();
        assert_eq!(socks_reply(&mut s).await, 0);
        s
    }
    async fn record(
        events: &mut (impl futures::Stream<Item = Event> + Unpin),
    ) -> Arc<ConnectionRecord> {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), events.next())
                .await
                .expect("a record in time")
                .unwrap()
            {
                Event::ConnectionRecord(record) => return record,
                Event::Routed(routed) => {
                    assert_eq!(routed.user.as_deref(), Some("alice"), "{:?}", routed)
                }
                other => panic!("unexpected {:?}", other),
            }
        }
    }

    // Finished both ways: the client's end first, then the echo's.
    let mut s = as_alice(socks, echo.port()).await;
    round_trip(&mut s, b"hello").await;
    s.shutdown().await.unwrap();
    let mut rest = Vec::new();
    s.read_to_end(&mut rest).await.unwrap();
    let told = record(&mut events).await;
    assert_eq!(told.kind, RecordKind::Closed(End::Finished), "{:?}", told);
    assert_eq!(told.user.as_deref(), Some("alice"));
    assert_eq!(told.inbound, "socks-in");
    assert_eq!(told.chain, ["direct"]);
    assert_eq!(told.outbound.as_deref(), Some("direct"));
    assert_eq!(told.outcome, Some(Outcome::Ok));
    assert_eq!(
        told.local,
        std::net::SocketAddr::from(([127, 0, 0, 1], socks))
    );
    assert_eq!((told.up_total, told.down_total), (5, 5));
    assert_eq!(told.seq, 0);
    assert!(told.request_destination.is_some());

    // Closed by the host while open.
    let mut s = as_alice(socks, echo.port()).await;
    round_trip(&mut s, b"abc").await;
    let open = instance.connections().await.unwrap();
    assert_eq!(open.len(), 1);
    assert!(instance.close_connection(open[0].id).await.unwrap());
    let told = record(&mut events).await;
    assert_eq!(
        told.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Api)),
        "{:?}",
        told
    );
    assert_eq!((told.up_total, told.down_total), (3, 3));
    assert_eq!(told.id, open[0].id);
    drop(s);

    instance.stop().await.unwrap();
}

/// An interim pass asked for records what each open connection moved so
/// far, whether it moved anything new or not; a stop cuts what is left
/// open, and its closed record tells all, and that the stop ended it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interim_pass_before_a_stop_records_what_is_open() {
    use futures::StreamExt;
    use sail::embed::{ClosedBy, ConnectionRecord, End, Event, Kinds, RecordKind};
    use std::sync::Arc;

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let socks = common::free_port();
    let instance = Instance::new(options()).unwrap();
    instance
        .start(Config::Json(config(socks, 53)))
        .await
        .unwrap();
    let mut events = Box::pin(instance.events(Kinds::CONNECTION));
    async fn record(
        events: &mut (impl futures::Stream<Item = Event> + Unpin),
    ) -> Arc<ConnectionRecord> {
        match tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("a record in time")
            .unwrap()
        {
            Event::ConnectionRecord(record) => record,
            other => panic!("unexpected {:?}", other),
        }
    }

    let mut s = socks_asked(socks, echo.port()).await;
    assert_eq!(socks_reply(&mut s).await, 0);
    round_trip(&mut s, b"hello").await;
    assert_eq!(instance.report_connections().await.unwrap(), 1);
    let interim = record(&mut events).await;
    assert_eq!(interim.kind, RecordKind::Interim);
    assert_eq!(
        (interim.up_total, interim.down_total, interim.seq),
        (5, 5, 0)
    );
    assert_eq!(
        instance.report_connections().await.unwrap(),
        1,
        "nothing new, still asked for"
    );
    let again = record(&mut events).await;
    assert_eq!((again.up_total, again.seq), (5, 1));

    round_trip(&mut s, b"ab").await;
    instance.stop().await.unwrap();
    let closed = record(&mut events).await;
    assert_eq!(
        closed.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Stopped)),
        "{:?}",
        closed
    );
    assert_eq!(closed.seq, 2);
    assert_eq!((closed.up_total, closed.down_total), (7, 7));
    assert_eq!(closed.id, interim.id);
    assert_eq!(closed.run, interim.run);
}

/// Under pressure, connections stalled in their handshake are closed, the
/// level change is told, and the instance counts what it did. Pressure is
/// made of descriptors here, which a test can set: one handshake in flight
/// at most, by a share of the open-file limit as large as the limit.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_handshakes_are_closed_under_pressure() {
    use futures::StreamExt;
    use sail::embed::{AdmissionLevel, Event, Kinds};

    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes the struct it is given, nothing else.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    let share = u32::try_from(limit.rlim_cur).unwrap_or(u32::MAX);
    let settings = serde_json::json!({
        "set": [
            format!("inbound.handshake_descriptor_share={}", share),
            "inbound.handshake_stall=100ms".to_string(),
        ],
    })
    .to_string();
    let socks = common::free_port();
    let instance = Instance::new(options().settings_json(&settings).unwrap()).unwrap();
    instance
        .start(Config::Json(config(socks, 53)))
        .await
        .unwrap();
    let mut events = Box::pin(instance.events(Kinds::ADMISSION));
    let info = instance.admission().unwrap().expect("admission is on");
    assert_eq!(info.level, AdmissionLevel::Normal);

    // Two that never say a word, in their handshake past the stall.
    let mut stalled = Vec::new();
    for _ in 0..2 {
        stalled.push(
            tokio::net::TcpStream::connect(("127.0.0.1", socks))
                .await
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The next accept finds two in flight, one more than may be: pressure,
    // and the stalled two are closed.
    let mut s = socks_asked(socks, 9).await;
    for mut s in stalled {
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("closed in time");
        assert!(matches!(read, Ok(0) | Err(_)), "{:?}", read);
    }
    match tokio::time::timeout(Duration::from_secs(5), events.next())
        .await
        .expect("a change in time")
        .unwrap()
    {
        Event::Admission(change) => assert_eq!(change.level, AdmissionLevel::Pressure),
        other => panic!("unexpected {:?}", other),
    }
    let info = instance.admission().unwrap().unwrap();
    assert_eq!(info.evicted, 2, "{:?}", info);
    assert!(info.pressure > Duration::ZERO || info.level == AdmissionLevel::Pressure);
    // The one that came on is not refused: it gets its reply.
    let _ = socks_reply(&mut s).await;
    instance.stop().await.unwrap();
}

/// A UDP association has authenticated once it is set up: it gives its
/// handshake place back then, and a connection after it takes it, with
/// one place in all. It held the place for as long as it lived.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_udp_association_gives_its_handshake_place_back() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let settings = serde_json::json!({ "set": ["inbound.max_handshakes=1"] }).to_string();
    let socks = common::free_port();
    let instance = Instance::new(options().settings_json(&settings).unwrap()).unwrap();
    instance
        .start(Config::Json(config(socks, 53)))
        .await
        .unwrap();

    // UDP ASSOCIATE, kept open.
    let mut association = tokio::net::TcpStream::connect(("127.0.0.1", socks))
        .await
        .unwrap();
    association.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeted = [0u8; 2];
    association.read_exact(&mut greeted).await.unwrap();
    association
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    assert_eq!(socks_reply(&mut association).await, 0);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A connection after it has the one place.
    let mut s = socks_asked(socks, echo.port()).await;
    assert_eq!(socks_reply(&mut s).await, 0);
    round_trip(&mut s, b"x").await;
    drop(association);
    instance.stop().await.unwrap();
}

/// With admission on, an inbound whose handshake places are all taken
/// closes its stalled handshakes, whatever the memory: a slow-loris holds
/// its one place for the stall at most, and a prompt client gets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_inbound_makes_room_for_a_prompt_client() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let settings = serde_json::json!({
        "set": [
            "inbound.max_handshakes=1",
            "inbound.handshake_stall=100ms",
            "inbound.memory_reserve=1",
        ],
    })
    .to_string();
    let socks = common::free_port();
    let instance = Instance::new(options().settings_json(&settings).unwrap()).unwrap();
    instance
        .start(Config::Json(config(socks, 53)))
        .await
        .unwrap();

    // It says nothing, and holds the inbound's one place.
    let mut stalled = tokio::net::TcpStream::connect(("127.0.0.1", socks))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Turned away, it closes the stalled one.
    let _turned_away = tokio::net::TcpStream::connect(("127.0.0.1", socks))
        .await
        .unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), stalled.read(&mut buf))
        .await
        .expect("the stalled one closed in time");
    assert!(matches!(read, Ok(0) | Err(_)), "{:?}", read);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The next prompt client has the place.
    let mut s = socks_asked(socks, echo.port()).await;
    assert_eq!(socks_reply(&mut s).await, 0);
    round_trip(&mut s, b"x").await;
    let info = instance.admission().unwrap().unwrap();
    assert_eq!(info.evicted_full, 1, "{:?}", info);
    instance.stop().await.unwrap();
}

/// A host limits a user and disconnects it without a reload: a TCP
/// connection past its `max_tcp_connections` is refused, its connections
/// close when it is disconnected, and limits for a user not made yet wait
/// for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_limits_and_disconnects_a_user_without_a_reload() {
    use sail::embed::UserLimits;
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let socks = common::free_port();
    let config = serde_json::json!({
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks,
            "users": [{ "username": "alice", "password": "secret" }],
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    })
    .to_string();
    let instance = Instance::new(options()).unwrap();
    instance.start(Config::Json(config.clone())).await.unwrap();

    async fn as_alice(socks: u16, port: u16) -> (tokio::net::TcpStream, u8) {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks))
            .await
            .unwrap();
        s.write_all(&[5, 1, 2]).await.unwrap();
        let mut chosen = [0u8; 2];
        s.read_exact(&mut chosen).await.unwrap();
        let mut auth = vec![1, 5];
        auth.extend(b"alice");
        auth.push(6);
        auth.extend(b"secret");
        s.write_all(&auth).await.unwrap();
        let mut authed = [0u8; 2];
        s.read_exact(&mut authed).await.unwrap();
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(port.to_be_bytes());
        s.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        let code = match tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut reply))
            .await
            .expect("a reply in time")
        {
            Ok(_) => reply[1],
            Err(_) => 0xff,
        };
        (s, code)
    }

    let mut one_tcp = UserLimits::default();
    one_tcp.max_tcp_connections = Some(1);
    instance.set_user_limits("alice", one_tcp).unwrap();
    // A user there is none of yet: kept for when there is.
    instance
        .set_user_limits("carol", UserLimits::default())
        .unwrap();
    assert_eq!(instance.disconnect_user("carol").unwrap(), 0);

    let (mut first, code) = as_alice(socks, echo.port()).await;
    assert_eq!(code, 0);
    round_trip(&mut first, b"x").await;
    let (_second, code) = as_alice(socks, echo.port()).await;
    assert_ne!(code, 0, "past its max_tcp_connections");

    assert_eq!(instance.disconnect_user("alice").unwrap(), 1);
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), first.read(&mut buf))
        .await
        .expect("closed in time");
    assert!(matches!(read, Ok(0) | Err(_)), "{:?}", read);

    // A reload that leaves alice's configured limits as they were keeps
    // hers: one at once still.
    let report = instance
        .reload(Some(Config::Json(config.clone())))
        .await
        .unwrap();
    assert!(report.user_limits_dropped.is_empty(), "{:?}", report);
    let (mut held, code) = as_alice(socks, echo.port()).await;
    assert_eq!(code, 0);
    round_trip(&mut held, b"h").await;
    let (_over, code) = as_alice(socks, echo.port()).await;
    assert_ne!(code, 0, "kept through the reload");
    // One that changes them drops hers, and names her.
    let mut changed: serde_json::Value = serde_json::from_str(&config).unwrap();
    changed["user_limits"] = serde_json::json!({ "alice": { "max_connections": 5 } });
    let report = instance
        .reload(Some(Config::Json(changed.to_string())))
        .await
        .unwrap();
    assert_eq!(report.user_limits_dropped, ["alice"]);
    let (mut second, code) = as_alice(socks, echo.port()).await;
    assert_eq!(code, 0, "the configuration's now");
    round_trip(&mut second, b"s").await;
    drop((held, second));

    // Put back to the configuration's, none: two at once again.
    instance.restore_user_limits("alice").unwrap();
    let (mut a, code) = as_alice(socks, echo.port()).await;
    assert_eq!(code, 0);
    let (mut b, code) = as_alice(socks, echo.port()).await;
    assert_eq!(code, 0);
    round_trip(&mut a, b"a").await;
    round_trip(&mut b, b"b").await;
    instance.stop().await.unwrap();
}

/// With lossless records, every closed record is kept for a late reader,
/// though no one subscribes; while `cap` of them wait, a new connection is
/// refused, and counted, until the reader takes one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lossless_records_keep_every_closed_one_and_refuse_past_the_cap() {
    use sail::embed::{End, Outcome, RecordKind};
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let socks = common::free_port();
    let instance = Instance::new(options().connection_records_lossless(3)).unwrap();
    instance
        .start(Config::Json(config(socks, 53)))
        .await
        .unwrap();
    async fn closed_after(socks: u16, port: u16, n: usize) {
        let mut s = socks_asked(socks, port).await;
        assert_eq!(socks_reply(&mut s).await, 0);
        round_trip(&mut s, &vec![b'x'; n]).await;
        s.shutdown().await.unwrap();
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).await.unwrap();
    }
    // Three connections, each a round trip of a different size, closed.
    for n in 1..=3usize {
        closed_after(socks, echo.port(), n * 100).await;
    }
    let mut reader = instance.connection_records().unwrap();
    assert!(instance.connection_records().is_err(), "one reader");
    // Their closed records may still be on their way.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while reader.queued() < 3 {
        assert!(tokio::time::Instant::now() < deadline, "three records");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // At the cap: the next is refused, never answered.
    let mut s = socks_asked(socks, echo.port()).await;
    let mut reply = [0u8; 10];
    let read = tokio::time::timeout(Duration::from_secs(5), s.read(&mut reply))
        .await
        .expect("closed in time");
    assert!(
        matches!(read, Ok(0) | Err(_)) || reply[1] != 0,
        "refused: {:?}",
        read
    );
    assert_eq!(reader.refused(), 1);
    let mut up = 0;
    while let Some(r) = reader.try_next() {
        assert_eq!(r.kind, RecordKind::Closed(End::Finished), "{:?}", r);
        assert_eq!(r.outcome, Some(Outcome::Ok));
        assert_eq!(r.outbound.as_deref(), Some("direct"));
        up += r.up_total;
    }
    assert_eq!(up, 600);
    // Taken: let in again.
    closed_after(socks, echo.port(), 1).await;
    instance.stop().await.unwrap();
    let last = reader.try_next().expect("its closed record");
    assert_eq!((last.up_total, last.down_total), (1, 1));
    assert!(reader.try_next().is_none());
    assert_eq!((reader.refused(), reader.dropped()), (1, 0));
}

/// Each connection routed has exactly one closed record, which tells how
/// it was used: relayed, a dial that failed, blocked by a reject rule,
/// hijacked DNS served, its user refused. One refused has no bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_connection_has_one_closed_record_telling_its_outcome() {
    use futures::StreamExt;
    use sail::embed::{
        ClosedBy, ConnectionRecord, End, Event, Kinds, Outcome, RecordKind, UserLimits,
    };
    use std::sync::Arc;

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let [socks, rejected, hijacked, dead] = common::free_ports();
    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [{ "tag": "upstream", "type": "udp", "server": "127.0.0.1", "server_port": 53 }],
        },
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks,
            "users": [{ "username": "alice", "password": "secret" }],
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": {
            "rules": [
                { "port": [rejected], "action": "reject" },
                { "port": [hijacked], "action": "hijack-dns" },
            ],
            "final": "direct",
        },
    })
    .to_string();
    let instance = Instance::new(options()).unwrap();
    instance.start(Config::Json(config)).await.unwrap();
    let mut events = Box::pin(instance.events(Kinds::CONNECTION));
    async fn record(
        events: &mut (impl futures::Stream<Item = Event> + Unpin),
    ) -> Arc<ConnectionRecord> {
        match tokio::time::timeout(Duration::from_secs(5), events.next())
            .await
            .expect("a record in time")
            .unwrap()
        {
            Event::ConnectionRecord(record) => record,
            other => panic!("unexpected {:?}", other),
        }
    }
    async fn as_alice(socks: u16, port: u16) -> (tokio::net::TcpStream, u8) {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks))
            .await
            .unwrap();
        s.write_all(&[5, 1, 2]).await.unwrap();
        let mut chosen = [0u8; 2];
        s.read_exact(&mut chosen).await.unwrap();
        let mut auth = vec![1, 5];
        auth.extend(b"alice");
        auth.push(6);
        auth.extend(b"secret");
        s.write_all(&auth).await.unwrap();
        let mut authed = [0u8; 2];
        s.read_exact(&mut authed).await.unwrap();
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(port.to_be_bytes());
        s.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        let code = match tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut reply))
            .await
            .expect("a reply in time")
        {
            Ok(_) => reply[1],
            Err(_) => 0xff,
        };
        (s, code)
    }
    let closed = |r: &ConnectionRecord| match r.kind {
        RecordKind::Closed(end) => end,
        _ => panic!("not closed: {:?}", r),
    };

    // Relayed, held open.
    let (mut held, code) = as_alice(socks, echo.port()).await;
    assert_eq!(code, 0);
    round_trip(&mut held, b"x").await;

    // A dial that fails.
    let (_s, code) = as_alice(socks, dead).await;
    assert_ne!(code, 0);
    let r = record(&mut events).await;
    assert_eq!(r.outcome, Some(Outcome::DialFailed), "{:?}", r);
    assert_eq!(
        closed(&r),
        End::Error(std::io::ErrorKind::ConnectionRefused)
    );
    assert_eq!(r.user.as_deref(), Some("alice"));
    assert_eq!(r.outbound.as_deref(), Some("direct"));
    assert_eq!((r.up_total, r.down_total), (0, 0));

    // A reject.
    let (_s, code) = as_alice(socks, rejected).await;
    assert_ne!(code, 0);
    let r = record(&mut events).await;
    assert_eq!(r.outcome, Some(Outcome::Blocked), "{:?}", r);
    assert_eq!(closed(&r), End::Closed(ClosedBy::Rules));
    assert_eq!(r.outbound, None);

    // Hijacked DNS, served until the client goes.
    let (s, _) = as_alice(socks, hijacked).await;
    drop(s);
    let r = record(&mut events).await;
    assert_eq!(r.outcome, Some(Outcome::Ok), "{:?}", r);
    assert_eq!(r.outbound, None);

    // Its user at its most connections.
    let mut one_tcp = UserLimits::default();
    one_tcp.max_tcp_connections = Some(1);
    instance.set_user_limits("alice", one_tcp).unwrap();
    let (_s, code) = as_alice(socks, echo.port()).await;
    assert_ne!(code, 0);
    let r = record(&mut events).await;
    assert_eq!(r.outcome, Some(Outcome::Rejected), "{:?}", r);
    assert_eq!(closed(&r), End::Closed(ClosedBy::User));
    assert_eq!(r.user.as_deref(), Some("alice"));

    // The one held, closed: relayed. And no record twice.
    drop(held);
    let r = record(&mut events).await;
    assert_eq!(r.outcome, Some(Outcome::Ok), "{:?}", r);
    assert_eq!(r.outbound.as_deref(), Some("direct"));
    assert_eq!((r.up_total, r.down_total), (1, 1));
    assert!(
        tokio::time::timeout(Duration::from_millis(500), events.next())
            .await
            .is_err(),
        "a connection had a second closed record"
    );
    instance.stop().await.unwrap();
}
