//! Sessions a host submits with no listener (`Instance::sessions`), as a
//! host takes them off a link of its own: routed by the rules for their
//! inbound and user, dialled with the outbound's bind address, held to
//! their user's limits and rates, and recorded; and connections dialled
//! through an outbound (`dial_tcp`, `dial_udp`), the outbound's own, with
//! no relay between.
#![cfg(all(feature = "outbound-direct", feature = "inbound-socks"))]

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use futures::StreamExt;
use sail::embed::{
    Address, Config, ConnectionRecord, DatagramRecv, DatagramSend, Datagrams, ErrorKind, Event,
    HostOutbound, HostStream, Instance, Kinds, NewSession, Options, RecordKind, Refused,
    SessionInfo, Threads, Via,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::common;

/// What `seen-test` was asked for: each session's user, source, local
/// address, inbound and number.
type Seen = (Option<String>, SocketAddr, SocketAddr, String, u64);

static SEEN: LazyLock<Mutex<Vec<Seen>>> = LazyLock::new(Default::default);

/// Takes note of the session, and goes on through `bound`.
struct SeenOutbound;

impl HostOutbound for SeenOutbound {
    fn stream<'a>(
        &'a self,
        session: &'a SessionInfo,
        via: &'a Via,
    ) -> BoxFuture<'a, io::Result<HostStream>> {
        SEEN.lock().unwrap().push((
            session.user.clone(),
            session.source,
            session.local,
            session.inbound_tag.clone(),
            session.id,
        ));
        Box::pin(async move { via.stream("bound", session).await })
    }
}

fn seen(user: &str) -> Vec<Seen> {
    SEEN.lock()
        .unwrap()
        .iter()
        .filter(|s| s.0.as_deref() == Some(user))
        .cloned()
        .collect()
}

/// An instance whose sessions of `alice` go through `seen-test` and on
/// through `bound`, a direct with a bind address of its own, everyone
/// else's direct; `carol` may have one connection,
/// at 8 Mbps up.
async fn start() -> Instance {
    let options = Options::new()
        .threads(Threads::Workers(2, 2 << 20))
        .outbound_kind("seen-test", |_| Ok(Arc::new(SeenOutbound)))
        .unwrap();
    let instance = Instance::new(options).unwrap();
    // The users the host submits as: `user_limits` names users an inbound
    // has.
    let users: Vec<serde_json::Value> = ["alice", "bob", "carol", "dave"]
        .iter()
        .map(|u| serde_json::json!({ "username": u, "password": u }))
        .collect();
    let config = serde_json::json!({
        "log": { "level": "debug" },
        "inbounds": [{
            "type": "socks", "tag": "link",
            "listen": "127.0.0.1", "listen_port": common::free_port(),
            "users": users,
        }],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "seen-test", "tag": "seen" },
            { "type": "direct", "tag": "bound", "inet4_bind_address": "127.0.0.1" },
        ],
        "route": {
            "rules": [{ "auth_user": ["alice"], "outbound": "seen" }],
            "final": "direct",
        },
        "user_limits": { "carol": { "max_connections": 1, "up_mbps": 8 } },
    });
    instance
        .start(Config::Json(config.to_string()))
        .await
        .unwrap();
    instance
}

/// A server that writes each client the address it came from, and closes.
async fn peer_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, peer)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = s.write_all(peer.ip().to_string().as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

/// A server that reads each client to its end, and writes how many bytes.
async fn sink_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let mut n = 0u64;
                while let Ok(read) = s.read(&mut buf).await {
                    if read == 0 {
                        break;
                    }
                    n += read as u64;
                }
                let _ = s.write_all(n.to_string().as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

async fn read_all<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> String {
    let mut back = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut back))
        .await
        .expect("an answer in time")
        .unwrap();
    String::from_utf8(back).unwrap()
}

/// The closed record of the connection `id`.
async fn closed_record(
    events: &mut (impl futures::Stream<Item = Event> + Unpin),
    id: u64,
) -> Arc<ConnectionRecord> {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), events.next()).await {
            Ok(Some(Event::ConnectionRecord(record)))
                if record.id == id && matches!(record.kind, RecordKind::Closed(_)) =>
            {
                return record;
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => panic!("no closed record of {}", id),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_submits_a_users_stream_with_no_listener() {
    let instance = start().await;
    let peer = peer_server().await;
    let mut events = Box::pin(instance.events(Kinds::CONNECTION));
    let sessions = instance.sessions("link").unwrap();
    let source: SocketAddr = "10.0.0.7:4000".parse().unwrap();
    let local: SocketAddr = "10.0.0.1:443".parse().unwrap();

    // Alice's goes where the rule sends her, from the outbound's address.
    let (mut client, ours) = tokio::io::duplex(64 * 1024);
    let new = NewSession::new(Address::from(peer))
        .user(instance.user("alice").unwrap())
        .source(source)
        .local(local);
    let id = sessions.tcp(new, ours).await.unwrap();
    assert_eq!(read_all(&mut client).await, "127.0.0.1");
    // The host closes its end, and the session ends.
    drop(client);
    assert_eq!(
        seen("alice"),
        vec![(Some("alice".into()), source, local, "link".into(), id)]
    );
    let record = closed_record(&mut events, id).await;
    assert_eq!(record.user.as_deref(), Some("alice"));
    assert_eq!(record.inbound, "link");
    assert_eq!(record.source, source);
    // The rule's outbound, and the one it went on through; a loopback
    // destination is reached from loopback whatever the bind
    // (net/dial.rs), so the bind itself is the dialer's tests'.
    assert!(record.chain.contains(&"seen".to_string()), "{:?}", record);
    assert!(record.chain.contains(&"bound".to_string()), "{:?}", record);
    assert_eq!(record.down_total, "127.0.0.1".len() as u64);
    assert_eq!(record.local, local);

    // Bob's, no rule for him, goes direct.
    let (mut client, ours) = tokio::io::duplex(64 * 1024);
    let new = NewSession::new(Address::from(peer)).user(instance.user("bob").unwrap());
    let id = sessions.tcp(new, ours).await.unwrap();
    assert_eq!(read_all(&mut client).await, "127.0.0.1");
    // The host closes its end, and the session ends.
    drop(client);
    assert!(seen("bob").is_empty());
    let record = closed_record(&mut events, id).await;
    assert_eq!(record.chain, vec!["direct".to_string()]);

    // Each session's bytes were copied once: by its own task, with no
    // relay between the host's stream and the outbound's.
    let tasks = instance.tasks().unwrap();
    assert!(
        !tasks.iter().any(|(name, _)| name.starts_with("dial ")),
        "{:?}",
        tasks
    );
    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_session_is_held_to_its_users_limits_and_rate() {
    let instance = start().await;
    let sink = sink_server().await;
    let sessions = instance.sessions("link").unwrap();
    let carol = instance.user("carol").unwrap();

    let (mut first, ours) = tokio::io::duplex(64 * 1024);
    let id = sessions
        .tcp(
            NewSession::new(Address::from(sink)).user(carol.clone()),
            ours,
        )
        .await
        .unwrap();
    // Once it is counted, a second is one too many.
    for _ in 0..100 {
        let connections = instance.connections().await.unwrap();
        if connections.iter().any(|c| c.id == id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (_second, ours) = tokio::io::duplex(1024);
    let refused = sessions
        .tcp(
            NewSession::new(Address::from(sink)).user(carol.clone()),
            ours,
        )
        .await;
    assert!(
        matches!(refused, Err(Refused::User { ref name, .. }) if name == "carol"),
        "{:?}",
        refused
    );

    // 2 MB up at 8 Mbps, 1 MB/s, takes about 2 s.
    let upload = vec![7u8; 2 << 20];
    let started = Instant::now();
    first.write_all(&upload).await.unwrap();
    first.shutdown().await.unwrap();
    assert_eq!(read_all(&mut first).await, upload.len().to_string());
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(1200), "{:?}", took);
    instance.stop().await.unwrap();
}

/// Datagrams of a host's, each to and from one address.
struct Channel {
    to: Address,
    from_host: mpsc::Receiver<Vec<u8>>,
}

struct Back(mpsc::Sender<Vec<u8>>);

impl DatagramRecv for Channel {
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, Address)>> {
        Box::pin(async move {
            let data = self
                .from_host
                .recv()
                .await
                .ok_or(io::ErrorKind::BrokenPipe)?;
            buf[..data.len()].copy_from_slice(&data);
            Ok((data.len(), self.to.clone()))
        })
    }
}

impl DatagramSend for Back {
    fn send_to<'a>(
        &'a mut self,
        data: &'a [u8],
        _from: &'a Address,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.0
                .send(data.to_vec())
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_submits_a_users_datagrams_with_no_listener() {
    let instance = start().await;
    let (echo, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let sessions = instance.sessions("link").unwrap();

    let (to_sail, from_host) = mpsc::channel(8);
    let (back, mut from_sail) = mpsc::channel(8);
    let datagrams = Datagrams {
        recv: Box::new(Channel {
            to: Address::from(echo),
            from_host,
        }),
        send: Box::new(Back(back)),
    };
    let new = NewSession::new(Address::from(echo)).user(instance.user("dave").unwrap());
    let id = sessions.udp(new, datagrams).await.unwrap();
    for what in [&b"one"[..], &b"two two"[..]] {
        to_sail.send(what.to_vec()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), from_sail.recv())
            .await
            .expect("a datagram back in time")
            .unwrap();
        assert_eq!(got, what);
    }
    // Listed as the inbound's and the user's, by its number, until its NAT
    // session times out.
    let connections = instance.connections().await.unwrap();
    let listed = connections
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("{} in {:?}", id, connections));
    assert_eq!(listed.user.as_deref(), Some("dave"));
    assert_eq!(listed.inbound_tag, "link");
    assert_eq!((listed.upload, listed.download), (10, 10));
    drop(to_sail);
    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_need_an_inbound_and_a_running_instance() {
    let instance = start().await;
    let err = instance.sessions("nowhere").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound, "{}", err);
    let sessions = instance.sessions("link").unwrap();
    instance.stop().await.unwrap();
    let (_client, ours) = tokio::io::duplex(1024);
    let refused = sessions
        .tcp(
            NewSession::new(Address::from(SocketAddr::from(([127, 0, 0, 1], 9)))),
            ours,
        )
        .await;
    assert_eq!(refused, Err(Refused::Closed));
    assert!(instance.sessions("link").is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dialled_stream_is_the_outbounds_own() {
    let instance = start().await;
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let mut stream = instance
        .dial_tcp("direct", Address::from(echo), Duration::from_secs(5))
        .await
        .unwrap();
    let tasks = instance.tasks().unwrap();
    assert!(
        !tasks.iter().any(|(name, _)| name.starts_with("dial ")),
        "{:?}",
        tasks
    );
    // Read and written from a thread of no runtime's, on an executor of
    // its own.
    let stream = std::thread::spawn(move || {
        futures::executor::block_on(async {
            stream.write_all(b"hello").await.unwrap();
            let mut back = [0u8; 5];
            stream.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"hello");
        });
        stream
    })
    .join()
    .unwrap();
    // Once the instance stops, it fails or ends.
    let mut stream = stream;
    instance.stop().await.unwrap();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("the stream ends as the instance stops");
    assert!(matches!(read, Ok(0) | Err(_)), "{:?}", read);
    drop(stream);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialled_datagrams_are_the_outbounds_own() {
    let instance = start().await;
    let (echo, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let datagrams = instance
        .dial_udp("direct", Address::from(echo), Duration::from_secs(5))
        .await
        .unwrap();
    let tasks = instance.tasks().unwrap();
    assert!(
        !tasks.iter().any(|(name, _)| name.starts_with("dial ")),
        "{:?}",
        tasks
    );
    let mut buf = vec![0u8; 65_535];
    for what in [&b"one"[..], &b"three"[..]] {
        datagrams.send(what).await.unwrap();
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), datagrams.recv_from(&mut buf))
            .await
            .expect("a datagram back in time")
            .unwrap();
        assert_eq!(&buf[..n], what);
        assert_eq!(from, Address::from(echo));
    }
    drop(datagrams);
    // Its close runs on the instance's runtime, and the stop is clean.
    instance.stop().await.unwrap();
    let report = instance.stop_report().expect("a report after a stop");
    assert!(report.clean(), "{:?}", report);
}
