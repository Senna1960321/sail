//! A host's own inbound and outbound kinds (`sail::embed`, Host kinds):
//! sessions a host inbound submits, many to one connection, are routed,
//! counted, limited and listed as a built-in inbound's are, and a host
//! outbound dials through sail's outbounds by tag.
//!
//! The host here, `mux-test`, multiplexes streams over one TCP connection:
//! after the client's `HELLO\n`, frames of a stream id (2 bytes), a kind
//! (open, data, close) and a length (2 bytes). An open's payload is the
//! stream's JSON header (user, destination, UDP or not, tenant); a UDP
//! stream carries datagrams each with a 2-byte length. `table-test` sends
//! each session where a table, swapped by the test, says for its tenant.
#![cfg(feature = "outbound-direct")]

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use futures::future::BoxFuture;
use sail::embed::{
    Accepted, Address, Config, DatagramRecv, DatagramSend, Datagrams, DomainSource, ErrorKind,
    Extensions, HostInbound, HostOutbound, HostStream, Instance, KindContext, NewSession, Options,
    Refused, SessionInfo, Threads, User, Via,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::common;

const OPEN: u8 = 0;
const DATA: u8 = 1;
const CLOSE: u8 = 2;

// ---------------------------------------------------------------- the mux

/// One end of the multiplexed connection: streams opened by either side,
/// each a duplex pipe pumped to and from frames.
struct Mux {
    out: mpsc::Sender<(u16, u8, Vec<u8>)>,
    streams: Streams,
}

type Spawn = fn(BoxFuture<'static, ()>);

/// Each open stream's way in, by id.
type Streams = Arc<Mutex<HashMap<u16, mpsc::Sender<Vec<u8>>>>>;

fn host_spawn(fut: BoxFuture<'static, ()>) {
    sail::embed::spawn("mux-test stream", fut);
}

fn test_spawn(fut: BoxFuture<'static, ()>) {
    tokio::spawn(fut);
}

impl Mux {
    /// Runs the connection; each stream the far side opens is handed to
    /// `opened` with its header.
    fn new<S>(conn: S, spawn: Spawn, opened: Option<mpsc::Sender<(Vec<u8>, DuplexStream)>>) -> Mux
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut r, mut w) = tokio::io::split(conn);
        let (out, mut frames) = mpsc::channel::<(u16, u8, Vec<u8>)>(64);
        spawn(Box::pin(async move {
            while let Some((id, kind, data)) = frames.recv().await {
                let mut f = Vec::with_capacity(5 + data.len());
                f.extend_from_slice(&id.to_be_bytes());
                f.push(kind);
                f.extend_from_slice(&(data.len() as u16).to_be_bytes());
                f.extend_from_slice(&data);
                if w.write_all(&f).await.is_err() {
                    break;
                }
            }
            let _ = w.shutdown().await;
        }));
        let streams: Streams = Arc::default();
        let mux = Mux {
            out: out.clone(),
            streams: streams.clone(),
        };
        spawn(Box::pin(async move {
            loop {
                let mut head = [0u8; 5];
                if r.read_exact(&mut head).await.is_err() {
                    break;
                }
                let id = u16::from_be_bytes([head[0], head[1]]);
                let mut data = vec![0u8; u16::from_be_bytes([head[3], head[4]]) as usize];
                if r.read_exact(&mut data).await.is_err() {
                    break;
                }
                match head[2] {
                    OPEN => {
                        let ours = pump(id, &out, &streams, spawn);
                        if let Some(opened) = &opened {
                            let _ = opened.send((data, ours)).await;
                        }
                    }
                    DATA => {
                        let to = streams.lock().unwrap().get(&id).cloned();
                        if let Some(to) = to {
                            let _ = to.send(data).await;
                        }
                    }
                    _ => {
                        streams.lock().unwrap().remove(&id);
                    }
                }
            }
            // The connection gone, every stream ends.
            streams.lock().unwrap().clear();
        }));
        mux
    }

    /// Opens stream `id` with `header`.
    async fn open(&self, id: u16, header: serde_json::Value) -> DuplexStream {
        let ours = pump(id, &self.out, &self.streams, test_spawn);
        self.out
            .send((id, OPEN, header.to_string().into_bytes()))
            .await
            .unwrap();
        ours
    }
}

/// The pipe of stream `id`: what is written to the end returned goes out
/// as its frames, and its frames come in to be read from it.
fn pump(
    id: u16,
    out: &mpsc::Sender<(u16, u8, Vec<u8>)>,
    streams: &Streams,
    spawn: Spawn,
) -> DuplexStream {
    let (theirs, ours) = tokio::io::duplex(64 * 1024);
    let (mut pr, mut pw) = tokio::io::split(theirs);
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    streams.lock().unwrap().insert(id, tx);
    spawn(Box::pin(async move {
        while let Some(data) = rx.recv().await {
            if pw.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = pw.shutdown().await;
    }));
    let out = out.clone();
    spawn(Box::pin(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match pr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out.send((id, DATA, buf[..n].to_vec())).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = out.send((id, CLOSE, Vec::new())).await;
    }));
    ours
}

// ---------------------------------------------------------------- the host

/// The tenant a stream's header names, which the inbound puts in the
/// session's extensions and `table-test` routes by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tenant(u32);

/// What `table-test` adds for the next host hop, `hop-test`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hop(u32);

/// The host's state, as a host keeps it: its users, by name, bound with
/// `Instance::user`; its routing table; what it saw.
#[derive(Default)]
struct HostState {
    users: Mutex<HashMap<String, User>>,
    table: Mutex<HashMap<u32, String>>,
    refused: Mutex<Vec<Refused>>,
    tenants: Mutex<Vec<u32>>,
    hops: Mutex<Vec<u32>>,
    /// The numbers its sessions were submitted as.
    submitted: Mutex<Vec<u64>>,
    /// What `table-test` was told of each session: its number, and the
    /// domain known for it and where from.
    seen: Mutex<Vec<Seen>>,
}

/// A session's number, and its domain and where from.
type Seen = (u64, Option<String>, Option<DomainSource>);

/// The state of each test's host, by the `host` field of its objects: the
/// tests run in parallel.
static HOSTS: LazyLock<Mutex<HashMap<String, Arc<HostState>>>> = LazyLock::new(Default::default);

fn host(name: &str) -> Arc<HostState> {
    HOSTS
        .lock()
        .unwrap()
        .entry(name.to_string())
        .or_default()
        .clone()
}

fn host_of(cx: &KindContext<'_>) -> Result<Arc<HostState>, String> {
    if cx.options.get("panic").and_then(|v| v.as_bool()) == Some(true) {
        panic!("a factory that panics");
    }
    let name = cx
        .options
        .get("host")
        .and_then(|v| v.as_str())
        .ok_or("no host")?;
    Ok(host(name))
}

struct MuxInbound(Arc<HostState>);

impl HostInbound for MuxInbound {
    fn serve(&self, mut conn: Accepted) -> BoxFuture<'static, io::Result<()>> {
        let state = self.0.clone();
        Box::pin(async move {
            let mut hello = [0u8; 6];
            conn.stream.read_exact(&mut hello).await?;
            if &hello == b"PANIC\n" {
                panic!("a connection's serve panics");
            }
            if &hello != b"HELLO\n" {
                return Err(io::Error::other("not a hello"));
            }
            conn.sessions.established();
            let (opened, mut streams) = mpsc::channel(16);
            let _mux = Mux::new(conn.stream, host_spawn, Some(opened));
            while let Some((header, stream)) = streams.recv().await {
                let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
                let destination = destination_of(&header);
                let mut new = NewSession::new(destination)
                    .extension(Tenant(header["tenant"].as_u64().unwrap_or(0) as u32));
                if let Some(name) = header["user"].as_str() {
                    let user = state.users.lock().unwrap().get(name).cloned();
                    new = new.user(user.expect("the test bound the user"));
                }
                let submitted = match header["udp"].as_bool() == Some(true) {
                    true => {
                        conn.sessions
                            .udp(new, framed_datagrams(stream, destination_of(&header)))
                            .await
                    }
                    // Refused, the stream is dropped, and the client reads its end.
                    false => conn.sessions.tcp(new, stream).await,
                };
                match submitted {
                    Ok(id) => state.submitted.lock().unwrap().push(id),
                    Err(refused) => state.refused.lock().unwrap().push(refused),
                }
            }
            Ok(())
        })
    }
}

/// The header's `dest`: an address, or a name and a port.
fn destination_of(header: &serde_json::Value) -> Address {
    let dest = header["dest"].as_str().unwrap();
    match dest.parse::<std::net::SocketAddr>() {
        Ok(to) => Address::from(to),
        Err(_) => {
            let (name, port) = dest.rsplit_once(':').unwrap();
            Address::Domain(name.to_string(), port.parse().unwrap())
        }
    }
}

/// A UDP stream of the mux as datagrams: each with its 2-byte length, all
/// to `to`.
fn framed_datagrams(stream: DuplexStream, to: Address) -> Datagrams {
    let (r, w) = tokio::io::split(stream);
    Datagrams {
        recv: Box::new(FramedRecv(r, to)),
        send: Box::new(FramedSend(w)),
    }
}

struct FramedRecv(tokio::io::ReadHalf<DuplexStream>, Address);
struct FramedSend(tokio::io::WriteHalf<DuplexStream>);

impl DatagramRecv for FramedRecv {
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, Address)>> {
        Box::pin(async move {
            let n = self.0.read_u16().await? as usize;
            self.0.read_exact(&mut buf[..n]).await?;
            Ok((n, self.1.clone()))
        })
    }
}

impl DatagramSend for FramedSend {
    fn send_to<'a>(
        &'a mut self,
        data: &'a [u8],
        _from: &'a Address,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.0.write_u16(data.len() as u16).await?;
            self.0.write_all(data).await
        })
    }
}

/// Routes by the tenant in the extensions, through the outbound the table
/// names; `hop:N` goes on to `hop-test` with `Hop(N)` added.
struct TableOutbound(Arc<HostState>);

impl TableOutbound {
    fn next(&self, session: &SessionInfo) -> io::Result<(String, SessionInfo)> {
        let Tenant(tenant) = *session
            .extensions
            .get::<Tenant>()
            .expect("the inbound's tenant");
        self.0.tenants.lock().unwrap().push(tenant);
        self.0.seen.lock().unwrap().push((
            session.id,
            session.domain.clone(),
            session.domain_source,
        ));
        if tenant == 99 {
            panic!("a dial that panics");
        }
        let tag = self.0.table.lock().unwrap().get(&tenant).cloned();
        let tag = tag.ok_or_else(|| io::Error::other("no route for the tenant"))?;
        match tag.strip_prefix("hop:") {
            Some(hop) => {
                let mut extensions: Extensions = session.extensions.clone();
                extensions.insert(Hop(hop.parse().unwrap()));
                Ok(("hop".into(), session.clone().with_extensions(extensions)))
            }
            None => Ok((tag, session.clone())),
        }
    }
}

impl HostOutbound for TableOutbound {
    fn stream<'a>(
        &'a self,
        session: &'a SessionInfo,
        via: &'a Via,
    ) -> BoxFuture<'a, io::Result<HostStream>> {
        Box::pin(async move {
            let (tag, next) = self.next(session)?;
            via.stream(&tag, &next).await
        })
    }

    fn datagrams<'a>(
        &'a self,
        session: &'a SessionInfo,
        via: &'a Via,
    ) -> BoxFuture<'a, io::Result<Datagrams>> {
        Box::pin(async move {
            let (tag, next) = self.next(session)?;
            via.datagrams(&tag, &next).await
        })
    }
}

/// The next host hop: reads the `Hop` the table added, and goes direct.
struct HopOutbound(Arc<HostState>);

impl HostOutbound for HopOutbound {
    fn stream<'a>(
        &'a self,
        session: &'a SessionInfo,
        via: &'a Via,
    ) -> BoxFuture<'a, io::Result<HostStream>> {
        Box::pin(async move {
            let Hop(hop) = *session.extensions.get::<Hop>().expect("the table's hop");
            self.0.hops.lock().unwrap().push(hop);
            via.stream("direct", session).await
        })
    }
}

fn options(settings: &[&str]) -> Options {
    let settings = serde_json::json!({ "set": settings }).to_string();
    Options::new()
        .threads(Threads::Workers(2, 2 << 20))
        .log_lines(200)
        .settings_json(&settings)
        .unwrap()
        .inbound_kind("mux-test", |cx| Ok(Arc::new(MuxInbound(host_of(cx)?))))
        .unwrap()
        .outbound_kind("table-test", |cx| Ok(Arc::new(TableOutbound(host_of(cx)?))))
        .unwrap()
        .outbound_kind("hop-test", |cx| Ok(Arc::new(HopOutbound(host_of(cx)?))))
        .unwrap()
}

fn config(name: &str, port: u16, users: &[&str], limits: serde_json::Value) -> String {
    let users: Vec<_> = users
        .iter()
        .map(|u| serde_json::json!({ "name": u }))
        .collect();
    serde_json::json!({
        "log": { "level": "debug" },
        "inbounds": [{
            "type": "mux-test", "tag": "mux-in", "host": name,
            "listen": "127.0.0.1", "listen_port": port, "users": users,
        }],
        "outbounds": [
            { "type": "table-test", "tag": "table", "host": name },
            { "type": "hop-test", "tag": "hop", "host": name },
            { "type": "direct", "tag": "direct" },
            { "type": "direct", "tag": "direct2", "tcp_fast_open": false },
        ],
        "route": { "final": "table" },
        "user_limits": limits,
    })
    .to_string()
}

/// Starts an instance whose host is `name`, binding the host's users.
async fn start(
    name: &str,
    settings: &[&str],
    users: &[&str],
    limits: serde_json::Value,
) -> (Instance, u16) {
    let instance = Instance::new(options(settings)).unwrap();
    let port = common::free_port();
    instance
        .start(Config::Json(config(name, port, users, limits)))
        .await
        .unwrap();
    let state = host(name);
    for user in users {
        state
            .users
            .lock()
            .unwrap()
            .insert(user.to_string(), instance.user(user).unwrap());
    }
    (instance, port)
}

async fn connect(port: u16) -> Mux {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    conn.write_all(b"HELLO\n").await.unwrap();
    Mux::new(conn, test_spawn, None)
}

fn header(user: &str, dest: std::net::SocketAddr, tenant: u32, udp: bool) -> serde_json::Value {
    serde_json::json!({ "user": user, "dest": dest.to_string(), "tenant": tenant, "udp": udp })
}

async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, what: &[u8]) {
    s.write_all(what).await.unwrap();
    let mut back = vec![0u8; what.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back))
        .await
        .expect("an echo in time")
        .unwrap();
    assert_eq!(back, what);
}

async fn datagram_round_trip(s: &mut DuplexStream, what: &[u8]) {
    s.write_u16(what.len() as u16).await.unwrap();
    s.write_all(what).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), s.read_u16())
        .await
        .expect("a datagram back in time")
        .unwrap() as usize;
    let mut back = vec![0u8; n];
    s.read_exact(&mut back).await.unwrap();
    assert_eq!(back, what);
}

/// Whether `s` is closed: it reads its end within a while.
async fn closed(s: &mut DuplexStream) -> bool {
    let mut buf = [0u8; 64];
    matches!(
        tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await,
        Ok(Ok(0)) | Ok(Err(_))
    )
}

async fn wait_until<F: Fn() -> bool>(what: &str, f: F) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{} did not happen", what);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_sessions_on_one_connection_are_routed_counted_and_listed() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let (udp_echo, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let name = "routed";
    let (instance, port) = start(name, &[], &["alice", "bob"], serde_json::json!({})).await;
    let state = host(name);
    state.table.lock().unwrap().extend([
        (1, "direct".to_string()),
        (2, "direct2".to_string()),
        (3, "hop:7".to_string()),
    ]);

    // Two TCP sessions and a UDP one on one connection.
    let mux = connect(port).await;
    let mut a = mux.open(1, header("alice", echo, 1, false)).await;
    let mut b = mux.open(2, header("bob", echo, 2, false)).await;
    let mut u = mux.open(3, header("alice", udp_echo, 1, true)).await;
    round_trip(&mut a, &[1u8; 3000]).await;
    round_trip(&mut b, &[2u8; 5000]).await;
    datagram_round_trip(&mut u, b"a datagram").await;

    let connections = instance.connections().await.unwrap();
    assert_eq!(connections.len(), 3, "{:?}", connections);
    for c in &connections {
        assert_eq!(c.inbound_tag, "mux-in");
        assert_eq!(c.inbound_type, "mux-test");
    }
    let of = |user: &str, network: sail::embed::Network| {
        connections
            .iter()
            .find(|c| c.user.as_deref() == Some(user) && c.network == network)
            .unwrap_or_else(|| panic!("{}'s {:?} session in {:?}", user, network, connections))
    };
    // The member the table took, the last first, then the outbound the
    // rules picked.
    assert_eq!(
        of("alice", sail::embed::Network::Tcp).chains,
        ["direct", "table"]
    );
    assert_eq!(
        of("bob", sail::embed::Network::Tcp).chains,
        ["direct2", "table"]
    );
    assert_eq!(
        of("alice", sail::embed::Network::Udp).chains,
        ["direct", "table"]
    );
    // What the inbound put in the extensions is what the outbound read.
    // (The sessions dial at once, in any order.)
    let mut tenants = state.tenants.lock().unwrap().clone();
    tenants.sort();
    assert_eq!(tenants, [1, 1, 2]);

    // The table swapped, no reload: the next session of tenant 1 goes the
    // other way, and one through two host hops carries what the first
    // added.
    state.table.lock().unwrap().insert(1, "direct2".to_string());
    let mut c = mux.open(4, header("alice", echo, 1, false)).await;
    round_trip(&mut c, b"swapped").await;
    let mut d = mux.open(5, header("bob", echo, 3, false)).await;
    round_trip(&mut d, b"two hops").await;
    assert_eq!(*state.hops.lock().unwrap(), [7]);
    let connections = instance.connections().await.unwrap();
    let chains: Vec<_> = connections.iter().map(|c| c.chains.clone()).collect();
    assert!(
        chains.contains(&vec!["direct2".to_string(), "table".to_string()]),
        "{:?}",
        chains
    );
    assert!(
        chains.contains(&vec![
            "direct".to_string(),
            "hop".to_string(),
            "table".to_string()
        ]),
        "{:?}",
        chains
    );

    // Closed, each session's bytes are its user's, once. (The UDP session
    // lasts its `udp_timeout`, as a UoT stream's does.)
    drop((a, b, u, c, d, mux));
    for _ in 0..100 {
        let connections = instance.connections().await.unwrap();
        if connections
            .iter()
            .all(|c| c.network != sail::embed::Network::Tcp)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(instance
        .connections()
        .await
        .unwrap()
        .iter()
        .all(|c| c.network != sail::embed::Network::Tcp));
    let manager = instance.manager().unwrap();
    let alice = manager.user("alice").unwrap().unwrap();
    let bob = manager.user("bob").unwrap().unwrap();
    assert_eq!(
        alice.traffic.up,
        3000 + "a datagram".len() as u64 + "swapped".len() as u64
    );
    assert_eq!(alice.traffic.down, alice.traffic.up);
    assert_eq!(bob.traffic.up, 5000 + "two hops".len() as u64);
    assert_eq!(bob.traffic.down, bob.traffic.up);
    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_users_are_limited_and_refused_as_any_inbounds_are() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let name = "limited";
    let limits = serde_json::json!({ "alice": { "max_connections": 1 } });
    let (instance, port) = start(name, &[], &["alice", "bob", "carol"], limits.clone()).await;
    let state = host(name);
    state.table.lock().unwrap().insert(1, "direct".to_string());

    // Alice's second session on the same connection is refused, her first
    // goes on.
    let mux = connect(port).await;
    let mut first = mux.open(1, header("alice", echo, 1, false)).await;
    round_trip(&mut first, b"first").await;
    let mut second = mux.open(2, header("alice", echo, 1, false)).await;
    assert!(closed(&mut second).await);
    round_trip(&mut first, b"still").await;
    wait_until("the refusal", || !state.refused.lock().unwrap().is_empty()).await;
    assert!(matches!(
        &state.refused.lock().unwrap()[0],
        Refused::User { name, .. } if name == "alice"
    ));

    // Disconnected, bob's sessions close, and the next is let in again.
    let mut bob = mux.open(3, header("bob", echo, 1, false)).await;
    round_trip(&mut bob, b"bob").await;
    assert_eq!(
        instance.manager().unwrap().disconnect_user("bob").unwrap(),
        1
    );
    assert!(closed(&mut bob).await);

    // A reload that keeps alice keeps her session and her handle; one that
    // takes carol out of the inbound closes hers and refuses her, clearly.
    let mut carol = mux.open(4, header("carol", echo, 1, false)).await;
    round_trip(&mut carol, b"carol").await;
    let report = instance
        .reload(Some(Config::Json(config(
            name,
            port,
            &["alice", "bob"],
            limits,
        ))))
        .await
        .unwrap();
    assert!(
        report.inbounds.iter().any(|(tag, change)| tag == "mux-in"
            && *change == sail::embed::InboundChange::Reloaded),
        "{:?}",
        report.inbounds
    );
    assert!(closed(&mut carol).await);
    round_trip(&mut first, b"kept").await;
    let mut again = mux.open(5, header("carol", echo, 1, false)).await;
    assert!(closed(&mut again).await);
    wait_until("carol's refusal", || {
        state.refused.lock().unwrap().len() == 2
    })
    .await;
    match &state.refused.lock().unwrap()[1] {
        Refused::User { name, reason } => {
            assert_eq!(name, "carol");
            assert!(
                reason.contains("taken out of the inbound [mux-in]"),
                "{}",
                reason
            );
        }
        other => panic!("{:?}", other),
    }
    // Her first session ended, she is let in again.
    drop(first);
    let manager = instance.manager().unwrap();
    wait_until("alice's first session ends", || {
        manager.user("alice").unwrap().unwrap().live == 0
    })
    .await;
    let mut alice = mux.open(6, header("alice", echo, 1, false)).await;
    round_trip(&mut alice, b"alice again").await;

    // A user of another run is refused.
    drop((alice, mux, manager));
    instance.stop().await.unwrap();
    let old = state.users.lock().unwrap().get("bob").cloned().unwrap();
    instance
        .start(Config::Json(config(
            name,
            port,
            &["alice", "bob"],
            serde_json::json!({}),
        )))
        .await
        .unwrap();
    state.users.lock().unwrap().insert("bob".into(), old);
    let mux = connect(port).await;
    let mut stale = mux.open(1, header("bob", echo, 1, false)).await;
    assert!(closed(&mut stale).await);
    wait_until("the stale user's refusal", || {
        state.refused.lock().unwrap().len() >= 3
    })
    .await;
    assert!(matches!(
        state.refused.lock().unwrap().last().unwrap(),
        Refused::User { reason, .. } if reason.contains("another instance")
    ));
    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_connection_holds_its_handshake_place_until_established() {
    let name = "handshakes";
    let (instance, port) = start(
        name,
        &["inbound.max_handshakes=1", "inbound.handshake_timeout=2s"],
        &[],
        serde_json::json!({}),
    )
    .await;
    // One in its handshake: the next is closed at once.
    let mut waiting = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut next = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), next.read(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{:?}", read);
    // Established, it gives the place back: another is let in, and stays.
    waiting.write_all(b"HELLO\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut third = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let read = tokio::time::timeout(Duration::from_secs(1), third.read(&mut buf)).await;
    assert!(
        read.is_err(),
        "the third is kept, waiting for its hello: {:?}",
        read
    );
    // One that never says hello is closed at the handshake timeout.
    let read = tokio::time::timeout(Duration::from_secs(4), third.read(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{:?}", read);
    // The established one is not.
    let read = tokio::time::timeout(Duration::from_millis(500), waiting.read(&mut buf)).await;
    assert!(read.is_err(), "{:?}", read);
    instance.stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_kinds_panic_ends_its_connection_alone() {
    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let name = "panics";
    let (instance, port) = start(name, &[], &["alice"], serde_json::json!({})).await;
    host(name)
        .table
        .lock()
        .unwrap()
        .insert(1, "direct".to_string());
    let faults = instance.faults().unwrap();

    // The serve of one connection.
    let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    conn.write_all(b"PANIC\n").await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf)).await;
    assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{:?}", read);
    // One dial.
    let mux = connect(port).await;
    let mut panics = mux.open(1, header("alice", echo, 99, false)).await;
    assert!(closed(&mut panics).await);
    wait_until("both faults", || instance.faults().unwrap() >= faults + 2).await;
    // The instance goes on, the connection too.
    let mut fine = mux.open(2, header("alice", echo, 1, false)).await;
    round_trip(&mut fine, b"fine").await;
    assert!(matches!(
        instance.state(),
        sail::embed::State::Running { .. }
    ));

    // Stopped with a session open, nothing is left.
    instance.stop().await.unwrap();
    let report = instance.stop_report().expect("a stop's report");
    assert!(report.tasks.is_empty(), "{:?}", report);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_kinds_are_registered_once_and_checked_as_sails_are() {
    let err = Options::new()
        .inbound_kind("vless", |cx| Ok(Arc::new(MuxInbound(host_of(cx)?))))
        .err()
        .expect("refused");
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    let err = Options::new()
        .outbound_kind("direct", |cx| Ok(Arc::new(TableOutbound(host_of(cx)?))))
        .err()
        .expect("refused");
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);
    let err = options(&[])
        .inbound_kind("mux-test", |cx| Ok(Arc::new(MuxInbound(host_of(cx)?))))
        .err()
        .expect("refused");
    assert_eq!(err.kind(), ErrorKind::InvalidArgument);

    let port = common::free_port();
    let text = config("checked", port, &["alice"], serde_json::json!({}));
    // check() knows the kinds; without them the type is unknown.
    sail::embed::check(&Config::Json(text.clone()), &options(&[])).unwrap();
    let unknown = Instance::new(Options::new().threads(Threads::One)).unwrap();
    let err = unknown.start(Config::Json(text.clone())).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Config);
    assert!(err.to_string().contains("unknown protocol"), "{}", err);

    // A factory's error and its panic are the start's, naming the tag.
    let mut failing: serde_json::Value = serde_json::from_str(&text).unwrap();
    failing["inbounds"][0]["host"] = serde_json::Value::Null;
    let instance = Instance::new(options(&[])).unwrap();
    let err = instance
        .start(Config::Json(failing.to_string()))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Config);
    assert!(
        err.to_string().contains("[mux-in] inbound: no host"),
        "{}",
        err
    );
    failing["inbounds"][0]["panic"] = serde_json::Value::Bool(true);
    let err = instance
        .start(Config::Json(failing.to_string()))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Config);
    assert!(err.to_string().contains("factory panicked"), "{}", err);
}

/// Each host session, one routed through `Via` and one through two host
/// hops, is one closed connection record (#14) with its user and its
/// bytes: no record of the connection that carries them, and none of the
/// dials through `Via`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_host_session_is_one_connection_record() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds, RecordKind};

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let name = "records";
    let (instance, port) = start(name, &[], &["alice", "bob"], serde_json::json!({})).await;
    host(name)
        .table
        .lock()
        .unwrap()
        .extend([(1, "direct".to_string()), (3, "hop:5".to_string())]);
    let mut events = Box::pin(instance.events(Kinds::CONNECTION));

    let mux = connect(port).await;
    let mut a = mux.open(1, header("alice", echo, 1, false)).await;
    let mut b = mux.open(2, header("bob", echo, 3, false)).await;
    round_trip(&mut a, &[1u8; 1234]).await;
    round_trip(&mut b, &[2u8; 777]).await;
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    assert!(closed(&mut a).await && closed(&mut b).await);

    let mut records = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(2), events.next()).await {
            Ok(Some(Event::ConnectionRecord(record))) => {
                if matches!(record.kind, RecordKind::Closed(_)) {
                    records.push(record);
                }
            }
            Ok(Some(_)) => {}
            // Nothing more for a while: every record is in.
            Ok(None) | Err(_) => break,
        }
    }
    assert_eq!(records.len(), 2, "{:?}", records);
    let of = |user: &str| {
        records
            .iter()
            .find(|r| r.user.as_deref() == Some(user))
            .unwrap_or_else(|| panic!("{}'s record in {:?}", user, records))
    };
    let alice = of("alice");
    assert_eq!((alice.up_total, alice.down_total), (1234, 1234));
    assert_eq!(alice.inbound, "mux-in");
    assert!(alice.chain.contains(&"direct".to_string()), "{:?}", alice);
    let bob = of("bob");
    assert_eq!((bob.up_total, bob.down_total), (777, 777));
    assert!(bob.chain.contains(&"hop".to_string()), "{:?}", bob);
    drop(mux);
    instance.stop().await.unwrap();
}

/// A host is told the number of each session, as its inbound submits it
/// and as its outbound is asked for it, and the domain known for it: the
/// destination's own, or one a `sniff` rule read. Each number is one closed
/// record's, the sessions the outbound refuses included, TCP and UDP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_knows_its_sessions_by_their_numbers_and_domains() {
    use futures::StreamExt;
    use sail::embed::{Event, Kinds, RecordKind};

    let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let (udp_echo, serve) = common::run_udp_echo_server("127.0.0.1:0").await.unwrap();
    tokio::spawn(serve);
    let name = "numbers";
    let state = host(name);
    state.table.lock().unwrap().insert(1, "direct".to_string());
    let instance = Instance::new(options(&[])).unwrap();
    let port = common::free_port();
    let mut config: serde_json::Value =
        serde_json::from_str(&config(name, port, &["alice"], serde_json::json!({}))).unwrap();
    config["route"]["rules"] = serde_json::json!([{ "action": "sniff", "timeout": "1s" }]);
    instance
        .start(Config::Json(config.to_string()))
        .await
        .unwrap();
    state
        .users
        .lock()
        .unwrap()
        .insert("alice".into(), instance.user("alice").unwrap());
    let mut events = Box::pin(instance.events(Kinds::CONNECTION));

    let mux = connect(port).await;
    // By address, nothing sniffed: no domain.
    let mut plain = mux.open(1, header("alice", echo, 1, false)).await;
    round_trip(&mut plain, b"plain").await;
    // By name: the destination's own.
    let named = serde_json::json!({
        "user": "alice", "dest": format!("localhost:{}", echo.port()), "tenant": 1,
    });
    let mut named = mux.open(2, named).await;
    round_trip(&mut named, b"named").await;
    // By address, a ClientHello first: what the sniff read.
    let mut sniffed = mux.open(3, header("alice", echo, 1, false)).await;
    round_trip(&mut sniffed, &common::client_hello("sni.test")).await;
    // Refused by the outbound, TCP and UDP: the tenant has no route.
    let mut refused = mux.open(4, header("alice", echo, 7, false)).await;
    assert!(closed(&mut refused).await);
    let mut udp = mux.open(5, header("alice", udp_echo, 7, true)).await;
    // Dispatched at its first datagram.
    udp.write_u16(4).await.unwrap();
    udp.write_all(b"ping").await.unwrap();
    for s in [&mut plain, &mut named, &mut sniffed] {
        s.shutdown().await.unwrap();
        assert!(closed(s).await);
    }
    wait_until("five submitted and seen", || {
        state.submitted.lock().unwrap().len() == 5 && state.seen.lock().unwrap().len() == 5
    })
    .await;

    // In the order the mux opened them, which submits them in turn.
    let submitted = state.submitted.lock().unwrap().clone();
    let seen: HashMap<_, _> = state
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|(id, domain, source)| (*id, (domain.clone(), *source)))
        .collect();
    let mut distinct = submitted.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), 5, "{:?}", submitted);
    let domains: Vec<_> = submitted
        .iter()
        .map(|id| {
            let (domain, source) = seen
                .get(id)
                .unwrap_or_else(|| panic!("{} in {:?}", id, seen));
            (domain.as_deref(), *source)
        })
        .collect();
    assert_eq!(
        domains,
        [
            (None, None),
            (Some("localhost"), Some(DomainSource::Request)),
            (Some("sni.test"), Some(DomainSource::Sniffed)),
            (None, None),
            (None, None),
        ]
    );

    // The UDP session refused ends as its last copy goes: its stream.
    drop(udp);
    let mut closed_records = HashMap::new();
    while closed_records.len() < 5 {
        let record = match tokio::time::timeout(Duration::from_secs(5), events.next()).await {
            Ok(Some(Event::ConnectionRecord(record))) => record,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        };
        if matches!(record.kind, RecordKind::Closed(_)) {
            assert!(
                closed_records.insert(record.id, record.clone()).is_none(),
                "two closed records of {}: {:?}",
                record.id,
                record
            );
        }
    }
    let mut recorded: Vec<_> = closed_records.keys().copied().collect();
    recorded.sort();
    assert_eq!(recorded, distinct, "{:?}", closed_records);
    for id in &submitted[3..] {
        let record = &closed_records[id];
        assert_eq!((record.up_total, record.down_total), (0, 0), "{:?}", record);
        assert_eq!(record.user.as_deref(), Some("alice"));
    }
    let sniffed = &closed_records[&submitted[2]];
    assert_eq!(sniffed.domain.as_deref(), Some("sni.test"));
    assert_eq!(sniffed.domain_source, Some(DomainSource::Sniffed));
    drop(mux);
    instance.stop().await.unwrap();
}
