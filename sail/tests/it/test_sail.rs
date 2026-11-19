//! Sail/1 between sail instances (sail#60): streams share one TLS
//! connection, the server's padding scheme reaches the client, a user the
//! rules refuse and a target that refuses fail fast, a half-close
//! carries through, and UDP goes over the same session's streams.
//!
//! A counting TCP forwarder in front of the server shows the client's
//! connections to it.

#![cfg(all(
    feature = "inbound-sail",
    feature = "outbound-sail",
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
))]

#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use sail::session::{Session, SocksAddr};

/// The 32 bytes 0x5a and 0x33, as tokens.
const ALICE: &str = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo";
const BOB: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM";
/// A token no user has: 32 bytes of 0x11.
const NOBODY: &str = "ERERERERERERERERERERERERERERERERERERERERERE";

struct Certs {
    cert: String,
    key: String,
    _dir: common::TempDir,
}

fn certs(name: &str) -> anyhow::Result<Certs> {
    let dir = common::TempDir::new(&format!("sail-{}", name))?;
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    Ok(Certs {
        cert: common::json_path(&cert_path),
        key: common::json_path(&key_path),
        _dir: dir,
    })
}

/// A TCP forwarder to `target`, and the count of its connections.
async fn counting_forwarder(target: u16) -> anyhow::Result<(u16, Arc<AtomicUsize>)> {
    slow_forwarder(target, Duration::ZERO).await
}

/// A counting forwarder that holds each connection `delay` before it
/// forwards anything: a dial that takes that long.
async fn slow_forwarder(target: u16, delay: Duration) -> anyhow::Result<(u16, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                if let Ok(mut outbound) = TcpStream::connect(("127.0.0.1", target)).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    Ok((port, count))
}

fn session_to(addr: SocketAddr) -> Session {
    Session {
        destination: SocksAddr::from(addr),
        ..Default::default()
    }
}

/// Echoes `len` bytes through a new stream from the SOCKS server at
/// `socks_port`.
async fn echo_stream(
    socks_port: u16,
    echo: SocketAddr,
    seed: u8,
    len: usize,
) -> anyhow::Result<()> {
    let mut stream = timeout(
        Duration::from_secs(5),
        common::new_socks_stream("127.0.0.1", socks_port, &session_to(echo), None, None),
    )
    .await??;
    let data: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect();
    let (mut r, mut w) = tokio::io::split(&mut stream);
    let write = async {
        w.write_all(&data).await?;
        anyhow::Ok(())
    };
    let read = async {
        let mut back = vec![0u8; len];
        r.read_exact(&mut back).await?;
        anyhow::Ok(back)
    };
    let (written, back) =
        timeout(Duration::from_secs(10), async { tokio::join!(write, read) }).await?;
    written?;
    anyhow::ensure!(back? == data, "stream {} echoed something else", seed);
    Ok(())
}

/// Echoes a few packets through each of two UDP associations: UoT over
/// Sail/1 streams, each packet naming its address.
async fn echo_datagrams(socks_port: u16, echo: SocketAddr) -> anyhow::Result<()> {
    let sess = session_to(echo);
    for round in 0..2u8 {
        let dgram = timeout(
            Duration::from_secs(5),
            common::new_socks_datagram("127.0.0.1", socks_port, &sess, None, None),
        )
        .await??;
        let (mut r, mut s) = dgram.split();
        for i in 0..3u8 {
            let msg = vec![round * 16 + i; 100 + i as usize * 500];
            s.send_to(&msg, &sess.destination).await?;
            let mut buf = vec![0u8; 4096];
            let (n, from) = timeout(Duration::from_secs(5), r.recv_from(&mut buf))
                .await
                .map_err(|_| anyhow::anyhow!("udp round {} packet {}: no echo", round, i))??;
            anyhow::ensure!(buf[..n] == msg[..], "udp echo mismatch");
            anyhow::ensure!(from == sess.destination, "udp echo from {}", from);
        }
    }
    Ok(())
}

fn socks_to_sail(socks_port: u16, server_port: u16, token: &str, certs: &Certs) -> String {
    serde_json::json!({
        "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": socks_port }],
        "outbounds": [{
            "type": "sail",
            "server": "127.0.0.1",
            "server_port": server_port,
            "token": token,
            "tls": {
                "enabled": true,
                "server_name": "localhost",
                "certificate_path": certs.cert,
            }
        }]
    })
    .to_string()
}

/// A server that lets only `alice` through: the user's name has to reach
/// routing for anything to work.
fn sail_server(port: u16, certs: &Certs) -> String {
    serde_json::json!({
        "inbounds": [{
            "type": "sail",
            "listen": "127.0.0.1",
            "listen_port": port,
            "users": [
                { "name": "alice", "token": ALICE },
                { "name": "bob", "token": BOB }
            ],
            "padding_scheme": ["stop=4", "0=10-20", "1=200-300", "2=100-200,c,300-400", "3=50-60"],
            "tls": {
                "enabled": true,
                "certificate_path": certs.cert,
                "key_path": certs.key,
                "alpn": ["h2", "http/1.1"]
            }
        }],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" }
        ],
        "route": {
            "rules": [{ "auth_user": ["alice"], "outbound": "direct" }],
            "final": "block"
        }
    })
    .to_string()
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

/// A server that reads to its peer's FIN, then answers how much it read
/// and closes: only a half-close lets the answer come back.
async fn counting_server() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut all = Vec::new();
                if conn.read_to_end(&mut all).await.is_ok() {
                    let _ = conn.write_all(format!("{}", all.len()).as_bytes()).await;
                }
            });
        }
    });
    Ok(addr)
}

// app(socks) -> sail(sail) -> forwarder -> sail(sail, alice only) -> targets
#[test]
fn test_sail_to_sail() -> anyhow::Result<()> {
    let certs = certs("sail")?;
    common::retry_port_clash(|| {
        let [server, socks, nobody, bob, closed] = common::free_ports();
        let rt = runtime()?;
        let (forwarder, connections) = rt.block_on(counting_forwarder(server))?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                sail_server(server, &certs),
                socks_to_sail(socks, forwarder, ALICE, &certs),
                socks_to_sail(nobody, server, NOBODY, &certs),
                socks_to_sail(bob, server, BOB, &certs),
            ],
        )?;
        let result = rt.block_on(async {
            let (echo, echo_server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_server = tokio::spawn(echo_server);
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Sequential streams, then concurrent ones: one connection for
            // all of them, streams sharing it (6 concurrent stays below
            // STREAMS_PER_SESSION = 8 while the last sequential SOCKS stream
            // finishes closing).
            for i in 0..5u8 {
                echo_stream(socks, echo, i, 1000 + 40_000 * i as usize).await?;
            }
            let concurrent: Vec<_> = (0..6u8)
                .map(|i| tokio::spawn(echo_stream(socks, echo, 100 + i, 300_000)))
                .collect();
            for task in concurrent {
                task.await??;
            }
            anyhow::ensure!(
                connections.load(Ordering::SeqCst) == 1,
                "{} connections for 11 streams, not 1",
                connections.load(Ordering::SeqCst)
            );

            // A half-close reaches the target, and its answer comes back.
            let counter = counting_server().await?;
            let mut stream =
                common::new_socks_stream("127.0.0.1", socks, &session_to(counter), None, None)
                    .await?;
            stream.write_all(&[9u8; 70_000]).await?;
            stream.shutdown().await?;
            let mut answer = String::new();
            timeout(Duration::from_secs(5), stream.read_to_string(&mut answer)).await??;
            anyhow::ensure!(answer == "70000", "the target answered {:?}", answer);

            // A target that refuses: the stream fails at once, not when
            // some timeout is up.
            let start = Instant::now();
            let refused = SocketAddr::from(([127, 0, 0, 1], closed));
            let result = echo_stream(socks, refused, 1, 10).await;
            anyhow::ensure!(result.is_err(), "a refused target echoed");
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(3),
                "a refused target took {:?}",
                start.elapsed()
            );

            // A token no user has, and a user the rules do not let through.
            for port in [nobody, bob] {
                let result = echo_stream(port, echo, 1, 10).await;
                anyhow::ensure!(result.is_err(), "port {}: expected a failure", port);
            }
            // The refused stream did not take the session down.
            echo_stream(socks, echo, 7, 5000).await?;

            // UDP, over streams of the same session.
            let (udp_echo, udp_server) = common::run_udp_echo_server("127.0.0.1:0").await?;
            let udp_server = tokio::spawn(udp_server);
            let udp = echo_datagrams(socks, udp_echo).await;
            udp_server.abort();
            udp?;
            anyhow::ensure!(
                connections.load(Ordering::SeqCst) == 1,
                "UDP opened {} connections in all, not 1",
                connections.load(Ordering::SeqCst)
            );
            echo_server.abort();
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}

// A burst of streams on cold pools, each dial held 300 ms: 6 share one
// session's dial, and 20 three, with STREAMS_PER_SESSION at 8. Each burst
// through a client of its own.
#[test]
fn test_sail_cold_pool_shares_dials() -> anyhow::Result<()> {
    let certs = certs("sail-cold")?;
    common::retry_port_clash(|| {
        let [server, six, twenty] = common::free_ports();
        let rt = runtime()?;
        let (to6, count6) = rt.block_on(slow_forwarder(server, Duration::from_millis(300)))?;
        let (to20, count20) = rt.block_on(slow_forwarder(server, Duration::from_millis(300)))?;
        let ids = common::run_sail_instances(
            &rt,
            vec![
                sail_server(server, &certs),
                socks_to_sail(six, to6, ALICE, &certs),
                socks_to_sail(twenty, to20, ALICE, &certs),
            ],
        )?;
        let result = rt.block_on(async {
            let (echo, echo_server) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            let echo_server = tokio::spawn(echo_server);
            tokio::time::sleep(Duration::from_millis(200)).await;
            for (port, streams, count, want) in [(six, 6u8, &count6, 1), (twenty, 20, &count20, 3)]
            {
                let burst: Vec<_> = (0..streams)
                    .map(|i| tokio::spawn(echo_stream(port, echo, i, 20_000)))
                    .collect();
                for task in burst {
                    task.await??;
                }
                anyhow::ensure!(
                    count.load(Ordering::SeqCst) == want,
                    "{} streams at once on a cold pool: {} connections, not {}",
                    streams,
                    count.load(Ordering::SeqCst),
                    want
                );
            }
            echo_server.abort();
            anyhow::Ok(())
        });
        common::shutdown_instances(&rt, ids);
        result
    })
}
