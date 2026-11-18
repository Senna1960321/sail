//! sail embedded in a host that installed its own `tracing` subscriber
//! first: with `sail::embed::tracing_layer()` in it, each instance's log
//! gets its own lines, at its own level. A binary of its own: the global
//! subscriber is the process's.
#![cfg(all(feature = "outbound-direct", feature = "inbound-socks"))]
// Tests drive tasks of their own.
#![allow(clippy::disallowed_methods)]

use std::time::Duration;

use futures::StreamExt;
use sail::embed::{Config, Instance, LogFilter, Options, Threads};
use tracing_subscriber::layer::SubscriberExt;

fn config(port: u16, level: &str, tag: &str) -> String {
    serde_json::json!({
        "log": { "level": level },
        "inbounds": [{ "type": "socks", "tag": tag, "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
    })
    .to_string()
}

#[path = "../src/test_ports.rs"]
mod test_ports;
use test_ports::free_port;

/// The lines of `instance`'s log so far: those kept.
async fn lines(instance: &Instance) -> Vec<String> {
    let mut logs = Box::pin(instance.logs(LogFilter::default()));
    let first = tokio::time::timeout(Duration::from_secs(5), logs.next())
        .await
        .expect("the backlog at once")
        .expect("a first batch");
    first.lines.iter().map(|l| l.message.clone()).collect()
}

/// The host's subscriber, with sail's layer added: once for the process.
fn host_subscriber() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let subscriber = tracing_subscriber::registry().with(sail::embed::tracing_layer());
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_instance_gets_its_own_lines_under_the_hosts_subscriber() {
    host_subscriber();

    let (a_port, b_port) = (free_port(), free_port());
    let a = Instance::new(Options::new().threads(Threads::One)).unwrap();
    let b = Instance::new(Options::new().threads(Threads::One)).unwrap();
    a.start(Config::Json(config(a_port, "info", "in-a")))
        .await
        .unwrap();
    // b keeps warnings and errors only: its start's info lines are not
    // its.
    b.start(Config::Json(config(b_port, "warn", "in-b")))
        .await
        .unwrap();

    let (a_listens, b_listens) = (
        format!("listening tcp 127.0.0.1:{}", a_port),
        format!("listening tcp 127.0.0.1:{}", b_port),
    );
    // A line reaches an instance's log through the logger's worker, which
    // may not have written a's start line yet when the start returns: it
    // is waited for. b's, read after, has had as long.
    let a_lines = lines_until(&a, &a_listens).await;
    let b_lines = lines(&b).await;
    assert!(
        a_lines.iter().any(|l| l.contains(&a_listens)),
        "a logs its start: {:?}",
        a_lines
    );
    assert!(
        a_lines.iter().all(|l| !l.contains(&b_listens)),
        "none of b's lines in a's log: {:?}",
        a_lines
    );
    assert!(
        b_lines
            .iter()
            .all(|l| !l.contains(&a_listens) && !l.contains(&b_listens)),
        "b keeps no info line, and none of a's: {:?}",
        b_lines
    );

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}

/// The lines of `instance`'s log, until one has `wanted` or 5 s pass.
async fn lines_until(instance: &Instance, wanted: &str) -> Vec<String> {
    let mut logs = Box::pin(instance.logs(LogFilter::default()));
    let mut lines = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(batch) = logs.next().await {
            if batch.reset {
                lines.clear();
            }
            lines.extend(batch.lines.iter().map(|l| l.message.clone()));
            if lines.iter().any(|l| l.contains(wanted)) {
                break;
            }
        }
    })
    .await;
    lines
}

/// On the host's runtime, what an instance's tasks log on the host's
/// threads (a connection's line) is the instance's, and only its.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_the_hosts_runtime_each_instance_gets_its_tasks_lines() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    host_subscriber();
    let host = tokio::runtime::Handle::current();
    let on_host = || Options::new().runtime(sail::embed::Runtime::Host(host.clone()));
    let (a, b) = (
        Instance::new(on_host()).unwrap(),
        Instance::new(on_host()).unwrap(),
    );
    let (a_port, b_port) = (free_port(), free_port());
    a.start(Config::Json(config(a_port, "info", "in-a")))
        .await
        .unwrap();
    b.start(Config::Json(config(b_port, "info", "in-b")))
        .await
        .unwrap();

    // A connection through each, to a port that is a listener of the test.
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    for port in [a_port, b_port] {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeted = [0u8; 2];
        s.read_exact(&mut greeted).await.unwrap();
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend(target_port.to_be_bytes());
        s.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut reply))
            .await
            .expect("a SOCKS reply in time")
            .unwrap();
        assert_eq!(reply[1], 0, "connected");
        let _accepted = target.accept().await.unwrap();
    }

    let (in_a, in_b) = ("in=in-a", "in=in-b");
    let a_lines = lines_until(&a, in_a).await;
    assert!(
        a_lines.iter().any(|l| l.contains(in_a)) && a_lines.iter().all(|l| !l.contains(in_b)),
        "a has its connection's line, and none of b's: {:?}",
        a_lines
    );
    let b_lines = lines_until(&b, in_b).await;
    assert!(
        b_lines.iter().any(|l| l.contains(in_b)) && b_lines.iter().all(|l| !l.contains(in_a)),
        "b has its connection's line, and none of a's: {:?}",
        b_lines
    );

    a.stop().await.unwrap();
    b.stop().await.unwrap();
}
