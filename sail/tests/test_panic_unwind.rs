//! A contained panic in a build that unwinds, as the mobile libraries are
//! (the dist-mobile profile): the task alone ends, the instance and the
//! host go on, on sail's runtime and on the host's. CI runs it built with that profile (`--profile dist-mobile`);
//! any profile that unwinds runs it the same.
#![cfg(all(
    feature = "fault-injection",
    feature = "inbound-socks",
    feature = "outbound-direct"
))]
// Tests drive tasks of their own.
#![allow(clippy::disallowed_methods)]

use std::time::Duration;

use futures::StreamExt;
use sail::embed::{Config, Event, Instance, Kinds, Options, Runtime, State, Threads};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "../src/test_ports.rs"]
mod test_ports;
use test_ports::free_port;

fn config(port: u16) -> String {
    serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "final": "direct" },
    })
    .to_string()
}

/// A SOCKS5 connection through `port` to `target`, an echo round trip.
async fn echo_through(port: u16, target: std::net::SocketAddr) {
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeted = [0u8; 2];
    s.read_exact(&mut greeted).await.unwrap();
    let std::net::SocketAddr::V4(v4) = target else {
        unreachable!("the echo listens on 127.0.0.1")
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend(v4.ip().octets());
    request.extend(v4.port().to_be_bytes());
    s.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "connected");
    s.write_all(b"x").await.unwrap();
    let mut back = [0u8; 1];
    s.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"x");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contained_panic_leaves_the_host_and_the_instance_running() {
    contained_panic(Options::new().threads(Threads::One)).await;
}

/// The same on the host's runtime: the instance's tasks are on it, and so
/// is the host's own task, which goes on through the panic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contained_panic_on_the_hosts_runtime_leaves_it_running() {
    let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ticking = ticks.clone();
    let host_task = tokio::spawn(async move {
        loop {
            ticking.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    contained_panic(Options::new().runtime(Runtime::Host(tokio::runtime::Handle::current()))).await;
    let after = ticks.load(std::sync::atomic::Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        ticks.load(std::sync::atomic::Ordering::Relaxed) > after,
        "the host's task goes on"
    );
    assert!(!host_task.is_finished());
    host_task.abort();
}

/// The fault points are the process's: one test arms one at a time.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn contained_panic(options: Options) {
    // A constant of the build's profile: what this test is to be run in.
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(sail::embed::PANICS_ARE_CAUGHT, "this build unwinds");
    }
    let _one = ONE_AT_A_TIME.lock().await;
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let instance = Instance::new(options.log_lines(100)).unwrap();
    let mut faults = Box::pin(instance.events(Kinds::FAULT));
    let mut port = 0;
    for _ in 0..5 {
        port = free_port();
        if instance.start(Config::Json(config(port))).await.is_ok() {
            break;
        }
    }
    assert!(matches!(instance.state(), State::Running { .. }));

    // The next connection's task panics.
    sail::fault::arm(sail::fault::Point::ContainedTask);
    let _panicking = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    // The events, subscribed before the start, are first polled after the
    // fault: it is told all the same.
    tokio::time::timeout(Duration::from_secs(10), async {
        while instance.faults().unwrap() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the task panics");
    let fault = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match faults.next().await {
                Some(Event::Fault(fault)) => return fault,
                Some(_) => continue,
                None => panic!("the events ended"),
            }
        }
    })
    .await
    .expect("the fault is told");
    assert_eq!(fault.task, "inbound tcp");
    assert_eq!(fault.count, 1);

    // The instance goes on, and so does this process, the host.
    assert!(matches!(instance.state(), State::Running { .. }));
    assert_eq!(instance.faults().unwrap(), 1);
    echo_through(port, target).await;
    instance.stop().await.unwrap();
}
