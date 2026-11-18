//! A hundred instances in one process, on sail's runtimes and then on the
//! host's: started and stopped one after another, then ten at a time, each
//! carrying a connection. After them the process is as before: no task
//! left on the host's runtime, no file, no thread, no runtime id, no heap.
//! A binary of its own: it counts the process's threads, files and heap.
//!
//! The heap is counted by this binary's allocator, not read from RSS: with
//! ten runtimes at once, glibc keeps a heap arena for each of their threads,
//! and RSS grows by hundreds of MB that it never returns, while the bytes
//! alive stay where they were.
#![cfg(all(
    target_os = "linux",
    feature = "inbound-socks",
    feature = "outbound-direct"
))]
// Tests drive tasks of their own.
#![allow(clippy::disallowed_methods)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::{Duration, Instant};

use sail::embed::{Config, Instance, Options, Runtime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The system's allocator, counting the bytes alive.
struct Counting;

static ALIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        ALIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALIVE.fetch_add(
            new_size as isize - layout.size() as isize,
            Ordering::Relaxed,
        );
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// Instances started and stopped one after another.
const ONE_BY_ONE: usize = 100;
/// Rounds of instances at once, and how many in each.
const ROUNDS: usize = 10;
const AT_ONCE: usize = 10;
/// A stop's bound (the design's).
const STOP_WITHIN: Duration = Duration::from_secs(2);
/// How many more heap bytes may be alive after the runs than after the
/// first round. Measured over 1000 runs: 3 to 4 KiB more, reached in the
/// first passes and level after (queues grown to their highest keep their
/// capacity), once 19 KiB when a single run was the base; 320 bytes left
/// by each of the 200 runs here would fail it.
const HEAP_SLACK: isize = 64 * 1024;
/// How long whatever ends just after a stop (a task's last drop, a worker
/// thread's exit, an idle blocking thread) has to end.
const SETTLE: Duration = Duration::from_secs(10);

fn config(port: u16) -> String {
    serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "final": "direct" },
    })
    .to_string()
}

#[path = "../src/test_ports.rs"]
mod test_ports;
use test_ports::free_port;

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

/// One instance's life: started, a connection through it, stopped within
/// the bound with nothing left, dropped.
async fn one_run(options: Options, target: std::net::SocketAddr) {
    let instance = Instance::new(options).unwrap();
    let mut port = 0;
    let mut started = Err(None);
    for _ in 0..5 {
        port = free_port();
        match instance.start(Config::Json(config(port))).await {
            Ok(()) => {
                started = Ok(());
                break;
            }
            Err(e) => started = Err(Some(e)),
        }
    }
    started.expect("the instance starts");
    echo_through(port, target).await;
    let asked = Instant::now();
    instance.stop().await.expect("the stop is Ok");
    let took = asked.elapsed();
    assert!(took < STOP_WITHIN, "the stop took {took:?}");
    let report = instance.stop_report().expect("a report after a stop");
    assert!(report.clean(), "{report:?}");
}

fn count_dir(dir: &str) -> usize {
    std::fs::read_dir(dir).unwrap().count()
}

fn rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|kb| kb.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmRSS")
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Held {
    tasks: usize,
    fds: usize,
    threads: usize,
    heap: isize,
    ids: usize,
    runtimes: usize,
}

fn held(host: &tokio::runtime::Handle) -> Held {
    Held {
        tasks: host.metrics().num_alive_tasks(),
        fds: count_dir("/proc/self/fd"),
        threads: count_dir("/proc/self/task"),
        heap: ALIVE.load(Ordering::Relaxed),
        ids: sail::embed::ids_held(),
        runtimes: sail::runtime_managers().len(),
    }
}

/// What the process holds once whatever ends just after a stop has ended:
/// the first time it is no more than `before`, or the last seen.
async fn settled(host: &tokio::runtime::Handle, before: Held) -> Held {
    let deadline = Instant::now() + SETTLE;
    loop {
        let now = held(host);
        let back = now.tasks <= before.tasks
            && now.fds <= before.fds
            && now.threads <= before.threads
            && now.heap <= before.heap + HEAP_SLACK
            && now.ids == 0
            && now.runtimes == 0;
        if back || Instant::now() > deadline {
            return now;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The hundred runs on `options`' runtime, the process checked after them
/// against what it held after the first.
async fn hundred(options: impl Fn() -> Options) {
    let host = tokio::runtime::Handle::current();
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo.local_addr().unwrap();
    let serving = tokio::spawn(async move {
        while let Ok((mut s, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    // The first runs start what lives as long as the process (the
    // logger's worker, lazy statics) and grow its queues as ten at once do:
    // what is held after them is the base, once the host's idle blocking
    // threads have gone.
    one_run(options(), target).await;
    futures::future::join_all((0..AT_ONCE).map(|_| one_run(options(), target))).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = held(&host);
    assert_eq!((before.ids, before.runtimes), (0, 0), "{before:?}");
    let rss_before = rss_kb();

    for _ in 0..ONE_BY_ONE {
        one_run(options(), target).await;
    }
    for _ in 0..ROUNDS {
        futures::future::join_all((0..AT_ONCE).map(|_| one_run(options(), target))).await;
    }

    let after = settled(&host, before).await;
    let rss_after = rss_kb();
    eprintln!("held before {before:?}, after {after:?}; RSS {rss_before} kB, then {rss_after} kB");
    assert_eq!(after.ids, 0, "runtime ids held: {after:?}");
    assert_eq!(after.runtimes, 0, "runtimes registered: {after:?}");
    assert!(
        after.tasks <= before.tasks,
        "tasks left on the host's runtime: {before:?} -> {after:?}"
    );
    assert!(
        after.fds <= before.fds,
        "files left open: {before:?} -> {after:?}"
    );
    assert!(
        after.threads <= before.threads,
        "threads left: {before:?} -> {after:?}"
    );
    assert!(
        after.heap <= before.heap + HEAP_SLACK,
        "heap left: {before:?} -> {after:?}"
    );
    serving.abort();
}

/// The host's runtime. Its idle blocking threads go within the settling
/// time, not tokio's default 10 s, so that they are not counted as left.
fn host_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_keep_alive(Duration::from_millis(500))
        .enable_all()
        .build()
        .unwrap()
}

/// One test, so that no other test's threads or files are counted: on
/// sail's runtimes first, then on the host's.
#[test]
fn a_hundred_instances_leave_the_process_as_it_was() {
    let host = host_runtime();
    host.block_on(hundred(Options::new));
    let handle = host.handle().clone();
    host.block_on(hundred(|| {
        Options::new().runtime(Runtime::Host(handle.clone()))
    }));
}
