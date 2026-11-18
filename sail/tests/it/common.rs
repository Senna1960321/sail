#![allow(dead_code)]

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::future::abortable;

use rand::RngCore;
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tracing::info;

use sail::adapter::*;
use sail::session::Session;

/// The runtime IDs the harness hands out begin here, far from the others
/// of a test binary: `sail::embed` gives its instances the lowest free ID
/// from 1 up, and a few tests start an instance under an ID of their own
/// choosing, in the hundreds. Counted from 0, the harness met both: an
/// instance made by `sail::embed` holds its ID before it starts, when the
/// harness cannot see it is taken.
pub const FIRST_RT_ID: u16 = 30_000;

/// The runtime IDs tests of this binary choose themselves, each for a test
/// whose subject is the start or the ID itself and that cannot take the
/// harness's. All of them are here and nowhere else: `test_harness` checks
/// that no two are equal, that none is the harness's to hand out, and
/// that no test file names an ID of its own.
pub mod fixed_rt_id {
    use sail::RuntimeId;

    /// `test_inbound_resources`: this and the four after it.
    pub const INBOUND_RESOURCES: RuntimeId = 950;
    pub const LIFECYCLE_STOPPED_STARTING: RuntimeId = 1001;
    pub const LIFECYCLE_TAKEN_TWICE: RuntimeId = 1002;
    pub const LIFECYCLE_RELOADING: RuntimeId = 1003;
    pub const LIFECYCLE_BYSTANDER: RuntimeId = 1004;
    pub const LIFECYCLE_LOGGED_A: RuntimeId = 1005;
    pub const LIFECYCLE_LOGGED_B: RuntimeId = 1006;
    pub const LIFECYCLE_NO_MODES: RuntimeId = 1007;

    pub const ALL: &[RuntimeId] = &[
        INBOUND_RESOURCES,
        INBOUND_RESOURCES + 1,
        INBOUND_RESOURCES + 2,
        INBOUND_RESOURCES + 3,
        INBOUND_RESOURCES + 4,
        LIFECYCLE_STOPPED_STARTING,
        LIFECYCLE_TAKEN_TWICE,
        LIFECYCLE_RELOADING,
        LIFECYCLE_BYSTANDER,
        LIFECYCLE_LOGGED_A,
        LIFECYCLE_LOGGED_B,
        LIFECYCLE_NO_MODES,
    ];
}

static NEXT_RT_ID: AtomicU16 = AtomicU16::new(FIRST_RT_ID);

/// `path` as it goes into a configuration written as JSON text: with `/`
/// for separators, which Windows takes too, so that a `\` is not read as
/// an escape.
pub fn json_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// A runtime ID no other instance of the tests has.
pub fn next_rt_id() -> sail::RuntimeId {
    NEXT_RT_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Ports and files
//
// Tests never use fixed ports or paths, so that any number of test binaries,
// and whole suites in other checkouts, can run at the same time.
// ---------------------------------------------------------------------------

/// The scope of what a test drives directly, without an instance: what
/// sail's parts spawn goes into a scope, as an instance's does.
pub fn test_scope() -> sail::runtime::scope::TaskScope {
    static SCOPE: std::sync::OnceLock<sail::runtime::scope::TaskScope> = std::sync::OnceLock::new();
    SCOPE.get_or_init(Default::default).clone()
}

/// `fut`, run in the tests' scope (`test_scope`).
pub fn scoped<F: std::future::Future>(fut: F) -> impl std::future::Future<Output = F::Output> {
    test_scope().enter(fut)
}

/// The ports `free_port` hands out: below every range a system gives the
/// sockets that ask for no port, so that none of the connections the tests
/// themselves make, thousands in a run, is given one of them between its
/// being handed out and its being bound. Linux gives 32768 and up unless
/// told otherwise (what it was told is read), macOS and Windows 49152 and
/// up, as IANA has it.
fn handed_out_ports() -> std::ops::Range<u16> {
    const FROM: u16 = 10_000;
    // Lowered on Linux only.
    #[allow(unused_mut)]
    let mut below = 32_768;
    #[cfg(target_os = "linux")]
    if let Some(low) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse::<u16>().ok())
    {
        // A host whose own range leaves too little room below it: the
        // room above 10000 is used all the same, as it was before.
        if low >= FROM + 5_000 {
            below = below.min(low);
        }
    }
    FROM..below
}

/// What `read` gives once it is `expected`, or after 5 s what it gives
/// then, for the caller to assert on. A connection's byte counts are taken
/// after the write that sent the bytes returned: the answer to them can
/// reach the client, and be counted down, while the thread that sent them
/// has yet to count them up. A count read just after an echo trails by
/// that much, and converges.
pub async fn settled<T, F, Fut>(expected: T, mut read: F) -> T
where
    T: PartialEq,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let got = read().await;
        if got == expected || tokio::time::Instant::now() >= deadline {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A port on 127.0.0.1 that is free for both TCP and UDP, as sail inbounds
/// bind both on the port they are given. It is taken from
/// `handed_out_ports`, in turn from where this process began, which
/// differs between processes; no port is handed out twice in one process.
///
/// The port is free when returned, but not held: another process may take
/// it before the test binds it, by asking for that very port, as another
/// test binary run at the same time would. `retry_port_clash` covers that.
pub fn free_port() -> u16 {
    static TAKEN: std::sync::Mutex<Option<std::collections::HashSet<u16>>> =
        std::sync::Mutex::new(None);
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let ports = handed_out_ports();
    let count = usize::from(ports.end - ports.start);
    // Where this process begins: far from where another does, most often.
    let first = (std::process::id() as usize).wrapping_mul(7919);
    for _ in 0..count {
        let turn = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = ports.start + (first.wrapping_add(turn) % count) as u16;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_err()
            || std::net::UdpSocket::bind(("127.0.0.1", port)).is_err()
        {
            continue;
        }
        let mut taken = TAKEN.lock().unwrap_or_else(|e| e.into_inner());
        if taken.get_or_insert_with(Default::default).insert(port) {
            return port;
        }
    }
    panic!("no free port on 127.0.0.1");
}

/// `N` distinct free ports.
pub fn free_ports<const N: usize>() -> [u16; N] {
    std::array::from_fn(|_| free_port())
}

/// Whether `e` says an address was in use: a port from `free_port` that
/// someone else took before the test bound it.
pub fn is_port_clash(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::AddrInUse {
                return true;
            }
        }
        let message = cause.to_string().to_ascii_lowercase();
        message.contains("address already in use")
            || message.contains("address in use")
            || message.contains("os error 10048")
    })
}

/// Runs `f` until it does not fail for a port clash, a few times at most.
/// `f` takes its ports from `free_port`, so that each try has new ones.
pub fn retry_port_clash<T>(mut f: impl FnMut() -> anyhow::Result<T>) -> anyhow::Result<T> {
    const TRIES: usize = 5;
    for attempt in 1.. {
        match f() {
            Err(e) if attempt < TRIES && is_port_clash(&e) => {
                tracing::warn!("port clash, retrying with new ports: {:#}", e);
            }
            result => return result,
        }
    }
    unreachable!()
}

/// A directory of its own under the system's temporary directory, removed
/// with everything in it when dropped.
pub struct TempDir(std::path::PathBuf);

impl TempDir {
    /// A new directory, its name starting with `prefix`; unique to this
    /// process and call.
    pub fn new(prefix: &str) -> anyhow::Result<Self> {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "sail-test-{}-{}-{}-{}",
            prefix,
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            nanos
        ));
        std::fs::create_dir_all(&path)
            .map_err(|e| anyhow::anyhow!("create {}: {}", path.display(), e))?;
        Ok(TempDir(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join<P: AsRef<Path>>(&self, p: P) -> std::path::PathBuf {
        self.0.join(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// sing-box
// ---------------------------------------------------------------------------

/// sing-box: `$SING_BOX`, else Homebrew's, else the one on the PATH.
pub fn sing_box_path() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("SING_BOX") {
        return path.into();
    }
    let homebrew = Path::new("/opt/homebrew/bin/sing-box");
    if homebrew.exists() {
        homebrew.to_path_buf()
    } else {
        "sing-box".into()
    }
}

/// An external proxy process (sing-box, Xray), killed when dropped. Its
/// log goes to the test's stderr, but for the lines at level INFO.
pub struct Daemon {
    child: std::process::Child,
}

impl Daemon {
    /// Writes `config` to `dir/name.json` and runs sing-box on it. Returns
    /// once sing-box has started, every inbound listening: waiting on what
    /// sing-box says, not on probes, works for UDP inbounds too. An inbound
    /// that cannot listen fails it with sing-box's message, which
    /// `retry_port_clash` recognizes.
    pub fn sing_box(dir: &Path, name: &str, mut config: serde_json::Value) -> anyhow::Result<Self> {
        // "sing-box started" is at INFO.
        config["log"] = serde_json::json!({
            "level": "info",
            "timestamp": false,
        });
        let path = dir.join(format!("{}.json", name));
        std::fs::write(&path, config.to_string())?;
        let mut command = std::process::Command::new(sing_box_path());
        command.arg("run").arg("-c").arg(&path);
        Self::spawn(command, &format!("sing-box {}", name), |line| {
            line.contains("sing-box started")
        })
    }

    /// Runs `command`, its log on stderr, and returns once a line of it
    /// satisfies `ready`; it fails if the process exits first, or is not
    /// ready within 30s.
    pub fn spawn(
        mut command: std::process::Command,
        name: &str,
        ready: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        use std::io::BufRead;
        use std::process::Stdio;

        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("run {}: {}", name, e))?;
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        // Both streams are read to the end, so that the process never
        // blocks on a full pipe.
        let streams: Vec<Box<dyn std::io::Read + Send>> = vec![
            Box::new(child.stdout.take().expect("piped")),
            Box::new(child.stderr.take().expect("piped")),
        ];
        let ready = Arc::new(ready);
        for stream in streams {
            let ready = ready.clone();
            let ready_tx = ready_tx.clone();
            let name = name.to_string();
            std::thread::spawn(move || {
                let mut tail = std::collections::VecDeque::new();
                let mut signalled = false;
                for line in std::io::BufReader::new(stream).lines() {
                    let Ok(line) = line else { break };
                    if !line.contains("INFO") {
                        eprintln!("[{}] {}", name, line);
                    }
                    if !signalled {
                        if ready(&line) {
                            signalled = true;
                            let _ = ready_tx.send(Ok(()));
                        } else {
                            tail.push_back(line);
                            if tail.len() > 20 {
                                tail.pop_front();
                            }
                        }
                    }
                }
                if !signalled {
                    let tail: Vec<_> = tail.into_iter().collect();
                    let _ = ready_tx.send(Err(tail.join("\n")));
                }
            });
        }
        drop(ready_tx);
        let mut daemon = Daemon { child };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut logs = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match ready_rx.recv_timeout(left) {
                Ok(Ok(())) => return Ok(daemon),
                // One stream ended; the other may still say it is ready.
                Ok(Err(tail)) => logs.push(tail),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let status = daemon.child.wait()?;
                    anyhow::bail!("{} exited ({}): {}", name, status, logs.join("\n"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    anyhow::bail!("{} did not start within 30s", name);
                }
            }
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Shuts the instances down and waits until each has stopped, so that
/// what they listened on is free again.
pub fn shutdown_instances(rt: &tokio::runtime::Runtime, ids: Vec<sail::RuntimeId>) {
    let _ = STARTED.try_with(|started| started.borrow_mut().0.retain(|id| !ids.contains(id)));
    for id in ids {
        sail::shutdown(id);
        let stopped =
            rt.block_on(async { timeout(Duration::from_secs(10), wait_for_shutdown(id)).await });
        if stopped.is_err() {
            tracing::warn!("sail instance {} did not stop within 10s", id);
        }
        let _ = std::fs::remove_dir_all(instance_cache_dir(id));
    }
}

/// Echoes on `stream` until it ends, and says why it did: reading goes on
/// while a write waits, what is read being kept until it is written back.
/// `read` and `written` are told each count of bytes as it happens.
///
/// An echo that reads, then writes all of it before it reads again, stops
/// reading whenever its peer is slow to take what comes back. Linux 6.17
/// can then leave the connection standing for good: with no room to
/// receive in, the echo's socket takes its window back, and after that
/// each end refuses the other's acknowledgements as beyond the window
/// (fixed in Linux 7.1, "tcp: implement RFC 7323 window retraction
/// receiver requirements"). A program of four sockets and no sail in it
/// stood still so 169 times in 4.9 million transfers on 6.17, never in 2.4
/// million on 6.8, and never in 780,000 on 6.17 once its echo read while
/// it wrote. It is what stopped `test_reality_sail_to_sail` twice in CI.
pub async fn echo(
    stream: tokio::net::TcpStream,
    read: impl Fn(usize) + Send + 'static,
    written: impl Fn(usize) + Send + 'static,
) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut reader, mut writer) = stream.into_split();
    let (kept, mut to_write) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let reading = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => return "its client closed".to_string(),
                Ok(n) => {
                    read(n);
                    if kept.send(buf[..n].to_vec()).is_err() {
                        return "writing ended".to_string();
                    }
                }
                Err(e) => return format!("reading failed: {}", e),
            }
        }
    });
    while let Some(data) = to_write.recv().await {
        let mut done = 0;
        while done < data.len() {
            match writer.write(&data[done..]).await {
                Ok(0) => {
                    reading.abort();
                    return "writing took nothing".to_string();
                }
                Ok(taken) => {
                    done += taken;
                    written(taken);
                }
                Err(e) => {
                    reading.abort();
                    return format!("writing failed: {}", e);
                }
            }
        }
    }
    // All that was read is written back: the client's close, or what
    // reading failed with.
    reading
        .await
        .unwrap_or_else(|e| format!("reading stopped: {}", e))
}

pub async fn run_tcp_echo_server(
    addr: &str,
) -> anyhow::Result<(
    std::net::SocketAddr,
    impl std::future::Future<Output = anyhow::Result<()>>,
)> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let fut = async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(echo(stream, |_| {}, |_| {}));
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("accept tcp failed: {}", e));
                }
            }
        }
    };
    Ok((local_addr, fut))
}

/// The next datagram on `socket`, past the receives that fail. On Windows
/// a datagram sent to a socket already closed comes back as an error of
/// the sender's next receive (WSAECONNRESET): a stub server that stopped
/// at it would answer nothing after, and what asks it later would fail
/// for no fault of sail's. Every UDP stub of the tests receives through
/// this.
pub async fn recv_past_errors(socket: &UdpSocket, buf: &mut [u8]) -> (usize, std::net::SocketAddr) {
    loop {
        match socket.recv_from(buf).await {
            Ok(received) => return received,
            Err(_) => tokio::time::sleep(Duration::from_millis(1)).await,
        }
    }
}

pub async fn run_udp_echo_server(
    addr: &str,
) -> anyhow::Result<(
    std::net::SocketAddr,
    impl std::future::Future<Output = anyhow::Result<()>>,
)> {
    let socket = UdpSocket::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind udp failed: {}", e))?;
    sail::net::fit_largest_datagram(socket2::SockRef::from(&socket))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let fut = async move {
        // Holds any UDP payload.
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, raddr) = recv_past_errors(&socket, &mut buf).await;
            let _ = socket
                .send_to(&buf[..n], &raddr)
                .await
                .map_err(|e| anyhow::anyhow!("send udp failed: {}", e))?;
        }
    };
    Ok((local_addr, fut))
}

/// The tuning test instances run with: short idle timeouts after
/// half-close, so that the half-close tests do not wait out the defaults.
pub fn runtime_options() -> sail::runtime::RuntimeOptions {
    let mut options = sail::runtime::RuntimeOptions::default();
    options
        .set_all([
            "relay.uplink_idle_timeout=3s",
            "relay.downlink_idle_timeout=3s",
        ])
        .unwrap();
    options
}

// Runs multiple sail instances.
/// Where the instance `rt_id` of this process keeps its cache.
fn instance_cache_dir(rt_id: sail::RuntimeId) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("sail-test-cache-{}-{}", std::process::id(), rt_id))
}

pub fn run_sail_instances(
    rt: &tokio::runtime::Runtime,
    configs: Vec<String>,
) -> anyhow::Result<Vec<sail::RuntimeId>> {
    run_sail_instances_in(rt, configs, None)
}

/// `run_sail_instances`, with `data_dir` the instances' data directory.
pub fn run_sail_instances_in(
    _rt: &tokio::runtime::Runtime,
    configs: Vec<String>,
    data_dir: Option<&std::path::Path>,
) -> anyhow::Result<Vec<sail::RuntimeId>> {
    let mut sail_rt_ids = Vec::new();
    for config in configs {
        let rt_id = NEXT_RT_ID.fetch_add(1, Ordering::Relaxed);
        // A cache of its own: instances running at once would wait on one
        // another's cache file.
        let host = sail::runtime::Host {
            cache_dir: Some(instance_cache_dir(rt_id)),
            data_dir: data_dir.map(std::path::Path::to_path_buf),
            ..Default::default()
        };
        let config = sail::config::from_string_for(&config, &host)
            .map_err(|e| anyhow::anyhow!("parse config failed: {}", e))?;
        let opts = sail::StartOptions {
            signals: false,
            config: sail::Config::Internal(Box::new(config)),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: sail::RuntimeOption::SingleThread,
            runtime: runtime_options(),
            host,
        };
        if let Err(e) = start_instance(rt_id, opts) {
            for id in &sail_rt_ids {
                sail::shutdown(*id);
            }
            return Err(e);
        }
        sail_rt_ids.push(rt_id);
    }
    Ok(sail_rt_ids)
}

/// Starts an instance of `opts` as `rt_id`, an ID from `next_rt_id`, and
/// returns once it runs, or with the error its start failed with: a start
/// that fails must fail the test, not leave it waiting. The instance is
/// among those its thread started, shut down when the thread ends if the
/// test has not stopped it: every test that starts an instance starts it
/// through this, or through `run_sail_instances`.
pub fn start_instance(rt_id: sail::RuntimeId, opts: sail::StartOptions) -> anyhow::Result<()> {
    // A thread of its own, not a runtime's blocking pool: dropping the
    // runtime, as a test that panics does, would wait for the instance to
    // stop.
    let start = std::thread::Builder::new()
        .name(format!("sail-{}", rt_id))
        .spawn(move || sail::start(rt_id, opts))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if sail::is_running(rt_id) {
            break;
        }
        if start.is_finished() {
            return Err(match start.join() {
                Ok(Err(e)) => anyhow::anyhow!("start sail failed: {}", e),
                Ok(Ok(())) => anyhow::anyhow!("sail stopped as soon as it started"),
                Err(_) => anyhow::anyhow!("start sail panicked"),
            });
        }
        if std::time::Instant::now() > deadline {
            // It may run yet: stopped with its thread all the same.
            stops_with_its_thread(rt_id);
            anyhow::bail!("sail did not start within 10s");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    stops_with_its_thread(rt_id);
    Ok(())
}

/// Has the instance `rt_id` shut down when this thread ends, as those
/// `start_instance` starts are: for a test that starts its instance
/// itself, the start being what it tests.
pub fn stops_with_its_thread(rt_id: sail::RuntimeId) {
    let _ = STARTED.try_with(|started| {
        let mut started = started.borrow_mut();
        if !started.0.contains(&rt_id) {
            started.0.push(rt_id);
        }
    });
}

/// Shuts the instance `rt_id` down and waits until it has stopped, ten
/// seconds at most.
pub fn stop_instance(rt_id: sail::RuntimeId) {
    keep_running(&[rt_id]);
    sail::shutdown(rt_id);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while sail::is_running(rt_id) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Leaves `ids` running when the thread that started them ends: for an
/// instance a test binary starts once and its tests share, until the
/// process ends.
pub fn keep_running(ids: &[sail::RuntimeId]) {
    let _ = STARTED.try_with(|started| started.borrow_mut().0.retain(|id| !ids.contains(id)));
}

/// The instances a thread started and has not shut down. A test that fails
/// before `shutdown_instances` leaves them running; they are shut down when
/// its thread ends, so that its ports are free again.
struct Started(Vec<sail::RuntimeId>);

thread_local! {
    static STARTED: std::cell::RefCell<Started> = const { std::cell::RefCell::new(Started(Vec::new())) };
}

impl Drop for Started {
    fn drop(&mut self) {
        // Those a test stopped itself, without the harness, are not told
        // of: only what still runs.
        let ids: Vec<_> = std::mem::take(&mut self.0)
            .into_iter()
            .filter(|&id| sail::is_running(id))
            .collect();
        if ids.is_empty() {
            return;
        }
        // Said, for an instance other threads may still use: a test that
        // shares one past its own thread calls `keep_running`.
        eprintln!(
            "test harness: the thread that started sail instance(s) {:?} ended without \
             shutting them down; shutting them down now",
            ids
        );
        // On a thread of its own: this thread's locals, which shutting an
        // instance down may use, are being destroyed.
        let stop = std::thread::spawn(move || {
            for &id in &ids {
                sail::shutdown(id);
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while ids.iter().any(|&id| sail::is_running(id)) && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            for &id in &ids {
                let _ = std::fs::remove_dir_all(instance_cache_dir(id));
            }
        });
        let _ = stop.join();
    }
}

fn new_socks_outbound(
    socks_addr: &str,
    socks_port: u16,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<AnyOutboundHandler> {
    // Make use of a socks outbound to initiate a socks request to a sail instance.
    // It stands for an application, whose datagrams may be fragmented.
    let mut socks = serde_json::json!({
        "type": "socks",
        "tag": "socks",
        "server": socks_addr,
        "server_port": socks_port,
        "udp_fragment": true,
    });
    if let Some(username) = username {
        socks["username"] = username.into();
    }
    if let Some(password) = password {
        socks["password"] = password.into();
    }
    let config =
        sail::config::Config::from_json(&serde_json::json!({ "outbounds": [socks] }).to_string())?;
    let dial_defaults = sail::net::DialDefaults::default();
    let dns_client = sail::app::dns_client::DnsClient::new(
        &config.dns,
        Arc::new(dial_defaults.clone()),
        &Default::default(),
    )?
    .into_shared();
    let outbound_manager = sail::app::outbound::manager::OutboundManager::new(
        &config.outbounds,
        &dial_defaults,
        &sail::runtime::RuntimeEnv::default(),
        dns_client,
    )?;

    Ok((outbound_manager
        .get("socks")
        .ok_or_else(|| anyhow::anyhow!("socks outbound not found"))?) as _)
}

pub async fn new_socks_stream(
    socks_addr: &str,
    socks_port: u16,
    sess: &Session,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<AnyStream> {
    // Use a socks outbound to simulate a client request.
    let handler = new_socks_outbound(socks_addr, socks_port, username, password)?;
    let stream = tokio::net::TcpStream::connect(format!("{}:{}", socks_addr, socks_port)).await?;
    timeout(
        Duration::from_secs(10),
        handler.stream().map_err(|e| anyhow::anyhow!(e))?.handle(
            sess,
            None,
            Some(Box::new(stream)),
        ),
    )
    .await?
    .map_err(|e| anyhow::anyhow!(e))
}

pub async fn new_socks_datagram(
    socks_addr: &str,
    socks_port: u16,
    sess: &Session,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<AnyOutboundDatagram> {
    // Use a socks outbound to simulate a client request.
    let handler = new_socks_outbound(socks_addr, socks_port, username, password)?;
    timeout(
        Duration::from_secs(10),
        handler
            .datagram()
            .map_err(|e| anyhow::anyhow!(e))?
            .handle(sess, None),
    )
    .await?
    .map_err(|e| anyhow::anyhow!(e))
}

pub fn test_tcp_half_close_on_configs(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
) -> anyhow::Result<()> {
    info!("testing tcp half close");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;
    let sail_rt_ids = run_sail_instances(&rt, configs)?;
    let socks_addr = socks_addr.to_string();
    let res = rt.block_on(rt.spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::Ip(local_addr),
            ..Default::default()
        };
        let mut client_stream =
            new_socks_stream(&socks_addr, socks_port, &sess, None, None).await?;
        let (mut server_stream, _) = listener
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("accept tcp failed: {}", e))?;

        // client <-> server
        //
        // Ensure both directions work.
        //
        // When testing with proxy protocols need additional info from the other
        // side to initialize itself, such as shadowsocks needs a salt from the
        // other side, we must forward some payload first.
        client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| anyhow::anyhow!("write hello failed: {}", e))?;
        let mut buf = Vec::new();
        let n = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read hello failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world failed: {}", e))?;
        let mut buf = Vec::new();
        let n = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read world failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");

        // client(shutdown) <-> server
        //
        // The case client performs a shutdown.
        //
        // The expected behaiver is, the client socket is no longer writable
        // after the shutdown, but can still read data from server socket.
        // The server socket can write data to client, a read on the server socket
        // will return zero bytes (EOF) immediately. Data from the server keeps
        // the connection open, and once nothing has moved for the downlink
        // idle timeout, a read on client socket returns zero bytes even though
        // we havn't explicitly shutdown the server socket.
        client_stream
            .shutdown()
            .await
            .map_err(|e| anyhow::anyhow!("shutdown client failed: {}", e))?;
        let res = client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| e.kind());
        assert!(res.is_err());
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world after shutdown failed: {}", e))?;
        let mut buf = Vec::new();
        let n = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read world after shutdown failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");
        // The downlink's idle time runs from here.
        let downlink_active = tokio::time::Instant::now();
        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(2), server_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read failed: {}", e))?;
        assert_eq!(n, 0);
        // Well within the downlink's idle time, counted from its last bytes,
        // as on the uplink below.
        tokio::time::sleep_until(
            downlink_active + runtime_options().relay.downlink_idle_timeout / 2,
        )
        .await;
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world after timeout failed: {}", e))?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let res = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read buf after timeout failed: {}", e))?;
        assert_eq!(res, 5);
        let mut buf = Vec::new();
        // The idle timeout counts from the last "world".
        let n = timeout(Duration::from_secs(4), client_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read 2 failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read 2 failed: {}", e))?;
        assert_eq!(n, 0);

        let mut client_stream =
            new_socks_stream(&socks_addr, socks_port, &sess, None, None).await?;
        let (mut server_stream, _) = listener
            .accept()
            .await
            .map_err(|e| anyhow::anyhow!("accept 2 failed: {}", e))?;

        // Another direction.
        //
        // client <-> server
        //
        // Ensure both directions work.
        //
        // When testing with proxy protocols need additional info from the other
        // side to initialize itself, such as shadowsocks needs a salt from the
        // other side, we must forward some payload first.
        client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| anyhow::anyhow!("write hello 2 failed: {}", e))?;
        let mut buf = Vec::new();
        let n = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read hello 2 failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        server_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world 2 failed: {}", e))?;
        let mut buf = Vec::new();
        let n = client_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read world 2 failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "world");

        server_stream
            .shutdown()
            .await
            .map_err(|e| anyhow::anyhow!("shutdown server failed: {}", e))?;
        client_stream
            .write_all(b"hello")
            .await
            .map_err(|e| anyhow::anyhow!("write hello 3 failed: {}", e))?;
        let mut buf = Vec::new();
        let n = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read hello 3 failed: {}", e))?;
        assert_eq!(String::from_utf8_lossy(&buf[..n]), "hello");
        // The uplink's idle time runs from here.
        let uplink_active = tokio::time::Instant::now();
        let res = server_stream
            .write_all(b"world")
            .await
            .map_err(|e| e.kind());
        assert!(res.is_err());
        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(2), client_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read 3 failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read 3 failed: {}", e))?;
        assert_eq!(n, 0);
        // Well within the uplink's idle time, counted from its last bytes,
        // the half-closed connection still carries the client's: half of it,
        // so that a slow host's delays in the steps above leave room.
        tokio::time::sleep_until(uplink_active + runtime_options().relay.uplink_idle_timeout / 2)
            .await;
        client_stream
            .write_all(b"world")
            .await
            .map_err(|e| anyhow::anyhow!("write world 3 failed: {}", e))?;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let res = server_stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read buf 3 failed: {}", e))?;
        assert_eq!(res, 5);
        let mut buf = Vec::new();
        let n = timeout(Duration::from_secs(4), server_stream.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("timeout read 4 failed: {}", e))?
            .map_err(|e| anyhow::anyhow!("read 4 failed: {}", e))?;
        assert_eq!(n, 0);
        Ok::<(), anyhow::Error>(())
    }));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow::anyhow!("task join error: {}", e)),
    }
}

async fn file_hash<P: AsRef<Path>>(p: P) -> anyhow::Result<Box<[u8]>> {
    let mut src = tokio::fs::File::open(p)
        .await
        .map_err(|e| anyhow::anyhow!("open file failed: {}", e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = src
            .read_buf(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("read file failed: {}", e))?;
        if n == 0 {
            break;
        }
        hasher
            .write_all(&buf[..n])
            .map_err(|e| anyhow::anyhow!("write hasher failed: {}", e))?;
    }
    Ok(hasher.finalize().as_slice().to_owned().into_boxed_slice())
}

/// Waits for the receiver to take the datagram just sent.
async fn received(acks: &mut tokio::sync::mpsc::Receiver<()>) -> anyhow::Result<()> {
    timeout(Duration::from_secs(10), acks.recv())
        .await
        .map_err(|_| anyhow::anyhow!("a datagram was not received within 10s"))?
        .ok_or_else(|| anyhow::anyhow!("the receiver stopped"))
}

pub fn test_data_transfering_reliability_on_configs(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
) -> anyhow::Result<()> {
    info!("testing data transfering reliability");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;
    // Files of this call's own, removed when it returns.
    let dir = TempDir::new("transfer")?;
    let src_file = "source_random_bytes.bin";
    let dst_file = "destination_random_bytes.bin";
    let source = dir.join(src_file);
    let dst = dir.join(dst_file);
    let path = dir.path().to_path_buf();
    let mut rng = StdRng::from_entropy();
    let mut data = vec![0u8; 2 * 1024 * 1024];
    rng.fill_bytes(&mut data);
    let mut f = std::fs::File::create(&source)
        .map_err(|e| anyhow::anyhow!("create source failed: {}", e))?;
    f.write_all(&data)
        .map_err(|e| anyhow::anyhow!("write source failed: {}", e))?;
    f.sync_all()
        .map_err(|e| anyhow::anyhow!("sync source failed: {}", e))?;

    // TCP uplink
    let listener = rt
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        let (mut stream, _) = timeout(Duration::from_secs(10), listener.accept())
            .await
            .map_err(|e| anyhow::anyhow!("accept timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("accept failed: {}", e))?;
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let n = timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut stream, &mut dst_file),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata failed: {}", e))?
                .len(),
            n
        );
        let src_hash = file_hash(source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let send_task = async move {
        let source = path.join(src_file);
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::Ip(local_addr),
            ..Default::default()
        };
        let mut stream =
            new_socks_stream(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut src, &mut stream),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        Ok::<(), anyhow::Error>(())
    };
    let sail_rt_ids = run_sail_instances(&rt, configs.clone())?;
    let futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>> =
        vec![Box::pin(recv_task), Box::pin(send_task)];
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(anyhow::anyhow!("task join error: {}", e)),
    }

    // TCP downlink
    let listener = rt
        .block_on(TcpListener::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind tcp failed: {}", e))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;
    let socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::Ip(local_addr),
            ..Default::default()
        };
        let mut stream =
            new_socks_stream(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let n = timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut stream, &mut dst_file),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata failed: {}", e))?
                .len(),
            n
        );
        let src_hash = file_hash(source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let _socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let send_task = async move {
        let source = path.join(src_file);
        let (mut stream, _) = timeout(Duration::from_secs(10), listener.accept())
            .await
            .map_err(|e| anyhow::anyhow!("accept timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("accept failed: {}", e))?;
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        timeout(
            Duration::from_secs(600),
            tokio::io::copy(&mut src, &mut stream),
        )
        .await
        .map_err(|e| anyhow::anyhow!("copy timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("copy failed: {}", e))?;
        Ok::<(), anyhow::Error>(())
    };
    let sail_rt_ids = run_sail_instances(&rt, configs.clone())?;
    let futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>> =
        vec![Box::pin(recv_task), Box::pin(send_task)];
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(anyhow::anyhow!("task join error: {}", e)),
    }

    // UDP uplink
    // One datagram at a time: the next is sent once the last is received,
    // so that what is checked is that each arrives, whole and in order,
    // not that a burst outruns nothing on the way.
    let (ack, mut acks) = tokio::sync::mpsc::channel::<()>(1);
    let socket = rt
        .block_on(UdpSocket::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind udp failed: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;

    let path = dir.path().to_path_buf();
    let recv_task = async move {
        let source = path.join(src_file);
        let dst = path.join(dst_file);
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let expected_total_bytes = tokio::fs::File::open(&source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?
            .metadata()
            .await
            .map_err(|e| anyhow::anyhow!("metadata source failed: {}", e))?
            .len() as usize;
        let mut recvd_bytes: usize = 0;
        let mut buf = vec![0u8; 1500];
        let mut recvd_data = Vec::new();
        loop {
            assert!(recvd_bytes <= expected_total_bytes);
            if recvd_bytes == expected_total_bytes {
                break;
            }
            let (n, _) = timeout(Duration::from_secs(10), socket.recv_from(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("recv timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("recv failed: {}", e))?;
            recvd_data.push(buf[..n].to_vec());
            recvd_bytes += n;
            let _ = ack.send(()).await;
        }
        for data in recvd_data.into_iter() {
            dst_file
                .write_all(&data)
                .await
                .map_err(|e| anyhow::anyhow!("write dst failed: {}", e))?;
        }
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata dst failed: {}", e))?
                .len() as usize,
            expected_total_bytes
        );
        let src_hash = file_hash(&source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let send_task = async move {
        let source = path.join(src_file);
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::Ip(local_addr),
            ..Default::default()
        };
        let dgram = new_socks_datagram(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        let (_, mut s) = dgram.split();
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        let mut buf = vec![0u8; 1500];
        loop {
            let n = timeout(Duration::from_secs(2), src.read(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("read timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("read failed: {}", e))?;
            if n > 0 {
                let _n = timeout(
                    Duration::from_secs(2),
                    s.send_to(&buf[..n], &sess.destination),
                )
                .await
                .map_err(|e| anyhow::anyhow!("send timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("send failed: {}", e))?;
                received(&mut acks).await?;
            } else {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let sail_rt_ids = run_sail_instances(&rt, configs.clone())?;
    let futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>> =
        vec![Box::pin(recv_task), Box::pin(send_task)];
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(_)) => (),
        Ok(Err(e)) => return Err(e),
        Err(e) => return Err(anyhow::anyhow!("task join error: {}", e)),
    }

    // UDP downlink
    // One datagram at a time: the next is sent once the last is received,
    // so that what is checked is that each arrives, whole and in order,
    // not that a burst outruns nothing on the way.
    let (ack, mut acks) = tokio::sync::mpsc::channel::<()>(1);
    let socket = rt
        .block_on(UdpSocket::bind("127.0.0.1:0"))
        .map_err(|e| anyhow::anyhow!("bind udp failed: {}", e))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| anyhow::anyhow!("get local addr failed: {}", e))?;

    let socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let recv_task = async move {
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::Ip(local_addr),
            ..Default::default()
        };
        let dgram = new_socks_datagram(&socks_addr_cloned, socks_port, &sess, None, None).await?;
        let (mut r, mut s) = dgram.split();
        let source = path.join(src_file);
        let _buf = vec![0u8; 1500];
        if dst.exists() {
            tokio::fs::remove_file(&dst)
                .await
                .map_err(|e| anyhow::anyhow!("remove dst failed: {}", e))?;
        }
        let mut dst_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dst)
            .await
            .map_err(|e| anyhow::anyhow!("open dst failed: {}", e))?;
        let expected_total_bytes = tokio::fs::File::open(&source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?
            .metadata()
            .await
            .map_err(|e| anyhow::anyhow!("metadata source failed: {}", e))?
            .len() as usize;
        let mut recvd_bytes: usize = 0;
        let mut buf = vec![0u8; 1500];
        let mut recvd_data = Vec::new();
        // Send a datagram to establish the session.
        s.send_to(b"hello", &sess.destination)
            .await
            .map_err(|e| anyhow::anyhow!("send hello failed: {}", e))?;
        loop {
            assert!(recvd_bytes <= expected_total_bytes);
            if recvd_bytes == expected_total_bytes {
                break;
            }
            let (n, _) = timeout(Duration::from_secs(10), r.recv_from(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("recv timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("recv failed: {}", e))?;
            recvd_data.push(buf[..n].to_vec());
            recvd_bytes += n;
            let _ = ack.send(()).await;
        }
        for data in recvd_data.into_iter() {
            dst_file
                .write_all(&data)
                .await
                .map_err(|e| anyhow::anyhow!("write dst failed: {}", e))?;
        }
        dst_file
            .sync_all()
            .await
            .map_err(|e| anyhow::anyhow!("sync dst failed: {}", e))?;
        assert_eq!(
            dst_file
                .metadata()
                .await
                .map_err(|e| anyhow::anyhow!("metadata dst failed: {}", e))?
                .len() as usize,
            expected_total_bytes
        );
        let src_hash = file_hash(&source).await?;
        let dst_hash = file_hash(&dst).await?;
        assert_eq!(src_hash.as_ref(), dst_hash.as_ref());
        Ok::<(), anyhow::Error>(())
    };
    let _socks_addr_cloned = socks_addr.to_string();
    let path = dir.path().to_path_buf();
    let send_task = async move {
        let source = path.join(src_file);
        let mut src = tokio::fs::File::open(source)
            .await
            .map_err(|e| anyhow::anyhow!("open source failed: {}", e))?;
        let mut buf = vec![0u8; 1500];
        // Receive a single packet to decide the remote peer.
        let (_, raddr) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| anyhow::anyhow!("recv initial failed: {}", e))?;
        loop {
            let n = timeout(Duration::from_secs(2), src.read(&mut buf))
                .await
                .map_err(|e| anyhow::anyhow!("read timeout: {}", e))?
                .map_err(|e| anyhow::anyhow!("read failed: {}", e))?;
            if n > 0 {
                let _n = timeout(Duration::from_secs(2), socket.send_to(&buf[..n], &raddr))
                    .await
                    .map_err(|e| anyhow::anyhow!("send timeout: {}", e))?
                    .map_err(|e| anyhow::anyhow!("send failed: {}", e))?;
                received(&mut acks).await?;
            } else {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let sail_rt_ids = run_sail_instances(&rt, configs.clone())?;
    let futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>> =
        vec![Box::pin(recv_task), Box::pin(send_task)];
    let res = rt.block_on(rt.spawn(futures::future::try_join_all(futs)));
    shutdown_instances(&rt, sail_rt_ids);
    match res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(anyhow::anyhow!("task join error: {}", e)),
    }
}

// Runs multiple sail instances, thereafter a socks request will be sent to the
// given socks server to test the proxy chain. The proxy chain is expected to
// correctly handle the request to it's destination.
pub fn test_configs(configs: Vec<String>, socks_addr: &str, socks_port: u16) -> anyhow::Result<()> {
    test_configs_with_auth(configs, socks_addr, socks_port, None, None)
}

pub fn test_configs_with_auth(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<()> {
    test_configs_full(
        configs,
        socks_addr,
        socks_port,
        username,
        password,
        None,
        Duration::from_secs(10),
    )
}

/// `test_configs` where the configuration is to refuse the connection or
/// its datagrams, each step waiting `wait` before it counts as failed: a
/// dropped connection fails only by its wait running out.
pub fn test_configs_refused(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
    wait: Duration,
) -> anyhow::Result<()> {
    test_configs_full(configs, socks_addr, socks_port, None, None, None, wait)
}

/// How long a step meant to be refused waits: ten times the slowest that
/// passed in the same test, half a second at least, so that the wait
/// follows the machine rather than a guess.
pub fn refusal_wait(passed: &[Duration]) -> Duration {
    (passed.iter().max().copied().unwrap_or_default() * 10).max(Duration::from_millis(500))
}

/// `test_configs`, with `data_dir` the instances' data directory.
pub fn test_configs_in(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
    data_dir: &std::path::Path,
) -> anyhow::Result<()> {
    test_configs_full(
        configs,
        socks_addr,
        socks_port,
        None,
        None,
        Some(data_dir),
        Duration::from_secs(10),
    )
}

fn test_configs_full(
    configs: Vec<String>,
    socks_addr: &str,
    socks_port: u16,
    username: Option<String>,
    password: Option<String>,
    data_dir: Option<&std::path::Path>,
    wait: Duration,
) -> anyhow::Result<()> {
    info!("testing configs");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("build runtime failed: {}", e))?;

    // Use an echo server as the destination of the socks request.
    let mut bg_tasks: Vec<
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>,
    > = Vec::new();
    let (tcp_addr, tcp_fut) = rt.block_on(run_tcp_echo_server("127.0.0.1:0"))?;
    let (udp_addr, udp_fut) = rt.block_on(run_udp_echo_server("127.0.0.1:0"))?;
    bg_tasks.push(Box::pin(tcp_fut));
    bg_tasks.push(Box::pin(udp_fut));
    let (bg_task, bg_task_handle) = abortable(futures::future::try_join_all(bg_tasks));

    let sail_rt_ids = run_sail_instances_in(&rt, configs, data_dir)?;

    // Simulates an application request.
    let socks_addr = socks_addr.to_string();
    let app_task = async move {
        let mut sess = sail::session::Session {
            destination: sail::session::SocksAddr::Ip(tcp_addr),
            ..Default::default()
        };
        let mut s = timeout(
            wait,
            new_socks_stream(
                &socks_addr,
                socks_port,
                &sess,
                username.clone(),
                password.clone(),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("connect socks stream timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("connect socks stream failed: {}", e))?;

        timeout(wait, s.write_all(b"abc"))
            .await
            .map_err(|e| anyhow::anyhow!("write to stream timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("write to stream failed: {}", e))?;

        let mut buf = Vec::new();
        let n = timeout(wait, s.read_buf(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("read from stream timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("read from stream failed: {}", e))?;

        if "abc" != String::from_utf8_lossy(&buf[..n]) {
            return Err(anyhow::anyhow!(
                "stream echo mismatch: expected 'abc', got '{}'",
                String::from_utf8_lossy(&buf[..n])
            ));
        }

        // Test UDP
        sess.destination = sail::session::SocksAddr::Ip(udp_addr);
        let dgram = timeout(
            wait,
            new_socks_datagram(
                &socks_addr,
                socks_port,
                &sess,
                username.clone(),
                password.clone(),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("create socks datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("create socks datagram failed: {}", e))?;

        let (mut r, mut s) = dgram.split();
        let msg = b"def";
        let n = timeout(wait, s.send_to(msg.as_ref(), &sess.destination))
            .await
            .map_err(|e| anyhow::anyhow!("send datagram timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("send datagram failed: {}", e))?;

        if msg.len() != n {
            return Err(anyhow::anyhow!(
                "send datagram partial write: expected {}, got {}",
                msg.len(),
                n
            ));
        }

        let mut buf = vec![0u8; 2 * 1024];
        let (n, raddr) = timeout(wait, r.recv_from(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("recv datagram timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("recv datagram failed: {}", e))?;

        if msg != &buf[..n] {
            return Err(anyhow::anyhow!(
                "datagram echo mismatch: expected {:?}, got {:?}",
                msg,
                &buf[..n]
            ));
        }
        if raddr != sess.destination {
            return Err(anyhow::anyhow!(
                "datagram source mismatch: expected {:?}, got {:?}",
                sess.destination,
                raddr
            ));
        }

        // Test if we can handle a second UDP session. This can fail in stream
        // transports if the stream ID has not been correctly set.
        let dgram2 = timeout(
            wait,
            new_socks_datagram(
                &socks_addr,
                socks_port,
                &sess,
                username.clone(),
                password.clone(),
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("create second socks datagram timeout: {}", e))?
        .map_err(|e| anyhow::anyhow!("create second socks datagram failed: {}", e))?;

        let (mut r, mut s) = dgram2.split();
        let msg = b"ghi";
        let n = timeout(wait, s.send_to(msg.as_ref(), &sess.destination))
            .await
            .map_err(|e| anyhow::anyhow!("send second datagram timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("send second datagram failed: {}", e))?;

        if msg.len() != n {
            return Err(anyhow::anyhow!(
                "send second datagram partial write: expected {}, got {}",
                msg.len(),
                n
            ));
        }

        let mut buf = vec![0u8; 2 * 1024];
        let (n, raddr) = timeout(wait, r.recv_from(&mut buf))
            .await
            .map_err(|e| anyhow::anyhow!("recv second datagram timeout: {}", e))?
            .map_err(|e| anyhow::anyhow!("recv second datagram failed: {}", e))?;

        if msg != &buf[..n] {
            return Err(anyhow::anyhow!(
                "second datagram echo mismatch: expected {:?}, got {:?}",
                msg,
                &buf[..n]
            ));
        }
        if raddr != sess.destination {
            return Err(anyhow::anyhow!(
                "second datagram source mismatch: expected {:?}, got {:?}",
                sess.destination,
                raddr
            ));
        }

        // Cancel the background task.
        bg_task_handle.abort();
        Ok::<(), anyhow::Error>(())
    };
    let bg_task = async move {
        match bg_task.await {
            Ok(res) => res.map(|_| ()),
            Err(_) => Ok(()), // Aborted
        }
    };
    let futs = vec![rt.spawn(bg_task), rt.spawn(app_task)];
    let res = rt.block_on(async {
        timeout(Duration::from_secs(60), futures::future::select_all(futs))
            .await
            .map_err(|e| anyhow::anyhow!("test timeout: {}", e))
    });

    shutdown_instances(&rt, sail_rt_ids);

    match res {
        Ok((result, _, _)) => {
            // result is Result<Result<(), Error>, JoinError>
            match result {
                Ok(inner_res) => inner_res,
                Err(e) => Err(anyhow::anyhow!("task join failed: {:?}", e)),
            }
        }
        Err(e) => Err(anyhow::anyhow!("test execution failed: {:?}", e)),
    }
}

pub async fn wait_for_shutdown(id: sail::RuntimeId) {
    loop {
        if !sail::is_running(id) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A TLS ClientHello naming `name`, as much of one as sniffing reads.
pub fn client_hello(name: &str) -> Vec<u8> {
    let name = name.as_bytes();
    let mut list = ((3 + name.len()) as u16).to_be_bytes().to_vec();
    list.push(0);
    list.extend_from_slice(&(name.len() as u16).to_be_bytes());
    list.extend_from_slice(name);
    let mut extensions = vec![0, 0];
    extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&list);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![1];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}
