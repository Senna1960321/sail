//! `log.redact`: with destinations, sources and processes redacted, no
//! line at INFO or above tells where a real connection went or came from;
//! another instance in the same process, which redacts nothing, logs its
//! own in full. A process of its own, since the log level is the
//! process's.

#![cfg(all(feature = "inbound-mixed", feature = "outbound-direct"))]
// Tests drive tasks of their own.
#![allow(clippy::disallowed_methods)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// Through the SOCKS5 server at `proxy`, to `host:port`; what was sent
/// comes back.
fn through(proxy: u16, host: &str, port: u16) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend(host.as_bytes());
    request.extend(port.to_be_bytes());
    s.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply[1], 0, "connect refused: {:?}", reply);
    s.write_all(b"ping").unwrap();
    let mut echoed = [0u8; 4];
    s.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"ping");
}

#[path = "../src/test_ports.rs"]
mod test_ports;
use test_ports::free_port;

/// An instance `rt_id` with a mixed inbound on `proxy`, logging to `log`.
fn start(
    rt_id: sail::RuntimeId,
    proxy: u16,
    redact: &[&str],
    log: &std::sync::Arc<sail::app::logger::InstanceLog>,
) -> std::thread::JoinHandle<Result<(), sail::Error>> {
    let config = serde_json::json!({
        // DEBUG lines are written too, but not redacted, and not scanned.
        "log": { "level": "debug", "redact": redact },
        "inbounds": [{ "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": proxy }],
        "outbounds": [{ "type": "direct", "tag": "direct" }],
        "route": { "final": "direct" }
    });
    let parsed = sail::config::from_string(&config.to_string()).unwrap();
    let opts = sail::StartOptions {
        signals: false,
        config: sail::Config::Internal(Box::new(parsed)),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: Default::default(),
        host: sail::runtime::Host {
            log: Some(sail::app::logger::InstanceLogRef(log.clone())),
            cache_dir: Some(std::env::temp_dir().join(format!("sail-log-redact-{}", proxy))),
            ..Default::default()
        },
    };
    let start = std::thread::spawn(move || sail::start(rt_id, opts));
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !sail::is_running(rt_id) {
        assert!(!start.is_finished(), "sail stopped: {:?}", start.join());
        assert!(std::time::Instant::now() < deadline, "sail did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    start
}

/// `log`'s lines at INFO and above.
fn lines(log: &sail::app::logger::InstanceLog) -> Vec<String> {
    log.follow()
        .0
        .iter()
        .filter(|l| l.level <= tracing::Level::INFO)
        .map(|l| l.message.clone())
        .collect()
}

/// The line `log` has for the connection handled.
fn handled(log: &sail::app::logger::InstanceLog) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(line) = lines(log).into_iter().find(|l| l.starts_with("handled ")) {
            return line;
        }
        assert!(std::time::Instant::now() < deadline, "{:?}", lines(log));
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn no_line_at_info_or_above_tells_where_a_connection_went() {
    // A server that echoes, reached by name.
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in echo.incoming() {
            let Ok(mut s) = s else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 64];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    // Both running at once: the one that redacts, and one that does not.
    let (proxy, open_proxy) = (free_port(), free_port());
    let log = sail::app::logger::InstanceLog::new(100_000);
    let open_log = sail::app::logger::InstanceLog::new(100_000);
    let started = start(1, proxy, &["destination", "source", "process"], &log);
    let open_started = start(2, open_proxy, &[], &open_log);

    through(proxy, "localhost", echo_port);
    through(open_proxy, "localhost", echo_port);
    let handled_open = handled(&open_log);
    let handled = handled(&log);
    sail::shutdown(1);
    sail::shutdown(2);
    let _ = started.join();
    let _ = open_started.join();

    // The other instance's line names where it went: the redaction is not
    // the process's.
    assert!(
        handled_open.ends_with(&format!("dst=localhost:{}", echo_port)),
        "{}",
        handled_open
    );
    assert!(!handled_open.contains("src=*"), "{}", handled_open);

    // The connection's line is there, redacted, with the port kept.
    assert!(handled.contains("src=*"), "{}", handled);
    assert!(
        handled.ends_with(&format!("dst=*:{}", echo_port)),
        "{}",
        handled
    );
    assert!(!handled.contains("process="), "{}", handled);
    // No line at INFO or above names where it went, under any key.
    for line in lines(&log) {
        assert!(!line.contains("localhost"), "{}", line);
    }
}
