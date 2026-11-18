//! Ports for tests to give sail's inbounds, shared by the library's tests
//! and, through `#[path]`, by the integration tests: never one the system
//! may give a socket that asks for none (`127.0.0.1:0`).
//!
//! A port taken by binding `127.0.0.1:0` and then let go is in the range
//! the system hands out: any test running alongside that binds a socket
//! of its own may be given it before sail binds it ("address already in
//! use"). These are taken from below that range instead.
#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};

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

/// A port on 127.0.0.1 that is free for both TCP and UDP, as sail inbounds
/// bind both on the port they are given. It is taken from
/// `handed_out_ports`, in turn from where this process began, which
/// differs between processes; no port is handed out twice in one process,
/// so a test may bind it again after letting it go (a restart).
///
/// The port is free when returned, but not held: another process may take
/// it before the test binds it, by asking for that very port, as another
/// test binary run at the same time would.
pub fn free_port() -> u16 {
    static TAKEN: std::sync::Mutex<Option<std::collections::HashSet<u16>>> =
        std::sync::Mutex::new(None);
    static NEXT: AtomicUsize = AtomicUsize::new(0);
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
