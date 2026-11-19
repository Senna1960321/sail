//! Tuning an instance runs with: buffer and queue sizes, internal timeouts
//! and limits. They are not part of a configuration -- what a user writes
//! does not depend on them -- but chosen by whoever starts the instance: a
//! preset for the device (`--profile`), and single values on top of it
//! (`--set relay.buffer_size=32`).

use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde_derive::{Deserialize, Serialize};

/// A resource budget to start from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Profile {
    /// Phones: a small memory budget, few concurrent connections.
    Mobile,
    /// The default.
    #[default]
    Desktop,
    /// Many concurrent connections; throughput over memory.
    Server,
    /// Routers and other small devices: the least memory.
    Router,
}

/// The threads a profile's runtime runs on, unless told otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileThreads {
    /// One thread, the runtime's and the tasks' alike.
    One,
    /// This many worker threads.
    Workers(usize),
    /// A worker thread to each CPU.
    PerCpu,
}

/// The worker threads of a desktop: measured. A connection's tasks wake
/// one another, and each wake that lands on another worker is a thread
/// woken, which costs more than the work handed over. Client CPU seconds
/// per GiB, 4 streams over loopback, by worker threads:
///
/// | Windows, 4 CPUs (two runners) | 4          | 2         | 1        |
/// |-------------------------------|------------|-----------|----------|
/// | Hysteria2 download            | 27.8, 15.9 | 13.1, 8.7 | 7.7, 4.8 |
/// | its throughput over sing-box  | 0.62, 0.70 | 1.12, 1.02 | 1.23, 1.23 |
/// | Trojan download over sing-box | 0.89, 0.92 | 0.97, 0.98 | 1.03, 1.02 |
///
/// | Linux, 8 CPUs, Mbit/s | 8     | 2     | 1    |
/// |-----------------------|-------|-------|------|
/// | Trojan download       | 11777 | 10204 | 6468 |
/// | Trojan upload         | 12131 | 10598 | 5491 |
/// | Hysteria2 download    | 5084  | 5757  | 6075 |
///
/// One worker is the cheapest until it is one CPU's worth of work, and
/// then it is the limit: Trojan and multiplexed uploads lose 39 to 55%.
/// Two keep 87% or more of what every CPU gives, at about half the cost
/// of four where waking a thread is dear.
const DESKTOP_WORKERS: usize = 2;

/// The worker threads of a phone: two, as a desktop's (2026-10-24, the
/// user's decision on roadmap 5.5's measurements). On one thread the TUN
/// path held at about one CPU: Trojan through TUN on loopback ran at 0.68
/// times sing-box both ways, its one thread busy 94-99% of the time,
/// though at about 2.0 CPU seconds a GiB against sing-box's 2.6. Two,
/// against one and sing-box (master 75d4b49f5, the same path, 2 GiB, 3
/// rounds):
///
/// |                                   | 2 workers  | 1          | sing-box   |
/// |-----------------------------------|------------|------------|------------|
/// | Mbit/s down, up                   | 6098, 6007 | 4382, 4306 | 5739, 5468 |
/// | CPU seconds a GiB down, up        | 2.52, 2.62 | 1.96, 1.99 | 2.83, 2.94 |
/// | anon KiB idle, peak, glibc malloc | 4248, 6352 | 4212, 5658 |            |
/// | idle wakeups a second             | 1.1        | 0.65       | 0.16       |
///
/// A byte costs about 30% more CPU than on one worker, still less than
/// sing-box's; the memory and the idle wakeups barely move.
const MOBILE_WORKERS: usize = 2;

impl Profile {
    /// The threads its runtime runs on, unless told otherwise.
    ///
    /// - A phone: `MOBILE_WORKERS`, or its CPUs if fewer.
    /// - A desktop: `DESKTOP_WORKERS`, or its CPUs if fewer.
    /// - A server and a router: a worker to each CPU. A server of one
    ///   worker answered 500 new connections a second in 4.8 to 11 s at
    ///   the 99th percentile, against 6 to 12 ms; a router's CPUs are
    ///   slow enough that it needs each.
    pub fn threads(self) -> ProfileThreads {
        let workers = |n: usize| {
            let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
            ProfileThreads::Workers(n.min(cpus))
        };
        match self {
            Profile::Mobile => workers(MOBILE_WORKERS),
            Profile::Desktop => workers(DESKTOP_WORKERS),
            Profile::Server | Profile::Router => ProfileThreads::PerCpu,
        }
    }

    /// How long an outbound keeps a carrier, the connection its streams
    /// and UDP sessions go over, with none open (`transport::idle`). 60 s
    /// on every profile: a judgment, mux's idle timeout, not measured. The
    /// profile's rather than a runtime option, so that a phone can go
    /// lower once measured, without a setting nobody needs.
    pub fn carrier_idle_timeout(self) -> Duration {
        Duration::from_secs(60)
    }
}

impl FromStr for Profile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "mobile" => Ok(Profile::Mobile),
            "desktop" => Ok(Profile::Desktop),
            "server" => Ok(Profile::Server),
            "router" => Ok(Profile::Router),
            _ => Err(anyhow!(
                "unknown profile \"{}\", expected mobile, desktop, server or router",
                s
            )),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeOptions {
    pub relay: Relay,
    pub udp: Udp,
    pub netstack: Netstack,
    pub inbound: Inbound,
    pub quic: Quic,
    pub memory: Memory,
    pub ws: Ws,
    pub dns: Dns,
    pub stats: Stats,
    pub mux: Mux,
    pub lifecycle: Lifecycle,
    /// The profile the options started from; not an option itself.
    #[serde(skip)]
    pub profile: Profile,
    /// The sessions `fit_to_memory` lowered `inbound.max_connections` to,
    /// and the memory it found, in MiB; not an option itself.
    #[serde(skip)]
    pub sessions_for_memory: Option<(usize, u64)>,
}

/// Forwarding a TCP connection.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    /// The buffer a direction starts with, in KiB.
    pub buffer_size: usize,
    /// The largest a direction's buffer grows to, in KiB.
    pub buffer_max_size: usize,
    /// The buffers a worker thread keeps for reuse once a connection goes
    /// idle, in KiB: a fixed cost a thread, not one a connection; less
    /// means more trips to the allocator when many connections turn busy
    /// at once. The process's, as the threads are: the last instance to
    /// start sets it.
    pub buffer_pool: usize,
    /// A direction with data its writer does not take for this long
    /// aborts the connection, both sides closed. Short outages stall
    /// writes for a while and TCP recovers from them: a 90 s outage has
    /// been seen to stall one for 123 s.
    #[serde(with = "duration")]
    pub write_stall_timeout: Duration,
    /// Idle after half-close: once the server closed its side, the
    /// client-to-server direction is closed after this long without a
    /// byte moving, counted from the close or the last byte. Connections
    /// that were never half-closed have no idle timeout.
    #[serde(with = "duration")]
    pub uplink_idle_timeout: Duration,
    /// Idle after half-close the other way: the server-to-client direction
    /// once the client closed its side. Data the client sent may still be
    /// on its way to the server, in buffers further on where the relay
    /// cannot see it move, while the answer waits for it.
    #[serde(with = "duration")]
    pub downlink_idle_timeout: Duration,
    /// The congestion control of sail's own TCP connections, those
    /// outbounds dial and those inbounds accept, as the kernel names it
    /// (`bbr`, `cubic`); empty, the system's (`net.ipv4.tcp_congestion_control`).
    /// `bbr` on the mobile, desktop and router profiles, the system's on the
    /// server's; a server takes BBR with `bbr` here or, for every program on
    /// it, `net.ipv4.tcp_congestion_control = bbr` (with `tcp_bbr` loaded).
    /// Linux and Android only; other systems choose it themselves. One the
    /// system refuses, not built or loaded, or, without `CAP_NET_ADMIN` as
    /// an Android app is, not in `net.ipv4.tcp_allowed_congestion_control`,
    /// leaves the system's, and the log says once which is used. TCP Brutal,
    /// where a multiplexed connection negotiates it, replaces it on that
    /// connection. A sail extension, as Xray's `sockopt.tcpcongestion`:
    /// sing-box and Mihomo leave it to the system.
    pub tcp_congestion: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Udp {
    /// The buffer a datagram is read into, in KiB: 64 holds the largest
    /// UDP payload (65535 bytes), and a smaller one drops bigger datagrams.
    /// One per UDP session and one per inbound datagram, reused.
    pub datagram_buffer_size: usize,
    /// Datagrams queued towards outbounds.
    pub uplink_channel_size: usize,
    /// Datagrams queued towards a TUN.
    pub downlink_channel_size: usize,
    /// How often idle UDP sessions are looked for.
    #[serde(with = "duration")]
    pub session_check_interval: Duration,
}

/// The TUN inbound's TCP/IP stack.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Netstack {
    /// The hard memory and flow budget: `mobile`, `router`, `desktop` or
    /// `server`.
    pub budget: NetstackBudget,
    /// Packets read from or written to the device at a time.
    pub batch_size: usize,
    /// Linux: GSO/GRO offload, which needs `batch_size` to hold a whole
    /// 64 KiB super-packet at the configured MTU.
    pub offload: bool,
    /// Application commands and accepted connections queued per runner.
    pub command_channel_size: usize,
    /// Datagrams queued from the stack towards NAT.
    pub udp_uplink_channel_size: usize,
    /// The receive window a TCP connection of the stack starts with, in
    /// KiB, reserved from the budget when it opens: the budget's TCP bytes
    /// over this bound how many connections the stack holds at once.
    pub receive_window: usize,
    /// The most a connection's receive window grows to while it is read as
    /// fast as it arrives, in KiB, each step reserved when granted; equal to
    /// `receive_window`, windows do not grow.
    pub receive_window_max: usize,
    /// What a read of a connection takes from the stack beyond what the
    /// reader has room for, in KiB, kept for its next reads: one exchange
    /// with the stack's task brings this much rather than one relay
    /// buffer. The bytes held are charged to the budget's TCP bytes, as the
    /// stack's own are, and a read the budget has no room for takes only
    /// what the reader asked; on a busy mobile stack that is often the case,
    /// as intended (not a reason to grow the budget). Zero reads no more
    /// than asked. Measured on the router profile; a judgement on others.
    pub read_ahead: usize,
    /// The most a TUN connection holds for its client, in KiB: sent and not
    /// yet acknowledged, or waiting to be sent. A relay's write beyond it
    /// waits for the client's acknowledgments, as `inbound.tcp_send_buffer`
    /// does for an inbound's socket; without it, a fast download holds up
    /// to the client's receive window in the budget's TCP bytes. Zero, no
    /// limit but the client's window and the budget.
    pub send_buffer: usize,
}

/// A budget preset of the TUN inbound's stack.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetstackBudget {
    Mobile,
    Router,
    Desktop,
    Server,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Inbound {
    /// How long a client has to finish its protocol's handshake.
    #[serde(with = "duration")]
    pub handshake_timeout: Duration,
    /// Streams of one multiplexed connection handshaking at once.
    pub multiplex_accept_concurrency: usize,
    /// Resets accepted TCP connections on close instead of closing them
    /// gracefully: sockets are reclaimed at once, and whatever is still
    /// queued for the peer is lost.
    pub tcp_abort_on_close: bool,
    /// What an accepted TCP connection (an inbound's, or one `auto_redirect`
    /// takes) keeps queued for a client that reads slower than it is sent
    /// to, or not at all, in KiB; zero leaves
    /// it to the system, which on Linux grows it up to the largest of
    /// `net.ipv4.tcp_wmem` (4 MiB) while the connection goes fast. Linux
    /// keeps twice what is set, for its own bookkeeping.
    pub tcp_send_buffer: usize,
    /// The most an accepted TCP connection's send buffer grows to, in KiB,
    /// from `inbound.tcp_send_buffer`, out of `memory.transfer_budget`:
    /// it doubles while it, rather than the network or the client's
    /// reading, holds the client's transfer back, and returns to
    /// `tcp_send_buffer` when the connection goes a second without filling
    /// it, or a second without taking what fills it (a client that stopped
    /// reading). Zero, or not more than `tcp_send_buffer`, or a system
    /// other than Linux and Android: no growth.
    #[serde(default)]
    pub tcp_send_buffer_max: usize,
    /// What an accepted TCP connection (an inbound's, or one
    /// `auto_redirect` takes) holds received and not yet read by sail
    /// (`SO_RCVBUF`), in KiB; zero leaves it to the system, which on Linux
    /// grows it up to the largest of `net.ipv4.tcp_rmem` (6 MiB) while a
    /// client sends faster than sail forwards, as an upload through a
    /// slower upstream does. Linux keeps twice what is set. A client on the
    /// LAN is a fraction of a millisecond away, so a small buffer does not
    /// slow it; sail's own connections upstream keep the system's tuning.
    #[serde(default)]
    pub tcp_receive_buffer: usize,
    /// Proxied sessions (connections, UDP sessions, and streams of a
    /// multiplexed or QUIC inbound) live at once; 0, no limit. One more
    /// waits for one to end, `MAX_CONNECTIONS_WAIT` at most, and is then
    /// refused. A sail extension: neither sing-box nor Mihomo bounds them.
    #[serde(default)]
    pub max_connections: usize,
    /// Connections of one inbound in their handshake at once, those that
    /// never finish it included; 0, no limit. One more is closed at once.
    /// What never authenticates takes 25 to 37 KiB until the handshake
    /// deadline in a musl build (mimalloc), 9 to 20 with glibc (measured).
    /// A sail extension: sing-box does not bound them.
    #[serde(default)]
    pub max_handshakes: usize,
    /// The most of them one source address may hold; 0, no limit, the
    /// default: behind a carrier's NAT many clients share an address.
    #[serde(default)]
    pub max_handshakes_per_source: usize,
    /// The memory kept free, in percent of what the system or the
    /// process's cgroup gives: with less free, connections still in their
    /// handshake are held back (app/inbound/admission.rs); 0, memory is
    /// not looked at. Where free memory cannot be read (Windows, macOS),
    /// no pressure is seen, but a full inbound still closes its stalled
    /// handshakes. A sail extension.
    #[serde(default)]
    pub memory_reserve: u32,
    /// Under memory pressure, a connection in its handshake for longer is
    /// closed, the oldest first.
    #[serde(default = "handshake_stall", with = "duration")]
    pub handshake_stall: Duration,
    /// Handshakes in flight across the inbounds are pressure, as memory
    /// short of the reserve is, past the open-file limit divided by this;
    /// 0, they are not looked at.
    #[serde(default)]
    pub handshake_descriptor_share: u32,
    /// Under memory pressure, a source address four of whose handshakes
    /// failed in the last minute, none succeeding since, is refused at
    /// accept; a handshake that succeeds clears its failures.
    #[serde(default)]
    pub score_sources: bool,
}

/// A sing-box based server's in production, whose admission this follows.
fn handshake_stall() -> Duration {
    Duration::from_secs(3)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Quic {
    pub max_concurrent_streams: u32,
    #[serde(with = "duration")]
    pub client_idle_timeout: Duration,
    #[serde(with = "duration")]
    pub client_keep_alive_interval: Duration,
    #[serde(with = "duration")]
    pub server_idle_timeout: Duration,
    /// How long a client has to finish a QUIC handshake with an inbound;
    /// the idle timeout applies from then on. quic-go's (sing-box's)
    /// `DefaultHandshakeIdleTimeout`: a client that sends an Initial and
    /// falls silent is dropped then, not after the idle timeout.
    #[serde(with = "duration")]
    pub server_handshake_timeout: Duration,
    /// Zero sends none.
    #[serde(with = "duration")]
    pub server_keep_alive_interval: Duration,
    /// What a Hysteria2 or TUIC connection's peer may send ahead of what
    /// is read, all streams together, in KiB, to begin with. It grows
    /// with its streams' windows (to 1.5 times the largest) and, as they
    /// do, while it is read about as fast as data arrives, up to
    /// `receive_window_max`.
    pub receive_window: usize,
    /// What a Hysteria2 or TUIC stream's peer may send ahead of what is
    /// read, in KiB, to begin with. A stream read about as fast as data
    /// arrives (more than half its window within four times that share of
    /// a round trip) doubles it, as quic-go's do, up to
    /// `stream_window_max`; a stream nobody reads keeps what it had.
    pub stream_window: usize,
    /// What a Hysteria2 or TUIC connection keeps sent and not yet
    /// acknowledged, in KiB, at the least: it follows twice the
    /// congestion window, up to `send_window_max`.
    pub send_window: usize,
    /// The largest a stream's receive window grows to, in KiB.
    pub stream_window_max: usize,
    /// The largest a connection's receive window grows to, in KiB.
    pub receive_window_max: usize,
    /// The largest the send window grows to, in KiB.
    pub send_window_max: usize,
    /// Hysteria2's and TUIC's connections give their peer credit for
    /// stream data as it arrives, lent out of `memory.transfer_budget`
    /// until the stream reads it, rather than only once it is read. A
    /// stream nobody reads (a client that stopped reading) then holds its
    /// own window and no more, where it would otherwise hold its share of
    /// the connection's window and, with a few others, stop every stream
    /// on the connection (sail#18). Where the budget is spent, credit comes
    /// back on read, as with it off.
    pub credit_on_receipt: bool,
    /// The receive buffer (`SO_RCVBUF`) asked for the UDP socket of a QUIC
    /// endpoint (Hysteria2, TUIC, the quic transport, DNS over QUIC), in
    /// KiB: the datagrams the system holds while sail is busy, and drops
    /// beyond. Zero leaves the system's, 64 KiB on Windows and about
    /// 200 KiB on Linux. The system may give less than is asked: Linux
    /// keeps twice the number for its own bookkeeping and stops at
    /// `net.core.rmem_max`, past which sail is given more only with
    /// CAP_NET_ADMIN. sing-box's QUIC (quic-go) asks for 7 MiB, Chromium
    /// for 1 MiB.
    pub udp_receive_buffer: usize,
    /// The send buffer (`SO_SNDBUF`) of the same sockets, in KiB; zero
    /// leaves the system's. On Linux, twice the number and no more than
    /// `net.core.wmem_max` unless sail has CAP_NET_ADMIN. quic-go asks
    /// for 7 MiB here too.
    pub udp_send_buffer: usize,
    /// The datagrams a QUIC endpoint takes from its UDP socket in one
    /// system call, at most 32; zero for quinn's 32. The endpoint keeps
    /// room for this many for as long as it lives, each up to 64 datagrams
    /// that Linux coalesced (GRO): about 3 MB at 32.
    #[serde(default)]
    pub udp_receive_batch: usize,
}

/// What `quic.udp_receive_buffer`, `quic.udp_send_buffer` and
/// `quic.udp_receive_batch` ask for, buffers in bytes; zero leaves the
/// system's, or quinn's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpBuffers {
    pub receive: usize,
    pub send: usize,
    pub receive_batch: usize,
}

impl Quic {
    /// The buffers its UDP sockets ask the system for.
    pub fn udp_buffers(&self) -> UdpBuffers {
        UdpBuffers {
            receive: self.udp_receive_buffer.saturating_mul(1024),
            send: self.udp_send_buffer.saturating_mul(1024),
            receive_batch: self.udp_receive_batch,
        }
    }
}

/// What the process's growable transfer buffers may take
/// (`runtime::transfer_budget`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    /// What Hysteria2's and TUIC's windows and the send buffers of
    /// accepted TCP connections (`inbound.tcp_send_buffer_max`) together
    /// may grow by past their starting sizes, in KiB: one budget for the
    /// process, so that one transfer can take a large share and many share
    /// it. A buffer the budget cannot grow stays as it is. Sail/1's
    /// streams that nothing reads are charged their windows here while
    /// they are kept (`mux.stall_timeout`).
    pub transfer_budget: usize,
    /// The memory buffers leave free, in KiB: while less than this is free
    /// (the least of MemAvailable and the process's cgroups' limits less
    /// their use, read at most once a second), buffers grow by no more
    /// than is free beyond it, and not at all below it. Buffers that grew
    /// keep what they have. Zero, or memory that cannot be read (outside
    /// Linux and Android), leaves only `transfer_budget`.
    pub free_memory_floor: usize,
    /// The anonymous memory (RssAnon) past which the process's buffers
    /// stop growing, in KiB, read as `free_memory_floor`'s memory is; zero
    /// for none.
    pub anon_memory_max: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Ws {
    /// Half-closes a WebSocket stream instead of closing it, for servers
    /// that relay after the client stops sending.
    pub half_close: bool,
}

/// Retrying DNS servers, and resolving both families.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// Attempts per query to one server.
    pub max_retries: usize,
    /// How long an AAAA answer is waited for after the A answer.
    #[serde(with = "duration")]
    pub dualstack_delay: Duration,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Stats {
    /// Finished connections kept for the API to list.
    pub max_recent_connections: usize,
}

/// Starting and stopping.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    /// On SIGTERM or Ctrl-C, how long the TCP connections open may finish
    /// once no new ones are taken; 0 stops at once. A second signal stops
    /// at once too.
    #[serde(with = "duration")]
    pub drain_timeout: Duration,
}

/// The streams of a multiplexed connection: sing-mux's smux and yamux,
/// AnyTLS, amux.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Mux {
    /// The largest a stream's receive window grows to, in KiB (yamux,
    /// amux). Windows start at 256 KiB and double while a stream is read
    /// faster than its window lets data in, so that one stream can fill a
    /// long fat link. h2mux's windows, which do not grow, are a quarter of
    /// it a stream and twice it a connection.
    pub stream_window_max: usize,
    /// What a stream of a protocol without windows (smux, AnyTLS) holds
    /// unread, in KiB, before its connection stops being read.
    pub stream_buffer: usize,
    /// A stream whose received data nothing has read for this long is
    /// reset, alone, so that it holds up neither its connection nor its
    /// memory. Hysteria2's and TUIC's streams take it too, and with
    /// `quic.credit_on_receipt` give back what was lent them. Sail/1's
    /// streams are kept instead, their windows charged to
    /// `memory.transfer_budget`, and reset only where it has no room.
    #[serde(with = "duration")]
    pub stall_timeout: Duration,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self::profile(Profile::default())
    }
}

impl Default for Relay {
    fn default() -> Self {
        RuntimeOptions::default().relay
    }
}

impl Default for Udp {
    fn default() -> Self {
        RuntimeOptions::default().udp
    }
}

impl Default for Netstack {
    fn default() -> Self {
        RuntimeOptions::default().netstack
    }
}

impl Default for Inbound {
    fn default() -> Self {
        RuntimeOptions::default().inbound
    }
}

impl Default for Quic {
    fn default() -> Self {
        RuntimeOptions::default().quic
    }
}

impl Default for Ws {
    fn default() -> Self {
        RuntimeOptions::default().ws
    }
}

impl Default for Dns {
    fn default() -> Self {
        RuntimeOptions::default().dns
    }
}

impl Default for Stats {
    fn default() -> Self {
        RuntimeOptions::default().stats
    }
}

impl Default for Mux {
    fn default() -> Self {
        RuntimeOptions::default().mux
    }
}

impl RuntimeOptions {
    /// The options a profile starts from.
    pub fn profile(profile: Profile) -> Self {
        RuntimeOptions {
            profile,
            ..Self::tuned(profile)
        }
    }

    fn tuned(profile: Profile) -> Self {
        let desktop = RuntimeOptions {
            profile: Profile::Desktop,
            sessions_for_memory: None,
            relay: Relay {
                buffer_size: 16,
                buffer_max_size: 128,
                buffer_pool: 1024,
                write_stall_timeout: Duration::from_secs(300),
                uplink_idle_timeout: Duration::from_secs(300),
                downlink_idle_timeout: Duration::from_secs(300),
                // The client profiles' (mobile, desktop, router), by the
                // user's decision; the server's is the system's. Where the
                // kernel's TCP limits a connection, BBR against the system's
                // cubic, the same binary, the sending side (mobile profile,
                // uploads, medians of 3, 3 protocols): 24-42x at 0.5% loss,
                // 49-74x at 2%, 29-38x in loss bursts, 2.0-2.5x at 150 ms,
                // 1.5x at 300 ms, 2.1-3.3x at 5% reordering, 0.99x at 10
                // Mbit/s; the router profile's 35-37x, 68-75x, 30-47x,
                // 1.9-2.6x, 1.6-1.7x, 2.1-2.8x and 0.99x; the desktop's
                // (trojan) 19x at 0.5% loss, 62x at 2%, 50x in bursts, 1.8x
                // at 150 ms, 1.5x at 300 ms. It retransmits 0.5% of what it
                // sends at 0.5% loss (cubic 3.3%), 2.1% at 2% (2.2%), 2.8%
                // in bursts (4.3%), 0.02% at 5% reordering (4.1%), 0.07% at
                // 10 Mbit/s (0.6%); on the router and desktop profiles at
                // most 2.6% in any cell's median. Under 25 +/- 10 ms of
                // jitter each way it retransmits 0.02-0.07% (cubic
                // 0.03-0.09%), uploads are 2.9-3.8x cubic, and its rounds
                // split, about 420 against 510 Mbit/s (server profile, 9
                // rounds): BBR's min_rtt filter keeps the low tail of the
                // delays, 37 ms against 54 in the fast rounds, and its
                // window, twice the bandwidth by that, falls below what the
                // median round trip of 78 ms needs. Where it keeps 24-29 ms
                // the estimate collapses, to 90-127 Mbit/s against cubic's
                // 150-210 (2 of 3 rounds of one cell, the server sending).
                // Its cost: beside a kernel cubic flow through 100
                // Mbit/s at 40 ms, it takes 0.90 of a queue of half the
                // path's BDP, as the system's own bbr does, and 0.31 of one
                // of 4x (cubic against cubic 0.41-0.52; 9 rounds). On a
                // client, that is the user's own last mile (measured
                // 2026-10-25 to 27).
                tcp_congestion: "bbr".to_owned(),
            },
            udp: Udp {
                datagram_buffer_size: 64,
                uplink_channel_size: 256,
                downlink_channel_size: 256,
                session_check_interval: Duration::from_secs(10),
            },
            netstack: Netstack {
                budget: NetstackBudget::Desktop,
                batch_size: 32,
                offload: false,
                command_channel_size: 512,
                udp_uplink_channel_size: 256,
                // As the server profile's, whose measurement this shares the code of;
                // 2000 connections opened with it (measured).
                receive_window: 16,
                receive_window_max: 256,
                read_ahead: 64,
                // As the server profile's, measured there: Trojan over TUN, 1 GiB, 4
                // streams, 3 interleaved rounds, medians: download 6682 Mbit/s without a
                // limit, 5687 at 128 KiB, 6675 at 256 and 6809 at 1024, the client's peak
                // RSS 95 MB without and 85 at 256 or 1024; upload unchanged. Four times
                // what still cost nothing, as a margin (a judgment).
                send_buffer: 1024,
            },
            inbound: Inbound {
                handshake_timeout: Duration::from_secs(60),
                multiplex_accept_concurrency: 256,
                tcp_abort_on_close: false,
                tcp_send_buffer: 0,
                tcp_send_buffer_max: 0,
                tcp_receive_buffer: 0,
                max_connections: 0,
                // A judgment: a client's local inbounds see few at once.
                max_handshakes: 1024,
                max_handshakes_per_source: 0,
                memory_reserve: 0,
                handshake_stall: handshake_stall(),
                handshake_descriptor_share: 0,
                score_sources: false,
            },
            quic: Quic {
                max_concurrent_streams: 1024,
                client_idle_timeout: Duration::from_secs(15),
                client_keep_alive_interval: Duration::from_secs(3),
                server_idle_timeout: Duration::from_secs(120),
                server_handshake_timeout: Duration::from_secs(5),
                server_keep_alive_interval: Duration::ZERO,
                // Judgments, to be measured (sail#9): windows start as
                // quic-go's do and grow while they are read about as fast
                // as data arrives, a stream to 16 MiB (four streams fill
                // 450 Mbit/s at 300 ms each), a connection to 64 MiB.
                receive_window: 768,
                stream_window: 512,
                send_window: 1 << 10,
                stream_window_max: 16 << 10,
                receive_window_max: 64 << 10,
                send_window_max: 32 << 10,
                credit_on_receipt: true,
                // 7 MiB to receive, quic-go's. In Linux's 208 KiB a sender
                // at some hundred Mbit/s on a path of 50 or 150 ms lost
                // every fourth batch of datagrams, and a Hysteria2
                // download ran at a third of what it does with 7 MiB
                // (measured, with the 1 MiB that still lost 1 to 5%); a
                // larger send buffer changed nothing. 2 MiB lost nothing
                // either, and 4 to 16 MiB did the same: 7 rather than 2
                // is a judgment, for margin.
                udp_receive_buffer: 7168,
                udp_send_buffer: 0,
                udp_receive_batch: 0,
            },
            memory: Memory {
                transfer_budget: 256 << 10,
                // Judgments: what a desktop's other programs may want
                // next, and no bound of its own.
                free_memory_floor: 128 << 10,
                anon_memory_max: 0,
            },
            ws: Ws { half_close: false },
            dns: Dns {
                max_retries: 4,
                dualstack_delay: Duration::from_millis(250),
            },
            stats: Stats {
                max_recent_connections: 0,
            },
            lifecycle: Lifecycle {
                drain_timeout: Duration::ZERO,
            },
            mux: Mux {
                stream_window_max: 16 << 10,
                stream_buffer: 256,
                stall_timeout: Duration::from_secs(60),
            },
        };
        match profile {
            Profile::Desktop => desktop,
            Profile::Mobile => RuntimeOptions {
                relay: Relay {
                    buffer_size: 8,
                    buffer_max_size: 64,
                    // A judgment: a phone's memory is short, and it
                    // carries few connections busy at once.
                    buffer_pool: 256,
                    ..desktop.relay
                },
                udp: Udp {
                    uplink_channel_size: 128,
                    downlink_channel_size: 128,
                    ..desktop.udp
                },
                netstack: Netstack {
                    budget: NetstackBudget::Mobile,
                    batch_size: 1,
                    offload: false,
                    command_channel_size: 256,
                    udp_uplink_channel_size: 128,
                    // Measured over a Linux TUN, Trojan, four upload streams against
                    // sing-box on the same cores: growing from 4 KiB to 64 KiB carried 0.91
                    // of sing-box's upload, to 128 KiB 0.98 and to 256 KiB 0.98 (medians of
                    // 3; download 0.97 at all three). Starting at 4 KiB, 2000 connections
                    // reserve 8 MiB of the budget's 12 whatever the ceiling (7.4 to 7.8
                    // MiB used at 64, 128 and 256); at 16 KiB only 653 of 2000 opened.
                    receive_window: 4,
                    receive_window_max: 128,
                    read_ahead: 32,
                    // Measured as the desktop's: download 3838 Mbit/s without a limit,
                    // 3806 at 128 KiB, 3785 at 256 and 3759 at 1024, peak RSS the same;
                    // twice what still cost nothing.
                    send_buffer: 256,
                },
                inbound: Inbound {
                    multiplex_accept_concurrency: 64,
                    // A judgment, as the router's: a phone's VPN extension
                    // may be killed at 50 MiB, and a session costs about
                    // 26 KiB idle, more under data (measured: 300 held
                    // took 8 to 9 MiB; 2000 a 88 to 101 MiB peak). 512
                    // keeps the sessions to about 13 MiB.
                    max_connections: 512,
                    ..desktop.inbound
                },
                quic: Quic {
                    max_concurrent_streams: 256,
                    // An iOS network extension may be killed at 50 MiB.
                    // What windows hold is what a phone's memory goes to:
                    // four streams at fixed 32/8/16 MiB windows held 23-49
                    // MB of anonymous memory, 13-16 at 8/2/8 (measured,
                    // glibc, sail#9). With these, four streams cold at
                    // 150 and 300 ms or 2% loss came down at 1.21-1.43
                    // times sing-box's and held at most 43.8 MB (measured,
                    // sail#9); the maxima and the budget are judgments.
                    receive_window: 384,
                    stream_window: 256,
                    send_window: 512,
                    stream_window_max: 8 << 10,
                    receive_window_max: 32 << 10,
                    send_window_max: 16 << 10,
                    // A judgment: a phone's links are not those the
                    // 7 MiB was measured for, and its memory is short.
                    udp_receive_buffer: 1024,
                    ..desktop.quic
                },
                // The budget, as the windows' maxima, a judgment (see the
                // windows').
                memory: Memory {
                    transfer_budget: 24 << 10,
                    // A judgment: Android kills background apps before
                    // MemAvailable runs out.
                    free_memory_floor: 64 << 10,
                    // Clear of the 50 MB: four streams cold peaked at
                    // 41.4 MB with it, 42.1 without, as fast (measured,
                    // glibc, sail#9).
                    anon_memory_max: 40 << 10,
                },
                mux: Mux {
                    stream_window_max: 8 << 10,
                    ..desktop.mux
                },
                ..desktop
            },
            Profile::Router => RuntimeOptions {
                relay: Relay {
                    buffer_size: 4,
                    // Trojan over TUN, one core, 8 streams, medians of 3:
                    // download 4347 Mbit/s at 16 KiB (0.81 of sing-box's),
                    // 4881 at 32, 5551 at 64 (1.03), 5475 at 128; upload
                    // 5155 to 5257 at all four; CPU a GiB down 3.53 s at 16,
                    // 2.86 at 64 (measured). An idle session holds no
                    // buffer, a stalled writer one full one: if every one of
                    // the 512 sessions `inbound.max_connections` allows
                    // stalled both ways, 64 MiB, which is why it caps them.
                    buffer_max_size: 64,
                    // A judgment, as the mobile profile's.
                    buffer_pool: 256,
                    ..desktop.relay
                },
                udp: Udp {
                    uplink_channel_size: 64,
                    downlink_channel_size: 64,
                    ..desktop.udp
                },
                netstack: Netstack {
                    budget: NetstackBudget::Router,
                    batch_size: 4,
                    offload: false,
                    command_channel_size: 128,
                    udp_uplink_channel_size: 64,
                    // As mobile's: at 16 KiB 436 of 2000 connections opened, at 4 KiB 1753,
                    // which another budget than the TCP bytes then bounded (2 KiB opened
                    // 1736); one upload stream carried 590 to 736 Mbit/s (measured).
                    // Since the 512 sessions of `inbound.max_connections`, 512 of 2000 open
                    // at any ceiling. A ceiling of 128 or 256 took four upload streams over
                    // Trojan from 0.67 of sing-box's to 0.74-0.75, not enough to be worth
                    // its reservations (medians of 3).
                    receive_window: 4,
                    receive_window_max: 64,
                    // Trojan over TUN, 1 GiB, 3 interleaved rounds: upload
                    // 3766 Mbit/s without, 4807 at 32 KiB, 4962 at 64 KiB
                    // (3.65, 3.20, 3.06 CPU s a GiB); download unchanged
                    // (measured).
                    read_ahead: 64,
                    // As mobile's (not measured on this profile).
                    send_buffer: 256,
                },
                inbound: Inbound {
                    multiplex_accept_concurrency: 32,
                    // Twenty LAN clients that stopped reading hold 6 MiB
                    // with it, 50 without (measured); twice this, what
                    // Linux keeps, carries 200 Mbit/s at 20 ms.
                    tcp_send_buffer: 256,
                    // Four downloads by a client 8 ms away (Wi-Fi), through
                    // Hysteria2 or TUIC, in a 64 MiB cgroup, at fixed
                    // sizes: 0.34 of sing-box's at 256 KiB, 0.57-0.59 at
                    // 512, 0.85-0.86 at 1 MiB, 0.99-1.02 at 2 MiB, which
                    // peaked at 50.8-52.8 MiB (measured, sail#10). The
                    // size that reached sing-box's, out of the budget:
                    // grown from it, 0.88-0.91 at a 37.8 MiB peak, 42.2
                    // with 20 stalled clients beside them (measured, sail#10).
                    tcp_send_buffer_max: 2048,
                    // Uploads through Hysteria2 or TUIC queued 18-22 MB
                    // in four LAN connections' receive buffers without it.
                    // A client 8 ms away (Wi-Fi) uploaded as fast with 1 MiB
                    // as with the system's tuning, 2706 and 2199 Mbit/s
                    // against 2631 and 2071; 512 KiB held Hysteria2 to 2157,
                    // 256 to about 1080 (measured, sail#9).
                    tcp_receive_buffer: 1024,
                    // A settled session is 24 to 39 KiB, trojan's the
                    // most (one still connecting likely more; not
                    // measured). In a 64 MiB budget with 2000
                    // trojan connections held and bursts of new ones: 1024
                    // was killed at 500 a second, 768 at 1000, and 512 and
                    // 384 lived through both (measured); the most that did.
                    // Fewer with less memory: `router_sessions`.
                    max_connections: 512,
                    // A judgment, from the above: half the sessions the
                    // budget carries, at up to 37 KiB each in a musl build
                    // (measured), 9 MiB.
                    max_handshakes: 256,
                    // As the server's (sail#15), but for the sources: a LAN
                    // client that mistyped its password three times and
                    // then got in was refused 9 times of 10 under pressure
                    // when they were scored as on a server (measured).
                    memory_reserve: 20,
                    handshake_descriptor_share: 8,
                    score_sources: false,
                    ..desktop.inbound
                },
                quic: Quic {
                    max_concurrent_streams: 128,
                    // A router must not be killed at 64 MiB, with 16 MiB
                    // to spare. In a 64 MiB cgroup a router build's peak
                    // was 10-27 MB of anonymous memory, what the windows
                    // held, 13.6 of its file's pages and 14-24 of socket
                    // buffers (measured, sail#9). With
                    // `inbound.tcp_receive_buffer`, four streams cold at
                    // 150 and 300 ms or 2% loss came down at 1.10-1.20
                    // times sing-box's with a 12 MiB budget and a 42.5 MiB
                    // peak, 1.21-1.36 with 16 MiB but 49.5, 0.84-0.97 with
                    // 8 (measured, sail#9): the most that keeps 16 MiB. A
                    // connection takes four times a stream, so that
                    // streams a LAN client stopped reading, which keep
                    // what they grew to, leave room for the rest (at 8 MiB
                    // a stream, four of them froze a 32 MiB connection for
                    // good: #4).
                    receive_window: 192,
                    stream_window: 128,
                    send_window: 256,
                    stream_window_max: 4 << 10,
                    receive_window_max: 16 << 10,
                    // In a 64 MiB cgroup, uploads to a sing-box server at
                    // 150 and 300 ms or 2% loss went at 0.94-1.17 times
                    // sing-box's with 12 MiB and a 16 MiB budget, peak
                    // 47.3 MiB, against 0.76-1.01 with 8; 16 or 24 MiB fit
                    // only under a 12 MiB budget, which took 0.1-0.2 off
                    // downloads (measured, sail#11).
                    send_window_max: 12 << 10,
                    // As mobile's.
                    udp_receive_buffer: 1024,
                    // In a 64 MiB cgroup, a quarter of quinn's 32 lowered
                    // downloads' peaks by 2-3 MiB, uploads' by up to 0.7
                    // (where only acknowledgments arrive, so little of the
                    // room is touched), and slowed no cell: on the LAN at
                    // 0 and 8 ms, at 150 and 300 ms, up to 5.7 Gbit/s
                    // (measured, sail#10).
                    udp_receive_batch: 8,
                    ..desktop.quic
                },
                memory: Memory {
                    // At most; `transfer_budget_for` the memory, 16 MiB at
                    // 64 MiB.
                    transfer_budget: 64 << 10,
                    // The 16 MiB a router keeps to spare. With 16 MiB
                    // taken by another process first, no budget was
                    // killed in 64 MiB, and uploads at 150 and 300 ms were
                    // held to 0.7 to 0.9 of what a 12 MiB budget without
                    // it carried (measured, sail#9).
                    free_memory_floor: 16 << 10,
                    ..desktop.memory
                },
                // As mobile's: with the kernel's TCP buffers of a 256 or
                // 512 MB router, one connection is held to 100 or 200
                // Mbit/s at 100 ms whatever the window (measured), and a
                // session's windows grow by four times this at most, which
                // at 4 MiB twenty stuck streams used up, holding four
                // downloads to 82 Mbit/s instead of 185 (measured); h2mux
                // follows, at 2 MiB a stream.
                mux: Mux {
                    stream_window_max: 8 << 10,
                    ..desktop.mux
                },
                ..desktop
            },
            Profile::Server => RuntimeOptions {
                relay: Relay {
                    buffer_size: 16,
                    buffer_max_size: 256,
                    // The system's, by the user's decision: a server's
                    // egress is shared, and BBR takes 0.90 of a shallow
                    // queue from the cubic flows beside it (see the
                    // desktop profile's). It would gain on the weak cells
                    // as a client does (server profile, against the
                    // system's cubic: 29-44x at 0.5% loss, 45-76x at 2%,
                    // 37-50x in bursts, 2.6-4.7x at 150 ms, 2.7-2.9x at 300
                    // ms; measured 2026-10-24).
                    tcp_congestion: String::new(),
                    ..desktop.relay
                },
                udp: Udp {
                    uplink_channel_size: 1024,
                    ..desktop.udp
                },
                netstack: Netstack {
                    budget: NetstackBudget::Server,
                    batch_size: 64,
                    offload: true,
                    command_channel_size: 1024,
                    udp_uplink_channel_size: 1024,
                    // Measured as mobile's: fixed at 16 KiB, one upload stream carried 319
                    // Mbit/s; growing to 256 KiB, 1811; to 1024 KiB, 1693.
                    receive_window: 16,
                    receive_window_max: 256,
                    read_ahead: 64,
                    // Measured: see the desktop profile's.
                    send_buffer: 1024,
                },
                inbound: Inbound {
                    multiplex_accept_concurrency: 1024,
                    // sing-box's for a TLS or REALITY handshake
                    // (`C.TCPTimeout`); the slowest whole setup measured,
                    // REALITY over 300 ms and 5% loss, took 4.7 s.
                    handshake_timeout: Duration::from_secs(15),
                    // A judgment: at up to 37 KiB each in a musl build, 20
                    // with glibc (measured), 150 or 80 MiB
                    // when full; 1000 new connections a second over a
                    // 300 ms path keep about 900 in their handshake.
                    max_handshakes: 4096,
                    // A sing-box based server's in production: a 20%
                    // reserve, and handshakes past an eighth of the
                    // open-file limit (sail#15).
                    memory_reserve: 20,
                    handshake_descriptor_share: 8,
                    score_sources: true,
                    ..desktop.inbound
                },
                quic: Quic {
                    max_concurrent_streams: 4096,
                    ..desktop.quic
                },
                memory: Memory {
                    // Judgment: what a server's many clients' windows may
                    // grow by, all together.
                    transfer_budget: 1 << 20,
                    ..desktop.memory
                },
                // Kubernetes' default grace period (terminationGracePeriod-
                // Seconds); the systemd unit's stop timeout leaves room
                // past it.
                lifecycle: Lifecycle {
                    drain_timeout: Duration::from_secs(30),
                },
                ..desktop
            },
        }
    }

    /// Sets the option at `key`, a dotted path such as `relay.buffer_size`,
    /// from its text: a number, `true` or `false`, or a duration like `10s`.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        let mut tree = serde_json::to_value(&*self)?;
        let mut node = &mut tree;
        for part in key.split('.') {
            node = node
                .get_mut(part)
                .filter(|_| !part.is_empty())
                .ok_or_else(|| anyhow!("unknown runtime option \"{}\"", key))?;
        }
        if node.is_object() {
            return Err(anyhow!(
                "runtime option \"{}\" is a group; set one of its options",
                key
            ));
        }
        *node = match serde_json::from_str::<serde_json::Value>(value) {
            Ok(v @ (serde_json::Value::Number(_) | serde_json::Value::Bool(_))) => v,
            _ => serde_json::Value::String(value.to_string()),
        };
        let profile = self.profile;
        // A setting of the sessions is the user's, not the memory's.
        let fitted = self
            .sessions_for_memory
            .filter(|_| key != "inbound.max_connections");
        *self = serde_json::from_value(tree)
            .map_err(|e| anyhow!("runtime option \"{}\": {}", key, e))?;
        // Not options, so not in the tree: kept as they were.
        self.profile = profile;
        self.sessions_for_memory = fitted;
        Ok(())
    }

    /// Applies `key=value` settings in order.
    pub fn set_all<'a>(&mut self, settings: impl IntoIterator<Item = &'a str>) -> Result<()> {
        for setting in settings {
            let (key, value) = setting.split_once('=').ok_or_else(|| {
                anyhow!("invalid runtime option \"{}\", expected key=value", setting)
            })?;
            self.set(key.trim(), value.trim())?;
        }
        Ok(())
    }

    /// What `memory`, in bytes, the system's or its cgroup's, carries:
    /// the transfer budget lowered to `transfer_budget_for` it, and the
    /// router profile's sessions, `inbound.max_connections`, to
    /// `router_sessions` of it, where those are less; nothing when the
    /// memory is unknown.
    pub fn fit_to_memory(&mut self, memory: Option<u64>) {
        let Some(mib) = memory.map(|bytes| bytes >> 20) else {
            return;
        };
        self.memory.transfer_budget = self.memory.transfer_budget.min(transfer_budget_for(mib));
        if self.profile != Profile::Router {
            return;
        }
        let sessions = router_sessions(mib);
        if sessions < self.inbound.max_connections {
            self.inbound.max_connections = sessions;
            self.sessions_for_memory = Some((sessions, mib));
        }
    }
}

/// The transfer budget, in KiB, for `mib` MiB of memory: a quarter of
/// it.
///
/// Four streams cold at 150 and 300 ms or 2% loss, the router profile in a
/// cgroup of 64 MiB, with `memory.free_memory_floor` at 16 MiB: a 16 MiB
/// budget peaked at 44.0 to 46.6 MiB (12 MiB: 43.2) and came down at 0.99
/// to 1.43 times a sing-box client's, Hysteria2 at 300 ms at 1.02 and 1.11
/// (12 MiB: 0.91 to 1.27); 24 MiB with
/// 8 and 32 MiB windows came down faster but peaked at 56.2. In 128 MiB,
/// 32 MiB peaked at 47.2, as fast as 16 for four streams (measured,
/// sail#9). Between and beyond them, a judgment.
pub fn transfer_budget_for(mib: u64) -> usize {
    (mib << 8) as usize
}

/// The sessions a router of `mib` MiB of memory (MemTotal) carries at
/// once: twice its MiB beyond the first 20, 64 to 512.
///
/// Measured in a qemu guest (a Debian kernel, sail's musl router build in
/// its initramfs, the LAN clients and the upstream outside it): a load of
/// echoes, 8 MiB downloads and uploads and 100 new connections a second,
/// with all the sessions but 24 stalled 60 s by readers that stopped while
/// the upstream kept sending. With 128 MiB, MemTotal 84 MiB: 128 and 192
/// sessions lived (MemAvailable down to 7 to 10 MiB at 192), 256 and more
/// were killed for memory. With 256 MiB, MemTotal 210 MiB, and 512 MiB,
/// MemTotal 462 MiB, 512 lived (MemAvailable down to 48 and 224 MiB). The
/// rule takes the step below the most that lived, 128 and 384, and the
/// line through them (a judgment between them and beyond).
pub fn router_sessions(mib: u64) -> usize {
    (mib.saturating_sub(20) * 2).clamp(64, 512) as usize
}

/// Durations as text, `10s`, both ways.
mod duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}ms", d.as_millis()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(de)?;
        crate::config::model::parse_duration(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn handshakes_are_bounded_as_sing_box_bounds_them() {
        // TLS and REALITY's (sing-box's C.TCPTimeout) for a server; QUIC's
        // as quic-go's handshake idle timeout, on every profile.
        let server = RuntimeOptions::profile(Profile::Server);
        assert_eq!(server.inbound.handshake_timeout, Duration::from_secs(15));
        assert_eq!(server.profile, Profile::Server);
        for profile in [
            Profile::Mobile,
            Profile::Desktop,
            Profile::Server,
            Profile::Router,
        ] {
            let options = RuntimeOptions::profile(profile);
            assert_eq!(
                options.quic.server_handshake_timeout,
                Duration::from_secs(5)
            );
            assert_eq!(options.profile, profile);
        }
    }

    use super::*;

    #[test]
    fn a_setting_changes_one_option() {
        let mut options = RuntimeOptions::profile(Profile::Mobile);
        options
            .set_all([
                "relay.buffer_size=32",
                "inbound.tcp_abort_on_close=true",
                "dns.dualstack_delay=1s",
            ])
            .unwrap();
        assert_eq!(options.relay.buffer_size, 32);
        assert!(options.inbound.tcp_abort_on_close);
        assert_eq!(options.dns.dualstack_delay, Duration::from_secs(1));
        // The rest stays as the profile has it, and so does the profile.
        assert_eq!(options.profile, Profile::Mobile);
        assert_eq!(
            options.relay.buffer_max_size,
            RuntimeOptions::profile(Profile::Mobile)
                .relay
                .buffer_max_size
        );
    }

    #[test]
    fn a_bad_setting_is_an_error_that_names_it() {
        let mut options = RuntimeOptions::default();
        let err = options.set("relay.bufer_size", "1").unwrap_err();
        assert_eq!(
            err.to_string(),
            "unknown runtime option \"relay.bufer_size\""
        );
        let err = options.set("relay", "1").unwrap_err();
        assert!(err.to_string().contains("is a group"), "{}", err);
        let err = options.set("relay.buffer_size", "big").unwrap_err();
        assert!(
            err.to_string()
                .starts_with("runtime option \"relay.buffer_size\""),
            "{}",
            err
        );
        let err = options.set_all(["relay.buffer_size"]).unwrap_err();
        assert!(err.to_string().contains("expected key=value"), "{}", err);
    }

    /// A QUIC socket asks for room to receive in, more where the links
    /// are fast, and keeps the system's to send from; a router's endpoint
    /// takes fewer datagrams at a time, for less memory.
    #[test]
    fn quic_sockets_ask_for_a_receive_buffer_by_profile() {
        for (profile, receive, receive_batch) in [
            (Profile::Mobile, 1 << 20, 0),
            (Profile::Desktop, 7 << 20, 0),
            (Profile::Server, 7 << 20, 0),
            (Profile::Router, 1 << 20, 8),
        ] {
            let quic = RuntimeOptions::profile(profile).quic;
            assert_eq!(
                quic.udp_buffers(),
                UdpBuffers {
                    receive,
                    send: 0,
                    receive_batch
                },
                "{:?}",
                profile
            );
        }
        // Zero still leaves the system's.
        let mut options = RuntimeOptions::default();
        options.set("quic.udp_receive_buffer", "0").unwrap();
        assert_eq!(options.quic.udp_buffers(), UdpBuffers::default());
        let mut options = RuntimeOptions::default();
        options
            .set_all(["quic.udp_receive_buffer=7168", "quic.udp_send_buffer=1024"])
            .unwrap();
        assert_eq!(options.quic.udp_receive_buffer, 7168);
        assert_eq!(
            options.quic.udp_buffers(),
            UdpBuffers {
                receive: 7168 << 10,
                send: 1 << 20,
                receive_batch: 0,
            }
        );
        for bad in ["7m", "-1", "1.5", "true"] {
            let err = options.set("quic.udp_receive_buffer", bad).unwrap_err();
            assert!(
                err.to_string()
                    .starts_with("runtime option \"quic.udp_receive_buffer\""),
                "{}: {}",
                bad,
                err
            );
        }
        // A refused value changes nothing.
        assert_eq!(options.quic.udp_receive_buffer, 7168);
    }

    /// A phone's and a router's sessions are bounded, a desktop's and a
    /// server's are not.
    #[test]
    fn small_profiles_bound_their_sessions() {
        let cap = |profile| RuntimeOptions::profile(profile).inbound.max_connections;
        assert_eq!(cap(Profile::Mobile), 512);
        assert_eq!(cap(Profile::Router), 512);
        assert_eq!(cap(Profile::Desktop), 0);
        assert_eq!(cap(Profile::Server), 0);
    }

    /// A router's sessions follow its memory: the measured points, and the
    /// bounds.
    #[test]
    fn a_router_s_sessions_follow_its_memory() {
        assert_eq!(router_sessions(0), 64);
        assert_eq!(router_sessions(52), 64);
        assert_eq!(router_sessions(84), 128);
        assert_eq!(router_sessions(210), 380);
        assert_eq!(router_sessions(276), 512);
        assert_eq!(router_sessions(512), 512);
        assert_eq!(router_sessions(u64::MAX >> 20), 512);
        let mib = |n: u64| Some(n << 20);
        let fitted = |profile, memory| {
            let mut options = RuntimeOptions::profile(profile);
            options.fit_to_memory(memory);
            (options.inbound.max_connections, options.sessions_for_memory)
        };
        assert_eq!(fitted(Profile::Router, mib(84)), (128, Some((128, 84))));
        // Enough memory, or none known: the profile's, and nothing to log.
        assert_eq!(fitted(Profile::Router, mib(512)), (512, None));
        assert_eq!(fitted(Profile::Router, None), (512, None));
        // Other profiles keep theirs.
        assert_eq!(fitted(Profile::Mobile, mib(84)), (512, None));
        assert_eq!(fitted(Profile::Desktop, mib(84)), (0, None));
        assert_eq!(fitted(Profile::Server, mib(84)), (0, None));
    }

    /// Every profile's transfer budget is held to a quarter of the memory;
    /// a router's is the quarter, up to 64 MiB.
    #[test]
    fn the_transfer_budget_follows_the_memory() {
        let budget = |profile, memory| {
            let mut options = RuntimeOptions::profile(profile);
            options.fit_to_memory(memory);
            options.memory.transfer_budget >> 10
        };
        assert_eq!(budget(Profile::Router, Some(64 << 20)), 16);
        assert_eq!(budget(Profile::Router, Some(128 << 20)), 32);
        assert_eq!(budget(Profile::Router, Some(1 << 30)), 64);
        assert_eq!(budget(Profile::Router, None), 64);
        assert_eq!(budget(Profile::Mobile, Some(4 << 30)), 24);
        assert_eq!(budget(Profile::Server, Some(2 << 30)), 512);
        assert_eq!(budget(Profile::Desktop, Some(16 << 30)), 256);
        // A setting wins.
        let mut options = RuntimeOptions::profile(Profile::Router);
        options.fit_to_memory(Some(64 << 20));
        options.set("memory.transfer_budget", "12288").unwrap();
        assert_eq!(options.memory.transfer_budget, 12288);
    }

    /// What the user sets wins over the memory, and only that setting
    /// does.
    #[test]
    fn a_setting_of_the_sessions_wins_over_the_memory() {
        let mut options = RuntimeOptions::profile(Profile::Router);
        options.fit_to_memory(Some(84 << 20));
        options.set("relay.buffer_size", "8").unwrap();
        assert_eq!(options.inbound.max_connections, 128);
        assert_eq!(options.sessions_for_memory, Some((128, 84)));
        options.set("inbound.max_connections", "512").unwrap();
        assert_eq!(options.inbound.max_connections, 512);
        assert_eq!(options.sessions_for_memory, None);
    }

    #[test]
    fn clients_take_bbr_and_a_server_the_systems() {
        for profile in [Profile::Mobile, Profile::Desktop, Profile::Router] {
            assert_eq!(RuntimeOptions::profile(profile).relay.tcp_congestion, "bbr");
        }
        assert_eq!(
            RuntimeOptions::profile(Profile::Server)
                .relay
                .tcp_congestion,
            ""
        );
    }

    #[test]
    fn profiles_are_named_as_on_the_command_line() {
        assert_eq!("router".parse::<Profile>().unwrap(), Profile::Router);
        assert!("laptop".parse::<Profile>().is_err());
        assert!(
            RuntimeOptions::profile(Profile::Router)
                .relay
                .buffer_max_size
                < RuntimeOptions::profile(Profile::Server)
                    .relay
                    .buffer_max_size
        );
    }
}
