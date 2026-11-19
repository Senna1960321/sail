use std::collections::VecDeque;
use std::fmt;
use std::future::{poll_fn, Future};
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;

use crate::metrics::increment_counter;
use crate::trace::DebugTrace;
use crate::{
    emit_icmp_echo_reply, emit_icmp_error, fragment_outbound_ip_packet, parse_icmp_packet,
    parse_ip_packet, parse_tcp_segment, parse_udp_datagram, ArenaPacket, BudgetError, FlowId,
    FragmentError, FragmentReassembler, IcmpErrorKind, IcmpMessage, IpEndpoint, IpVersion,
    NetworkGeneration, Packet, PacketArena, PacketBatch, PacketCapabilities, PacketIo, PacketToken,
    PmtuError, PmtuTable, PressureLevel, ResourceKind, ResourceLedger, Scheduler, SchedulerConfig,
    ShardId, StackStats, TcpConnection, TcpError, TcpEvent, TcpFlowToken, TcpIngress, TcpTable,
    TcpTableConfig, TcpTableError, TcpTimerCancel, TcpTimerRequest, TimerError, TimerEvent,
    TimerId, TimerWheel, TraceKind, TraceSnapshot, TransportProtocol, UdpError, UdpFlowToken,
    UdpIngress, UdpTable, WireError, WorkClass, MAX_DEBUG_TRACE_EVENTS,
};

// IPv6 + TCP + MSS/SACK/window-scale/timestamp SYN options.
/// The largest IP and TCP headers a segment of this stack carries: IPv6's 40
/// bytes, TCP's 20, and 40 of options (timestamps and three SACK blocks).
/// A payload of at most the MTU less this always fits.
pub const TCP_MAX_HEADER_BYTES: usize = 100;
/// A half-open flow is reclaimed under pressure only once it has waited
/// this long for its handshake's last ACK: the initial RTO and one
/// doubling, so a client on a slow or lossy link whose ACK comes after
/// the SYN-ACK's first retransmission keeps its connection (a judgment,
/// not measured).
const SYN_RECEIVED_STALE_MS: u64 = 3_000;
/// Half-open flows reclaimed at most on one entry into Critical or
/// Exhausted pressure; new SYNs are refused meanwhile (a judgment).
const SYN_RECLAIM_CAP: usize = 256;
const TCP_CONTROL_PACKET_BYTES: usize = TCP_MAX_HEADER_BYTES;
/// Resets a network reset or a closing runner holds for flows still to be
/// told, about 70 bytes each; a phone's change of network can end
/// thousands of flows at once, and each step sends what the control pool
/// and the TX queue allow. Those past it are counted (a judgment).
const RESET_QUEUE_CAP: usize = 8192;
/// How long a runner past its draining deadline still sends the resets of
/// the flows it ends, before it closes (a judgment).
const CLOSING_FLUSH_MS: u64 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnerConfig {
    pub generation: NetworkGeneration,
    pub shard: ShardId,
    pub mtu: usize,
    pub udp_idle_timeout_ms: u64,
    pub fragment_timeout_ms: u64,
    pub pmtu_timeout_ms: u64,
    pub icmp_echo_burst: u32,
    pub icmp_echo_refill_ms: u64,
    pub icmp_error_burst: u32,
    pub icmp_error_refill_ms: u64,
    pub fragment_burst: u32,
    pub fragment_refill_ms: u64,
    pub payload_chunk_size: usize,
    pub max_packet_size: usize,
    pub scheduler: SchedulerConfig,
    pub tcp: TcpTableConfig,
    pub timer_tick_ms: u64,
    pub debug_trace_capacity: usize,
    /// How many packets one step sends, and how many it receives, while the
    /// device takes or has them at once: a device batch of one packet (a
    /// mobile TUN) would otherwise cost one pass of the caller's loop per
    /// packet. Waiting stays at one batch. One, the default, is one batch a
    /// step.
    pub packets_per_step: usize,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            generation: NetworkGeneration::default(),
            shard: ShardId::default(),
            mtu: 1_500,
            udp_idle_timeout_ms: 60_000,
            fragment_timeout_ms: 30_000,
            pmtu_timeout_ms: 600_000,
            icmp_echo_burst: 128,
            icmp_echo_refill_ms: 10,
            icmp_error_burst: 32,
            icmp_error_refill_ms: 100,
            fragment_burst: 1_024,
            fragment_refill_ms: 1,
            payload_chunk_size: 2_048,
            max_packet_size: 65_535 + 128,
            scheduler: SchedulerConfig::default(),
            tcp: TcpTableConfig::default(),
            timer_tick_ms: 10,
            debug_trace_capacity: 0,
            packets_per_step: 1,
        }
    }
}

impl RunnerConfig {
    fn validate(self) -> Result<Self, RunnerError> {
        if !(576..=65_535).contains(&self.mtu) {
            return Err(RunnerError::InvalidConfig(
                "MTU must be between 576 and 65535",
            ));
        }
        if self.udp_idle_timeout_ms == 0
            || self.fragment_timeout_ms == 0
            || self.pmtu_timeout_ms == 0
            || self.icmp_echo_burst == 0
            || self.icmp_echo_refill_ms == 0
            || self.icmp_error_burst == 0
            || self.icmp_error_refill_ms == 0
            || self.fragment_burst == 0
            || self.fragment_refill_ms == 0
            || self.payload_chunk_size == 0
        {
            return Err(RunnerError::InvalidConfig(
                "UDP/fragment/PMTU timeout, ICMP rate, and payload chunk size must be non-zero",
            ));
        }
        if self.max_packet_size < self.mtu {
            return Err(RunnerError::InvalidConfig(
                "maximum packet allocation must cover the MTU",
            ));
        }
        if self.tcp.receive_credit_bytes == 0
            || self.tcp.max_segment_payload_bytes == 0
            || self.tcp.time_wait_ms == 0
            || self.tcp.delayed_ack_ms == 0
            || self.tcp.persist_initial_ms == 0
            || self.tcp.persist_max_ms < self.tcp.persist_initial_ms
            || self.tcp.keepalive_idle_ms == Some(0)
            || self.tcp.keepalive_interval_ms == 0
            || self.tcp.keepalive_max_probes == 0
            || self.tcp.max_retransmission_timeouts == 0
            || self.tcp.syn_burst == 0
            || self.tcp.syn_refill_ms == 0
            || self.tcp.defensive_ack_burst == 0
            || self.tcp.defensive_ack_refill_ms == 0
            || self.tcp.challenge_ack_burst == 0
            || self.tcp.challenge_ack_refill_ms == 0
            || self.tcp.stateless_reset_burst == 0
            || self.tcp.stateless_reset_refill_ms == 0
        {
            return Err(RunnerError::InvalidConfig(
                "invalid TCP credit, segment, timer, persist, or keepalive configuration",
            ));
        }
        if self.timer_tick_ms == 0 {
            return Err(RunnerError::InvalidConfig("timer tick must be non-zero"));
        }
        if self.packets_per_step == 0 {
            return Err(RunnerError::InvalidConfig(
                "packets per step must be non-zero",
            ));
        }
        if self.debug_trace_capacity > MAX_DEBUG_TRACE_EVENTS {
            return Err(RunnerError::InvalidConfig(
                "debug trace capacity exceeds the hard limit",
            ));
        }
        self.scheduler
            .validate()
            .map_err(|_| RunnerError::InvalidConfig("invalid shard scheduler configuration"))?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunnerState {
    Created,
    Running,
    Draining { deadline_ms: u64 },
    Closed,
    Failed,
}

#[derive(Debug)]
pub enum RunnerError {
    InvalidConfig(&'static str),
    InvalidIoReport(&'static str),
    Io(io::Error),
    Budget(BudgetError),
    Udp(UdpError),
    Tcp(TcpTableError),
    Wire(WireError),
    Timer(TimerError),
    Fragment(FragmentError),
    Pmtu(PmtuError),
    PacketExceedsMtu,
    RxQueueFull,
    TxQueueFull,
    /// A flow was opened on a shard its replies would not reach.
    ForeignFlow,
    Closed,
}

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid runner config: {message}"),
            Self::InvalidIoReport(message) => {
                write!(formatter, "invalid packet I/O report: {message}")
            }
            Self::Io(error) => write!(formatter, "packet I/O failed: {error}"),
            Self::Budget(error) => write!(formatter, "packet resource allocation failed: {error}"),
            Self::Udp(error) => write!(formatter, "UDP processing failed: {error}"),
            Self::Tcp(error) => write!(formatter, "TCP processing failed: {error}"),
            Self::Wire(error) => write!(formatter, "packet parsing failed: {error}"),
            Self::Timer(error) => write!(formatter, "timer processing failed: {error}"),
            Self::Fragment(error) => write!(formatter, "fragment processing failed: {error}"),
            Self::Pmtu(error) => write!(formatter, "PMTU processing failed: {error}"),
            Self::PacketExceedsMtu => formatter.write_str("packet exceeds current MTU"),
            Self::RxQueueFull => formatter.write_str("packet RX queue is full"),
            Self::TxQueueFull => formatter.write_str("packet TX queue is full"),
            Self::ForeignFlow => formatter.write_str("flow belongs to another shard"),
            Self::Closed => formatter.write_str("stack runner is closed"),
        }
    }
}

impl std::error::Error for RunnerError {}

impl From<UdpError> for RunnerError {
    fn from(error: UdpError) -> Self {
        Self::Udp(error)
    }
}

impl From<BudgetError> for RunnerError {
    fn from(error: BudgetError) -> Self {
        Self::Budget(error)
    }
}

impl From<TcpTableError> for RunnerError {
    fn from(error: TcpTableError) -> Self {
        Self::Tcp(error)
    }
}

impl From<TimerError> for RunnerError {
    fn from(error: TimerError) -> Self {
        Self::Timer(error)
    }
}

impl From<FragmentError> for RunnerError {
    fn from(error: FragmentError) -> Self {
        Self::Fragment(error)
    }
}

impl From<PmtuError> for RunnerError {
    fn from(error: PmtuError) -> Self {
        Self::Pmtu(error)
    }
}

#[derive(Debug, Default)]
pub struct StepOutcome {
    pub datagrams: Vec<UdpIngress>,
    pub tcp_events: Vec<TcpEvent>,
    pub tcp_timers: Vec<TcpTimerRequest>,
    pub tcp_cancelled_timers: Vec<TcpTimerCancel>,
    pub received_packets: usize,
    pub processed_packets: usize,
    pub sent_packets: usize,
    pub dropped_packets: usize,
    pub would_block: bool,
}

/// Executor-independent single-shard driver.
///
/// The caller repeatedly awaits [`SingleShardRunner::step`]. A control-plane
/// adapter must race that future with control events; dropping the step future
/// cancels a pending platform operation before calling `abort`, `shutdown`, or
/// `reset_network`. Adapters may also drop it routinely for timers and
/// application commands: a step records sent packets only after `send`
/// completes, which is safe under the [`PacketIo`] cancellation contract.
#[derive(Debug)]
pub struct SingleShardRunner<I> {
    io: I,
    capabilities: PacketCapabilities,
    ledger: Arc<ResourceLedger>,
    arena: PacketArena,
    udp: UdpTable,
    tcp: TcpTable,
    fragments: FragmentReassembler,
    pmtu: PmtuTable,
    scheduler: Scheduler<Packet>,
    flow_hasher: RandomState,
    tx: PacketBatch,
    tx_pending: VecDeque<Packet>,
    /// Resets of flows a network reset or a closing runner ended, still to
    /// be sent: see `RESET_QUEUE_CAP`.
    pending_resets: VecDeque<Vec<u8>>,
    /// Past its draining deadline: when it closes, whatever is left.
    closing_until_ms: Option<u64>,
    tx_pending_limit: usize,
    tcp_timers: TimerWheel<ScheduledTcpTimer>,
    tcp_timer_ids: crate::FlowMap<(TcpFlowToken, TimerEvent), ArmedTcpTimer>,
    next_timer_serial: u64,
    timer_tick_ms: u64,
    packets_per_step: usize,
    state: RunnerState,
    last_pressure: PressureLevel,
    mtu: usize,
    next_packet_token: u64,
    next_fragment_identification: u32,
    icmp_echo_limiter: IcmpErrorLimiter,
    icmp_error_limiter: IcmpErrorLimiter,
    fragment_limiter: IcmpErrorLimiter,
    counters: RunnerCounters,
    trace: DebugTrace,
}

#[derive(Clone, Copy, Debug, Default)]
struct RunnerCounters {
    rx_packets: u64,
    rx_bytes: u64,
    rx_batches: u64,
    rx_batch_packets: u64,
    rx_batch_max: usize,
    rx_io_wakeups: u64,
    tx_packets: u64,
    tx_bytes: u64,
    tx_batches: u64,
    tx_batch_packets: u64,
    tx_batch_max: usize,
    tx_io_wakeups: u64,
    dropped_packets: u64,
    dropped_wire_packets: u64,
    dropped_resource_packets: u64,
    dropped_policy_packets: u64,
    dropped_rate_limited_packets: u64,
    dropped_output_packets: u64,
    dropped_other_packets: u64,
    partial_sends: u64,
    runner_failures: u64,
    shutdowns: u64,
    aborts: u64,
    network_resets: u64,
    reset_rsts_dropped: u64,
    mtu_changes: u64,
    scheduler_rounds: u64,
    scheduler_packets: u64,
    scheduler_bytes: u64,
    scheduler_control_packets_processed: u64,
    scheduler_active_flow_visits: u64,
    scheduler_time_budget_exhaustions: u64,
    pressure_transitions: u64,
    pressure_constrained_entries: u64,
    pressure_critical_entries: u64,
    pressure_exhausted_entries: u64,
    pressure_rejected_new_flows: u64,
    icmp_echo_replies: u64,
    icmp_echo_rate_limited: u64,
    icmp_errors_sent: u64,
    icmp_errors_rate_limited: u64,
    fragment_packets_rate_limited: u64,
    outbound_fragments: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketDropReason {
    Wire,
    Resource,
    Policy,
    RateLimited,
    Output,
    Other,
}

impl RunnerCounters {
    fn record_drop(&mut self, reason: PacketDropReason) {
        increment_counter(&mut self.dropped_packets);
        let counter = match reason {
            PacketDropReason::Wire => &mut self.dropped_wire_packets,
            PacketDropReason::Resource => &mut self.dropped_resource_packets,
            PacketDropReason::Policy => &mut self.dropped_policy_packets,
            PacketDropReason::RateLimited => &mut self.dropped_rate_limited_packets,
            PacketDropReason::Output => &mut self.dropped_output_packets,
            PacketDropReason::Other => &mut self.dropped_other_packets,
        };
        increment_counter(counter);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnqueueDisposition {
    Queued,
    Consumed,
    Dropped(PacketDropReason),
}

/// Counts executor resumptions after the initial poll. This observes the
/// runner's I/O boundary without requiring platform-specific waker hooks.
async fn await_io<F: Future>(future: F, wakeups: &mut u64) -> F::Output {
    let mut future = pin!(future);
    let mut first_poll = true;
    poll_fn(|context| {
        if first_poll {
            first_poll = false;
        } else {
            increment_counter(wakeups);
        }
        future.as_mut().poll(context)
    })
    .await
}

/// A TCP timer as the flow last set it, and the wheel entry standing for
/// it. A flow re-arms its retransmission, delayed-ACK and keepalive timers
/// on most segments it takes; one re-armed later keeps its entry, which
/// moves on to `due_ms` when it fires, and one disarmed keeps it too, to be
/// dropped then: a segment costs a lookup, not a cancel and a schedule.
#[derive(Clone, Copy, Debug)]
struct ArmedTcpTimer {
    id: TimerId,
    serial: u64,
    /// When the wheel entry fires.
    wheel_ms: u64,
    /// When the timer is due, or `None` once disarmed.
    due_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct ScheduledTcpTimer {
    request: TcpTimerRequest,
    serial: u64,
}

#[derive(Clone, Copy, Debug)]
struct IcmpErrorLimiter {
    burst: u32,
    tokens: u32,
    refill_ms: u64,
    last_refill_ms: Option<u64>,
}

impl IcmpErrorLimiter {
    const fn new(burst: u32, refill_ms: u64) -> Self {
        Self {
            burst,
            tokens: burst,
            refill_ms,
            last_refill_ms: None,
        }
    }

    fn allow(&mut self, now_ms: u64) -> bool {
        let last = *self.last_refill_ms.get_or_insert(now_ms);
        if now_ms >= last {
            let refills = (now_ms - last) / self.refill_ms;
            if refills > 0 {
                let added = u32::try_from(refills).unwrap_or(u32::MAX);
                self.tokens = self.tokens.saturating_add(added).min(self.burst);
                self.last_refill_ms =
                    Some(last.saturating_add(refills.saturating_mul(self.refill_ms)));
            }
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    fn reset(&mut self) {
        self.tokens = self.burst;
        self.last_refill_ms = None;
    }
}

struct ScheduledContext<'a> {
    allow_new: bool,
    pressure_blocks_new: bool,
    now_ms: u64,
    udp: &'a mut UdpTable,
    tcp: &'a mut TcpTable,
    arena: &'a PacketArena,
    counters: &'a mut RunnerCounters,
    icmp_echo_limiter: &'a mut IcmpErrorLimiter,
    icmp_error_limiter: &'a mut IcmpErrorLimiter,
    pmtu: &'a mut PmtuTable,
    outcome: &'a mut StepOutcome,
    available_tx_slots: usize,
    headroom: usize,
    mtu: usize,
    output_packets: Vec<ArenaPacket>,
    fatal: Option<RunnerError>,
    trace: &'a mut DebugTrace,
}

impl ScheduledContext<'_> {
    fn process(&mut self, packet: &Packet) {
        if self.fatal.is_some() {
            self.drop_packet(PacketDropReason::Other);
            return;
        }
        let Ok(ip) = parse_ip_packet(packet.payload(), true) else {
            self.drop_packet(PacketDropReason::Wire);
            return;
        };
        match (ip.version, ip.next_header) {
            (IpVersion::V4, 1) | (IpVersion::V6, 58) => self.process_icmp(ip),
            (IpVersion::V6, 59) => self.drop_packet(PacketDropReason::Policy),
            (_, 17) => self.process_udp(packet),
            (_, 6) => self.process_tcp(packet),
            _ => self.process_unsupported(packet),
        }
    }

    fn process_icmp(&mut self, ip: crate::ParsedIpPacket<'_>) {
        match parse_icmp_packet(ip, true) {
            Ok(icmp) if matches!(icmp.message, IcmpMessage::EchoRequest { .. }) => {
                if !self.icmp_echo_limiter.allow(self.now_ms) {
                    self.counters.icmp_echo_rate_limited =
                        self.counters.icmp_echo_rate_limited.saturating_add(1);
                    self.drop_packet(PacketDropReason::RateLimited);
                    return;
                }
                let queued = emit_icmp_echo_reply(ip, 64).is_ok_and(|wire| self.push_wire(&wire));
                if queued {
                    increment_counter(&mut self.counters.icmp_echo_replies);
                } else {
                    self.drop_packet(PacketDropReason::Output);
                }
            }
            Ok(icmp) => {
                if let IcmpMessage::PacketTooBig { mtu } = icmp.message {
                    let Some(quoted) = quoted_transport_endpoints(icmp.payload) else {
                        self.pmtu.reject_unmatched_flow();
                        return;
                    };
                    let matched = match quoted {
                        QuotedTransport::Tcp(source, destination) => {
                            self.tcp.has_quoted_flow(source, destination)
                        }
                        QuotedTransport::Udp(source, destination) => {
                            self.udp.has_quoted_reply(source, destination)
                        }
                    };
                    if !matched {
                        self.pmtu.reject_unmatched_flow();
                        return;
                    }
                    if let Ok(path_mtu) = self.pmtu.learn_from_icmp(
                        ip.destination,
                        icmp.payload,
                        mtu,
                        self.mtu,
                        self.now_ms,
                    ) {
                        if let QuotedTransport::Tcp(source, destination) = quoted {
                            let _ = self.tcp.lower_path_mtu(source, destination, path_mtu);
                        }
                    }
                }
            }
            Err(_) => self.drop_packet(PacketDropReason::Wire),
        }
    }

    fn process_udp(&mut self, packet: &Packet) {
        match self
            .udp
            .ingest_with_policy(packet.payload(), self.now_ms, self.allow_new)
        {
            Ok(datagram) => self.outcome.datagrams.push(datagram),
            Err(UdpError::NewFlowsDisabled) => {
                if self.pressure_blocks_new {
                    self.counters.pressure_rejected_new_flows =
                        self.counters.pressure_rejected_new_flows.saturating_add(1);
                }
                self.drop_packet(PacketDropReason::Policy);
            }
            Err(UdpError::InvalidAddress) => self.drop_packet(PacketDropReason::Policy),
            Err(UdpError::Wire(_)) => self.drop_packet(PacketDropReason::Wire),
            Err(UdpError::Budget(_)) => self.drop_packet(PacketDropReason::Resource),
            Err(error) => self.fatal = Some(error.into()),
        }
    }

    fn process_unsupported(&mut self, packet: &Packet) {
        let Ok(wire) = emit_icmp_error(packet.payload(), IcmpErrorKind::UnsupportedProtocol, 64)
        else {
            self.drop_packet(PacketDropReason::Policy);
            return;
        };
        if !self.icmp_error_limiter.allow(self.now_ms) {
            increment_counter(&mut self.counters.icmp_errors_rate_limited);
            self.drop_packet(PacketDropReason::RateLimited);
            return;
        }
        if self.push_wire(&wire) {
            increment_counter(&mut self.counters.icmp_errors_sent);
        } else {
            self.drop_packet(PacketDropReason::Output);
        }
    }

    fn process_tcp(&mut self, packet: &Packet) {
        let available = self
            .available_tx_slots
            .saturating_sub(self.output_packets.len());
        if available == 0 {
            self.drop_packet(PacketDropReason::Output);
            return;
        }
        // Room for a control reply (IPv6 and a TCP header with every
        // option), taken before the packet changes any state; a reply that
        // carries data gets an allocation of its own size.
        let Ok(allocation) = self
            .arena
            .allocate_control(self.headroom, TCP_CONTROL_PACKET_BYTES)
        else {
            self.drop_packet(PacketDropReason::Resource);
            return;
        };
        let mut reserved = Some(allocation);
        match self.tcp.ingest_with_policy_at_limit(
            packet.payload(),
            self.allow_new,
            self.now_ms,
            available,
        ) {
            Ok(mut ingress) => {
                for wire in ingress.outgoing.drain(..) {
                    if wire.len() > self.mtu {
                        self.fatal = Some(RunnerError::PacketExceedsMtu);
                        return;
                    }
                    let mut allocation = if let Some(allocation) = reserved
                        .take_if(|allocation| allocation.payload_capacity_mut().len() >= wire.len())
                    {
                        allocation
                    } else {
                        let Ok(allocation) = self.arena.allocate_control(self.headroom, wire.len())
                        else {
                            self.drop_packet(PacketDropReason::Resource);
                            continue;
                        };
                        allocation
                    };
                    allocation.payload_capacity_mut()[..wire.len()].copy_from_slice(&wire);
                    if let Err(error) = allocation.set_len(wire.len()) {
                        self.fatal = Some(error.into());
                        return;
                    }
                    self.output_packets.push(allocation);
                }
                self.outcome.tcp_events.append(&mut ingress.events);
                self.outcome.tcp_timers.append(&mut ingress.timers);
                self.outcome
                    .tcp_cancelled_timers
                    .append(&mut ingress.cancelled_timers);
            }
            Err(TcpTableError::NewFlowsDisabled) => {
                if self.pressure_blocks_new {
                    self.counters.pressure_rejected_new_flows =
                        self.counters.pressure_rejected_new_flows.saturating_add(1);
                }
                self.drop_packet(PacketDropReason::Policy);
            }
            Err(TcpTableError::Invariant(message)) => {
                self.fatal = Some(TcpTableError::Invariant(message).into());
            }
            Err(TcpTableError::Wire(_)) => self.drop_packet(PacketDropReason::Wire),
            Err(TcpTableError::Budget(_)) => self.drop_packet(PacketDropReason::Resource),
            Err(_) => self.drop_packet(PacketDropReason::Policy),
        }
    }

    fn push_wire(&mut self, wire: &[u8]) -> bool {
        if wire.len() > self.mtu || self.output_packets.len() == self.available_tx_slots {
            return false;
        }
        let Ok(mut allocation) = self.arena.allocate_control(self.headroom, wire.len()) else {
            return false;
        };
        allocation.payload_capacity_mut().copy_from_slice(wire);
        if allocation.set_len(wire.len()).is_err() {
            return false;
        }
        self.output_packets.push(allocation);
        true
    }

    fn drop_packet(&mut self, reason: PacketDropReason) {
        self.counters.record_drop(reason);
        self.outcome.dropped_packets = self.outcome.dropped_packets.saturating_add(1);
        self.trace
            .record(self.now_ms, TraceKind::PacketsDropped { count: 1 });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuotedTransport {
    Tcp(SocketAddr, SocketAddr),
    Udp(SocketAddr, SocketAddr),
}

fn quoted_transport_endpoints(packet: &[u8]) -> Option<QuotedTransport> {
    let version = packet.first()? >> 4;
    let (source, destination, protocol, transport_offset) = match version {
        4 if packet.len() >= 20 => {
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || packet.len() < header_len + 4 {
                return None;
            }
            let fragment_bits = u16::from_be_bytes([packet[6], packet[7]]);
            if fragment_bits & 0x1fff != 0 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                )),
                packet[9],
                header_len,
            )
        }
        6 if packet.len() >= 40 => {
            let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
            let destination =
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
            let mut protocol = packet[6];
            let mut offset = 40_usize;
            let mut found_transport = false;
            for _ in 0..8 {
                let extension_len = match protocol {
                    0 | 43 | 60 => {
                        let header = packet.get(offset..offset.checked_add(2)?)?;
                        (usize::from(header[1]) + 1) * 8
                    }
                    51 => {
                        let header = packet.get(offset..offset.checked_add(2)?)?;
                        (usize::from(header[1]) + 2) * 4
                    }
                    44 => {
                        let header = packet.get(offset..offset.checked_add(8)?)?;
                        let fragment_bits = u16::from_be_bytes([header[2], header[3]]);
                        if fragment_bits & 0xfff8 != 0 {
                            return None;
                        }
                        8
                    }
                    _ => {
                        found_transport = true;
                        break;
                    }
                };
                let header = packet.get(offset..offset.checked_add(extension_len)?)?;
                protocol = header[0];
                offset = offset.checked_add(extension_len)?;
            }
            if !found_transport {
                return None;
            }
            (source, destination, protocol, offset)
        }
        _ => return None,
    };
    if !matches!(protocol, 6 | 17) || packet.len() < transport_offset + 4 {
        return None;
    }
    let source_port = u16::from_be_bytes([packet[transport_offset], packet[transport_offset + 1]]);
    let destination_port =
        u16::from_be_bytes([packet[transport_offset + 2], packet[transport_offset + 3]]);
    let source = SocketAddr::new(source, source_port);
    let destination = SocketAddr::new(destination, destination_port);
    match protocol {
        6 => Some(QuotedTransport::Tcp(source, destination)),
        17 => Some(QuotedTransport::Udp(source, destination)),
        _ => None,
    }
}

impl<I: PacketIo> SingleShardRunner<I> {
    /// # Errors
    ///
    /// Returns [`RunnerError`] when runner configuration or platform
    /// capabilities are invalid.
    pub fn new(
        io: I,
        ledger: Arc<ResourceLedger>,
        config: RunnerConfig,
    ) -> Result<Self, RunnerError> {
        let config = config.validate()?;
        let capabilities = io.capabilities().validate().map_err(RunnerError::Io)?;
        let maximum_packet_allocation =
            capabilities
                .headroom
                .checked_add(config.mtu)
                .ok_or(RunnerError::InvalidConfig(
                    "control packet reserve size overflows usize",
                ))?;
        if config.max_packet_size < maximum_packet_allocation {
            return Err(RunnerError::InvalidConfig(
                "maximum packet allocation must cover MTU plus headroom",
            ));
        }
        let minimum_control_reserve =
            config
                .mtu
                .checked_add(maximum_packet_allocation)
                .ok_or(RunnerError::InvalidConfig(
                    "control packet reserve size overflows usize",
                ))?;
        if ledger.budget().control_packet_bytes < minimum_control_reserve {
            return Err(RunnerError::InvalidConfig(
                "control packet reserve must hold one RX and one TX packet",
            ));
        }
        let arena = PacketArena::new(Arc::clone(&ledger), config.max_packet_size);
        let scheduler = Scheduler::new(config.scheduler)
            .map_err(|_| RunnerError::InvalidConfig("invalid shard scheduler configuration"))?;
        let udp = UdpTable::new_on_shard(
            Arc::clone(&ledger),
            config.generation,
            config.shard,
            config.udp_idle_timeout_ms,
            config.payload_chunk_size,
        );
        // Each flow sizes its segments from the link, for its family and
        // options, under the configured ceiling.
        let mut tcp_config = config.tcp;
        tcp_config.link_mtu = Some(config.mtu);
        let tcp = TcpTable::new_on_shard(
            Arc::clone(&ledger),
            config.generation,
            config.shard,
            tcp_config,
        );
        let fragments = FragmentReassembler::new(Arc::clone(&ledger), config.fragment_timeout_ms);
        let pmtu = PmtuTable::new(
            Arc::clone(&ledger),
            config.generation,
            config.pmtu_timeout_ms,
        );
        let last_pressure = ledger.snapshot().pressure;
        Ok(Self {
            io,
            capabilities,
            ledger,
            arena,
            udp,
            tcp,
            fragments,
            pmtu,
            scheduler,
            flow_hasher: RandomState::new(),
            tx: PacketBatch::with_limit(capabilities.max_batch),
            tx_pending: VecDeque::new(),
            pending_resets: VecDeque::new(),
            closing_until_ms: None,
            tx_pending_limit: config.scheduler.max_queued_packets,
            tcp_timers: TimerWheel::new(config.timer_tick_ms, 0),
            tcp_timer_ids: crate::FlowMap::default(),
            next_timer_serial: 0,
            timer_tick_ms: config.timer_tick_ms,
            state: RunnerState::Created,
            last_pressure,
            mtu: config.mtu,
            next_packet_token: 0,
            next_fragment_identification: 1,
            icmp_echo_limiter: IcmpErrorLimiter::new(
                config.icmp_echo_burst,
                config.icmp_echo_refill_ms,
            ),
            icmp_error_limiter: IcmpErrorLimiter::new(
                config.icmp_error_burst,
                config.icmp_error_refill_ms,
            ),
            fragment_limiter: IcmpErrorLimiter::new(
                config.fragment_burst,
                config.fragment_refill_ms,
            ),
            counters: RunnerCounters::default(),
            trace: DebugTrace::new(config.debug_trace_capacity),
            packets_per_step: config.packets_per_step,
        })
    }

    #[must_use]
    pub const fn state(&self) -> RunnerState {
        self.state
    }

    #[must_use]
    pub const fn mtu(&self) -> usize {
        self.mtu
    }

    #[must_use]
    pub fn pending_tx(&self) -> usize {
        self.tx.len() + self.tx_pending.len()
    }

    #[must_use]
    pub fn pending_rx(&self) -> usize {
        self.scheduler.snapshot().queued_packets
    }

    #[must_use]
    pub fn pending_tcp_timers(&self) -> usize {
        self.tcp_timer_ids
            .values()
            .filter(|armed| armed.due_ms.is_some())
            .count()
    }

    /// Copies the current bounded diagnostic history. Tracing is disabled
    /// when `RunnerConfig::debug_trace_capacity` is zero (the default).
    #[must_use]
    pub fn trace_snapshot(&self) -> TraceSnapshot {
        self.trace.snapshot()
    }

    /// Removes retained diagnostic events without enabling or resizing trace.
    pub fn clear_trace(&mut self) {
        self.trace.clear();
    }

    fn observe_pressure(&mut self, now_ms: u64, pressure: PressureLevel) {
        if pressure == self.last_pressure {
            return;
        }
        let previous = self.last_pressure;
        self.last_pressure = pressure;
        self.counters.pressure_transitions = self.counters.pressure_transitions.saturating_add(1);
        match pressure {
            PressureLevel::Normal => {}
            PressureLevel::Constrained => {
                self.counters.pressure_constrained_entries =
                    self.counters.pressure_constrained_entries.saturating_add(1);
            }
            PressureLevel::Critical => {
                self.counters.pressure_critical_entries =
                    self.counters.pressure_critical_entries.saturating_add(1);
            }
            PressureLevel::Exhausted => {
                self.counters.pressure_exhausted_entries =
                    self.counters.pressure_exhausted_entries.saturating_add(1);
            }
        }
        // Only handshakes that went stale: a client that already has its
        // SYN-ACK and answers in time keeps its connection.
        if matches!(pressure, PressureLevel::Critical | PressureLevel::Exhausted) {
            for _ in 0..SYN_RECLAIM_CAP {
                let Some(token) = self
                    .tcp
                    .reclaim_stale_syn_received(now_ms, SYN_RECEIVED_STALE_MS)
                else {
                    break;
                };
                self.cancel_tcp_timer(token, TimerEvent::Retransmission);
            }
        }
        self.trace.record(
            now_ms,
            TraceKind::PressureChanged {
                from: previous,
                to: pressure,
            },
        );
    }

    fn expire_fragments(&mut self, now_ms: u64, timeout_divisor: u64) -> Result<(), RunnerError> {
        let max_quotes = self
            .tx_pending_limit
            .saturating_sub(self.pending_tx())
            .min(self.capabilities.max_batch)
            .min(self.icmp_error_limiter.burst as usize);
        let expired = self.fragments.advance_time_under_pressure_with_quotes(
            now_ms,
            timeout_divisor,
            max_quotes,
        )?;
        for invoking_packet in expired.invoking_packets {
            let Ok(wire) = emit_icmp_error(
                &invoking_packet,
                IcmpErrorKind::TimeExceeded { code: 1 },
                64,
            ) else {
                continue;
            };
            if !self.icmp_error_limiter.allow(now_ms) {
                self.counters.icmp_errors_rate_limited =
                    self.counters.icmp_errors_rate_limited.saturating_add(1);
            } else if wire.len() <= self.mtu && self.queue_control_wire(&wire).is_ok() {
                self.counters.icmp_errors_sent = self.counters.icmp_errors_sent.saturating_add(1);
            }
        }
        Ok(())
    }

    /// Observes memory pressure and expires the state it shortens: idle UDP
    /// flows, incomplete fragments, and stale PMTU entries.
    fn expire_under_pressure(&mut self, now_ms: u64) -> Result<(), RunnerError> {
        let pressure = self.ledger.pressure();
        self.observe_pressure(now_ms, pressure);
        let timeout_divisor = match pressure {
            PressureLevel::Normal => 1,
            PressureLevel::Constrained => 2,
            PressureLevel::Critical => 4,
            PressureLevel::Exhausted => 8,
        };
        self.udp
            .expire_idle_under_pressure(now_ms, timeout_divisor)?;
        self.expire_fragments(now_ms, timeout_divisor)?;
        self.pmtu.expire(now_ms)?;
        Ok(())
    }

    /// When the runner next has work that no packet or command brings: a TCP
    /// timer, an idle UDP flow, a fragment or a PMTU entry to expire, the
    /// end of a shutdown, or, a tick on, resets it had no room to queue.
    /// `None` when it has none, so that an idle stack
    /// need not wake. It may come early, never late: a step at that time
    /// does the work due, and a step that changes it returns, so that the
    /// caller asks again.
    #[must_use]
    pub fn next_deadline_ms(&self) -> Option<u64> {
        let shutdown = match self.state {
            RunnerState::Draining { deadline_ms } => {
                Some(self.closing_until_ms.unwrap_or(deadline_ms))
            }
            _ => None,
        };
        let resets = (!self.pending_resets.is_empty())
            .then_some(self.tcp_timers.now_ms().saturating_add(self.timer_tick_ms));
        [
            resets,
            self.tcp_timers.next_deadline_ms(),
            self.udp.next_deadline_ms(),
            self.fragments.next_deadline_ms(),
            self.pmtu.next_deadline_ms(),
            shutdown,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Performs one bounded send/receive pass. `WouldBlock` is reported as a
    /// temporary outcome; other I/O errors transition the runner to `Failed`.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerError`] for permanent I/O failures, invalid platform
    /// counts, reversed virtual time, or a closed runner.
    pub async fn step(&mut self, now_ms: u64) -> Result<StepOutcome, RunnerError> {
        self.step_with_clock(now_ms, || now_ms).await
    }

    /// [`Self::step`], reading `clock` again for what it does after waiting
    /// on the device: a step that waits for packets as long as nothing is
    /// due takes them at the time they came, not at the one it began at.
    ///
    /// # Errors
    ///
    /// As [`Self::step`].
    pub async fn step_with_clock(
        &mut self,
        mut now_ms: u64,
        clock: impl Fn() -> u64,
    ) -> Result<StepOutcome, RunnerError> {
        match self.state {
            RunnerState::Created => {
                self.state = RunnerState::Running;
                self.trace.record(now_ms, TraceKind::RunnerStarted);
            }
            RunnerState::Closed | RunnerState::Failed => return Err(RunnerError::Closed),
            RunnerState::Running | RunnerState::Draining { .. } => {}
        }
        if let RunnerState::Draining { deadline_ms } = self.state {
            if now_ms >= deadline_ms {
                // The flows left are reset, so that their apps learn they
                // ended; the runner closes once those are sent, or soon.
                let until = if let Some(until) = self.closing_until_ms {
                    until
                } else {
                    let resets = self.tcp.abort_all();
                    self.queue_resets(resets);
                    let until = now_ms.saturating_add(CLOSING_FLUSH_MS);
                    self.closing_until_ms = Some(until);
                    until
                };
                let sent = self.pending_resets.is_empty() && self.pending_tx() == 0;
                if sent || now_ms >= until {
                    self.close();
                    return Ok(StepOutcome::default());
                }
            }
        }

        let mut outcome = StepOutcome::default();
        let deadline = self.next_deadline_ms();
        // Commands between steps (connect, write, read, close) run at the
        // table's clock, which only packets and timers moved: an idle shard
        // would date a connect's SYN seconds early.
        self.tcp.advance_clock(now_ms)?;
        self.expire_under_pressure(now_ms)?;
        self.advance_tcp_timers(now_ms, &mut outcome)?;
        // Adapters drop a pending step whenever a timer or command wins the
        // race, and events only exist in this outcome: hand them over before
        // any await. What the timers queued to send goes out next step.
        if !outcome.tcp_events.is_empty() {
            return Ok(outcome);
        }
        self.send_pending_resets();
        self.flush_tx(&mut outcome).await?;
        while !outcome.would_block
            && outcome.sent_packets < self.packets_per_step
            && (!self.tx.is_empty() || !self.tx_pending.is_empty())
        {
            let before = outcome.sent_packets;
            if poll_once(self.flush_tx(&mut outcome))
                .transpose()?
                .is_none()
                || outcome.sent_packets == before
            {
                break;
            }
        }
        if outcome.would_block || !self.tx.is_empty() {
            return Ok(outcome);
        }
        now_ms = self.read_clock(now_ms, &clock)?;
        self.process_scheduled(now_ms, &mut outcome)?;
        if outcome.processed_packets > 0 || self.pending_rx() > 0 {
            return Ok(outcome);
        }
        let mut received = PacketBatch::with_limit(self.capabilities.max_batch);
        // A step with packets left to send (past `packets_per_step`) does
        // not wait for packets, nor one that moved the next deadline: the
        // adapter sleeps until the one it read before the step, and would
        // wake late.
        let received_now = if self.tx_pending.is_empty() && self.next_deadline_ms() == deadline {
            self.recv_batch(&mut received).await
        } else {
            match poll_once(self.recv_batch(&mut received)) {
                Some(result) => result,
                None => return Ok(outcome),
            }
        };
        let reported = match received_now {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                outcome.would_block = true;
                return Ok(outcome);
            }
            Err(error) => return self.fail(error),
        };
        now_ms = self.read_clock(now_ms, &clock)?;
        self.take_received(&mut received, reported, now_ms, &mut outcome)?;
        // More while the device has them at once, as sending does.
        while outcome.received_packets < self.packets_per_step {
            let Some(result) = poll_once(self.recv_batch(&mut received)) else {
                break;
            };
            match result {
                Ok(reported) => {
                    self.take_received(&mut received, reported, now_ms, &mut outcome)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return self.fail(error),
            }
        }
        self.process_scheduled(now_ms, &mut outcome)?;
        Ok(outcome)
    }

    /// The time after an await: `clock`'s, never before `now_ms`, with the
    /// TCP table's clock moved to it. Timers due since go off next step.
    fn read_clock(&mut self, now_ms: u64, clock: &impl Fn() -> u64) -> Result<u64, RunnerError> {
        let now_ms = clock().max(now_ms);
        self.tcp.advance_clock(now_ms)?;
        Ok(now_ms)
    }

    /// Budgets and queues one batch the device returned.
    fn take_received(
        &mut self,
        received: &mut PacketBatch,
        reported: usize,
        now_ms: u64,
        outcome: &mut StepOutcome,
    ) -> Result<(), RunnerError> {
        if reported == 0 {
            return self.fail(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if reported != received.len() || reported > self.capabilities.max_batch {
            return self.fail_invalid("recv count does not match returned batch");
        }
        self.counters.rx_batches = self.counters.rx_batches.saturating_add(1);
        self.counters.rx_batch_packets = self
            .counters
            .rx_batch_packets
            .saturating_add(u64::try_from(reported).unwrap_or(u64::MAX));
        self.counters.rx_batch_max = self.counters.rx_batch_max.max(reported);
        self.trace
            .record(now_ms, TraceKind::RxBatch { packets: reported });
        outcome.received_packets = outcome.received_packets.saturating_add(reported);
        while let Some(packet) = received.pop_front() {
            increment_counter(&mut self.counters.rx_packets);
            self.counters.rx_bytes = self
                .counters
                .rx_bytes
                .saturating_add(u64::try_from(packet.payload().len()).unwrap_or(u64::MAX));
            match self.budget_and_enqueue(packet, now_ms) {
                Ok(EnqueueDisposition::Queued | EnqueueDisposition::Consumed) => {}
                Ok(EnqueueDisposition::Dropped(reason)) => {
                    self.record_drop(outcome, now_ms, reason);
                }
                Err(
                    RunnerError::Wire(_)
                    | RunnerError::Udp(UdpError::Wire(_))
                    | RunnerError::Tcp(TcpTableError::Wire(_))
                    | RunnerError::Fragment(
                        FragmentError::Wire(_)
                        | FragmentError::Malformed(_)
                        | FragmentError::Overlap,
                    ),
                ) => self.record_drop(outcome, now_ms, PacketDropReason::Wire),
                Err(
                    RunnerError::Budget(_)
                    | RunnerError::Udp(UdpError::Budget(_))
                    | RunnerError::Tcp(TcpTableError::Budget(_))
                    | RunnerError::Fragment(FragmentError::Budget(_))
                    | RunnerError::RxQueueFull,
                ) => {
                    self.record_drop(outcome, now_ms, PacketDropReason::Resource);
                }
                Err(RunnerError::PacketExceedsMtu | RunnerError::Tcp(_)) => {
                    self.record_drop(outcome, now_ms, PacketDropReason::Policy);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Queues a budgeted UDP reply for the next send pass.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale flow, an unfragmentable/budget-denied
    /// packet, full platform batch, reversed time, or a closed runner.
    pub fn queue_udp_reply(
        &mut self,
        token: UdpFlowToken,
        source: SocketAddr,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(), RunnerError> {
        if matches!(self.state, RunnerState::Closed | RunnerState::Failed) {
            return Err(RunnerError::Closed);
        }
        let wire = self.udp.emit_reply(token, source, payload, now_ms)?;
        self.queue_udp_wire(&wire, now_ms)
    }

    /// Sends a datagram from `local` to `remote`, opening the flow its
    /// replies come back on, and returns the flow's token and local address.
    /// Port 0 in `local` picks an ephemeral port whose replies reach this
    /// runner.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerError::ForeignFlow`] for an explicit local port whose
    /// replies go to another shard, a UDP error for unusable endpoints or
    /// payloads, or an error for TX backpressure or a closed runner.
    pub fn originate_udp(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<(UdpFlowToken, SocketAddr), RunnerError> {
        if matches!(self.state, RunnerState::Closed | RunnerState::Failed) {
            return Err(RunnerError::Closed);
        }
        let io = &self.io;
        let usable = |local| {
            io.owns_flow(IpEndpoint {
                source: remote,
                destination: local,
                protocol: TransportProtocol::Udp,
            })
        };
        if local.port() != 0 && !usable(local) {
            return Err(RunnerError::ForeignFlow);
        }
        let (token, local, wire) = self
            .udp
            .originate_using(local, remote, payload, now_ms, usable)?;
        self.queue_udp_wire(&wire, now_ms)?;
        Ok((token, local))
    }

    fn queue_udp_wire(&mut self, wire: &[u8], now_ms: u64) -> Result<(), RunnerError> {
        let destination = parse_ip_packet(wire, true)
            .map_err(RunnerError::Wire)?
            .destination;
        let path_mtu = self.pmtu.effective_mtu(destination, self.mtu, now_ms)?;
        if wire.len() <= path_mtu {
            return self.queue_wire(wire);
        }
        let identification = self.next_fragment_identification;
        self.next_fragment_identification = self.next_fragment_identification.wrapping_add(1);
        let fragments = fragment_outbound_ip_packet(wire, path_mtu, identification)
            .map_err(RunnerError::Wire)?;
        self.queue_wires(&fragments)?;
        self.counters.outbound_fragments = self
            .counters
            .outbound_fragments
            .saturating_add(u64::try_from(fragments.len()).unwrap_or(u64::MAX));
        Ok(())
    }

    /// Opens a TCP connection from `local` to `remote` and queues its SYN.
    /// Port 0 in `local` picks an ephemeral port whose replies reach this
    /// runner. [`StepOutcome::tcp_events`] reports
    /// [`TcpEvent::Connected`](crate::TcpEvent::Connected) when the handshake
    /// completes, or [`TcpEvent::Closed`](crate::TcpEvent::Closed) when it
    /// fails.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerError::ForeignFlow`] for an explicit local port whose
    /// replies go to another shard, a TCP error for unusable or taken
    /// endpoints, or an error for TX backpressure, exhausted memory, or a
    /// closed runner.
    pub fn connect_tcp(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<TcpFlowToken, RunnerError> {
        self.ensure_open()?;
        let io = &self.io;
        let usable = |local| {
            io.owns_flow(IpEndpoint {
                source: remote,
                destination: local,
                protocol: TransportProtocol::Tcp,
            })
        };
        if local.port() != 0 && !usable(local) {
            return Err(RunnerError::ForeignFlow);
        }
        let allocation = self.reserve_tcp_control()?;
        let (token, output) = self.tcp.connect_using(local, remote, usable)?;
        self.finish_tcp_output(allocation, output)?;
        Ok(token)
    }

    /// Removes a completed handshake from the bounded accept queue.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale token or a closed runner.
    pub fn accept_tcp(&mut self, token: TcpFlowToken) -> Result<TcpConnection, RunnerError> {
        self.ensure_open()?;
        self.tcp.accept(token).map_err(Into::into)
    }

    /// Reads received TCP bytes and queues the resulting window update before
    /// returning bytes to the application.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, TX backpressure, or exhausted packet
    /// memory. The receive state is unchanged if control capacity cannot first
    /// be reserved.
    pub fn read_tcp(
        &mut self,
        token: TcpFlowToken,
        max_bytes: usize,
    ) -> Result<Vec<u8>, RunnerError> {
        self.ensure_open()?;
        if max_bytes == 0 {
            return self
                .tcp
                .read(token, 0)
                .map(|read| read.bytes)
                .map_err(Into::into);
        }
        let allocation = self.reserve_tcp_control()?;
        let read = self.tcp.read(token, max_bytes)?;
        self.queue_reserved_control(allocation, read.outgoing)?;
        let now_ms = self.tcp_timers.now_ms();
        self.apply_tcp_timer_updates(&read.cancelled_timers, &read.timers, &[], now_ms)?;
        Ok(read.bytes)
    }

    /// Sends one bounded TCP segment. The payload remains charged to the TCP
    /// pool until acknowledged and is retained for RTO retransmission.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/unaccepted state, an outstanding segment,
    /// peer-window backpressure, TX backpressure, or exhausted memory.
    pub fn write_tcp(
        &mut self,
        token: TcpFlowToken,
        payload: &[u8],
    ) -> Result<TcpIngress, RunnerError> {
        self.ensure_open()?;
        if payload.len() > self.tcp.max_segment_payload_bytes() {
            return Err(TcpTableError::PayloadTooLarge.into());
        }
        if payload.is_empty() {
            return self.tcp.write(token, payload).map_err(Into::into);
        }
        let packet_capacity = self.tcp.packet_len(token, payload.len())?;
        if packet_capacity > self.mtu {
            return Err(RunnerError::PacketExceedsMtu);
        }
        let allocation = self.reserve_tcp_packet(packet_capacity)?;
        let output = self.tcp.write(token, payload)?;
        self.finish_tcp_output(allocation, output)
    }

    /// Sends `payload` as many segments as it takes, each no larger than the
    /// flow's segment size, and returns how many bytes it took. It stops at
    /// the first segment it cannot send and reports the bytes before it;
    /// the caller offers the rest again once the flow is writable. Sized by
    /// [`Self::tcp_write_capacity`], it takes the whole payload unless
    /// packet or payload memory runs out.
    ///
    /// # Errors
    ///
    /// Returns the error of the first segment when it could send none.
    pub fn write_tcp_segments(
        &mut self,
        token: TcpFlowToken,
        payload: &[u8],
    ) -> Result<(usize, TcpIngress), RunnerError> {
        let segment = self.tcp_write_limit(token)?;
        let mut written = 0;
        let mut ingress = TcpIngress::default();
        while written < payload.len() {
            let end = payload.len().min(written + segment);
            match self.write_tcp(token, &payload[written..end]) {
                Ok(output) => {
                    ingress.outgoing.extend(output.outgoing);
                    ingress.events.extend(output.events);
                    ingress.timers.extend(output.timers);
                    ingress.cancelled_timers.extend(output.cancelled_timers);
                    written = end;
                }
                Err(error) if written == 0 => return Err(error),
                Err(_) => break,
            }
        }
        Ok((written, ingress))
    }

    /// Returns the current peer- and PMTU-constrained TCP write size.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale flow or closed runner.
    pub fn tcp_write_limit(&mut self, token: TcpFlowToken) -> Result<usize, RunnerError> {
        self.ensure_open()?;
        self.tcp.write_limit(token).map_err(Into::into)
    }

    /// Returns the number of bytes an application write can hand to TCP now.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale flow or closed runner.
    pub fn tcp_write_capacity(&mut self, token: TcpFlowToken) -> Result<usize, RunnerError> {
        self.ensure_open()?;
        self.tcp.write_capacity(token).map_err(Into::into)
    }

    /// Starts an orderly TCP close and queues its control segment.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, TX backpressure, or exhausted packet memory.
    pub fn close_tcp(&mut self, token: TcpFlowToken) -> Result<TcpIngress, RunnerError> {
        self.ensure_open()?;
        let allocation = self.reserve_tcp_control()?;
        let output = self.tcp.close(token)?;
        self.finish_tcp_output(allocation, output)
    }

    /// Lets go of a TCP flow the application has closed: see
    /// [`crate::TcpTable::release`].
    ///
    /// # Errors
    ///
    /// Returns an error for stale state.
    pub fn release_tcp(&mut self, token: TcpFlowToken) -> Result<TcpIngress, RunnerError> {
        self.ensure_open()?;
        let allocation = self.reserve_tcp_control()?;
        let output = self.tcp.release(token)?;
        self.finish_tcp_output(allocation, output)
    }

    /// Aborts a TCP flow and queues RST before releasing it.
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, TX backpressure, or exhausted packet memory.
    pub fn abort_tcp(&mut self, token: TcpFlowToken) -> Result<TcpIngress, RunnerError> {
        self.ensure_open()?;
        let allocation = self.reserve_tcp_control()?;
        let output = self.tcp.abort(token)?;
        self.finish_tcp_output(allocation, output)
    }

    /// Applies a TCP timer request previously returned by [`SingleShardRunner::step`].
    ///
    /// # Errors
    ///
    /// Returns an error for stale state, TX backpressure, or exhausted packet memory.
    pub fn fire_tcp_timer(
        &mut self,
        token: TcpFlowToken,
        event: TimerEvent,
    ) -> Result<TcpIngress, RunnerError> {
        self.ensure_open()?;
        let allocation = self.reserve_tcp_control()?;
        let output = self.tcp.on_timer(token, event)?;
        self.finish_tcp_output(allocation, output)
    }

    pub fn shutdown(&mut self, deadline_ms: u64) {
        if matches!(self.state, RunnerState::Created | RunnerState::Running) {
            self.state = RunnerState::Draining { deadline_ms };
            self.counters.shutdowns = self.counters.shutdowns.saturating_add(1);
            self.trace.record(
                self.tcp_timers.now_ms(),
                TraceKind::ShutdownRequested { deadline_ms },
            );
        }
    }

    pub fn abort(&mut self) {
        self.counters.aborts = self.counters.aborts.saturating_add(1);
        self.trace
            .record(self.tcp_timers.now_ms(), TraceKind::Aborted);
        self.close();
    }

    pub fn reset_network(&mut self, generation: NetworkGeneration) {
        // Each flow's reset, before its state goes: an app that only reads
        // would otherwise wait for its own timeout.
        let resets = self.tcp.abort_all();
        self.udp.reset_network(generation);
        self.tcp.reset_network(generation);
        self.fragments.clear();
        self.pmtu.reset_network(generation);
        self.icmp_echo_limiter.reset();
        self.icmp_error_limiter.reset();
        self.fragment_limiter.reset();
        self.clear_scheduled();
        self.tx = PacketBatch::with_limit(self.capabilities.max_batch);
        self.tx_pending.clear();
        self.clear_tcp_timers();
        // Added to those of a reset before not yet sent (a phone's Wi-Fi
        // gone and its cellular up, close together): the next step sends
        // them, after the TX queue this reset cleared.
        self.queue_resets(resets);
        self.counters.network_resets = self.counters.network_resets.saturating_add(1);
        self.trace.record(
            self.tcp_timers.now_ms(),
            TraceKind::NetworkReset {
                generation: generation.get(),
            },
        );
    }

    /// # Errors
    ///
    /// Returns [`RunnerError::InvalidConfig`] for an invalid MTU.
    pub fn update_mtu(&mut self, mtu: usize) -> Result<(), RunnerError> {
        if !(576..=65_535).contains(&mtu) || mtu > self.arena.max_packet_size() {
            return Err(RunnerError::InvalidConfig("invalid runtime MTU"));
        }
        self.mtu = mtu;
        self.tcp.set_link_mtu(mtu);
        self.tcp.lower_platform_mtu(mtu);
        self.counters.mtu_changes = self.counters.mtu_changes.saturating_add(1);
        self.trace
            .record(self.tcp_timers.now_ms(), TraceKind::MtuChanged { mtu });
        Ok(())
    }

    /// Expires UDP state even when no packets arrive.
    ///
    /// # Errors
    ///
    /// Returns an error if virtual time moves backwards.
    pub fn advance_time(&mut self, now_ms: u64) -> Result<usize, RunnerError> {
        self.udp.expire_idle(now_ms).map_err(Into::into)
    }

    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the snapshot maps every public counter explicitly"
    )]
    pub fn stats_snapshot(&self) -> StackStats {
        let fragments = self.fragments.stats();
        let pmtu = self.pmtu.stats();
        let tcp = self.tcp.stats();
        let udp = self.udp.stats();
        let scheduler = self.scheduler.snapshot();
        StackStats {
            generation: self.udp.generation(),
            resources: self.ledger.snapshot(),
            rx_packets: self.counters.rx_packets,
            rx_bytes: self.counters.rx_bytes,
            rx_batches: self.counters.rx_batches,
            rx_batch_packets: self.counters.rx_batch_packets,
            rx_batch_max: self.counters.rx_batch_max,
            rx_io_wakeups: self.counters.rx_io_wakeups,
            tx_packets: self.counters.tx_packets,
            tx_bytes: self.counters.tx_bytes,
            tx_batches: self.counters.tx_batches,
            tx_batch_packets: self.counters.tx_batch_packets,
            tx_batch_max: self.counters.tx_batch_max,
            tx_io_wakeups: self.counters.tx_io_wakeups,
            dropped_packets: self.counters.dropped_packets,
            dropped_wire_packets: self.counters.dropped_wire_packets,
            dropped_resource_packets: self.counters.dropped_resource_packets,
            dropped_policy_packets: self.counters.dropped_policy_packets,
            dropped_rate_limited_packets: self.counters.dropped_rate_limited_packets,
            dropped_output_packets: self.counters.dropped_output_packets,
            dropped_other_packets: self.counters.dropped_other_packets,
            partial_sends: self.counters.partial_sends,
            runner_failures: self.counters.runner_failures,
            shutdowns: self.counters.shutdowns,
            aborts: self.counters.aborts,
            network_resets: self.counters.network_resets,
            reset_rsts_dropped: self.counters.reset_rsts_dropped,
            mtu_changes: self.counters.mtu_changes,
            scheduler_rounds: self.counters.scheduler_rounds,
            scheduler_packets: self.counters.scheduler_packets,
            scheduler_bytes: self.counters.scheduler_bytes,
            scheduler_control_packets_processed: self.counters.scheduler_control_packets_processed,
            scheduler_active_flow_visits: self.counters.scheduler_active_flow_visits,
            scheduler_time_budget_exhaustions: self.counters.scheduler_time_budget_exhaustions,
            scheduler_active_flows: scheduler.active_flows,
            scheduler_queued_packets: scheduler.queued_packets,
            scheduler_queued_bytes: scheduler.queued_bytes,
            scheduler_control_packets: scheduler.control_packets,
            pressure_transitions: self.counters.pressure_transitions,
            pressure_constrained_entries: self.counters.pressure_constrained_entries,
            pressure_critical_entries: self.counters.pressure_critical_entries,
            pressure_exhausted_entries: self.counters.pressure_exhausted_entries,
            pressure_rejected_new_flows: self.counters.pressure_rejected_new_flows,
            icmp_echo_replies: self.counters.icmp_echo_replies,
            icmp_echo_rate_limited: self.counters.icmp_echo_rate_limited,
            icmp_errors_sent: self.counters.icmp_errors_sent,
            icmp_errors_rate_limited: self.counters.icmp_errors_rate_limited,
            fragment_packets_rate_limited: self.counters.fragment_packets_rate_limited,
            outbound_fragments: self.counters.outbound_fragments,
            pmtu_entries: pmtu.active_entries,
            pmtu_learned: pmtu.learned,
            pmtu_lowered: pmtu.lowered,
            pmtu_expired: pmtu.expired,
            pmtu_evicted: pmtu.evicted,
            pmtu_rejected: pmtu.rejected,
            tcp_active_flows: tcp.active_flows,
            tcp_peak_active_flows: tcp.peak_active_flows,
            tcp_time_wait: tcp.time_wait,
            tcp_peak_time_wait: tcp.peak_time_wait,
            tcp_syn_received: tcp.syn_received,
            tcp_peak_syn_received: tcp.peak_syn_received,
            tcp_accept_queue: tcp.accept_queue,
            tcp_peak_accept_queue: tcp.peak_accept_queue,
            tcp_buffered_bytes: tcp.buffered_bytes,
            tcp_send_buffered_bytes: tcp.send_buffered_bytes,
            tcp_created_flows: tcp.created_flows,
            tcp_closed_flows: tcp.closed_flows,
            tcp_time_wait_evictions: tcp.time_wait_evictions,
            tcp_malformed_packets: tcp.malformed_packets,
            tcp_invalid_address_drops: tcp.invalid_address_drops,
            tcp_timestamp_missing_drops: tcp.timestamp_missing_drops,
            tcp_paws_rejections: tcp.paws_rejections,
            tcp_window_scale_clamps: tcp.window_scale_clamps,
            tcp_stale_operations: tcp.stale_operations,
            tcp_zero_window_writes: tcp.zero_window_writes,
            tcp_persist_probes: tcp.persist_probes,
            tcp_keepalive_probes: tcp.keepalive_probes,
            tcp_keepalive_timeouts: tcp.keepalive_timeouts,
            tcp_nagle_buffered_writes: tcp.nagle_buffered_writes,
            tcp_sack_recovery_events: tcp.sack_recovery_events,
            tcp_sack_retransmitted_segments: tcp.sack_retransmitted_segments,
            tcp_sack_rescue_segments: tcp.sack_rescue_segments,
            tcp_retransmission_timeouts: tcp.retransmission_timeouts,
            tcp_retransmission_failures: tcp.retransmission_failures,
            tcp_black_hole_mtu_fallbacks: tcp.black_hole_mtu_fallbacks,
            tcp_syns_rate_limited: tcp.syns_rate_limited,
            tcp_defensive_acks_sent: tcp.defensive_acks_sent,
            tcp_defensive_acks_rate_limited: tcp.defensive_acks_rate_limited,
            tcp_challenge_acks_sent: tcp.challenge_acks_sent,
            tcp_challenge_acks_rate_limited: tcp.challenge_acks_rate_limited,
            tcp_stateless_resets_sent: tcp.stateless_resets_sent,
            tcp_stateless_resets_rate_limited: tcp.stateless_resets_rate_limited,
            tcp_accept_overflow_drops: tcp.accept_overflow_drops,
            tcp_accept_overflow_rejections: tcp.accept_overflow_rejections,
            tcp_pressure_reclaimed_syns: tcp.pressure_reclaimed_syns,
            tcp_receive_pressure_drops: tcp.receive_pressure_drops,
            udp_active_flows: udp.active_flows,
            udp_peak_active_flows: udp.peak_active_flows,
            udp_created_flows: udp.created_flows,
            udp_expired_flows: udp.expired_flows,
            udp_stale_replies: udp.stale_replies,
            udp_malformed_packets: udp.malformed_packets,
            udp_invalid_address_drops: udp.invalid_address_drops,
            fragment_datagrams: fragments.active_datagrams,
            buffered_fragments: fragments.buffered_fragments,
            completed_reassemblies: fragments.completed_datagrams,
            expired_reassemblies: fragments.expired_datagrams,
            evicted_reassemblies: fragments.evicted_datagrams,
            overlapping_fragment_drops: fragments.overlap_drops,
        }
    }

    async fn recv_batch(&mut self, received: &mut PacketBatch) -> io::Result<usize> {
        await_io(self.io.recv(received), &mut self.counters.rx_io_wakeups).await
    }

    async fn flush_tx(&mut self, outcome: &mut StepOutcome) -> Result<(), RunnerError> {
        self.fill_tx_batch();
        if self.tx.is_empty() {
            return Ok(());
        }
        let before = self.tx.len();
        let sent = match await_io(self.io.send(&self.tx), &mut self.counters.tx_io_wakeups).await {
            Ok(0) => return self.fail(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                outcome.would_block = true;
                return Ok(());
            }
            Err(error) => return self.fail(error),
        };
        if sent > before {
            return self.fail_invalid("send count exceeds supplied batch");
        }
        let sent_bytes = self
            .tx
            .iter()
            .take(sent)
            .map(|packet| packet.payload().len())
            .sum::<usize>();
        self.tx.acknowledge_sent(sent).map_err(RunnerError::Io)?;
        self.counters.tx_batches = self.counters.tx_batches.saturating_add(1);
        self.counters.tx_batch_packets = self
            .counters
            .tx_batch_packets
            .saturating_add(u64::try_from(sent).unwrap_or(u64::MAX));
        self.counters.tx_batch_max = self.counters.tx_batch_max.max(sent);
        if sent < before {
            increment_counter(&mut self.counters.partial_sends);
            self.trace.record(
                self.tcp_timers.now_ms(),
                TraceKind::PartialSend {
                    sent,
                    pending: before - sent,
                },
            );
        }
        self.counters.tx_packets = self
            .counters
            .tx_packets
            .saturating_add(u64::try_from(sent).unwrap_or(u64::MAX));
        self.counters.tx_bytes = self
            .counters
            .tx_bytes
            .saturating_add(u64::try_from(sent_bytes).unwrap_or(u64::MAX));
        outcome.sent_packets = outcome.sent_packets.saturating_add(sent);
        self.trace.record(
            self.tcp_timers.now_ms(),
            TraceKind::TxBatch { packets: sent },
        );
        Ok(())
    }

    fn close(&mut self) {
        self.trace
            .record(self.tcp_timers.now_ms(), TraceKind::RunnerClosed);
        self.udp.clear();
        self.tcp.reset_network(self.udp.generation());
        self.fragments.clear();
        self.pmtu.clear();
        self.clear_scheduled();
        self.tx = PacketBatch::with_limit(self.capabilities.max_batch);
        self.tx_pending.clear();
        self.pending_resets.clear();
        self.closing_until_ms = None;
        self.clear_tcp_timers();
        self.state = RunnerState::Closed;
    }

    fn fail<T>(&mut self, error: io::Error) -> Result<T, RunnerError> {
        increment_counter(&mut self.counters.runner_failures);
        self.trace
            .record(self.tcp_timers.now_ms(), TraceKind::RunnerFailed);
        self.udp.clear();
        self.tcp.reset_network(self.udp.generation());
        self.fragments.clear();
        self.pmtu.clear();
        self.clear_scheduled();
        self.tx = PacketBatch::with_limit(self.capabilities.max_batch);
        self.tx_pending.clear();
        self.clear_tcp_timers();
        self.state = RunnerState::Failed;
        Err(RunnerError::Io(error))
    }

    fn fail_invalid<T>(&mut self, message: &'static str) -> Result<T, RunnerError> {
        increment_counter(&mut self.counters.runner_failures);
        self.trace
            .record(self.tcp_timers.now_ms(), TraceKind::RunnerFailed);
        self.udp.clear();
        self.tcp.reset_network(self.udp.generation());
        self.fragments.clear();
        self.pmtu.clear();
        self.clear_scheduled();
        self.tx = PacketBatch::with_limit(self.capabilities.max_batch);
        self.tx_pending.clear();
        self.clear_tcp_timers();
        self.state = RunnerState::Failed;
        Err(RunnerError::InvalidIoReport(message))
    }

    fn record_drop(&mut self, outcome: &mut StepOutcome, now_ms: u64, reason: PacketDropReason) {
        self.counters.record_drop(reason);
        outcome.dropped_packets = outcome.dropped_packets.saturating_add(1);
        self.trace
            .record(now_ms, TraceKind::PacketsDropped { count: 1 });
    }

    fn budget_and_enqueue(
        &mut self,
        packet: Packet,
        now_ms: u64,
    ) -> Result<EnqueueDisposition, RunnerError> {
        let initial_ip = self.parse_initial_ip(packet.payload(), now_ms)?;
        // The MTU bounds what this stack sends. For the flows it ends it is
        // the host, which takes any packet it has room for (RFC 1122 3.3.2,
        // RFC 8200 5): a tunnel peer with a larger MTU is still heard.
        if packet.payload().len() > self.arena.max_packet_size() {
            let error = match initial_ip.version {
                IpVersion::V6 => Some(IcmpErrorKind::PacketTooBig {
                    mtu: u32::try_from(self.mtu).unwrap_or(u32::MAX),
                }),
                IpVersion::V4 if packet.payload().get(6).is_some_and(|byte| byte & 0x40 != 0) => {
                    Some(IcmpErrorKind::PacketTooBig {
                        mtu: u32::try_from(self.mtu).unwrap_or(u32::MAX),
                    })
                }
                IpVersion::V4 => None,
            };
            if let Some(error) = error {
                if let Ok(wire) = emit_icmp_error(packet.payload(), error, 64) {
                    if !self.icmp_error_limiter.allow(now_ms) {
                        increment_counter(&mut self.counters.icmp_errors_rate_limited);
                    } else if wire.len() <= self.mtu && self.queue_control_wire(&wire).is_ok() {
                        increment_counter(&mut self.counters.icmp_errors_sent);
                    }
                }
            }
            return Err(RunnerError::PacketExceedsMtu);
        }
        let reassembled;
        let mut whole = true;
        let payload = if initial_ip
            .fragment
            .is_some_and(|fragment| !fragment.is_atomic())
        {
            if !self.fragment_limiter.allow(now_ms) {
                self.counters.fragment_packets_rate_limited = self
                    .counters
                    .fragment_packets_rate_limited
                    .saturating_add(1);
                return Ok(EnqueueDisposition::Dropped(PacketDropReason::RateLimited));
            }
            let Some(packet) = self.fragments.ingest(packet.payload(), now_ms)? else {
                return Ok(EnqueueDisposition::Consumed);
            };
            reassembled = packet;
            whole = false;
            reassembled.as_slice()
        } else {
            packet.payload()
        };
        let ip = parse_ip_packet(payload, true).map_err(RunnerError::Wire)?;
        let work_class = match ip.next_header {
            6 => {
                // Its class needs only the ports and whether it carries
                // data; the table checks the checksum when it takes it.
                let segment = parse_tcp_segment(ip, false).map_err(RunnerError::Wire)?;
                if segment.payload.is_empty() {
                    WorkClass::Control
                } else {
                    let flow_key = (
                        segment.source,
                        segment.destination,
                        self.udp.generation().get(),
                    );
                    WorkClass::Data {
                        flow: FlowId::new(self.flow_hasher.hash_one(flow_key)),
                        weight: 1,
                    }
                }
            }
            17 => {
                let datagram = parse_udp_datagram(ip, false).map_err(RunnerError::Wire)?;
                let flow_key = (
                    datagram.source,
                    datagram.destination,
                    self.udp.generation().get(),
                );
                WorkClass::Data {
                    flow: FlowId::new(self.flow_hasher.hash_one(flow_key)),
                    weight: 1,
                }
            }
            1 if matches!(ip.version, IpVersion::V4) => WorkClass::Control,
            58 if matches!(ip.version, IpVersion::V6) => WorkClass::Control,
            _ => WorkClass::Control,
        };
        let packet_len = payload.len();
        let kind = match work_class {
            WorkClass::Control => ResourceKind::ControlPacketBytes,
            WorkClass::Data { .. } => ResourceKind::PacketBytes,
        };
        let token = PacketToken::new(self.next_packet_token);
        self.next_packet_token = self.next_packet_token.wrapping_add(1);
        // A whole packet the platform handed over unbudgeted is kept as it
        // came, its storage charged: copied into storage of the arena's it
        // cost an allocation, zeroing it and the copy, on every packet.
        let owned = if whole && !packet.is_budgeted() {
            let lease = self.arena.charge(kind, packet.storage_len())?;
            packet.budgeted(token, lease)
        } else {
            let mut allocation = self.arena.allocate_from(kind, 0, packet_len)?;
            allocation.payload_capacity_mut().copy_from_slice(payload);
            allocation.set_len(packet_len)?;
            Packet::from_arena(token, allocation)
        };
        self.scheduler
            .enqueue(work_class, packet_len, owned)
            .map_err(|_| RunnerError::RxQueueFull)?;
        Ok(EnqueueDisposition::Queued)
    }

    fn parse_initial_ip<'packet>(
        &mut self,
        packet: &'packet [u8],
        now_ms: u64,
    ) -> Result<crate::ParsedIpPacket<'packet>, RunnerError> {
        match parse_ip_packet(packet, true) {
            Ok(ip) => Ok(ip),
            Err(error @ WireError::Ipv6OptionDiscard { pointer, send_icmp }) => {
                self.handle_ipv6_parameter_problem(packet, 2, pointer, send_icmp, now_ms);
                Err(RunnerError::Wire(error))
            }
            Err(error @ WireError::Ipv6RoutingDiscard { pointer }) => {
                self.handle_ipv6_parameter_problem(packet, 0, pointer, true, now_ms);
                Err(RunnerError::Wire(error))
            }
            Err(error @ WireError::Ipv6NextHeaderDiscard { pointer }) => {
                self.handle_ipv6_parameter_problem(packet, 1, pointer, true, now_ms);
                Err(RunnerError::Wire(error))
            }
            Err(error) => Err(RunnerError::Wire(error)),
        }
    }

    fn handle_ipv6_parameter_problem(
        &mut self,
        packet: &[u8],
        code: u8,
        pointer: u32,
        send_icmp: bool,
        now_ms: u64,
    ) {
        if !send_icmp {
            return;
        }
        let Ok(wire) = emit_icmp_error(
            packet,
            IcmpErrorKind::ParameterProblem { code, pointer },
            64,
        ) else {
            return;
        };
        if !self.icmp_error_limiter.allow(now_ms) {
            increment_counter(&mut self.counters.icmp_errors_rate_limited);
        } else if wire.len() <= self.mtu && self.queue_control_wire(&wire).is_ok() {
            increment_counter(&mut self.counters.icmp_errors_sent);
        }
    }

    fn process_scheduled(
        &mut self,
        now_ms: u64,
        outcome: &mut StepOutcome,
    ) -> Result<(), RunnerError> {
        let available_tx_slots = self
            .tx_pending_limit
            .saturating_sub(self.tx.len() + self.tx_pending.len());
        let timer_start = outcome.tcp_timers.len();
        let cancel_start = outcome.tcp_cancelled_timers.len();
        let event_start = outcome.tcp_events.len();
        let pressure_blocks_new = matches!(
            self.ledger.admission(),
            PressureLevel::Critical | PressureLevel::Exhausted
        );
        let mut context = ScheduledContext {
            allow_new: matches!(self.state, RunnerState::Running) && !pressure_blocks_new,
            pressure_blocks_new,
            now_ms,
            udp: &mut self.udp,
            tcp: &mut self.tcp,
            arena: &self.arena,
            counters: &mut self.counters,
            icmp_echo_limiter: &mut self.icmp_echo_limiter,
            icmp_error_limiter: &mut self.icmp_error_limiter,
            pmtu: &mut self.pmtu,
            outcome,
            available_tx_slots,
            headroom: self.capabilities.headroom,
            mtu: self.mtu,
            output_packets: Vec::new(),
            fatal: None,
            trace: &mut self.trace,
        };
        let stats = self
            .scheduler
            .run_round(|_, packet| context.process(&packet));
        let output_packets = std::mem::take(&mut context.output_packets);
        let fatal = context.fatal.take();
        drop(context);
        for allocation in output_packets {
            let token = PacketToken::new(self.next_packet_token);
            self.next_packet_token = self.next_packet_token.wrapping_add(1);
            self.tx_pending
                .push_back(Packet::from_arena(token, allocation));
        }
        let new_cancellations = outcome.tcp_cancelled_timers[cancel_start..].to_vec();
        let new_timers = outcome.tcp_timers[timer_start..].to_vec();
        let new_events = outcome.tcp_events[event_start..].to_vec();
        self.apply_tcp_timer_updates(&new_cancellations, &new_timers, &new_events, now_ms)?;
        self.counters.scheduler_rounds = self.counters.scheduler_rounds.saturating_add(1);
        self.counters.scheduler_packets = self
            .counters
            .scheduler_packets
            .saturating_add(u64::try_from(stats.packets).unwrap_or(u64::MAX));
        self.counters.scheduler_bytes = self
            .counters
            .scheduler_bytes
            .saturating_add(u64::try_from(stats.bytes).unwrap_or(u64::MAX));
        self.counters.scheduler_control_packets_processed = self
            .counters
            .scheduler_control_packets_processed
            .saturating_add(u64::try_from(stats.control_packets).unwrap_or(u64::MAX));
        self.counters.scheduler_active_flow_visits = self
            .counters
            .scheduler_active_flow_visits
            .saturating_add(u64::try_from(stats.active_flows_visited).unwrap_or(u64::MAX));
        if stats.time_budget_exhausted {
            self.counters.scheduler_time_budget_exhaustions = self
                .counters
                .scheduler_time_budget_exhaustions
                .saturating_add(1);
        }
        if stats.packets > 0 || stats.time_budget_exhausted {
            self.trace.record(
                now_ms,
                TraceKind::SchedulerRound {
                    packets: stats.packets,
                    bytes: stats.bytes,
                },
            );
        }
        outcome.processed_packets = outcome.processed_packets.saturating_add(stats.packets);
        fatal.map_or(Ok(()), Err)
    }

    fn clear_scheduled(&mut self) {
        self.scheduler.clear();
    }

    fn queue_wire(&mut self, wire: &[u8]) -> Result<(), RunnerError> {
        self.queue_wires(std::slice::from_ref(&wire))
    }

    /// Holds `resets` to send, up to `RESET_QUEUE_CAP`; those past it are
    /// counted.
    fn queue_resets(&mut self, resets: Vec<Vec<u8>>) {
        for wire in resets {
            if self.pending_resets.len() < RESET_QUEUE_CAP {
                self.pending_resets.push_back(wire);
            } else {
                increment_counter(&mut self.counters.reset_rsts_dropped);
            }
        }
    }

    /// Moves held resets to the TX queue while it and the control pool
    /// take them; the rest wait for the next step.
    fn send_pending_resets(&mut self) {
        while let Some(wire) = self.pending_resets.pop_front() {
            match self.queue_control_wire(&wire) {
                Ok(()) => {}
                Err(RunnerError::PacketExceedsMtu) => {
                    increment_counter(&mut self.counters.reset_rsts_dropped);
                }
                Err(_) => {
                    self.pending_resets.push_front(wire);
                    break;
                }
            }
        }
    }

    fn queue_control_wire(&mut self, wire: &[u8]) -> Result<(), RunnerError> {
        if self.pending_tx() >= self.tx_pending_limit {
            return Err(RunnerError::TxQueueFull);
        }
        if wire.len() > self.mtu {
            return Err(RunnerError::PacketExceedsMtu);
        }
        let mut allocation = self
            .arena
            .allocate_control(self.capabilities.headroom, wire.len())?;
        allocation.payload_capacity_mut().copy_from_slice(wire);
        allocation.set_len(wire.len())?;
        let token = PacketToken::new(self.next_packet_token);
        self.next_packet_token = self.next_packet_token.wrapping_add(1);
        self.tx_pending
            .push_back(Packet::from_arena(token, allocation));
        Ok(())
    }

    fn queue_wires<T: AsRef<[u8]>>(&mut self, wires: &[T]) -> Result<(), RunnerError> {
        if self.pending_tx().saturating_add(wires.len()) > self.tx_pending_limit {
            return Err(RunnerError::TxQueueFull);
        }
        let mut allocations = Vec::with_capacity(wires.len());
        for wire in wires {
            let wire = wire.as_ref();
            if wire.len() > self.mtu {
                return Err(RunnerError::PacketExceedsMtu);
            }
            let mut allocation = self
                .arena
                .allocate(self.capabilities.headroom, wire.len())?;
            allocation.payload_capacity_mut().copy_from_slice(wire);
            allocation.set_len(wire.len())?;
            allocations.push(allocation);
        }
        for allocation in allocations {
            let token = PacketToken::new(self.next_packet_token);
            self.next_packet_token = self.next_packet_token.wrapping_add(1);
            self.tx_pending
                .push_back(Packet::from_arena(token, allocation));
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), RunnerError> {
        if matches!(self.state, RunnerState::Closed | RunnerState::Failed) {
            Err(RunnerError::Closed)
        } else {
            Ok(())
        }
    }

    fn reserve_tcp_control(&self) -> Result<ArenaPacket, RunnerError> {
        self.reserve_tcp_control_packet(TCP_CONTROL_PACKET_BYTES)
    }

    fn reserve_tcp_packet(&self, capacity: usize) -> Result<ArenaPacket, RunnerError> {
        if self.pending_tx() >= self.tx_pending_limit {
            return Err(RunnerError::TxQueueFull);
        }
        self.arena
            .allocate(self.capabilities.headroom, capacity)
            .map_err(Into::into)
    }

    fn reserve_tcp_control_packet(&self, capacity: usize) -> Result<ArenaPacket, RunnerError> {
        if self.pending_tx() >= self.tx_pending_limit {
            return Err(RunnerError::TxQueueFull);
        }
        self.arena
            .allocate_control(self.capabilities.headroom, capacity)
            .map_err(Into::into)
    }

    fn queue_reserved_control(
        &mut self,
        mut allocation: ArenaPacket,
        mut outgoing: Vec<Vec<u8>>,
    ) -> Result<(), RunnerError> {
        if outgoing.len() > 1 {
            return Err(TcpTableError::Invariant(
                "one TCP operation emitted multiple control packets",
            )
            .into());
        }
        let Some(wire) = outgoing.pop() else {
            return Ok(());
        };
        if wire.len() > self.mtu || wire.len() > allocation.capacity() {
            return Err(RunnerError::PacketExceedsMtu);
        }
        allocation.payload_capacity_mut()[..wire.len()].copy_from_slice(&wire);
        allocation.set_len(wire.len())?;
        let packet_token = PacketToken::new(self.next_packet_token);
        self.next_packet_token = self.next_packet_token.wrapping_add(1);
        self.tx_pending
            .push_back(Packet::from_arena(packet_token, allocation));
        Ok(())
    }

    fn finish_tcp_output(
        &mut self,
        allocation: ArenaPacket,
        mut output: TcpIngress,
    ) -> Result<TcpIngress, RunnerError> {
        self.queue_reserved_control(allocation, std::mem::take(&mut output.outgoing))?;
        let now_ms = self.tcp_timers.now_ms();
        self.apply_tcp_timer_updates(
            &output.cancelled_timers,
            &output.timers,
            &output.events,
            now_ms,
        )?;
        Ok(output)
    }

    fn apply_tcp_timer_updates(
        &mut self,
        cancellations: &[TcpTimerCancel],
        timers: &[TcpTimerRequest],
        events: &[TcpEvent],
        now_ms: u64,
    ) -> Result<(), RunnerError> {
        for cancellation in cancellations {
            self.disarm_tcp_timer(cancellation.token, cancellation.event);
        }
        for event in events {
            if let TcpEvent::Closed(token) = *event {
                self.cancel_tcp_timer(token, TimerEvent::Retransmission);
                self.cancel_tcp_timer(token, TimerEvent::DelayedAck);
                self.cancel_tcp_timer(token, TimerEvent::Persist);
                self.cancel_tcp_timer(token, TimerEvent::Keepalive);
                self.cancel_tcp_timer(token, TimerEvent::TimeWaitExpired);
                self.cancel_tcp_timer(token, TimerEvent::FinWait2Timeout);
            }
        }
        for request in timers {
            self.schedule_tcp_timer(*request, now_ms)?;
        }
        Ok(())
    }

    fn schedule_tcp_timer(
        &mut self,
        request: TcpTimerRequest,
        now_ms: u64,
    ) -> Result<(), RunnerError> {
        let deadline_ms = now_ms
            .checked_add(request.after_ms)
            .ok_or(TimerError::DeadlineOutOfRange)?;
        let key = (request.token, request.event);
        if let Some(armed) = self.tcp_timer_ids.get_mut(&key) {
            if armed.wheel_ms <= deadline_ms {
                armed.due_ms = Some(deadline_ms);
                return Ok(());
            }
            self.tcp_timers.cancel(armed.id);
        }
        let serial = self.next_timer_serial;
        self.next_timer_serial = self.next_timer_serial.wrapping_add(1);
        let id = self
            .tcp_timers
            .schedule(deadline_ms, ScheduledTcpTimer { request, serial })?;
        self.tcp_timer_ids.insert(
            key,
            ArmedTcpTimer {
                id,
                serial,
                wheel_ms: deadline_ms,
                due_ms: Some(deadline_ms),
            },
        );
        Ok(())
    }

    /// Disarms a timer the flow no longer wants; its wheel entry goes when
    /// it fires, unless the flow re-arms it first.
    fn disarm_tcp_timer(&mut self, token: TcpFlowToken, event: TimerEvent) {
        if let Some(armed) = self.tcp_timer_ids.get_mut(&(token, event)) {
            armed.due_ms = None;
        }
    }

    /// Removes a timer and its wheel entry, for a flow that is gone.
    fn cancel_tcp_timer(&mut self, token: TcpFlowToken, event: TimerEvent) {
        if let Some(armed) = self.tcp_timer_ids.remove(&(token, event)) {
            self.tcp_timers.cancel(armed.id);
        }
    }

    fn clear_tcp_timers(&mut self) {
        let now_ms = self.tcp_timers.now_ms();
        self.tcp_timers = TimerWheel::new(self.timer_tick_ms, now_ms);
        self.tcp_timer_ids.clear();
    }

    fn advance_tcp_timers(
        &mut self,
        now_ms: u64,
        outcome: &mut StepOutcome,
    ) -> Result<(), RunnerError> {
        let expired = self.tcp_timers.advance_to(now_ms)?;
        for scheduled in expired {
            let key = (scheduled.request.token, scheduled.request.event);
            let Some(armed) = self.tcp_timer_ids.get_mut(&key) else {
                continue;
            };
            if armed.serial != scheduled.serial {
                continue;
            }
            match armed.due_ms {
                None => {
                    self.tcp_timer_ids.remove(&key);
                    continue;
                }
                // Re-armed later since: on to then.
                Some(due_ms) if due_ms > now_ms => {
                    armed.id = self.tcp_timers.schedule(due_ms, scheduled)?;
                    armed.wheel_ms = due_ms;
                    continue;
                }
                Some(_) => {}
            }
            self.tcp_timer_ids.remove(&key);
            // A retransmitted segment fits the link, whatever the ceiling.
            let capacity = TCP_CONTROL_PACKET_BYTES
                .saturating_add(self.tcp.max_segment_payload_bytes())
                .min(self.mtu);
            let allocation = match self.reserve_tcp_control_packet(capacity) {
                Ok(allocation) => allocation,
                Err(RunnerError::TxQueueFull | RunnerError::Budget(_)) => {
                    let retry = TcpTimerRequest {
                        after_ms: self.timer_tick_ms,
                        ..scheduled.request
                    };
                    self.schedule_tcp_timer(retry, now_ms)?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let output =
                match self
                    .tcp
                    .on_timer_at(scheduled.request.token, scheduled.request.event, now_ms)
                {
                    Ok(output) => output,
                    Err(TcpTableError::StaleToken | TcpTableError::State(TcpError::Closed)) => {
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
            let mut output = self.finish_tcp_output(allocation, output)?;
            outcome.tcp_events.append(&mut output.events);
            outcome.tcp_timers.append(&mut output.timers);
            outcome
                .tcp_cancelled_timers
                .append(&mut output.cancelled_timers);
        }
        Ok(())
    }

    fn fill_tx_batch(&mut self) {
        while self.tx.len() < self.tx.limit() {
            let Some(packet) = self.tx_pending.pop_front() else {
                break;
            };
            if let Err(packet) = self.tx.push(packet) {
                self.tx_pending.push_front(packet);
                break;
            }
        }
    }
}

/// Polls `future` once: its output if it is ready at once, otherwise
/// nothing, dropping it as a cancelled step would be.
fn poll_once<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => Some(output),
        std::task::Poll::Pending => None,
    }
}

mod flow_samples;

#[cfg(test)]
mod quoted_transport_tests {
    use super::{quoted_transport_endpoints, QuotedTransport};
    use std::net::{Ipv6Addr, SocketAddr};

    #[test]
    fn ipv6_quote_extension_bound_and_fragment_offset_fail_closed() {
        let accepted = ipv6_udp_quote(7, None);
        assert_eq!(
            quoted_transport_endpoints(&accepted),
            Some(QuotedTransport::Udp(
                SocketAddr::from((Ipv6Addr::LOCALHOST, 1_000)),
                SocketAddr::from((Ipv6Addr::from(2_u128), 2_000)),
            ))
        );
        assert_eq!(quoted_transport_endpoints(&ipv6_udp_quote(8, None)), None);
        assert!(quoted_transport_endpoints(&ipv6_udp_quote(0, Some(0))).is_some());
        assert_eq!(
            quoted_transport_endpoints(&ipv6_udp_quote(0, Some(8))),
            None
        );
    }

    fn ipv6_udp_quote(extension_count: usize, fragment_bits: Option<u16>) -> Vec<u8> {
        let extension_bytes = extension_count * 8 + usize::from(fragment_bits.is_some()) * 8;
        let payload_len = extension_bytes + 4;
        let mut packet = vec![0_u8; 40 + payload_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&u16::try_from(payload_len).unwrap().to_be_bytes());
        packet[6] = if extension_count > 0 {
            0
        } else if fragment_bits.is_some() {
            44
        } else {
            17
        };
        packet[23] = 1;
        packet[39] = 2;
        for index in 0..extension_count {
            let offset = 40 + index * 8;
            packet[offset] = if index + 1 < extension_count {
                0
            } else if fragment_bits.is_some() {
                44
            } else {
                17
            };
        }
        let transport_offset = 40 + extension_count * 8;
        let transport_offset = if let Some(bits) = fragment_bits {
            packet[transport_offset] = 17;
            packet[transport_offset + 2..transport_offset + 4].copy_from_slice(&bits.to_be_bytes());
            transport_offset + 8
        } else {
            transport_offset
        };
        packet[transport_offset..transport_offset + 2].copy_from_slice(&1_000_u16.to_be_bytes());
        packet[transport_offset + 2..transport_offset + 4]
            .copy_from_slice(&2_000_u16.to_be_bytes());
        packet
    }
}
