use std::collections::{hash_map::RandomState, BTreeMap, VecDeque};
use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::metrics::increment_counter;
use crate::{
    emit_tcp_control, emit_tcp_segment, emit_tcp_segment_with_options, parse_ip_packet,
    parse_tcp_segment, BudgetError, BudgetLease, FlowId, NetworkGeneration, ResourceKind,
    ResourceLedger, SackBlock, SendControl, SeqNumber, ShardId, TcpAction, TcpError, TcpFlags,
    TcpFlowToken, TcpOptions, TcpState, TcpTcb, TimerEvent, WireError,
};

mod flow_samples;
pub use flow_samples::TcpFlowSample;

const TCP_FLOW_METADATA_CHARGE: usize = 512;
const TCP_CHUNK_METADATA_CHARGE: usize = 64;
const TIME_WAIT_METADATA_CHARGE: usize = 128;
const IPV4_BLACK_HOLE_FALLBACK_MTU: usize = 576;
const IPV6_BLACK_HOLE_FALLBACK_MTU: usize = 1_280;
const PAWS_IDLE_INVALIDATION_MS: u64 = 24 * 24 * 60 * 60 * 1_000;
/// How long a peer that shut its window with our data outstanding may stay
/// silent before the flow gives up: twice the largest RTO, as Linux's
/// `tcp_rtx_probe0_timed_out`. While it answers, the flow waits.
const SHUT_WINDOW_SILENCE_MS: u64 = 2 * super::rto::MAX_RTO_MS;
// Fixed header sizes (RFC 791, RFC 8200 3, RFC 9293 3.1).
const IPV4_HEADER_BYTES: usize = 20;
const IPV6_HEADER_BYTES: usize = 40;
const TCP_HEADER_BYTES: usize = 20;
// The TCP option space: a data offset of at most 15 words (RFC 9293 3.1).
const TCP_MAX_OPTION_BYTES: usize = 40;
// Timestamps, 10 bytes, with the two NOPs that align them (RFC 7323 3).
const TCP_TIMESTAMP_OPTION_BYTES: usize = 12;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AcceptOverflowPolicy {
    /// Ignore the completing ACK and leave the connection in SYN-RECEIVED so
    /// a later retransmission may complete after the queue drains.
    #[default]
    Drop,
    /// Release the embryonic connection and reject the completing ACK with a
    /// rate-limited reset.
    RejectWithReset,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpTableConfig {
    /// The receive window a flow starts with, reserved when it opens.
    pub receive_credit_bytes: usize,
    /// The most a flow's receive window grows to while the application
    /// reads as fast as it arrives, each step reserved when granted; with
    /// none, the window stays as it started.
    pub max_receive_credit_bytes: Option<usize>,
    /// The most a flow holds for its peer, sent and not yet acknowledged
    /// or waiting to be sent: a write beyond it waits for acknowledgments,
    /// as one to a socket waits on its send buffer. With none, only the
    /// peer's window and the budget bound it.
    pub max_send_buffer_bytes: Option<usize>,
    /// The most payload one segment carries, whatever the link allows.
    pub max_segment_payload_bytes: usize,
    /// The MTU of the link the table's packets cross, when known. Each flow
    /// then sizes its segments from it for its own address family and
    /// options (see [`link_mss`]), under `max_segment_payload_bytes`.
    pub link_mtu: Option<usize>,
    pub time_wait_ms: u64,
    /// How long a flow the application has let go of waits in FIN-WAIT-2
    /// for the peer's FIN, as Linux's `tcp_fin_timeout`. A flow the
    /// application still holds, half-closed, waits as long as it does.
    pub fin_wait2_timeout_ms: u64,
    pub delayed_ack_ms: u64,
    pub persist_initial_ms: u64,
    pub persist_max_ms: u64,
    pub keepalive_idle_ms: Option<u64>,
    pub keepalive_interval_ms: u64,
    pub syn_refill_ms: u64,
    pub syn_burst: u32,
    pub defensive_ack_refill_ms: u64,
    pub defensive_ack_burst: u32,
    pub challenge_ack_refill_ms: u64,
    pub challenge_ack_burst: u32,
    pub stateless_reset_refill_ms: u64,
    pub stateless_reset_burst: u32,
    pub hop_limit: u8,
    pub keepalive_max_probes: u8,
    pub nagle_enabled: bool,
    pub max_retransmission_timeouts: u8,
    pub black_hole_rto_threshold: Option<u8>,
    pub accept_overflow_policy: AcceptOverflowPolicy,
}

impl Default for TcpTableConfig {
    fn default() -> Self {
        Self {
            receive_credit_bytes: 16 * 1024,
            max_receive_credit_bytes: None,
            max_send_buffer_bytes: None,
            max_segment_payload_bytes: 1_200,
            link_mtu: None,
            hop_limit: 64,
            time_wait_ms: 60_000,
            fin_wait2_timeout_ms: 60_000,
            delayed_ack_ms: 40,
            persist_initial_ms: 1_000,
            persist_max_ms: 60_000,
            keepalive_idle_ms: None,
            keepalive_interval_ms: 75_000,
            keepalive_max_probes: 9,
            nagle_enabled: false,
            max_retransmission_timeouts: 12,
            black_hole_rto_threshold: Some(2),
            accept_overflow_policy: AcceptOverflowPolicy::Drop,
            syn_burst: 4_096,
            syn_refill_ms: 1,
            defensive_ack_burst: 4_096,
            defensive_ack_refill_ms: 1,
            challenge_ack_burst: 100,
            challenge_ack_refill_ms: 10,
            stateless_reset_burst: 100,
            stateless_reset_refill_ms: 10,
        }
    }
}

/// A flow's addresses and generation, with their hash: a segment looks its
/// flow up a dozen times, and hashing two socket addresses each time was
/// the most of each lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TcpFlowKey {
    source: SocketAddr,
    destination: SocketAddr,
    generation: NetworkGeneration,
    hash: u64,
}

impl TcpFlowKey {
    fn new(source: SocketAddr, destination: SocketAddr, generation: NetworkGeneration) -> Self {
        // Seeded once a process, as the maps' own hashers are.
        static SEED: std::sync::OnceLock<foldhash::fast::RandomState> = std::sync::OnceLock::new();
        let hash = SEED
            .get_or_init(Default::default)
            .hash_one((source, destination, generation));
        Self {
            source,
            destination,
            generation,
            hash,
        }
    }
}

impl Hash for TcpFlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

#[derive(Debug)]
struct ReceiveChunk {
    bytes: Box<[u8]>,
    offset: usize,
    _metadata_lease: BudgetLease,
}

#[derive(Debug)]
struct OutOfOrderChunk {
    sequence: SeqNumber,
    bytes: Box<[u8]>,
    metadata_lease: BudgetLease,
}

#[derive(Debug)]
struct ReceiveAdmission {
    buffering: bool,
    chunk: Option<ReceiveChunk>,
    out_of_order: Option<OutOfOrderChunk>,
    out_of_order_fin: Option<SeqNumber>,
}

impl ReceiveAdmission {
    const fn nothing() -> Self {
        Self {
            buffering: false,
            chunk: None,
            out_of_order: None,
            out_of_order_fin: None,
        }
    }
}

#[derive(Debug)]
struct TcpFlow {
    id: FlowId,
    tcb: TcpTcb,
    receive: VecDeque<ReceiveChunk>,
    pending_initial_receive: Option<ReceiveChunk>,
    out_of_order: Vec<OutOfOrderChunk>,
    out_of_order_fin: Option<SeqNumber>,
    recent_out_of_order: Option<SeqNumber>,
    send: VecDeque<SendChunk>,
    pending_send: Option<PendingSend>,
    persist_backoff_ms: u64,
    keepalive_probes_sent: u8,
    /// The application has let go of the flow: nothing reads or writes it.
    orphaned: bool,
    /// The FIN-WAIT-2 timer of an orphaned flow is set.
    fin_wait2_armed: bool,
    retransmission_timeouts: u8,
    /// When the peer was last heard from, in the table's clock.
    last_received_ms: u64,
    max_send_segment_bytes: usize,
    sack_permitted: bool,
    peer_window_scale: Option<u8>,
    local_window_scale: u8,
    /// Added to the millisecond clock for this flow's `TSval`, so that its
    /// timestamps reveal neither the stack's uptime nor another flow's
    /// clock (RFC 7323 7.1).
    timestamp_offset: u32,
    timestamp: Option<TimestampState>,
    rtt_probe: Option<RttProbe>,
    sack_recovery: Option<SackRecovery>,
    syn_lease: Option<BudgetLease>,
    accept_lease: Option<BudgetLease>,
    stats: FlowStatsContribution,
    _flow_lease: BudgetLease,
    _metadata_lease: BudgetLease,
    receive_credit_lease: BudgetLease,
    /// Receive capacity added since the flow opened, one lease a step.
    receive_growth: Vec<BudgetLease>,
    /// When the current measure of the application's reading began, and
    /// what it has read since.
    read_measure_start_ms: u64,
    read_measure_bytes: usize,
}

impl TcpFlow {
    /// Whether a retransmission timeout probes a window the peer shut: it
    /// keeps the flow while the peer answers (RFC 9293 3.8.6.2.1: a sender
    /// SHOULD NOT time out over data past the window's edge). A flow the
    /// application let go of counts its timeouts as any other.
    fn probes_shut_window(&self) -> bool {
        self.tcb.peer_window() == 0
            && !self.orphaned
            && !matches!(self.tcb.state(), TcpState::SynSent | TcpState::SynReceived)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FlowStatsContribution {
    syn_received: usize,
    accept_queue: usize,
    buffered_bytes: usize,
    send_buffered_bytes: usize,
}

#[derive(Clone, Copy, Debug)]
struct TimestampState {
    recent: u32,
    recent_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimestampDisposition {
    Accept,
    DropSilently,
    RejectWithAck,
}

#[derive(Clone, Copy, Debug)]
struct RttProbe {
    end_sequence: SeqNumber,
    sent_at_ms: u64,
    sent_timestamp: Option<u32>,
}

#[derive(Debug)]
struct SendChunk {
    sequence: SeqNumber,
    bytes: Box<[u8]>,
    payload_lease: BudgetLease,
    sacked: bool,
    retransmitted: bool,
    resegment: bool,
    _metadata_lease: BudgetLease,
}

#[derive(Clone, Copy, Debug)]
struct SackRecovery {
    recovery_point: SeqNumber,
    rescue_after: SeqNumber,
}

#[derive(Debug)]
struct SackSplitPlan {
    valid_blocks: Vec<SackBlock>,
    cuts_by_chunk: Vec<Vec<usize>>,
    metadata: Vec<BudgetLease>,
}

#[derive(Debug)]
struct PendingSend {
    bytes: Box<[u8]>,
    payload_lease: BudgetLease,
    reason: PendingSendReason,
    _metadata_lease: BudgetLease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingSendReason {
    Persist,
    Nagle,
}

#[derive(Debug)]
struct TimeWaitEntry {
    id: FlowId,
    acknowledgment: SendControl,
    /// The peer's last timestamp, when the connection used them: a SYN
    /// with a newer one may open the four-tuple again.
    peer_timestamp: Option<u32>,
    _slot_lease: BudgetLease,
    _metadata_lease: BudgetLease,
}

/// A connection whose handshake completed. `source` opened it and
/// `destination` was connected to: the peer and the intercepted address for
/// an accepted connection, the local and remote address for one we opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpConnection {
    pub token: TcpFlowToken,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub max_segment_payload_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpEvent {
    Accepted(TcpConnection),
    /// A connection opened by [`TcpTable::connect`] completed its handshake.
    Connected(TcpConnection),
    Readable {
        token: TcpFlowToken,
        bytes: usize,
    },
    Writable(TcpFlowToken),
    PeerHalfClosed(TcpFlowToken),
    Closed(TcpFlowToken),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpTimerRequest {
    pub token: TcpFlowToken,
    pub event: TimerEvent,
    pub after_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpTimerCancel {
    pub token: TcpFlowToken,
    pub event: TimerEvent,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct TcpIngress {
    pub outgoing: Vec<Vec<u8>>,
    pub events: Vec<TcpEvent>,
    pub timers: Vec<TcpTimerRequest>,
    pub cancelled_timers: Vec<TcpTimerCancel>,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct TcpRead {
    pub bytes: Vec<u8>,
    pub outgoing: Vec<Vec<u8>>,
    pub timers: Vec<TcpTimerRequest>,
    pub cancelled_timers: Vec<TcpTimerCancel>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpTableStats {
    /// Times a flow's receive window grew.
    pub receive_window_growths: u64,
    pub active_flows: usize,
    pub peak_active_flows: usize,
    pub time_wait: usize,
    pub peak_time_wait: usize,
    pub syn_received: usize,
    pub peak_syn_received: usize,
    pub accept_queue: usize,
    pub peak_accept_queue: usize,
    pub buffered_bytes: usize,
    pub send_buffered_bytes: usize,
    pub created_flows: u64,
    pub closed_flows: u64,
    pub time_wait_evictions: u64,
    /// TIME-WAIT entries a new connection's SYN ended (RFC 6191).
    pub time_wait_reuses: u64,
    pub malformed_packets: u64,
    pub invalid_address_drops: u64,
    pub timestamp_missing_drops: u64,
    pub paws_rejections: u64,
    pub window_scale_clamps: u64,
    pub stale_operations: u64,
    pub zero_window_writes: u64,
    pub persist_probes: u64,
    pub keepalive_probes: u64,
    pub keepalive_timeouts: u64,
    pub fin_wait2_timeouts: u64,
    pub nagle_buffered_writes: u64,
    pub sack_recovery_events: u64,
    pub sack_retransmitted_segments: u64,
    pub sack_rescue_segments: u64,
    pub retransmission_timeouts: u64,
    pub retransmission_failures: u64,
    pub black_hole_mtu_fallbacks: u64,
    pub syns_rate_limited: u64,
    pub defensive_acks_sent: u64,
    pub defensive_acks_rate_limited: u64,
    pub challenge_acks_sent: u64,
    pub challenge_acks_rate_limited: u64,
    pub stateless_resets_sent: u64,
    pub stateless_resets_rate_limited: u64,
    pub accept_overflow_drops: u64,
    pub accept_overflow_rejections: u64,
    pub pressure_reclaimed_syns: u64,
    /// Segments whose data the memory budget refused: their ACK was taken,
    /// their data left to come again.
    pub receive_pressure_drops: u64,
}

#[derive(Debug)]
pub enum TcpTableError {
    Wire(WireError),
    Budget(BudgetError),
    State(TcpError),
    UnknownFlow,
    StaleToken,
    NewFlowsDisabled,
    NotAccepted,
    PayloadTooLarge,
    Invariant(&'static str),
    ClockWentBackwards,
    /// `connect` was given endpoints that cannot carry a unicast flow.
    InvalidAddress,
    /// `connect` found its four-tuple taken, or no free ephemeral port.
    AddressInUse,
}

impl fmt::Display for TcpTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "TCP wire error: {error}"),
            Self::Budget(error) => write!(formatter, "TCP resource error: {error}"),
            Self::State(error) => write!(formatter, "TCP state error: {error}"),
            Self::UnknownFlow => formatter.write_str("unknown TCP flow"),
            Self::StaleToken => formatter.write_str("stale or unknown TCP flow token"),
            Self::NewFlowsDisabled => formatter.write_str("new TCP flows are disabled"),
            Self::NotAccepted => formatter.write_str("TCP flow has not left the accept queue"),
            Self::PayloadTooLarge => formatter.write_str("TCP write exceeds one segment"),
            Self::Invariant(message) => write!(formatter, "TCP table invariant failed: {message}"),
            Self::ClockWentBackwards => formatter.write_str("TCP clock moved backwards"),
            Self::InvalidAddress => formatter.write_str("TCP endpoints cannot carry a flow"),
            Self::AddressInUse => formatter.write_str("TCP four-tuple is in use"),
        }
    }
}

impl std::error::Error for TcpTableError {}

impl From<WireError> for TcpTableError {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

impl From<BudgetError> for TcpTableError {
    fn from(value: BudgetError) -> Self {
        Self::Budget(value)
    }
}

impl From<TcpError> for TcpTableError {
    fn from(value: TcpError) -> Self {
        Self::State(value)
    }
}

/// Shard-local passive TCP table. Receive memory is reserved before its window
/// is advertised, and every externally held capability is generation checked.
#[derive(Debug)]
pub struct TcpTable {
    ledger: Arc<ResourceLedger>,
    generation: NetworkGeneration,
    shard: ShardId,
    config: TcpTableConfig,
    hash_state: RandomState,
    next_flow_id: u64,
    next_ipv4_id: u16,
    now_ms: u64,
    by_key: crate::FlowMap<TcpFlowKey, TcpFlow>,
    time_wait: crate::FlowMap<TcpFlowKey, TimeWaitEntry>,
    time_wait_order: BTreeMap<u64, TcpFlowKey>,
    by_id: crate::FlowMap<FlowId, TcpFlowKey>,
    /// Flows in `SYN_RECEIVED` by id, which is their creation order, with
    /// when each was created.
    syn_received_order: BTreeMap<u64, (TcpFlowKey, u64)>,
    stats: TcpTableStats,
    syn_limiter: ControlRateLimiter,
    defensive_ack_limiter: ControlRateLimiter,
    challenge_ack_limiter: ControlRateLimiter,
    stateless_reset_limiter: ControlRateLimiter,
}

#[derive(Debug)]
struct ControlRateLimiter {
    burst: u32,
    tokens: u32,
    refill_ms: u64,
    last_refill_ms: Option<u64>,
}

impl ControlRateLimiter {
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
        let refills = now_ms.saturating_sub(last) / self.refill_ms;
        if refills > 0 {
            self.tokens = self
                .tokens
                .saturating_add(u32::try_from(refills).unwrap_or(u32::MAX))
                .min(self.burst);
            self.last_refill_ms = Some(last.saturating_add(refills.saturating_mul(self.refill_ms)));
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

impl TcpTable {
    /// # Panics
    ///
    /// Panics when receive credit, maximum segment payload, delayed ACK,
    /// persist bounds, or TIME-WAIT duration is invalid.
    #[must_use]
    pub fn new(
        ledger: Arc<ResourceLedger>,
        generation: NetworkGeneration,
        config: TcpTableConfig,
    ) -> Self {
        Self::new_on_shard(ledger, generation, ShardId::default(), config)
    }

    /// Constructs a table whose capabilities are owned by `shard`.
    ///
    /// # Panics
    ///
    /// Panics when receive credit, maximum segment payload, delayed ACK,
    /// persist bounds, or TIME-WAIT duration is invalid.
    #[must_use]
    pub fn new_on_shard(
        ledger: Arc<ResourceLedger>,
        generation: NetworkGeneration,
        shard: ShardId,
        config: TcpTableConfig,
    ) -> Self {
        assert!(
            config.receive_credit_bytes > 0,
            "TCP receive credit must be non-zero"
        );
        assert!(
            config
                .max_receive_credit_bytes
                .is_none_or(|max| max >= config.receive_credit_bytes),
            "TCP receive window ceiling must not be below its start"
        );
        assert!(
            config.max_send_buffer_bytes != Some(0),
            "TCP send buffer must be non-zero"
        );
        assert!(
            config.max_segment_payload_bytes > 0,
            "TCP maximum segment payload must be non-zero"
        );
        assert!(config.time_wait_ms > 0, "TCP TIME-WAIT must be non-zero");
        assert!(
            config.fin_wait2_timeout_ms > 0,
            "TCP FIN-WAIT-2 timeout must be non-zero"
        );
        assert!(
            config.delayed_ack_ms > 0,
            "TCP delayed ACK must be non-zero"
        );
        assert!(
            config.persist_initial_ms > 0,
            "TCP persist interval must be non-zero"
        );
        assert!(
            config.persist_max_ms >= config.persist_initial_ms,
            "TCP maximum persist interval must not be below its initial interval"
        );
        assert!(
            config.keepalive_idle_ms != Some(0),
            "TCP keepalive idle interval must be non-zero when enabled"
        );
        assert!(
            config.keepalive_interval_ms > 0,
            "TCP keepalive probe interval must be non-zero"
        );
        assert!(
            config.keepalive_max_probes > 0,
            "TCP keepalive probe count must be non-zero"
        );
        assert!(
            config.max_retransmission_timeouts > 0,
            "TCP retransmission timeout count must be non-zero"
        );
        assert!(
            config.black_hole_rto_threshold != Some(0),
            "TCP black-hole RTO threshold must be non-zero when enabled"
        );
        assert!(
            config.syn_burst > 0 && config.syn_refill_ms > 0,
            "TCP SYN rate must be non-zero"
        );
        assert!(
            config.defensive_ack_burst > 0 && config.defensive_ack_refill_ms > 0,
            "TCP defensive ACK rate must be non-zero"
        );
        assert!(
            config.challenge_ack_burst > 0 && config.challenge_ack_refill_ms > 0,
            "TCP challenge ACK rate must be non-zero"
        );
        assert!(
            config.stateless_reset_burst > 0 && config.stateless_reset_refill_ms > 0,
            "TCP stateless reset rate must be non-zero"
        );
        Self {
            ledger,
            generation,
            shard,
            config,
            hash_state: RandomState::new(),
            next_flow_id: 0,
            next_ipv4_id: 0,
            now_ms: 0,
            by_key: crate::FlowMap::default(),
            time_wait: crate::FlowMap::default(),
            time_wait_order: BTreeMap::new(),
            by_id: crate::FlowMap::default(),
            syn_received_order: BTreeMap::new(),
            stats: TcpTableStats::default(),
            syn_limiter: ControlRateLimiter::new(config.syn_burst, config.syn_refill_ms),
            defensive_ack_limiter: ControlRateLimiter::new(
                config.defensive_ack_burst,
                config.defensive_ack_refill_ms,
            ),
            challenge_ack_limiter: ControlRateLimiter::new(
                config.challenge_ack_burst,
                config.challenge_ack_refill_ms,
            ),
            stateless_reset_limiter: ControlRateLimiter::new(
                config.stateless_reset_burst,
                config.stateless_reset_refill_ms,
            ),
        }
    }

    /// Parses and processes one TCP packet atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, unknown non-SYN traffic, protocol
    /// state violations, or admission failure. Failed admission does not mutate
    /// protocol state or advertise unreserved receive memory.
    pub fn ingest(&mut self, packet: &[u8]) -> Result<TcpIngress, TcpTableError> {
        self.ingest_with_policy_at(packet, true, self.now_ms)
    }

    /// Equivalent to [`TcpTable::ingest`] with explicit new-flow admission.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::NewFlowsDisabled`] for a new SYN while draining.
    pub fn ingest_with_policy(
        &mut self,
        packet: &[u8],
        allow_new: bool,
    ) -> Result<TcpIngress, TcpTableError> {
        self.ingest_with_policy_at(packet, allow_new, self.now_ms)
    }

    /// Processes a packet at an explicit monotonic time for timestamp/PAWS.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::ClockWentBackwards`] if `now_ms` regresses.
    pub fn ingest_with_policy_at(
        &mut self,
        packet: &[u8],
        allow_new: bool,
        now_ms: u64,
    ) -> Result<TcpIngress, TcpTableError> {
        self.ingest_with_policy_at_limit(packet, allow_new, now_ms, usize::MAX)
    }

    pub(crate) fn ingest_with_policy_at_limit(
        &mut self,
        packet: &[u8],
        allow_new: bool,
        now_ms: u64,
        outgoing_limit: usize,
    ) -> Result<TcpIngress, TcpTableError> {
        self.update_clock(now_ms)?;
        let ip = match parse_ip_packet(packet, true) {
            Ok(ip) => ip,
            Err(error) => {
                increment_counter(&mut self.stats.malformed_packets);
                return Err(error.into());
            }
        };
        let segment = match parse_tcp_segment(ip, true) {
            Ok(segment) => segment,
            Err(error) => {
                increment_counter(&mut self.stats.malformed_packets);
                return Err(error.into());
            }
        };
        if !crate::wire::valid_flow_source(segment.source.ip())
            || !crate::wire::valid_flow_destination(segment.destination.ip())
        {
            increment_counter(&mut self.stats.invalid_address_drops);
            return Ok(TcpIngress::default());
        }
        let key = TcpFlowKey::new(segment.source, segment.destination, self.generation);
        if self
            .by_key
            .get(&key)
            .is_some_and(|flow| flow.tcb.state() == TcpState::SynSent)
        {
            self.ingest_syn_sent(key, segment.meta, &segment.options)
        } else if self.by_key.contains_key(&key) {
            self.ingest_existing(
                key,
                segment.meta,
                segment.options,
                segment.payload,
                outgoing_limit,
            )
        } else if self.time_wait.contains_key(&key)
            && !self.time_wait_yields_to(key, segment.meta, &segment.options)
        {
            self.ingest_time_wait(key, segment.meta)
        } else if is_initial_syn(segment.meta) {
            if !allow_new {
                return Err(TcpTableError::NewFlowsDisabled);
            }
            if !self.syn_limiter.allow(self.now_ms) {
                self.stats.syns_rate_limited = self.stats.syns_rate_limited.saturating_add(1);
                return Ok(TcpIngress::default());
            }
            // A SYN a TIME-WAIT yields to: the old connection ends once the
            // new one is taken (a SYN refused leaves it waiting), and its
            // owner is told, as one evicted is.
            let mut output =
                self.ingest_new(key, segment.meta, segment.options, segment.payload)?;
            let ended = self.end_time_wait(key);
            if let Some(ended) = ended {
                output.events.push(TcpEvent::Closed(ended.token));
                output.cancelled_timers.push(ended);
            }
            Ok(output)
        } else {
            self.reject_unknown(key, segment.meta, segment.options)
        }
    }

    fn reject_unknown(
        &mut self,
        key: TcpFlowKey,
        segment: crate::TcpSegmentMeta,
        options: TcpOptions,
    ) -> Result<TcpIngress, TcpTableError> {
        if segment.flags.contains(TcpFlags::RST) {
            return Ok(TcpIngress::default());
        }
        if !self.stateless_reset_limiter.allow(self.now_ms) {
            self.stats.stateless_resets_rate_limited =
                self.stats.stateless_resets_rate_limited.saturating_add(1);
            return Ok(TcpIngress::default());
        }
        let control = if let Some(acknowledgment) = segment.acknowledgment {
            SendControl {
                sequence: acknowledgment,
                acknowledgment: SeqNumber::new(0),
                flags: TcpFlags::RST,
                window: 0,
            }
        } else {
            let length = segment.payload_len
                + usize::from(segment.flags.contains(TcpFlags::SYN))
                + usize::from(segment.flags.contains(TcpFlags::FIN));
            SendControl {
                sequence: SeqNumber::new(0),
                acknowledgment: segment.sequence.wrapping_add(length),
                flags: TcpFlags::RST.union(TcpFlags::ACK),
                window: 0,
            }
        };
        let wire = if let Some((value, _)) = options.timestamps {
            let mut reset_options = [0_u8; 12];
            reset_options[0..2].copy_from_slice(&[8, 10]);
            reset_options[6..10].copy_from_slice(&value.to_be_bytes());
            reset_options[10..12].copy_from_slice(&[1, 1]);
            self.emit_with_options(key, control, &reset_options)?
        } else {
            self.emit(key, control)?
        };
        self.stats.stateless_resets_sent = self.stats.stateless_resets_sent.saturating_add(1);
        Ok(TcpIngress {
            outgoing: vec![wire],
            ..TcpIngress::default()
        })
    }

    /// Opens a connection from `local` to `remote` (RFC 9293 3.10.1) and
    /// returns its token with the SYN to send. Port 0 in `local` picks a free
    /// ephemeral port. The connection reports [`TcpEvent::Connected`] once
    /// the handshake completes, or [`TcpEvent::Closed`] when it is refused or
    /// its SYN is never answered.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::InvalidAddress`] for endpoints that cannot
    /// carry a unicast flow, [`TcpTableError::AddressInUse`] when the
    /// four-tuple is live or in TIME-WAIT, or a budget error when the flow
    /// cannot be charged.
    pub fn connect(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Result<(TcpFlowToken, TcpIngress), TcpTableError> {
        self.connect_using(local, remote, |_| true)
    }

    /// [`TcpTable::connect`], choosing an ephemeral port only among the
    /// local addresses `usable` accepts: those whose replies reach this
    /// table when several share the traffic.
    ///
    /// # Errors
    ///
    /// As [`TcpTable::connect`].
    pub fn connect_using(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        usable: impl Fn(SocketAddr) -> bool,
    ) -> Result<(TcpFlowToken, TcpIngress), TcpTableError> {
        // Replies arrive from `remote` to `local`, and must pass the same
        // endpoint checks as any inbound segment.
        if local.is_ipv4() != remote.is_ipv4()
            || remote.port() == 0
            || !crate::wire::valid_flow_source(remote.ip())
            || !crate::wire::valid_flow_destination(local.ip())
        {
            return Err(TcpTableError::InvalidAddress);
        }
        let local = if local.port() == 0 {
            self.ephemeral_local(local, remote, usable)?
        } else {
            local
        };
        let key = TcpFlowKey::new(remote, local, self.generation);
        if self.by_key.contains_key(&key) || self.time_wait.contains_key(&key) {
            return Err(TcpTableError::AddressInUse);
        }
        let flow_lease = self.ledger.try_acquire(ResourceKind::TcpFlows, 1)?;
        let metadata_lease = self
            .ledger
            .try_acquire(ResourceKind::MetadataBytes, TCP_FLOW_METADATA_CHARGE)?;
        let receive_credit = self.ledger.try_acquire_within(
            ResourceKind::TcpPayloadBytes,
            self.config.receive_credit_bytes,
            self.ledger.budget().tcp_receive_ceiling(),
        )?;
        let id = FlowId::new(self.next_flow_id);
        let isn = self.initial_sequence(key, id);
        let timestamp_offset = self.timestamp_offset(key);
        let local_window_scale = window_scale_for(self.receive_window_ceiling());
        let local_mss = self.local_mss(remote);
        let (tcb, actions) = TcpTcb::connect(
            isn,
            self.config.receive_credit_bytes,
            local_mss,
            local_window_scale,
        );
        let default_peer_mss = if remote.is_ipv4() { 536 } else { 1_220 };
        let rtt_probe = Some(RttProbe {
            end_sequence: tcb.send_next(),
            sent_at_ms: self.now_ms,
            sent_timestamp: None,
        });
        self.next_flow_id = self.next_flow_id.wrapping_add(1);
        self.by_key.insert(
            key,
            TcpFlow {
                id,
                tcb,
                receive: VecDeque::new(),
                pending_initial_receive: None,
                out_of_order: Vec::new(),
                out_of_order_fin: None,
                recent_out_of_order: None,
                send: VecDeque::new(),
                pending_send: None,
                persist_backoff_ms: 0,
                keepalive_probes_sent: 0,
                orphaned: false,
                fin_wait2_armed: false,
                retransmission_timeouts: 0,
                last_received_ms: self.now_ms,
                max_send_segment_bytes: local_mss.min(default_peer_mss),
                sack_permitted: false,
                peer_window_scale: None,
                local_window_scale,
                timestamp_offset,
                timestamp: None,
                rtt_probe,
                sack_recovery: None,
                syn_lease: None,
                accept_lease: None,
                stats: FlowStatsContribution::default(),
                _flow_lease: flow_lease,
                _metadata_lease: metadata_lease,
                receive_credit_lease: receive_credit,
                receive_growth: Vec::new(),
                read_measure_start_ms: self.now_ms,
                read_measure_bytes: 0,
            },
        );
        self.by_id.insert(id, key);
        increment_counter(&mut self.stats.created_flows);
        self.sync_flow_stats(key);
        self.refresh_structural_stats();
        let output = self.render_actions(key, id, &actions)?;
        Ok((
            TcpFlowToken::new_on_shard(id, self.generation, self.shard),
            output,
        ))
    }

    /// A local address on `local`'s IP with a free port in the IANA dynamic
    /// range (RFC 6335), starting at a keyed offset so that ports are hard
    /// to predict and successive connections spread out.
    fn ephemeral_local(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        usable: impl Fn(SocketAddr) -> bool,
    ) -> Result<SocketAddr, TcpTableError> {
        const FIRST: u16 = 49_152;
        const SPAN: u64 = 65_536 - FIRST as u64;
        let start = self
            .hash_state
            .hash_one((remote, local.ip(), self.next_flow_id));
        (0..SPAN)
            .map(|offset| {
                let port = FIRST
                    + u16::try_from((start.wrapping_add(offset)) % SPAN)
                        .expect("an offset below SPAN fits a port");
                SocketAddr::new(local.ip(), port)
            })
            .find(|candidate| {
                let key = TcpFlowKey::new(remote, *candidate, self.generation);
                !self.by_key.contains_key(&key)
                    && !self.time_wait.contains_key(&key)
                    && usable(*candidate)
            })
            .ok_or(TcpTableError::AddressInUse)
    }

    /// A segment for a connection in SYN-SENT. A SYN from the peer settles
    /// the options before the control block takes it: SACK, window scaling
    /// and timestamps apply only when both SYNs carry them (RFC 2018,
    /// RFC 7323 1.3).
    fn ingest_syn_sent(
        &mut self,
        key: TcpFlowKey,
        segment: crate::TcpSegmentMeta,
        options: &TcpOptions,
    ) -> Result<TcpIngress, TcpTableError> {
        let now_ms = self.now_ms;
        let max_segment_payload_bytes = self.local_mss(key.source);
        let link_mtu = self.config.link_mtu;
        let flow = self
            .by_key
            .get_mut(&key)
            .ok_or(TcpTableError::UnknownFlow)?;
        let answers_our_syn = segment
            .acknowledgment
            .is_none_or(|acknowledgment| acknowledgment == flow.tcb.send_next());
        if segment.flags.contains(TcpFlags::SYN)
            && !segment.flags.contains(TcpFlags::RST)
            && answers_our_syn
        {
            flow.sack_permitted = options.sack_permitted;
            flow.peer_window_scale = options.window_scale;
            if options.window_scale.is_none() {
                flow.local_window_scale = 0;
                flow.tcb.withdraw_receive_window_scale();
            }
            flow.timestamp = options.timestamps.map(|(recent, _)| TimestampState {
                recent,
                recent_at_ms: now_ms,
            });
            let default_peer_mss = if key.source.is_ipv4() { 536 } else { 1_220 };
            flow.max_send_segment_bytes = max_segment_payload_bytes.min(peer_segment_bytes(
                usize::from(options.maximum_segment_size.unwrap_or(default_peer_mss)),
                flow.sack_permitted,
                flow.timestamp.is_some(),
            ));
            if let Some(mtu) = link_mtu {
                lower_flow_mtu(key, flow, mtu);
            }
            if options.window_scale_clamped {
                increment_counter(&mut self.stats.window_scale_clamps);
            }
        }
        let flow = self
            .by_key
            .get_mut(&key)
            .ok_or(TcpTableError::UnknownFlow)?;
        let old_send_unacked = flow.tcb.send_unacked();
        let actions = flow.tcb.on_segment(segment)?;
        record_ack_progress(flow, old_send_unacked, *options, now_ms);
        let id = flow.id;
        self.finish_existing_ingress(key, id, &actions, (None, false, usize::MAX))
    }

    fn ingest_new(
        &mut self,
        key: TcpFlowKey,
        segment: crate::TcpSegmentMeta,
        options: TcpOptions,
        payload: &[u8],
    ) -> Result<TcpIngress, TcpTableError> {
        if !segment.flags.contains(TcpFlags::SYN)
            || segment.flags.contains(TcpFlags::ACK)
            || segment.flags.contains(TcpFlags::RST)
        {
            return Err(TcpError::InvalidSyn.into());
        }
        if payload.len() > self.config.receive_credit_bytes {
            return Err(TcpError::ReceiveCreditExceeded.into());
        }
        let flow_lease = self.ledger.try_acquire(ResourceKind::TcpFlows, 1)?;
        let syn_lease = self.ledger.try_acquire(ResourceKind::SynReceived, 1)?;
        let metadata_lease = self
            .ledger
            .try_acquire(ResourceKind::MetadataBytes, TCP_FLOW_METADATA_CHARGE)?;
        let receive_credit = self.ledger.try_acquire_within(
            ResourceKind::TcpPayloadBytes,
            self.config.receive_credit_bytes,
            self.ledger.budget().tcp_receive_ceiling(),
        )?;
        let pending_initial_receive = (!payload.is_empty())
            .then(|| receive_chunk(&self.ledger, payload))
            .transpose()?;
        let id = FlowId::new(self.next_flow_id);
        let isn = self.initial_sequence(key, id);
        let timestamp_offset = self.timestamp_offset(key);
        let local_mss = self.local_mss(key.source);
        let max_send_segment_bytes = self.passive_segment_bytes(key, &options);
        let local_window_scale = options
            .window_scale
            .map_or(0, |_| window_scale_for(self.receive_window_ceiling()));
        let (tcb, actions) = TcpTcb::from_syn_with_options(
            segment,
            isn,
            self.config.receive_credit_bytes,
            local_mss,
            local_window_scale,
        )?;
        let rtt_probe = Some(RttProbe {
            end_sequence: tcb.send_next(),
            sent_at_ms: self.now_ms,
            sent_timestamp: options
                .timestamps
                .map(|_| timestamp_value(self.now_ms, timestamp_offset)),
        });
        self.next_flow_id = self.next_flow_id.wrapping_add(1);
        self.by_key.insert(
            key,
            TcpFlow {
                id,
                tcb,
                receive: VecDeque::new(),
                pending_initial_receive,
                out_of_order: Vec::new(),
                out_of_order_fin: None,
                recent_out_of_order: None,
                send: VecDeque::new(),
                pending_send: None,
                persist_backoff_ms: 0,
                keepalive_probes_sent: 0,
                orphaned: false,
                fin_wait2_armed: false,
                retransmission_timeouts: 0,
                last_received_ms: self.now_ms,
                max_send_segment_bytes,
                sack_permitted: options.sack_permitted,
                peer_window_scale: options.window_scale,
                local_window_scale,
                timestamp_offset,
                timestamp: options.timestamps.map(|(recent, _)| TimestampState {
                    recent,
                    recent_at_ms: self.now_ms,
                }),
                rtt_probe,
                sack_recovery: None,
                syn_lease: Some(syn_lease),
                accept_lease: None,
                stats: FlowStatsContribution::default(),
                _flow_lease: flow_lease,
                _metadata_lease: metadata_lease,
                receive_credit_lease: receive_credit,
                receive_growth: Vec::new(),
                read_measure_start_ms: self.now_ms,
                read_measure_bytes: 0,
            },
        );
        self.by_id.insert(id, key);
        self.syn_received_order.insert(id.get(), (key, self.now_ms));
        if options.window_scale_clamped {
            increment_counter(&mut self.stats.window_scale_clamps);
        }
        increment_counter(&mut self.stats.created_flows);
        self.sync_flow_stats(key);
        self.refresh_structural_stats();
        self.render_actions(key, id, &actions)
    }

    fn ingest_existing(
        &mut self,
        key: TcpFlowKey,
        mut segment: crate::TcpSegmentMeta,
        options: TcpOptions,
        payload: &[u8],
        outgoing_limit: usize,
    ) -> Result<TcpIngress, TcpTableError> {
        if let Some(output) = self.handle_existing_timestamp(key, segment, &options)? {
            return Ok(output);
        }
        let flow = self.by_key.get(&key).ok_or(TcpTableError::UnknownFlow)?;
        apply_peer_window_scale(flow, &mut segment);
        let original_segment = segment;
        let accepting = flow.tcb.accepts_final_ack(segment);
        let (payload, payload_admissible) =
            normalize_receive_segment(flow, &mut segment, payload, accepting);
        let mut state_segment = state_segment(flow, original_segment, segment, accepting);
        let old_recv_next = flow.tcb.recv_next();
        let had_send = !flow.send.is_empty();
        let old_send_unacked = flow.tcb.send_unacked();
        let old_send_available = flow.tcb.send_available();
        let (sender_feedback_admissible, sack_split_plan) =
            prepare_sender_feedback(&self.ledger, flow, segment, &options.sack_blocks)?;
        let delivers_initial = accepting && flow.pending_initial_receive.is_some();
        let accept_lease = if accepting {
            match self.ledger.try_acquire(ResourceKind::AcceptQueue, 1) {
                Ok(lease) => Some(lease),
                Err(_) => return self.handle_accept_overflow(key, segment, options),
            }
        } else {
            None
        };
        let (admission, pressure_dropped) = admit_or_strip(
            &self.ledger,
            flow,
            (&mut segment, &mut state_segment),
            payload,
            payload_admissible,
            accepting,
        )?;
        let sack_anchor =
            (payload_admissible && !pressure_dropped && original_segment.payload_len > 0)
                .then_some(original_segment.sequence);
        let flow = self
            .by_key
            .get_mut(&key)
            .ok_or(TcpTableError::UnknownFlow)?;
        let mut actions = flow.tcb.on_segment(state_segment)?;
        if pressure_dropped {
            answer_pressure_drop(flow, &mut self.stats, &mut actions);
        }
        apply_challenge_ack_limit(
            &mut self.challenge_ack_limiter,
            &mut self.stats,
            self.now_ms,
            &mut actions,
        );
        flow.keepalive_probes_sent = 0;
        flow.last_received_ms = self.now_ms;
        record_ack_progress(flow, old_send_unacked, options, self.now_ms);
        update_recent_timestamp(flow, segment, options, old_recv_next, self.now_ms);
        update_sender_sack(
            flow,
            sender_feedback_admissible,
            sack_split_plan,
            &mut self.stats,
            &mut actions,
        );
        apply_accept_lease(flow, accept_lease, &actions);
        promote_initial_receive(flow, delivers_initial)?;
        let delivered_current = admission.buffering
            && actions
                .iter()
                .any(|action| matches!(action, TcpAction::DeliverPayload { .. }));
        if delivered_current {
            let chunk = admission.chunk.ok_or(TcpTableError::Invariant(
                "payload delivery lacked an admitted receive chunk",
            ))?;
            flow.receive.push_back(chunk);
        }
        queue_out_of_order_and_promote(
            flow,
            admission.out_of_order,
            admission.out_of_order_fin,
            sack_anchor,
            delivered_current || delivers_initial,
            &mut actions,
        )?;
        release_acknowledged_send(flow)?;
        let resegment_control = pending_resegment_control(flow, old_send_unacked);
        let id = flow.id;
        let became_writable =
            flow_became_writable(flow, had_send, old_send_unacked, old_send_available);
        self.finish_existing_ingress(
            key,
            id,
            &actions,
            (resegment_control, became_writable, outgoing_limit),
        )
    }

    fn handle_existing_timestamp(
        &mut self,
        key: TcpFlowKey,
        segment: crate::TcpSegmentMeta,
        options: &TcpOptions,
    ) -> Result<Option<TcpIngress>, TcpTableError> {
        let flow = self.by_key.get(&key).ok_or(TcpTableError::UnknownFlow)?;
        match validate_segment_timestamp(flow, segment, options, self.now_ms) {
            TimestampDisposition::Accept => Ok(None),
            TimestampDisposition::DropSilently => {
                increment_counter(&mut self.stats.timestamp_missing_drops);
                Ok(Some(TcpIngress::default()))
            }
            TimestampDisposition::RejectWithAck => {
                increment_counter(&mut self.stats.paws_rejections);
                let flow = self
                    .by_key
                    .get_mut(&key)
                    .ok_or(TcpTableError::UnknownFlow)?;
                let id = flow.id;
                let actions = flow.tcb.reject_unacceptable_segment();
                self.render_actions(key, id, &actions).map(Some)
            }
        }
    }

    fn finish_existing_ingress(
        &mut self,
        key: TcpFlowKey,
        id: FlowId,
        actions: &[TcpAction],
        completion: (Option<SendControl>, bool, usize),
    ) -> Result<TcpIngress, TcpTableError> {
        let (resegment_control, became_writable, outgoing_limit) = completion;
        if actions.contains(&TcpAction::Accepted) {
            self.syn_received_order.remove(&id.get());
        }
        let closed = actions.contains(&TcpAction::Closed);
        let enters_time_wait = actions.contains(&TcpAction::ArmTimeWait);
        let mut output = self.render_actions(key, id, actions)?;
        self.append_resegmented(key, resegment_control, actions, &mut output)?;
        output.outgoing.truncate(outgoing_limit);
        let remaining = outgoing_limit.saturating_sub(output.outgoing.len());
        output
            .outgoing
            .append(&mut self.render_sack_recovery(key, remaining)?);
        let promote_to_persist = self.by_key.get(&key).is_some_and(|flow| {
            flow.tcb.peer_window() == 0
                && flow
                    .pending_send
                    .as_ref()
                    .is_some_and(|pending| pending.reason == PendingSendReason::Nagle)
        });
        if promote_to_persist {
            let flow = self
                .by_key
                .get_mut(&key)
                .ok_or(TcpTableError::UnknownFlow)?;
            flow.pending_send
                .as_mut()
                .expect("pending send checked above")
                .reason = PendingSendReason::Persist;
            flow.persist_backoff_ms = self.config.persist_initial_ms;
            output.timers.push(TcpTimerRequest {
                token: TcpFlowToken::new_on_shard(id, self.generation, self.shard),
                event: TimerEvent::Persist,
                after_ms: self.config.persist_initial_ms,
            });
        }
        // A write Nagle or a closed window held goes out with whatever else
        // this segment draws: waiting for a quiet ACK could wait forever,
        // since once the flight is empty neither end has a reason to send.
        if !closed && output.outgoing.len() < outgoing_limit {
            let pending = self.flush_pending_send(key)?;
            merge_ingress(&mut output, pending);
        }
        // With no room left to send it now and nothing in flight, the persist
        // timer releases it.
        let stranded = self.by_key.get(&key).is_some_and(|flow| {
            flow.send.is_empty()
                && flow
                    .pending_send
                    .as_ref()
                    .is_some_and(|pending| pending.reason == PendingSendReason::Nagle)
        });
        if !closed && stranded {
            let flow = self
                .by_key
                .get_mut(&key)
                .ok_or(TcpTableError::UnknownFlow)?;
            flow.persist_backoff_ms = self.config.persist_initial_ms;
            output.timers.push(TcpTimerRequest {
                token: TcpFlowToken::new_on_shard(id, self.generation, self.shard),
                event: TimerEvent::Persist,
                after_ms: self.config.persist_initial_ms,
            });
        }
        if !closed && !enters_time_wait {
            self.arm_keepalive_if_active(key, &mut output)?;
            self.arm_fin_wait2_if_orphaned(key, &mut output)?;
        }
        if became_writable && !closed {
            output
                .events
                .push(TcpEvent::Writable(TcpFlowToken::new_on_shard(
                    id,
                    self.generation,
                    self.shard,
                )));
        }
        if closed {
            self.remove(key);
        } else if enters_time_wait
            && self
                .by_key
                .get(&key)
                .is_some_and(|flow| flow.receive.is_empty() || flow.orphaned)
        {
            // A flow with bytes its application has yet to read stays whole
            // until they are read and it lets go, as Linux keeps them on the
            // socket: the compact entry keeps no data.
            self.move_to_time_wait(key, id, &mut output)?;
        }
        self.sync_flow_stats(key);
        self.refresh_structural_stats();
        Ok(output)
    }

    fn handle_accept_overflow(
        &mut self,
        key: TcpFlowKey,
        segment: crate::TcpSegmentMeta,
        options: TcpOptions,
    ) -> Result<TcpIngress, TcpTableError> {
        match self.config.accept_overflow_policy {
            AcceptOverflowPolicy::Drop => {
                self.stats.accept_overflow_drops =
                    self.stats.accept_overflow_drops.saturating_add(1);
                Ok(TcpIngress::default())
            }
            AcceptOverflowPolicy::RejectWithReset => {
                let id = self.by_key.get(&key).ok_or(TcpTableError::UnknownFlow)?.id;
                let token = TcpFlowToken::new_on_shard(id, self.generation, self.shard);
                let mut output = self.reject_unknown(key, segment, options)?;
                output.cancelled_timers.push(TcpTimerCancel {
                    token,
                    event: TimerEvent::Retransmission,
                });
                self.remove(key);
                self.refresh_structural_stats();
                self.stats.accept_overflow_rejections =
                    self.stats.accept_overflow_rejections.saturating_add(1);
                Ok(output)
            }
        }
    }

    /// Removes one accepted connection from the bounded accept queue.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::StaleToken`] for a stale, unknown, or not-yet-
    /// accepted token.
    pub fn accept(&mut self, token: TcpFlowToken) -> Result<TcpConnection, TcpTableError> {
        let key = self.key_for(token)?;
        let flow = self.by_key.get_mut(&key).ok_or(TcpTableError::StaleToken)?;
        if flow.accept_lease.take().is_none() {
            increment_counter(&mut self.stats.stale_operations);
            return Err(TcpTableError::StaleToken);
        }
        let max_segment_payload_bytes = flow.max_send_segment_bytes;
        self.sync_flow_stats(key);
        Ok(TcpConnection {
            token,
            source: key.source,
            destination: key.destination,
            max_segment_payload_bytes,
        })
    }

    /// Reclaims the oldest incomplete passive handshake, if at `now_ms` it
    /// began at least `older_than_ms` ago, without allocating a temporary
    /// candidate list. The peer may retry with a fresh SYN.
    #[must_use]
    pub fn reclaim_stale_syn_received(
        &mut self,
        now_ms: u64,
        older_than_ms: u64,
    ) -> Option<TcpFlowToken> {
        let (_, (_, created_ms)) = self.syn_received_order.first_key_value()?;
        if now_ms.saturating_sub(*created_ms) < older_than_ms {
            return None;
        }
        let (id, (key, _)) = self.syn_received_order.pop_first()?;
        let token = TcpFlowToken::new_on_shard(FlowId::new(id), self.generation, self.shard);
        self.remove(key);
        self.stats.pressure_reclaimed_syns = self.stats.pressure_reclaimed_syns.saturating_add(1);
        self.refresh_structural_stats();
        Some(token)
    }

    /// Copies up to `max_bytes` from the reserved receive queue and advances
    /// the advertised right edge only after the bytes leave stack ownership.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::StaleToken`] for a stale or unknown token.
    pub fn read(
        &mut self,
        token: TcpFlowToken,
        max_bytes: usize,
    ) -> Result<TcpRead, TcpTableError> {
        let key = self.key_for(token)?;
        if max_bytes == 0 {
            return Ok(TcpRead::default());
        }
        let Some(flow) = self.by_key.get_mut(&key) else {
            // TIME-WAIT's compact entry: everything was read, and the
            // peer's FIN is the end of the stream.
            return if self.time_wait.contains_key(&key) {
                Ok(TcpRead::default())
            } else {
                Err(TcpTableError::StaleToken)
            };
        };
        let amount = max_bytes.min(flow.tcb.recv_buffered());
        let mut bytes = Vec::with_capacity(amount);
        while bytes.len() < amount {
            let chunk = flow.receive.front_mut().ok_or(TcpTableError::Invariant(
                "receive queue shorter than TCB buffered byte count",
            ))?;
            let take = (amount - bytes.len()).min(chunk.bytes.len() - chunk.offset);
            bytes.extend_from_slice(&chunk.bytes[chunk.offset..chunk.offset + take]);
            chunk.offset += take;
            if chunk.offset == chunk.bytes.len() {
                flow.receive.pop_front();
            }
        }
        grow_receive_window(
            &self.ledger,
            flow,
            amount,
            self.now_ms,
            self.config.max_receive_credit_bytes,
            &mut self.stats.receive_window_growths,
        );
        let actions = flow.tcb.on_app_event(crate::AppEvent::Consumed(amount))?;
        let id = flow.id;
        let rendered = self.render_actions(key, id, &actions)?;
        self.sync_flow_stats(key);
        Ok(TcpRead {
            bytes,
            outgoing: rendered.outgoing,
            timers: rendered.timers,
            cancelled_timers: rendered.cancelled_timers,
        })
    }

    /// Queues one bounded TCP data segment while the peer window has space.
    ///
    /// # Errors
    ///
    /// Returns an error for stale/unaccepted state, peer-window backpressure,
    /// an oversized segment, or exhausted payload/metadata budget.
    pub fn write(
        &mut self,
        token: TcpFlowToken,
        payload: &[u8],
    ) -> Result<TcpIngress, TcpTableError> {
        let key = self.key_for(token)?;
        if payload.is_empty() {
            return Ok(TcpIngress::default());
        }
        let flow = self.by_key.get(&key).ok_or(TcpTableError::StaleToken)?;
        if payload.len() > flow.max_send_segment_bytes {
            return Err(TcpTableError::PayloadTooLarge);
        }
        if flow.accept_lease.is_some() {
            return Err(TcpTableError::NotAccepted);
        }
        // The persist and Nagle paths buffer before the TCB sees the send, so
        // check its state here: data queued after a local FIN would later be
        // emitted beyond the FIN's sequence number.
        if !matches!(
            flow.tcb.state(),
            TcpState::Established | TcpState::CloseWait
        ) {
            return Err(TcpError::InvalidSendState.into());
        }
        if flow.pending_send.is_some() {
            return Err(TcpError::SendWindowExceeded.into());
        }
        let payload_lease = self
            .ledger
            .try_acquire(ResourceKind::TcpPayloadBytes, payload.len())?;
        let metadata_lease = self
            .ledger
            .try_acquire(ResourceKind::MetadataBytes, TCP_CHUNK_METADATA_CHARGE)?;
        let bytes: Box<[u8]> = payload.into();
        let flow = self.by_key.get_mut(&key).ok_or(TcpTableError::StaleToken)?;
        let pending_reason = if flow.tcb.peer_window() == 0 {
            Some(PendingSendReason::Persist)
        } else if self.config.nagle_enabled
            && !flow.send.is_empty()
            && bytes.len() < flow.max_send_segment_bytes
        {
            Some(PendingSendReason::Nagle)
        } else {
            None
        };
        if let Some(reason) = pending_reason {
            flow.pending_send = Some(PendingSend {
                bytes,
                payload_lease,
                reason,
                _metadata_lease: metadata_lease,
            });
            let id = flow.id;
            let mut output = TcpIngress::default();
            match reason {
                PendingSendReason::Persist => {
                    flow.persist_backoff_ms = self.config.persist_initial_ms;
                    self.stats.zero_window_writes = self.stats.zero_window_writes.saturating_add(1);
                    output.timers.push(TcpTimerRequest {
                        token: TcpFlowToken::new_on_shard(id, self.generation, self.shard),
                        event: TimerEvent::Persist,
                        after_ms: self.config.persist_initial_ms,
                    });
                }
                PendingSendReason::Nagle => {
                    self.stats.nagle_buffered_writes =
                        self.stats.nagle_buffered_writes.saturating_add(1);
                }
            }
            self.sync_flow_stats(key);
            return Ok(output);
        }
        let sequence = flow.tcb.send_next();
        let actions = flow.tcb.on_app_event(crate::AppEvent::Send(bytes.len()))?;
        arm_rtt_probe(flow, sequence.wrapping_add(bytes.len()), self.now_ms);
        flow.send.push_back(SendChunk {
            sequence,
            bytes,
            payload_lease,
            sacked: false,
            retransmitted: false,
            resegment: false,
            _metadata_lease: metadata_lease,
        });
        let id = flow.id;
        let output = self.render_actions(key, id, &actions)?;
        self.sync_flow_stats(key);
        Ok(output)
    }

    /// Starts an orderly application close.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::StaleToken`] for a stale or unknown token, or
    /// [`TcpError::SendOutstanding`] while an unsent persist/Nagle buffer must
    /// precede the FIN. Already-transmitted payload may remain unacknowledged;
    /// its sequence space precedes the FIN and is retransmitted first on loss.
    pub fn close(&mut self, token: TcpFlowToken) -> Result<TcpIngress, TcpTableError> {
        let key = self.key_for(token)?;
        let flow = self.by_key.get(&key).ok_or(TcpTableError::StaleToken)?;
        if flow.pending_send.is_some() {
            return Err(TcpError::SendOutstanding.into());
        }
        self.apply_app_event(token, crate::AppEvent::Close)
    }

    /// The application lets go of a flow it has closed: nothing will read
    /// or write it again. Once in FIN-WAIT-2, it waits
    /// `fin_wait2_timeout_ms` for the peer's FIN, then leaves the table
    /// (Linux's orphan `tcp_fin_timeout`). Other states end by themselves:
    /// retransmission bounds FIN-WAIT-1, CLOSING and LAST-ACK.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::StaleToken`] for a stale or unknown token.
    pub fn release(&mut self, token: TcpFlowToken) -> Result<TcpIngress, TcpTableError> {
        let key = self.key_for(token)?;
        let mut output = TcpIngress::default();
        let Some(flow) = self.by_key.get_mut(&key) else {
            // In TIME-WAIT, which ends by itself.
            return Ok(output);
        };
        flow.orphaned = true;
        // In TIME-WAIT still whole, for bytes it had not read.
        if flow.tcb.state() == TcpState::TimeWait {
            let id = flow.id;
            self.move_to_time_wait(key, id, &mut output)?;
            self.sync_flow_stats(key);
            self.refresh_structural_stats();
            return Ok(output);
        }
        self.arm_fin_wait2_if_orphaned(key, &mut output)?;
        Ok(output)
    }

    /// Aborts a connection and releases it after emitting RST.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::StaleToken`] for a stale or unknown token.
    pub fn abort(&mut self, token: TcpFlowToken) -> Result<TcpIngress, TcpTableError> {
        self.apply_app_event(token, crate::AppEvent::Abort)
    }

    /// Aborts every flow but those in `TIME_WAIT` (another map), each as
    /// [`TcpTable::abort`] does one, and returns the resets they rendered:
    /// from the flow's remote side to the app, at `SND.NXT`, acknowledging
    /// `RCV.NXT`. Like `abort`, these do not pass the stateless-reset limiter:
    /// one each, for flows of our own. A network reset or a closing runner
    /// sends them, so that an app reading a flow learns that it ended. The
    /// aborts' events and cancelled timers are dropped: the flows go with
    /// what calls this, and a timer of one resolves to a stale token.
    pub fn abort_all(&mut self) -> Vec<Vec<u8>> {
        let ids: Vec<FlowId> = self.by_key.values().map(|flow| flow.id).collect();
        let mut wires = Vec::new();
        for id in ids {
            let token = TcpFlowToken::new_on_shard(id, self.generation, self.shard);
            if let Ok(mut output) = self.abort(token) {
                wires.append(&mut output.outgoing);
            }
        }
        wires
    }

    fn apply_app_event(
        &mut self,
        token: TcpFlowToken,
        event: crate::AppEvent,
    ) -> Result<TcpIngress, TcpTableError> {
        let key = self.key_for(token)?;
        let flow = self.by_key.get_mut(&key).ok_or(TcpTableError::StaleToken)?;
        let actions = flow.tcb.on_app_event(event)?;
        let id = flow.id;
        let closed = actions.contains(&TcpAction::Closed);
        let output = self.render_actions(key, id, &actions)?;
        if closed {
            self.remove(key);
        }
        self.sync_flow_stats(key);
        self.refresh_structural_stats();
        Ok(output)
    }

    /// Applies a previously requested protocol timer.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::StaleToken`] for a stale or unknown token.
    pub fn on_timer(
        &mut self,
        token: TcpFlowToken,
        event: TimerEvent,
    ) -> Result<TcpIngress, TcpTableError> {
        self.on_timer_at(token, event, self.now_ms)
    }

    /// Applies a protocol timer at an explicit monotonic time.
    ///
    /// # Errors
    ///
    /// Returns an error for stale flow state or a regressing clock.
    pub fn on_timer_at(
        &mut self,
        token: TcpFlowToken,
        event: TimerEvent,
        now_ms: u64,
    ) -> Result<TcpIngress, TcpTableError> {
        self.update_clock(now_ms)?;
        let key = self.key_for(token)?;
        if self.time_wait.contains_key(&key) {
            if event != TimerEvent::TimeWaitExpired {
                return Ok(TcpIngress::default());
            }
            let entry = self
                .time_wait
                .remove(&key)
                .ok_or(TcpTableError::StaleToken)?;
            self.time_wait_order.remove(&entry.id.get());
            self.by_id.remove(&token.flow());
            increment_counter(&mut self.stats.closed_flows);
            self.refresh_structural_stats();
            return Ok(TcpIngress {
                events: vec![TcpEvent::Closed(token)],
                ..TcpIngress::default()
            });
        }
        if event == TimerEvent::Persist {
            return self.on_persist_timer(key);
        }
        if event == TimerEvent::Keepalive {
            return self.on_keepalive_timer(key);
        }
        if event == TimerEvent::FinWait2Timeout {
            let flow = self.by_key.get(&key).ok_or(TcpTableError::StaleToken)?;
            if !(flow.orphaned && flow.tcb.state() == TcpState::FinWait2) {
                return Ok(TcpIngress::default());
            }
            // As Linux: gone without a word; a segment from the peer later
            // finds no flow and is answered with RST.
            self.remove(key);
            self.stats.fin_wait2_timeouts = self.stats.fin_wait2_timeouts.saturating_add(1);
            self.refresh_structural_stats();
            return Ok(TcpIngress {
                events: vec![TcpEvent::Closed(token)],
                ..TcpIngress::default()
            });
        }
        if event == TimerEvent::Retransmission {
            let flow = self.by_key.get_mut(&key).ok_or(TcpTableError::StaleToken)?;
            if flow.tcb.send_unacked() == flow.tcb.send_next() {
                return Ok(TcpIngress::default());
            }
            // Silent too long, a peer probed through a shut window ends the
            // flow, as Linux's does.
            let probing_shut_window = flow.probes_shut_window();
            let gave_up = if probing_shut_window {
                self.now_ms.saturating_sub(flow.last_received_ms) > SHUT_WINDOW_SILENCE_MS
            } else {
                flow.retransmission_timeouts >= self.config.max_retransmission_timeouts
            };
            if gave_up {
                self.remove(key);
                self.stats.retransmission_failures =
                    self.stats.retransmission_failures.saturating_add(1);
                self.refresh_structural_stats();
                return Ok(TcpIngress {
                    events: vec![TcpEvent::Closed(token)],
                    ..TcpIngress::default()
                });
            }
            if !probing_shut_window {
                flow.retransmission_timeouts = flow.retransmission_timeouts.saturating_add(1);
            }
            flow.rtt_probe = None;
            self.stats.retransmission_timeouts =
                self.stats.retransmission_timeouts.saturating_add(1);
            let fallback_mtu = if key.source.is_ipv4() {
                IPV4_BLACK_HOLE_FALLBACK_MTU
            } else {
                IPV6_BLACK_HOLE_FALLBACK_MTU
            };
            if self
                .config
                .black_hole_rto_threshold
                .is_some_and(|threshold| flow.retransmission_timeouts >= threshold)
                && !flow.send.is_empty()
                && lower_flow_mtu(key, flow, fallback_mtu)
            {
                self.stats.black_hole_mtu_fallbacks =
                    self.stats.black_hole_mtu_fallbacks.saturating_add(1);
            }
        }
        let flow = self.by_key.get_mut(&key).ok_or(TcpTableError::StaleToken)?;
        if event == TimerEvent::Retransmission {
            for chunk in &mut flow.send {
                chunk.sacked = false;
                chunk.retransmitted = false;
            }
            flow.sack_recovery = None;
        }
        let actions = flow.tcb.on_timer(event)?;
        let id = flow.id;
        let closed = actions.contains(&TcpAction::Closed);
        let output = self.render_actions(key, id, &actions)?;
        if closed {
            self.remove(key);
        }
        self.sync_flow_stats(key);
        self.refresh_structural_stats();
        Ok(output)
    }

    pub fn reset_network(&mut self, generation: NetworkGeneration) {
        self.generation = generation;
        self.by_key.clear();
        self.time_wait.clear();
        self.time_wait_order.clear();
        self.by_id.clear();
        self.syn_received_order.clear();
        self.syn_limiter.reset();
        self.defensive_ack_limiter.reset();
        self.challenge_ack_limiter.reset();
        self.stateless_reset_limiter.reset();
        self.reset_live_stats();
    }

    #[must_use]
    pub const fn stats(&self) -> TcpTableStats {
        self.stats
    }

    #[must_use]
    pub const fn max_segment_payload_bytes(&self) -> usize {
        self.config.max_segment_payload_bytes
    }

    /// The most receive window a flow may reach, which its window scale must
    /// be able to announce.
    fn receive_window_ceiling(&self) -> usize {
        self.config
            .max_receive_credit_bytes
            .unwrap_or(self.config.receive_credit_bytes)
    }

    /// Sets the MTU flows opened from now on size their segments by; flows
    /// already open follow a lower one through [`Self::lower_platform_mtu`].
    pub fn set_link_mtu(&mut self, mtu: usize) {
        self.config.link_mtu = Some(mtu);
    }

    /// The segment size of a flow a peer's SYN opens: our MSS, the peer's
    /// (RFC 9293 3.7.1 defaults when it sends none), and room for the
    /// options the SYN asks for.
    fn passive_segment_bytes(&self, key: TcpFlowKey, options: &TcpOptions) -> usize {
        let default_peer_mss = if key.source.is_ipv4() { 536 } else { 1_220 };
        let bytes = self.local_mss(key.source).min(peer_segment_bytes(
            usize::from(options.maximum_segment_size.unwrap_or(default_peer_mss)),
            options.sack_permitted,
            options.timestamps.is_some(),
        ));
        self.config.link_mtu.map_or(bytes, |mtu| {
            bytes.min(segment_ceiling(
                key.source.is_ipv4(),
                options.sack_permitted,
                options.timestamps.is_some(),
                mtu,
            ))
        })
    }

    /// The MSS for a flow with `peer`: announced in its SYN, and the most
    /// it sends before options are known.
    fn local_mss(&self, peer: SocketAddr) -> usize {
        self.config
            .link_mtu
            .map_or(self.config.max_segment_payload_bytes, |mtu| {
                self.config
                    .max_segment_payload_bytes
                    .min(link_mss(peer.is_ipv4(), mtu))
            })
    }

    /// Returns whether an outgoing packet quote names the reverse direction
    /// of a live intercepted flow in the current network generation.
    #[must_use]
    pub fn has_quoted_flow(
        &self,
        quoted_source: SocketAddr,
        quoted_destination: SocketAddr,
    ) -> bool {
        self.by_key.contains_key(&TcpFlowKey::new(
            quoted_destination,
            quoted_source,
            self.generation,
        ))
    }

    /// Lowers the send segment ceiling for the flow named by an outgoing
    /// packet quoted in an authenticated Packet Too Big message.
    #[must_use]
    pub fn lower_path_mtu(
        &mut self,
        quoted_source: SocketAddr,
        quoted_destination: SocketAddr,
        path_mtu: usize,
    ) -> bool {
        let key = TcpFlowKey::new(quoted_destination, quoted_source, self.generation);
        let Some(flow) = self.by_key.get_mut(&key) else {
            return false;
        };
        lower_flow_mtu(key, flow, path_mtu)
    }

    /// Lowers every active flow after a platform MTU change.
    pub fn lower_platform_mtu(&mut self, mtu: usize) -> usize {
        let mut changed = 0;
        for (key, flow) in &mut self.by_key {
            changed += usize::from(lower_flow_mtu(*key, flow, mtu));
        }
        changed
    }

    /// Returns the current peer/PMTU-constrained application write ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::StaleToken`] for a stale or unknown token.
    pub fn write_limit(&mut self, token: TcpFlowToken) -> Result<usize, TcpTableError> {
        let key = self.key_for(token)?;
        self.by_key
            .get(&key)
            .map(|flow| flow.max_send_segment_bytes)
            .ok_or(TcpTableError::StaleToken)
    }

    /// Returns how many application bytes this flow can take ownership of now:
    /// what the peer and congestion windows leave room for, possibly many
    /// segments, which [`crate::SingleShardRunner::write_tcp`] cuts. A
    /// zero-window flow, or one Nagle holds back, may still accept one
    /// segment into its pending slot. Either is no more than the flow's
    /// send buffer (`max_send_buffer_bytes`) has room for.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::StaleToken`] for a stale or unknown token.
    pub fn write_capacity(&mut self, token: TcpFlowToken) -> Result<usize, TcpTableError> {
        let key = self.key_for(token)?;
        let flow = self.by_key.get(&key).ok_or(TcpTableError::StaleToken)?;
        if flow.pending_send.is_some() {
            return Ok(0);
        }
        let capacity = if flow.tcb.peer_window() == 0
            || (self.config.nagle_enabled && !flow.send.is_empty())
        {
            flow.max_send_segment_bytes
        } else {
            flow.tcb.send_available()
        };
        Ok(match self.config.max_send_buffer_bytes {
            Some(max) => capacity.min(max.saturating_sub(send_buffered_bytes(flow))),
            None => capacity,
        })
    }

    /// Returns the exact IP plus TCP packet size for a payload on this flow.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::StaleToken`] for a stale or unknown token.
    pub fn packet_len(
        &mut self,
        token: TcpFlowToken,
        payload_len: usize,
    ) -> Result<usize, TcpTableError> {
        let key = self.key_for(token)?;
        let flow = self.by_key.get(&key).ok_or(TcpTableError::StaleToken)?;
        if payload_len > flow.max_send_segment_bytes {
            return Err(TcpTableError::PayloadTooLarge);
        }
        let mut header_len: usize = if key.source.is_ipv4() { 40 } else { 60 };
        header_len += self.segment_options(key).map_or(0, |options| options.len());
        header_len
            .checked_add(payload_len)
            .ok_or(TcpTableError::PayloadTooLarge)
    }

    fn key_for(&mut self, token: TcpFlowToken) -> Result<TcpFlowKey, TcpTableError> {
        if !token.is_owned_by(self.generation, self.shard) {
            increment_counter(&mut self.stats.stale_operations);
            return Err(TcpTableError::StaleToken);
        }
        self.by_id.get(&token.flow()).copied().ok_or_else(|| {
            increment_counter(&mut self.stats.stale_operations);
            TcpTableError::StaleToken
        })
    }

    /// Moves the table's clock to `now_ms`. Operations that take no time of
    /// their own (connect, write, read, close) run at this clock, so a
    /// caller keeps it current: a clock left behind while the flow was idle
    /// dates what they send too early, and the RTT measured from it is too
    /// long.
    ///
    /// # Errors
    ///
    /// Returns [`TcpTableError::ClockWentBackwards`] for an earlier time.
    pub fn advance_clock(&mut self, now_ms: u64) -> Result<(), TcpTableError> {
        self.update_clock(now_ms)
    }

    fn update_clock(&mut self, now_ms: u64) -> Result<(), TcpTableError> {
        if now_ms < self.now_ms {
            return Err(TcpTableError::ClockWentBackwards);
        }
        self.now_ms = now_ms;
        Ok(())
    }

    fn render_actions(
        &mut self,
        key: TcpFlowKey,
        id: FlowId,
        actions: &[TcpAction],
    ) -> Result<TcpIngress, TcpTableError> {
        let token = TcpFlowToken::new_on_shard(id, self.generation, self.shard);
        let mut output = TcpIngress::default();
        for action in actions {
            match *action {
                TcpAction::Send(control) => {
                    if control.flags.contains(TcpFlags::SYN) {
                        let options = if control.flags.contains(TcpFlags::ACK) {
                            self.syn_ack_options(key)?
                        } else {
                            self.syn_options(key)?
                        };
                        output
                            .outgoing
                            .push(self.emit_with_options(key, control, &options)?);
                    } else {
                        output.outgoing.push(self.emit(key, control)?);
                    }
                }
                TcpAction::DefensiveAck(control) => {
                    if self.defensive_ack_limiter.allow(self.now_ms) {
                        output.outgoing.push(self.emit(key, control)?);
                        self.stats.defensive_acks_sent =
                            self.stats.defensive_acks_sent.saturating_add(1);
                    } else {
                        self.stats.defensive_acks_rate_limited =
                            self.stats.defensive_acks_rate_limited.saturating_add(1);
                    }
                }
                TcpAction::SendPayload(control) => {
                    output.outgoing.push(self.render_send(key, control)?);
                }
                TcpAction::RetransmitPayload(mut control) => {
                    let Some(packet) = self.render_retransmit(key, &mut control)? else {
                        continue;
                    };
                    output.outgoing.push(packet);
                }
                TcpAction::DeliverPayload { len } => {
                    output.events.push(TcpEvent::Readable { token, bytes: len });
                }
                TcpAction::Accepted => output
                    .events
                    .push(TcpEvent::Accepted(self.connection(key, token, false)?)),
                TcpAction::Connected => output
                    .events
                    .push(TcpEvent::Connected(self.connection(key, token, true)?)),
                TcpAction::PeerHalfClosed => {
                    output.events.push(TcpEvent::PeerHalfClosed(token));
                }
                TcpAction::ArmRetransmission { after_ms } => {
                    output.timers.push(TcpTimerRequest {
                        token,
                        event: TimerEvent::Retransmission,
                        after_ms,
                    });
                }
                TcpAction::DisarmRetransmission => {
                    output.cancelled_timers.push(TcpTimerCancel {
                        token,
                        event: TimerEvent::Retransmission,
                    });
                }
                TcpAction::ArmDelayedAck => output.timers.push(TcpTimerRequest {
                    token,
                    event: TimerEvent::DelayedAck,
                    after_ms: self.config.delayed_ack_ms,
                }),
                TcpAction::DisarmDelayedAck => output.cancelled_timers.push(TcpTimerCancel {
                    token,
                    event: TimerEvent::DelayedAck,
                }),
                TcpAction::ArmTimeWait => output.timers.push(TcpTimerRequest {
                    token,
                    event: TimerEvent::TimeWaitExpired,
                    after_ms: self.config.time_wait_ms,
                }),
                TcpAction::ChallengeAck => {
                    let flow = self.by_key.get(&key).ok_or(TcpTableError::UnknownFlow)?;
                    let control = SendControl {
                        sequence: flow.tcb.acceptable_seq(),
                        acknowledgment: flow.tcb.recv_next(),
                        flags: TcpFlags::ACK,
                        window: flow.tcb.advertised_window(),
                    };
                    output.outgoing.push(self.emit(key, control)?);
                }
                TcpAction::Closed => output.events.push(TcpEvent::Closed(token)),
            }
        }
        Ok(output)
    }

    fn on_persist_timer(&mut self, key: TcpFlowKey) -> Result<TcpIngress, TcpTableError> {
        let Some(flow) = self.by_key.get(&key) else {
            return Err(TcpTableError::StaleToken);
        };
        if flow.pending_send.is_none() {
            return Ok(TcpIngress::default());
        }
        if flow.tcb.send_available() > 0 {
            return self.flush_pending_send(key);
        }

        let token = TcpFlowToken::new_on_shard(flow.id, self.generation, self.shard);
        let next_backoff = flow
            .persist_backoff_ms
            .saturating_mul(2)
            .min(self.config.persist_max_ms);
        let should_probe = flow.tcb.peer_window() == 0;
        let control = SendControl {
            sequence: flow.tcb.send_next(),
            acknowledgment: flow.tcb.recv_next(),
            flags: TcpFlags::ACK,
            window: flow.tcb.advertised_window(),
        };
        let probe = should_probe.then(|| {
            flow.pending_send
                .as_ref()
                .expect("pending send checked above")
                .bytes[0]
        });
        self.by_key
            .get_mut(&key)
            .ok_or(TcpTableError::StaleToken)?
            .persist_backoff_ms = next_backoff;
        let mut output = TcpIngress {
            timers: vec![TcpTimerRequest {
                token,
                event: TimerEvent::Persist,
                after_ms: next_backoff,
            }],
            ..TcpIngress::default()
        };
        if let Some(byte) = probe {
            output
                .outgoing
                .push(self.emit_payload(key, control, &[byte])?);
            self.stats.persist_probes = self.stats.persist_probes.saturating_add(1);
        }
        Ok(output)
    }

    fn on_keepalive_timer(&mut self, key: TcpFlowKey) -> Result<TcpIngress, TcpTableError> {
        let Some(idle_ms) = self.config.keepalive_idle_ms else {
            return Ok(TcpIngress::default());
        };
        let flow = self.by_key.get(&key).ok_or(TcpTableError::StaleToken)?;
        if !matches!(
            flow.tcb.state(),
            TcpState::Established | TcpState::CloseWait
        ) {
            return Ok(TcpIngress::default());
        }
        let token = TcpFlowToken::new_on_shard(flow.id, self.generation, self.shard);
        if !flow.send.is_empty() || flow.pending_send.is_some() {
            return Ok(TcpIngress {
                timers: vec![TcpTimerRequest {
                    token,
                    event: TimerEvent::Keepalive,
                    after_ms: idle_ms,
                }],
                ..TcpIngress::default()
            });
        }
        if flow.keepalive_probes_sent >= self.config.keepalive_max_probes {
            self.remove(key);
            self.stats.keepalive_timeouts = self.stats.keepalive_timeouts.saturating_add(1);
            self.refresh_structural_stats();
            return Ok(TcpIngress {
                events: vec![TcpEvent::Closed(token)],
                ..TcpIngress::default()
            });
        }
        let control = SendControl {
            sequence: SeqNumber::new(flow.tcb.send_next().get().wrapping_sub(1)),
            acknowledgment: flow.tcb.recv_next(),
            flags: TcpFlags::ACK,
            window: flow.tcb.advertised_window(),
        };
        let packet = self.emit(key, control)?;
        let flow = self.by_key.get_mut(&key).ok_or(TcpTableError::StaleToken)?;
        flow.keepalive_probes_sent = flow.keepalive_probes_sent.saturating_add(1);
        self.stats.keepalive_probes = self.stats.keepalive_probes.saturating_add(1);
        Ok(TcpIngress {
            outgoing: vec![packet],
            timers: vec![TcpTimerRequest {
                token,
                event: TimerEvent::Keepalive,
                after_ms: self.config.keepalive_interval_ms,
            }],
            ..TcpIngress::default()
        })
    }

    fn arm_keepalive_if_active(
        &self,
        key: TcpFlowKey,
        output: &mut TcpIngress,
    ) -> Result<(), TcpTableError> {
        let Some(after_ms) = self.config.keepalive_idle_ms else {
            return Ok(());
        };
        let flow = self.by_key.get(&key).ok_or(TcpTableError::UnknownFlow)?;
        if matches!(
            flow.tcb.state(),
            TcpState::Established | TcpState::CloseWait
        ) {
            output.timers.push(TcpTimerRequest {
                token: TcpFlowToken::new_on_shard(flow.id, self.generation, self.shard),
                event: TimerEvent::Keepalive,
                after_ms,
            });
        }
        Ok(())
    }

    fn arm_fin_wait2_if_orphaned(
        &mut self,
        key: TcpFlowKey,
        output: &mut TcpIngress,
    ) -> Result<(), TcpTableError> {
        let flow = self
            .by_key
            .get_mut(&key)
            .ok_or(TcpTableError::UnknownFlow)?;
        if flow.orphaned && !flow.fin_wait2_armed && flow.tcb.state() == TcpState::FinWait2 {
            flow.fin_wait2_armed = true;
            output.timers.push(TcpTimerRequest {
                token: TcpFlowToken::new_on_shard(flow.id, self.generation, self.shard),
                event: TimerEvent::FinWait2Timeout,
                after_ms: self.config.fin_wait2_timeout_ms,
            });
        }
        Ok(())
    }

    fn flush_pending_send(&mut self, key: TcpFlowKey) -> Result<TcpIngress, TcpTableError> {
        let amount = {
            let flow = self.by_key.get(&key).ok_or(TcpTableError::StaleToken)?;
            let Some(pending) = &flow.pending_send else {
                return Ok(TcpIngress::default());
            };
            if pending.reason == PendingSendReason::Nagle && !flow.send.is_empty() {
                return Ok(TcpIngress::default());
            }
            flow.tcb
                .send_available()
                .min(flow.max_send_segment_bytes)
                .min(pending.bytes.len())
        };
        if amount == 0 {
            return Ok(TcpIngress::default());
        }

        let remainder_metadata = {
            let flow = self.by_key.get(&key).ok_or(TcpTableError::StaleToken)?;
            (amount
                < flow
                    .pending_send
                    .as_ref()
                    .expect("checked above")
                    .bytes
                    .len())
            .then(|| {
                self.ledger
                    .try_acquire(ResourceKind::MetadataBytes, TCP_CHUNK_METADATA_CHARGE)
            })
            .transpose()
        };
        let Ok(remainder_metadata) = remainder_metadata else {
            let flow = self.by_key.get_mut(&key).ok_or(TcpTableError::StaleToken)?;
            flow.persist_backoff_ms = self.config.persist_initial_ms;
            return Ok(TcpIngress {
                timers: vec![TcpTimerRequest {
                    token: TcpFlowToken::new_on_shard(flow.id, self.generation, self.shard),
                    event: TimerEvent::Persist,
                    after_ms: self.config.persist_initial_ms,
                }],
                ..TcpIngress::default()
            });
        };
        let flow = self.by_key.get_mut(&key).ok_or(TcpTableError::StaleToken)?;
        let pending = flow.pending_send.take().ok_or(TcpTableError::Invariant(
            "pending send disappeared during flush",
        ))?;
        let sequence = flow.tcb.send_next();
        let actions = flow.tcb.on_app_event(crate::AppEvent::Send(amount))?;
        arm_rtt_probe(flow, sequence.wrapping_add(amount), self.now_ms);
        let PendingSend {
            bytes,
            mut payload_lease,
            reason,
            _metadata_lease: metadata_lease,
        } = pending;
        let sent_bytes: Box<[u8]> = bytes[..amount].into();
        let remainder_lease = payload_lease.split_off(amount);
        flow.send.push_back(SendChunk {
            sequence,
            bytes: sent_bytes,
            payload_lease,
            sacked: false,
            retransmitted: false,
            resegment: false,
            _metadata_lease: metadata_lease,
        });
        if amount < bytes.len() {
            flow.pending_send = Some(PendingSend {
                bytes: bytes[amount..].into(),
                payload_lease: remainder_lease,
                reason: PendingSendReason::Persist,
                _metadata_lease: remainder_metadata.expect("partial flush reserved metadata"),
            });
            flow.persist_backoff_ms = self.config.persist_initial_ms;
        } else {
            drop(remainder_lease);
            flow.persist_backoff_ms = 0;
        }
        let id = flow.id;
        let has_remainder = flow.pending_send.is_some();
        let mut output = self.render_actions(key, id, &actions)?;
        if has_remainder {
            output.timers.push(TcpTimerRequest {
                token: TcpFlowToken::new_on_shard(id, self.generation, self.shard),
                event: TimerEvent::Persist,
                after_ms: self.config.persist_initial_ms,
            });
        } else if reason == PendingSendReason::Persist {
            output.cancelled_timers.push(TcpTimerCancel {
                token: TcpFlowToken::new_on_shard(id, self.generation, self.shard),
                event: TimerEvent::Persist,
            });
        }
        self.sync_flow_stats(key);
        Ok(output)
    }

    fn append_resegmented(
        &mut self,
        key: TcpFlowKey,
        control: Option<SendControl>,
        actions: &[TcpAction],
        output: &mut TcpIngress,
    ) -> Result<(), TcpTableError> {
        let Some(mut control) = control else {
            return Ok(());
        };
        let already_retransmitted = actions
            .iter()
            .any(|action| matches!(action, TcpAction::RetransmitPayload(_)));
        if !already_retransmitted && output.outgoing.is_empty() {
            if let Some(packet) = self.render_retransmit(key, &mut control)? {
                output.outgoing.push(packet);
            }
        }
        Ok(())
    }

    fn render_send(
        &mut self,
        key: TcpFlowKey,
        control: SendControl,
    ) -> Result<Vec<u8>, TcpTableError> {
        let chunk = self
            .by_key
            .get(&key)
            .and_then(|flow| {
                flow.send.iter().find(|chunk| {
                    usize::try_from(control.sequence.distance_from(chunk.sequence))
                        .is_ok_and(|offset| offset < chunk.bytes.len())
                })
            })
            .ok_or(TcpTableError::Invariant(
                "payload action lacked matching send chunk",
            ))?;
        let offset = usize::try_from(control.sequence.distance_from(chunk.sequence))
            .map_err(|_| TcpTableError::Invariant("payload send offset exceeds usize"))?;
        let payload = chunk
            .bytes
            .get(offset..)
            .ok_or(TcpTableError::Invariant(
                "payload sequence lies outside send chunk",
            ))?
            .to_vec();
        self.emit_payload(key, control, &payload)
            .map_err(Into::into)
    }

    /// The completed connection of `key`, oriented from whoever opened it.
    fn connection(
        &self,
        key: TcpFlowKey,
        token: TcpFlowToken,
        opened_here: bool,
    ) -> Result<TcpConnection, TcpTableError> {
        let (source, destination) = if opened_here {
            (key.destination, key.source)
        } else {
            (key.source, key.destination)
        };
        Ok(TcpConnection {
            token,
            source,
            destination,
            max_segment_payload_bytes: self
                .by_key
                .get(&key)
                .ok_or(TcpTableError::UnknownFlow)?
                .max_send_segment_bytes,
        })
    }

    /// The options of our own SYN: everything this stack can use, left to
    /// the peer's SYN-ACK to accept.
    fn syn_options(&self, key: TcpFlowKey) -> Result<Vec<u8>, TcpTableError> {
        let flow = self.by_key.get(&key).ok_or(TcpTableError::UnknownFlow)?;
        let advertised_mss = u16::try_from(self.local_mss(key.source)).unwrap_or(u16::MAX);
        let mut options = vec![2, 4];
        options.extend_from_slice(&advertised_mss.to_be_bytes());
        options.extend_from_slice(&[4, 2, 8, 10]);
        options
            .extend_from_slice(&timestamp_value(self.now_ms, flow.timestamp_offset).to_be_bytes());
        options.extend_from_slice(&0_u32.to_be_bytes());
        options.extend_from_slice(&[1, 3, 3, flow.local_window_scale]);
        Ok(options)
    }

    fn syn_ack_options(&self, key: TcpFlowKey) -> Result<Vec<u8>, TcpTableError> {
        let flow = self.by_key.get(&key).ok_or(TcpTableError::UnknownFlow)?;
        let advertised_mss = u16::try_from(self.local_mss(key.source)).unwrap_or(u16::MAX);
        let mut options = vec![2, 4];
        options.extend_from_slice(&advertised_mss.to_be_bytes());
        if flow.sack_permitted {
            options.extend_from_slice(&[4, 2, 1, 1]);
        }
        if flow.peer_window_scale.is_some() {
            options.extend_from_slice(&[3, 3, flow.local_window_scale, 1]);
        }
        if let Some(timestamp) = flow.timestamp {
            options.extend_from_slice(&[8, 10]);
            options.extend_from_slice(
                &timestamp_value(self.now_ms, flow.timestamp_offset).to_be_bytes(),
            );
            options.extend_from_slice(&timestamp.recent.to_be_bytes());
            options.extend_from_slice(&[1, 1]);
        }
        Ok(options)
    }

    fn render_retransmit(
        &mut self,
        key: TcpFlowKey,
        control: &mut SendControl,
    ) -> Result<Option<Vec<u8>>, TcpTableError> {
        let payload = {
            let flow = self
                .by_key
                .get_mut(&key)
                .ok_or(TcpTableError::UnknownFlow)?;
            let limit = flow.max_send_segment_bytes;
            let Some(chunk) = flow
                .send
                .iter_mut()
                .find(|chunk| !chunk.sacked && !chunk.retransmitted)
            else {
                return Ok(None);
            };
            control.sequence = chunk.sequence;
            let amount = chunk.bytes.len().min(limit);
            chunk.resegment = chunk.bytes.len() > amount;
            chunk.retransmitted = true;
            flow.rtt_probe = None;
            chunk.bytes[..amount].to_vec()
        };
        self.emit_payload(key, *control, &payload)
            .map(Some)
            .map_err(Into::into)
    }

    fn render_sack_recovery(
        &mut self,
        key: TcpFlowKey,
        packet_limit: usize,
    ) -> Result<Vec<Vec<u8>>, TcpTableError> {
        let mut packets = Vec::new();
        while packets.len() < packet_limit {
            let selection = {
                let flow = self.by_key.get(&key).ok_or(TcpTableError::UnknownFlow)?;
                let Some(recovery) = flow.sack_recovery else {
                    break;
                };
                if flow.tcb.congestion_window().saturating_sub(sack_pipe(flow))
                    < flow.max_send_segment_bytes
                {
                    break;
                }
                next_sack_segment(flow, recovery)
            };
            let Some((index, rescue)) = selection else {
                break;
            };
            let (control, payload) = {
                let flow = self
                    .by_key
                    .get_mut(&key)
                    .ok_or(TcpTableError::UnknownFlow)?;
                flow.rtt_probe = None;
                if rescue {
                    let recovery = flow.sack_recovery.as_mut().expect("recovery checked above");
                    recovery.rescue_after = recovery.recovery_point;
                }
                let chunk = flow.send.get_mut(index).ok_or(TcpTableError::Invariant(
                    "SACK recovery selected a missing send chunk",
                ))?;
                let amount = chunk.bytes.len().min(flow.max_send_segment_bytes);
                let control = SendControl {
                    sequence: chunk.sequence,
                    acknowledgment: flow.tcb.recv_next(),
                    flags: TcpFlags::ACK,
                    window: flow.tcb.advertised_window(),
                };
                if !rescue {
                    chunk.retransmitted = true;
                }
                (control, chunk.bytes[..amount].to_vec())
            };
            packets.push(self.emit_payload(key, control, &payload)?);
            self.stats.sack_retransmitted_segments =
                self.stats.sack_retransmitted_segments.saturating_add(1);
            if rescue {
                self.stats.sack_rescue_segments = self.stats.sack_rescue_segments.saturating_add(1);
            }
        }
        Ok(packets)
    }

    fn emit(&mut self, key: TcpFlowKey, control: SendControl) -> Result<Vec<u8>, WireError> {
        let identification = self.next_ipv4_id;
        self.next_ipv4_id = self.next_ipv4_id.wrapping_add(1);
        if let Some(options) = self.segment_options(key) {
            emit_tcp_segment_with_options(
                key.destination,
                key.source,
                control,
                &options,
                &[],
                self.config.hop_limit,
                identification,
            )
        } else {
            emit_tcp_control(
                key.destination,
                key.source,
                control,
                self.config.hop_limit,
                identification,
            )
        }
    }

    fn emit_payload(
        &mut self,
        key: TcpFlowKey,
        control: SendControl,
        payload: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        let identification = self.next_ipv4_id;
        self.next_ipv4_id = self.next_ipv4_id.wrapping_add(1);
        if let Some(options) = self.segment_options(key) {
            emit_tcp_segment_with_options(
                key.destination,
                key.source,
                control,
                &options,
                payload,
                self.config.hop_limit,
                identification,
            )
        } else {
            emit_tcp_segment(
                key.destination,
                key.source,
                control,
                payload,
                self.config.hop_limit,
                identification,
            )
        }
    }

    fn timestamp_options(&self, key: TcpFlowKey) -> Option<[u8; 12]> {
        let flow = self.by_key.get(&key)?;
        let timestamp = flow.timestamp?;
        let mut options = [0_u8; 12];
        options[0..2].copy_from_slice(&[8, 10]);
        options[2..6]
            .copy_from_slice(&timestamp_value(self.now_ms, flow.timestamp_offset).to_be_bytes());
        options[6..10].copy_from_slice(&timestamp.recent.to_be_bytes());
        options[10..12].copy_from_slice(&[1, 1]);
        Some(options)
    }

    fn segment_options(&self, key: TcpFlowKey) -> Option<Vec<u8>> {
        let flow = self.by_key.get(&key)?;
        let mut options = self
            .timestamp_options(key)
            .map_or_else(Vec::new, |timestamp| timestamp.to_vec());
        if flow.sack_permitted && !flow.out_of_order.is_empty() {
            let max_blocks = (40_usize.saturating_sub(options.len() + 2) / 8).min(4);
            let blocks = receive_sack_blocks(flow, max_blocks);
            if !blocks.is_empty() {
                options.push(5);
                options.push(u8::try_from(2 + blocks.len() * 8).expect("SACK option fits u8"));
                for (left, right) in blocks {
                    options.extend_from_slice(&left.get().to_be_bytes());
                    options.extend_from_slice(&right.get().to_be_bytes());
                }
            }
        }
        if options.is_empty() {
            return None;
        }
        options.resize(options.len().next_multiple_of(4), 1);
        Some(options)
    }

    fn emit_with_options(
        &mut self,
        key: TcpFlowKey,
        control: SendControl,
        options: &[u8],
    ) -> Result<Vec<u8>, WireError> {
        let identification = self.next_ipv4_id;
        self.next_ipv4_id = self.next_ipv4_id.wrapping_add(1);
        emit_tcp_segment_with_options(
            key.destination,
            key.source,
            control,
            options,
            &[],
            self.config.hop_limit,
            identification,
        )
    }

    /// Whether a SYN on a four-tuple in TIME-WAIT opens a new connection, as
    /// Linux's `tcp_timewait_state_process` has it (RFC 6191): unless its
    /// timestamp is older than the old connection's last (an old duplicate,
    /// PAWS), when its timestamp is newer, or its sequence number is past
    /// what the old connection received. sail closes first toward the app,
    /// so TIME-WAIT is sail's, and the app's kernel, holding none, reuses
    /// the port: refused, its SYNs would retransmit until TIME-WAIT ends.
    fn time_wait_yields_to(
        &self,
        key: TcpFlowKey,
        segment: crate::TcpSegmentMeta,
        options: &TcpOptions,
    ) -> bool {
        if !is_initial_syn(segment) {
            return false;
        }
        let Some(entry) = self.time_wait.get(&key) else {
            return false;
        };
        let (newer, older) = match (entry.peer_timestamp, options.timestamps) {
            (Some(recent), Some((value, _))) => {
                // Serial-number arithmetic, as PAWS compares them.
                #[allow(clippy::cast_possible_wrap)]
                let ahead = value.wrapping_sub(recent) as i32;
                (ahead > 0, ahead < 0)
            }
            _ => (false, false),
        };
        !older && (newer || segment.sequence.after(entry.acknowledgment.acknowledgment))
    }

    /// Ends the TIME-WAIT of `key` for a new connection: its timer is the
    /// one to cancel.
    fn end_time_wait(&mut self, key: TcpFlowKey) -> Option<TcpTimerCancel> {
        let entry = self.time_wait.remove(&key)?;
        self.time_wait_order.remove(&entry.id.get());
        self.by_id.remove(&entry.id);
        increment_counter(&mut self.stats.closed_flows);
        increment_counter(&mut self.stats.time_wait_reuses);
        self.refresh_structural_stats();
        Some(TcpTimerCancel {
            token: TcpFlowToken::new_on_shard(entry.id, self.generation, self.shard),
            event: TimerEvent::TimeWaitExpired,
        })
    }

    fn ingest_time_wait(
        &mut self,
        key: TcpFlowKey,
        segment: crate::TcpSegmentMeta,
    ) -> Result<TcpIngress, TcpTableError> {
        let entry = self.time_wait.get(&key).ok_or(TcpTableError::UnknownFlow)?;
        let id = entry.id;
        let acknowledgment = entry.acknowledgment;
        let mut output = TcpIngress::default();
        let is_reset = segment.flags.contains(TcpFlags::RST);
        if !is_reset {
            output.outgoing.push(self.emit(key, acknowledgment)?);
        }
        let retransmits_final_fin = !is_reset
            && segment.flags.contains(TcpFlags::ACK)
            && segment.flags.contains(TcpFlags::FIN)
            && segment.sequence.wrapping_add(segment.payload_len)
                == SeqNumber::new(acknowledgment.acknowledgment.get().wrapping_sub(1));
        if retransmits_final_fin {
            output.timers.push(TcpTimerRequest {
                token: TcpFlowToken::new_on_shard(id, self.generation, self.shard),
                event: TimerEvent::TimeWaitExpired,
                after_ms: self.config.time_wait_ms,
            });
        }
        Ok(output)
    }

    /// Moves the flow `key`, `id`, into TIME-WAIT's compact entry. Whichever
    /// flow leaves the table here, its owner is told: the evicted oldest
    /// TIME-WAIT, or this one when it cannot wait.
    fn move_to_time_wait(
        &mut self,
        key: TcpFlowKey,
        id: FlowId,
        output: &mut TcpIngress,
    ) -> Result<(), TcpTableError> {
        let (evicted, kept) = self.compact_time_wait(key)?;
        if let Some(cancelled) = evicted {
            output.events.push(TcpEvent::Closed(cancelled.token));
            output.cancelled_timers.push(cancelled);
        }
        if !kept {
            let token = TcpFlowToken::new_on_shard(id, self.generation, self.shard);
            output.timers.retain(|timer| timer.token != token);
            output.events.push(TcpEvent::Closed(token));
        }
        Ok(())
    }

    /// Moves a flow into TIME-WAIT, evicting the oldest entry when the slots
    /// are full. Returns the evicted entry, and whether the flow was kept:
    /// without a slot it is removed outright.
    fn compact_time_wait(
        &mut self,
        key: TcpFlowKey,
    ) -> Result<(Option<TcpTimerCancel>, bool), TcpTableError> {
        let mut cancelled = None;
        let slot_lease = self
            .ledger
            .try_acquire(ResourceKind::TimeWait, 1)
            .ok()
            .or_else(|| {
                cancelled = self.evict_oldest_time_wait();
                cancelled.as_ref()?;
                self.ledger.try_acquire(ResourceKind::TimeWait, 1).ok()
            });
        let Some(slot_lease) = slot_lease else {
            self.remove(key);
            return Ok((cancelled, false));
        };
        let flow = self.by_key.remove(&key).ok_or(TcpTableError::Invariant(
            "TIME-WAIT transition lost its full flow",
        ))?;
        let TcpFlow {
            id,
            tcb,
            stats,
            timestamp,
            _metadata_lease: mut metadata_lease,
            ..
        } = flow;
        self.syn_received_order.remove(&id.get());
        replace_flow_stats(&mut self.stats, stats, FlowStatsContribution::default());
        metadata_lease.shrink_to(TIME_WAIT_METADATA_CHARGE);
        let acknowledgment = SendControl {
            sequence: tcb.send_next(),
            acknowledgment: tcb.recv_next(),
            flags: TcpFlags::ACK,
            window: 0,
        };
        self.time_wait.insert(
            key,
            TimeWaitEntry {
                id,
                acknowledgment,
                peer_timestamp: timestamp.map(|state| state.recent),
                _slot_lease: slot_lease,
                _metadata_lease: metadata_lease,
            },
        );
        self.time_wait_order.insert(id.get(), key);
        Ok((cancelled, true))
    }

    fn evict_oldest_time_wait(&mut self) -> Option<TcpTimerCancel> {
        let (id, key) = self.time_wait_order.pop_first()?;
        let entry = self.time_wait.remove(&key)?;
        debug_assert_eq!(entry.id.get(), id);
        self.by_id.remove(&entry.id);
        self.stats.time_wait_evictions = self.stats.time_wait_evictions.saturating_add(1);
        increment_counter(&mut self.stats.closed_flows);
        Some(TcpTimerCancel {
            token: TcpFlowToken::new_on_shard(entry.id, self.generation, self.shard),
            event: TimerEvent::TimeWaitExpired,
        })
    }

    /// A keyed offset for the timestamp clock of `key`'s four-tuple, as
    /// Linux derives it. It depends on the four-tuple alone, so a new
    /// connection on the same one continues the old one's timestamps, which
    /// the peer's PAWS check and TIME-WAIT reuse rely on (RFC 6191).
    fn timestamp_offset(&self, key: TcpFlowKey) -> u32 {
        let mut hasher = self.hash_state.build_hasher();
        "tcp timestamp offset".hash(&mut hasher);
        key.source.hash(&mut hasher);
        key.destination.hash(&mut hasher);
        let bytes = hasher.finish().to_le_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn initial_sequence(&self, key: TcpFlowKey, id: FlowId) -> SeqNumber {
        let mut hasher = self.hash_state.build_hasher();
        key.hash(&mut hasher);
        id.hash(&mut hasher);
        let bytes = hasher.finish().to_le_bytes();
        let keyed = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let clock_bytes = self.now_ms.saturating_mul(250).to_le_bytes();
        let clock = u32::from_le_bytes([
            clock_bytes[0],
            clock_bytes[1],
            clock_bytes[2],
            clock_bytes[3],
        ]);
        SeqNumber::new(keyed.wrapping_add(clock))
    }

    fn remove(&mut self, key: TcpFlowKey) {
        if let Some(flow) = self.by_key.remove(&key) {
            replace_flow_stats(
                &mut self.stats,
                flow.stats,
                FlowStatsContribution::default(),
            );
            self.syn_received_order.remove(&flow.id.get());
            self.by_id.remove(&flow.id);
            increment_counter(&mut self.stats.closed_flows);
        } else if let Some(entry) = self.time_wait.remove(&key) {
            self.time_wait_order.remove(&entry.id.get());
            self.by_id.remove(&entry.id);
            increment_counter(&mut self.stats.closed_flows);
        }
    }

    fn sync_flow_stats(&mut self, key: TcpFlowKey) {
        let Some(flow) = self.by_key.get_mut(&key) else {
            return;
        };
        let old = flow.stats;
        let new = flow_stats_contribution(flow);
        flow.stats = new;
        replace_flow_stats(&mut self.stats, old, new);
    }

    fn refresh_structural_stats(&mut self) {
        self.stats.active_flows = self.by_key.len() + self.time_wait.len();
        self.stats.time_wait = self.time_wait.len();
        self.stats.peak_active_flows = self.stats.peak_active_flows.max(self.stats.active_flows);
        self.stats.peak_time_wait = self.stats.peak_time_wait.max(self.stats.time_wait);
    }

    fn reset_live_stats(&mut self) {
        self.stats.active_flows = 0;
        self.stats.time_wait = 0;
        self.stats.syn_received = 0;
        self.stats.accept_queue = 0;
        self.stats.buffered_bytes = 0;
        self.stats.send_buffered_bytes = 0;
    }
}

fn flow_stats_contribution(flow: &TcpFlow) -> FlowStatsContribution {
    FlowStatsContribution {
        syn_received: usize::from(flow.syn_lease.is_some()),
        accept_queue: usize::from(flow.accept_lease.is_some()),
        buffered_bytes: flow.tcb.recv_buffered()
            + flow
                .pending_initial_receive
                .as_ref()
                .map_or(0, |chunk| chunk.bytes.len())
            + flow
                .out_of_order
                .iter()
                .map(|chunk| chunk.bytes.len())
                .sum::<usize>(),
        send_buffered_bytes: send_buffered_bytes(flow),
    }
}

/// What a flow holds for its peer: sent and not yet acknowledged, or
/// waiting to be sent.
fn send_buffered_bytes(flow: &TcpFlow) -> usize {
    flow.send
        .iter()
        .map(|chunk| chunk.bytes.len())
        .sum::<usize>()
        + flow
            .pending_send
            .as_ref()
            .map_or(0, |chunk| chunk.bytes.len())
}

fn replace_flow_stats(
    stats: &mut TcpTableStats,
    old: FlowStatsContribution,
    new: FlowStatsContribution,
) {
    stats.syn_received = stats
        .syn_received
        .saturating_sub(old.syn_received)
        .saturating_add(new.syn_received);
    stats.accept_queue = stats
        .accept_queue
        .saturating_sub(old.accept_queue)
        .saturating_add(new.accept_queue);
    stats.peak_syn_received = stats.peak_syn_received.max(stats.syn_received);
    stats.peak_accept_queue = stats.peak_accept_queue.max(stats.accept_queue);
    stats.buffered_bytes = stats
        .buffered_bytes
        .saturating_sub(old.buffered_bytes)
        .saturating_add(new.buffered_bytes);
    stats.send_buffered_bytes = stats
        .send_buffered_bytes
        .saturating_sub(old.send_buffered_bytes)
        .saturating_add(new.send_buffered_bytes);
}

fn release_acknowledged_send(flow: &mut TcpFlow) -> Result<(), TcpTableError> {
    let acknowledged = flow.tcb.send_unacked();
    while let Some(chunk) = flow.send.front_mut() {
        let offset = usize::try_from(acknowledged.distance_from(chunk.sequence))
            .map_err(|_| TcpTableError::Invariant("acknowledged send distance exceeds usize"))?;
        if offset == 0 {
            break;
        }
        if offset >= chunk.bytes.len() {
            flow.send.pop_front();
            continue;
        }
        chunk.bytes = chunk.bytes[offset..].into();
        chunk.sequence = acknowledged;
        chunk.payload_lease.shrink_to(chunk.bytes.len());
        chunk.retransmitted = false;
        break;
    }
    Ok(())
}

fn out_of_order_overlaps(flow: &TcpFlow, start: usize, end: usize) -> bool {
    flow.out_of_order.iter().any(|chunk| {
        let Ok(queued_start) = usize::try_from(chunk.sequence.distance_from(flow.tcb.recv_next()))
        else {
            return true;
        };
        let queued_end = queued_start.saturating_add(chunk.bytes.len());
        start < queued_end && queued_start < end
    })
}

fn validate_segment_timestamp(
    flow: &TcpFlow,
    segment: crate::TcpSegmentMeta,
    options: &TcpOptions,
    now_ms: u64,
) -> TimestampDisposition {
    let Some(timestamp) = flow.timestamp else {
        return TimestampDisposition::Accept;
    };
    if segment.flags.contains(TcpFlags::RST) {
        return TimestampDisposition::Accept;
    }
    let Some((value, _)) = options.timestamps else {
        return TimestampDisposition::DropSilently;
    };
    let recent_is_current =
        now_ms.saturating_sub(timestamp.recent_at_ms) <= PAWS_IDLE_INVALIDATION_MS;
    if recent_is_current && timestamp_before(value, timestamp.recent) {
        return TimestampDisposition::RejectWithAck;
    }
    TimestampDisposition::Accept
}

fn apply_peer_window_scale(flow: &TcpFlow, segment: &mut crate::TcpSegmentMeta) {
    if !segment.flags.contains(TcpFlags::SYN) {
        if let Some(scale) = flow.peer_window_scale {
            segment.window <<= scale;
        }
    }
}

fn update_recent_timestamp(
    flow: &mut TcpFlow,
    segment: crate::TcpSegmentMeta,
    options: TcpOptions,
    old_recv_next: SeqNumber,
    now_ms: u64,
) {
    let sequence_len = segment.payload_len
        + usize::from(segment.flags.contains(TcpFlags::SYN))
        + usize::from(segment.flags.contains(TcpFlags::FIN));
    let covers_previous_receive_edge = sequence_len > 0
        && !segment.sequence.after(old_recv_next)
        && old_recv_next.before(segment.sequence.wrapping_add(sequence_len));
    if !segment.flags.contains(TcpFlags::RST) && covers_previous_receive_edge {
        if let (Some(timestamp), Some((value, _))) = (&mut flow.timestamp, options.timestamps) {
            timestamp.recent = value;
            timestamp.recent_at_ms = now_ms;
        }
    }
}

fn record_ack_progress(
    flow: &mut TcpFlow,
    old_send_unacked: SeqNumber,
    options: TcpOptions,
    now_ms: u64,
) {
    if flow.tcb.send_unacked() == old_send_unacked {
        return;
    }
    flow.retransmission_timeouts = 0;
    if flow
        .rtt_probe
        .is_some_and(|probe| !flow.tcb.send_unacked().before(probe.end_sequence))
    {
        let probe = flow.rtt_probe.take().expect("RTT probe checked above");
        let timestamp_matches = match probe.sent_timestamp {
            Some(sent) => options.timestamps.is_some_and(|(_, echoed)| echoed == sent),
            None => true,
        };
        if timestamp_matches {
            flow.tcb
                .record_rtt_sample(now_ms.saturating_sub(probe.sent_at_ms));
        }
    }
}

fn arm_rtt_probe(flow: &mut TcpFlow, end_sequence: SeqNumber, now_ms: u64) {
    if flow.rtt_probe.is_none() {
        flow.rtt_probe = Some(RttProbe {
            end_sequence,
            sent_at_ms: now_ms,
            sent_timestamp: flow
                .timestamp
                .map(|_| timestamp_value(now_ms, flow.timestamp_offset)),
        });
    }
}

fn is_initial_syn(segment: crate::TcpSegmentMeta) -> bool {
    segment.flags.contains(TcpFlags::SYN)
        && !segment.flags.contains(TcpFlags::ACK)
        && !segment.flags.contains(TcpFlags::RST)
}

fn payload_is_admissible(flow: &TcpFlow, segment: crate::TcpSegmentMeta) -> bool {
    !flow.tcb.peer_receive_closed()
        && flow.tcb.accepts_receive_sequence(segment)
        && segment.flags.contains(TcpFlags::ACK)
        && !segment.flags.contains(TcpFlags::SYN)
        && !segment.flags.contains(TcpFlags::RST)
        && segment
            .acknowledgment
            .is_some_and(|acknowledgment| !acknowledgment.after(flow.tcb.send_next()))
}

fn prepare_receive_admission(
    ledger: &Arc<ResourceLedger>,
    flow: &TcpFlow,
    segment: crate::TcpSegmentMeta,
    payload: &[u8],
    payload_admissible: bool,
    accepting: bool,
) -> Result<ReceiveAdmission, TcpTableError> {
    let final_ack_payload_capacity = if accepting {
        flow.tcb.final_ack_payload_capacity()
    } else {
        None
    };
    let buffering = payload_admissible
        && !payload.is_empty()
        && (segment.sequence == flow.tcb.recv_next() || final_ack_payload_capacity.is_some());
    if payload_admissible
        && final_ack_payload_capacity.is_some_and(|capacity| payload.len() > capacity)
    {
        return Err(TcpError::ReceiveCreditExceeded.into());
    }
    if buffering && payload.len() > flow.tcb.receive_available() {
        return Err(TcpError::ReceiveCreditExceeded.into());
    }
    let chunk = buffering
        .then(|| receive_chunk(ledger, payload))
        .transpose()?;
    let out_of_order = if payload_admissible && !buffering && !accepting {
        admit_out_of_order(ledger, flow, segment.sequence, payload)?
    } else {
        None
    };
    Ok(ReceiveAdmission {
        buffering,
        chunk,
        out_of_order,
        out_of_order_fin: if accepting {
            None
        } else {
            out_of_order_fin(flow, segment, payload_admissible)
        },
    })
}

/// Received bytes held for the application, their metadata reserved.
fn receive_chunk(ledger: &Arc<ResourceLedger>, bytes: &[u8]) -> Result<ReceiveChunk, BudgetError> {
    Ok(ReceiveChunk {
        bytes: bytes.into(),
        offset: 0,
        _metadata_lease: ledger
            .try_acquire(ResourceKind::MetadataBytes, TCP_CHUNK_METADATA_CHARGE)?,
    })
}

/// Admits a segment's data, as [`prepare_receive_admission`]. Short of
/// memory for it, the segment still counts for its ACK, window and SACK:
/// its data and FIN are stripped from both its forms, to come again.
/// Dropped whole, the acknowledgment that would free the send queue's
/// memory would go with it.
fn admit_or_strip(
    ledger: &Arc<ResourceLedger>,
    flow: &TcpFlow,
    (segment, state_segment): (&mut crate::TcpSegmentMeta, &mut crate::TcpSegmentMeta),
    payload: &[u8],
    payload_admissible: bool,
    accepting: bool,
) -> Result<(ReceiveAdmission, bool), TcpTableError> {
    match prepare_receive_admission(
        ledger,
        flow,
        *segment,
        payload,
        payload_admissible,
        accepting,
    ) {
        Ok(admission) => Ok((admission, false)),
        Err(TcpTableError::Budget(_)) if !accepting && carries_data(*segment) => {
            strip_data(segment);
            strip_data(state_segment);
            Ok((ReceiveAdmission::nothing(), true))
        }
        Err(error) => Err(error),
    }
}

/// Answers a segment whose data memory pressure dropped, unless the control
/// block already did: the peer learns at once that it must come again.
fn answer_pressure_drop(
    flow: &mut TcpFlow,
    stats: &mut TcpTableStats,
    actions: &mut Vec<TcpAction>,
) {
    increment_counter(&mut stats.receive_pressure_drops);
    let answered = actions.iter().any(|action| {
        matches!(
            action,
            TcpAction::Send(_) | TcpAction::DefensiveAck(_) | TcpAction::Closed
        )
    });
    if !answered {
        actions.extend(flow.tcb.reject_unacceptable_segment());
    }
}

fn normalize_receive_segment<'a>(
    flow: &TcpFlow,
    segment: &mut crate::TcpSegmentMeta,
    payload: &'a [u8],
    accepting: bool,
) -> (&'a [u8], bool) {
    let admissible = payload_is_admissible(flow, *segment);
    if !admissible || accepting {
        return (payload, admissible);
    }
    let receive_next = flow.tcb.receive_admission_left_edge();
    let payload = trim_received_prefix(receive_next, segment, payload);
    let payload = trim_to_receive_window(flow, receive_next, segment, payload);
    (
        trim_against_out_of_order(flow, receive_next, segment, payload),
        true,
    )
}

fn apply_challenge_ack_limit(
    limiter: &mut ControlRateLimiter,
    stats: &mut TcpTableStats,
    now_ms: u64,
    actions: &mut Vec<TcpAction>,
) {
    if !actions.contains(&TcpAction::ChallengeAck) {
        return;
    }
    if limiter.allow(now_ms) {
        stats.challenge_acks_sent = stats.challenge_acks_sent.saturating_add(1);
    } else {
        actions.retain(|action| *action != TcpAction::ChallengeAck);
        stats.challenge_acks_rate_limited = stats.challenge_acks_rate_limited.saturating_add(1);
    }
}

fn trim_received_prefix<'a>(
    receive_next: SeqNumber,
    segment: &mut crate::TcpSegmentMeta,
    payload: &'a [u8],
) -> &'a [u8] {
    if segment.flags.contains(TcpFlags::SYN) || !receive_next.after(segment.sequence) {
        return payload;
    }
    let Ok(already_received) = usize::try_from(receive_next.distance_from(segment.sequence)) else {
        return payload;
    };
    if already_received > payload.len() {
        return payload;
    }
    segment.sequence = receive_next;
    segment.payload_len = payload.len() - already_received;
    &payload[already_received..]
}

fn trim_to_receive_window<'a>(
    flow: &TcpFlow,
    receive_next: SeqNumber,
    segment: &mut crate::TcpSegmentMeta,
    payload: &'a [u8],
) -> &'a [u8] {
    let Ok(offset) = usize::try_from(segment.sequence.distance_from(receive_next)) else {
        return payload;
    };
    let window = usize::try_from(flow.tcb.advertised_right_edge().distance_from(receive_next))
        .unwrap_or(usize::MAX);
    if offset >= window {
        segment.payload_len = 0;
        segment.flags = TcpFlags::from_bits(segment.flags.bits() & !TcpFlags::FIN.bits());
        return &payload[..0];
    }
    let available = window - offset;
    if segment.flags.contains(TcpFlags::FIN) && payload.len() >= available {
        segment.flags = TcpFlags::from_bits(segment.flags.bits() & !TcpFlags::FIN.bits());
    }
    if payload.len() <= available {
        return payload;
    }
    segment.payload_len = available;
    &payload[..available]
}

fn trim_against_out_of_order<'a>(
    flow: &TcpFlow,
    receive_next: SeqNumber,
    segment: &mut crate::TcpSegmentMeta,
    mut payload: &'a [u8],
) -> &'a [u8] {
    for queued in &flow.out_of_order {
        let (Ok(start), Ok(queued_start)) = (
            usize::try_from(segment.sequence.distance_from(receive_next)),
            usize::try_from(queued.sequence.distance_from(receive_next)),
        ) else {
            return payload;
        };
        let Some(end) = start.checked_add(payload.len()) else {
            return payload;
        };
        let queued_end = queued_start.saturating_add(queued.bytes.len());
        if end <= queued_start {
            return payload;
        }
        if start < queued_start {
            let keep = queued_start - start;
            segment.payload_len = keep;
            if segment.flags.contains(TcpFlags::FIN) {
                segment.flags = TcpFlags::from_bits(segment.flags.bits() & !TcpFlags::FIN.bits());
            }
            return &payload[..keep];
        }
        if start < queued_end {
            let overlap = (queued_end - start).min(payload.len());
            segment.sequence = segment.sequence.wrapping_add(overlap);
            payload = &payload[overlap..];
            segment.payload_len = payload.len();
            if payload.is_empty() {
                return payload;
            }
        }
    }
    payload
}

fn admit_out_of_order(
    ledger: &Arc<ResourceLedger>,
    flow: &TcpFlow,
    sequence: SeqNumber,
    payload: &[u8],
) -> Result<Option<OutOfOrderChunk>, TcpTableError> {
    let Some(start) = sequence
        .after(flow.tcb.recv_next())
        .then(|| usize::try_from(sequence.distance_from(flow.tcb.recv_next())).ok())
        .flatten()
    else {
        return Ok(None);
    };
    let Some(end) = start.checked_add(payload.len()) else {
        return Ok(None);
    };
    let receive_edge = usize::try_from(
        flow.tcb
            .advertised_right_edge()
            .distance_from(flow.tcb.recv_next()),
    )
    .unwrap_or(usize::MAX);
    if payload.is_empty() || end > receive_edge || out_of_order_overlaps(flow, start, end) {
        return Ok(None);
    }
    Ok(Some(OutOfOrderChunk {
        sequence,
        bytes: payload.into(),
        metadata_lease: ledger
            .try_acquire(ResourceKind::MetadataBytes, TCP_CHUNK_METADATA_CHARGE)?,
    }))
}

fn out_of_order_fin(
    flow: &TcpFlow,
    segment: crate::TcpSegmentMeta,
    payload_admissible: bool,
) -> Option<SeqNumber> {
    (payload_admissible
        && !flow.tcb.peer_receive_closed()
        && segment.flags.contains(TcpFlags::FIN)
        && segment.sequence.after(flow.tcb.recv_next()))
    .then(|| segment.sequence.wrapping_add(segment.payload_len))
}

fn queue_out_of_order_and_promote(
    flow: &mut TcpFlow,
    pending: Option<OutOfOrderChunk>,
    pending_fin: Option<SeqNumber>,
    sack_anchor: Option<SeqNumber>,
    delivered_current: bool,
    actions: &mut Vec<TcpAction>,
) -> Result<(), TcpTableError> {
    let sack_anchor = pending
        .as_ref()
        .map_or(sack_anchor, |chunk| Some(chunk.sequence));
    if let Some(chunk) = pending {
        let offset = usize::try_from(chunk.sequence.distance_from(flow.tcb.recv_next()))
            .map_err(|_| TcpTableError::Invariant("out-of-order offset exceeds usize"))?;
        let index = flow.out_of_order.partition_point(|queued| {
            usize::try_from(queued.sequence.distance_from(flow.tcb.recv_next()))
                .is_ok_and(|queued_offset| queued_offset < offset)
        });
        flow.out_of_order.insert(index, chunk);
    }
    if let Some(fin) = pending_fin {
        if flow
            .out_of_order_fin
            .is_none_or(|queued| fin.before(queued))
        {
            flow.out_of_order_fin = Some(fin);
        }
    }
    if let Some(fin) = flow.out_of_order_fin {
        truncate_out_of_order_at_fin(flow, fin);
    }
    if sack_anchor.is_some_and(|anchor| {
        flow.out_of_order.iter().any(|chunk| {
            !anchor.before(chunk.sequence)
                && anchor.before(chunk.sequence.wrapping_add(chunk.bytes.len()))
        })
    }) {
        flow.recent_out_of_order = sack_anchor;
    }
    if actions.contains(&TcpAction::PeerHalfClosed) {
        flow.out_of_order.clear();
        flow.out_of_order_fin = None;
        flow.recent_out_of_order = None;
        return Ok(());
    }
    if !delivered_current {
        return Ok(());
    }
    let mut promoted = false;
    while flow
        .out_of_order
        .first()
        .is_some_and(|chunk| chunk.sequence == flow.tcb.recv_next())
    {
        let chunk = flow.out_of_order.remove(0);
        actions.push(flow.tcb.accept_queued_payload(chunk.bytes.len())?);
        flow.receive.push_back(ReceiveChunk {
            bytes: chunk.bytes,
            offset: 0,
            _metadata_lease: chunk.metadata_lease,
        });
        promoted = true;
    }
    if flow.recent_out_of_order.is_some_and(|recent| {
        !flow.out_of_order.iter().any(|chunk| {
            !recent.before(chunk.sequence)
                && recent.before(chunk.sequence.wrapping_add(chunk.bytes.len()))
        })
    }) {
        flow.recent_out_of_order = None;
    }
    if flow
        .out_of_order_fin
        .is_some_and(|fin| fin.before(flow.tcb.recv_next()))
    {
        flow.out_of_order_fin = None;
    }
    let promoted_fin = flow.out_of_order_fin == Some(flow.tcb.recv_next());
    if promoted_fin {
        flow.out_of_order_fin = None;
        actions.extend(flow.tcb.accept_queued_fin());
    } else if promoted {
        actions.extend(flow.tcb.force_ack());
    }
    Ok(())
}

fn receive_sack_blocks(flow: &TcpFlow, limit: usize) -> Vec<(SeqNumber, SeqNumber)> {
    let recent = flow
        .recent_out_of_order
        .and_then(|anchor| sack_block_containing(&flow.out_of_order, anchor));
    let mut blocks = Vec::with_capacity(limit);
    if let Some(block) = recent {
        blocks.push(block);
    }
    let mut current: Option<(SeqNumber, SeqNumber)> = None;
    for chunk in &flow.out_of_order {
        let right = chunk.sequence.wrapping_add(chunk.bytes.len());
        if let Some((_, current_right)) = current.as_mut() {
            if *current_right == chunk.sequence {
                *current_right = right;
                continue;
            }
        }
        if let Some(block) = current.take() {
            if Some(block) != recent && blocks.len() < limit {
                blocks.push(block);
            }
        }
        current = Some((chunk.sequence, right));
    }
    if let Some(block) = current {
        if Some(block) != recent && blocks.len() < limit {
            blocks.push(block);
        }
    }
    blocks
}

fn sack_block_containing(
    chunks: &[OutOfOrderChunk],
    anchor: SeqNumber,
) -> Option<(SeqNumber, SeqNumber)> {
    let mut current: Option<(SeqNumber, SeqNumber)> = None;
    for chunk in chunks {
        let right = chunk.sequence.wrapping_add(chunk.bytes.len());
        if let Some((left, current_right)) = current.as_mut() {
            if *current_right == chunk.sequence {
                *current_right = right;
                continue;
            }
            if !anchor.before(*left) && anchor.before(*current_right) {
                return current;
            }
        }
        current = Some((chunk.sequence, right));
    }
    current.filter(|(left, right)| !anchor.before(*left) && anchor.before(*right))
}

fn truncate_out_of_order_at_fin(flow: &mut TcpFlow, fin: SeqNumber) {
    flow.out_of_order.retain_mut(|chunk| {
        if !chunk.sequence.before(fin) {
            return false;
        }
        let keep = usize::try_from(fin.distance_from(chunk.sequence)).unwrap_or(usize::MAX);
        if chunk.bytes.len() > keep {
            let mut bytes = std::mem::take(&mut chunk.bytes).into_vec();
            bytes.truncate(keep);
            chunk.bytes = bytes.into_boxed_slice();
        }
        !chunk.bytes.is_empty()
    });
}

fn merge_ingress(target: &mut TcpIngress, mut source: TcpIngress) {
    target.outgoing.append(&mut source.outgoing);
    target.events.append(&mut source.events);
    target.timers.append(&mut source.timers);
    target.cancelled_timers.append(&mut source.cancelled_timers);
}

fn apply_accept_lease(
    flow: &mut TcpFlow,
    accept_lease: Option<BudgetLease>,
    actions: &[TcpAction],
) {
    if actions.contains(&TcpAction::Accepted) {
        flow.syn_lease = None;
        flow.accept_lease = accept_lease;
    }
}

fn promote_initial_receive(
    flow: &mut TcpFlow,
    delivers_initial: bool,
) -> Result<(), TcpTableError> {
    if !delivers_initial {
        return Ok(());
    }
    let chunk = flow
        .pending_initial_receive
        .take()
        .ok_or(TcpTableError::Invariant(
            "initial payload delivery lacked its receive chunk",
        ))?;
    flow.receive.push_back(chunk);
    Ok(())
}

/// The MSS this stack announces for a link: the MTU less the fixed IP and
/// TCP headers, options not counted (RFC 9293 3.7.1, RFC 6691 2).
fn link_mss(ipv4: bool, mtu: usize) -> usize {
    let fixed_headers = if ipv4 {
        IPV4_HEADER_BYTES
    } else {
        IPV6_HEADER_BYTES
    } + TCP_HEADER_BYTES;
    mtu.saturating_sub(fixed_headers).max(1)
}

/// The most payload a segment of a flow carries within `mtu`: the MSS less
/// the options its segments may carry (RFC 6691 2). With SACK that is the
/// whole 40-byte option space (RFC 9293 3.1), as a segment may carry
/// timestamps and three SACK blocks; with timestamps alone, their 10 bytes
/// padded to 12 (RFC 7323 3).
fn segment_ceiling(ipv4: bool, sack_permitted: bool, timestamps: bool, mtu: usize) -> usize {
    link_mss(ipv4, mtu)
        .saturating_sub(option_allowance(sack_permitted, timestamps))
        .max(1)
}

/// The most payload a segment to a peer that announced `peer_mss` carries:
/// its MSS counts no options (RFC 6691 2), so those our segments may carry
/// come off it, as off the link's MSS in [`segment_ceiling`]. A peer
/// announcing 1460 for a 1500-byte link takes 1448 with timestamps, 1420
/// with SACK; 1460 would make packets of up to 1520 bytes.
fn peer_segment_bytes(peer_mss: usize, sack_permitted: bool, timestamps: bool) -> usize {
    peer_mss
        .saturating_sub(option_allowance(sack_permitted, timestamps))
        .max(1)
}

/// The option bytes a flow's segments may carry: with SACK the whole
/// 40-byte option space, timestamps and up to three blocks; with
/// timestamps alone their 10 bytes padded to 12.
const fn option_allowance(sack_permitted: bool, timestamps: bool) -> usize {
    if sack_permitted {
        TCP_MAX_OPTION_BYTES
    } else if timestamps {
        TCP_TIMESTAMP_OPTION_BYTES
    } else {
        0
    }
}

fn lower_flow_mtu(key: TcpFlowKey, flow: &mut TcpFlow, mtu: usize) -> bool {
    let ceiling = segment_ceiling(
        key.source.is_ipv4(),
        flow.sack_permitted,
        flow.timestamp.is_some(),
        mtu,
    );
    if ceiling >= flow.max_send_segment_bytes {
        return false;
    }
    flow.max_send_segment_bytes = ceiling;
    for chunk in &mut flow.send {
        chunk.resegment |= chunk.bytes.len() > ceiling;
    }
    true
}

fn pending_resegment_control(flow: &TcpFlow, old_send_unacked: SeqNumber) -> Option<SendControl> {
    (flow.tcb.send_unacked() != old_send_unacked
        && flow.send.front().is_some_and(|chunk| chunk.resegment))
    .then(|| SendControl {
        sequence: flow.tcb.send_unacked(),
        acknowledgment: flow.tcb.recv_next(),
        flags: TcpFlags::ACK,
        window: flow.tcb.advertised_window(),
    })
}

/// Doubles a flow's receive window, up to `max`, when the application read
/// at least half of it within one round trip: the window, not the reader,
/// may be what holds the peer back. This is the test Linux's receive buffer
/// autotuning makes (`tcp_rcv_space_adjust`), with a window that grows but
/// never shrinks. Each step is reserved first, within the budget's
/// [`tcp_optional_ceiling`](crate::ResourceBudget::tcp_optional_ceiling):
/// when the budget refuses it, the window stays.
fn grow_receive_window(
    ledger: &Arc<ResourceLedger>,
    flow: &mut TcpFlow,
    read: usize,
    now_ms: u64,
    max: Option<usize>,
    growths: &mut u64,
) {
    let Some(max) = max else {
        return;
    };
    flow.read_measure_bytes = flow.read_measure_bytes.saturating_add(read);
    // The table's clock counts milliseconds: a round trip within one is
    // measured over one.
    let round_trip_ms = flow.tcb.smoothed_rtt_ms().unwrap_or(0).max(1);
    if now_ms.saturating_sub(flow.read_measure_start_ms) < round_trip_ms {
        return;
    }
    let capacity = flow.tcb.receive_capacity();
    let ceiling = max.min(flow.tcb.announceable_receive_capacity());
    if flow.read_measure_bytes.saturating_mul(2) >= capacity && capacity < ceiling {
        let additional = capacity.min(ceiling - capacity);
        if let Ok(lease) = ledger.try_acquire_within(
            ResourceKind::TcpPayloadBytes,
            additional,
            ledger.budget().tcp_optional_ceiling(),
        ) {
            flow.receive_growth.push(lease);
            flow.tcb.grow_receive_capacity(additional);
            increment_counter(growths);
            debug_assert_eq!(
                flow.receive_credit_lease.amount()
                    + flow
                        .receive_growth
                        .iter()
                        .map(BudgetLease::amount)
                        .sum::<usize>(),
                flow.tcb.receive_capacity(),
                "receive capacity is reserved in full"
            );
        }
    }
    flow.read_measure_start_ms = now_ms;
    flow.read_measure_bytes = 0;
}

fn flow_became_writable(
    flow: &TcpFlow,
    had_send: bool,
    old_send_unacked: SeqNumber,
    old_send_available: usize,
) -> bool {
    (had_send && flow.tcb.send_unacked() != old_send_unacked)
        || (old_send_available == 0 && flow.tcb.send_available() > 0)
}

fn prepare_sack_split(
    ledger: &Arc<ResourceLedger>,
    flow: &TcpFlow,
    blocks: &[Option<SackBlock>; 4],
) -> Result<Option<SackSplitPlan>, TcpTableError> {
    let send_unacked = flow.tcb.send_unacked();
    let send_next = flow.tcb.send_next();
    let valid = blocks
        .iter()
        .flatten()
        .filter(|block| !block.left.before(send_unacked) && !block.right.after(send_next))
        .copied()
        .collect::<Vec<_>>();
    if valid.is_empty() {
        return Ok(None);
    }
    let mut cuts_by_chunk = Vec::with_capacity(flow.send.len());
    let mut extra_chunks = 0_usize;
    for chunk in &flow.send {
        let chunk_end = chunk.sequence.wrapping_add(chunk.bytes.len());
        let mut cuts = valid
            .iter()
            .flat_map(|block| [block.left, block.right])
            .filter(|point| point.after(chunk.sequence) && point.before(chunk_end))
            .map(|point| usize::try_from(point.distance_from(chunk.sequence)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TcpTableError::Invariant("SACK split offset exceeds usize"))?;
        cuts.sort_unstable();
        cuts.dedup();
        extra_chunks = extra_chunks.saturating_add(cuts.len());
        cuts_by_chunk.push(cuts);
    }
    let metadata = (0..extra_chunks)
        .map(|_| ledger.try_acquire(ResourceKind::MetadataBytes, TCP_CHUNK_METADATA_CHARGE))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(SackSplitPlan {
        valid_blocks: valid,
        cuts_by_chunk,
        metadata,
    }))
}

/// Whether `segment` is acceptable sender feedback, and how its SACK blocks
/// split the send queue. Short of memory for the split, the SACK blocks go
/// unread and the cumulative ACK alone is taken: the ACK is what frees memory.
fn prepare_sender_feedback(
    ledger: &Arc<ResourceLedger>,
    flow: &TcpFlow,
    segment: crate::TcpSegmentMeta,
    blocks: &[Option<SackBlock>; 4],
) -> Result<(bool, Option<SackSplitPlan>), TcpTableError> {
    let admissible = flow.tcb.accepts_sender_feedback(segment);
    let split = if admissible && flow.sack_permitted {
        match prepare_sack_split(ledger, flow, blocks) {
            Err(TcpTableError::Budget(_)) => None,
            split => split?,
        }
    } else {
        None
    };
    Ok((admissible, split))
}

/// The segment the control block sees: the one trimmed to what the table
/// took, but as it came when it is still in the handshake or ahead of
/// RCV.NXT, and when the window had no room for any of its data or FIN,
/// so that the control block takes its ACK and answers it.
fn state_segment(
    flow: &TcpFlow,
    original: crate::TcpSegmentMeta,
    trimmed: crate::TcpSegmentMeta,
    accepting: bool,
) -> crate::TcpSegmentMeta {
    let handshaking = flow.tcb.state() == TcpState::SynReceived;
    if (handshaking && !accepting)
        || (!handshaking && original.sequence.after(flow.tcb.recv_next()))
        || (carries_data(original) && !carries_data(trimmed))
    {
        original
    } else {
        trimmed
    }
}

/// Whether a segment carries data or a FIN.
fn carries_data(segment: crate::TcpSegmentMeta) -> bool {
    segment.payload_len > 0 || segment.flags.contains(TcpFlags::FIN)
}

/// Leaves a segment its ACK and window only: a FIN after data not taken
/// cannot be taken either.
fn strip_data(segment: &mut crate::TcpSegmentMeta) {
    segment.payload_len = 0;
    segment.flags = TcpFlags::from_bits(segment.flags.bits() & !TcpFlags::FIN.bits());
}

fn apply_sack_split(flow: &mut TcpFlow, plan: SackSplitPlan) {
    let SackSplitPlan {
        valid_blocks,
        cuts_by_chunk,
        metadata,
    } = plan;
    let mut metadata = metadata.into_iter();
    let old = std::mem::take(&mut flow.send);
    for (chunk, cuts) in old.into_iter().zip(cuts_by_chunk) {
        split_sack_chunk(flow, chunk, &cuts, &valid_blocks, &mut metadata);
    }
}

fn split_sack_chunk(
    flow: &mut TcpFlow,
    chunk: SendChunk,
    cuts: &[usize],
    blocks: &[SackBlock],
    metadata: &mut impl Iterator<Item = BudgetLease>,
) {
    let SendChunk {
        sequence,
        bytes,
        mut payload_lease,
        sacked,
        retransmitted,
        resegment: _,
        _metadata_lease: first_metadata,
    } = chunk;
    let mut start = 0_usize;
    let mut first_metadata = Some(first_metadata);
    for end in cuts.iter().copied().chain(std::iter::once(bytes.len())) {
        let amount = end - start;
        let tail_lease = payload_lease.split_off(amount);
        let piece_sequence = sequence.wrapping_add(start);
        let piece_end = piece_sequence.wrapping_add(amount);
        let piece_sacked = sacked
            || blocks
                .iter()
                .any(|block| !piece_sequence.before(block.left) && !piece_end.after(block.right));
        flow.send.push_back(SendChunk {
            sequence: piece_sequence,
            bytes: bytes[start..end].into(),
            payload_lease,
            sacked: piece_sacked,
            retransmitted,
            resegment: amount > flow.max_send_segment_bytes,
            _metadata_lease: first_metadata
                .take()
                .unwrap_or_else(|| metadata.next().expect("SACK split metadata preallocated")),
        });
        payload_lease = tail_lease;
        start = end;
    }
}

fn apply_sender_sack(
    flow: &mut TcpFlow,
    split_plan: Option<SackSplitPlan>,
    stats: &mut TcpTableStats,
    actions: &mut Vec<TcpAction>,
) {
    if !flow.sack_permitted {
        return;
    }
    if let Some(plan) = split_plan {
        apply_sack_split(flow, plan);
    }
    if !sack_loss_detected(flow) {
        return;
    }
    let recovery = flow.tcb.on_sack_loss();
    if recovery
        .iter()
        .any(|action| matches!(action, TcpAction::RetransmitPayload(_)))
    {
        flow.sack_recovery = Some(SackRecovery {
            recovery_point: flow.tcb.send_next(),
            rescue_after: flow.tcb.send_unacked(),
        });
        stats.sack_recovery_events = stats.sack_recovery_events.saturating_add(1);
        stats.sack_retransmitted_segments = stats.sack_retransmitted_segments.saturating_add(1);
    }
    actions.extend(recovery);
}

fn update_sender_sack(
    flow: &mut TcpFlow,
    feedback_admissible: bool,
    split_plan: Option<SackSplitPlan>,
    stats: &mut TcpTableStats,
    actions: &mut Vec<TcpAction>,
) {
    let has_valid_sack = split_plan.is_some();
    if feedback_admissible {
        apply_sender_sack(flow, split_plan, stats, actions);
    }
    if feedback_admissible
        && flow.sack_permitted
        && flow.sack_recovery.is_none()
        && has_valid_sack
        && actions
            .iter()
            .any(|action| matches!(action, TcpAction::RetransmitPayload(_)))
    {
        flow.sack_recovery = Some(SackRecovery {
            recovery_point: flow.tcb.send_next(),
            rescue_after: flow.tcb.send_unacked(),
        });
        stats.sack_recovery_events = stats.sack_recovery_events.saturating_add(1);
        stats.sack_retransmitted_segments = stats.sack_retransmitted_segments.saturating_add(1);
    }
    if flow
        .sack_recovery
        .is_some_and(|recovery| !flow.tcb.send_unacked().before(recovery.recovery_point))
    {
        flow.sack_recovery = None;
    }
}

fn sack_loss_detected(flow: &TcpFlow) -> bool {
    let lost = lost_prefix(&flow.send, flow.max_send_segment_bytes);
    flow.send.iter().take(lost).any(|chunk| !chunk.sacked)
}

/// What the SACK scoreboard reads of a chunk sent and not yet acknowledged.
trait Scored {
    fn sacked(&self) -> bool;
    fn retransmitted(&self) -> bool;
    fn len(&self) -> usize;
}

impl Scored for SendChunk {
    fn sacked(&self) -> bool {
        self.sacked
    }
    fn retransmitted(&self) -> bool {
        self.retransmitted
    }
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

/// How many chunks at the front of `chunks` count as lost, as RFC 6675's
/// `IsLost` has it: a chunk is, once three chunks above it, or three
/// segments' bytes of them, are selectively acknowledged. The queue runs in
/// sequence order without gaps, so every chunk after one is above it, and
/// what is acknowledged above a chunk only shrinks along the queue: the
/// lost chunks are a prefix of it, found in one pass from the end.
fn lost_prefix<C: Scored>(chunks: &VecDeque<C>, max_segment: usize) -> usize {
    let three_segments = max_segment.saturating_mul(3);
    let (mut sacked, mut bytes) = (0_usize, 0_usize);
    for (index, chunk) in chunks.iter().enumerate().rev() {
        if sacked >= 3 || bytes >= three_segments {
            return index + 1;
        }
        if chunk.sacked() {
            sacked += 1;
            bytes = bytes.saturating_add(chunk.len());
        }
    }
    0
}

/// RFC 6675's pipe: what is presumed in the network, the chunks neither
/// selectively acknowledged nor lost, and those retransmitted once more.
fn pipe<C: Scored>(chunks: &VecDeque<C>, max_segment: usize) -> usize {
    let lost = lost_prefix(chunks, max_segment);
    chunks
        .iter()
        .enumerate()
        .filter(|(_, chunk)| !chunk.sacked())
        .map(|(index, chunk)| {
            let in_network = if index < lost { 0 } else { chunk.len() };
            in_network
                + if chunk.retransmitted() {
                    chunk.len()
                } else {
                    0
                }
        })
        .sum()
}

/// The SACK scoreboard's reading, for the fuzz target that holds it to RFC
/// 6675's `IsLost` asked chunk by chunk (feature `fuzzing`).
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod sack_fuzzing {
    use std::collections::VecDeque;

    /// A chunk in flight, in a queue without gaps.
    pub struct Chunk {
        pub len: usize,
        pub sacked: bool,
        pub retransmitted: bool,
    }

    impl super::Scored for Chunk {
        fn sacked(&self) -> bool {
            self.sacked
        }
        fn retransmitted(&self) -> bool {
            self.retransmitted
        }
        fn len(&self) -> usize {
            self.len
        }
    }

    /// How many chunks at the front count as lost.
    #[must_use]
    pub fn lost_prefix(chunks: &VecDeque<Chunk>, max_segment: usize) -> usize {
        super::lost_prefix(chunks, max_segment)
    }

    /// RFC 6675's pipe of the queue.
    #[must_use]
    pub fn pipe(chunks: &VecDeque<Chunk>, max_segment: usize) -> usize {
        super::pipe(chunks, max_segment)
    }
}

fn sack_pipe(flow: &TcpFlow) -> usize {
    debug_assert!(
        flow.send
            .iter()
            .zip(flow.send.iter().skip(1))
            .all(|(a, b)| b.sequence == a.sequence.wrapping_add(a.bytes.len())),
        "the send queue runs in sequence order without gaps"
    );
    pipe(&flow.send, flow.max_send_segment_bytes)
}

fn next_sack_segment(flow: &TcpFlow, recovery: SackRecovery) -> Option<(usize, bool)> {
    let highest_sacked = flow
        .send
        .iter()
        .filter(|chunk| chunk.sacked)
        .map(|chunk| chunk.sequence.wrapping_add(chunk.bytes.len()))
        .max_by(|left, right| {
            left.distance_from(flow.tcb.send_unacked())
                .cmp(&right.distance_from(flow.tcb.send_unacked()))
        })?;
    let lost = lost_prefix(&flow.send, flow.max_send_segment_bytes);
    if let Some((index, _)) = flow.send.iter().enumerate().find(|(index, chunk)| {
        !chunk.sacked
            && !chunk.retransmitted
            && chunk.sequence.before(highest_sacked)
            && *index < lost
    }) {
        return Some((index, false));
    }
    if let Some((index, _)) = flow.send.iter().enumerate().find(|(_, chunk)| {
        !chunk.sacked && !chunk.retransmitted && chunk.sequence.before(highest_sacked)
    }) {
        return Some((index, false));
    }
    if !flow.tcb.send_unacked().after(recovery.rescue_after) {
        return None;
    }
    flow.send
        .iter()
        .rposition(|chunk| !chunk.sacked)
        .map(|index| (index, true))
}

fn window_scale_for(receive_credit_bytes: usize) -> u8 {
    let mut scale = 0_u8;
    while scale < 14 && (receive_credit_bytes >> scale) > usize::from(u16::MAX) {
        scale += 1;
    }
    scale
}

fn timestamp_before(value: u32, recent: u32) -> bool {
    i32::from_ne_bytes(value.wrapping_sub(recent).to_ne_bytes()) < 0
}

/// The `TSval` a flow sends at `now_ms`: a millisecond clock, shifted by the
/// flow's offset.
fn timestamp_value(now_ms: u64, offset: u32) -> u32 {
    let bytes = now_ms.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).wrapping_add(offset)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::{BudgetProfile, ResourceLedger, SeqNumber, TcpFlags};

    /// A chunk of a scoreboard under test.
    struct Scoreboard {
        sequence: SeqNumber,
        len: usize,
        sacked: bool,
        retransmitted: bool,
    }

    impl Scored for Scoreboard {
        fn sacked(&self) -> bool {
            self.sacked
        }
        fn retransmitted(&self) -> bool {
            self.retransmitted
        }
        fn len(&self) -> usize {
            self.len
        }
    }

    /// RFC 6675's `IsLost` as sail had it, over the chunks above the one
    /// asked about, each time.
    fn is_lost_each(chunks: &VecDeque<Scoreboard>, lost_index: usize, max_segment: usize) -> bool {
        let lost = &chunks[lost_index];
        let lost_end = lost.sequence.wrapping_add(lost.len);
        let (mut sacked, mut bytes) = (0_usize, 0_usize);
        for chunk in chunks.iter().skip(lost_index + 1) {
            if chunk.sacked && !chunk.sequence.before(lost_end) {
                sacked += 1;
                bytes = bytes.saturating_add(chunk.len);
            }
        }
        sacked >= 3 || bytes >= max_segment.saturating_mul(3)
    }

    /// The pipe as sail had it: `IsLost` asked for each chunk.
    fn pipe_each(chunks: &VecDeque<Scoreboard>, max_segment: usize) -> usize {
        chunks
            .iter()
            .enumerate()
            .filter(|(_, chunk)| !chunk.sacked)
            .map(|(index, chunk)| {
                let in_network = if is_lost_each(chunks, index, max_segment) {
                    0
                } else {
                    chunk.len
                };
                in_network + if chunk.retransmitted { chunk.len } else { 0 }
            })
            .sum()
    }

    /// The scoreboard read in one pass says what it said chunk by chunk:
    /// which chunks are lost, and the pipe, over random scoreboards (sizes,
    /// selectively acknowledged and retransmitted chunks, sequence numbers that wrap).
    #[test]
    fn the_scoreboard_in_one_pass_reads_as_chunk_by_chunk() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |below: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % below
        };
        for _ in 0..5000 {
            let max_segment = [1, 536, 1460][usize::try_from(next(3)).unwrap()];
            let sacked_one_in = next(4) + 1;
            let mut sequence = SeqNumber::new(u32::try_from(next(1 << 32)).unwrap());
            let chunks: VecDeque<Scoreboard> = (0..next(40))
                .map(|_| {
                    let len = usize::try_from(next(3 * max_segment as u64) + 1).unwrap();
                    let chunk = Scoreboard {
                        sequence,
                        len,
                        sacked: next(sacked_one_in) == 0,
                        retransmitted: next(5) == 0,
                    };
                    sequence = sequence.wrapping_add(len);
                    chunk
                })
                .collect();
            let lost = lost_prefix(&chunks, max_segment);
            for index in 0..chunks.len() {
                assert_eq!(
                    index < lost,
                    is_lost_each(&chunks, index, max_segment),
                    "chunk {index}"
                );
            }
            assert_eq!(pipe(&chunks, max_segment), pipe_each(&chunks, max_segment));
        }
    }

    fn segment(
        source: SocketAddr,
        destination: SocketAddr,
        control: SendControl,
        payload: &[u8],
    ) -> Vec<u8> {
        emit_tcp_segment(source, destination, control, payload, 64, 1).unwrap()
    }

    /// A flow in FIN-WAIT-2, the peer having acknowledged our FIN, and its token;
    /// `release_first` lets go of it while in FIN-WAIT-1.
    fn in_fin_wait2(release_first: bool) -> (TcpTable, TcpFlowToken, TcpIngress) {
        let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
        let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
        let peer = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 2), 40_001));
        let local = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 1), 443));
        let control = |sequence: u32, acknowledgment: u32, flags: TcpFlags| SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(acknowledgment),
            flags,
            window: 4_096,
        };
        let syn_ack = table
            .ingest(&segment(peer, local, control(100, 0, TcpFlags::SYN), &[]))
            .unwrap();
        let syn_ack =
            parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        let accepted = table
            .ingest(&segment(
                peer,
                local,
                control(101, server_next, TcpFlags::ACK),
                &[],
            ))
            .unwrap();
        let Some(TcpEvent::Accepted(connection)) = accepted.events.first() else {
            panic!("no connection: {:?}", accepted.events);
        };
        let token = connection.token;
        table.accept(token).unwrap();
        let fin = table.close(token).unwrap();
        assert_eq!(fin.outgoing.len(), 1);
        if release_first {
            let released = table.release(token).unwrap();
            assert!(released.timers.is_empty(), "armed in FIN-WAIT-1");
        }
        let acked = table
            .ingest(&segment(
                peer,
                local,
                control(101, server_next.wrapping_add(1), TcpFlags::ACK),
                &[],
            ))
            .unwrap();
        (table, token, acked)
    }

    fn fin_wait2_timer(output: &TcpIngress) -> Option<&TcpTimerRequest> {
        output
            .timers
            .iter()
            .find(|timer| timer.event == TimerEvent::FinWait2Timeout)
    }

    /// Half-closed and still held, a flow waits in FIN-WAIT-2 as long as
    /// the application does: there is no timer, and a stray one does not
    /// end it.
    #[test]
    fn a_held_half_closed_flow_waits_in_fin_wait2() {
        let (mut table, token, acked) = in_fin_wait2(false);
        assert!(fin_wait2_timer(&acked).is_none());
        let fired = table.on_timer(token, TimerEvent::FinWait2Timeout).unwrap();
        assert!(fired.events.is_empty());
        assert_eq!(table.stats().active_flows, 1);
    }

    /// Let go of, it waits `fin_wait2_timeout_ms` for the peer's FIN, then
    /// leaves the table without a segment, as Linux's orphans do.
    #[test]
    fn a_released_flow_leaves_fin_wait2_after_the_timeout() {
        let (mut table, token, acked) = in_fin_wait2(false);
        assert!(fin_wait2_timer(&acked).is_none());
        let released = table.release(token).unwrap();
        let timer = fin_wait2_timer(&released).expect("no FIN-WAIT-2 timer");
        assert_eq!(timer.after_ms, 60_000);
        // Set once.
        assert!(fin_wait2_timer(&table.release(token).unwrap()).is_none());
        let fired = table.on_timer(token, TimerEvent::FinWait2Timeout).unwrap();
        assert!(fired.outgoing.is_empty());
        assert!(matches!(fired.events[..], [TcpEvent::Closed(closed)] if closed == token));
        assert_eq!(table.stats().active_flows, 0);
        assert_eq!(table.stats().fin_wait2_timeouts, 1);
    }

    /// Let go of in FIN-WAIT-1, the timer is set when the peer's ACK brings
    /// it to FIN-WAIT-2.
    #[test]
    fn a_flow_released_in_fin_wait1_is_timed_from_fin_wait2() {
        let (_table, _token, acked) = in_fin_wait2(true);
        let timer = fin_wait2_timer(&acked).expect("no FIN-WAIT-2 timer");
        assert_eq!(timer.after_ms, 60_000);
    }

    /// A held write that the answer to the last ACK had no room to carry is
    /// released by the persist timer, since nothing else will wake the flow.
    #[test]
    fn a_held_write_without_room_to_go_waits_on_the_persist_timer() {
        let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
        let mut table = TcpTable::new(
            ledger,
            NetworkGeneration::new(1),
            TcpTableConfig {
                max_segment_payload_bytes: 100,
                nagle_enabled: true,
                ..TcpTableConfig::default()
            },
        );
        let peer = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 2), 40_000));
        let local = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 1), 443));
        let control = |sequence: u32, acknowledgment: u32, flags: TcpFlags| SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(acknowledgment),
            flags,
            window: 4_096,
        };
        let syn_ack = table
            .ingest(&segment(peer, local, control(100, 0, TcpFlags::SYN), &[]))
            .unwrap();
        let syn_ack =
            parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
        let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
        let accepted = table
            .ingest(&segment(
                peer,
                local,
                control(101, server_next, TcpFlags::ACK),
                &[],
            ))
            .unwrap();
        let Some(TcpEvent::Accepted(connection)) = accepted.events.first() else {
            panic!("no connection: {:?}", accepted.events);
        };
        let token = connection.token;
        table.accept(token).unwrap();
        assert_eq!(table.write(token, b"first").unwrap().outgoing.len(), 1);
        assert!(table.write(token, b"tiny").unwrap().outgoing.is_empty());

        // Room for one packet, which the answer to the data past a hole takes.
        let last_ack = segment(
            peer,
            local,
            control(111, server_next.wrapping_add(5), TcpFlags::ACK),
            b"after a hole",
        );
        let answered = table
            .ingest_with_policy_at_limit(&last_ack, true, 0, 1)
            .unwrap();
        assert_eq!(answered.outgoing.len(), 1);
        let answer =
            parse_tcp_segment(parse_ip_packet(&answered.outgoing[0], true).unwrap(), true).unwrap();
        assert!(answer.payload.is_empty());
        let persist = answered
            .timers
            .iter()
            .find(|timer| timer.event == TimerEvent::Persist)
            .expect("the held write was left without a timer");

        let released = table
            .on_timer_at(token, TimerEvent::Persist, persist.after_ms)
            .unwrap();
        let released =
            parse_tcp_segment(parse_ip_packet(&released.outgoing[0], true).unwrap(), true).unwrap();
        assert_eq!(released.payload, b"tiny");
        assert_eq!(
            released.meta.sequence,
            SeqNumber::new(server_next.wrapping_add(5))
        );
    }

    /// Opens connections from `peers` on `table` until one is refused,
    /// each peer's window 64 KiB: the tokens of those that opened.
    fn open_until_refused(table: &mut TcpTable, peers: u16) -> Vec<TcpFlowToken> {
        let local = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 1), 443));
        let control = |sequence: u32, acknowledgment: u32, flags: TcpFlags| SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(acknowledgment),
            flags,
            window: u16::MAX,
        };
        let mut tokens = Vec::new();
        for port in 0..peers {
            let peer = SocketAddr::from((Ipv4Addr::new(10, 7, 0, 2), 10_000 + port));
            let Ok(syn_ack) =
                table.ingest(&segment(peer, local, control(100, 0, TcpFlags::SYN), &[]))
            else {
                break;
            };
            let Some(syn_ack) = syn_ack.outgoing.first() else {
                break;
            };
            let syn_ack = parse_tcp_segment(parse_ip_packet(syn_ack, true).unwrap(), true).unwrap();
            if !syn_ack.meta.flags.contains(TcpFlags::SYN) {
                break;
            }
            let server_next = syn_ack.meta.sequence.wrapping_add(1).get();
            let accepted = table
                .ingest(&segment(
                    peer,
                    local,
                    control(101, server_next, TcpFlags::ACK),
                    &[],
                ))
                .unwrap();
            let Some(TcpEvent::Accepted(connection)) = accepted.events.first() else {
                panic!("connection {port}: not accepted: {:?}", accepted.events);
            };
            table.accept(connection.token).unwrap();
            tokens.push(connection.token);
        }
        tokens
    }

    /// The connections' starting windows take no more than the budget's
    /// receive share of the TCP bytes: once new connections are refused,
    /// those open still send (peakpassvpn/sail#6, where they took it all
    /// and no write went out again).
    #[test]
    fn connections_refused_for_the_budget_leave_room_to_send() {
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let mut table = TcpTable::new(
            Arc::clone(&ledger),
            NetworkGeneration::new(1),
            TcpTableConfig::default(),
        );
        let tokens = open_until_refused(&mut table, 2_000);
        let ceiling = ledger.budget().tcp_receive_ceiling();
        assert_eq!(
            tokens.len(),
            ceiling / TcpTableConfig::default().receive_credit_bytes
        );
        for token in &tokens {
            let sent = table.write(*token, &[7; 500]).unwrap();
            assert_eq!(sent.outgoing.len(), 1);
        }
    }

    /// A write takes no more than the flow's send buffer leaves room for,
    /// whatever the peer's window.
    #[test]
    fn the_send_buffer_bounds_what_a_flow_holds_for_its_peer() {
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let mut table = TcpTable::new(
            ledger,
            NetworkGeneration::new(1),
            TcpTableConfig {
                max_send_buffer_bytes: Some(4_096),
                ..TcpTableConfig::default()
            },
        );
        let token = open_until_refused(&mut table, 1)[0];
        assert_eq!(table.write_capacity(token).unwrap(), 4_096);
        // Segments of the 536 bytes a peer without the MSS option takes.
        table.write(token, &[7; 512]).unwrap();
        assert_eq!(table.write_capacity(token).unwrap(), 3_584);
        for _ in 0..7 {
            table.write(token, &[7; 512]).unwrap();
        }
        assert_eq!(table.write_capacity(token).unwrap(), 0);
    }
}
