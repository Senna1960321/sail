//! The transport child of the internal diagnostics (sail#69): what holds a
//! TUN's throughput, read about once a second by a host.
//!
//! The netstack's counters and its busiest TCP flow are read through the
//! stack's command channel, as its stats are: nothing is added to a
//! packet's path there. The packet bridge and the relays count with
//! relaxed atomics, and read a clock only when a queue is full or a relay
//! waits. Counters only grow, saturating; a field whose name ends in
//! `_now` is the value at the read.

#[cfg(feature = "inbound-tun")]
use std::collections::HashMap;
#[cfg(feature = "inbound-tun")]
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Duration;

use portable_atomic::{AtomicU64, Ordering::Relaxed};
use serde_derive::Serialize;

use crate::RuntimeManager;

const SCHEMA_VERSION: u32 = 1;

fn add(counter: &AtomicU64, n: u64) {
    // Saturating: a counter that reached the top stays there.
    let _ = counter.fetch_update(Relaxed, Relaxed, |v| Some(v.saturating_add(n)));
}

fn nanos(waited: Duration) -> u64 {
    u64::try_from(waited.as_nanos()).unwrap_or(u64::MAX)
}

/// The time relays waited, summed over every relay of the process: on
/// their writer (data the writer does not take) and on their reader
/// (nothing to read). Uplink is the client's side to the outbound,
/// downlink the outbound's to the client. An idle connection's wait on its
/// reader counts too, so read waits grow with the connections open.
#[derive(Default)]
struct RelayCounters {
    uplink_write_waits: AtomicU64,
    uplink_write_wait_ns: AtomicU64,
    uplink_read_waits: AtomicU64,
    uplink_read_wait_ns: AtomicU64,
    downlink_write_waits: AtomicU64,
    downlink_write_wait_ns: AtomicU64,
    downlink_read_waits: AtomicU64,
    downlink_read_wait_ns: AtomicU64,
}

static RELAY: RelayCounters = RelayCounters {
    uplink_write_waits: AtomicU64::new(0),
    uplink_write_wait_ns: AtomicU64::new(0),
    uplink_read_waits: AtomicU64::new(0),
    uplink_read_wait_ns: AtomicU64::new(0),
    downlink_write_waits: AtomicU64::new(0),
    downlink_write_wait_ns: AtomicU64::new(0),
    downlink_read_waits: AtomicU64::new(0),
    downlink_read_wait_ns: AtomicU64::new(0),
};

/// A relay direction waited `waited`, on its writer or its reader.
pub(crate) fn relay_waited(downlink: bool, writer: bool, waited: Duration) {
    let (count, ns) = match (downlink, writer) {
        (false, true) => (&RELAY.uplink_write_waits, &RELAY.uplink_write_wait_ns),
        (false, false) => (&RELAY.uplink_read_waits, &RELAY.uplink_read_wait_ns),
        (true, true) => (&RELAY.downlink_write_waits, &RELAY.downlink_write_wait_ns),
        (true, false) => (&RELAY.downlink_read_waits, &RELAY.downlink_read_wait_ns),
    };
    add(count, 1);
    add(ns, nanos(waited));
}

#[cfg(feature = "inbound-tun")]
/// One packet bridge's counts (`TunPacketFlow`): uplink is the host's
/// packets into sail, downlink sail's out to the host.
#[derive(Default)]
pub(crate) struct BridgeCounters {
    capacity: u64,
    uplink_sent: AtomicU64,
    uplink_received: AtomicU64,
    uplink_send_waits: AtomicU64,
    uplink_send_wait_ns: AtomicU64,
    downlink_sent: AtomicU64,
    downlink_received: AtomicU64,
    downlink_reserve_waits: AtomicU64,
    downlink_reserve_wait_ns: AtomicU64,
}

#[cfg(feature = "inbound-tun")]
impl std::fmt::Debug for BridgeCounters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeCounters")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "inbound-tun")]
impl BridgeCounters {
    /// The host's send was taken into the uplink queue.
    pub(crate) fn uplink_sent(&self) {
        add(&self.uplink_sent, 1);
    }
    /// The stack took a packet off the uplink queue.
    pub(crate) fn uplink_received(&self) {
        add(&self.uplink_received, 1);
    }
    /// The host's send found the uplink queue full and waited `waited`.
    pub(crate) fn uplink_send_waited(&self, waited: Duration) {
        add(&self.uplink_send_waits, 1);
        add(&self.uplink_send_wait_ns, nanos(waited));
    }
    /// The stack put a packet on the downlink queue.
    pub(crate) fn downlink_sent(&self) {
        add(&self.downlink_sent, 1);
    }
    /// The host took a packet off the downlink queue.
    pub(crate) fn downlink_received(&self) {
        add(&self.downlink_received, 1);
    }
    /// The stack found the downlink queue full and waited `waited`.
    pub(crate) fn downlink_reserve_waited(&self, waited: Duration) {
        add(&self.downlink_reserve_waits, 1);
        add(&self.downlink_reserve_wait_ns, nanos(waited));
    }

    pub(crate) fn snapshot(&self) -> BridgeDiagnostics {
        let uplink_sent = self.uplink_sent.load(Relaxed);
        let uplink_received = self.uplink_received.load(Relaxed);
        let downlink_sent = self.downlink_sent.load(Relaxed);
        let downlink_received = self.downlink_received.load(Relaxed);
        BridgeDiagnostics {
            capacity: self.capacity,
            uplink_sent,
            uplink_received,
            uplink_depth_now: uplink_sent.saturating_sub(uplink_received),
            uplink_send_waits: self.uplink_send_waits.load(Relaxed),
            uplink_send_wait_ns: self.uplink_send_wait_ns.load(Relaxed),
            downlink_sent,
            downlink_received,
            downlink_depth_now: downlink_sent.saturating_sub(downlink_received),
            downlink_reserve_waits: self.downlink_reserve_waits.load(Relaxed),
            downlink_reserve_wait_ns: self.downlink_reserve_wait_ns.load(Relaxed),
        }
    }
}

#[cfg(feature = "inbound-tun")]
/// The newest packet bridge of the process: what a read reports.
static BRIDGE: Mutex<Weak<BridgeCounters>> = Mutex::new(Weak::new());

#[cfg(feature = "inbound-tun")]
/// Counters for a new packet bridge of `capacity` packets each way, the
/// one reads report from now on.
pub(crate) fn register_bridge(capacity: usize) -> Arc<BridgeCounters> {
    let counters = Arc::new(BridgeCounters {
        capacity: u64::try_from(capacity).unwrap_or(u64::MAX),
        ..BridgeCounters::default()
    });
    *BRIDGE.lock().unwrap_or_else(|e| e.into_inner()) = Arc::downgrade(&counters);
    counters
}

#[cfg(feature = "inbound-tun")]
/// What was read of each flow last time, to tell the bytes each flow had
/// acknowledged since.
struct Tracked {
    send_unacked: u32,
    acked_bytes: u64,
}

#[cfg(feature = "inbound-tun")]
#[derive(Default)]
struct FlowTracker {
    generation: u64,
    flows: HashMap<(usize, u64), Tracked>,
}

#[cfg(feature = "inbound-tun")]
static FLOWS: LazyLock<Mutex<FlowTracker>> = LazyLock::new(Default::default);

#[cfg(feature = "inbound-tun")]
impl FlowTracker {
    /// The flow that had the most bytes acknowledged since the last read
    /// (on the first, or a tie, the one holding most for its peer), and
    /// forgets the flows gone. A new network generation starts afresh:
    /// flow ids are unique only within one.
    fn busiest(
        &mut self,
        generation: u64,
        shards: &[Vec<sail_netstack::tcp::TcpFlowSample>],
    ) -> Option<FlowDiagnostics> {
        if generation != self.generation {
            self.generation = generation;
            self.flows.clear();
        }
        let mut seen = HashMap::with_capacity(self.flows.len());
        let mut busiest: Option<(u64, FlowDiagnostics)> = None;
        for (shard, samples) in shards.iter().enumerate() {
            for sample in samples {
                let key = (shard, sample.id);
                let (since, acked_bytes) = match self.flows.remove(&key) {
                    Some(old) => {
                        let since = u64::from(sample.send_unacked.wrapping_sub(old.send_unacked));
                        (since, old.acked_bytes.saturating_add(since))
                    }
                    None => (0, 0),
                };
                seen.insert(
                    key,
                    Tracked {
                        send_unacked: sample.send_unacked,
                        acked_bytes,
                    },
                );
                let flow = FlowDiagnostics {
                    shard,
                    id: sample.id,
                    acked_bytes,
                    acked_bytes_since_last: since,
                    in_flight_now: sample.in_flight,
                    send_buffered_now: sample.send_buffered,
                    peer_window_now: sample.peer_window,
                    congestion_window_now: sample.congestion_window,
                    smoothed_rtt_ms_now: sample.smoothed_rtt_ms,
                    rto_ms_now: sample.rto_ms,
                };
                let better = busiest.as_ref().is_none_or(|(best, current)| {
                    (since, flow.send_buffered_now) > (*best, current.send_buffered_now)
                });
                if better {
                    busiest = Some((since, flow));
                }
            }
        }
        self.flows = seen;
        busiest.map(|(_, flow)| flow)
    }
}

/// `InternalDiagnostics` with its `transport` child: the same JSON, one
/// field more.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct InternalTransportDiagnostics {
    #[serde(flatten)]
    pub base: crate::app::sessions::diagnostics::InternalDiagnostics,
    pub transport: TransportDiagnostics,
}

/// The transport child of `InternalDiagnostics`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TransportDiagnostics {
    pub schema_version: u32,
    /// The running TUN's stack: null without one, or when it did not
    /// answer.
    pub netstack: Option<NetstackDiagnostics>,
    /// The newest packet bridge (`TunPacketFlow`): null without one.
    pub bridge: Option<BridgeDiagnostics>,
    pub relay: RelayDiagnostics,
}

/// The stack's counters, summed over its shards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct NetstackDiagnostics {
    pub shards: usize,
    pub generation: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_batches: u64,
    pub rx_io_wakeups: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_batches: u64,
    pub tx_io_wakeups: u64,
    pub dropped_packets: u64,
    pub dropped_resource_packets: u64,
    pub dropped_output_packets: u64,
    pub partial_sends: u64,
    pub scheduler_rounds: u64,
    pub scheduler_time_budget_exhaustions: u64,
    pub pressure_constrained_entries: u64,
    pub pressure_critical_entries: u64,
    pub pressure_exhausted_entries: u64,
    pub pressure_rejected_new_flows: u64,
    pub tcp_created_flows: u64,
    pub tcp_closed_flows: u64,
    pub tcp_zero_window_writes: u64,
    pub tcp_persist_probes: u64,
    pub tcp_retransmission_timeouts: u64,
    pub tcp_sack_recovery_events: u64,
    pub tcp_sack_retransmitted_segments: u64,
    pub tcp_receive_pressure_drops: u64,
    pub budget_denied: u64,
    pub tcp_active_flows_now: usize,
    pub tcp_buffered_bytes_now: usize,
    pub tcp_send_buffered_bytes_now: usize,
    pub scheduler_queued_packets_now: usize,
    pub budget_total_bytes_now: usize,
    pub budget_tcp_payload_bytes_now: usize,
    pub budget_packet_bytes_now: usize,
    pub budget_metadata_bytes_now: usize,
    /// "normal", "constrained", "critical" or "exhausted".
    pub pressure_now: &'static str,
    /// The flow that had the most bytes acknowledged since the last read.
    pub busiest_flow: Option<FlowDiagnostics>,
}

/// One TCP flow of the stack toward its client. `shard` and `id` stay the
/// same while it lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FlowDiagnostics {
    pub shard: usize,
    pub id: u64,
    /// Acknowledged by the client since the flow was first read.
    pub acked_bytes: u64,
    pub acked_bytes_since_last: u64,
    pub in_flight_now: usize,
    pub send_buffered_now: usize,
    pub peer_window_now: usize,
    pub congestion_window_now: usize,
    /// Millisecond resolution: a round trip within a millisecond reads 0;
    /// null until one was measured.
    pub smoothed_rtt_ms_now: Option<u64>,
    pub rto_ms_now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BridgeDiagnostics {
    pub capacity: u64,
    pub uplink_sent: u64,
    pub uplink_received: u64,
    pub uplink_depth_now: u64,
    pub uplink_send_waits: u64,
    pub uplink_send_wait_ns: u64,
    pub downlink_sent: u64,
    pub downlink_received: u64,
    pub downlink_depth_now: u64,
    pub downlink_reserve_waits: u64,
    pub downlink_reserve_wait_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RelayDiagnostics {
    pub uplink_write_waits: u64,
    pub uplink_write_wait_ns: u64,
    pub uplink_read_waits: u64,
    pub uplink_read_wait_ns: u64,
    pub downlink_write_waits: u64,
    pub downlink_write_wait_ns: u64,
    pub downlink_read_waits: u64,
    pub downlink_read_wait_ns: u64,
}

fn relay_snapshot() -> RelayDiagnostics {
    RelayDiagnostics {
        uplink_write_waits: RELAY.uplink_write_waits.load(Relaxed),
        uplink_write_wait_ns: RELAY.uplink_write_wait_ns.load(Relaxed),
        uplink_read_waits: RELAY.uplink_read_waits.load(Relaxed),
        uplink_read_wait_ns: RELAY.uplink_read_wait_ns.load(Relaxed),
        downlink_write_waits: RELAY.downlink_write_waits.load(Relaxed),
        downlink_write_wait_ns: RELAY.downlink_write_wait_ns.load(Relaxed),
        downlink_read_waits: RELAY.downlink_read_waits.load(Relaxed),
        downlink_read_wait_ns: RELAY.downlink_read_wait_ns.load(Relaxed),
    }
}

#[cfg(feature = "inbound-tun")]
fn pressure_name(level: sail_netstack::PressureLevel) -> &'static str {
    match level {
        sail_netstack::PressureLevel::Normal => "normal",
        sail_netstack::PressureLevel::Constrained => "constrained",
        sail_netstack::PressureLevel::Critical => "critical",
        sail_netstack::PressureLevel::Exhausted => "exhausted",
    }
}

#[cfg(feature = "inbound-tun")]
fn netstack(
    stats: &sail_netstack::StackStats,
    shards: usize,
    busiest_flow: Option<FlowDiagnostics>,
) -> NetstackDiagnostics {
    use sail_netstack::ResourceKind;
    let resources = &stats.resources;
    NetstackDiagnostics {
        shards,
        generation: stats.generation.get(),
        rx_packets: stats.rx_packets,
        rx_bytes: stats.rx_bytes,
        rx_batches: stats.rx_batches,
        rx_io_wakeups: stats.rx_io_wakeups,
        tx_packets: stats.tx_packets,
        tx_bytes: stats.tx_bytes,
        tx_batches: stats.tx_batches,
        tx_io_wakeups: stats.tx_io_wakeups,
        dropped_packets: stats.dropped_packets,
        dropped_resource_packets: stats.dropped_resource_packets,
        dropped_output_packets: stats.dropped_output_packets,
        partial_sends: stats.partial_sends,
        scheduler_rounds: stats.scheduler_rounds,
        scheduler_time_budget_exhaustions: stats.scheduler_time_budget_exhaustions,
        pressure_constrained_entries: stats.pressure_constrained_entries,
        pressure_critical_entries: stats.pressure_critical_entries,
        pressure_exhausted_entries: stats.pressure_exhausted_entries,
        pressure_rejected_new_flows: stats.pressure_rejected_new_flows,
        tcp_created_flows: stats.tcp_created_flows,
        tcp_closed_flows: stats.tcp_closed_flows,
        tcp_zero_window_writes: stats.tcp_zero_window_writes,
        tcp_persist_probes: stats.tcp_persist_probes,
        tcp_retransmission_timeouts: stats.tcp_retransmission_timeouts,
        tcp_sack_recovery_events: stats.tcp_sack_recovery_events,
        tcp_sack_retransmitted_segments: stats.tcp_sack_retransmitted_segments,
        tcp_receive_pressure_drops: stats.tcp_receive_pressure_drops,
        budget_denied: resources.denied,
        tcp_active_flows_now: stats.tcp_active_flows,
        tcp_buffered_bytes_now: stats.tcp_buffered_bytes,
        tcp_send_buffered_bytes_now: stats.tcp_send_buffered_bytes,
        scheduler_queued_packets_now: stats.scheduler_queued_packets,
        budget_total_bytes_now: resources.total_bytes,
        budget_tcp_payload_bytes_now: resources.used(ResourceKind::TcpPayloadBytes),
        budget_packet_bytes_now: resources.used(ResourceKind::PacketBytes),
        budget_metadata_bytes_now: resources.used(ResourceKind::MetadataBytes),
        pressure_now: pressure_name(resources.pressure),
        busiest_flow,
    }
}

#[cfg(feature = "inbound-tun")]
/// The running TUN's stack, null without one or when it does not answer.
async fn read_netstack(manager: &RuntimeManager) -> Option<NetstackDiagnostics> {
    let mut control = manager.current_tun_control()?;
    let stats = control.stats_snapshot().await.ok()?;
    let samples = control.flow_samples().await.ok()?;
    let busiest = FLOWS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .busiest(stats.stack.generation.get(), &samples);
    Some(netstack(&stats.stack, stats.shard_count, busiest))
}

/// A read of the transport, as `Instance::internal_diagnostics_with_transport`
/// returns it.
#[cfg_attr(not(feature = "inbound-tun"), allow(clippy::unused_async))]
pub(crate) async fn read(manager: &RuntimeManager) -> TransportDiagnostics {
    #[cfg(feature = "inbound-tun")]
    let (netstack, bridge) = (
        read_netstack(manager).await,
        BRIDGE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .upgrade()
            .map(|counters| counters.snapshot()),
    );
    #[cfg(not(feature = "inbound-tun"))]
    let (netstack, bridge) = {
        let _ = manager;
        (None, None)
    };
    TransportDiagnostics {
        schema_version: SCHEMA_VERSION,
        netstack,
        bridge,
        relay: relay_snapshot(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "inbound-tun")]
    use sail_netstack::tcp::TcpFlowSample;

    #[cfg(feature = "inbound-tun")]
    fn sample(id: u64, send_unacked: u32, send_buffered: usize) -> TcpFlowSample {
        TcpFlowSample {
            id,
            send_unacked,
            in_flight: 0,
            send_buffered,
            peer_window: 65_535,
            congestion_window: 14_600,
            smoothed_rtt_ms: Some(3),
            rto_ms: 200,
        }
    }

    /// The busiest flow is the one that moved most since the last read,
    /// with its bytes counted across reads and the sequence's wrap; a flow
    /// gone is forgotten, and a new generation starts afresh.
    #[cfg(feature = "inbound-tun")]
    #[test]
    fn the_busiest_flow_is_the_one_that_moved_most_since_the_last_read() {
        let mut tracker = FlowTracker::default();
        // First read: nothing moved yet; the one holding most stands out.
        let first = tracker
            .busiest(1, &[vec![sample(1, 1_000, 10), sample(2, 5_000, 900)]])
            .unwrap();
        assert_eq!((first.id, first.acked_bytes_since_last), (2, 0));

        // Flow 2 is gone: forgotten.
        let second = tracker
            .busiest(1, &[vec![sample(1, 1_000, 10)], vec![]])
            .unwrap();
        assert_eq!(second.id, 1);
        assert!(!tracker.flows.contains_key(&(0, 2)));
        // Flow 1 moves on, then 70 000 bytes past the wrap of its
        // sequence; flow 2, back as a new flow, moves 100 and holds more:
        // flow 1 is the busiest.
        let start = u32::MAX - 9_999;
        let _ = tracker.busiest(1, &[vec![sample(1, start, 10), sample(2, 5_100, 900)]]);
        let fourth = tracker
            .busiest(
                1,
                &[vec![
                    sample(1, start.wrapping_add(70_000), 10),
                    sample(2, 5_200, 900),
                ]],
            )
            .unwrap();
        assert_eq!(fourth.id, 1);
        assert_eq!(fourth.acked_bytes_since_last, 70_000);
        assert_eq!(
            fourth.acked_bytes,
            u64::from(start.wrapping_sub(1_000)) + 70_000
        );

        // Shard and id together name a flow: the same id on another shard
        // is another flow, read for the first time.
        let other = tracker
            .busiest(1, &[vec![], vec![sample(1, 9, 1)]])
            .unwrap();
        assert_eq!((other.shard, other.acked_bytes), (1, 0));
        assert!(!tracker.flows.contains_key(&(0, 1)));

        // A network reset: ids start over, so does the count.
        let reset = tracker
            .busiest(2, &[vec![], vec![sample(1, 50, 1)]])
            .unwrap();
        assert_eq!(reset.acked_bytes, 0);
    }

    #[cfg(feature = "inbound-tun")]
    #[test]
    fn bridge_depths_are_what_was_queued_and_not_taken() {
        let counters = register_bridge(64);
        counters.uplink_sent();
        counters.uplink_sent();
        counters.uplink_received();
        counters.downlink_sent();
        counters.uplink_send_waited(Duration::from_micros(5));
        let read = counters.snapshot();
        assert_eq!(read.capacity, 64);
        assert_eq!((read.uplink_depth_now, read.downlink_depth_now), (1, 1));
        assert_eq!(
            (read.uplink_send_waits, read.uplink_send_wait_ns),
            (1, 5_000)
        );
    }

    /// A downlink whose client reads late waits on its writer, and the
    /// uplink, with nothing to send meanwhile, on its reader: both counted
    /// for as long as they waited.
    #[tokio::test]
    async fn a_relay_counts_its_waits_on_its_writer_and_its_reader() {
        use crate::net::relay::{copy_buf_bidirectional_with_timeout, RelayTimeouts};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const LATE: Duration = Duration::from_millis(100);
        let before = relay_snapshot();
        let (mut client, mut a) = tokio::io::duplex(1024);
        let (mut b, mut server) = tokio::io::duplex(64 * 1024);
        let timeouts = RelayTimeouts {
            write_stall: Duration::from_secs(10),
            a_to_b_idle: Duration::from_secs(10),
            b_to_a_idle: Duration::from_secs(10),
        };
        let relay = copy_buf_bidirectional_with_timeout(&mut a, &mut b, 1024, 1024, timeouts);
        let peers = async move {
            // More than the client's pipe holds, read only after LATE.
            server.write_all(&[7; 16 * 1024]).await.unwrap();
            tokio::time::sleep(LATE).await;
            let mut got = vec![0; 16 * 1024];
            client.read_exact(&mut got).await.unwrap();
            drop(client);
            drop(server);
        };
        let (relayed, ()) = tokio::join!(relay, peers);
        relayed.unwrap();
        let after = relay_snapshot();
        let late = nanos(LATE) / 2;
        assert!(after.downlink_write_waits > before.downlink_write_waits);
        assert!(after.downlink_write_wait_ns - before.downlink_write_wait_ns >= late);
        assert!(after.uplink_read_waits > before.uplink_read_waits);
        assert!(after.uplink_read_wait_ns - before.uplink_read_wait_ns >= late);
    }

    #[test]
    fn counters_saturate() {
        let counter = AtomicU64::new(u64::MAX - 1);
        add(&counter, 5);
        assert_eq!(counter.load(Relaxed), u64::MAX);
    }
}
