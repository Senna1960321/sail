//! What each live flow holds toward its peer, read for a host's
//! diagnostics: nothing here runs on a packet's path.

use super::{send_buffered_bytes, TcpTable};

/// One live flow's sending state, as a diagnostics read finds it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpFlowSample {
    /// The flow's id, unique within its shard and generation.
    pub id: u64,
    /// The oldest byte the peer has not acknowledged. Successive samples
    /// of a flow tell the bytes acknowledged between them, modulo 2^32.
    pub send_unacked: u32,
    /// Sent and not yet acknowledged.
    pub in_flight: usize,
    /// Held for the peer: in flight, or waiting to be sent.
    pub send_buffered: usize,
    /// The peer's receive window, in bytes.
    pub peer_window: usize,
    pub congestion_window: usize,
    /// None until a round trip was measured.
    pub smoothed_rtt_ms: Option<u64>,
    pub rto_ms: u64,
}

impl TcpTable {
    /// A sample of every live flow, TIME-WAIT left out.
    #[must_use]
    pub fn flow_samples(&self) -> Vec<TcpFlowSample> {
        self.by_key
            .values()
            .map(|flow| TcpFlowSample {
                id: flow.id.get(),
                send_unacked: flow.tcb.send_unacked().get(),
                in_flight: usize::try_from(
                    flow.tcb.send_next().distance_from(flow.tcb.send_unacked()),
                )
                .unwrap_or(usize::MAX),
                send_buffered: send_buffered_bytes(flow),
                peer_window: flow.tcb.peer_window(),
                congestion_window: flow.tcb.congestion_window(),
                smoothed_rtt_ms: flow.tcb.smoothed_rtt_ms(),
                rto_ms: flow.tcb.rto_ms(),
            })
            .collect()
    }
}
