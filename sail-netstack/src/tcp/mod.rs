//! Deterministic TCP protocol core. Allocation, I/O, and wakeups live outside
//! this module and are represented as explicit actions.

mod congestion;
mod rto;
mod state;
mod table;
mod wire;

pub use congestion::NewReno;
pub use rto::RtoEstimator;
pub use state::{
    AppEvent, SendControl, SeqNumber, TcpAction, TcpError, TcpFlags, TcpSegmentMeta, TcpState,
    TcpTcb, TimerEvent,
};
#[cfg(feature = "fuzzing")]
pub use table::sack_fuzzing;
pub use table::TcpFlowSample;
pub use table::{
    AcceptOverflowPolicy, TcpConnection, TcpEvent, TcpIngress, TcpRead, TcpTable, TcpTableConfig,
    TcpTableError, TcpTableStats, TcpTimerCancel, TcpTimerRequest,
};
pub use wire::{
    emit_tcp_control, emit_tcp_segment, emit_tcp_segment_with_options, parse_tcp_segment,
    ParsedTcpSegment, SackBlock, TcpOptions,
};
