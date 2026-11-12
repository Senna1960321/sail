//! Observation-only counters for an explicitly enabled diagnostic build.

use portable_atomic::{AtomicU64, Ordering};
use serde_derive::Serialize;

/// Independent atomic reads, not a transactional accounting identity.
/// None means the existing pool is absent or the metric is not observed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AdmissionDiagnostics {
    pub limit: usize,
    pub live: Option<usize>,
    /// The core's waiting-budget counter, including its baseline's bugs.
    pub waiting: Option<usize>,
    pub waiting_limit: Option<usize>,
    /// Permit grants, not completed connections or datagrams.
    pub admitted_total: Option<u64>,
    /// Refusal decisions, independent of the resettable warning window.
    pub refused_total: Option<u64>,
    /// Only the admission wait's own Tokio timeout; a subset of refusals.
    pub wait_timeout_total: Option<u64>,
    /// A polled queued future dropped before a terminal outcome. This
    /// includes outer timeout/shutdown/select cancellation, not user intent.
    pub wait_cancelled_total: Option<u64>,
    /// Caller intent is not observable at this layer.
    pub active_cancel_total: Option<u64>,
}

/// The currently running instance's dispatcher incarnation only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct InternalDiagnostics {
    pub schema_version: u32,
    pub instance_id: crate::RuntimeId,
    pub epoch: u64,
    pub sessions: AdmissionDiagnostics,
    /// Not inferred from application connections or accepted totals.
    pub dot_live_carriers: Option<usize>,
    pub dot_active_queries: Option<usize>,
}

pub(crate) fn next_epoch() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[derive(Default)]
pub(super) struct Counters {
    admitted: AtomicU64,
    refused: AtomicU64,
    timeout: AtomicU64,
    cancelled: AtomicU64,
}

impl Counters {
    pub(super) fn admitted(&self) {
        self.admitted.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn timed_out(&self) {
        self.timeout.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn snapshot(
        &self,
        limit: usize,
        live: usize,
        waiting: usize,
        waiting_limit: usize,
    ) -> AdmissionDiagnostics {
        AdmissionDiagnostics {
            limit,
            live: Some(live),
            waiting: Some(waiting),
            waiting_limit: Some(waiting_limit),
            admitted_total: Some(self.admitted.load(Ordering::Relaxed)),
            refused_total: Some(self.refused.load(Ordering::Relaxed)),
            wait_timeout_total: Some(self.timeout.load(Ordering::Relaxed)),
            wait_cancelled_total: Some(self.cancelled.load(Ordering::Relaxed)),
            active_cancel_total: None,
        }
    }
}

/// Records abandonment only. In particular this does not repair or
/// decrement the core waiting counter on baselines where it leaks.
pub(super) struct WaitObservation<'a> {
    counters: &'a Counters,
    terminal: bool,
}

impl<'a> WaitObservation<'a> {
    pub(super) fn new(counters: &'a Counters) -> Self {
        Self {
            counters,
            terminal: false,
        }
    }

    pub(super) fn finish(&mut self) {
        self.terminal = true;
    }
}

impl Drop for WaitObservation<'_> {
    fn drop(&mut self) {
        if !self.terminal {
            self.counters.cancelled.fetch_add(1, Ordering::Relaxed);
        }
    }
}
