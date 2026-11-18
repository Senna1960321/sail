//! Counters of the sessions of every protocol on the core, for all
//! instances of the process: how many are open, their streams, and the
//! streams reset for stalling.

use portable_atomic::AtomicU64;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use serde_derive::Serialize;

/// One protocol's counters.
#[derive(Default)]
pub struct Counters {
    sessions: AtomicU64,
    streams: AtomicU64,
    stalls: AtomicU64,
    refused: AtomicU64,
    sessions_created: AtomicU64,
    streams_opened: AtomicU64,
    streams_reused: AtomicU64,
    padding_received: AtomicU64,
}

impl Counters {
    pub(super) fn session_opened(&self) {
        self.sessions.fetch_add(1, Ordering::Relaxed);
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn session_closed(&self) {
        self.sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn stream_opened(&self, reused: bool) {
        self.streams.fetch_add(1, Ordering::Relaxed);
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
        if reused {
            self.streams_reused.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn stream_closed(&self) {
        self.streams.fetch_sub(1, Ordering::Relaxed);
    }

    pub(super) fn stalled(&self) {
        self.stalls.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(any(feature = "inbound-anytls", feature = "outbound-anytls", test))]
    pub(crate) fn padding_received(&self, bytes: usize) {
        self.padding_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            sessions: self.sessions.load(Ordering::Relaxed),
            streams: self.streams.load(Ordering::Relaxed),
            stalls: self.stalls.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            sessions_created: self.sessions_created.load(Ordering::Relaxed),
            streams_opened: self.streams_opened.load(Ordering::Relaxed),
            streams_reused: self.streams_reused.load(Ordering::Relaxed),
            padding_received_bytes: self.padding_received.load(Ordering::Relaxed),
        }
    }
}

/// One protocol's counters as they stand.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    /// Sessions open.
    pub sessions: u64,
    /// Streams open, across those sessions.
    pub streams: u64,
    /// Streams reset since start because nothing read their data.
    pub stalls: u64,
    /// Streams the peer opened and this end turned away, since start.
    pub refused: u64,
    /// Multiplex sessions started since process start, client and server,
    /// whether or not the protocol authenticates them.
    pub sessions_created: u64,
    /// Streams opened or accepted since process start, including the first.
    pub streams_opened: u64,
    /// Streams after the first on each session, since process start.
    pub streams_reused: u64,
    /// Received padding, including waste frame headers and authentication
    /// padding, excluding TLS records and ordinary protocol framing.
    pub padding_received_bytes: u64,
}

static COUNTERS: Mutex<BTreeMap<&'static str, Arc<Counters>>> = Mutex::new(BTreeMap::new());

/// The counters of `protocol`.
pub(crate) fn counters(protocol: &'static str) -> Arc<Counters> {
    let mut all = COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    all.entry(protocol).or_default().clone()
}

/// Every protocol's counters, by name, for those that have had a session.
pub fn snapshot() -> BTreeMap<&'static str, Snapshot> {
    let all = COUNTERS.lock().unwrap_or_else(|e| e.into_inner());
    all.iter().map(|(name, c)| (*name, c.snapshot())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_counters_survive_stream_and_session_close() {
        let counters = Counters::default();
        counters.session_opened();
        counters.stream_opened(false);
        counters.stream_closed();
        counters.stream_opened(true);
        counters.padding_received(17);
        counters.stream_closed();
        counters.session_closed();
        let sample = counters.snapshot();
        assert_eq!(sample.sessions, 0);
        assert_eq!(sample.streams, 0);
        assert_eq!(sample.sessions_created, 1);
        assert_eq!(sample.streams_opened, 2);
        assert_eq!(sample.streams_reused, 1);
        assert_eq!(sample.padding_received_bytes, 17);
    }
}
