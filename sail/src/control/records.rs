//! Connection records that are never lost, for a host that bills by them
//! (`embed::Options::connection_records_lossless`, sail#14 and sail#24).
//!
//! `Kinds::CONNECTION` is a broadcast: a subscriber that falls behind is
//! told `lagged`, and the records it missed are gone, so that no connection
//! waits for it. This sink loses no connection's end instead: its records
//! queue for one reader, and every closed record is kept, however far
//! behind the reader is. What bounds them is admission: while `cap`
//! closed records wait for the reader, a new connection is refused, and
//! counted so, until it catches up. Interim records carry a connection's
//! bytes since it started, so the next holds all one held: those of a
//! timed pass are dropped, and counted, while `cap` records wait; those of
//! a pass the host asks for are kept, as a barrier it asked for.
//!
//! Adding a record is a push under a short lock, made where records are
//! made, as a connection closes and in interim passes: the data path never
//! waits for the reader. The queue belongs to the instance, not a run: the
//! records of the connections a stop cut wait for the reader. What is not
//! read when the process ends, a crash, is lost with it.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::events::{ConnectionRecord, RecordKind};

/// A lossless sink of connection records, the instance's.
pub struct LosslessRecords {
    cap: usize,
    queue: Mutex<Queue>,
    /// Closed records queued: read without the lock, as each new
    /// connection asks whether it is refused.
    closed: AtomicUsize,
    notify: tokio::sync::Notify,
    /// A reader holds it.
    taken: AtomicBool,
}

#[derive(Default)]
struct Queue {
    records: VecDeque<Arc<ConnectionRecord>>,
    /// Interim records dropped since the sink was made.
    dropped: u64,
    /// Connections refused since the sink was made.
    refused: u64,
}

impl LosslessRecords {
    /// A sink that keeps `cap` closed records (one at least) before it
    /// refuses new connections.
    pub fn new(cap: usize) -> Arc<Self> {
        Arc::new(LosslessRecords {
            cap: cap.max(1),
            queue: Mutex::default(),
            closed: AtomicUsize::new(0),
            notify: tokio::sync::Notify::new(),
            taken: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Takes `record`: queued, unless it is `droppable` and `cap` records
    /// wait; a closed record always is. Never waits for the reader.
    pub(crate) fn push(&self, record: Arc<ConnectionRecord>, droppable: bool) {
        let closed = matches!(record.kind, RecordKind::Closed(_));
        {
            let mut queue = self.lock();
            if !closed && droppable && queue.records.len() >= self.cap {
                queue.dropped += 1;
                return;
            }
            queue.records.push_back(record);
            if closed {
                self.closed.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.notify.notify_one();
    }

    /// Whether a new connection is refused: `cap` closed records wait for
    /// the reader. Counted when it is.
    pub(crate) fn refuse(&self) -> bool {
        if self.closed.load(Ordering::Relaxed) < self.cap {
            return false;
        }
        let refused = {
            let mut queue = self.lock();
            queue.refused += 1;
            queue.refused
        };
        if refused == 1 || refused.is_power_of_two() {
            tracing::warn!(
                "connection records: {} closed records wait for the host: new connections refused ({} so far)",
                self.cap, refused
            );
        }
        true
    }

    /// The next record; none now.
    fn take(&self) -> Option<Arc<ConnectionRecord>> {
        let record = self.lock().records.pop_front()?;
        if matches!(record.kind, RecordKind::Closed(_)) {
            self.closed.fetch_sub(1, Ordering::Relaxed);
        }
        Some(record)
    }

    /// The reader, unless one holds it already.
    pub fn reader(self: &Arc<Self>) -> Option<RecordStream> {
        (!self.taken.swap(true, Ordering::AcqRel)).then(|| RecordStream(self.clone()))
    }
}

/// The reader of a lossless sink: one at a time; dropped, another may be
/// taken, and nothing is lost in between.
pub struct RecordStream(Arc<LosslessRecords>);

impl RecordStream {
    /// The next record, waiting for one.
    pub async fn next(&mut self) -> Arc<ConnectionRecord> {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(record) = self.0.take() {
                return record;
            }
            notified.await;
        }
    }

    /// The next record if there is one now: to drain what is left, as
    /// after a stop.
    pub fn try_next(&mut self) -> Option<Arc<ConnectionRecord>> {
        self.0.take()
    }

    /// Records queued now.
    pub fn queued(&self) -> usize {
        self.0.lock().records.len()
    }

    /// Interim records dropped since the sink was made, the queue full:
    /// each connection's next record holds what they did.
    pub fn dropped(&self) -> u64 {
        self.0.lock().dropped
    }

    /// Connections refused since the sink was made, its closed records
    /// at the cap.
    pub fn refused(&self) -> u64 {
        self.0.lock().refused
    }
}

impl Drop for RecordStream {
    fn drop(&mut self) {
        self.0.taken.store(false, Ordering::Release);
    }
}

impl std::fmt::Debug for RecordStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordStream")
    }
}

#[cfg(test)]
mod tests;
