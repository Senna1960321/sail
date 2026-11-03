//! A user's rate, one way, by GCRA: the time the next byte is due, in one
//! atomic, which each connection of the user moves on by what it sent.
//! Equivalent to a token bucket as deep as `BURST` at the rate, without a
//! task to refill it.

use portable_atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How far ahead of the rate a user may go: a token bucket this deep.
/// Measured (in memory, 1-256 connections, 10-1000 Mbps): the first
/// second goes over by it, 1.05, 1.10 and 1.25 times the rate for 50, 100
/// and 250 ms, and every second after is within 1% of the rate for each.
pub(crate) const BURST: Duration = Duration::from_millis(100);

/// The most a rate-limited stream reads or writes at once: this much of
/// the rate, between `CHUNK_MIN` and `CHUNK_MAX`. Each connection may go a
/// chunk over before it waits, so the first second goes over by the
/// connections times this, whatever the rate: measured 1.36 times the rate
/// with 256 connections and a 100 ms burst, where 4 KiB chunks went to
/// 1.94 and 16 KiB to 4.4 at 10 Mbps. A user reads at most about a
/// thousand times a second.
const CHUNK_TIME: Duration = Duration::from_millis(1);
const CHUNK_MIN: usize = 1 << 10;
const CHUNK_MAX: usize = 64 << 10;

/// The chunk at `bps`.
pub(crate) fn chunk(bps: u64) -> usize {
    let bytes = u128::from(bps) * CHUNK_TIME.as_nanos() / 1_000_000_000;
    (bytes.min(CHUNK_MAX as u128) as usize).clamp(CHUNK_MIN, CHUNK_MAX)
}

fn now() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// How long `n` bytes take at `bps` bytes a second, in nanoseconds.
fn cost(n: u64, bps: u64) -> u64 {
    (u128::from(n) * 1_000_000_000 / u128::from(bps.max(1))) as u64
}

#[derive(Debug, Default)]
pub(crate) struct Gcra {
    /// When the next byte is due, in nanoseconds since the first use.
    due: AtomicU64,
}

impl Gcra {
    /// Counts `n` bytes gone at `bps`: how long the next must wait, if the
    /// user is more than `BURST` ahead. Shaping, as TCP is.
    pub(crate) fn take(&self, n: u64, bps: u64) -> Option<Duration> {
        self.take_within(n, bps, BURST)
    }

    /// `take`, `burst` ahead at most.
    pub(crate) fn take_within(&self, n: u64, bps: u64, burst: Duration) -> Option<Duration> {
        self.take_at(n, bps, burst, now())
    }

    /// `take_within` at `now`, in nanoseconds since the first use.
    fn take_at(&self, n: u64, bps: u64, burst: Duration, now: u64) -> Option<Duration> {
        let cost = cost(n, bps);
        let mut due = self.due.load(Ordering::Relaxed);
        loop {
            let next = due.max(now) + cost;
            match self
                .due
                .compare_exchange_weak(due, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => {
                    let ahead = next - now;
                    let burst = burst.as_nanos() as u64;
                    return (ahead > burst).then(|| Duration::from_nanos(ahead - burst));
                }
                Err(actual) => due = actual,
            }
        }
    }

    /// Takes back `n` bytes counted at `bps` that did not go after all:
    /// another rate refused them.
    pub(crate) fn refund(&self, n: u64, bps: u64) {
        let cost = cost(n, bps);
        let _ = self
            .due
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |due| {
                Some(due.saturating_sub(cost))
            });
    }

    /// Whether `n` bytes may go now at `bps`, counting them if so; those
    /// that may not are dropped, not counted. Policing, as UDP is.
    pub(crate) fn admit(&self, n: u64, bps: u64) -> bool {
        self.admit_within(n, bps, BURST)
    }

    /// `admit`, `burst` ahead at most.
    pub(crate) fn admit_within(&self, n: u64, bps: u64, burst: Duration) -> bool {
        self.admit_at(n, bps, burst, now())
    }

    /// `admit_within` at `now`, in nanoseconds since the first use.
    fn admit_at(&self, n: u64, bps: u64, burst: Duration, now: u64) -> bool {
        let cost = cost(n, bps);
        let burst = burst.as_nanos() as u64;
        let mut due = self.due.load(Ordering::Relaxed);
        loop {
            let next = due.max(now) + cost;
            if next - now > burst + cost.min(burst) {
                return false;
            }
            match self
                .due
                .compare_exchange_weak(due, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => due = actual,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn a_burst_goes_at_once_and_then_the_rate() {
        let rate = Gcra::default();
        let bps = 1_000_000;
        let take = |n, at| rate.take_at(n, bps, BURST, at);
        // 100 ms at 1 MB/s: 100 kB go without waiting.
        assert_eq!(take(50_000, 0), None);
        assert_eq!(take(50_000, 0), None);
        assert_eq!(take(10_000, 0), Some(Duration::from_millis(10)));
        // Waited out, the next goes; what was not used is not kept.
        assert_eq!(take(10_000, 10 * MS), Some(Duration::from_millis(10)));
        assert_eq!(take(1_000, 1_000 * MS), None);
        assert_eq!(take(100_000, 1_000 * MS), Some(Duration::from_millis(1)));
    }

    #[test]
    fn a_chunk_is_a_millisecond_of_the_rate() {
        assert_eq!(chunk(125_000), 1 << 10);
        assert_eq!(chunk(12_500_000), 12_500);
        assert_eq!(chunk(125_000_000), 64 << 10);
    }

    #[test]
    fn datagrams_over_the_burst_are_dropped() {
        let rate = Gcra::default();
        let bps = 1_000_000;
        let admit = |at| rate.admit_at(1000, bps, BURST, at);
        // At once: the burst of 100 kB and the one it overlaps; the rest are
        // dropped, and not counted.
        let admitted = (0..300).filter(|_| admit(0)).count();
        assert_eq!(admitted, 101);
        // Each millisecond after lets one more through.
        assert!(!admit(0));
        assert!(admit(MS));
        assert!(!admit(MS));
    }
}
