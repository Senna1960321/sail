//! What all of a process's growable transfer buffers may grow by,
//! together: Hysteria2's and TUIC's windows and the send buffers of the
//! TCP connections inbounds accept. Sail/1's streams that nothing reads
//! are charged their windows here too while they are kept, parked rather
//! than reset (`transport::muxcore`).
//!
//! quinn (sail's fork) grows a stream's receive window while it is read
//! about as fast as data arrives, the connection's with it, and the send
//! window with the congestion window; an accepted connection's send buffer
//! grows while it, not the network, is what holds the client's transfer
//! back (`net::send_buffer`). Every growth past the starting sizes is asked
//! of the [`TransferBudget`] first. One budget for the process lets one
//! transfer take a large share while many share it, and bounds what they
//! can hold at once: a far server's download needs the windows and not the
//! LAN send buffer, a near one's the send buffer and not the windows
//! (sail#9, sail#10).
//!
//! The budget follows the memory too: once a second at most, when a
//! buffer asks to grow, it reads what is free (and, where it has a bound,
//! what the process holds), and lets buffers grow by no more than leaves
//! `memory.free_memory_floor` free. A cgroup's use counts its sockets'
//! memory, so what send buffers took leaves the windows less, and the
//! reverse. It is read when asked, not on a timer: the limit only matters
//! to a growth, and an idle process never wakes for it.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use portable_atomic::{AtomicU64, Ordering};

use crate::runtime::options::Memory;
use crate::runtime::system_memory;

/// How often the memory is read, at most.
const READ_EVERY: Duration = Duration::from_secs(1);

/// The process's transfer budget.
#[derive(Debug, Default)]
pub struct TransferBudget {
    limit: AtomicU64,
    held: AtomicU64,
    peak: AtomicU64,
    refused: AtomicU64,
    memory: OnceLock<MemoryRead>,
}

/// What the budget reads the memory with, and what it read last.
#[derive(Debug)]
struct MemoryRead {
    free: system_memory::Free,
    floor: u64,
    anon_max: u64,
    start: Instant,
    /// When to read again, in milliseconds from `start`.
    next: AtomicU64,
    /// What buffers may hold, all together, for the memory read last.
    limit: AtomicU64,
    refused: AtomicU64,
}

impl MemoryRead {
    /// What buffers may hold for the memory, read again if it was read
    /// more than a second ago, given that they hold `held` now.
    fn limit(&self, held: u64) -> u64 {
        let now = self.start.elapsed().as_millis() as u64;
        let next = self.next.load(Ordering::Relaxed);
        if now >= next
            && self
                .next
                .compare_exchange(
                    next,
                    now + READ_EVERY.as_millis() as u64,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            let free = (self.floor > 0).then(|| self.free.bytes()).flatten();
            let anon = (self.anon_max > 0)
                .then(system_memory::process_anon)
                .flatten();
            let room = room(free, self.floor, anon, self.anon_max);
            self.limit.store(
                room.map_or(u64::MAX, |room| held.saturating_add(room)),
                Ordering::Relaxed,
            );
        }
        self.limit.load(Ordering::Relaxed)
    }
}

impl TransferBudget {
    /// What buffers hold past their starting sizes now, in bytes.
    pub fn held(&self) -> u64 {
        self.held.load(Ordering::Relaxed)
    }

    /// The most they have held.
    pub fn peak(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }

    /// Growths refused for want of budget.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Of those, the ones refused for want of memory.
    pub fn refused_for_memory(&self) -> u64 {
        self.memory
            .get()
            .map_or(0, |memory| memory.refused.load(Ordering::Relaxed))
    }

    /// Takes `bytes` more for a buffer's growth, if the budget and the
    /// memory have them; a growth refused leaves the buffer as it is.
    pub fn try_grow(&self, bytes: u64) -> bool {
        let limit = self.limit.load(Ordering::Relaxed);
        let for_memory = self
            .memory
            .get()
            .map_or(u64::MAX, |memory| memory.limit(self.held()));
        let grown = self
            .held
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                held.checked_add(bytes)
                    .filter(|&held| held <= limit.min(for_memory))
            });
        match grown {
            Ok(held) => {
                self.peak.fetch_max(held + bytes, Ordering::Relaxed);
                true
            }
            Err(held) => {
                self.refused.fetch_add(1, Ordering::Relaxed);
                if let Some(memory) = self.memory.get() {
                    if held + bytes <= limit {
                        memory.refused.fetch_add(1, Ordering::Relaxed);
                    }
                }
                false
            }
        }
    }

    /// Gives back what a buffer grew by.
    pub fn release(&self, bytes: u64) {
        let _ = self
            .held
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                Some(held.saturating_sub(bytes))
            });
    }
}

impl TransferBudget {
    /// A budget of `limit` bytes, of no memory's: a test's own.
    #[cfg(test)]
    pub(crate) fn limited(limit: u64) -> Self {
        Self {
            limit: AtomicU64::new(limit),
            ..Default::default()
        }
    }
}

/// The process's budget: unbounded until an instance [`configure`]s it.
pub fn global() -> &'static TransferBudget {
    static BUDGET: OnceLock<TransferBudget> = OnceLock::new();
    BUDGET.get_or_init(|| TransferBudget {
        limit: AtomicU64::new(u64::MAX),
        ..Default::default()
    })
}

/// The process's budget at `options.transfer_budget` from now on: what
/// buffers already hold stays theirs, and new growth is judged against
/// it. It also leaves `free_memory_floor` of memory free and keeps the
/// process's anonymous memory under `anon_memory_max` (zero for neither),
/// as the first call has them. The process's, as the budget is: the last
/// instance to start sets it.
pub fn configure(options: &Memory) {
    let budget = global();
    budget
        .limit
        .store(options.transfer_budget as u64 * 1024, Ordering::Relaxed);
    let floor = options.free_memory_floor as u64 * 1024;
    let anon_max = options.anon_memory_max as u64 * 1024;
    if floor > 0 || anon_max > 0 {
        budget
            .memory
            .get_or_init(|| MemoryRead::new(system_memory::Free::new(), floor, anon_max));
    }
}

/// What buffers may grow by for the memory: what is `free` beyond the
/// `floor`, and what the process's `anon` memory is short of `anon_max`;
/// none when neither is known.
fn room(free: Option<u64>, floor: u64, anon: Option<u64>, anon_max: u64) -> Option<u64> {
    let free = free.map(|free| free.saturating_sub(floor));
    let anon = anon.map(|anon| anon_max.saturating_sub(anon));
    free.into_iter().chain(anon).min()
}

impl MemoryRead {
    fn new(free: system_memory::Free, floor: u64, anon_max: u64) -> Self {
        Self {
            free,
            floor,
            anon_max,
            start: Instant::now(),
            next: AtomicU64::new(0),
            limit: AtomicU64::new(u64::MAX),
            refused: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_is_refused_past_the_limit_and_released() {
        let budget = TransferBudget::default();
        budget.limit.store(100, Ordering::Relaxed);
        assert!(budget.try_grow(60));
        assert!(!budget.try_grow(41));
        assert!(budget.try_grow(40));
        assert_eq!(
            (budget.held(), budget.peak(), budget.refused()),
            (100, 100, 1)
        );
        budget.release(70);
        assert!(budget.try_grow(41));
        assert_eq!((budget.held(), budget.peak()), (71, 100));
    }

    #[test]
    fn the_room_is_the_least_of_the_free_memory_s_and_the_process_s() {
        assert_eq!(room(Some(100), 30, None, 0), Some(70));
        assert_eq!(room(Some(20), 30, None, 0), Some(0));
        assert_eq!(room(None, 0, Some(35), 40), Some(5));
        assert_eq!(room(Some(100), 30, Some(45), 40), Some(0));
        assert_eq!(room(None, 30, None, 40), None);
    }

    /// Below the floor, buffers that grew keep what they have, and no
    /// more growth is given until a read finds the memory again.
    #[test]
    fn below_the_floor_buffers_stop_growing() {
        let budget = TransferBudget::default();
        budget.limit.store(1000, Ordering::Relaxed);
        assert!(budget.try_grow(100));
        let memory = budget.memory.get_or_init(|| {
            let mut memory = MemoryRead::new(system_memory::Free::default(), 0, 0);
            // As read: the floor reached, with 100 held.
            memory.next = AtomicU64::new(u64::MAX);
            memory.limit = AtomicU64::new(100);
            memory
        });
        assert!(!budget.try_grow(1));
        assert_eq!(
            (budget.held(), budget.refused(), budget.refused_for_memory()),
            (100, 1, 1)
        );
        // What the budget alone refuses is not the memory's.
        memory.limit.store(u64::MAX, Ordering::Relaxed);
        assert!(!budget.try_grow(901));
        assert_eq!((budget.refused(), budget.refused_for_memory()), (2, 1));
        assert!(budget.try_grow(900));
    }
}
