//! Owned, host-private context. Never projected into records' JSON or C ABI.
use std::any::Any;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A host's frozen binding, shared by a session, its target attempts and
/// their record envelopes. Cloning retains the same binding slot.
/// The payload must not hold a session, instance or record back-reference.
#[derive(Clone)]
pub struct RecordContext(Arc<Binding>);

struct Binding {
    value: Box<dyn Any + Send + Sync>,
    _slot: Slot,
    // The exact authenticated row is retained even when the host copies
    // an inner business Arc into the session payload.
    _credential: Option<RecordContext>,
}

impl RecordContext {
    /// Reads the payload by its original type. Treat it as immutable;
    /// synchronize any interior mutability in the host itself.
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.0.value.downcast_ref()
    }
}

impl std::fmt::Debug for RecordContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordContext(..)")
    }
}

/// Equality and hashing compare binding identity, never payload contents.
impl PartialEq for RecordContext {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for RecordContext {}
impl std::hash::Hash for RecordContext {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&Arc::as_ptr(&self.0), state);
    }
}

pub(crate) struct ContextPool {
    capacity: usize,
    live: AtomicUsize,
}

struct Slot(Arc<ContextPool>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ContextPool {
    pub(crate) fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            live: AtomicUsize::new(0),
        })
    }

    /// Reserve before invoking host code; a panic releases the slot too.
    pub(crate) fn bind<T: Send + Sync + 'static>(
        self: &Arc<Self>,
        build: impl FnOnce() -> T,
    ) -> Option<RecordContext> {
        self.bind_with_credential(None, build)
    }

    pub(crate) fn bind_with_credential<T: Send + Sync + 'static>(
        self: &Arc<Self>,
        credential: Option<RecordContext>,
        build: impl FnOnce() -> T,
    ) -> Option<RecordContext> {
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                if live < self.capacity {
                    Some(live + 1)
                } else {
                    None
                }
            })
            .ok()?;
        let slot = Slot(self.clone());
        Some(RecordContext(Arc::new(Binding {
            value: Box::new(build()),
            _slot: slot,
            _credential: credential,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindings_hold_one_slot_through_clones_and_release_on_last_drop() {
        let pool = ContextPool::new(1);
        let drops = Arc::new(AtomicUsize::new(0));
        struct Value(Arc<AtomicUsize>);
        impl Drop for Value {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let context = pool.bind(|| Value(drops.clone())).unwrap();
        let copy = context.clone();
        assert!(pool.bind(|| ()).is_none());
        drop(context);
        assert!(pool.bind(|| ()).is_none());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(copy);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(pool.bind(|| ()).is_some());
        assert_eq!(pool.live.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_panicking_builder_releases_its_reserved_slot() {
        let pool = ContextPool::new(1);
        let result = std::panic::catch_unwind(|| pool.bind(|| panic!("binding panic")));
        assert!(result.is_err());
        assert!(pool.bind(|| 42_u64).is_some());
        assert_eq!(pool.live.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn a_session_binding_keeps_the_authenticated_row_slot_until_its_last_owner() {
        let rows = ContextPool::new(1);
        let sessions = ContextPool::new(1);
        let row = rows.bind(|| 7_u64).unwrap();
        let binding = sessions
            .bind_with_credential(Some(row.clone()), || ())
            .unwrap();
        drop(row);
        assert!(rows.bind(|| 99_u64).is_none());
        let pending = binding.clone();
        drop(binding);
        assert!(rows.bind(|| 99_u64).is_none());
        drop(pending);
        assert!(rows.bind(|| 99_u64).is_some());
        assert!(sessions.bind(|| ()).is_some());
    }
}
