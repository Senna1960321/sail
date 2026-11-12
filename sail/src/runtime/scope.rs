//! An instance's tasks, as a scope: every task sail spawns for it is
//! registered here, so that a stop ends them all within a bound and says
//! what it could not end, and a panic in one is caught and dealt with by
//! the task's class (docs/embed.md, Panics):
//!
//! - `spawn`, contained: work bound to one connection, stream, session,
//!   request or probe. A panic there ends that task alone; it is logged,
//!   counted and told (`Fault`), and the instance goes on.
//! - `spawn_essential`: what the instance cannot do its job without, and
//!   whose loss would degrade it silently. A panic there fails its scope.
//!   The instance monitors its root scope; dynamic TUN attachments have
//!   an isolated failure domain drained independently.
//!
//! In doubt, essential: a stopped instance is visible, a silently dead
//! updater is not.
// The one place sail spawns on tokio directly: the scope itself.
#![allow(clippy::disallowed_methods)]

use portable_atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures::FutureExt;
use tokio::task::{AbortHandle, JoinHandle};

/// Shards of the registry: spawns from many threads take different locks.
const SHARDS: usize = 16;

/// What the scope adds to a task's future, at most: the task-local's key
/// and slot, the scope, the registration, the class and the name, and the
/// combinators' states. The sum of these fields is about 70 bytes; the
/// bound leaves room for padding.
pub const TASK_OVERHEAD: usize = 128;

/// How long a stop waits for the instance's tasks to end, unless the host
/// says. Measured against: an instance holding 550 connections stops in
/// 12–23 ms at the median and 133 ms at the most (design-notes, E2).
pub const STOP_WITHIN: Duration = Duration::from_secs(2);

tokio::task_local! {
    /// The scope of the task running: the instance's.
    static CURRENT: TaskScope;
    /// Transient query ownership, distinct from the shared carrier poll context.
    static REQUEST_OWNER: TaskScope;
}

std::thread_local! {
    /// The scope of the instance `run()` is building on this thread.
    static BUILDING: std::cell::RefCell<Option<TaskScope>> = const { std::cell::RefCell::new(None) };
}

/// While it is held, the thread that holds it builds the instance of its
/// scope: what that build spawns through `sail::spawn` is the scope's.
/// Held by `run()` on its start thread from the runtime's entry until the
/// instance's root tasks run, which have the scope as their task-local.
/// `Instance::build` is synchronous and runs on no task, so there is no
/// task-local to find then; groups' health checks and probes, among
/// others, spawn there. A reload builds inside the scope already, on one
/// of its tasks. Not `Send`: it is the thread's.
pub struct Building {
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Drop for Building {
    fn drop(&mut self) {
        BUILDING.with(|b| b.borrow_mut().take());
    }
}

/// A task's class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskClass {
    Contained,
    Essential,
}

/// What a stop could not end within its bound, and what the instance's
/// teardown could not undo in the system.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StopReport {
    /// The tasks still running, by name, with how many of each.
    pub tasks: Vec<(&'static str, usize)>,
    /// How long the stop waited.
    pub waited: Duration,
    /// What is left in the system (routes, rules, filters, a device), each
    /// with why and how to clear it by hand (runtime::teardown).
    pub left: Vec<crate::runtime::teardown::Left>,
}

impl StopReport {
    /// Whether everything ended and nothing is left in the system.
    pub fn clean(&self) -> bool {
        self.tasks.is_empty() && self.left.is_empty()
    }
}

type Registry = Mutex<HashMap<u64, (&'static str, Option<AbortHandle>)>>;

struct Inner {
    next: AtomicU64,
    shards: [Registry; SHARDS],
    /// Contained panics since the scope was made.
    faults: Arc<AtomicU64>,
    /// Why the instance failed: an essential task's panic, or a lock it
    /// poisoned; told once to whoever waits on it.
    failed: tokio::sync::watch::Sender<Option<String>>,
    events: crate::control::events::EventHub,
    report: Mutex<Option<StopReport>>,
    /// The instance's log: what its tasks log goes there, on whatever
    /// thread they run (a host's runtime's too).
    log: std::sync::OnceLock<Arc<crate::app::logger::InstanceLog>>,
    /// What the system's clock is behind the instance's NTP server, in
    /// nanoseconds (`crate::clock`).
    clock: Arc<portable_atomic::AtomicI64>,
    #[cfg(feature = "inbound-tun")]
    children: Mutex<Vec<std::sync::Weak<Inner>>>,
}

/// An instance's tasks. Cheap to clone; every clone the same.
#[derive(Clone)]
pub struct TaskScope(Arc<Inner>);

impl Default for TaskScope {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl std::fmt::Debug for TaskScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TaskScope({} tasks)", self.len())
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn message(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic".to_string())
}

impl TaskScope {
    pub fn new(events: crate::control::events::EventHub) -> Self {
        Self::with_context(
            events,
            Arc::new(AtomicU64::new(0)),
            Arc::new(portable_atomic::AtomicI64::new(0)),
        )
    }

    fn with_context(
        events: crate::control::events::EventHub,
        faults: Arc<AtomicU64>,
        clock: Arc<portable_atomic::AtomicI64>,
    ) -> Self {
        TaskScope(Arc::new(Inner {
            next: AtomicU64::new(0),
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            faults,
            failed: tokio::sync::watch::channel(None).0,
            events,
            report: Mutex::new(None),
            log: std::sync::OnceLock::new(),
            clock,
            #[cfg(feature = "inbound-tun")]
            children: Mutex::new(Vec::new()),
        }))
    }

    /// An independently drainable task registry/failure domain in the same
    /// instance. Logs, events, NTP clock and fault accounting remain shared.
    #[cfg(feature = "inbound-tun")]
    pub(crate) fn isolated(&self) -> Self {
        let scope = Self::with_context(
            self.0.events.clone(),
            self.0.faults.clone(),
            self.0.clock.clone(),
        );
        if let Some(log) = self.log() {
            scope.set_log(log);
        }
        lock(&self.0.children).push(Arc::downgrade(&scope.0));
        scope
    }

    // A root stop still owns the complete run, including locally drainable
    // domains retained by old manager handles. Weak links form no owner cycle.
    fn children(&self) -> Vec<TaskScope> {
        #[cfg(feature = "inbound-tun")]
        {
            let mut children = lock(&self.0.children);
            children.retain(|child| child.strong_count() > 0);
            children
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .map(TaskScope)
                .collect()
        }
        #[cfg(not(feature = "inbound-tun"))]
        Vec::new()
    }

    /// What the system's clock is behind the instance's NTP server, in
    /// nanoseconds; 0 without one.
    pub(crate) fn clock_offset(&self) -> i64 {
        self.0.clock.load(portable_atomic::Ordering::Relaxed)
    }

    /// Takes `nanos` as what the system's clock is behind, for the time the
    /// instance's protocols go by.
    pub(crate) fn set_clock_offset(&self, nanos: i64) {
        self.0
            .clock
            .store(nanos, portable_atomic::Ordering::Relaxed);
    }

    /// Makes `log` the log of what the scope's tasks log: the threads they
    /// run on need not be the instance's own.
    pub(crate) fn set_log(&self, log: Arc<crate::app::logger::InstanceLog>) {
        let _ = self.0.log.set(log);
    }

    /// The instance's log, once set.
    pub(crate) fn log(&self) -> Option<Arc<crate::app::logger::InstanceLog>> {
        self.0.log.get().cloned()
    }

    /// Runs `fut` in this scope: what it spawns through `sail::spawn` is
    /// the scope's. For the instance's root tasks.
    pub fn enter<F: Future>(&self, fut: F) -> impl Future<Output = F::Output> {
        CURRENT.scope(self.clone(), fut)
    }

    /// An attachment's request tasks are local even while outbound I/O
    /// polls under the instance context to construct shared carriers there.
    pub(crate) fn own_requests<F: Future>(&self, future: F) -> impl Future<Output = F::Output> {
        REQUEST_OWNER.scope(self.clone(), future)
    }

    /// Poll-free construction on a blocking thread still needs this scope's
    /// task context (the runtime handle is entered separately by its owner).
    #[cfg(feature = "inbound-tun")]
    pub(crate) fn enter_sync<T>(&self, f: impl FnOnce() -> T) -> T {
        CURRENT.sync_scope(self.clone(), f)
    }

    /// Keeps an owned result counted until its resources actually drop,
    /// including while a completed blocking task stores an unjoined result.
    #[cfg(feature = "inbound-tun")]
    pub(crate) fn hold_resource(&self, name: &'static str) -> TaskResource {
        let id = self.0.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.0.shards[(id as usize) % SHARDS]).insert(id, (name, None));
        TaskResource {
            _registration: Registered(self.clone(), id),
        }
    }

    /// The scope of the task running, if it is a scoped one; else that of
    /// the instance this thread is building, if it is building one.
    pub fn current() -> Option<TaskScope> {
        CURRENT
            .try_with(|s| s.clone())
            .ok()
            .or_else(|| BUILDING.with(|b| b.borrow().clone()))
    }

    /// `current()`'s clock offset, read without cloning the scope: the
    /// time is read per datagram, on every core.
    pub(crate) fn current_clock_offset() -> i64 {
        CURRENT
            .try_with(|s| s.clock_offset())
            .ok()
            .or_else(|| BUILDING.with(|b| b.borrow().as_ref().map(|s| s.clock_offset())))
            .unwrap_or(0)
    }

    /// Marks this thread as building this scope's instance, until the
    /// guard drops. One at a time: a second is a mistake.
    pub fn building(&self) -> Building {
        BUILDING.with(|b| {
            let mut b = b.borrow_mut();
            assert!(b.is_none(), "a thread builds one instance at a time");
            *b = Some(self.clone());
        });
        Building {
            _not_send: std::marker::PhantomData,
        }
    }

    /// `fut`, a root task `run()` polls itself (a runner, the reload and
    /// signal watchers): a panic in it fails the instance, as an essential
    /// task's does, and ends it there instead of unwinding `run()`, which
    /// then stops as on any end of a root task.
    pub fn root<F: Future<Output = ()>>(
        &self,
        name: &'static str,
        fut: F,
    ) -> impl Future<Output = ()> {
        let scope = self.clone();
        std::panic::AssertUnwindSafe(fut)
            .catch_unwind()
            .map(move |result| {
                if let Err(panic) = result {
                    scope.panicked(TaskClass::Essential, name, &*panic);
                }
            })
    }

    /// Names of the tasks registered now, with how many of each.
    pub fn tasks(&self) -> Vec<(&'static str, usize)> {
        let mut by_name: HashMap<&'static str, usize> = HashMap::new();
        for shard in &self.0.shards {
            for (name, _) in lock(shard).values() {
                *by_name.entry(name).or_default() += 1;
            }
        }
        for child in self.children() {
            for (name, count) in child.tasks() {
                *by_name.entry(name).or_default() += count;
            }
        }
        let mut tasks: Vec<_> = by_name.into_iter().collect();
        tasks.sort();
        tasks
    }

    /// `fut`, run in this scope as a child its owner ends: a `JoinSet`'s,
    /// a connection's list of tasks. Not registered, as the owner is; a
    /// stop names the owner. A panic in it is caught, and counted and
    /// told, or fails the instance, as `class` says, then goes on to the
    /// owner as tokio's `JoinError`.
    fn child<F: Future>(
        &self,
        class: TaskClass,
        name: &'static str,
        fut: F,
    ) -> impl Future<Output = F::Output> {
        let scope = self.clone();
        // Combinators, as `task`, for its size.
        std::panic::AssertUnwindSafe(CURRENT.scope(scope.clone(), fut))
            .catch_unwind()
            .map(move |result| match result {
                Ok(output) => output,
                Err(panic) => {
                    scope.panicked(class, name, &*panic);
                    std::panic::resume_unwind(panic)
                }
            })
    }

    /// Spawns `fut` as contained work on the current runtime.
    pub fn spawn<F>(&self, name: &'static str, fut: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_as(TaskClass::Contained, None, name, fut)
    }

    /// Spawns `fut` as essential work on the current runtime.
    pub fn spawn_essential<F>(&self, name: &'static str, fut: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_as(TaskClass::Essential, None, name, fut)
    }

    /// Spawns `fut` as contained work on `handle`'s runtime: from where no
    /// runtime is entered, a host's executor among them.
    pub fn spawn_on<F>(
        &self,
        handle: &tokio::runtime::Handle,
        name: &'static str,
        fut: F,
    ) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_as(TaskClass::Contained, Some(handle), name, fut)
    }

    /// Spawns `fut` as essential work on `handle`'s runtime.
    pub fn spawn_essential_on<F>(
        &self,
        handle: &tokio::runtime::Handle,
        name: &'static str,
        fut: F,
    ) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_as(TaskClass::Essential, Some(handle), name, fut)
    }

    fn spawn_as<F>(
        &self,
        class: TaskClass,
        handle: Option<&tokio::runtime::Handle>,
        name: &'static str,
        fut: F,
    ) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (id, task) = self.task(class, name, fut);
        let handle = match handle {
            Some(handle) => handle.spawn(task),
            None => tokio::spawn(task),
        };
        if let Some(entry) = lock(&self.0.shards[(id as usize) % SHARDS]).get_mut(&id) {
            entry.1 = Some(handle.abort_handle());
        }
        handle
    }

    /// `fut` registered as a task of `class` named `name`, wrapped to run
    /// in the scope, its panic caught; and its id. Combinators, not an
    /// async block: a block keeps `fut` and what wraps it apart, the task
    /// twice its size or more (4 KiB more a held connection, measured). It
    /// is `fut` and `TASK_OVERHEAD` at most.
    fn task<F: Future>(
        &self,
        class: TaskClass,
        name: &'static str,
        fut: F,
    ) -> (u64, impl Future<Output = F::Output>) {
        let id = self.0.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.0.shards[(id as usize) % SHARDS]).insert(id, (name, None));
        let scope = self.clone();
        // Out of the registry however it ends: done, aborted, panicked, or
        // aborted before it ever ran, when the future drops unpolled.
        let registered = Registered(scope.clone(), id);
        let task = std::panic::AssertUnwindSafe(CURRENT.scope(scope.clone(), fut))
            .catch_unwind()
            .map(move |result| {
                let _registered = registered;
                match result {
                    Ok(output) => output,
                    Err(panic) => {
                        scope.panicked(class, name, &*panic);
                        // As before for whoever awaits it: tokio's JoinError.
                        std::panic::resume_unwind(panic)
                    }
                }
            });
        (id, task)
    }

    /// Runs `f` on the blocking pool as contained work: counted in the
    /// scope while it runs, which an abort cannot end, so a stop reports it
    /// if it outlasts the bound.
    pub fn spawn_blocking<F, R>(&self, name: &'static str, f: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let id = self.0.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.0.shards[(id as usize) % SHARDS]).insert(id, (name, None));
        let scope = self.clone();
        let registered = Registered(scope.clone(), id);
        tokio::task::spawn_blocking(move || {
            let _registered = registered;
            // A host's blocking thread logs to no instance of its own.
            let _log = scope.log().map(|log| crate::app::logger::enter(Some(log)));
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
                Ok(output) => output,
                Err(panic) => {
                    scope.panicked(TaskClass::Contained, name, &*panic);
                    std::panic::resume_unwind(panic)
                }
            }
        })
    }

    fn panicked(&self, class: TaskClass, name: &'static str, panic: &(dyn std::any::Any + Send)) {
        let what = message(panic);
        match class {
            TaskClass::Contained => {
                let count = self.0.faults.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::error!(
                    "task [{}] panicked: {}; the instance goes on ({} so far)",
                    name,
                    what,
                    count
                );
                self.0
                    .events
                    .fault(crate::control::events::Fault::new(name, class, what, count));
            }
            TaskClass::Essential => {
                tracing::error!("task [{}] panicked: {}; its scope fails", name, what);
                self.fail(format!("task [{}] panicked: {}", name, what));
            }
        }
    }

    /// Fails this scope: the first reason is kept. A root scope fails the
    /// instance; an isolated attachment scope fails only that attachment.
    pub fn fail(&self, why: String) {
        self.0.failed.send_if_modified(|failed| {
            if failed.is_none() {
                *failed = Some(why);
                true
            } else {
                false
            }
        });
    }

    /// Why the instance failed, if it did.
    pub fn failure(&self) -> Option<String> {
        self.0.failed.borrow().clone()
    }

    /// Returns once the instance has failed.
    pub async fn failed(&self) {
        let mut failed = self.0.failed.subscribe();
        let _ = failed.wait_for(|f| f.is_some()).await;
    }

    /// The instance's lock `m`, named `name`; or, when an earlier panic
    /// poisoned it, the instance fails, naming it, and the caller gets an
    /// error to give up with, rather than panicking in its turn.
    pub fn lock<'a, T>(
        &self,
        m: &'a Mutex<T>,
        name: &str,
    ) -> Result<MutexGuard<'a, T>, PoisonedLock> {
        m.lock().map_err(|_| {
            self.fail(format!("lock [{}] poisoned by an earlier panic", name));
            PoisonedLock(name.to_string())
        })
    }

    /// Contained panics so far.
    pub fn faults(&self) -> u64 {
        self.0.faults.load(Ordering::Relaxed)
    }

    /// Tasks registered now.
    pub fn len(&self) -> usize {
        self.0.shards.iter().map(|s| lock(s).len()).sum::<usize>()
            + self.children().iter().map(TaskScope::len).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Emergency cancellation without waiting, for an owner's Drop. Normal
    /// lifecycle operations use stop() and inspect its resource barrier.
    pub(crate) fn abort_all(&self) {
        for child in self.children() {
            child.abort_all();
        }
        for shard in &self.0.shards {
            for (_, abort) in lock(shard).values() {
                if let Some(abort) = abort {
                    abort.abort();
                }
            }
        }
    }

    /// Ends every task: aborts them, then waits up to `within` for them to
    /// be gone. What is left (a blocking call, which an abort cannot end)
    /// is reported, and kept for `report`.
    pub async fn stop(&self, within: Duration) -> StopReport {
        let started = Instant::now();
        self.abort_all();
        while !self.is_empty() && started.elapsed() < within {
            // A running task can register a child just as abort is requested.
            self.abort_all();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut report = lock(&self.0.report);
        let report = report.get_or_insert_with(Default::default);
        report.tasks = self.tasks();
        report.waited = started.elapsed();
        report.clone()
    }

    /// Records what the instance's teardown left, in the report of the
    /// stop (one with no tasks left if there was none).
    pub fn note_left(&self, left: Vec<crate::runtime::teardown::Left>) {
        lock(&self.0.report)
            .get_or_insert_with(Default::default)
            .left = left;
    }

    /// What the last stop could not end.
    pub fn report(&self) -> Option<StopReport> {
        lock(&self.0.report).clone()
    }
}

#[cfg(feature = "inbound-tun")]
pub(crate) struct TaskResource {
    _registration: Registered,
}

/// Takes its task out of the registry when it ends.
struct Registered(TaskScope, u64);

impl Drop for Registered {
    fn drop(&mut self) {
        lock(&self.0 .0.shards[(self.1 as usize) % SHARDS]).remove(&self.1);
    }
}

/// An instance lock an earlier panic poisoned; the instance has failed.
#[derive(Debug, Clone, thiserror::Error)]
#[error("lock [{0}] poisoned by an earlier panic: the instance has failed")]
pub struct PoisonedLock(pub String);

impl From<PoisonedLock> for std::io::Error {
    fn from(e: PoisonedLock) -> Self {
        std::io::Error::other(e)
    }
}

/// Spawns `fut` as contained work in the current task's scope. Where no
/// scope is set (a thread of sail's own, a callback, the blocking pool),
/// pass the scope and call its `spawn` instead: it is warned of, counted
/// (`unscoped_count`) and spawned unscoped.
pub fn spawn<F>(name: &'static str, fut: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match here() {
        Some(scope) => scope.spawn(name, fut),
        None => unscoped(name, fut),
    }
}

/// Spawns `fut` as essential work in the current task's scope; as `spawn`
/// where there is none.
pub fn spawn_essential<F>(name: &'static str, fut: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match here() {
        Some(scope) => scope.spawn_essential(name, fut),
        None => unscoped(name, fut),
    }
}

/// Spawns `fut` in the current scope as `class` says: for a task whose
/// lifetime its caller knows, not the spawning code.
pub fn spawn_of<F>(class: TaskClass, name: &'static str, fut: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match class {
        TaskClass::Contained => spawn(name, fut),
        TaskClass::Essential => spawn_essential(name, fut),
    }
}

/// `fut` as contained work of the current scope, for an owner that ends
/// it: a `JoinSet`'s or a connection's own tasks (`TaskScope::child`).
/// Where no scope is set, as `spawn`.
pub fn scoped<F: Future>(name: &'static str, fut: F) -> impl Future<Output = F::Output> {
    in_scope(TaskClass::Contained, name, fut)
}

/// `fut` as essential work of the current scope, for an owner that ends
/// it; as `scoped`.
pub fn scoped_essential<F: Future>(name: &'static str, fut: F) -> impl Future<Output = F::Output> {
    in_scope(TaskClass::Essential, name, fut)
}

fn in_scope<F: Future>(
    class: TaskClass,
    name: &'static str,
    fut: F,
) -> futures::future::Either<impl Future<Output = F::Output>, F> {
    match here() {
        Some(scope) => futures::future::Either::Left(scope.child(class, name, fut)),
        None => {
            unscoped_note(name);
            futures::future::Either::Right(fut)
        }
    }
}

/// The instance's lock `m`, named `name`, from the current scope
/// (`TaskScope::lock`): on poison the instance fails and the caller gets
/// an error to give up with. Where no scope is set, the error alone.
pub fn instance_lock<'a, T>(
    m: &'a Mutex<T>,
    name: &str,
) -> Result<MutexGuard<'a, T>, PoisonedLock> {
    match here() {
        Some(scope) => scope.lock(m, name),
        None => m.lock().map_err(|_| {
            tracing::error!("lock [{}] poisoned by an earlier panic", name);
            PoisonedLock(name.to_string())
        }),
    }
}

/// Runs `f` on the blocking pool as contained work of the current scope;
/// as `spawn` where there is none.
pub fn spawn_blocking<F, R>(name: &'static str, f: F) -> JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    match here() {
        Some(scope) => scope.spawn_blocking(name, f),
        None => {
            unscoped_note(name);
            tokio::task::spawn_blocking(f)
        }
    }
}

/// `fut` run in place, as contained work inside a longer task: one
/// member's test in a group's round. A panic in it is caught, counted and
/// told as a contained task's, and gives `None`; the task around it goes
/// on.
pub fn contain<F: Future>(name: &'static str, fut: F) -> impl Future<Output = Option<F::Output>> {
    // Combinators, as `TaskScope::task`, for its size.
    std::panic::AssertUnwindSafe(fut)
        .catch_unwind()
        .map(move |result| match result {
            Ok(output) => Some(output),
            Err(panic) => {
                match here() {
                    Some(scope) => scope.panicked(TaskClass::Contained, name, &*panic),
                    None => tracing::error!("[{}] panicked: {}", name, message(&*panic)),
                }
                None
            }
        })
}

/// Spawns `fut` into `set` as contained work of the current scope, which
/// the set ends (`scoped`).
pub fn spawn_child<T, F>(
    set: &mut tokio::task::JoinSet<T>,
    name: &'static str,
    fut: F,
) -> AbortHandle
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    set.spawn(scoped(name, fut))
}

/// Spawns `fut` into `set` as essential work of the current scope, which
/// the set ends (`scoped_essential`).
pub fn spawn_child_essential<T, F>(
    set: &mut tokio::task::JoinSet<T>,
    name: &'static str,
    fut: F,
) -> AbortHandle
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    set.spawn(scoped_essential(name, fut))
}

/// Spawns `fut` into `set` as `class` says (`spawn_of`), which the set
/// ends.
pub fn spawn_child_of<T, F>(
    class: TaskClass,
    set: &mut tokio::task::JoinSet<T>,
    name: &'static str,
    fut: F,
) -> AbortHandle
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    match class {
        TaskClass::Contained => spawn_child(set, name, fut),
        TaskClass::Essential => spawn_child_essential(set, name, fut),
    }
}

/// Spawns `fut` as contained work in `scope`, a scope kept for a spawn
/// from where none is set (a `Drop`, a stored handle); as `spawn` where it
/// is none.
pub fn spawn_in<F>(scope: Option<&TaskScope>, name: &'static str, fut: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match scope {
        Some(scope) => scope.spawn(name, fut),
        None => spawn(name, fut),
    }
}

/// The scope to spawn in: the current one. In sail's own unit tests only
/// (`cfg(test)` of this crate), where none is set, a process-wide scope of
/// their own, so that a test driving a protocol directly needs none; the
/// integration tests and every other crate are warned and counted
/// (`unscoped_count`), and asserted from S2f.
pub fn here() -> Option<TaskScope> {
    let current = TaskScope::current();
    #[cfg(test)]
    let current = current.or_else(|| {
        static TESTS: std::sync::OnceLock<TaskScope> = std::sync::OnceLock::new();
        Some(TESTS.get_or_init(TaskScope::default).clone())
    });
    current
}

/// Spawns with no scope there is: a mistake, never silent.
fn unscoped<F>(name: &'static str, fut: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    unscoped_note(name);
    tokio::spawn(fut)
}

static UNSCOPED: AtomicU64 = AtomicU64::new(0);

/// A task with no scope there is: a mistake, never silent. It is counted
/// (`unscoped_count`) and warned of once per call site (a task's name),
/// and in a debug build it fails the assertion: every area spawns through
/// the scope (E2 S2a–e), and the whole integration suite runs with none
/// (S2f's criterion). In a debug build, `SAIL_SCOPE_STRICT` aborts the
/// process there, so that a spawn on a task of its own, whose panic tokio
/// would catch, still fails the run (CI's test jobs set it), and
/// `SAIL_SCOPE_REPORT` prints where it was and goes on, to list them all.
fn unscoped_note(name: &'static str) {
    static WARNED: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    let n = UNSCOPED.fetch_add(1, Ordering::Relaxed) + 1;
    {
        let mut warned = lock(&WARNED);
        if !warned.contains(&name) {
            warned.push(name);
            tracing::warn!(
                "task [{}] spawned outside any instance's scope ({} so far): a stop will not end it",
                name,
                n
            );
        }
    }
    if cfg!(debug_assertions) {
        if std::env::var_os("SAIL_SCOPE_STRICT").is_some() {
            eprintln!(
                "task [{}] spawned outside any instance's scope: aborting",
                name
            );
            std::process::abort();
        }
        if std::env::var_os("SAIL_SCOPE_REPORT").is_some() {
            eprintln!(
                "UNSCOPED [{}] on {:?}\n{}",
                name,
                std::thread::current().name(),
                std::backtrace::Backtrace::force_capture()
            );
            return;
        }
    }
    debug_assert!(
        false,
        "task [{}] spawned outside any instance's scope",
        name
    );
}

/// How many tasks were spawned outside any instance's scope, in this
/// process: zero once every area spawns through it.
#[doc(hidden)]
pub fn unscoped_count() -> u64 {
    UNSCOPED.load(Ordering::Relaxed)
}

/// Register a per-request task with an explicit attachment owner, keeping
/// its I/O poll context at the root. Ordinary requests retain spawn().
pub(crate) fn spawn_request<F>(name: &'static str, future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match REQUEST_OWNER.try_with(Clone::clone).ok() {
        None => spawn(name, future),
        Some(owner) => {
            let context = TaskScope::current();
            let requests = owner.clone();
            owner.spawn(name, async move {
                requests
                    .own_requests(async move {
                        match context {
                            Some(context) => context.enter(future).await,
                            None => future.await,
                        }
                    })
                    .await
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "inbound-tun")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_root_stop_reports_resources_owned_by_a_retained_child_scope() {
        let root = TaskScope::default();
        let child = root.isolated();
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        struct Release(Arc<(Mutex<bool>, std::sync::Condvar)>);
        impl Drop for Release {
            fn drop(&mut self) {
                *self.0 .0.lock().unwrap() = true;
                self.0 .1.notify_all();
            }
        }
        let release = Release(gate.clone());
        let (ready, entered) = tokio::sync::oneshot::channel();
        let task = child.spawn_blocking("test retained attachment resource", move || {
            ready.send(()).unwrap();
            let mut open = gate.0.lock().unwrap();
            while !*open {
                open = gate.1.wait(open).unwrap();
            }
        });
        entered.await.unwrap();
        let report = root.stop(Duration::from_millis(20)).await;
        drop(release);
        task.await.unwrap();
        let final_report = root.stop(Duration::from_secs(1)).await;
        assert!(
            !report.clean(),
            "root must not report a retained child resource as clean"
        );
        assert!(report
            .tasks
            .iter()
            .any(|(name, _)| *name == "test retained attachment resource"));
        assert!(final_report.clean());
        assert!(child.is_empty());
    }

    #[cfg(feature = "inbound-tun")]
    #[tokio::test]
    async fn an_unjoined_blocking_result_stays_owned_until_its_payload_drops() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        struct Payload(Arc<AtomicBool>);
        impl Drop for Payload {
            fn drop(&mut self) {
                self.0.store(true, AtomicOrdering::SeqCst);
            }
        }
        struct OwnedResult {
            _payload: Payload,
            _held: TaskResource,
        }
        let scope = TaskScope::default();
        let dropped = Arc::new(AtomicBool::new(false));
        let payload = Payload(dropped.clone());
        let held = scope.hold_resource("unjoined opening result");
        let result = scope.spawn_blocking("opening task", move || OwnedResult {
            _payload: payload,
            _held: held,
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !result.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!dropped.load(AtomicOrdering::SeqCst));
        let report = scope.stop(Duration::from_millis(20)).await;
        assert!(!report.clean());
        assert_eq!(report.tasks, [("unjoined opening result", 1)]);
        drop(result);
        assert!(dropped.load(AtomicOrdering::SeqCst));
        assert!(scope.is_empty());
    }

    #[cfg(feature = "inbound-tun")]
    #[tokio::test]
    async fn an_isolated_registry_keeps_instance_context_but_not_failure_or_tasks() {
        let parent = TaskScope::default();
        let child = parent.isolated();
        parent.set_clock_offset(17);
        assert_eq!(child.clock_offset(), 17);
        child.set_clock_offset(23);
        assert_eq!(parent.clock_offset(), 23);
        let bad = child.spawn("isolated panic", async { panic!("one attachment") });
        assert!(bad.await.is_err());
        assert_eq!(parent.faults(), 1);
        assert!(parent.failure().is_none());
        child.fail("attachment failed".to_string());
        assert!(parent.failure().is_none());
        assert!(child.failure().is_some());
        let _task = child.spawn("isolated pending", std::future::pending::<()>());
        assert!(parent.0.shards.iter().all(|shard| lock(shard).is_empty()));
        assert_eq!(parent.len(), 1, "whole-run accounting includes the child");
        assert!(child.stop(Duration::from_secs(1)).await.clean());
        assert!(parent.is_empty());
    }

    #[tokio::test]
    async fn a_contained_panic_is_counted_and_the_scope_goes_on() {
        let scope = TaskScope::default();
        let mut faults = scope.0.events.faults();
        let failed = scope.spawn("doomed", async { panic!("a bad packet") });
        assert!(failed.await.unwrap_err().is_panic());
        assert_eq!(scope.faults(), 1);
        assert!(scope.failure().is_none(), "a contained panic fails nothing");
        let fault = faults.recv().await.unwrap();
        assert_eq!((fault.task, fault.count), ("doomed", 1));
        assert!(scope.is_empty(), "out of the registry");
    }

    #[tokio::test]
    async fn an_essential_panic_fails_the_instance() {
        let scope = TaskScope::default();
        let _ = scope
            .spawn_essential("router", async { panic!("broken state") })
            .await;
        tokio::time::timeout(Duration::from_secs(5), scope.failed())
            .await
            .expect("failed in time");
        assert!(scope
            .failure()
            .unwrap()
            .contains("[router] panicked: broken state"));
    }

    /// What a teardown left goes into the stop's report, which is then
    /// not clean, whether the stop came before or after.
    #[tokio::test]
    async fn what_a_teardown_left_is_in_the_report() {
        let left = crate::runtime::teardown::Left {
            kind: crate::runtime::teardown::LeftKind::Nft,
            resource: "nft table inet sail_tun0".into(),
            why: "timed out after 5s".into(),
            clear: Some("nft delete table inet sail_tun0".into()),
        };
        let before = TaskScope::default();
        before.note_left(vec![left.clone()]);
        assert!(!before.report().unwrap().clean());
        let after = TaskScope::default();
        let report = after.stop(Duration::from_millis(10)).await;
        assert!(report.clean());
        after.note_left(vec![left.clone()]);
        let report = after.report().unwrap();
        assert_eq!(report.left, vec![left]);
        assert!(!report.clean());
    }

    /// A root task's panic fails the instance and ends the task; nothing
    /// unwinds past it.
    #[tokio::test]
    async fn a_root_task_s_panic_fails_the_instance_without_unwinding() {
        let scope = TaskScope::default();
        scope.root("root", async { panic!("a runner") }).await;
        let why = scope.failure().expect("failed");
        assert!(why.contains("root") && why.contains("a runner"), "{}", why);
    }

    /// A child is its future and `TASK_OVERHEAD` at most, as a task.
    #[test]
    fn a_child_is_its_future_and_a_few_words() {
        let scope = TaskScope::default();
        let fut = async {
            let big = [7u8; 4096];
            std::future::ready(()).await;
            std::hint::black_box(&big);
        };
        let size = std::mem::size_of_val(&fut);
        let child = scope.child(TaskClass::Contained, "sized", fut);
        assert!(std::mem::size_of_val(&child) <= size + TASK_OVERHEAD);
        let contained = contain("sized", async {
            let big = [7u8; 4096];
            std::future::ready(()).await;
            std::hint::black_box(&big);
        });
        assert!(std::mem::size_of_val(&contained) <= size + TASK_OVERHEAD);
    }

    /// A scoped task is its future and `TASK_OVERHEAD` at most, whatever
    /// the future's size: never two copies of it.
    #[test]
    fn a_scoped_task_is_its_future_and_a_few_words() {
        let scope = TaskScope::default();
        for n in [64usize, 4096] {
            let fut = async move {
                let held = vec![0u8; n];
                let big = [7u8; 4096];
                std::future::ready(()).await;
                std::hint::black_box((&held, &big[..n.min(4096)]));
            };
            let size = std::mem::size_of_val(&fut);
            let (_, task) = scope.task(TaskClass::Contained, "sized", fut);
            let wrapped = std::mem::size_of_val(&task);
            assert!(
                wrapped <= size + TASK_OVERHEAD,
                "{} bytes for a {}-byte future",
                wrapped,
                size
            );
            drop(task);
        }
        // Dropped unpolled, it left the registry.
        assert!(scope.is_empty());
    }

    #[tokio::test]
    async fn a_stop_ends_the_tasks_and_says_what_is_left() {
        let scope = TaskScope::default();
        for _ in 0..3 {
            scope.spawn("idle", std::future::pending::<()>());
        }
        // A scoped task's own spawns are in the scope too.
        scope
            .spawn("parent", async {
                let _child = spawn("child", std::future::pending::<()>());
            })
            .await
            .unwrap();
        assert_eq!(scope.len(), 4);
        let report = scope.stop(Duration::from_secs(2)).await;
        assert!(report.clean(), "{:?}", report);
        assert!(scope.is_empty());
    }

    #[tokio::test]
    async fn a_contained_part_of_a_task_is_caught_in_place() {
        let scope = TaskScope::default();
        let caught = scope
            .enter(async {
                let failed = contain("part", async { panic!("one member") }).await;
                let fine = contain("part", async { 7 }).await;
                (failed, fine)
            })
            .await;
        assert_eq!(caught, (None::<()>, Some(7)));
        assert_eq!(scope.faults(), 1);
        assert!(scope.failure().is_none());
    }

    #[tokio::test]
    async fn a_blocking_task_past_the_bound_is_named_in_the_report() {
        let scope = TaskScope::default();
        scope.spawn("idle", std::future::pending::<()>());
        scope.spawn_blocking("slow", || std::thread::sleep(Duration::from_millis(500)));
        let report = scope.stop(Duration::from_millis(50)).await;
        assert!(!report.clean());
        assert_eq!(report.tasks, vec![("slow", 1)], "{:?}", report);
        assert!(report.waited >= Duration::from_millis(50), "{:?}", report);
        assert_eq!(scope.report(), Some(report));
    }

    #[test]
    fn a_poisoned_lock_fails_the_instance_instead_of_a_cascade() {
        let scope = TaskScope::default();
        let m = Arc::new(Mutex::new(0));
        let poison = m.clone();
        let _ = std::thread::spawn(move || {
            let _held = poison.lock().unwrap();
            panic!("while holding it");
        })
        .join();
        let err = scope.lock(&m, "table").unwrap_err();
        assert_eq!(err.0, "table");
        assert!(scope.failure().unwrap().contains("lock [table] poisoned"));
    }
}
