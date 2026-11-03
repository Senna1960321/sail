//! An instance's life: made once, started from a configuration, reloaded,
//! stopped, any number of times; any number of instances at once.

use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread::{JoinHandle, ThreadId};
use std::time::{Duration, SystemTime};

use futures::future::BoxFuture;

use super::{Config, Error, ErrorKind, Options, ReloadOptions, ReloadReport, State, Threads};
use crate::app::logger::{InstanceLog, InstanceLogRef};
use crate::runtime::{Host, Platform, PlatformRef, RuntimeOptions};
use crate::{RuntimeId, RuntimeManager};

/// The runtime ids the instances hold, from their making until they are
/// gone: two never share one.
static IDS: Mutex<BTreeSet<RuntimeId>> = Mutex::new(BTreeSet::new());

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn take_id() -> Result<RuntimeId, Error> {
    let mut ids = lock(&IDS);
    // Not 0: a host of its own may start an instance 0, as sail-cli does.
    (1..=RuntimeId::MAX)
        .find(|id| !ids.contains(id) && !crate::is_running(*id))
        .inspect(|id| {
            ids.insert(*id);
        })
        .ok_or_else(|| Error::state("too many instances"))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Idle,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Starting => "starting",
            Phase::Running => "running",
            Phase::Stopping => "stopping",
            Phase::Stopped => "stopped",
            Phase::Failed => "failed",
        }
    }

    /// Whether the instance's thread may still run.
    fn live(self) -> bool {
        matches!(self, Phase::Starting | Phase::Running | Phase::Stopping)
    }
}

struct Life {
    phase: Phase,
    failure: Option<Error>,
    manager: Option<Arc<RuntimeManager>>,
    thread: Option<JoinHandle<()>>,
    thread_id: Option<ThreadId>,
    /// A stop was asked for this run.
    stop: bool,
    started_at: Option<SystemTime>,
    /// The last run's tasks, for what its stop could not end.
    scope: Option<crate::runtime::scope::TaskScope>,
    /// What the run starting or running runs with, from when the network
    /// it starts on is settled: its network is read from here before it
    /// runs.
    env: Option<Arc<crate::runtime::RuntimeEnv>>,
}

pub(super) struct Inner {
    id: RuntimeId,
    options: RuntimeOptions,
    host: Host,
    threads: Threads,
    runtime: super::Runtime,
    log: Arc<InstanceLog>,
    platform: Option<Arc<dyn Platform>>,
    clash_modes: bool,
    life: Mutex<Life>,
    /// Told of each change of `life`, for those who wait blocking.
    changed: Condvar,
    /// The state, for those who wait or follow.
    state: tokio::sync::watch::Sender<State>,
    /// What dials through the outbounds of the run starting or running,
    /// from when they are built: before it runs. None otherwise.
    dialer: tokio::sync::watch::Sender<Option<crate::control::Dialer>>,
    /// Each change of state, in order, for its events: a watch keeps only
    /// the last.
    transitions: tokio::sync::broadcast::Sender<State>,
    /// The events every run tells (faults, group switches, dial failures,
    /// routes, DNS): the instance's, so that a subscription made before a
    /// run, or polled late, misses none of it.
    events: crate::control::events::EventHub,
    me: Weak<Inner>,
}

/// What a host holds of an instance; the instance's thread holds `Inner`
/// alone, so that the host's last one going asks it to stop.
struct Handle(Arc<Inner>);

impl Drop for Handle {
    fn drop(&mut self) {
        self.0.ask_stop();
    }
}

/// An instance: made once, started and stopped any number of times; its
/// log outlives its runs. Cheap to clone. When the last clone goes, a
/// running instance is asked to stop, without waiting: `stop().await`
/// first is the clean way.
#[derive(Clone)]
pub struct Instance(Arc<Handle>);

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Instance({}, {})", self.inner().id, self.state())
    }
}

impl Instance {
    /// Makes an instance, idle until started.
    pub fn new(options: Options) -> Result<Instance, Error> {
        let Options {
            settings,
            platform,
            log_lines,
            threads,
            runtime,
            clash_modes,
            log,
            stop_within,
            connection_records,
            record_interval,
            lossless_records,
            kinds,
            admission,
        } = options;
        let profile: crate::runtime::Profile = match &settings.profile {
            Some(p) => p
                .parse()
                .map_err(|e| Error::new(ErrorKind::Config, format!("{:#}", e)))?,
            None => Default::default(),
        };
        let (options, mut host) = settings
            .resolve()
            .map_err(|e| Error::new(ErrorKind::Config, format!("{:#}", e)))?;
        host.stop_within = stop_within;
        host.kinds = kinds;
        host.admission_hooks = (!admission.is_empty())
            .then(|| crate::app::inbound::admission::HostHooksRef(Arc::new(admission)));
        // As sail-cli runs each profile.
        let threads = threads.unwrap_or(match profile.threads() {
            crate::runtime::ProfileThreads::One => Threads::One,
            crate::runtime::ProfileThreads::Workers(n) => Threads::Workers(n, super::STACK_SIZE),
            crate::runtime::ProfileThreads::PerCpu => Threads::Auto,
        });
        let id = take_id()?;
        let log = log.unwrap_or_else(|| InstanceLog::new(log_lines));
        let (state, _) = tokio::sync::watch::channel(State::Idle);
        let inner = Arc::new_cyclic(|me| Inner {
            id,
            options,
            host,
            threads,
            runtime,
            log,
            platform,
            clash_modes,
            life: Mutex::new(Life {
                phase: Phase::Idle,
                failure: None,
                manager: None,
                thread: None,
                thread_id: None,
                stop: false,
                started_at: None,
                scope: None,
                env: None,
            }),
            changed: Condvar::new(),
            state,
            dialer: tokio::sync::watch::channel(None).0,
            transitions: tokio::sync::broadcast::channel(16).0,
            events: crate::control::events::EventHub::with_records(
                connection_records.unwrap_or(crate::control::events::RECORD_CAPACITY),
                lossless_records,
            ),
            me: me.clone(),
        });
        inner.events.set_record_interval(record_interval);
        Ok(Instance(Arc::new(Handle(inner))))
    }

    pub(super) fn inner(&self) -> &Arc<Inner> {
        &self.0 .0
    }

    /// Starts it with `config`; returns once it runs, or with why it did
    /// not start. It runs on threads of its own until stopped.
    pub async fn start(&self, config: Config) -> Result<(), Error> {
        let mut states = self.inner().start(config)?;
        let _ = states.wait_for(|s| !matches!(s, State::Starting)).await;
        self.inner().started()
    }

    /// Starts it as `start` does, blocking this thread.
    #[doc(hidden)]
    pub fn blocking_start(&self, config: Config) -> Result<(), Error> {
        self.inner().start(config)?;
        let life = self
            .inner()
            .changed
            .wait_while(lock(&self.inner().life), |l| l.phase == Phase::Starting)
            .unwrap_or_else(|e| e.into_inner());
        drop(life);
        self.inner().started()
    }

    /// Reloads it in place with `config`, or, with none, from the file it
    /// was started from. What did not change goes on; a reload that fails
    /// leaves it as it was. The inbounds `config` has are those that run
    /// after it, and it tells what became of each: only those `Removed`
    /// and `Replaced` had their connections closed. See docs/embed.md for
    /// what a reload keeps, and for the two errors of its own:
    /// `NeedsRestart` and `InboundLost`.
    pub async fn reload(&self, config: Option<Config>) -> Result<ReloadReport, Error> {
        self.reload_rechecking(config, ReloadOptions::default())
            .await
    }

    /// `reload`, the connections open treated as `options` says. With
    /// `RecheckOpen::CloseRejected` each the rules routed is matched again,
    /// once the reload took, against the routing it leaves, with no side
    /// effect: those the rules now reject or drop are closed, and the
    /// report's `recheck` lists them, and those the rules send to another
    /// outbound, which go on. With `Keep`, the default, it is `reload`.
    pub async fn reload_rechecking(
        &self,
        config: Option<Config>,
        options: ReloadOptions,
    ) -> Result<ReloadReport, Error> {
        let host = self.inner().host.clone();
        self.with_manager(move |manager| {
            Box::pin(async move {
                let config = match config {
                    None => None,
                    Some(config) => Some(
                        match config {
                            Config::Json(text) => crate::config::from_string_for(&text, &host),
                            Config::File(path) => {
                                crate::config::from_file_for(&path.to_string_lossy(), &host)
                            }
                        }
                        .map_err(crate::Error::Config)?,
                    ),
                };
                manager.reload_rechecking(config, options).await
            })
        })
        .await?
        .map_err(Error::from)
    }

    /// Asks it to stop, then waits until it has: its thread ended, its
    /// runtime gone, its listeners closed. A stop while it starts ends the
    /// start; one not running does nothing.
    pub async fn stop(&self) -> Result<(), Error> {
        // Not running (failed, stopped, never started): nothing to ask, and
        // no second teardown, which has run with the run's end; what it
        // left, if anything, is told again.
        let Some(mut states) = self.inner().ask_stop() else {
            return self.inner().leftovers();
        };
        let _ = states
            .wait_for(|s| !matches!(s, State::Starting | State::Running { .. } | State::Stopping))
            .await;
        self.inner().join();
        self.inner().leftovers()
    }

    /// What the last stop could not end within its bound: the tasks still
    /// running, by name, and how long it waited. None before any stop.
    pub fn stop_report(&self) -> Option<crate::runtime::scope::StopReport> {
        lock(&self.inner().life)
            .scope
            .as_ref()
            .and_then(|s| s.report())
    }

    /// Asks it to stop, and waits up to `wait` blocking this thread; zero
    /// does not wait.
    #[doc(hidden)]
    pub fn blocking_stop(&self, wait: Duration) -> Result<(), Error> {
        let own = self.on_own_thread();
        if self.inner().ask_stop().is_none() || own || wait.is_zero() {
            return Ok(());
        }
        let (life, timeout) = self
            .inner()
            .changed
            .wait_timeout_while(lock(&self.inner().life), wait, |l| l.phase.live())
            .unwrap_or_else(|e| e.into_inner());
        drop(life);
        if timeout.timed_out() {
            return Err(Error::new(
                ErrorKind::Timeout,
                "the instance is still stopping",
            ));
        }
        self.inner().join();
        self.inner().leftovers()
    }

    /// The state now.
    pub fn state(&self) -> State {
        self.inner().state.borrow().clone()
    }

    /// The state, as each change is followed: `changed().await`, then
    /// `borrow()`.
    pub fn states(&self) -> tokio::sync::watch::Receiver<State> {
        self.inner().state.subscribe()
    }

    /// The instance's log: what it keeps, and what comes after.
    pub(super) fn log(&self) -> &Arc<InstanceLog> {
        &self.inner().log
    }

    /// Forgets the lines of the log kept; those following are told.
    pub fn clear_logs(&self) {
        self.inner().log.clear();
    }

    /// Whether this thread is one of the instance's own: the one starting
    /// it, or its runtime's, as a `Platform` callback runs on. A blocking
    /// call there would wait on itself.
    pub fn on_own_thread(&self) -> bool {
        let current = std::thread::current().id();
        lock(&self.inner().life).thread_id == Some(current)
            || crate::app::logger::current().is_some_and(|log| Arc::ptr_eq(&log, &self.inner().log))
    }

    /// What controls the running instance: sail's own, unstable.
    #[doc(hidden)]
    pub fn manager(&self) -> Result<Arc<RuntimeManager>, Error> {
        lock(&self.inner().life)
            .manager
            .clone()
            .ok_or_else(Error::not_running)
    }

    /// The runtime id, unique among the instances alive.
    #[doc(hidden)]
    pub fn id(&self) -> RuntimeId {
        self.inner().id
    }

    /// Runs `task` on the instance's runtime with what controls it, and
    /// waits for it, from any executor.
    #[doc(hidden)]
    pub async fn with_manager<T: Send + 'static>(
        &self,
        task: impl FnOnce(Arc<RuntimeManager>) -> BoxFuture<'static, T>,
    ) -> Result<T, Error> {
        let manager = self.manager()?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = task(manager.clone());
        manager
            .env
            .scope
            .spawn_on(manager.handle(), "host call", async move {
                let _ = tx.send(task.await);
            });
        rx.await.map_err(|_| Error::state("the instance stopped"))
    }

    /// Runs `task` on the instance's runtime with what dials through its
    /// outbounds and what is left of `within`, and waits for it, from any
    /// executor: while it runs, and while it starts, where a call made
    /// before the outbounds are built waits for them (`Inner::dialer`).
    pub(super) async fn with_dialer<T: Send + 'static>(
        &self,
        within: Duration,
        task: impl FnOnce(crate::control::Dialer, Duration) -> BoxFuture<'static, T>,
    ) -> Result<T, Error> {
        let asked = std::time::Instant::now();
        let dialer = self.inner().dialer(within).await?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = task(dialer.clone(), within.saturating_sub(asked.elapsed()));
        // The instance's task, as a host call's is: what the dial spawns
        // is the instance's, and a stop waits for it.
        dialer
            .env()
            .scope
            .spawn_on(dialer.handle(), "host dial", async move {
                let _ = tx.send(task.await);
            });
        rx.await.map_err(|_| Error::state("the instance stopped"))
    }

    /// `with_manager`, blocking this thread; on one of the instance's own,
    /// a WrongThread error.
    #[doc(hidden)]
    pub fn blocking_with_manager<T: Send + 'static>(
        &self,
        task: impl FnOnce(Arc<RuntimeManager>) -> BoxFuture<'static, T>,
    ) -> Result<T, Error> {
        if self.on_own_thread() {
            return Err(Error::new(
                ErrorKind::WrongThread,
                "called on a thread of the instance's own, where it would wait on itself",
            ));
        }
        futures::executor::block_on(self.with_manager(task))
    }
}

impl Inner {
    /// What the instance runs with of the host's.
    pub(super) fn host(&self) -> &Host {
        &self.host
    }

    /// What dials through the instance's outbounds: at once while it runs,
    /// and while it starts once they are built. A dial asked for earlier
    /// in a start waits for that, `within` at most, and is told
    /// `NotRunning` if the start fails or is stopped meanwhile. Any other
    /// state: `NotRunning`. It waits on no runtime, the host's nor sail's:
    /// the host may call from any executor.
    pub(super) async fn dialer(&self, within: Duration) -> Result<crate::control::Dialer, Error> {
        let mut dialers = self.dialer.subscribe();
        let mut states = self.state.subscribe();
        let mut expiry = None;
        loop {
            if let Some(dialer) = dialers.borrow_and_update().clone() {
                return Ok(dialer);
            }
            if !matches!(*states.borrow_and_update(), State::Starting) {
                return Err(Error::not_running());
            }
            let (expired, _waiting) = expiry.get_or_insert_with(|| expires(within));
            tokio::select! {
                biased;
                changed = dialers.changed() => {
                    if changed.is_err() {
                        return Err(Error::not_running());
                    }
                }
                changed = states.changed() => {
                    if changed.is_err() {
                        return Err(Error::not_running());
                    }
                }
                _ = expired => {
                    return Err(Error::new(
                        ErrorKind::Timeout,
                        "the instance was still building its outbounds",
                    ));
                }
            }
        }
    }

    /// The network of the run starting or running, from when the one it
    /// starts on is settled.
    pub(super) fn network(&self) -> Result<Arc<crate::runtime::RuntimeEnv>, Error> {
        lock(&self.life).env.clone().ok_or_else(Error::not_running)
    }

    /// What controls the instance, while it runs.
    pub(super) fn manager(&self) -> Result<Arc<RuntimeManager>, Error> {
        lock(&self.life)
            .manager
            .clone()
            .ok_or_else(Error::not_running)
    }

    /// The state, as each change is followed.
    pub(super) fn states(&self) -> tokio::sync::watch::Receiver<State> {
        self.state.subscribe()
    }

    /// Each change of state from now on, in order.
    pub(super) fn transitions(&self) -> tokio::sync::broadcast::Receiver<State> {
        self.transitions.subscribe()
    }

    pub(super) fn events(&self) -> &crate::control::events::EventHub {
        &self.events
    }

    fn publish(&self, life: &Life) {
        let state = match life.phase {
            Phase::Idle => State::Idle,
            Phase::Starting => State::Starting,
            Phase::Running => State::Running {
                since: life.started_at.unwrap_or_else(SystemTime::now),
            },
            Phase::Stopping => State::Stopping,
            Phase::Stopped => State::Stopped,
            Phase::Failed => State::Failed(
                life.failure
                    .clone()
                    .unwrap_or_else(|| Error::new(ErrorKind::Internal, "the instance failed")),
            ),
        };
        let _ = self.transitions.send(state.clone());
        self.state.send_replace(state);
        self.changed.notify_all();
    }

    /// Spawns the run; the instance is starting when it returns.
    fn start(&self, config: Config) -> Result<tokio::sync::watch::Receiver<State>, Error> {
        let mut life = lock(&self.life);
        if life.phase.live() {
            return Err(Error::state(format!(
                "the instance is {} already",
                life.phase.name()
            )));
        }
        // The last run's thread has ended, or is ending.
        if let Some(thread) = life.thread.take() {
            let _ = thread.join();
        }
        let this = self
            .me
            .upgrade()
            .ok_or_else(|| Error::state("the instance is being freed"))?;
        let mut host = self.host.clone();
        host.platform = Some(PlatformRef(Arc::new(Running {
            host: self.platform.clone(),
            instance: self.me.clone(),
        })));
        host.log = Some(InstanceLogRef(self.log.clone()));
        host.clash_modes = self.clash_modes;
        host.events = Some(self.events.clone());
        let options = crate::StartOptions {
            signals: false,
            config: match config {
                Config::Json(text) => crate::Config::Str(text),
                Config::File(path) => crate::Config::File(path.to_string_lossy().into_owned()),
            },
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: match (&self.runtime, self.threads) {
                (super::Runtime::Host(handle), _) => crate::RuntimeOption::Handle(handle.clone()),
                (_, Threads::One) => crate::RuntimeOption::SingleThread,
                (_, Threads::Auto) => crate::RuntimeOption::MultiThreadAuto(super::STACK_SIZE),
                (_, Threads::Workers(n, stack)) => crate::RuntimeOption::MultiThread(n, stack),
            },
            runtime: self.options.clone(),
            host,
        };
        let id = self.id;
        let states = self.state.subscribe();
        let thread = std::thread::Builder::new()
            .name(format!("sail-{}", id))
            .spawn(move || {
                let stopped = lock(&this.life).stop;
                let result = if stopped {
                    Ok(Ok(()))
                } else {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        crate::start(id, options)
                    }))
                };
                if result.is_err() {
                    // What a run that unwound left registered.
                    crate::forget(id);
                }
                this.finished(result);
            })
            .map_err(|e| Error::new(ErrorKind::Io, e.to_string()))?;
        life.phase = Phase::Starting;
        life.failure = None;
        life.stop = false;
        life.started_at = None;
        life.thread_id = Some(thread.thread().id());
        life.thread = Some(thread);
        self.publish(&life);
        Ok(states)
    }

    /// How a start ended, once it has.
    fn started(&self) -> Result<(), Error> {
        let life = lock(&self.life);
        match life.phase {
            Phase::Running => Ok(()),
            Phase::Failed => Err(life
                .failure
                .clone()
                .unwrap_or_else(|| Error::state("the instance failed"))),
            _ => Err(Error::new(
                ErrorKind::Cancelled,
                "the instance was stopped while it started",
            )),
        }
    }

    /// Told by the core, on the thread starting it, that the network it
    /// starts on is settled.
    fn settled(&self, env: Arc<crate::runtime::RuntimeEnv>) {
        let mut life = lock(&self.life);
        // This run's from here: a start that fails before it runs tells
        // what its teardown left through it.
        life.scope = Some(env.scope.clone());
        life.env = Some(env);
    }

    /// Told by the core, on the thread starting it, that its outbounds
    /// are built: those who wait to dial go on.
    fn dialable(&self, dialer: crate::control::Dialer) {
        self.dialer.send_replace(Some(dialer));
    }

    /// Told by the core, on the thread starting it, that it runs.
    fn running(&self, manager: Arc<RuntimeManager>) {
        let mut life = lock(&self.life);
        if life.stop {
            // Asked to stop before the core had it to stop.
            manager.blocking_shutdown();
            life.phase = Phase::Stopping;
        } else {
            life.phase = Phase::Running;
            life.started_at = Some(SystemTime::now());
        }
        life.scope = Some(manager.env.scope.clone());
        life.manager = Some(manager);
        self.publish(&life);
    }

    fn finished(&self, result: std::thread::Result<Result<(), crate::Error>>) {
        let mut life = lock(&self.life);
        life.manager = None;
        life.env = None;
        // Before the state is told: one who waits to dial sees no dialer,
        // and the state the run ended in.
        self.dialer.send_replace(None);
        life.thread_id = None;
        match result {
            Ok(Ok(())) => life.phase = Phase::Stopped,
            Ok(Err(e)) => {
                life.phase = Phase::Failed;
                let failure = Error::from(e);
                // A start that failed tells what its teardown left too.
                let left = life
                    .scope
                    .as_ref()
                    .and_then(|s| s.report())
                    .map(|r| r.left)
                    .unwrap_or_default();
                let failure = if left.is_empty() || failure.message().contains(crate::LEFT_SAID) {
                    failure
                } else {
                    Error::new(
                        failure.kind(),
                        crate::with_left(failure.message().to_string(), &left),
                    )
                };
                life.failure = Some(failure.with_left(left));
            }
            Err(panic) => {
                let what = panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "a panic".to_string());
                life.phase = Phase::Failed;
                life.failure = Some(Error::new(
                    ErrorKind::Panicked,
                    format!("sail panicked: {}", what),
                ));
            }
        }
        self.publish(&life);
    }

    /// Asks it to stop, without waiting; none when it does not run.
    fn ask_stop(&self) -> Option<tokio::sync::watch::Receiver<State>> {
        let mut life = lock(&self.life);
        if !life.phase.live() {
            return None;
        }
        life.stop = true;
        if life.phase != Phase::Stopping {
            life.phase = Phase::Stopping;
            self.publish(&life);
        }
        let manager = life.manager.clone();
        let states = self.state.subscribe();
        drop(life);
        // Either the running instance, or its start, takes it; one not in
        // the core yet sees `stop` when it gets there.
        match manager {
            Some(manager) => {
                manager.blocking_shutdown();
            }
            None => {
                crate::shutdown(self.id);
            }
        }
        Some(states)
    }

    /// `Ok`, or a Timeout naming what the last stop could not end.
    fn leftovers(&self) -> Result<(), Error> {
        let report = lock(&self.life).scope.as_ref().and_then(|s| s.report());
        match report {
            Some(report) if !report.tasks.is_empty() => Err(Error::new(
                ErrorKind::Timeout,
                crate::with_left(
                    format!(
                        "stopped, with tasks still running after {:?}: {:?}",
                        report.waited, report.tasks
                    ),
                    &report.left,
                ),
            )
            .with_left(report.left)),
            Some(report) if !report.left.is_empty() => Err(Error::new(
                ErrorKind::Failed,
                crate::with_left("stopped".to_string(), &report.left),
            )
            .with_left(report.left)),
            _ => Ok(()),
        }
    }

    /// Joins the thread of a run that has ended; it ends right after it
    /// says so.
    fn join(&self) {
        let mut life = lock(&self.life);
        if life.phase.live() {
            return;
        }
        if let Some(thread) = life.thread.take() {
            drop(life);
            if thread.thread().id() != std::thread::current().id() {
                let _ = thread.join();
            }
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        lock(&IDS).remove(&self.id);
    }
}

/// The platform an instance runs with: the host's, and the instance to
/// tell once it runs.
struct Running {
    host: Option<Arc<dyn Platform>>,
    instance: Weak<Inner>,
}

impl Platform for Running {
    fn log(&self, line: &str) {
        if let Some(host) = &self.host {
            host.log(line);
        }
    }

    fn protects_sockets(&self) -> bool {
        self.host.as_ref().is_some_and(|h| h.protects_sockets())
    }

    fn protect_socket(&self, fd: i32) -> std::io::Result<()> {
        match &self.host {
            Some(host) => host.protect_socket(fd),
            None => Ok(()),
        }
    }

    fn opens_tun(&self) -> bool {
        self.host.as_ref().is_some_and(|h| h.opens_tun())
    }

    fn open_tun(&self, request: &crate::runtime::TunRequest) -> std::io::Result<i32> {
        match &self.host {
            Some(host) => host.open_tun(request),
            None => Err(std::io::Error::from(std::io::ErrorKind::Unsupported)),
        }
    }

    fn finds_connection_owner(&self) -> bool {
        self.host
            .as_ref()
            .is_some_and(|h| h.finds_connection_owner())
    }

    fn find_connection_owner(
        &self,
        query: &crate::runtime::platform::ConnectionQuery,
    ) -> std::io::Result<Option<crate::runtime::platform::ConnectionOwner>> {
        match &self.host {
            Some(host) => host.find_connection_owner(query),
            None => Ok(None),
        }
    }

    fn settled(&self, env: &Arc<crate::runtime::RuntimeEnv>) {
        if let Some(host) = &self.host {
            host.settled(env);
        }
        if let Some(instance) = self.instance.upgrade() {
            instance.settled(env.clone());
        }
    }

    fn dialable(&self, dialer: &crate::control::Dialer) {
        if let Some(host) = &self.host {
            host.dialable(dialer);
        }
        if let Some(instance) = self.instance.upgrade() {
            instance.dialable(dialer.clone());
        }
    }

    fn running(&self, manager: &Arc<RuntimeManager>) {
        if let Some(host) = &self.host {
            host.running(manager);
        }
        if let Some(instance) = self.instance.upgrade() {
            instance.running(manager.clone());
        }
    }
}

/// Resolves `after` from now, on a thread of its own that ends then, or
/// as soon as the guard returned with it is dropped: a timer for a wait
/// that may run on any executor, or none of tokio's.
fn expires(
    after: Duration,
) -> (
    tokio::sync::oneshot::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (expired, rx) = tokio::sync::oneshot::channel();
    let (waiting, done) = std::sync::mpsc::channel::<()>();
    // Shared, so that it is not dropped with a thread that never ran:
    // dropped, it would read as expired.
    let expired = Arc::new(Mutex::new(Some(expired)));
    let timer = std::thread::Builder::new()
        .name("sail-dial-wait".into())
        .spawn({
            let expired = expired.clone();
            move || {
                if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = done.recv_timeout(after) {
                    if let Some(expired) = lock(&expired).take() {
                        let _ = expired.send(());
                    }
                }
            }
        });
    // No thread to be had: it never expires, and the wait ends with the
    // start, which is bounded.
    if timer.is_err() {
        if let Some(expired) = lock(&expired).take() {
            std::mem::forget(expired);
        }
    }
    (rx, waiting)
}

/// The runtime ids the instances alive hold: for tests that none leak.
#[doc(hidden)]
pub fn ids_held() -> usize {
    lock(&IDS).len()
}
