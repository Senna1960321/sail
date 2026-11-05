//! What the host follows of an instance, pushed to its callbacks: the
//! state, the log, the traffic, the connections, the outbounds. Every
//! callback of an instance is called on one thread of its own, the
//! instance's events thread, never while sail holds a lock of its own.

use std::ffi::{c_char, c_void, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::thread::{JoinHandle, ThreadId};
use std::time::Duration;

use serde::Serialize;

use crate::handles::Table;
use crate::instance::{Instance, SailInstance};
use crate::{call, json, opt_str_arg, out_value, Failure};

/// A subscription, as the host holds it; 0 is none.
pub type SailSubscription = u64;

/// Takes an event of `kind`, its JSON `json` (sail's, valid during the
/// call only), and the subscription's `context`.
pub type SailEventCallback = extern "C" fn(kind: u32, json: *const c_char, context: *mut c_void);

/// Releases the context of a subscription, once, after its last event.
pub type SailReleaseCallback = extern "C" fn(context: *mut c_void);

/// The instance's state, as `sail_instance_state` gives it: now, then on
/// each change.
pub const SAIL_EVENT_STATE: u32 = 1;
/// The instance's log: `{"reset", "lines": [{"level", "message",
/// "time_ms"}], "dropped"}`. Options: `{"level": "info"}` (every level
/// when unset), `{"backlog": false}` to leave out the lines kept before.
/// `reset` true: drop the lines had so far (the first event, and after a
/// `sail_clear_logs`). `dropped`: lines left out since the last event, as
/// the callback was too slow for them.
pub const SAIL_EVENT_LOG: u32 = 2;
/// The traffic, each interval while the instance runs: `{"up", "down"}`
/// in bytes a second, `"up_total", "down_total", "connections",
/// "memory"`. Options: `{"interval_ms": 1000}`.
pub const SAIL_EVENT_STATUS: u32 = 3;
/// The connections open, each interval while the instance runs, as
/// `sail_connections` gives them. Options: `{"interval_ms": 1000}`.
pub const SAIL_EVENT_CONNECTIONS: u32 = 4;
/// The outbounds and groups, as `sail_outbounds` gives them, when they
/// change: a selection, a delay measured. Options: `{"interval_ms": 250}`,
/// how often they are looked at.
pub const SAIL_EVENT_OUTBOUNDS: u32 = 5;
/// A change of network the connections made on the one before do not
/// survive: `{"generation", "reason": "default-interface" |
/// "state" | "host" | "wake", "old", "new"}`, the networks as
/// `sail_set_network_state` takes them; while the instance runs. In the
/// tunnel process only: a command service client's subscription fails with
/// SAIL_ERR_UNSUPPORTED, as libbox's apps follow the network there.
pub const SAIL_EVENT_NETWORK: u32 = 6;
/// A command service client's connection was lost, or the service closed:
/// `{"error": why, or null}`, once, the subscription's last event. Its
/// release follows.
pub const SAIL_EVENT_DISCONNECTED: u32 = 7;

/// A task of the instance panicked: `{"task", "class": "contained" |
/// "essential", "message", "count"}`, `count` the instance's contained
/// panics so far. A contained panic ended that task alone and the instance
/// goes on; an essential one failed it, which the state event tells too.
/// Through stops and starts; `{"lagged": missed}` when the host fell
/// behind and that many are gone. In the tunnel process only.
pub const SAIL_EVENT_FAULT: u32 = 8;
/// Each connection once it is routed, and dialled where the rules sent it
/// to an outbound: `{"id", "network", "inbound", "user", "source", "destination",
/// "request_destination", "domain", "domain_source", "sniffed_protocol",
/// "rule", "rule_text", "action": "outbound" | "reject" | "drop" |
/// "hijack_dns", "chain", "target", "connect_ms", "connect_error"}`; the
/// short ones, the rejected and the failed too, which a list of the
/// connections open misses. Built only while someone follows them.
/// `{"lagged": missed}` as for faults. In the tunnel process only.
pub const SAIL_EVENT_ROUTED: u32 = 9;
/// Each DNS query answered or failed, a client's or the instance's own:
/// `{"name", "qtype", "qtype_code", "server", "source": "exchanged" |
/// "cached" | "optimistic" | "rule", "rcode", "rcode_code", "error",
/// "answers", "answers_total", "ttl", "duration_ms", "attempt",
/// "for_instance"}`. Built only while someone follows them. `{"lagged":
/// missed}` as for faults. In the tunnel process only.
pub const SAIL_EVENT_DNS: u32 = 10;
/// A group took another member: `{"group", "from", "to", "reason":
/// "member_down" | "test_failed" | "recovered" | "all_down" | "pinned" |
/// "unpinned" | "selected" | "faster" | "members_changed"}`.
/// `{"lagged": missed}` as for faults. In the tunnel process only.
pub const SAIL_EVENT_GROUP: u32 = 11;
/// Dials through a chain failed, one event for each chain a second at
/// most: `{"chain", "destination", "error", "stage": "dial" | "handshake" |
/// "transfer", "more_to_try", "count"}`. `{"lagged": missed}` as for
/// faults. In the tunnel process only.
pub const SAIL_EVENT_DIAL: u32 = 12;
/// What happened to a user: `{"event": "shut" | "removed", "user",
/// "over_quota", "expired", "inbound"}`. `{"lagged": missed}` as for
/// faults. In the tunnel process only.
pub const SAIL_EVENT_USER: u32 = 13;
/// Something sail set up on the system for a TUN (a route, its DNS, its
/// address) that someone else changed, and that sail left as it is:
/// `{"kind": "route" | "dns" | "tun", "resource"}`, `resource` naming the
/// TUN first ("route 0.0.0.0/0 into tun0: gone"). Told once a break, and
/// again only once a check found it right in between; restoring it or
/// rebuilding the instance is the host's. Through stops and starts;
/// `{"lagged": missed}` as for faults. In the tunnel process only.
pub const SAIL_EVENT_SYSTEM: u32 = 14;
/// What each connection sent and received, for a host that counts traffic
/// by connection: one record when it closes, and one at each interim pass
/// that finds bytes new since its record before, or that the host asked
/// for, each with the bytes since the connection started: `{"id", "run_ms",
/// "seq", "kind": "interim" | "closed", "end": "finished" | "error" |
/// "idle_timeout" | "write_stall" | "closed" | "aborted", "error",
/// "closed_by": "api" | "user" | "inbound" | "rules" | "network" |
/// "stopped" | "host", "outcome": "ok" | "dial_failed" | "blocked" |
/// "rejected", "reason" (why the host's check refused it), "network", "user", "inbound", "source", "local", "destination",
/// "request_destination", "domain", "domain_source", "outbound", "chain",
/// "up_total", "down_total", "start_ms", "at_ms", "parent_id" (the root UDP
/// association for an additional target attempt, otherwise null)}`; a connection's closed
/// record has what its user was counted. Built only
/// while someone follows them. Through stops and starts; `{"lagged":
/// missed}` as for faults. In the tunnel process only.
pub const SAIL_EVENT_CONNECTION_RECORD: u32 = 15;

/// Intervals shorter are taken as this: a host cannot ask for a busy loop.
const INTERVAL_MIN: Duration = Duration::from_millis(100);
/// Lines to an event, at most.
const LOG_BATCH: usize = 256;

static SUBSCRIPTIONS: Mutex<Table<Subscription>> = Mutex::new(Table::new());

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// An instance's events thread: a runtime its subscriptions run on, and
/// call their callbacks from.
pub(crate) struct Events {
    handle: tokio::runtime::Handle,
    stop: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    thread_id: ThreadId,
    /// The subscriptions it runs, by handle.
    subscriptions: Mutex<Vec<SailSubscription>>,
}

impl Events {
    pub fn new(id: sail::RuntimeId) -> Result<Self, Failure> {
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name(format!("sail-events-{}", id))
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = handle_tx.send(Err(e.to_string()));
                        return;
                    }
                };
                let _ = handle_tx.send(Ok(rt.handle().clone()));
                let _ = rt.block_on(stopped);
                // The subscriptions go here, each context released on this
                // thread.
                drop(rt);
            })
            .map_err(|e| Failure::new(crate::SAIL_ERR_IO, e.to_string()))?;
        let thread_id = thread.thread().id();
        let handle = handle_rx
            .recv()
            .map_err(|_| Failure::new(crate::SAIL_ERR_INTERNAL, "the events thread ended"))?
            .map_err(|e| Failure::new(crate::SAIL_ERR_IO, e))?;
        Ok(Self {
            handle,
            stop: Mutex::new(Some(stop)),
            thread: Mutex::new(Some(thread)),
            thread_id,
            subscriptions: Mutex::new(Vec::new()),
        })
    }

    /// The runtime of the events thread.
    #[cfg(feature = "command-server")]
    pub fn handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    pub fn is_current(&self) -> bool {
        std::thread::current().id() == self.thread_id
    }

    /// Ends every subscription, and the thread. On the thread itself, it
    /// ends after the callback running returns.
    pub fn close(&self) {
        for sub in std::mem::take(&mut *lock(&self.subscriptions)) {
            if let Some(sub) = lock(&SUBSCRIPTIONS).remove(sub) {
                sub.active.store(false, Ordering::SeqCst);
            }
        }
        if let Some(stop) = lock(&self.stop).take() {
            let _ = stop.send(());
        }
        if !self.is_current() {
            if let Some(thread) = lock(&self.thread).take() {
                let _ = thread.join();
            }
        }
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        self.close();
    }
}

struct Subscription {
    /// Cleared when unsubscribed: no callback after.
    active: AtomicBool,
    task: OnceLock<tokio::task::AbortHandle>,
    done: Mutex<bool>,
    finished: Condvar,
    events_thread: ThreadId,
}

/// Where a subscription's events go: the host's callback. Released, once,
/// when the task holding it goes.
pub(crate) struct Sink {
    kind: u32,
    callback: SailEventCallback,
    context: *mut c_void,
    release: Option<SailReleaseCallback>,
    subscription: Arc<Subscription>,
}

// SAFETY: the host's contract: its context may be passed to its callbacks
// from any thread; sail passes it on the events thread only.
unsafe impl Send for Sink {}

impl Sink {
    fn call(&self, event: &impl Serialize) {
        if !self.subscription.active.load(Ordering::SeqCst) {
            return;
        }
        let Ok(json) = serde_json::to_string(event) else {
            return;
        };
        let Ok(json) = CString::new(json) else {
            return;
        };
        (self.callback)(self.kind, json.as_ptr(), self.context);
    }

    fn active(&self) -> bool {
        self.subscription.active.load(Ordering::SeqCst)
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            release(self.context);
        }
        *lock(&self.subscription.done) = true;
        self.subscription.finished.notify_all();
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Options {
    pub interval_ms: Option<u64>,
    pub level: Option<String>,
    pub backlog: Option<bool>,
}

/// The interval asked for, else `default`; never shorter than the least.
pub(crate) fn interval(asked_ms: Option<u64>, default: Duration) -> Duration {
    asked_ms
        .filter(|ms| *ms > 0)
        .map_or(default, Duration::from_millis)
        .max(INTERVAL_MIN)
}

/// The least severe level asked for: every one when none.
pub(crate) fn level(asked: Option<&str>) -> Result<tracing::Level, Failure> {
    Ok(match asked.filter(|l| !l.is_empty()) {
        None | Some("trace") => tracing::Level::TRACE,
        Some("debug") => tracing::Level::DEBUG,
        Some("info") => tracing::Level::INFO,
        Some("warn") | Some("warning") => tracing::Level::WARN,
        Some("error") => tracing::Level::ERROR,
        Some(other) => return Err(Failure::invalid(format!("level: \"{}\" is none", other))),
    })
}

/// Follows what `kind` names of the instance: `callback` is called with
/// each event, on the instance's events thread, in order, one at a time.
/// A slow callback delays only its instance's events: a status or the
/// connections are then sent less often, log lines left out and counted.
/// A callback may call any sail function, for this instance too.
///
/// @param options JSON, the kind's options, or null.
/// @param context Passed to `callback` and `release`.
/// @param release Called once, on the events thread or the one ending the
///     subscription, after the last event: when unsubscribed, or the
///     instance freed. Null for none. When the call fails, sail keeps
///     nothing of `context` and never calls it.
/// @param out Takes the subscription's handle.
/// @return SAIL_ERR_UNSUPPORTED for a kind this build does not follow.
#[no_mangle]
pub unsafe extern "C" fn sail_subscribe(
    instance: SailInstance,
    kind: u32,
    options: *const c_char,
    callback: Option<extern "C" fn(kind: u32, json: *const c_char, context: *mut c_void)>,
    context: *mut c_void,
    release: Option<extern "C" fn(context: *mut c_void)>,
    out: *mut SailSubscription,
    err: *mut *mut c_char,
) -> i32 {
    call(err, || {
        if out.is_null() {
            return Err(Failure::invalid("the out pointer is null"));
        }
        let callback = callback.ok_or_else(|| Failure::invalid("the callback is null"))?;
        let options: Options = match unsafe { opt_str_arg(options, "options") }? {
            Some(json) => serde_json::from_str(json)
                .map_err(|e| Failure::invalid(format!("options: {}", e)))?,
            None => Options::default(),
        };
        let target = crate::instance::target(instance)?;
        let events = match &target {
            crate::instance::Target::Local(instance) => &instance.events,
            #[cfg(feature = "command-server")]
            crate::instance::Target::Remote(client) => &client.events,
        };
        let subscription = Arc::new(Subscription {
            active: AtomicBool::new(true),
            task: OnceLock::new(),
            done: Mutex::new(false),
            finished: Condvar::new(),
            events_thread: events.thread_id,
        });
        // Checked before the sink exists: a failure releases nothing.
        let make = match &target {
            crate::instance::Target::Local(instance) => produce(kind, &options, instance)?,
            #[cfg(feature = "command-server")]
            crate::instance::Target::Remote(client) => {
                crate::command::client::produce(kind, &options, client)?
            }
        };
        let sink = Sink {
            kind,
            callback,
            context,
            release,
            subscription: subscription.clone(),
        };
        let task = events.handle.spawn(make(sink));
        let _ = subscription.task.set(task.abort_handle());
        let handle = lock(&SUBSCRIPTIONS).insert(subscription);
        lock(&events.subscriptions).push(handle);
        out_value(out, handle)
    })
}

/// Ends a subscription. Once it returns, its callback is not called again,
/// and its release has been called, but on the instance's events thread
/// (from a callback), where the callback running returns first, and the
/// release follows. A callback that waits on a lock the thread calling
/// this holds would wait for ever: don't.
///
/// @return SAIL_ERR_NO_INSTANCE for a subscription ended already, or its
///     instance freed.
#[no_mangle]
pub extern "C" fn sail_unsubscribe(subscription: SailSubscription, err: *mut *mut c_char) -> i32 {
    call(err, || {
        let sub = lock(&SUBSCRIPTIONS)
            .remove(subscription)
            .ok_or_else(|| Failure::new(crate::SAIL_ERR_NO_INSTANCE, "no such subscription"))?;
        sub.active.store(false, Ordering::SeqCst);
        if let Some(task) = sub.task.get() {
            task.abort();
        }
        if std::thread::current().id() != sub.events_thread {
            let done = lock(&sub.done);
            let _done = sub
                .finished
                .wait_while(done, |done| !*done)
                .unwrap_or_else(|e| e.into_inner());
        }
        Ok(())
    })
}

/// Where what is followed goes: a host's callback, or a command service
/// client's stream. False once it takes no more, which ends the following.
pub(crate) trait Emit<T>: Send {
    fn emit(&mut self, value: T) -> impl std::future::Future<Output = bool> + Send;

    /// Whether it still takes them.
    fn open(&self) -> bool;
}

impl<T: Serialize + Send + 'static> Emit<T> for Sink {
    async fn emit(&mut self, value: T) -> bool {
        self.call(&value);
        self.active()
    }

    fn open(&self) -> bool {
        self.active()
    }
}

pub(crate) type Producer = Box<dyn FnOnce(Sink) -> futures::future::BoxFuture<'static, ()> + Send>;

#[cfg(feature = "command-server")]
impl Emit<crate::command::client::Disconnected> for Sink {
    async fn emit(&mut self, value: crate::command::client::Disconnected) -> bool {
        #[derive(Serialize)]
        struct Event {
            error: Option<String>,
        }
        let kind = std::mem::replace(&mut self.kind, SAIL_EVENT_DISCONNECTED);
        self.call(&Event { error: value.error });
        self.kind = kind;
        self.active()
    }

    fn open(&self) -> bool {
        self.active()
    }
}

/// What follows `kind` of `instance`, given the sink its events go to.
fn produce(kind: u32, options: &Options, instance: &Arc<Instance>) -> Result<Producer, Failure> {
    let weak = Arc::downgrade(instance);
    Ok(match kind {
        SAIL_EVENT_STATE => {
            let state = instance.states();
            Box::new(move |sink| Box::pin(follow_state(sink, state)))
        }
        SAIL_EVENT_LOG => {
            let least = level(options.level.as_deref())?;
            let backlog = options.backlog.unwrap_or(true);
            let log = instance.log.clone();
            Box::new(move |sink| Box::pin(follow_log(sink, log, least, backlog)))
        }
        SAIL_EVENT_STATUS => {
            let every = interval(options.interval_ms, Duration::from_secs(1));
            Box::new(move |sink| Box::pin(follow_status(sink, weak, every)))
        }
        SAIL_EVENT_CONNECTIONS => {
            let every = interval(options.interval_ms, Duration::from_secs(1));
            Box::new(move |sink| Box::pin(follow_connections(sink, weak, every)))
        }
        SAIL_EVENT_OUTBOUNDS => {
            let every = interval(options.interval_ms, Duration::from_millis(250));
            Box::new(move |sink| Box::pin(follow_outbounds(sink, weak, every, false)))
        }
        SAIL_EVENT_NETWORK => {
            // Changes from this call on, through stops and starts: taken
            // now, not when the task starts on the events thread.
            let changes = instance.core().network_changes();
            Box::new(move |sink| Box::pin(follow_network(sink, changes)))
        }
        SAIL_EVENT_FAULT => {
            let events = instance.core().events(sail::embed::Kinds::FAULT);
            Box::new(move |sink| {
                Box::pin(follow_embed(sink, events, |event| match event {
                    sail::embed::Event::Fault(fault) => {
                        serde_json::to_value(json::Fault::of(&fault)).ok()
                    }
                    _ => None,
                }))
            })
        }
        SAIL_EVENT_ROUTED => {
            embed_events(instance, sail::embed::Kinds::ROUTE, |event| match event {
                sail::embed::Event::Routed(routed) => {
                    serde_json::to_value(json::Routed::of(&routed)).ok()
                }
                _ => None,
            })
        }
        SAIL_EVENT_DNS => embed_events(instance, sail::embed::Kinds::DNS, |event| match event {
            sail::embed::Event::DnsExchange(e) => {
                serde_json::to_value(json::DnsExchange::of(&e)).ok()
            }
            _ => None,
        }),
        SAIL_EVENT_GROUP => {
            embed_events(instance, sail::embed::Kinds::GROUP, |event| match event {
                sail::embed::Event::GroupSwitched(s) => {
                    serde_json::to_value(json::GroupSwitch::of(&s)).ok()
                }
                _ => None,
            })
        }
        SAIL_EVENT_DIAL => embed_events(instance, sail::embed::Kinds::DIAL, |event| match event {
            sail::embed::Event::DialFailed { failure, count } => {
                serde_json::to_value(json::DialFailed::of(&failure, count)).ok()
            }
            _ => None,
        }),
        SAIL_EVENT_USER => embed_events(instance, sail::embed::Kinds::USER, |event| match event {
            sail::embed::Event::User(user) => {
                user_event(user).and_then(|u| serde_json::to_value(u).ok())
            }
            _ => None,
        }),
        SAIL_EVENT_SYSTEM => {
            embed_events(instance, sail::embed::Kinds::SYSTEM, |event| match event {
                sail::embed::Event::SystemChanged { kind, resource } => {
                    serde_json::to_value(json::SystemChange::of(kind, &resource)).ok()
                }
                _ => None,
            })
        }
        SAIL_EVENT_CONNECTION_RECORD => embed_events(
            instance,
            sail::embed::Kinds::CONNECTION,
            |event| match event {
                sail::embed::Event::ConnectionRecord(record) => {
                    serde_json::to_value(json::ConnectionRecord::of(&record)).ok()
                }
                _ => None,
            },
        ),
        other => return Err(Failure::invalid(format!("no event kind {}", other))),
    })
}

/// A user's event, as the management API tells it; none for a kind this
/// sail does not tell yet.
fn user_event(event: sail::embed::UserEvent) -> Option<json::UserEvent> {
    Some(match event {
        sail::embed::UserEvent::Shut {
            user,
            over_quota,
            expired,
        } => json::UserEvent {
            event: "shut",
            user,
            over_quota,
            expired,
            inbound: None,
        },
        sail::embed::UserEvent::Removed { user, inbound } => json::UserEvent {
            event: "removed",
            user,
            over_quota: false,
            expired: false,
            inbound: Some(inbound),
        },
        _ => return None,
    })
}

/// The producer of embed's events of `kinds`, each told as `tell` makes
/// it of JSON (`follow_embed`).
fn embed_events(
    instance: &Arc<Instance>,
    kinds: sail::embed::Kinds,
    tell: fn(sail::embed::Event) -> Option<serde_json::Value>,
) -> Producer {
    let events = instance.core().events(kinds);
    Box::new(move |sink| Box::pin(follow_embed(sink, events, tell)))
}

/// What embed tells of a kind, each event as `tell` makes it of JSON;
/// `{"lagged": missed}` when the host fell behind on it. Through stops and
/// starts, as embed's events go.
async fn follow_embed(
    mut out: impl Emit<serde_json::Value>,
    events: impl futures::Stream<Item = sail::embed::Event> + Send + 'static,
    tell: impl Fn(sail::embed::Event) -> Option<serde_json::Value> + Send + 'static,
) {
    use futures::StreamExt;
    let mut events = Box::pin(events);
    while out.open() {
        let Some(event) = events.next().await else {
            return;
        };
        let told = match event {
            sail::embed::Event::Lagged { missed, .. } => {
                Some(serde_json::json!({ "lagged": missed }))
            }
            event => tell(event),
        };
        if let Some(told) = told {
            if !out.emit(told).await {
                return;
            }
        }
    }
}

/// Each change of network: through stops and starts, each run's, its
/// generations from 1. A change missed by a slow host is skipped; the next
/// carries the network as it is. Ends when the instance is freed.
async fn follow_network(
    mut out: impl Emit<json::NetworkEvent>,
    mut changes: tokio::sync::broadcast::Receiver<Arc<sail::net::network::NetworkChange>>,
) {
    use tokio::sync::broadcast::error::RecvError;
    while out.open() {
        match changes.recv().await {
            Ok(change) => {
                if !out.emit(json::NetworkEvent::of(&change)).await {
                    return;
                }
            }
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => return,
        }
    }
}

/// Each `every`, what controls the instance, while it runs; none once it
/// is freed.
pub(crate) async fn tick(
    ticker: &mut tokio::time::Interval,
    instance: &Weak<Instance>,
) -> Option<Option<Arc<sail::RuntimeManager>>> {
    ticker.tick().await;
    let instance = instance.upgrade()?;
    Some(instance.manager().ok())
}

pub(crate) fn ticker(every: Duration) -> tokio::time::Interval {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker
}

/// The state, then each change.
pub(crate) async fn follow_state(
    mut out: impl Emit<json::State>,
    mut state: tokio::sync::watch::Receiver<sail::embed::State>,
) {
    loop {
        let now = crate::instance::state_json(&state.borrow_and_update());
        if !out.emit(now).await || state.changed().await.is_err() {
            return;
        }
    }
}

async fn follow_connections(
    mut out: impl Emit<json::Connections>,
    instance: Weak<Instance>,
    every: Duration,
) {
    use futures::StreamExt;
    let Some(instance) = instance.upgrade() else {
        return;
    };
    let mut lists = Box::pin(instance.core().watch_connections(every));
    drop(instance);
    while let Some(list) = lists.next().await {
        let connections = json::Connections {
            connections: list.iter().map(json::Connection::of).collect(),
        };
        if !out.emit(connections).await {
            return;
        }
    }
}

/// The traffic each `every`, with its rate since the last, while the
/// instance runs: sail::embed's.
pub(crate) async fn follow_status(
    mut out: impl Emit<json::Status>,
    instance: Weak<Instance>,
    every: Duration,
) {
    use futures::StreamExt;
    let Some(instance) = instance.upgrade() else {
        return;
    };
    let mut statuses = Box::pin(instance.core().status(every));
    drop(instance);
    while let Some(s) = statuses.next().await {
        let status = json::Status {
            up: s.up,
            down: s.down,
            up_total: s.up_total,
            down_total: s.down_total,
            connections: s.connections,
            memory: s.memory,
            faults: s.faults,
        };
        if !out.emit(status).await {
            return;
        }
    }
}

/// The outbounds (or the groups only), when they change, while the
/// instance runs: sail::embed's.
pub(crate) async fn follow_outbounds(
    mut out: impl Emit<json::Outbounds>,
    instance: Weak<Instance>,
    every: Duration,
    groups: bool,
) {
    use futures::StreamExt;
    let Some(instance) = instance.upgrade() else {
        return;
    };
    let mut lists = Box::pin(instance.core().watch_outbounds(every, groups));
    drop(instance);
    while let Some(list) = lists.next().await {
        let outbounds = json::Outbounds {
            outbounds: list.iter().map(json::Outbound::of).collect(),
        };
        if !out.emit(outbounds).await {
            return;
        }
    }
}

/// The lines kept (when `backlog`), then the lines logged, in batches.
pub(crate) async fn follow_log(
    mut out: impl Emit<json::Log>,
    log: Arc<sail::app::logger::InstanceLog>,
    least: tracing::Level,
    backlog: bool,
) {
    use sail::app::logger::LogEvent;
    use tokio::sync::broadcast::error::{RecvError, TryRecvError};
    let wanted = |line: &sail::app::logger::LogLine| line.level <= least;
    let (kept, mut events) = log.follow();
    let first = json::Log {
        reset: true,
        lines: if backlog {
            kept.iter()
                .filter(|l| wanted(l))
                .map(|l| json::LogLine::of(l))
                .collect()
        } else {
            Vec::new()
        },
        dropped: 0,
    };
    if !out.emit(first).await {
        return;
    }
    let mut dropped = 0u64;
    while out.open() {
        let first = events.recv().await;
        let mut lines = Vec::new();
        let mut reset = false;
        let take = |event: LogEvent, lines: &mut Vec<json::LogLine>, reset: &mut bool| match event {
            LogEvent::Line(line) if wanted(&line) => lines.push(json::LogLine::of(&line)),
            LogEvent::Line(_) => {}
            LogEvent::Cleared => {
                lines.clear();
                *reset = true;
            }
        };
        match first {
            Ok(event) => take(event, &mut lines, &mut reset),
            Err(RecvError::Lagged(n)) => dropped += n,
            Err(RecvError::Closed) => return,
        }
        while lines.len() < LOG_BATCH {
            match events.try_recv() {
                Ok(event) => take(event, &mut lines, &mut reset),
                Err(TryRecvError::Lagged(n)) => dropped += n,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Closed) => break,
            }
        }
        if lines.is_empty() && !reset && dropped == 0 {
            continue;
        }
        let batch = json::Log {
            reset,
            lines,
            dropped: std::mem::take(&mut dropped),
        };
        if !out.emit(batch).await {
            return;
        }
    }
}

#[cfg(test)]
pub(crate) fn live_subscriptions() -> usize {
    lock(&SUBSCRIPTIONS).values().count()
}
