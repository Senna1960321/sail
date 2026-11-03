//! The network the host is on, as an instance sees it: a snapshot, and the
//! changes connections do not survive, as events.

use std::net::IpAddr;

use std::sync::Arc;

use futures::Stream;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use super::instance::Inner;

use super::{Error, Instance};
use crate::control::events::SystemChange;
use crate::net::network as net;
use crate::runtime::teardown::LeftKind;

/// The interface of the default route.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Interface {
    pub name: String,
    /// Its index, as `if_nametoindex` gives it; none where the host pushes
    /// the state and sail has not found it.
    pub index: Option<u32>,
}

/// What kind of network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkKind {
    Wifi,
    Cellular,
    Ethernet,
    Other,
}

/// The network now: what sail detected, or what the host pushed
/// (`set_network_state`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkState {
    /// The last change's, 0 before any; the same count as the events',
    /// from 1 in each run.
    pub generation: u64,
    /// None: offline, no default route.
    pub interface: Option<Interface>,
    pub kind: Option<NetworkKind>,
    pub gateway: Option<IpAddr>,
    /// The default interface's addresses, with their prefix lengths.
    pub addresses: Vec<(IpAddr, u8)>,
    /// Metered, as the system says.
    pub expensive: bool,
    /// In a low data mode, as the system says.
    pub constrained: bool,
    /// Behind a captive portal, as the host says.
    pub captive: bool,
}

impl NetworkState {
    /// No default interface.
    pub fn offline(&self) -> bool {
        self.interface.is_none()
    }

    fn of(state: &net::NetworkState, generation: u64) -> Self {
        NetworkState {
            generation,
            interface: state.interface.clone().map(|name| Interface {
                name,
                index: state.index,
            }),
            kind: state.kind.map(|kind| match kind {
                net::NetworkType::Wifi => NetworkKind::Wifi,
                net::NetworkType::Cellular => NetworkKind::Cellular,
                net::NetworkType::Ethernet => NetworkKind::Ethernet,
                net::NetworkType::Other => NetworkKind::Other,
            }),
            gateway: state.gateway,
            addresses: state
                .addresses
                .iter()
                .map(|inet| (inet.address(), inet.network_length()))
                .collect(),
            expensive: state.expensive,
            constrained: state.constrained,
            captive: state.captive,
        }
    }
}

/// How the network changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkChangeKind {
    /// Another default interface: a name or index differs.
    InterfaceChanged,
    /// The same interface on another network: its gateway, type or
    /// addresses (IPv6 by /64) differ; or the host says the network
    /// changed. A roam to another access point with the same addresses is
    /// no change. A wake with nothing different is told as this too, of
    /// reason `Wake`.
    Moved,
    /// The default interface is gone.
    Offline,
    /// A default interface is back after none.
    Restored,
}

/// What made sail look at the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkChangeReason {
    /// The interface sail sends through changed.
    DefaultInterface,
    /// What sail detects changed.
    Detected,
    /// The host told it (`set_network_state`, `network_changed`).
    Host,
    /// The system woke from sleep (`Instance::wake`, or sail saw it):
    /// no change of network by itself. It closes nothing, except after a
    /// sleep of 2 minutes or more, which closes the carriers left idle.
    Wake,
}

/// A change of network that the connections made before do not survive,
/// or a wake (reason `Wake`), which most of them do.
/// Each is settled: sail's detection waits for 100 ms without a notice
/// from the system (1 s at most) before it looks; a state the host pushes
/// is taken as given.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetworkEvent {
    pub generation: u64,
    pub change: NetworkChangeKind,
    pub reason: NetworkChangeReason,
    pub old: NetworkState,
    pub new: NetworkState,
}

impl NetworkEvent {
    fn of(change: &net::NetworkChange) -> Self {
        let old = NetworkState::of(&change.old, change.generation.saturating_sub(1));
        let new = NetworkState::of(&change.new, change.generation);
        let kind = match (&old.interface, &new.interface) {
            (Some(_), None) => NetworkChangeKind::Offline,
            (None, Some(_)) => NetworkChangeKind::Restored,
            (Some(a), Some(b)) if a != b => NetworkChangeKind::InterfaceChanged,
            _ => NetworkChangeKind::Moved,
        };
        NetworkEvent {
            generation: change.generation,
            change: kind,
            reason: match change.reason {
                net::ChangeReason::DefaultInterface => NetworkChangeReason::DefaultInterface,
                net::ChangeReason::State => NetworkChangeReason::Detected,
                net::ChangeReason::HostPush => NetworkChangeReason::Host,
                net::ChangeReason::Wake => NetworkChangeReason::Wake,
            },
            old,
            new,
        }
    }
}

/// Kinds of event a subscription takes; `Kinds::NETWORK | …`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Kinds(u32);

impl Kinds {
    /// The instance's state: each change of it.
    pub const STATE: Kinds = Kinds(1 << 0);
    pub const NETWORK: Kinds = Kinds(1 << 1);
    /// What happens to the users of its inbounds.
    pub const USER: Kinds = Kinds(1 << 2);
    /// A group taking another member, and why.
    pub const GROUP: Kinds = Kinds(1 << 3);
    /// Connections that failed, coalesced by chain: the first at once,
    /// then one a second with the count while they go on failing.
    pub const DIAL: Kinds = Kinds(1 << 4);
    /// A task's panic the instance went on after (a contained one).
    pub const FAULT: Kinds = Kinds(1 << 5);
    /// Every connection, once the rules decided of it and its dial ended:
    /// what a polled list of the connections open misses, the short ones
    /// and those that never opened. Built only while someone subscribes.
    pub const ROUTE: Kinds = Kinds(1 << 6);
    /// Every DNS query answered or failed: by a server, the cache or a
    /// rule; a client's and the instance's own. Built only while someone
    /// subscribes.
    pub const DNS: Kinds = Kinds(1 << 7);
    /// Something sail set up on the system for a TUN (a route, its DNS,
    /// its address) that someone else changed: told once a break, and
    /// again only once a check found it right in between. Sail leaves it
    /// as it is; restoring it or rebuilding the instance is the host's.
    pub const SYSTEM: Kinds = Kinds(1 << 8);
    /// What each connection sent and received since it started: a record
    /// when it closes, and one at each interim pass that finds bytes new
    /// since its record before, or that the host asked for
    /// (`ConnectionRecord`). Built only while someone subscribes;
    /// a connection's bytes not yet told when one does are in its next.
    pub const CONNECTION: Kinds = Kinds(1 << 9);
    /// Admission under memory pressure changing level
    /// (`inbound.memory_reserve`): `Event::Admission`.
    pub const ADMISSION: Kinds = Kinds(1 << 10);
    /// Every kind there is, and those added later.
    pub const ALL: Kinds = Kinds(u32::MAX);

    pub fn contains(self, other: Kinds) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Kinds {
    type Output = Kinds;
    fn bitor(self, other: Kinds) -> Kinds {
        Kinds(self.0 | other.0)
    }
}

/// What happens to an instance, by kind. More kinds come; a host matches
/// with `_ => {}`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The instance's state changed to this.
    State(super::State),
    Network(NetworkEvent),
    User(UserEvent),
    GroupSwitched(GroupSwitch),
    /// `count` attempts through `failure.chain` failed since the event
    /// before for that chain; `failure` is the last of them. A group's
    /// member that failed is one, the group going on to another, see
    /// `DialFailure::more_to_try`.
    DialFailed {
        failure: DialFailure,
        count: u64,
    },
    /// A task panicked and the instance went on: its name, class, message
    /// and the instance's running count of such panics.
    Fault(super::Fault),
    /// A connection was routed, and dialled where the rules sent it to an
    /// outbound.
    Routed(Arc<RoutedConnection>),
    /// A DNS query was answered or failed: a client's, or the instance's
    /// own.
    DnsExchange(Arc<DnsExchange>),
    /// What a connection sent and received since it started, as it closed
    /// or at an interim pass.
    ConnectionRecord(Arc<ConnectionRecord>),
    /// Admission under memory pressure changed level: what has not
    /// authenticated is held back, or no longer.
    Admission(AdmissionChange),
    /// Someone else changed what sail set up on the system for a TUN;
    /// see `Kinds::SYSTEM`. `resource` names the TUN first, e.g. "route
    /// 0.0.0.0/0 into tun0: gone".
    SystemChanged {
        kind: LeftKind,
        resource: String,
    },
    /// This subscriber fell behind on `kind`, and `missed` events of it
    /// are gone: read the snapshot again.
    Lagged {
        kind: Kinds,
        missed: u64,
    },
}

impl Instance {
    /// The network now. Read it after subscribing to `events`, and skip
    /// the events whose generation is this one's or lower: none is then
    /// missed nor taken twice.
    pub fn network(&self) -> Result<NetworkState, Error> {
        let env = self.inner().network()?;
        let now = env.network.snapshot_with_generation();
        Ok(NetworkState::of(&now.state, now.generation))
    }

    /// The events of `kinds`, from now on, through stops and starts,
    /// until dropped. Subscribed at once: a change after this call is not
    /// missed, though the stream is first polled after a start. User
    /// events are a run's, subscribed once it runs: those told between the
    /// start and the first poll after it are missed. A run's generations
    /// count from 1; after a start, read the snapshot again.
    pub fn events(&self, kinds: Kinds) -> impl Stream<Item = Event> + Send + 'static {
        let mut streams: Vec<futures::stream::BoxStream<'static, Event>> = Vec::new();
        if kinds.contains(Kinds::STATE) {
            streams.push(Box::pin(self.state_events()));
        }
        if kinds.contains(Kinds::NETWORK) {
            streams.push(Box::pin(self.network_events()));
        }
        if kinds.contains(Kinds::USER) {
            streams.push(Box::pin(self.user_events()));
        }
        let hub = self.inner().events();
        if kinds.contains(Kinds::GROUP) {
            streams.push(Box::pin(told(
                hub.group_switches(),
                Kinds::GROUP,
                |s: &GroupSwitch| Event::GroupSwitched(s.clone()),
            )));
        }
        if kinds.contains(Kinds::FAULT) {
            streams.push(Box::pin(told(
                hub.faults(),
                Kinds::FAULT,
                |f: &super::Fault| Event::Fault(f.clone()),
            )));
        }
        if kinds.contains(Kinds::DIAL) {
            let failures = told(hub.dial_failures(), Kinds::DIAL, |f: &DialFailure| {
                Event::DialFailed {
                    failure: f.clone(),
                    count: 1,
                }
            });
            streams.push(Box::pin(coalesce(failures, DIAL_WINDOW)));
        }
        if kinds.contains(Kinds::SYSTEM) {
            streams.push(Box::pin(told(
                hub.system_changes(),
                Kinds::SYSTEM,
                |c: &SystemChange| Event::SystemChanged {
                    kind: c.kind,
                    resource: c.resource.clone(),
                },
            )));
        }
        if kinds.contains(Kinds::ROUTE) {
            streams.push(Box::pin(told_counted(
                hub.routes(),
                Kinds::ROUTE,
                Event::Routed,
            )));
        }
        if kinds.contains(Kinds::DNS) {
            streams.push(Box::pin(told_counted(
                hub.dns_exchanges(),
                Kinds::DNS,
                Event::DnsExchange,
            )));
        }
        if kinds.contains(Kinds::ADMISSION) {
            streams.push(Box::pin(told(
                hub.admission_changes(),
                Kinds::ADMISSION,
                |c: &AdmissionChange| Event::Admission(c.clone()),
            )));
        }
        if kinds.contains(Kinds::CONNECTION) {
            streams.push(Box::pin(told_counted(
                hub.records(),
                Kinds::CONNECTION,
                Event::ConnectionRecord,
            )));
        }
        futures::stream::select_all(streams)
    }

    /// Each change of state, from now on, in order.
    fn state_events(&self) -> impl Stream<Item = Event> + Send + 'static {
        futures::stream::unfold(self.inner().transitions(), |mut rx| async move {
            let event = match rx.recv().await {
                Ok(state) => Event::State(state),
                Err(RecvError::Lagged(missed)) => Event::Lagged {
                    kind: Kinds::STATE,
                    missed,
                },
                Err(RecvError::Closed) => return None,
            };
            Some((event, rx))
        })
    }

    /// How many routed connections the instance built to tell, since it
    /// was made: none while no one subscribes to `Kinds::ROUTE`.
    #[doc(hidden)]
    pub fn routes_built(&self) -> Result<usize, Error> {
        Ok(self.inner().events().routes_built())
    }

    /// How many DNS exchanges the instance built to tell, since it was
    /// made: none while no one subscribes to `Kinds::DNS`.
    #[doc(hidden)]
    pub fn dns_built(&self) -> Result<usize, Error> {
        Ok(self.inner().events().dns_built())
    }

    fn network_events(&self) -> impl Stream<Item = Event> + Send + 'static {
        told(
            self.network_changes(),
            Kinds::NETWORK,
            |change: &Arc<net::NetworkChange>| Event::Network(NetworkEvent::of(change)),
        )
    }

    /// The network's changes, subscribed now, through stops and starts:
    /// the C ABI's network events.
    #[doc(hidden)]
    pub fn network_changes(&self) -> broadcast::Receiver<Arc<net::NetworkChange>> {
        self.inner().events().network_changes()
    }

    fn user_events(&self) -> impl Stream<Item = Event> + Send + 'static {
        per_run(
            self.inner().clone(),
            Kinds::USER,
            |m| m.env.users.subscribe(),
            |e: &crate::user::UserEvent| Event::User(UserEvent::of(e)),
        )
    }

    /// The names of the TUN devices, by inbound tag: as configured, or as
    /// sail chose them at start when none was (`chosen`). None for a TUN
    /// the host opens itself (Android, iOS).
    pub fn tun_names(&self) -> Result<std::collections::BTreeMap<String, TunName>, Error> {
        Ok(self.manager()?.tun_names())
    }

    /// The routes of others (another VPN's, say) that auto_route replaced
    /// with its own, a line each: "route 128.0.0.0/1 via 10.8.0.1 on
    /// utun4". sail puts them back when it stops, where they should go
    /// back. Read it after a start or a reload. macOS only; empty
    /// elsewhere.
    pub fn replaced_routes(&self) -> Result<Vec<String>, Error> {
        Ok(self.manager()?.replaced_routes())
    }
}

pub use crate::control::events::{
    AdmissionChange, AdmissionLevel, ClosedBy, ConnectionRecord, DialFailure, DialStage,
    DnsExchange, DnsOutcome, DnsSource, DomainSource, End, GroupSwitch, Outcome, RecordKind,
    RouteAction, RoutedConnection, SwitchReason,
};
pub use crate::runtime::TunName;

/// The events a run's broadcast tells, through stops and starts: each run's
/// in turn, subscribed at once when it runs now, else when the next runs.
fn per_run<T, S, M>(
    inner: Arc<Inner>,
    kind: Kinds,
    subscribe: S,
    map: M,
) -> impl Stream<Item = Event> + Send + 'static
where
    T: Clone + Send + 'static,
    S: Fn(&crate::RuntimeManager) -> broadcast::Receiver<T> + Send + Sync + 'static,
    M: Fn(&T) -> Event + Send + Sync + 'static,
{
    let first = inner.manager().ok().map(|m| subscribe(&m));
    let states = inner.states();
    futures::stream::unfold(
        (inner, first, states, subscribe, map),
        move |(inner, mut subscribed, mut states, subscribe, map)| async move {
            loop {
                let Some(mut rx) = subscribed.take() else {
                    // Not running: the next run's, once it runs.
                    states.changed().await.ok()?;
                    subscribed = inner.manager().ok().map(|m| subscribe(&m));
                    continue;
                };
                let event = match rx.recv().await {
                    Ok(value) => map(&value),
                    Err(RecvError::Lagged(missed)) => Event::Lagged { kind, missed },
                    // The run ended.
                    Err(RecvError::Closed) => continue,
                };
                return Some((event, (inner, Some(rx), states, subscribe, map)));
            }
        },
    )
}

/// The events of one of the instance's channels (`Inner::events`), which
/// outlive its runs: subscribed when this is called, so nothing told after
/// is missed, though the stream is first polled later. It ends when the
/// instance is gone.
fn told<T, M>(
    rx: broadcast::Receiver<T>,
    kind: Kinds,
    map: M,
) -> impl Stream<Item = Event> + Send + 'static
where
    T: Clone + Send + 'static,
    M: Fn(&T) -> Event + Send + Sync + 'static,
{
    futures::stream::unfold((rx, map), move |(mut rx, map)| async move {
        let event = match rx.recv().await {
            Ok(value) => map(&value),
            Err(RecvError::Lagged(missed)) => Event::Lagged { kind, missed },
            Err(RecvError::Closed) => return None,
        };
        Some((event, (rx, map)))
    })
}

/// `told`, of a channel that counts who listens (control::events'
/// `Channel`): what it tells is built only while a subscription is held.
fn told_counted<T, M>(
    rx: crate::control::events::Subscription<T>,
    kind: Kinds,
    map: M,
) -> impl Stream<Item = Event> + Send + 'static
where
    T: Clone + Send + 'static,
    M: Fn(T) -> Event + Send + Sync + 'static,
{
    futures::stream::unfold((rx, map), move |(mut rx, map)| async move {
        let event = match rx.recv().await {
            Ok(value) => map(value),
            Err(RecvError::Lagged(missed)) => Event::Lagged { kind, missed },
            Err(RecvError::Closed) => return None,
        };
        Some((event, (rx, map)))
    })
}

/// What happened to a user of the instance's inbounds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserEvent {
    /// It went over its quota, or past its expiry, and was disconnected.
    Shut {
        user: String,
        over_quota: bool,
        expired: bool,
    },
    /// It was taken out of an inbound, and disconnected from it.
    Removed { user: String, inbound: String },
}

impl UserEvent {
    fn of(e: &crate::user::UserEvent) -> Self {
        match e {
            crate::user::UserEvent::Shut { user, status } => UserEvent::Shut {
                user: user.clone(),
                over_quota: status.exhausted(),
                expired: status.expired(),
            },
            crate::user::UserEvent::Removed { user, inbound } => UserEvent::Removed {
                user: user.clone(),
                inbound: inbound.clone(),
            },
        }
    }
}

/// How long the failures of one chain are counted together.
const DIAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

/// The dial failures of `events` coalesced by chain: a chain's first
/// failure goes out at once and opens a window; those within it are
/// counted, and go out as one event, the last with the count, when it
/// closes. Other events pass straight through.
fn coalesce(
    events: impl Stream<Item = Event> + Send + 'static,
    window: std::time::Duration,
) -> impl Stream<Item = Event> + Send + 'static {
    use std::collections::HashMap;
    use tokio::time::Instant;
    // chain -> (the window's end, the failures counted in it, the last)
    type Open = HashMap<String, (Instant, u64, Option<DialFailure>)>;
    futures::stream::unfold(
        (Box::pin(events), Open::new(), false),
        move |(mut events, mut open, mut done)| async move {
            use futures::StreamExt;
            loop {
                // A window that has closed with failures counted goes out.
                let now = Instant::now();
                let due = open
                    .iter()
                    .filter(|(_, (end, _, _))| *end <= now)
                    .map(|(chain, _)| chain.clone())
                    .collect::<Vec<_>>();
                for chain in due {
                    if let Some((_, count, Some(last))) = open.remove(&chain) {
                        if count > 0 {
                            let event = Event::DialFailed {
                                failure: last,
                                count,
                            };
                            return Some((event, (events, open, done)));
                        }
                    }
                }
                if done && open.is_empty() {
                    return None;
                }
                let next_end = open.values().map(|(end, _, _)| *end).min();
                let item = match (next_end, done) {
                    (Some(end), true) => {
                        tokio::time::sleep_until(end).await;
                        continue;
                    }
                    (Some(end), false) => tokio::select! {
                        item = events.next() => item,
                        _ = tokio::time::sleep_until(end) => continue,
                    },
                    (None, _) => events.next().await,
                };
                match item {
                    None => done = true,
                    Some(Event::DialFailed { failure, .. }) => {
                        let now = Instant::now();
                        match open.get_mut(&failure.chain) {
                            Some((end, count, last)) if *end > now => {
                                *count += 1;
                                *last = Some(failure);
                            }
                            _ => {
                                open.insert(failure.chain.clone(), (now + window, 0, None));
                                let event = Event::DialFailed { failure, count: 1 };
                                return Some((event, (events, open, done)));
                            }
                        }
                    }
                    Some(other) => return Some((other, (events, open, done))),
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    fn failure(chain: &str) -> Event {
        Event::DialFailed {
            failure: DialFailure::new(
                chain.into(),
                "example.com:443".into(),
                std::io::ErrorKind::ConnectionRefused,
                DialStage::Dial,
            ),
            count: 1,
        }
    }

    /// A system change as the hub tells it; one missed as a lag of its
    /// own kind.
    #[tokio::test]
    async fn system_changes_are_told_with_their_kind() {
        let hub = crate::control::events::EventHub::default();
        let change = |n: usize| SystemChange {
            kind: LeftKind::Route,
            resource: format!("route 0.0.0.0/0 into tun{}: gone", n),
        };
        let map = |c: &SystemChange| Event::SystemChanged {
            kind: c.kind,
            resource: c.resource.clone(),
        };
        let mut events = Box::pin(told(hub.system_changes(), Kinds::SYSTEM, map));
        hub.system_changed(change(0));
        assert_eq!(
            events.next().await,
            Some(Event::SystemChanged {
                kind: LeftKind::Route,
                resource: "route 0.0.0.0/0 into tun0: gone".into(),
            })
        );
        let mut slow = Box::pin(told(hub.system_changes(), Kinds::SYSTEM, map));
        for n in 0..=crate::control::events::SYSTEM_CAPACITY {
            hub.system_changed(change(n));
        }
        assert_eq!(
            slow.next().await,
            Some(Event::Lagged {
                kind: Kinds::SYSTEM,
                missed: 1,
            })
        );
    }

    /// A chain's first failure at once; the rest of its window as one,
    /// counted; chains apart.
    #[tokio::test]
    async fn dial_failures_are_coalesced_by_chain() {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        let mut out = Box::pin(coalesce(rx, std::time::Duration::from_millis(100)));
        for _ in 0..5 {
            tx.unbounded_send(failure("sel>hk")).unwrap();
        }
        tx.unbounded_send(failure("sel>jp")).unwrap();
        let count = |e: Event| match e {
            Event::DialFailed { failure, count } => (failure.chain, count),
            other => panic!("{:?}", other),
        };
        assert_eq!(count(out.next().await.unwrap()), ("sel>hk".into(), 1));
        assert_eq!(count(out.next().await.unwrap()), ("sel>jp".into(), 1));
        // The window closes: the four after the first, as one.
        assert_eq!(count(out.next().await.unwrap()), ("sel>hk".into(), 4));
        drop(tx);
        assert!(out.next().await.is_none());
    }
}
