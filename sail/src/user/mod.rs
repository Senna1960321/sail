//! The users inbounds authenticate. A user is a name, one namespace for
//! the whole instance, as in sing-box: the same name in two inbounds, or
//! on two credentials of one inbound, is one user.
//!
//! Inbounds bind each named credential to its user when they build their
//! credential tables, and put the user in the session once a connection
//! authenticates: nothing is looked up by name on the data path. A reload
//! binds the names again and gets the same users, as long as the old
//! tables hold them.
//!
//! A user's traffic is counted in its state, so it goes on across reloads;
//! with `experimental.cache_file`, across restarts too. A user no table or
//! session holds any more is dropped with its counts, as sing-box's
//! ssm-api drops a deleted user's.
//!
//! `user_limits`, a sail extension, limits a user across every inbound it
//! is in: its live connections, its bytes up and down together, and until
//! when it may connect. A user over its quota or past its expiry is shut
//! out at once: its connections are closed, and new ones are refused as
//! those of an unknown user.

use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;

use crate::app::stat_manager::{Counter, Counts};

mod api;
mod limits;
mod rate;
pub use api::{UserEvent, UserSnapshot};
pub use limits::{Limits, Status};

/// Bytes a second in a megabit a second, as sing-box's Hysteria2 counts
/// `up_mbps`.
const MBPS: u64 = 125_000;

/// How many of `live` are TCP connections.
fn tcp_live(live: &HashMap<u64, Arc<Counter>>) -> usize {
    live.values()
        .filter(|c| c.sess.network == crate::session::Network::Tcp)
        .count()
}

/// What sail keeps of a user while it runs.
pub struct UserState {
    name: Arc<str>,
    traffic: UserTraffic,
    limits: Mutex<Limits>,
    /// Up and down together at which the quota runs out: `u64::MAX`
    /// without one. Read on the data path, where `limits` is not.
    quota_at: AtomicU64,
    /// Up and down together when the quota was last reset.
    quota_base: AtomicU64,
    /// What shuts the user out, as `Status` bits; none when it may connect.
    status: AtomicU8,
    /// Its rates, bytes a second, up, down and both together; 0 for none.
    /// Read on the data path, where `limits` is not.
    up_bps: AtomicU64,
    down_bps: AtomicU64,
    total_bps: AtomicU64,
    up_rate: rate::Gcra,
    down_rate: rate::Gcra,
    total_rate: rate::Gcra,
    /// The live connections, by id.
    live: Mutex<HashMap<u64, Arc<Counter>>>,
    /// The connections that carry others, a QUIC connection or a
    /// multiplexed one, by the inbound they came in through: closed with
    /// the user's, so that its client connects again and is refused.
    carriers: Mutex<HashMap<u64, (Arc<str>, CloseCarrier)>>,
    /// The inbounds it was taken out of. A session a transport keeps may
    /// still let it open streams under the credentials it had; they are
    /// refused.
    removed: Mutex<std::collections::HashSet<Arc<str>>>,
    /// Where what happens to it is told.
    events: tokio::sync::broadcast::Sender<UserEvent>,
}

/// What closes a carrier.
type CloseCarrier = Box<dyn Fn() + Send + Sync>;

/// Keeps a carrier among its user's while it lives.
pub struct Carrier {
    user: UserRef,
    id: u64,
}

impl Drop for Carrier {
    fn drop(&mut self) {
        self.user
            .carriers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

impl fmt::Debug for UserState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UserState")
            .field("name", &self.name)
            .field("traffic", &self.traffic)
            .field("status", &self.status())
            .finish()
    }
}

impl UserState {
    fn new(name: &str, counts: Counts, events: tokio::sync::broadcast::Sender<UserEvent>) -> Self {
        UserState {
            events,
            name: name.into(),
            traffic: UserTraffic::new(counts),
            limits: Mutex::default(),
            quota_at: AtomicU64::new(u64::MAX),
            quota_base: AtomicU64::new(0),
            status: AtomicU8::new(0),
            up_bps: AtomicU64::new(0),
            down_bps: AtomicU64::new(0),
            total_bps: AtomicU64::new(0),
            up_rate: rate::Gcra::default(),
            down_rate: rate::Gcra::default(),
            total_rate: rate::Gcra::default(),
            live: Mutex::default(),
            carriers: Mutex::default(),
            removed: Mutex::default(),
        }
    }

    pub fn name(&self) -> &Arc<str> {
        &self.name
    }

    pub fn traffic(&self) -> &UserTraffic {
        &self.traffic
    }

    pub fn limits(&self) -> Limits {
        self.limits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn status(&self) -> Status {
        Status::from_bits(self.status.load(Ordering::Acquire))
    }

    /// Whether the user may connect: neither over its quota nor expired.
    pub fn active(&self) -> bool {
        self.status.load(Ordering::Acquire) == 0
    }

    /// Bytes up and down together since the quota was last reset.
    pub fn quota_used(&self) -> u64 {
        let c = self.traffic.counts();
        (c.up + c.down).saturating_sub(self.quota_base.load(Ordering::Relaxed))
    }

    /// How many connections are live.
    pub fn live(&self) -> usize {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Takes `counter` among the live connections, unless the user may not
    /// connect or has as many as it may.
    pub(crate) fn admit(&self, counter: &Arc<Counter>) -> bool {
        if self.removed_from(&counter.sess.inbound_tag) {
            return false;
        }
        let limits = self.limits();
        let tcp = counter.sess.network == crate::session::Network::Tcp;
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        // Checked under the lock `shut` takes: a connection admitted is
        // one it closes.
        if !self.active()
            || limits
                .max_connections
                .is_some_and(|max| live.len() >= max as usize)
            || tcp
                && limits
                    .max_tcp_connections
                    .is_some_and(|max| tcp_live(&live) >= max as usize)
        {
            return false;
        }
        live.insert(counter.id, counter.clone());
        true
    }

    /// Whether a connection through the inbound `tag` would be admitted
    /// now, as a TCP one when `tcp`; `admit` decides.
    pub fn admits(&self, tag: &str) -> bool {
        self.admits_on(tag, true)
    }

    /// `admits`, of a connection of `tcp` or not.
    pub fn admits_on(&self, tag: &str, tcp: bool) -> bool {
        let limits = self.limits();
        if !self.active() || self.removed_from(tag) {
            return false;
        }
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        limits
            .max_connections
            .is_none_or(|max| live.len() < max as usize)
            && !(tcp
                && limits
                    .max_tcp_connections
                    .is_some_and(|max| tcp_live(&live) >= max as usize))
    }

    /// How many live TCP connections it has.
    pub fn live_tcp(&self) -> usize {
        tcp_live(&self.live.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Whether it was taken out of the inbound `tag`.
    pub fn removed_from(&self, tag: &str) -> bool {
        self.removed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(tag)
    }

    pub(crate) fn leave(&self, id: u64) {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    /// Closes the live connections, and what carries them; how many
    /// connections there were.
    pub fn disconnect(&self) -> usize {
        self.disconnect_where(|_| true)
    }

    /// Closes the live connections that came in through the inbound `tag`,
    /// and what carries them there; how many connections there were.
    pub fn disconnect_inbound(&self, tag: &str) -> usize {
        self.disconnect_where(|inbound| inbound == tag)
    }

    fn disconnect_where(&self, inbound: impl Fn(&str) -> bool) -> usize {
        let mut closed = 0;
        for counter in self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|c| inbound(&c.sess.inbound_tag))
        {
            counter
                .closer
                .close_by(crate::control::events::ClosedBy::User);
            closed += 1;
        }
        for (_, close) in self
            .carriers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|(tag, _)| inbound(tag))
        {
            close();
        }
        closed
    }

    /// Sets `bits` in the status; shuts the user out if it was active.
    fn shut(&self, bits: u8) {
        let _live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let was = self.status.fetch_or(bits, Ordering::AcqRel);
        drop(_live);
        for bit in [Status::EXHAUSTED, Status::EXPIRED] {
            if bits & bit != 0 && was & bit == 0 {
                let _ = self.events.send(UserEvent::Shut {
                    user: self.name.to_string(),
                    status: Status::from_bits(bit),
                });
            }
        }
        if was == 0 && bits != 0 {
            let closed = self.disconnect();
            tracing::info!(
                "user [{}]: {}; {} connections closed",
                self.name,
                Status::from_bits(bits),
                closed
            );
        }
    }

    fn clear(&self, bits: u8) {
        self.status.fetch_and(!bits, Ordering::AcqRel);
    }

    /// Checks the quota, on the data path, after bytes were counted.
    pub(crate) fn check_quota(&self) {
        let at = self.quota_at.load(Ordering::Relaxed);
        if at != u64::MAX {
            let c = &self.traffic;
            let total = c.up.load(Ordering::Relaxed) + c.down.load(Ordering::Relaxed);
            if total >= at && self.status.load(Ordering::Relaxed) & Status::EXHAUSTED == 0 {
                self.shut(Status::EXHAUSTED);
            }
        }
    }

    /// Takes `limits`, as `now` is: a user back within them may connect
    /// again, and one no longer is shut out.
    fn apply(&self, limits: Limits, now: SystemTime) {
        let base = self.quota_base.load(Ordering::Relaxed);
        let at = match limits.quota_bytes {
            Some(quota) => base.saturating_add(quota),
            None => u64::MAX,
        };
        let expired = limits.expire_at.is_some_and(|at| at <= now);
        // The state of the rates is kept: a reload gives no new burst.
        let bps = |mbps: Option<u64>| mbps.map_or(0, |mbps| mbps.saturating_mul(MBPS));
        self.up_bps.store(bps(limits.up_mbps), Ordering::Relaxed);
        self.down_bps
            .store(bps(limits.down_mbps), Ordering::Relaxed);
        self.total_bps
            .store(bps(limits.total_mbps), Ordering::Relaxed);
        *self.limits.lock().unwrap_or_else(|e| e.into_inner()) = limits;
        self.quota_at.store(at, Ordering::Relaxed);
        let c = self.traffic.counts();
        let mut shut = 0;
        let mut clear = 0;
        match c.up + c.down >= at {
            true => shut |= Status::EXHAUSTED,
            false => clear |= Status::EXHAUSTED,
        }
        match expired {
            true => shut |= Status::EXPIRED,
            false => clear |= Status::EXPIRED,
        }
        self.clear(clear);
        self.shut(shut);
    }

    /// How much a stream of its reads or writes at once `up` or down, when
    /// a rate limits it that way: the least of them.
    pub(crate) fn chunk(&self, up: bool) -> Option<usize> {
        let total = self.total_bps.load(Ordering::Relaxed);
        match (self.bps(up), total) {
            (0, 0) => None,
            (0, bps) | (bps, 0) => Some(rate::chunk(bps)),
            (one_way, total) => Some(rate::chunk(one_way.min(total))),
        }
    }

    fn bps(&self, up: bool) -> u64 {
        match up {
            true => &self.up_bps,
            false => &self.down_bps,
        }
        .load(Ordering::Relaxed)
    }

    fn rate(&self, up: bool) -> &rate::Gcra {
        match up {
            true => &self.up_rate,
            false => &self.down_rate,
        }
    }

    /// Counts `n` bytes against its rate `up` or down and its rate both
    /// ways: how long what comes next that way must wait, the longer of
    /// the two. TCP is shaped.
    pub(crate) fn shape(&self, up: bool, n: u64) -> Option<std::time::Duration> {
        let one_way = match self.bps(up) {
            0 => None,
            bps => self.rate(up).take(n, bps),
        };
        let total = match self.total_bps.load(Ordering::Relaxed) {
            0 => None,
            bps => self.total_rate.take(n, bps),
        };
        one_way.max(total)
    }

    /// Whether a datagram of `n` bytes may go `up` or down within its rate
    /// that way and its rate both ways; one that may not is dropped,
    /// counted by neither. UDP is policed.
    pub(crate) fn police(&self, up: bool, n: u64) -> bool {
        let one_way = self.bps(up);
        if one_way != 0 && !self.rate(up).admit(n, one_way) {
            return false;
        }
        let total = self.total_bps.load(Ordering::Relaxed);
        if total != 0 && !self.total_rate.admit(n, total) {
            if one_way != 0 {
                self.rate(up).refund(n, one_way);
            }
            return false;
        }
        true
    }

    /// Resets the quota: what was used so far no longer counts.
    pub fn reset_quota(&self) {
        let c = self.traffic.counts();
        self.quota_base.store(c.up + c.down, Ordering::Relaxed);
        let limits = self.limits();
        self.apply(limits, SystemTime::now());
    }

    /// Expires the user if its time has come; when it expires, if later.
    fn expire_if_due(&self, now: SystemTime) -> Option<SystemTime> {
        let at = self.limits().expire_at?;
        if at <= now {
            self.shut(Status::EXPIRED);
            None
        } else {
            Some(at)
        }
    }
}

/// A user's traffic: plain counters, as only the user's own connections
/// add to them.
#[derive(Debug, Default)]
pub struct UserTraffic {
    pub(crate) up: AtomicU64,
    pub(crate) down: AtomicU64,
    tcp: AtomicU64,
    udp: AtomicU64,
}

impl UserTraffic {
    fn new(counts: Counts) -> Self {
        UserTraffic {
            up: counts.up.into(),
            down: counts.down.into(),
            tcp: counts.tcp.into(),
            udp: counts.udp.into(),
        }
    }

    pub(crate) fn add_up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn add_down(&self, n: u64) {
        self.down.fetch_add(n, Ordering::Relaxed);
    }

    pub(crate) fn add_session(&self, udp: bool) {
        match udp {
            false => &self.tcp,
            true => &self.udp,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn counts(&self) -> Counts {
        Counts {
            up: self.up.load(Ordering::Relaxed),
            down: self.down.load(Ordering::Relaxed),
            tcp: self.tcp.load(Ordering::Relaxed),
            udp: self.udp.load(Ordering::Relaxed),
        }
    }
}

/// A user, as sessions and credential tables hold it. Two are equal when
/// their names are.
#[derive(Clone)]
pub struct UserRef(
    Arc<UserState>,
    Option<crate::control::context::RecordContext>,
);

static NEXT_CARRIER: AtomicU64 = AtomicU64::new(0);

impl UserRef {
    /// The immutable credential-registration snapshot, if the embedding
    /// host supplied one. This belongs to this reference, not the mutable
    /// name-indexed user state shared through reloads.
    pub fn credential_context(&self) -> Option<&crate::control::context::RecordContext> {
        self.1.as_ref()
    }

    pub(crate) fn with_credential_context(
        mut self,
        context: crate::control::context::RecordContext,
    ) -> Self {
        self.1 = Some(context);
        self
    }

    /// Keeps `close`, which closes a connection that carries others of
    /// this user through the inbound `tag`, until the guard is dropped:
    /// called when the user is shut out, or taken out of the inbound.
    /// Closed at once if the user is shut out already.
    pub fn carry(&self, tag: &str, close: impl Fn() + Send + Sync + 'static) -> Carrier {
        let id = NEXT_CARRIER.fetch_add(1, Ordering::Relaxed);
        {
            let _live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            if !self.active() {
                close();
            }
            self.carriers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id, (tag.into(), Box::new(close)));
        }
        Carrier {
            user: self.clone(),
            id,
        }
    }

    /// A user of no registry, for tests that need a session with one.
    #[cfg(test)]
    pub fn unbound(name: &str) -> Self {
        let (events, _) = tokio::sync::broadcast::channel(1);
        UserRef(
            Arc::new(UserState::new(name, Counts::default(), events)),
            None,
        )
    }

    /// Whether `self` and `other` are the same user object, not only the
    /// same name.
    pub fn same(&self, other: &UserRef) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Deref for UserRef {
    type Target = UserState;
    fn deref(&self) -> &UserState {
        &self.0
    }
}

impl PartialEq for UserRef {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for UserRef {}

impl Hash for UserRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state)
    }
}

impl fmt::Display for UserRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl fmt::Debug for UserRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&*self.name, f)
    }
}

/// The name of `user`, if there is one.
pub fn name(user: &Option<UserRef>) -> Option<&str> {
    user.as_ref().map(|user| &*user.name)
}

/// Whether `user` is one `user_limits` shuts out: an inbound refuses its
/// credential as that of no user.
pub fn shut_out(user: &Option<UserRef>) -> bool {
    user.as_ref().is_some_and(|user| !user.active())
}

/// Passwords by username, each with the user it authenticates, for the
/// inbounds whose username is the user's name: HTTP, SOCKS and mixed.
pub type Passwords = HashMap<String, (String, Option<UserRef>)>;

/// The clients an HTTP, SOCKS or mixed inbound lets in without
/// credentials, by the address they connect from: Mihomo's
/// `skip-auth-prefixes`, a sail extension. An IPv4-mapped IPv6 address is
/// its IPv4 one.
#[derive(Clone, Default)]
pub struct SkipAuth(std::sync::Arc<[cidr::IpCidr]>);

impl SkipAuth {
    /// `prefixes` read: `skip_auth_prefixes` of the inbound `tag`.
    pub fn new(tag: &str, prefixes: &[String]) -> anyhow::Result<Self> {
        let prefixes = prefixes
            .iter()
            .map(|p| {
                p.parse::<cidr::IpInet>().map(|p| p.network()).map_err(|_| {
                    anyhow::anyhow!(
                        "[{}] inbound: skip_auth_prefixes: {:?} is not an IP prefix",
                        tag,
                        p
                    )
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self(prefixes.into()))
    }

    /// Whether a client at `ip` goes in without credentials.
    pub fn covers(&self, ip: std::net::IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|p| p.contains(&ip))
    }
}

/// `Passwords` of `(username, password)` pairs, for tests.
#[cfg(test)]
pub fn passwords(pairs: &[(&str, &str)]) -> Passwords {
    let users = UserRegistry::default();
    pairs
        .iter()
        .map(|(name, password)| {
            (
                name.to_string(),
                (password.to_string(), users.bind_named(Some(name))),
            )
        })
        .collect()
}

/// The instance's users by name. Copies share them. It holds them weakly:
/// a user lives as long as a credential table or a session holds it.
#[derive(Clone, Default)]
pub struct UserRegistry(Arc<Mutex<Registry>>);

struct Registry {
    users: HashMap<Arc<str>, Weak<UserState>>,
    /// The counts the cache file kept, for users not made yet.
    kept: HashMap<String, Counts>,
    /// The limits in force, by name: those configured, but where the
    /// management API set others since.
    limits: HashMap<String, Limits>,
    /// The limits configured, by name, which a user's go back to.
    configured: HashMap<String, Limits>,
    /// The limits the host set (the management API, embed), by name: over
    /// those configured, through reloads that leave the user's configured
    /// limits as they were.
    overrides: HashMap<String, Limits>,
    /// Wakes what expires users when the limits change.
    changed: Arc<tokio::sync::Notify>,
    /// Where what happens to users is told.
    events: tokio::sync::broadcast::Sender<UserEvent>,
}

impl Default for Registry {
    fn default() -> Self {
        Registry {
            users: HashMap::new(),
            kept: HashMap::new(),
            limits: HashMap::new(),
            configured: HashMap::new(),
            overrides: HashMap::new(),
            changed: Arc::default(),
            events: tokio::sync::broadcast::channel(api::EVENTS).0,
        }
    }
}

impl UserRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `other` is this registry, not another instance's or run's.
    pub fn same(&self, other: &UserRegistry) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// The user named `name`, made if there is none. Used when inbounds
    /// build, not on the data path.
    pub fn bind(&self, name: &str) -> UserRef {
        let mut registry = self.lock();
        if let Some(user) = registry.users.get(name).and_then(Weak::upgrade) {
            return UserRef(user, None);
        }
        registry.users.retain(|_, user| user.strong_count() > 0);
        let counts = registry.kept.remove(name).unwrap_or_default();
        let user = Arc::new(UserState::new(name, counts, registry.events.clone()));
        let limits = registry.limits.get(name).cloned().unwrap_or_default();
        user.apply(limits, SystemTime::now());
        registry
            .users
            .insert(user.name.clone(), Arc::downgrade(&user));
        UserRef(user, None)
    }

    /// Starts the users made from now on with the counts `kept`, the cache
    /// file's.
    pub(crate) fn keep(&self, kept: HashMap<String, Counts>) {
        self.lock().kept = kept;
    }

    /// The limits `config` sets, by user.
    pub fn configured(config: &crate::config::Config) -> HashMap<String, Limits> {
        config
            .user_limits
            .iter()
            .map(|(name, limits)| (name.clone(), Limits::from_config(limits)))
            .collect()
    }

    /// Limits the users by `limits`, the configuration's, those there are
    /// and those made from now on; the users `limits` does not name are
    /// not limited. Limits the host set for a user stay over them, unless
    /// `limits` changes the user's own: those are dropped, and their users
    /// named, in order.
    pub fn set_limits(&self, limits: HashMap<String, Limits>) -> Vec<String> {
        let (users, changed, effective, mut dropped) = {
            let mut registry = self.lock();
            let was = std::mem::replace(&mut registry.configured, limits.clone());
            let mut dropped = Vec::new();
            registry.overrides.retain(|name, _| {
                let kept = was.get(name) == limits.get(name);
                if !kept {
                    dropped.push(name.clone());
                }
                kept
            });
            let mut effective = limits;
            for (name, set) in &registry.overrides {
                effective.insert(name.clone(), set.clone());
            }
            registry.limits = effective.clone();
            (
                registry
                    .users
                    .values()
                    .filter_map(Weak::upgrade)
                    .collect::<Vec<_>>(),
                registry.changed.clone(),
                effective,
                dropped,
            )
        };
        let now = SystemTime::now();
        for user in users {
            let limits = effective.get(&*user.name).cloned().unwrap_or_default();
            user.apply(limits, now);
        }
        changed.notify_one();
        dropped.sort();
        dropped
    }

    /// Expires each user at its time: sleeps until the next one is due,
    /// or a minute at most, as the system clock may jump, or until the
    /// limits change.
    pub fn expiry_task(&self) -> crate::Runner {
        let registry = self.clone();
        Box::pin(async move {
            let changed = registry.lock().changed.clone();
            loop {
                let now = SystemTime::now();
                let next = registry
                    .users()
                    .iter()
                    .filter_map(|user| user.expire_if_due(now))
                    .min();
                let wait = next
                    .and_then(|at| at.duration_since(now).ok())
                    .unwrap_or(limits::RECHECK)
                    .min(limits::RECHECK);
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = changed.notified() => {}
                }
            }
        })
    }

    /// The user named `name`, if there is one.
    pub fn get(&self, name: &str) -> Option<UserRef> {
        self.lock()
            .users
            .get(name)
            .and_then(Weak::upgrade)
            .map(|user| UserRef(user, None))
    }

    /// Limits `user` by `limits`, over what the configuration sets, until
    /// `restore_limit`, or a reload that changes what it sets for the user.
    pub fn set_limit(&self, user: &UserRef, limits: Limits) {
        self.set_limits_named([(user.name.to_string(), limits)]);
    }

    /// Limits each user named by its limits, over what the configuration
    /// sets, until `restore_limit_named`, or a reload that changes what it
    /// sets for the user: those there are at once, those not made yet as
    /// they are made.
    /// One lock for them all, and what expires users is woken only when an
    /// expiry changed: a host setting thousands of users' limits often
    /// costs a map insertion a user.
    pub fn set_limits_named(&self, limits: impl IntoIterator<Item = (String, Limits)>) {
        let (apply, changed) = {
            let mut registry = self.lock();
            let mut apply = Vec::new();
            let mut expiry_changed = false;
            for (name, limits) in limits {
                registry.overrides.insert(name.clone(), limits.clone());
                let was = registry.limits.insert(name.clone(), limits.clone());
                expiry_changed |= was.map(|was| was.expire_at) != Some(limits.expire_at);
                if let Some(user) = registry.users.get(name.as_str()).and_then(Weak::upgrade) {
                    apply.push((user, limits));
                }
            }
            (apply, expiry_changed.then(|| registry.changed.clone()))
        };
        let now = SystemTime::now();
        for (user, limits) in apply {
            user.apply(limits, now);
        }
        if let Some(changed) = changed {
            changed.notify_one();
        }
    }

    /// Limits the user `name` by what the configuration sets for it again,
    /// undoing `set_limits_named`; one not made yet will be.
    pub fn restore_limit_named(&self, name: &str) {
        let (user, limits, changed) = {
            let mut registry = self.lock();
            registry.overrides.remove(name);
            let limits = registry.configured.get(name).cloned().unwrap_or_default();
            registry.limits.insert(name.to_string(), limits.clone());
            (
                registry.users.get(name).and_then(Weak::upgrade),
                limits,
                registry.changed.clone(),
            )
        };
        if let Some(user) = user {
            user.apply(limits, SystemTime::now());
        }
        changed.notify_one();
    }

    /// Limits `user` by what the configuration sets for it again, undoing
    /// `set_limit`.
    pub fn restore_limit(&self, user: &UserRef) {
        let (limits, changed) = {
            let mut registry = self.lock();
            registry.overrides.remove(&*user.name);
            let limits = registry
                .configured
                .get(&*user.name)
                .cloned()
                .unwrap_or_default();
            registry
                .limits
                .insert(user.name.to_string(), limits.clone());
            (limits, registry.changed.clone())
        };
        user.apply(limits, SystemTime::now());
        changed.notify_one();
    }

    /// What happens to users from now on.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<UserEvent> {
        self.lock().events.subscribe()
    }

    /// The users there are.
    pub fn users(&self) -> Vec<UserRef> {
        self.lock()
            .users
            .values()
            .filter_map(Weak::upgrade)
            .map(|user| UserRef(user, None))
            .collect()
    }

    /// Takes the user `name` out of the inbound `tag`: what it has through
    /// it is closed, and what it would open refused; how many connections
    /// there were.
    pub fn remove_from(&self, name: &str, tag: &str) -> usize {
        let (user, events) = {
            let registry = self.lock();
            (
                registry.users.get(name).and_then(Weak::upgrade),
                registry.events.clone(),
            )
        };
        // Told whether or not anything holds the user now: one with no
        // connection is gone with the credentials that held it.
        let _ = events.send(UserEvent::Removed {
            user: name.to_owned(),
            inbound: tag.to_owned(),
        });
        user.map_or(0, |user| {
            user.removed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(tag.into());
            user.disconnect_inbound(tag)
        })
    }

    /// Puts the user `name` in the inbound `tag` again, if it was taken out.
    pub fn restore_to(&self, name: &str, tag: &str) {
        if let Some(user) = self.lock().users.get(name).and_then(Weak::upgrade) {
            user.removed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(tag);
        }
    }

    /// The user named `name` for a credential that may have none: sing-box
    /// gives no identity to a user without a name.
    pub fn bind_named(&self, name: Option<&str>) -> Option<UserRef> {
        name.filter(|name| !name.is_empty())
            .map(|name| self.bind(name))
    }
}

impl fmt::Debug for UserRegistry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let registry = self.lock();
        f.debug_set()
            .entries(
                registry
                    .users
                    .iter()
                    .filter(|(_, u)| u.strong_count() > 0)
                    .map(|(n, _)| n),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A prefix with host bits is its network's, an IPv4-mapped address
    /// its IPv4 one, and anything else a mistake that names the inbound.
    #[test]
    fn skip_auth_covers_its_prefixes() {
        let skip = SkipAuth::new("in", &["192.168.1.5/24".into(), "fd00::/8".into()]).unwrap();
        for (ip, covered) in [
            ("192.168.1.200", true),
            ("::ffff:192.168.1.7", true),
            ("fd12::1", true),
            ("192.168.2.1", false),
            ("fe80::1", false),
        ] {
            assert_eq!(skip.covers(ip.parse().unwrap()), covered, "{}", ip);
        }
        assert!(!SkipAuth::default().covers("127.0.0.1".parse().unwrap()));
        let e = SkipAuth::new("in", &["lan".into()]).err().unwrap();
        assert_eq!(
            e.to_string(),
            "[in] inbound: skip_auth_prefixes: \"lan\" is not an IP prefix"
        );
    }

    #[test]
    fn a_name_bound_twice_is_one_user() {
        let users = UserRegistry::default();
        let a = users.bind("alice");
        let b = users.clone().bind("alice");
        assert!(a.same(&b));
        assert!(!a.same(&users.bind("bob")));
    }

    #[test]
    fn a_user_no_one_holds_is_made_anew() {
        let users = UserRegistry::default();
        let old = Arc::downgrade(&users.bind("alice").0);
        assert!(old.upgrade().is_none());
        let _new = users.bind("alice");
        assert_eq!(users.lock().users.len(), 1);
    }

    #[test]
    fn an_empty_or_missing_name_is_no_user() {
        let users = UserRegistry::default();
        assert!(users.bind_named(None).is_none());
        assert!(users.bind_named(Some("")).is_none());
        assert_eq!(users.bind_named(Some("a")).unwrap().to_string(), "a");
    }

    #[cfg(all(feature = "inbound-trojan", feature = "inbound-http"))]
    mod inbounds {
        use super::*;
        use crate::adapter::{registry, AnyInboundHandler, InboundTransport};
        use crate::runtime::RuntimeEnv;
        use crate::session::Session;
        use sha2::{Digest, Sha224};
        use tokio::io::AsyncWriteExt;

        fn build(
            env: &RuntimeEnv,
            inbounds: serde_json::Value,
        ) -> HashMap<String, AnyInboundHandler> {
            let inbounds: Vec<crate::config::Inbound> = serde_json::from_value(inbounds).unwrap();
            let mut handlers = HashMap::new();
            registry::build_inbounds(
                &crate::include::INBOUNDS,
                &inbounds,
                crate::include::LISTENER_INBOUNDS,
                env,
                &Default::default(),
                &mut handlers,
                &mut HashMap::new(),
                &mut HashMap::new(),
            )
            .unwrap();
            handlers
        }

        async fn user(handler: &AnyInboundHandler, wire: Vec<u8>) -> Option<UserRef> {
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(&wire).await.unwrap();
            match handler
                .stream()
                .unwrap()
                .handle(Session::default(), Box::new(server))
                .await
                .unwrap()
            {
                InboundTransport::Stream(_, sess) => sess.user,
                _ => panic!("expected a stream"),
            }
        }

        fn trojan(password: &str) -> Vec<u8> {
            let mut wire = hex::encode(Sha224::digest(password.as_bytes())).into_bytes();
            wire.extend_from_slice(b"\r\n\x01\x01\x7f\x00\x00\x01\x00\x50\r\n");
            wire
        }

        fn http(credentials: &str) -> Vec<u8> {
            use base64::Engine;
            let auth = base64::engine::general_purpose::STANDARD.encode(credentials);
            format!("CONNECT 127.0.0.1:80 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")
                .into_bytes()
        }

        fn inbounds(trojan_users: serde_json::Value) -> serde_json::Value {
            serde_json::json!([
                { "type": "trojan", "tag": "t", "users": trojan_users },
                { "type": "http", "tag": "h",
                  "users": [{ "username": "alice", "password": "hp" }] },
            ])
        }

        #[tokio::test]
        async fn one_name_in_two_inbounds_is_one_user_across_reloads() {
            let env = RuntimeEnv::default();
            let handlers = build(
                &env,
                inbounds(serde_json::json!([
                    { "name": "alice", "password": "tp" },
                    { "name": "alice", "password": "tp2" },
                ])),
            );
            let by_trojan = user(&handlers["t"], trojan("tp")).await.unwrap();
            let by_second = user(&handlers["t"], trojan("tp2")).await.unwrap();
            let by_http = user(&handlers["h"], http("alice:hp")).await.unwrap();
            assert_eq!(by_trojan.to_string(), "alice");
            assert!(by_trojan.same(&by_second));
            assert!(by_trojan.same(&by_http));

            // A reload builds the tables again while the old ones hold the
            // users: the new tables get the same users.
            let reloaded = build(
                &env,
                inbounds(serde_json::json!([
                    { "name": "alice", "password": "tp" },
                ])),
            );
            drop(handlers);
            let after = user(&reloaded["t"], trojan("tp")).await.unwrap();
            assert!(after.same(&by_trojan));
        }

        /// A user shut out fails to authenticate, as one unknown does.
        #[tokio::test]
        async fn a_user_shut_out_is_refused_as_unknown() {
            let env = RuntimeEnv::default();
            let handlers = build(
                &env,
                inbounds(serde_json::json!([{ "name": "alice", "password": "tp" }])),
            );
            env.users.set_limits(HashMap::from([(
                "alice".to_string(),
                Limits {
                    expire_at: Some(std::time::UNIX_EPOCH),
                    ..Default::default()
                },
            )]));
            for (tag, wire) in [("t", trojan("tp")), ("h", http("alice:hp"))] {
                let (mut client, server) = tokio::io::duplex(4096);
                client.write_all(&wire).await.unwrap();
                let refused = handlers[tag]
                    .stream()
                    .unwrap()
                    .handle(Session::default(), Box::new(server))
                    .await;
                assert!(refused.is_err(), "{}", tag);
            }
            env.users.set_limits(HashMap::new());
            assert_eq!(
                user(&handlers["t"], trojan("tp"))
                    .await
                    .unwrap()
                    .to_string(),
                "alice"
            );
        }

        #[tokio::test]
        async fn a_credential_without_a_name_gives_no_user() {
            let env = RuntimeEnv::default();
            let handlers = build(
                &env,
                inbounds(serde_json::json!([
                    { "name": "", "password": "empty" },
                    { "password": "missing" },
                ])),
            );
            assert!(user(&handlers["t"], trojan("empty")).await.is_none());
            assert!(user(&handlers["t"], trojan("missing")).await.is_none());
        }
    }

    mod limits {
        use super::*;
        use crate::app::stat_manager::StatManager;
        use crate::session::{Network, Session};
        use std::time::Duration;

        fn limited(users: &UserRegistry, name: &str, limits: Limits) {
            users.set_limits(HashMap::from([(name.to_string(), limits)]));
        }

        fn session(user: &UserRef) -> Session {
            Session {
                user: Some(user.clone()),
                network: Network::Tcp,
                ..Default::default()
            }
        }

        fn stream(sm: &StatManager, user: &UserRef) -> crate::adapter::AnyStream {
            let (a, _b) = tokio::io::duplex(1 << 16);
            std::mem::forget(_b);
            sm.stat_stream(Box::new(a), session(user))
        }

        fn closed(sm: &StatManager) -> Vec<bool> {
            sm.connections()
                .iter()
                .map(|c| c.closer.is_closed())
                .collect()
        }

        #[tokio::test]
        async fn a_user_at_its_most_connections_is_refused_another() {
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            limited(
                &users,
                "alice",
                Limits {
                    max_connections: Some(2),
                    ..Default::default()
                },
            );
            let sm = StatManager::new(0, users.clone());
            let first = stream(&sm, &alice);
            let _second = stream(&sm, &alice);
            assert!(!alice.admits(""));
            let _third = stream(&sm, &alice);
            assert_eq!(closed(&sm), [false, false, true]);
            assert_eq!(alice.live(), 2);
            // One gone, another may come.
            drop(first);
            assert!(alice.admits(""));
            let _fourth = stream(&sm, &alice);
            assert_eq!(alice.live(), 2);
            assert_eq!(closed(&sm), [false, true, false]);
            // Others are not limited by it.
            let bob = users.bind("bob");
            let _bobs = (stream(&sm, &bob), stream(&sm, &bob), stream(&sm, &bob));
            assert_eq!(bob.live(), 3);
        }

        /// `max_tcp_connections` counts TCP connections alone: UDP
        /// sessions come on past it, and `max_connections` still counts
        /// them all.
        #[tokio::test]
        async fn max_tcp_connections_counts_tcp_alone() {
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            limited(
                &users,
                "alice",
                Limits {
                    max_connections: Some(4),
                    max_tcp_connections: Some(2),
                    ..Default::default()
                },
            );
            let sm = StatManager::new(0, users.clone());
            let udp = |sm: &StatManager| {
                let (a, _b) = tokio::io::duplex(1 << 16);
                std::mem::forget(_b);
                sm.stat_stream(
                    Box::new(a),
                    Session {
                        user: Some(alice.clone()),
                        network: Network::Udp,
                        ..Default::default()
                    },
                )
            };
            let _t = (stream(&sm, &alice), stream(&sm, &alice));
            assert!(!alice.admits_on("", true));
            assert!(alice.admits_on("", false));
            let _third_tcp = stream(&sm, &alice);
            let _u = (udp(&sm), udp(&sm));
            assert_eq!(closed(&sm), [false, false, true, false, false]);
            assert_eq!((alice.live(), alice.live_tcp()), (4, 2));
            // At max_connections, UDP too is refused.
            let _fifth = udp(&sm);
            assert!(*closed(&sm).last().unwrap());
            assert!(!alice.admits_on("", false));
        }

        /// Limits set by name apply to a user made later, and are put back
        /// to the configuration's by name.
        #[test]
        fn limits_set_by_name_wait_for_their_user() {
            let users = UserRegistry::default();
            users.set_limits(HashMap::from([(
                "carol".to_string(),
                Limits {
                    max_connections: Some(9),
                    ..Default::default()
                },
            )]));
            users.set_limits_named([(
                "carol".to_string(),
                Limits {
                    max_connections: Some(1),
                    ..Default::default()
                },
            )]);
            let carol = users.bind("carol");
            assert_eq!(carol.limits().max_connections, Some(1));
            users.restore_limit_named("carol");
            assert_eq!(carol.limits().max_connections, Some(9));
            // Many at once, those made and not.
            users.set_limits_named((0..1000).map(|n| {
                (
                    format!("u{}", n),
                    Limits {
                        quota_bytes: Some(n + 1),
                        ..Default::default()
                    },
                )
            }));
            assert_eq!(users.bind("u7").limits().quota_bytes, Some(8));
        }

        /// Limits the host set stay over the configuration's through a
        /// reload that leaves the user's configured limits alone; one that
        /// changes them, adds them or takes them away drops the override and
        /// names its user. Restoring drops it too.
        #[test]
        fn an_override_survives_a_reload_that_leaves_its_user_alone() {
            let users = UserRegistry::default();
            let of = |n: u32| Limits {
                max_connections: Some(n),
                ..Default::default()
            };
            let configured = |pairs: &[(&str, u32)]| -> HashMap<String, Limits> {
                pairs
                    .iter()
                    .map(|(name, n)| (name.to_string(), of(*n)))
                    .collect()
            };
            let (alice, bob, carol) = (users.bind("alice"), users.bind("bob"), users.bind("carol"));
            assert!(users
                .set_limits(configured(&[("alice", 9), ("bob", 9)]))
                .is_empty());
            users.set_limits_named([
                ("alice".to_string(), of(1)),
                ("bob".to_string(), of(2)),
                ("carol".to_string(), of(3)),
            ]);
            // Bob's and carol's configured limits change, alice's do not.
            let dropped = users.set_limits(configured(&[("alice", 9), ("bob", 8), ("carol", 7)]));
            assert_eq!(dropped, ["bob", "carol"]);
            assert_eq!(alice.limits(), of(1));
            assert_eq!(bob.limits(), of(8));
            assert_eq!(carol.limits(), of(7));
            // The same again: nothing dropped; taken away: dropped.
            assert!(users
                .set_limits(configured(&[("alice", 9), ("bob", 8), ("carol", 7)]))
                .is_empty());
            assert_eq!(alice.limits(), of(1));
            assert_eq!(users.set_limits(configured(&[])), ["alice"]);
            assert_eq!(alice.limits(), Limits::default());
            // Restored: the configuration's, and no override to drop.
            users.set_limits_named([("bob".to_string(), of(2))]);
            users.restore_limit_named("bob");
            assert_eq!(bob.limits(), Limits::default());
            assert!(users.set_limits(configured(&[("bob", 5)])).is_empty());
            assert_eq!(bob.limits(), of(5));
        }

        /// A combined rate is drawn from both ways, by every connection of
        /// the user, alongside the rates one way; it changes live.
        #[test]
        fn a_combined_rate_is_drawn_from_both_ways() {
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            // 1 Mbps both ways together: 125 kB/s, a burst of 12.5 kB.
            limited(
                &users,
                "alice",
                Limits {
                    total_mbps: Some(1),
                    ..Default::default()
                },
            );
            assert_eq!(alice.chunk(true), Some(1024));
            // Half a second up, then half a second down: the second waits
            // for both, less the burst.
            let up = alice.shape(true, 62_500).unwrap();
            let down = alice.shape(false, 62_500).unwrap();
            assert!(up < Duration::from_millis(450), "{:?}", up);
            assert!(down >= Duration::from_millis(850), "{:?}", down);
            // Datagrams either way are dropped now, and counted by neither.
            assert!(!alice.police(true, 1000));
            assert!(!alice.police(false, 1000));
            // The rate one way and the combined one both apply: the one
            // way that has room still waits for the combined.
            limited(
                &users,
                "alice",
                Limits {
                    up_mbps: Some(1000),
                    total_mbps: Some(1),
                    ..Default::default()
                },
            );
            assert!(alice.shape(true, 1).unwrap() >= Duration::from_millis(800));
            assert!(!alice.police(true, 1000));
            // Taken away, live: nothing holds it back.
            limited(&users, "alice", Limits::default());
            assert_eq!(alice.shape(false, 62_500), None);
            assert!(alice.police(false, 1000));
            assert_eq!(alice.chunk(false), None);
        }

        /// A combined rate shapes a user's TCP: what it sent up and what
        /// it received down share it.
        #[tokio::test]
        async fn tcp_both_ways_shares_a_combined_rate() {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            limited(
                &users,
                "alice",
                Limits {
                    total_mbps: Some(1),
                    ..Default::default()
                },
            );
            let sm = StatManager::new(0, users.clone());
            let (a, _far) = tokio::io::duplex(1 << 20);
            let (b, mut bfar) = tokio::io::duplex(1 << 20);
            let mut up = sm.stat_stream(Box::new(a), session(&alice));
            let mut down = sm.stat_stream(Box::new(b), session(&alice));
            let started = std::time::Instant::now();
            up.write_all(&[0u8; 50_000]).await.unwrap();
            bfar.write_all(&[0u8; 50_000]).await.unwrap();
            let mut buf = vec![0u8; 50_000];
            down.read_exact(&mut buf).await.unwrap();
            let took = started.elapsed();
            // (100 kB - the burst) at 125 kB/s: 0.7 s; each way alone at
            // the same rate would be 0.3 s.
            assert!(
                took >= Duration::from_millis(600) && took < Duration::from_secs(5),
                "{:?}",
                took
            );
        }

        /// Crossing the quota closes every live connection of the user, and
        /// refuses new ones, until the quota is raised.
        #[tokio::test]
        async fn crossing_the_quota_shuts_the_user_out() {
            use tokio::io::AsyncWriteExt;
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            let bob = users.bind("bob");
            limited(
                &users,
                "alice",
                Limits {
                    quota_bytes: Some(10),
                    ..Default::default()
                },
            );
            let sm = StatManager::new(0, users.clone());
            let mut a = stream(&sm, &alice);
            let _idle = stream(&sm, &alice);
            let _bobs = stream(&sm, &bob);
            a.write_all(b"123456789").await.unwrap();
            assert!(alice.active());
            a.write_all(b"0").await.unwrap();
            assert!(alice.status().exhausted());
            assert_eq!(closed(&sm), [true, true, false]);
            assert_eq!(alice.quota_used(), 10);
            assert!(!alice.admits(""));
            assert!(shut_out(&Some(alice.clone())));
            assert!(a.write_all(b"x").await.is_err());

            // A bigger quota lets it in again.
            limited(
                &users,
                "alice",
                Limits {
                    quota_bytes: Some(20),
                    ..Default::default()
                },
            );
            assert!(alice.active());
            // A reset quota counts from what was used.
            limited(
                &users,
                "alice",
                Limits {
                    quota_bytes: Some(10),
                    ..Default::default()
                },
            );
            assert!(!alice.active());
            alice.reset_quota();
            assert!(alice.active());
            assert_eq!(alice.quota_used(), 0);
        }

        #[tokio::test]
        async fn an_expired_user_is_shut_out_at_its_time() {
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            let sm = StatManager::new(0, users.clone());
            let _a = stream(&sm, &alice);
            let expiry = tokio::spawn(users.expiry_task());
            let at = SystemTime::now() + Duration::from_secs(1);
            limited(
                &users,
                "alice",
                Limits {
                    expire_at: Some(at),
                    ..Default::default()
                },
            );
            assert!(alice.active());
            // Expired once its time comes, however slow the machine.
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while alice.active() {
                assert!(std::time::Instant::now() < deadline, "not expired");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(SystemTime::now() >= at);
            assert!(alice.status().expired());
            assert_eq!(closed(&sm), [true]);
            // Later expiry, and it may come back.
            limited(
                &users,
                "alice",
                Limits {
                    expire_at: Some(SystemTime::now() + Duration::from_secs(3600)),
                    ..Default::default()
                },
            );
            assert!(alice.active());
            expiry.abort();
        }

        /// A carrier is closed with its user's connections, or those of
        /// its inbound, until it is dropped; at once when the user is shut
        /// out already.
        #[test]
        fn carriers_close_with_their_user() {
            use std::sync::atomic::{AtomicUsize, Ordering};
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            let closes = Arc::new(AtomicUsize::new(0));
            let counting = || {
                let closes = closes.clone();
                move || {
                    closes.fetch_add(1, Ordering::SeqCst);
                }
            };
            let on_a = alice.carry("a", counting());
            let _on_b = alice.carry("b", counting());
            alice.disconnect_inbound("a");
            assert_eq!(closes.load(Ordering::SeqCst), 1);
            alice.disconnect();
            assert_eq!(closes.load(Ordering::SeqCst), 3);
            drop(on_a);
            alice.disconnect();
            assert_eq!(closes.load(Ordering::SeqCst), 4);

            limited(
                &users,
                "alice",
                Limits {
                    expire_at: Some(SystemTime::UNIX_EPOCH),
                    ..Default::default()
                },
            );
            let before = closes.load(Ordering::SeqCst);
            let _late = alice.carry("a", counting());
            assert_eq!(closes.load(Ordering::SeqCst), before + 1);
        }

        /// A user's TCP goes at its rate, a burst ahead at most, in reads
        /// and writes of a chunk at most; others' are not held back.
        #[tokio::test]
        async fn tcp_is_shaped_to_the_rate() {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            let bob = users.bind("bob");
            // 1 Mbps: 125 kB/s, a burst of 12.5 kB.
            limited(
                &users,
                "alice",
                Limits {
                    up_mbps: Some(1),
                    down_mbps: Some(1),
                    ..Default::default()
                },
            );
            let sm = StatManager::new(0, users.clone());

            let (a, mut far) = tokio::io::duplex(1 << 20);
            let mut s = sm.stat_stream(Box::new(a), session(&alice));
            let started = std::time::Instant::now();
            s.write_all(&[0u8; 50_000]).await.unwrap();
            let took = started.elapsed();
            // (50 kB - the burst) at 125 kB/s: 0.3 s.
            assert!(
                took >= Duration::from_millis(250) && took < Duration::from_secs(5),
                "{:?}",
                took
            );

            far.write_all(&[0u8; 100_000]).await.unwrap();
            let mut buf = vec![0u8; 100_000];
            // A millisecond at 1 Mbps, 125 bytes, is less than the least.
            let n = s.read(&mut buf).await.unwrap();
            assert_eq!(n, 1024);

            let (b, mut bfar) = tokio::io::duplex(1 << 20);
            let mut free = sm.stat_stream(Box::new(b), session(&bob));
            let started = std::time::Instant::now();
            free.write_all(&[0u8; 500_000]).await.unwrap();
            // At alice's rate it would take 4 s.
            assert!(started.elapsed() < Duration::from_secs(2));
            bfar.write_all(&[0u8; 100_000]).await.unwrap();
            assert_eq!(free.read(&mut buf).await.unwrap(), 100_000);
        }

        /// A rate too large to count in bytes a second is no limit, not a
        /// wrapped one.
        #[tokio::test]
        async fn an_enormous_rate_saturates() {
            use tokio::io::AsyncWriteExt;
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            limited(
                &users,
                "alice",
                Limits {
                    up_mbps: Some(u64::MAX),
                    down_mbps: Some(u64::MAX),
                    ..Default::default()
                },
            );
            let sm = StatManager::new(0, users.clone());
            let (a, _far) = tokio::io::duplex(1 << 22);
            let mut s = sm.stat_stream(Box::new(a), session(&alice));
            let started = std::time::Instant::now();
            s.write_all(&vec![0u8; 1 << 21]).await.unwrap();
            // At 1 Mbps it would take 16 s.
            assert!(started.elapsed() < Duration::from_secs(5));
            assert!(alice.police(true, 65_535));
            assert_eq!(alice.shape(true, 65_535), None);
        }

        /// A user's datagrams over its rate and burst are dropped, and not
        /// counted.
        #[tokio::test]
        async fn udp_over_the_rate_is_dropped() {
            use crate::adapter::{
                OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf,
            };
            use crate::session::SocksAddr;
            struct Sink(Arc<AtomicU64>);
            #[async_trait::async_trait]
            impl OutboundDatagramSendHalf for Sink {
                async fn send_to(&mut self, buf: &[u8], _: &SocksAddr) -> std::io::Result<usize> {
                    self.0.fetch_add(buf.len() as u64, Ordering::Relaxed);
                    Ok(buf.len())
                }
                async fn close(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            struct Never;
            #[async_trait::async_trait]
            impl OutboundDatagramRecvHalf for Never {
                async fn recv_from(&mut self, _: &mut [u8]) -> std::io::Result<(usize, SocksAddr)> {
                    std::future::pending().await
                }
            }
            struct Datagram(Arc<AtomicU64>);
            impl OutboundDatagram for Datagram {
                fn split(
                    self: Box<Self>,
                ) -> (
                    Box<dyn OutboundDatagramRecvHalf>,
                    Box<dyn OutboundDatagramSendHalf>,
                ) {
                    (Box::new(Never), Box::new(Sink(self.0)))
                }
            }
            let users = UserRegistry::default();
            let alice = users.bind("alice");
            limited(
                &users,
                "alice",
                Limits {
                    up_mbps: Some(1),
                    ..Default::default()
                },
            );
            let sm = StatManager::new(0, users.clone());
            let sent = Arc::new(AtomicU64::new(0));
            let mut sess = session(&alice);
            sess.network = Network::Udp;
            let (_r, mut s) = sm
                .stat_outbound_datagram(Box::new(Datagram(sent.clone())), sess)
                .split();
            let started = std::time::Instant::now();
            for _ in 0..100 {
                assert_eq!(
                    s.send_to(&[0u8; 1200], &SocksAddr::any()).await.unwrap(),
                    1200
                );
            }
            // The 12.5 kB burst and the one datagram it overlaps, and what
            // the rate let through while they were sent.
            let sent = sent.load(Ordering::Relaxed);
            let refilled = (started.elapsed().as_secs_f64() * 125_000.0) as u64 + 1200;
            assert!(sent >= 12_000 && sent <= 14_400 + refilled, "{}", sent);
            assert!(sent < 100 * 1200, "{}", sent);
            assert_eq!(alice.traffic().counts().up, sent);
        }

        #[test]
        fn a_user_made_after_the_limits_is_limited_by_them() {
            let users = UserRegistry::default();
            limited(
                &users,
                "alice",
                Limits {
                    expire_at: Some(SystemTime::UNIX_EPOCH),
                    ..Default::default()
                },
            );
            let alice = users.bind("alice");
            assert!(alice.status().expired());
            assert!(users.bind("bob").active());
            // Limits no longer configured are lifted.
            users.set_limits(HashMap::new());
            assert!(alice.active());
        }

        #[cfg(all(feature = "inbound-trojan", feature = "inbound-http"))]
        fn config(json: &str) -> anyhow::Result<crate::config::Config> {
            crate::config::from_string(json)
        }

        #[cfg(all(feature = "inbound-trojan", feature = "inbound-http"))]
        fn with_limits(limits: &str, cache_file: bool) -> anyhow::Result<crate::config::Config> {
            config(&format!(
                r#"{{"inbounds": [{{"type": "trojan", "tag": "t", "listen_port": 1,
                     "users": [{{"name": "alice", "password": "p"}}]}},
                   {{"type": "http", "tag": "h", "listen_port": 2,
                     "users": [{{"username": "bob", "password": "p"}}]}}],
                   "user_limits": {limits},
                   "experimental": {{"cache_file": {{"enabled": {cache_file}}}}}}}"#
            ))
        }

        #[cfg(all(feature = "inbound-trojan", feature = "inbound-http"))]
        #[test]
        fn user_limits_are_read_and_checked() {
            let c = with_limits(
                r#"{"alice": {"max_connections": 3, "max_tcp_connections": 2,
                              "quota_bytes": 100,
                              "expire_at": "2026-12-31T16:00:00+08:00",
                              "up_mbps": 5, "down_mbps": 50, "total_mbps": 40},
                    "bob": {}}"#,
                true,
            )
            .unwrap();
            let limits = UserRegistry::configured(&c);
            assert_eq!(
                limits["alice"],
                Limits {
                    max_connections: Some(3),
                    max_tcp_connections: Some(2),
                    quota_bytes: Some(100),
                    expire_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_798_704_000)),
                    up_mbps: Some(5),
                    down_mbps: Some(50),
                    total_mbps: Some(40),
                }
            );
            assert_eq!(limits["bob"], Limits::default());

            for (limits, cache_file, error) in [
                (
                    r#"{"carol": {}}"#,
                    true,
                    "user_limits.carol: no inbound has a user of that name",
                ),
                (
                    r#"{"alice": {"max_connections": 0}}"#,
                    true,
                    "user_limits.alice.max_connections: must be more than 0",
                ),
                (
                    r#"{"alice": {"max_tcp_connections": 0}}"#,
                    true,
                    "user_limits.alice.max_tcp_connections: must be more than 0",
                ),
                (
                    r#"{"alice": {"quota_bytes": 0}}"#,
                    true,
                    "user_limits.alice.quota_bytes: must be more than 0",
                ),
                (
                    r#"{"alice": {"up_mbps": 0}}"#,
                    true,
                    "user_limits.alice.up_mbps: must be more than 0",
                ),
                (
                    r#"{"alice": {"down_mbps": 0}}"#,
                    true,
                    "user_limits.alice.down_mbps: must be more than 0",
                ),
                (
                    r#"{"alice": {"total_mbps": 0}}"#,
                    true,
                    "user_limits.alice.total_mbps: must be more than 0",
                ),
                (
                    r#"{"alice": {"quota_bytes": 1}}"#,
                    false,
                    "user_limits.alice.quota_bytes: needs experimental.cache_file",
                ),
                (
                    r#"{"alice": {"expire_at": "tomorrow"}}"#,
                    true,
                    "user_limits.alice.expire_at: \"tomorrow\" is not an RFC 3339 time",
                ),
                (
                    r#"{"alice": {"max_connection": 1}}"#,
                    true,
                    "unknown field `max_connection`",
                ),
                (r#"{"alice": {"quota_bytes": -1}}"#, true, "user_limits"),
            ] {
                let e = format!("{:#}", with_limits(limits, cache_file).unwrap_err());
                assert!(e.contains(error), "{}: {}", limits, e);
            }
        }
    }
}
