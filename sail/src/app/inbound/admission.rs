//! Admission under memory pressure: what an instance does with connections
//! that have not authenticated yet when memory, or descriptors, run short
//! (`inbound.memory_reserve`, sail#15). The fixed counts
//! (`inbound.max_handshakes`) bound a flood by number; a small host can run
//! out of memory before them, under a burst of handshakes or many slow
//! ones.
//!
//! A connection is unauthenticated while it holds a handshake place, from
//! its accept until it is a session (handshakes.rs). Under pressure, as a
//! connection is accepted:
//! - the handshakes in flight longer than `inbound.handshake_stall` are
//!   closed, oldest first: what a slow client holds goes to those that
//!   handshake promptly, where refusing new ones alone would leave the
//!   flood holding everything;
//! - with `inbound.score_sources`, a source whose last four handshakes or
//!   more in a minute failed, none succeeding since, is refused;
//! - under hard pressure, less than half the reserve free, every new one
//!   is refused.
//!
//! Whatever the memory, when an inbound's handshake places are all taken
//! (`inbound.max_handshakes`) its handshakes stalled past the stall are
//! closed too, oldest first: a slow-loris would otherwise hold every place,
//! and a client that handshakes promptly gets one within the stall.
//!
//! Sessions, the connections that authenticated, are never touched.
//!
//! A host that embeds sail adds checks of its own (`HostHooks`): one per
//! accepted connection and QUIC handshake, by its addresses, and one per
//! session, before it is routed. Each runs after sail's own, synchronously,
//! in the task of its own connection; a refusal is counted under its
//! reason, and a check that panics refuses.
//!
//! Pressure is read when a connection is accepted, at most every
//! `READ_EVERY`, as the QUIC window budget reads it: an idle instance never
//! wakes for it. A sing-box based server in production, whose admission
//! this follows, holds a 20% reserve, evicts handshakes stalled 3 s, and
//! refuses failing sources; sing-box itself has none of this. Measured
//! (sail#15): under a slow-loris at 2000 new connections a second an
//! inbound, a prompt client got in 19 or 20 times of 146 with the places
//! full and nothing evicted, and under memory pressure on a router 145 of
//! 145 with eviction against 62 without.

use portable_atomic::AtomicU64;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::control::events::{AdmissionChange, AdmissionLevel, EventHub};

/// The reasons a host refuses for that are counted apart, at most (a
/// judgment: a host's reasons are a handful; one that makes them of what
/// it refuses is not to grow the count without bound). Those past it are
/// counted under `other`.
const HOST_REASONS: usize = 64;

/// What a host's check says of a connection: `Err` refuses it, why.
pub type HostVerdict = Result<(), Cow<'static, str>>;

/// What checks a session, before it is routed.
type CredentialContext = dyn Fn(
        &crate::embed::CredentialInfo<'_>,
    ) -> Result<crate::control::context::RecordContext, Cow<'static, str>>
    + Send
    + Sync;

type BindContext = dyn Fn(
        &crate::session::Session,
    ) -> Result<crate::control::context::RecordContext, Cow<'static, str>>
    + Send
    + Sync;

type AdmitCheck = dyn Fn(&crate::session::Session) -> HostVerdict + Send + Sync;

/// What checks a connection by its source and the address it came to.
type SourceCheck = dyn Fn(SocketAddr, SocketAddr) -> HostVerdict + Send + Sync;

/// A host's own checks, run after sail's admission (embed::Options::admit,
/// admit_source).
#[derive(Default)]
pub struct HostHooks {
    /// Of each session, once its inbound authenticated it, before it is
    /// routed.
    pub(crate) admit: Option<Box<AdmitCheck>>,
    pub(crate) bind: Option<Box<BindContext>>,
    pub(crate) credential: Option<Box<CredentialContext>>,
    /// Of each connection accepted and QUIC handshake, by its source and
    /// the address it came to, before its handshake.
    pub(crate) admit_source: Option<Box<SourceCheck>>,
}

impl HostHooks {
    pub(crate) fn is_empty(&self) -> bool {
        self.admit.is_none()
            && self.admit_source.is_none()
            && self.bind.is_none()
            && self.credential.is_none()
    }
}

/// A host's checks, shared by every run of its instance.
#[doc(hidden)]
#[derive(Clone)]
pub struct HostHooksRef(pub(crate) Arc<HostHooks>);

impl PartialEq for HostHooksRef {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for HostHooksRef {}

impl std::fmt::Debug for HostHooksRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostHooks")
    }
}

/// How often the memory is read, at most (a judgment: a flood fills memory
/// over seconds; a read is one small file, two with a cgroup).
const READ_EVERY: Duration = Duration::from_millis(250);

/// Pressure ends once this much more than the reserve is free, in
/// hundredths of the reserve, so that it does not flap on its edge (a
/// judgment).
const HYSTERESIS: u64 = 5;

/// A source is judged on its handshakes of this long (a judgment).
const SCORE_WINDOW: Duration = Duration::from_secs(60);

/// A source is refused once this many of its handshakes in the window
/// failed, none succeeding since (a judgment: a client that mistyped its
/// password a few times is not refused for it, and one that then got in
/// is not refused at all).
const SCORE_MIN: u32 = 4;

/// The sources judged at once, at most (a judgment): a flood from spread
/// addresses costs no more than this.
const SCORE_SOURCES: usize = 4096;

/// The refusals are logged at most this often, with their count since.
const WARN_EVERY: Duration = Duration::from_secs(10);

/// Why a connection was refused at accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Hard pressure: every new one is.
    Hard,
    /// Its source's handshakes failed, none succeeding since.
    Source,
}

/// What the instance's admission did, since it started.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmissionInfo {
    pub level: AdmissionLevel,
    /// The memory free as last read, and the reserve, in bytes.
    pub free: Option<u64>,
    pub reserve: u64,
    /// Connections in their handshake now.
    pub handshakes: usize,
    /// Refused at accept, or as a host submitted them, under hard pressure.
    pub refused: u64,
    /// Refused at accept for their source's failures.
    pub refused_sources: u64,
    /// QUIC connections refused before their handshake, under pressure.
    pub refused_quic: u64,
    /// Closed in their handshake, stalled under pressure.
    pub evicted: u64,
    /// Closed in their handshake, stalled while their inbound's places
    /// were all taken.
    pub evicted_full: u64,
    /// How long the instance was under pressure, hard pressure included.
    pub pressure: Duration,
    /// Refused by the host's checks, by the reason each gave.
    pub host_refused: BTreeMap<String, u64>,
    /// The host's checks that panicked, each refusing its connection.
    pub host_panics: u64,
}

/// The handshakes of an instance, and how hard it holds back new ones.
pub struct Admission {
    /// Bytes kept free; 0, memory is not looked at.
    reserve: u64,
    /// More handshakes than this are pressure; 0, no such bound.
    descriptors: usize,
    stall: Duration,
    score: bool,
    free: Box<dyn Fn() -> Option<u64> + Send + Sync>,
    /// How often the memory is read, at most: `READ_EVERY`.
    read_every: Duration,
    start: Instant,
    /// When to read the memory again, and to look for stalled handshakes,
    /// in milliseconds from `start`.
    next: AtomicU64,
    level: AtomicU8,
    free_read: AtomicU64,
    handshakes: Mutex<InFlight>,
    in_flight: AtomicUsize,
    sources: Mutex<HashMap<IpAddr, Score>>,
    refused: AtomicU64,
    refused_sources: AtomicU64,
    refused_quic: AtomicU64,
    evicted: AtomicU64,
    evicted_full: AtomicU64,
    /// When to look for stalled handshakes again for an inbound whose
    /// places are all taken, in milliseconds from `start`.
    next_full: AtomicU64,
    /// When pressure began, and what earlier pressure lasted.
    pressure: Mutex<(Option<Instant>, Duration)>,
    unwarned: AtomicU64,
    warned: Mutex<Option<Instant>>,
    events: EventHub,
    hooks: Option<Arc<HostHooks>>,
    host_refused: Mutex<BTreeMap<String, u64>>,
    host_panics: AtomicU64,
}

#[derive(Default)]
struct InFlight {
    next_id: u64,
    entries: HashMap<u64, Arc<Entry>>,
}

/// One handshake in flight.
struct Entry {
    started: Instant,
    /// Its inbound's tag.
    inbound: Arc<str>,
    /// It authenticated: it is no longer evicted.
    done: AtomicBool,
    evicted: AtomicBool,
    notify: tokio::sync::Notify,
}

/// A source's handshakes that failed in the window, none succeeding
/// since.
struct Score {
    /// When the first of them failed.
    since: Instant,
    failed: u32,
}

impl Score {
    fn failing(&self) -> bool {
        self.failed >= SCORE_MIN
    }
}

const NORMAL: u8 = 0;
const PRESSURE: u8 = 1;
const HARD: u8 = 2;

fn level_of(code: u8) -> AdmissionLevel {
    match code {
        NORMAL => AdmissionLevel::Normal,
        PRESSURE => AdmissionLevel::Pressure,
        _ => AdmissionLevel::Hard,
    }
}

impl Admission {
    /// The admission `options` set, telling its changes to `events`, with
    /// the host's checks `hooks`; none when neither memory nor descriptors
    /// are looked at and the host has no checks.
    pub(crate) fn new(
        options: &crate::runtime::options::Inbound,
        events: EventHub,
        hooks: Option<&HostHooksRef>,
    ) -> Option<Arc<Self>> {
        let hooks = hooks
            .map(|hooks| hooks.0.clone())
            .filter(|hooks| !hooks.is_empty());
        let total = crate::runtime::system_memory::total();
        let admission = match Self::of_memory(options, total, events.clone()) {
            Some(admission) => admission,
            // sail's own off: the host's checks alone.
            None => {
                hooks.as_ref()?;
                Self::with(
                    0,
                    0,
                    options.handshake_stall,
                    false,
                    Box::new(|| None),
                    READ_EVERY,
                    events,
                )
            }
        };
        Some(Arc::new(Self { hooks, ..admission }))
    }

    /// As `new`, the system giving `total` bytes of memory. Where that
    /// cannot be read (Windows, macOS), a reserve set still keeps admission
    /// on: memory pressure is never seen, but a full inbound closes its
    /// stalled handshakes all the same.
    fn of_memory(
        options: &crate::runtime::options::Inbound,
        total: Option<u64>,
        events: EventHub,
    ) -> Option<Self> {
        if options.memory_reserve == 0 && options.handshake_descriptor_share == 0 {
            return None;
        }
        if options.memory_reserve > 0 && total.is_none() {
            info!(
                "admission: free memory cannot be read here: memory pressure is not seen, \
                 and a full inbound still closes its stalled handshakes"
            );
        }
        let reserve = total.map_or(0, |total| total / 100 * u64::from(options.memory_reserve));
        let descriptors = match options.handshake_descriptor_share {
            0 => 0,
            share => file_limit() / share as usize,
        };
        let free = crate::runtime::system_memory::Free::new();
        Some(Self::with(
            reserve,
            descriptors,
            options.handshake_stall,
            options.score_sources,
            Box::new(move || free.bytes()),
            READ_EVERY,
            events,
        ))
    }

    fn with(
        reserve: u64,
        descriptors: usize,
        stall: Duration,
        score: bool,
        free: Box<dyn Fn() -> Option<u64> + Send + Sync>,
        read_every: Duration,
        events: EventHub,
    ) -> Self {
        Admission {
            reserve,
            descriptors,
            stall,
            score,
            free,
            read_every,
            start: Instant::now(),
            next: AtomicU64::new(0),
            level: AtomicU8::new(NORMAL),
            free_read: AtomicU64::new(u64::MAX),
            handshakes: Mutex::default(),
            in_flight: AtomicUsize::new(0),
            sources: Mutex::default(),
            refused: AtomicU64::new(0),
            refused_sources: AtomicU64::new(0),
            refused_quic: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            evicted_full: AtomicU64::new(0),
            next_full: AtomicU64::new(0),
            pressure: Mutex::default(),
            unwarned: AtomicU64::new(0),
            warned: Mutex::default(),
            events,
            hooks: None,
            host_refused: Mutex::default(),
            host_panics: AtomicU64::new(0),
        }
    }

    /// Whether a connection from `source` is taken in, as it is accepted:
    /// under pressure, the stalled handshakes are closed first.
    pub(crate) fn check(&self, source: IpAddr) -> Result<(), Refusal> {
        let level = self.update();
        if level == NORMAL {
            return Ok(());
        }
        if level == HARD {
            self.refused.fetch_add(1, Ordering::Relaxed);
            self.warn("hard memory pressure");
            return Err(Refusal::Hard);
        }
        if self.score && self.failing(source) {
            self.refused_sources.fetch_add(1, Ordering::Relaxed);
            self.warn("its source's handshakes failed, under memory pressure");
            return Err(Refusal::Source);
        }
        Ok(())
    }

    /// Whether the host checks the connections by their addresses.
    pub(crate) fn checks_sources(&self) -> bool {
        self.hooks
            .as_ref()
            .is_some_and(|h| h.admit_source.is_some())
    }

    /// Whether the host checks each session before it is routed.
    pub(crate) fn checks_sessions(&self) -> bool {
        self.hooks
            .as_ref()
            .is_some_and(|h| h.admit.is_some() || h.bind.is_some())
    }

    /// Called while building the actual authentication row; an old row
    /// and its accepted UserRefs retain their old snapshot after reload.
    #[cfg(any(
        feature = "inbound-shadowsocks",
        feature = "inbound-vless",
        feature = "inbound-anytls"
    ))]
    pub(crate) fn bind_credential(
        &self,
        users: &crate::user::UserRegistry,
        protocol: &'static str,
        inbound: &str,
        name: Option<&str>,
        credential: &str,
    ) -> anyhow::Result<Option<crate::user::UserRef>> {
        let Some(name) = name.filter(|name| !name.is_empty()) else {
            return Ok(None);
        };
        let user = users.bind(name);
        let Some(bind) = self.hooks.as_ref().and_then(|h| h.credential.as_ref()) else {
            return Ok(Some(user));
        };
        let info = crate::embed::CredentialInfo {
            protocol,
            inbound,
            name,
            credential,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bind(&info)));
        match result {
            Ok(Ok(context)) => Ok(Some(user.with_credential_context(context))),
            Ok(Err(_)) => anyhow::bail!("credential context capacity exhausted"),
            Err(_) => anyhow::bail!("credential context callback panicked"),
        }
    }

    /// Freeze before user admission. Inherited contexts are never rebound.
    pub(crate) fn bind_session(
        &self,
        sess: &mut crate::session::Session,
    ) -> Result<(), Option<Cow<'static, str>>> {
        if sess.record_context.is_some() {
            return Ok(());
        }
        let Some(bind) = self.hooks.as_ref().and_then(|h| h.bind.as_ref()) else {
            return Ok(());
        };
        let mut context = None;
        self.host_verdict(|| {
            context = Some(bind(sess)?);
            Ok(())
        })?;
        sess.record_context = context;
        Ok(())
    }

    /// Whether the host takes in a connection from `source` to `local`, as
    /// it is accepted, before its handshake: sail's own admission took it.
    pub(crate) fn host_admits_source(&self, source: SocketAddr, local: SocketAddr) -> bool {
        match self.hooks.as_ref().and_then(|h| h.admit_source.as_ref()) {
            Some(check) => self.host_verdict(|| check(source, local)).is_ok(),
            None => true,
        }
    }

    /// Whether the host takes in the session `sess`, which its inbound
    /// authenticated, before it is routed; else why not, none for a check
    /// that panicked.
    pub(crate) fn host_admits(
        &self,
        sess: &crate::session::Session,
    ) -> Result<(), Option<Cow<'static, str>>> {
        match self.hooks.as_ref().and_then(|h| h.admit.as_ref()) {
            Some(check) => self.host_verdict(|| check(sess)),
            None => Ok(()),
        }
    }

    /// What a host's check says, counted: a panic refuses, and goes no
    /// further than here. It is called inline, in the connection's task:
    /// a check is to answer in microseconds, and one slower holds back
    /// the worker thread it runs on. As blocking work (`block_in_place`)
    /// it held back its own connection alone, but cost about 10 µs of CPU
    /// and a tenth of the accept rate of a churn of short connections
    /// (measured, the check returning at once), for a check that breaks
    /// its contract.
    fn host_verdict(
        &self,
        check: impl FnOnce() -> HostVerdict,
    ) -> Result<(), Option<Cow<'static, str>>> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(check)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(reason)) => {
                let mut refused = self.host_refused.lock().unwrap_or_else(|e| e.into_inner());
                let counted = refused.contains_key(reason.as_ref()) || refused.len() < HOST_REASONS;
                let key = match counted {
                    true => reason.to_string(),
                    false => "other".to_string(),
                };
                *refused.entry(key).or_default() += 1;
                Err(Some(reason))
            }
            Err(_) => {
                self.host_panics.fetch_add(1, Ordering::Relaxed);
                warn!("admission: the host's check panicked: the connection is refused");
                Err(None)
            }
        }
    }

    /// Whether a session a host submits with no listener is refused: under
    /// hard pressure, as every new connection is. It authenticated, so its
    /// source is not judged.
    pub(crate) fn refuses_submitted(&self) -> bool {
        if self.update() != HARD {
            return false;
        }
        self.refused.fetch_add(1, Ordering::Relaxed);
        self.warn("hard memory pressure");
        true
    }

    /// Whether a QUIC connection from `source` is refused before its
    /// handshake, as an endpoint takes it: under pressure, it is. A QUIC
    /// handshake in flight cannot be closed as a TCP one is, and it is
    /// left to `quic.server_handshake_timeout`; so new ones are not let
    /// in while memory is short.
    #[cfg(any(feature = "inbound-hysteria2", feature = "inbound-tuic"))]
    pub(crate) fn refuses_quic(&self, _source: IpAddr) -> bool {
        if self.update() == NORMAL {
            return false;
        }
        self.refused_quic.fetch_add(1, Ordering::Relaxed);
        self.warn("QUIC, under memory pressure");
        true
    }

    /// A handshake of a connection from `source` that was taken in, in
    /// flight until the ticket is told it authenticated or is dropped.
    pub(crate) fn enter(self: &Arc<Self>, source: IpAddr, inbound: &Arc<str>) -> Ticket {
        let entry = Arc::new(Entry {
            started: Instant::now(),
            inbound: inbound.clone(),
            done: AtomicBool::new(false),
            evicted: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        });
        let id = {
            let mut handshakes = self.handshakes.lock().unwrap_or_else(|e| e.into_inner());
            let id = handshakes.next_id;
            handshakes.next_id += 1;
            handshakes.entries.insert(id, entry.clone());
            id
        };
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        Ticket {
            admission: self.clone(),
            entry,
            id,
            source,
            ended: false,
        }
    }

    /// The level now, read again if it was read more than `READ_EVERY`
    /// ago; then, under pressure, the stalled handshakes closed.
    fn update(&self) -> u8 {
        let now = self.start.elapsed().as_millis() as u64;
        let next = self.next.load(Ordering::Relaxed);
        if now < next
            || self
                .next
                .compare_exchange(
                    next,
                    now + self.read_every.as_millis() as u64,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return self.level.load(Ordering::Relaxed);
        }
        let free = (self.reserve > 0).then(|| (self.free)()).flatten();
        self.free_read
            .store(free.unwrap_or(u64::MAX), Ordering::Relaxed);
        let was = self.level.load(Ordering::Relaxed);
        let mut level = match free {
            Some(free) if free < self.reserve / 2 => HARD,
            Some(free) if free < self.reserve => PRESSURE,
            // Still short of the reserve and its margin: pressure goes on.
            Some(free) if was != NORMAL && free < self.reserve / 100 * (100 + HYSTERESIS) => {
                PRESSURE
            }
            _ => NORMAL,
        };
        if self.descriptors > 0 && self.in_flight.load(Ordering::Relaxed) > self.descriptors {
            level = level.max(PRESSURE);
        }
        if level != was {
            self.level.store(level, Ordering::Relaxed);
            self.changed(was, level, free);
        }
        if level != NORMAL {
            let evicted = self.evict(None);
            self.evicted.fetch_add(evicted, Ordering::Relaxed);
        }
        level
    }

    /// The inbound `inbound` has no handshake place left for a connection
    /// it accepted: its handshakes stalled past the stall are closed,
    /// oldest first, at most every `READ_EVERY`, so that the next prompt
    /// client finds a place.
    pub(crate) fn full(&self, inbound: &str) {
        let now = self.start.elapsed().as_millis() as u64;
        let next = self.next_full.load(Ordering::Relaxed);
        if now < next
            || self
                .next_full
                .compare_exchange(
                    next,
                    now + self.read_every.as_millis() as u64,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return;
        }
        let evicted = self.evict(Some(inbound));
        self.evicted_full.fetch_add(evicted, Ordering::Relaxed);
    }

    /// Tells and logs a change of level, and keeps how long pressure
    /// lasted.
    fn changed(&self, was: u8, level: u8, free: Option<u64>) {
        let handshakes = self.in_flight.load(Ordering::Relaxed);
        {
            let mut pressure = self.pressure.lock().unwrap_or_else(|e| e.into_inner());
            match (was == NORMAL, level == NORMAL) {
                (true, false) => pressure.0 = Some(Instant::now()),
                (false, true) => {
                    if let Some(since) = pressure.0.take() {
                        pressure.1 += since.elapsed();
                    }
                }
                _ => {}
            }
        }
        let mib = |bytes: u64| bytes >> 20;
        let free_text = free.map_or("unknown".to_string(), |free| format!("{} MiB", mib(free)));
        match level {
            NORMAL => info!(
                "admission: memory pressure over: {} free (reserve {} MiB), {} handshakes",
                free_text,
                mib(self.reserve),
                handshakes
            ),
            _ => warn!(
                "admission: {}: {} free (reserve {} MiB), {} handshakes: stalled ones are \
                 closed{}",
                match level {
                    PRESSURE => "memory pressure",
                    _ => "hard memory pressure",
                },
                free_text,
                mib(self.reserve),
                handshakes,
                match level {
                    PRESSURE if self.score => ", failing sources refused",
                    PRESSURE => "",
                    _ => ", new connections refused",
                }
            ),
        }
        self.events.admission_changed(AdmissionChange {
            level: level_of(level),
            free,
            reserve: self.reserve,
            handshakes,
        });
    }

    /// Closes the handshakes in flight longer than the stall, of `inbound`
    /// or of every inbound, oldest first; how many.
    fn evict(&self, inbound: Option<&str>) -> u64 {
        let mut stalled: Vec<Arc<Entry>> = self
            .handshakes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .values()
            .filter(|e| {
                e.started.elapsed() >= self.stall
                    && !e.done.load(Ordering::Relaxed)
                    && inbound.is_none_or(|inbound| *e.inbound == *inbound)
            })
            .cloned()
            .collect();
        stalled.sort_by_key(|e| e.started);
        let mut evicted = 0;
        for entry in stalled {
            if !entry.evicted.swap(true, Ordering::Relaxed) {
                evicted += 1;
                entry.notify.notify_waiters();
            }
        }
        evicted
    }

    /// Whether `source`'s handshakes in the window failed, enough of them
    /// and none succeeding since.
    fn failing(&self, source: IpAddr) -> bool {
        let sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        sources
            .get(&source)
            .is_some_and(|s| s.since.elapsed() < SCORE_WINDOW && s.failing())
    }

    /// Counts a handshake of `source` that failed; one that authenticated
    /// clears its failures.
    fn scored(&self, source: IpAddr, ok: bool) {
        if !self.score {
            return;
        }
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        if ok {
            sources.remove(&source);
            return;
        }
        if sources.len() >= SCORE_SOURCES && !sources.contains_key(&source) {
            sources.retain(|_, s| s.since.elapsed() < SCORE_WINDOW);
            if sources.len() >= SCORE_SOURCES {
                return;
            }
        }
        let score = sources.entry(source).or_insert_with(|| Score {
            since: Instant::now(),
            failed: 0,
        });
        if score.since.elapsed() >= SCORE_WINDOW {
            *score = Score {
                since: Instant::now(),
                failed: 0,
            };
        }
        score.failed += 1;
    }

    fn warn(&self, why: &str) {
        let refused = self.unwarned.fetch_add(1, Ordering::Relaxed) + 1;
        let mut warned = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        if warned.is_none_or(|at| at.elapsed() >= WARN_EVERY) {
            *warned = Some(Instant::now());
            self.unwarned.store(0, Ordering::Relaxed);
            warn!(
                "admission: {} connections closed at accept: {}",
                refused, why
            );
        }
    }

    /// What it did, since it started.
    pub(crate) fn info(&self) -> AdmissionInfo {
        let free = self.free_read.load(Ordering::Relaxed);
        let pressure = {
            let pressure = self.pressure.lock().unwrap_or_else(|e| e.into_inner());
            pressure.1 + pressure.0.map_or(Duration::ZERO, |since| since.elapsed())
        };
        AdmissionInfo {
            level: level_of(self.level.load(Ordering::Relaxed)),
            free: (free != u64::MAX).then_some(free),
            reserve: self.reserve,
            handshakes: self.in_flight.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            refused_sources: self.refused_sources.load(Ordering::Relaxed),
            refused_quic: self.refused_quic.load(Ordering::Relaxed),
            evicted: self.evicted.load(Ordering::Relaxed),
            evicted_full: self.evicted_full.load(Ordering::Relaxed),
            pressure,
            host_refused: self
                .host_refused
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            host_panics: self.host_panics.load(Ordering::Relaxed),
        }
    }
}

impl Admission {
    /// One under pressure from the start: less free than its reserve.
    #[cfg(all(test, feature = "inbound-hysteria2"))]
    pub(crate) fn under_pressure() -> Arc<Self> {
        Arc::new(Self::with(
            100,
            0,
            Duration::from_secs(3),
            false,
            Box::new(|| Some(90)),
            Duration::ZERO,
            EventHub::default(),
        ))
    }
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admission")
            .field("reserve", &self.reserve)
            .field("level", &self.level.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// A handshake in flight: it fails unless told it authenticated before
/// it is dropped.
pub(crate) struct Ticket {
    admission: Arc<Admission>,
    entry: Arc<Entry>,
    id: u64,
    source: IpAddr,
    ended: bool,
}

impl Ticket {
    /// It authenticated: it is a session from now on, never evicted, and
    /// its source is counted as one that succeeded.
    pub(crate) fn succeeded(&mut self) {
        if !self.ended {
            self.ended = true;
            self.entry.done.store(true, Ordering::Relaxed);
            self.end();
            self.admission.scored(self.source, true);
        }
    }

    /// Ready once it is evicted, before it authenticated; never otherwise.
    pub(crate) fn eviction(&self) -> Eviction {
        Eviction(self.entry.clone())
    }

    fn end(&self) {
        self.admission
            .handshakes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .remove(&self.id);
        self.admission.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        if !self.ended {
            self.end();
            self.admission.scored(self.source, false);
        }
    }
}

/// A handshake's eviction, waited for beside its connection.
pub(crate) struct Eviction(Arc<Entry>);

impl Eviction {
    pub(crate) async fn evicted(self) {
        loop {
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.0.evicted.load(Ordering::Relaxed) && !self.0.done.load(Ordering::Relaxed) {
                return;
            }
            notified.await;
        }
    }
}

/// The open-file limit the process runs with; none known, as if unlimited.
fn file_limit() -> usize {
    #[cfg(unix)]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes the struct it is given, nothing else.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            return usize::try_from(limit.rlim_cur).unwrap_or(usize::MAX);
        }
    }
    usize::MAX
}

#[cfg(test)]
mod tests;
