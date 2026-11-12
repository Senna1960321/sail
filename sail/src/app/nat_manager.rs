use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::{abortable, BoxFuture};
use lru::LruCache;
use tokio::sync::{
    mpsc::{self, Sender},
    oneshot, Mutex, MutexGuard,
};
use tracing::{debug, error, trace, Instrument};

use crate::app::dispatcher::{DatagramSniffer, Dispatcher};
use crate::app::router::hijack_dns::{PendingAnswer, PendingAnswers};
use crate::session::{DatagramSource, Network, Session, SocksAddr, UdpAssociation};

#[derive(Debug)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
    // Keep queued plaintext tied to its authenticated encryption peer.
    resource_lease: Option<crate::session::DatagramResourceLease>,
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
            resource_lease: None,
        }
    }

    fn with_resource_lease(mut self, lease: Option<crate::session::DatagramResourceLease>) -> Self {
        self.resource_lease = lease;
        self
    }

    /// Consumes the whole reply, keeping its peer pinned through encode
    /// and socket send, including error and cancellation. Both inbound
    /// delivery loops use this ownership boundary.
    pub(crate) async fn send_through(
        self,
        sender: &mut dyn crate::adapter::InboundDatagramSendHalf,
    ) -> std::io::Result<usize> {
        let result = match self.dst_addr.as_socket_addr() {
            Some(dst) => sender.send_to(&self.data, &self.src_addr, dst).await,
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "datagram reply is not an IP address",
            )),
        };
        drop(self);
        result
    }
}

impl std::fmt::Display for UdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "src={} dst={} len={}",
            self.src_addr,
            self.dst_addr,
            self.data.len()
        )
    }
}

/// A UDP session: the inbound its datagrams came in on, and their source.
/// The inbound is part of it, for sources of different inbounds are
/// unrelated even when their addresses happen to be the same.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct NatKey {
    inbound_tag: String,
    source: DatagramSource,
}

impl NatKey {
    fn new(inbound_tag: &str, source: &DatagramSource) -> Self {
        NatKey {
            inbound_tag: inbound_tag.to_string(),
            source: source.clone(),
        }
    }
}

impl std::fmt::Display for NatKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[{}] {}", self.inbound_tag, self.source)
    }
}

/// Reservations for requests still owned by the private uplink queue.
/// Only the receiver owner closes this ledger; entry clones cannot close it.
#[derive(Clone)]
struct QueuedAdmissions(Arc<std::sync::Mutex<AdmissionState>>);

struct AdmissionState {
    pending: PendingAnswers,
    queued: Option<usize>,
}

struct AdmissionQueueOwner(QueuedAdmissions);

impl QueuedAdmissions {
    fn new(pending: PendingAnswers) -> (Self, AdmissionQueueOwner) {
        let queue = Self(Arc::new(std::sync::Mutex::new(AdmissionState {
            pending,
            queued: Some(0),
        })));
        (queue.clone(), AdmissionQueueOwner(queue))
    }

    fn reserve(&self) -> bool {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(n) = state.queued.as_mut() else {
            return false;
        };
        *n += 1;
        state.pending.add(1);
        true
    }

    fn reject_one(&self) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = state.queued.as_mut().filter(|n| **n > 0) {
            *n -= 1;
            state.pending.finish(1);
        }
    }
}

impl AdmissionQueueOwner {
    fn take_one(&self) -> Option<PendingAnswer> {
        let mut state = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
        let n = state.queued.as_mut().filter(|n| **n > 0)?;
        *n -= 1;
        Some(state.pending.reserved())
    }
}

impl Drop for AdmissionQueueOwner {
    fn drop(&mut self) {
        let mut state = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = state.queued.take() {
            state.pending.finish(n);
        }
    }
}

struct NatSession {
    #[cfg(feature = "internal-udp-target-diagnostics")]
    diagnostic_trace: Option<super::udp_target_diagnostics::Trace>,
    uplink: Sender<UdpPacket>,
    abort: oneshot::Sender<bool>,
    last_activity: Instant,
    idle_timeout: Duration,
    dns_answered: bool,
    // Also identifies the entry while a dispatch awaits routing/admission.
    generation: PendingAnswers,
    // Some before routing, retained only for hijack-dns after routing.
    pending: Option<PendingAnswers>,
    admissions: Option<QueuedAdmissions>,
}

impl NatSession {
    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_activity) >= self.idle_timeout
            || (self.dns_answered && self.pending.as_ref().is_none_or(PendingAnswers::is_idle))
    }
}

type SessionMap = HashMap<NatKey, NatSession>;

/// An old dispatch/downlink cannot remove a replacement of the same key.
#[expect(
    clippy::mutable_key_type,
    reason = "UserRef hashes its immutable name; associations and leases hash fixed identities"
)]
fn remove_current(sessions: &mut SessionMap, key: &NatKey, generation: &PendingAnswers) {
    if sessions
        .get(key)
        .is_some_and(|entry| entry.generation.same(generation))
    {
        sessions.remove(key);
    }
}

/// Ends the sessions whose keys `ends` picks, returning how many.
async fn end_sessions(sessions: &Mutex<SessionMap>, ends: impl Fn(&NatKey) -> bool) -> usize {
    let mut sessions = sessions.lock().await;
    let keys: Vec<NatKey> = sessions.keys().filter(|k| ends(k)).cloned().collect();
    for key in &keys {
        if let Some(sess) = sessions.remove(key) {
            // The uplink ends with its channel, dropped with the entry; the
            // downlink is told to.
            let _ = sess.abort.send(false);
            debug!("udp session {} ended", key);
        }
    }
    keys.len()
}

/// Ownership of a NAT task differs from the context in which it polls
/// outbound I/O. Attachment tasks drain locally; lazily created shared
/// carriers must always be spawned in the instance's root scope.
#[derive(Clone, Default)]
enum NatTasks {
    #[default]
    Inherited,
    #[cfg(feature = "inbound-tun")]
    Attachment {
        owner: crate::runtime::scope::TaskScope,
        context: crate::runtime::scope::TaskScope,
    },
}
impl NatTasks {
    fn spawn<F>(&self, name: &'static str, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_as(crate::runtime::scope::TaskClass::Contained, name, future)
    }
    fn spawn_essential<F>(
        &self,
        name: &'static str,
        future: F,
    ) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_as(crate::runtime::scope::TaskClass::Essential, name, future)
    }
    fn spawn_as<F>(
        &self,
        class: crate::runtime::scope::TaskClass,
        name: &'static str,
        future: F,
    ) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        use crate::runtime::scope::{self, TaskClass};
        match self {
            Self::Inherited => match class {
                TaskClass::Contained => scope::spawn(name, future),
                TaskClass::Essential => scope::spawn_essential(name, future),
            },
            #[cfg(feature = "inbound-tun")]
            Self::Attachment { owner, context } => {
                let context = context.clone();
                let requests = owner.clone();
                let future = async move { requests.own_requests(context.enter(future)).await };
                match class {
                    TaskClass::Contained => owner.spawn(name, future),
                    TaskClass::Essential => owner.spawn_essential(name, future),
                }
            }
        }
    }
}

pub struct NatManager {
    tasks: NatTasks,
    #[cfg(all(test, feature = "outbound-direct"))]
    cleanup_ticks: Arc<std::sync::atomic::AtomicUsize>,
    sessions: Arc<Mutex<SessionMap>>,
    dispatcher: Arc<Dispatcher>,
    timeout_check_task: Mutex<Option<BoxFuture<'static, ()>>>,
    /// `udp_timeout` by inbound tag.
    udp_timeouts: HashMap<String, Duration>,
    /// The associations a task waits on to end their sessions, by id.
    watched: Arc<std::sync::Mutex<HashSet<u64>>>,
}

impl NatManager {
    #[cfg(all(test, feature = "outbound-direct"))]
    pub(crate) fn test_cleanup_ticks(&self) -> usize {
        self.cleanup_ticks
            .load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(all(test, feature = "outbound-direct"))]
    pub(crate) async fn test_next_cleanup(&self) {
        let before = self.test_cleanup_ticks();
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.test_cleanup_ticks() == before {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the NAT cleanup task must actually run");
        eprintln!(
            "observed NAT cleanup tick {} -> {}",
            before,
            self.test_cleanup_ticks()
        );
    }

    /// The tuning and host of the instance this NAT belongs to.
    pub fn env(&self) -> &crate::runtime::RuntimeEnv {
        self.dispatcher.env()
    }

    pub fn new(dispatcher: Arc<Dispatcher>, inbounds: &[crate::config::Inbound]) -> Self {
        let udp_timeouts = inbounds
            .iter()
            .map(|i| (i.tag.clone(), i.udp_timeout()))
            .collect();
        let sessions: Arc<Mutex<SessionMap>> = Arc::new(Mutex::new(HashMap::new()));
        let sessions2 = sessions.clone();
        #[cfg(all(test, feature = "outbound-direct"))]
        let cleanup_ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        #[cfg(all(test, feature = "outbound-direct"))]
        let task_ticks = cleanup_ticks.clone();
        let check_interval = dispatcher.env().options.udp.session_check_interval;

        // The task is lazy, will not run until any sessions added.
        let timeout_check_task: BoxFuture<'static, ()> = Box::pin(async move {
            loop {
                let mut sessions = sessions2.lock().await;
                let n_total = sessions.len();
                let now = Instant::now();
                let mut to_be_remove = Vec::new();
                for (key, val) in sessions.iter() {
                    if val.expired(now) {
                        to_be_remove.push(key.to_owned());
                    }
                }
                for key in to_be_remove.iter() {
                    if let Some(sess) = sessions.remove(key) {
                        // Sends a signal to abort downlink task, uplink task will
                        // end automatically when we drop the channel's tx side upon
                        // session removal.
                        if let Err(e) = sess.abort.send(true) {
                            debug!("failed to send abort signal on session {}: {}", key, e);
                        }
                        debug!("udp session {} ended", key);
                    }
                }
                drop(to_be_remove); // drop explicitly
                let n_remaining = sessions.len();
                let n_removed = n_total - n_remaining;
                #[cfg(all(test, feature = "outbound-direct"))]
                task_ticks.fetch_add(1, std::sync::atomic::Ordering::Release);
                drop(sessions); // release the lock
                if n_removed > 0 {
                    debug!(
                        "removed {} nat sessions, remaining {} sessions",
                        n_removed, n_remaining
                    );
                }
                tokio::time::sleep(check_interval).await;
            }
        });

        NatManager {
            tasks: Default::default(),
            #[cfg(all(test, feature = "outbound-direct"))]
            cleanup_ticks,
            sessions,
            dispatcher,
            timeout_check_task: Mutex::new(Some(timeout_check_task)),
            udp_timeouts,
            watched: Default::default(),
        }
    }

    #[cfg(feature = "inbound-tun")]
    pub(crate) fn new_scoped(
        dispatcher: Arc<Dispatcher>,
        inbounds: &[crate::config::Inbound],
        owner: crate::runtime::scope::TaskScope,
    ) -> Self {
        let context = dispatcher.env().scope.clone();
        let mut manager = Self::new(dispatcher, inbounds);
        manager.tasks = NatTasks::Attachment { owner, context };
        manager
    }

    /// Ends the session of `source` through the inbound `inbound_tag`,
    /// returning whether there was one.
    pub async fn end_source(&self, inbound_tag: &str, source: &DatagramSource) -> bool {
        let key = NatKey::new(inbound_tag, source);
        end_sessions(&self.sessions, |k| *k == key).await > 0
    }

    /// Ends the sessions of `association`, returning how many there were.
    ///
    /// Sessions whose source carries an association end by themselves when
    /// it ends; this ends them sooner.
    pub async fn end_association(&self, association: &UdpAssociation) -> usize {
        end_sessions(&self.sessions, |k| {
            k.source.association.as_ref() == Some(association)
        })
        .await
    }

    /// Ends the sessions of `association` once it ends. One task waits per
    /// association, however many sessions it has.
    fn watch_association(&self, association: &UdpAssociation) {
        let id = association.id();
        if !self
            .watched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id)
        {
            return;
        }
        let association = association.clone();
        let sessions = self.sessions.clone();
        let watched = self.watched.clone();
        self.tasks.spawn("nat association watch", async move {
            association.ended().await;
            // Unwatched first: a session added from here on starts its own
            // watch, which finds the association ended at once.
            watched
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
            let n = end_sessions(&sessions, |k| {
                k.source.association.as_ref() == Some(&association)
            })
            .await;
            debug!("udp association {} ended with {} sessions", id, n);
        });
    }

    fn _send(&self, guard: &mut MutexGuard<'_, SessionMap>, key: &NatKey, pkt: UdpPacket) {
        if let Some(sess) = guard.get_mut(key) {
            #[cfg(feature = "internal-udp-target-diagnostics")]
            let diagnostic_trace = self.dispatcher.udp_target_trace(&pkt.dst_addr);
            #[cfg(feature = "internal-udp-target-diagnostics")]
            let mut diagnostic_event = diagnostic_trace.as_ref().map(|trace| {
                let mut event = trace.event(super::udp_target_diagnostics::NAT_QUEUE);
                event.parent_flow_id = sess.diagnostic_trace.as_ref().map_or(0, |t| t.flow_id);
                event.coverage_missing = sess.diagnostic_trace.is_none();
                event
            });
            let reserved = if let Some(queue) = &sess.admissions {
                if !queue.reserve() {
                    #[cfg(feature = "internal-udp-target-diagnostics")]
                    if let (Some(trace), Some(mut event)) =
                        (&diagnostic_trace, diagnostic_event.take())
                    {
                        event.result = super::udp_target_diagnostics::Outcome::Failed;
                        event.queue_status =
                            super::udp_target_diagnostics::QueueStatus::ReserveRefused;
                        trace.emit(event);
                    }
                    return;
                }
                true
            } else {
                false
            };
            let queued = sess.uplink.try_send(pkt);
            #[cfg(feature = "internal-udp-target-diagnostics")]
            if let (Some(trace), Some(mut event)) = (diagnostic_trace, diagnostic_event.take()) {
                event.result = if queued.is_ok() {
                    super::udp_target_diagnostics::Outcome::Accepted
                } else {
                    super::udp_target_diagnostics::Outcome::Failed
                };
                event.queue_status = match &queued {
                    Ok(_) => super::udp_target_diagnostics::QueueStatus::Accepted,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        super::udp_target_diagnostics::QueueStatus::Full
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        super::udp_target_diagnostics::QueueStatus::Closed
                    }
                };
                trace.emit(event);
            }
            match queued {
                Ok(()) => sess.dns_answered = false,
                Err(err) => {
                    if reserved {
                        sess.admissions.as_ref().unwrap().reject_one();
                    }
                    trace!("send uplink packet failed {}", err);
                }
            }
            sess.last_activity = Instant::now();
        } else {
            error!("no nat association found");
        }
    }

    pub async fn send(
        &self,
        sess: Option<&Session>,
        dgram_src: &DatagramSource,
        inbound_tag: &str,
        client_ch_tx: &Sender<UdpPacket>,
        mut pkt: UdpPacket,
    ) {
        // Each datagram names its own destination: a fake IP becomes its
        // domain on each, not only on the session's first.
        if let Err(e) = self.dispatcher.restore_fake_ip(&mut pkt.dst_addr) {
            debug!("drop udp packet from {}: {}", dgram_src, e);
            return;
        }
        #[cfg(feature = "internal-udp-target-diagnostics")]
        let diagnostic_trace = self.dispatcher.udp_target_trace(&pkt.dst_addr);
        let key = NatKey::new(inbound_tag, dgram_src);
        let mut guard = self.sessions.lock().await;
        #[cfg(feature = "internal-udp-target-diagnostics")]
        if let Some(trace) = &diagnostic_trace {
            let entry = guard.get(&key);
            let mut event = trace.event(super::udp_target_diagnostics::NAT_ENTRY);
            event.entry_hit = entry.is_some();
            event.original_is_fixture = entry.is_none_or(|e| e.diagnostic_trace.is_some());
            event.coverage_missing = entry.is_some_and(|e| e.diagnostic_trace.is_none());
            event.parent_flow_id = entry
                .and_then(|e| e.diagnostic_trace.as_ref())
                .map_or(0, |t| t.flow_id);
            trace.emit(event);
        }

        if guard.contains_key(&key) {
            self._send(&mut guard, &key, pkt);
            return;
        }
        if let Some(association) = dgram_src.association.as_ref() {
            if association.has_ended() {
                debug!("drop udp packet of ended association {}", dgram_src);
                return;
            }
            self.watch_association(association);
        }

        let mut sess = sess.cloned().unwrap_or_else(|| Session {
            network: Network::Udp,
            source: dgram_src.address,
            stream_id: dgram_src.stream_id,
            destination: pkt.dst_addr.clone(),
            inbound_tag: inbound_tag.to_string(),
            process_name: dgram_src.process_name.clone(),
            user: dgram_src.user.clone(),
            ..Default::default()
        });

        if sess.inbound_tag.is_empty() {
            sess.inbound_tag = inbound_tag.to_string();
        }
        // A datagram listener hands over a session with nothing filled in;
        // what it knows of the sender is in the datagram source.
        if sess.source.ip().is_unspecified() && sess.source.port() == 0 {
            sess.source = dgram_src.address;
        }
        if sess.stream_id.is_none() {
            sess.stream_id = dgram_src.stream_id;
        }
        if sess.process_name.is_none() {
            sess.process_name = dgram_src.process_name.clone();
        }
        if dgram_src.user.is_some() {
            sess.user = dgram_src.user.clone();
        }

        sess.new_span();
        let span = sess.span();
        let _g = span.enter();

        // Always update destination to the packet's destination, because the session passed
        // from inbound listener might have a default (empty) destination.
        sess.destination = pkt.dst_addr.clone();

        self.add_session(sess, dgram_src.clone(), client_ch_tx.clone(), &mut guard)
            .await;

        debug!(
            "added udp session {} -> {} ({})",
            &dgram_src,
            &pkt.dst_addr,
            guard.len(),
        );

        self._send(&mut guard, &key, pkt);

        drop(guard);
    }

    async fn add_session<'a>(
        &self,
        mut sess: Session,
        raddr: DatagramSource,
        client_ch_tx: Sender<UdpPacket>,
        guard: &mut MutexGuard<'a, SessionMap>,
    ) {
        // Runs the lazy task for session cleanup job, this task will run only once.
        if let Some(task) = self.timeout_check_task.lock().await.take() {
            self.tasks.spawn_essential("nat cleanup", task);
        }

        let (target_ch_tx, mut target_ch_rx) =
            mpsc::channel(self.dispatcher.env().options.udp.uplink_channel_size);
        let (downlink_abort_tx, mut downlink_abort_rx) = oneshot::channel();

        let udp_timeout = self
            .udp_timeouts
            .get(&sess.inbound_tag)
            .copied()
            .unwrap_or(crate::config::model::DEFAULT_UDP_TIMEOUT);
        let key = NatKey::new(&sess.inbound_tag, &raddr);
        #[cfg(feature = "internal-udp-target-diagnostics")]
        let diagnostic_trace = self.dispatcher.udp_target_trace(&sess.destination);
        let generation = PendingAnswers::default();
        let (admissions, admissions_owner) = QueuedAdmissions::new(generation.clone());
        guard.insert(
            key.clone(),
            NatSession {
                #[cfg(feature = "internal-udp-target-diagnostics")]
                diagnostic_trace: diagnostic_trace.clone(),
                uplink: target_ch_tx,
                abort: downlink_abort_tx,
                last_activity: Instant::now(),
                idle_timeout: udp_timeout,
                dns_answered: false,
                generation: generation.clone(),
                pending: Some(generation.clone()),
                admissions: Some(admissions),
            },
        );

        let dispatcher = self.dispatcher.clone();
        let datagram_buffer_size = dispatcher.env().options.udp.datagram_buffer_size * 1024;
        let sessions = self.sessions.clone();

        // Spawns a new task for dispatching to avoid blocking the current task,
        // because we have stream type transports for UDP traffic, establishing a
        // TCP stream would block the task.
        let raddr_cloned = raddr.clone();
        let span = sess.span();
        let tasks = self.tasks.clone();
        self.tasks.spawn(
            "nat dispatch",
            async move {
                // new socket to communicate with the target. A sniff rule
                // reads the first datagrams off the uplink while routing;
                // they are sent before the rest.
                // Keep only the pre-route identity, never the listed
                // number or state of the association's counter.
                let admission_session = match dispatcher.datagram_admission(&mut sess) {
                    Ok(session) => session,
                    Err(e) => {
                        debug!("UDP binding refused: {}", e);
                        remove_current(&mut *sessions.lock().await, &key, &generation);
                        return;
                    }
                };
                let mut sniffer = DatagramSniffer::new(&mut target_ch_rx);
                #[cfg(feature = "internal-udp-target-diagnostics")]
                if let Some(trace) = &diagnostic_trace {
                    trace.emit(trace.event(super::udp_target_diagnostics::DISPATCH));
                }
                let dispatch = dispatcher
                    .dispatch_datagram_tracked(sess, &mut sniffer, generation.clone())
                    .instrument(tracing::Span::current());
                #[cfg(feature = "internal-udp-target-diagnostics")]
                let socket =
                    super::udp_target_diagnostics::scope(diagnostic_trace.clone(), dispatch).await;
                #[cfg(not(feature = "internal-udp-target-diagnostics"))]
                let socket = dispatch.await;
                #[cfg(feature = "internal-udp-target-diagnostics")]
                if let Some(trace) = &diagnostic_trace {
                    trace.result(
                        super::udp_target_diagnostics::DISPATCH,
                        socket.as_ref().map(|_| ()).map_err(|e| e.kind()),
                    );
                }
                let sniffed = sniffer.into_read();
                let (socket, listed) = match socket {
                    Ok(((s, udp_timeout, listed), pending)) => {
                        let mut entries = sessions.lock().await;
                        let Some(entry) = entries
                            .get_mut(&key)
                            .filter(|entry| entry.generation.same(&generation))
                        else {
                            // The old entry may have ended while its dial
                            // awaited. Preserve that entry's already-sent
                            // reason on its own counter, never the replacement.
                            if let (Some(listed), Ok(idle)) =
                                (&listed, downlink_abort_rx.try_recv())
                            {
                                listed.ended(match idle {
                                    true => crate::control::events::End::IdleTimeout,
                                    false => crate::control::events::End::Finished,
                                });
                            }
                            return;
                        };
                        if let Some(timeout) = udp_timeout {
                            entry.idle_timeout = timeout;
                        }
                        if pending.is_none() {
                            entry.admissions = None;
                        }
                        entry.pending = pending;
                        (s, listed)
                    }
                    Err(e) => {
                        debug!("dispatch {} failed: {}", &raddr_cloned, e);
                        remove_current(&mut *sessions.lock().await, &key, &generation);
                        return;
                    }
                };

                let (mut target_sock_recv, mut target_sock_send) = socket.split();

                // downlink
                let raddr_downlink = raddr_cloned.clone();
                let key_downlink = key.clone();
                let generation_downlink = generation.clone();
                let downlink_task = async move {
                    let mut buf = vec![0u8; datagram_buffer_size];
                    loop {
                        match target_sock_recv.recv_from(&mut buf).await {
                            Err(err) => {
                                debug!(
                                    "Failed to receive downlink packets on session {}: {}",
                                    &raddr_downlink, err
                                );
                                break;
                            }
                            Ok((n, addr)) => {
                                trace!("outbound received udp packet src={} len={}", &addr, n);
                                let pkt = UdpPacket::new(
                                    buf[..n].to_vec(),
                                    addr.clone(),
                                    SocksAddr::from(raddr_downlink.address),
                                )
                                .with_resource_lease(raddr_downlink.resource_lease.clone());
                                if let Err(err) = client_ch_tx.send(pkt).await {
                                    debug!(
                                        "Failed to send downlink packets on session {} to {}: {}",
                                        &raddr_downlink, &addr, err
                                    );
                                    break;
                                }

                                // activity update
                                {
                                    let mut sessions = sessions.lock().await;
                                    if let Some(sess) = sessions
                                        .get_mut(&key_downlink)
                                        .filter(|entry| entry.generation.same(&generation_downlink))
                                    {
                                        sess.last_activity = Instant::now();
                                        sess.dns_answered = addr.port() == 53;
                                    }
                                }
                            }
                        }
                    }
                    remove_current(
                        &mut *sessions.lock().await,
                        &key_downlink,
                        &generation_downlink,
                    );
                }
                .instrument(tracing::Span::current());

                let (downlink_task, downlink_task_handle) = abortable(downlink_task);
                tasks.spawn("nat downlink", downlink_task);

                // Runs a task to receive the abort signal: the session ended,
                // standing idle, or by its client.
                tasks.spawn("nat downlink abort", async move {
                    if let Ok(idle) = downlink_abort_rx.await {
                        if let Some(listed) = &listed {
                            listed.ended(match idle {
                                true => crate::control::events::End::IdleTimeout,
                                false => crate::control::events::End::Finished,
                            });
                        }
                    }
                    downlink_task_handle.abort();
                });

                // uplink
                let raddr_uplink = raddr_cloned.clone();
                tasks.spawn(
                    "nat uplink",
                    async move {
                        // Authorization is bounded independently of the
                        // association's lifetime/number of destinations.
                        // Evicted targets must be checked again. Rejected
                        // targets are never cached.
                        let mut admitted = admission_session.as_ref().map(|base| {
                            let mut targets = LruCache::new(NonZeroUsize::new(64).unwrap());
                            targets.put(base.destination.clone(), ());
                            targets
                        });
                        let mut sniffed = sniffed.into_iter();
                        loop {
                            let pkt = match sniffed.next() {
                                Some(pkt) => pkt,
                                None => match target_ch_rx.recv().await {
                                    Some(pkt) => pkt,
                                    None => break,
                                },
                            };
                            // Transfer the queue reservation before authorization too:
                            // rejected targets and cancelled callbacks must release it.
                            let _admission = admissions_owner.take_one();
                            if let (Some(base), Some(targets)) = (&admission_session, &mut admitted)
                            {
                                if targets.get(&pkt.dst_addr).is_none() {
                                    // Do not authorize a new target after
                                    // the entry ended, or commit a callback
                                    // result onto an ended/replaced NAT.
                                    // Existing authorized packets retain
                                    // their previous drain semantics.
                                    if target_ch_rx.is_closed() {
                                        break;
                                    }
                                    if !dispatcher.admit_datagram_destination(base, &pkt.dst_addr) {
                                        continue;
                                    }
                                    if target_ch_rx.is_closed() {
                                        break;
                                    }
                                    targets.put(pkt.dst_addr.clone(), ());
                                }
                            }
                            trace!(
                                "outbound send udp packet dst={} len={}",
                                &pkt.dst_addr,
                                pkt.data.len()
                            );
                            if let Err(e) = target_sock_send.send_to(&pkt.data, &pkt.dst_addr).await
                            {
                                debug!(
                                    "Failed to send uplink packets on session {} to {}: {:?}",
                                    &raddr_uplink, &pkt.dst_addr, e
                                );
                                break;
                            }
                        }
                        if let Err(e) = target_sock_send.close().await {
                            debug!("Failed to close outbound datagram {}: {}", &raddr_uplink, e);
                        }
                    }
                    .instrument(tracing::Span::current()),
                );
            }
            .instrument(span),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Actual hijack query ownership is local; its root poll context must
    /// neither leak the request nor cancel a shared carrier at detach.
    #[cfg(all(feature = "inbound-tun", feature = "outbound-direct"))]
    #[tokio::test]
    async fn attachment_drain_joins_dns_requests_but_keeps_root_carriers() {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns":{"servers":[{"type":"udp","server":"127.0.0.1",
                    "server_port":upstream.local_addr().unwrap().port()}]},
                "outbounds":[{"type":"direct","tag":"direct"}],
                "route":{"rules":[{"port":53,"action":"hijack-dns"}]}
            })
            .to_string(),
        )
        .unwrap();
        let instance = instance(&config).await;
        let root = instance.env.scope.clone();
        let owner = root.isolated();
        let nat =
            NatManager::new_scoped(instance.dispatcher.clone(), &config.inbounds, owner.clone());
        let (answers, _receive) = mpsc::channel(1);
        let source = DatagramSource::new("192.0.2.1:50000".parse().unwrap(), None);
        let key = NatKey::new("test", &source);
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_ascii("pending.example.").unwrap(),
            RecordType::A,
        ));
        root.enter(nat.send(
            None,
            &source,
            "test",
            &answers,
            UdpPacket::new(
                query.to_vec().unwrap(),
                SocksAddr::Ip(source.address),
                SocksAddr::Ip("203.0.113.53:53".parse().unwrap()),
            ),
        ))
        .await;
        let mut buf = [0; 512];
        tokio::time::timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let generation = nat.sessions.lock().await[&key].generation.clone();
        let query_owned = owner
            .tasks()
            .iter()
            .any(|(name, _)| *name == "hijacked dns query");
        struct Ended(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Ended {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let held = Ended(ended.clone());
        let carrier = root.spawn("test shared carrier", async move {
            let _held = held;
            std::future::pending::<()>().await;
        });
        let report = owner.stop(Duration::from_secs(1)).await;
        let request_released = generation.is_idle();
        let carrier_alive =
            !carrier.is_finished() && !ended.load(std::sync::atomic::Ordering::SeqCst);
        assert!(root.stop(Duration::from_secs(1)).await.clean());
        assert!(
            query_owned,
            "hijacked request must be registered with the attachment"
        );
        assert!(report.clean(), "{report:?}");
        assert!(
            request_released,
            "detach must join the pending answer owner"
        );
        assert!(
            carrier_alive,
            "attachment drain must not own a shared root carrier"
        );
        assert!(ended.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancelling_queue_owner_drains_only_queued_admissions() {
        let pending = PendingAnswers::default();
        let answer = pending.begin();
        let (queue, owner) = QueuedAdmissions::new(pending.clone());
        assert!(queue.reserve());
        assert!(queue.reserve());
        let in_progress = owner.take_one().unwrap();
        let scope = crate::runtime::scope::TaskScope::default();
        let (ready, entered) = oneshot::channel();
        scope.spawn("test queued dispatch", async move {
            let _owner = owner;
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        entered.await.unwrap();
        assert!(scope.stop(Duration::from_secs(1)).await.clean());
        assert!(
            !queue.reserve(),
            "entry clones cannot revive a closed receiver"
        );
        queue.reject_one(); // rejection racing owner shutdown is harmless.
        drop(in_progress);
        assert!(
            !pending.is_idle(),
            "owner must not return a resolver's reservation"
        );
        drop(answer);
        assert!(pending.is_idle());
    }

    #[test]
    fn rejected_or_cancelled_dequeued_requests_return_once() {
        let pending = PendingAnswers::default();
        let (queue, owner) = QueuedAdmissions::new(pending.clone());
        for _ in 0..3 {
            assert!(queue.reserve());
        }
        queue.reject_one();
        let rejected_target = owner.take_one().unwrap();
        drop(rejected_target);
        let sending = owner.take_one().unwrap();
        let resolver = pending.begin();
        drop(sending);
        assert!(owner.take_one().is_none());
        drop(owner);
        assert!(!pending.is_idle());
        drop(resolver);
        assert!(pending.is_idle());
    }

    #[cfg(feature = "outbound-direct")]
    async fn instance(config: &crate::config::Config) -> crate::app::instance::Instance {
        let mut env = crate::runtime::RuntimeEnv::default();
        env.options.udp.session_check_interval = Duration::from_secs(1);
        env.options.inbound.max_connections = 128;
        let env = Arc::new(env);
        env.scope
            .enter(async {
                crate::app::instance::Instance::build(
                    config,
                    config.route.rules.clone(),
                    env.clone(),
                    Arc::default(),
                )
                .unwrap()
            })
            .await
    }

    #[cfg(feature = "outbound-direct")]
    #[tokio::test]
    async fn rejected_uplink_packets_do_not_leave_pending_answers() {
        let config = crate::config::Config::from_json("{}").unwrap();
        let instance = instance(&config).await;
        let nat = NatManager::new(instance.dispatcher.clone(), &config.inbounds);
        let (uplink, mut receive) = mpsc::channel(1);
        let (abort, _aborted) = oneshot::channel();
        let pending = PendingAnswers::default();
        let (queue, owner) = QueuedAdmissions::new(pending.clone());
        let source = DatagramSource::new("192.0.2.1:50000".parse().unwrap(), None);
        let key = NatKey::new("test", &source);
        let sessions = Mutex::new(HashMap::from([(
            key.clone(),
            NatSession {
                #[cfg(feature = "internal-udp-target-diagnostics")]
                diagnostic_trace: None,
                uplink,
                abort,
                last_activity: Instant::now(),
                idle_timeout: Duration::from_secs(30),
                dns_answered: false,
                pending: Some(pending.clone()),
                generation: pending.clone(),
                admissions: Some(queue),
            },
        )]));
        let mut entries = sessions.lock().await;
        for _ in 0..3 {
            nat._send(
                &mut entries,
                &key,
                UdpPacket::new(
                    vec![0],
                    SocksAddr::Ip(source.address),
                    SocksAddr::Ip("203.0.113.53:53".parse().unwrap()),
                ),
            );
        }
        assert!(!pending.is_idle(), "the accepted query is reserved");
        receive.try_recv().unwrap();
        assert!(
            receive.try_recv().is_err(),
            "the full channel rejected the rest"
        );
        drop(owner.take_one().unwrap());
        assert!(
            pending.is_idle(),
            "rejected packets must release their reservations"
        );
        drop(receive);
        nat._send(
            &mut entries,
            &key,
            UdpPacket::new(
                vec![0],
                SocksAddr::Ip(source.address),
                SocksAddr::Ip("203.0.113.53:53".parse().unwrap()),
            ),
        );
        assert!(
            pending.is_idle(),
            "a closed channel also releases its reservation"
        );
    }

    #[test]
    fn pending_dns_answers_do_not_extend_the_configured_idle_bound() {
        let (uplink, _receive) = mpsc::channel(1);
        let (abort, _aborted) = oneshot::channel();
        let pending = PendingAnswers::default();
        pending.add(2);
        let now = Instant::now();
        let mut session = NatSession {
            #[cfg(feature = "internal-udp-target-diagnostics")]
            diagnostic_trace: None,
            uplink,
            abort,
            last_activity: now,
            idle_timeout: Duration::from_millis(50),
            dns_answered: true,
            pending: Some(pending.clone()),
            generation: pending.clone(),
            admissions: None,
        };
        assert!(!session.expired(now + Duration::from_millis(49)));
        pending.finish(1);
        assert!(!session.expired(now + Duration::from_millis(49)));
        assert!(session.expired(now + Duration::from_millis(50)));
        pending.finish(1);
        assert!(session.expired(now), "finished DNS is reclaimed promptly");
        session.dns_answered = false;
        assert!(!session.expired(now), "ordinary UDP keeps its idle timeout");
        assert!(session.expired(now + Duration::from_millis(50)));
    }

    /// Three queries share a UDP session. A fast answer precedes two slow
    /// ones across multiple cleanup passes; the final answer then waits
    /// behind a full inbound channel. None may be cut off by eager DNS
    /// cleanup, and the session must be reclaimed after they are drained.
    #[cfg(feature = "outbound-direct")]
    #[tokio::test]
    async fn dns_cleanup_waits_for_pending_and_backpressured_answers() {
        use crate::util::DnsMessageExt;
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use tokio::net::UdpSocket;
        use tokio::time::{sleep, timeout};

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = crate::config::Config::from_json(
            &serde_json::json!({
                "dns": { "servers": [{ "type": "udp", "server": "127.0.0.1",
                    "server_port": upstream.local_addr().unwrap().port() }] },
                "outbounds": [{ "type": "direct", "tag": "direct" }],
                "route": { "rules": [{ "port": 53, "action": "hijack-dns" }] }
            })
            .to_string(),
        )
        .unwrap();
        let instance = instance(&config).await;
        let nat = NatManager::new(instance.dispatcher.clone(), &config.inbounds);
        let scope = instance.env.scope.clone();
        scope
            .enter(async {
                let source = DatagramSource::new("192.0.2.1:50000".parse().unwrap(), None);
                let destination = SocksAddr::Ip("203.0.113.53:53".parse().unwrap());
                let (client, mut received) = mpsc::channel(1);
                for id in 0..3 {
                    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
                    query.add_query(Query::query(
                        Name::from_ascii(format!("q{id}.example.")).unwrap(),
                        RecordType::A,
                    ));
                    nat.send(
                        None,
                        &source,
                        "test",
                        &client,
                        UdpPacket::new(
                            query.to_vec().unwrap(),
                            SocksAddr::Ip(source.address),
                            destination.clone(),
                        ),
                    )
                    .await;
                }
                let mut queries = Vec::new();
                for _ in 0..3 {
                    let mut buf = [0; 512];
                    let (n, peer) = timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                    let mut answer = Message::from_vec(&buf[..n]).unwrap();
                    answer.set_message_type(MessageType::Response);
                    queries.push((answer.to_vec().unwrap(), peer));
                }
                upstream.send_to(&queries[0].0, queries[0].1).await.unwrap();
                let first = timeout(Duration::from_secs(2), received.recv())
                    .await
                    .unwrap()
                    .unwrap();
                let mut ids = vec![Message::from_vec(&first.data).unwrap().id()];
                nat.test_next_cleanup().await;
                assert_eq!(
                    nat.sessions.lock().await.len(),
                    1,
                    "a fast answer must not retire pending queries"
                );
                for index in [2, 1] {
                    let (answer, peer) = &queries[index];
                    upstream.send_to(answer, peer).await.unwrap();
                }
                // One answer fills client_ch_tx; the other must remain protected
                // while the NAT's downlink waits for the client to make room.
                nat.test_next_cleanup().await;
                assert_eq!(
                    nat.sessions.lock().await.len(),
                    1,
                    "a backpressured answer must keep its session"
                );
                let mut queued = vec![first];
                for _ in 0..2 {
                    let answer = timeout(Duration::from_secs(2), received.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    ids.push(Message::from_vec(&answer.data).unwrap().id());
                    queued.push(answer);
                }
                ids.sort();
                assert_eq!(ids, vec![0, 1, 2]);
                timeout(Duration::from_secs(3), async {
                    while !nat.sessions.lock().await.is_empty() {
                        sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("finished DNS sessions are reclaimed at the next cleanup");
                // Handoff is not wire success: the slow writer still owns all
                // packets after NAT and Held halves have ended, then sends them.
                let wire = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let writer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                for packet in queued {
                    writer
                        .send_to(&packet.data, wire.local_addr().unwrap())
                        .await
                        .unwrap();
                }
                let mut wire_ids = Vec::new();
                for _ in 0..3 {
                    let mut buf = [0; 512];
                    let (n, _) = timeout(Duration::from_secs(2), wire.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                    wire_ids.push(Message::from_vec(&buf[..n]).unwrap().id());
                }
                wire_ids.sort();
                assert_eq!(wire_ids, vec![0, 1, 2]);
            })
            .await;
        assert!(scope.stop(Duration::from_secs(1)).await.clean());
    }
    /// Real SOCKS dispatch is held after its UDP ASSOCIATE request. While
    /// it awaits, end/recreate the key and start a real DNS exchange on it.
    #[cfg(all(feature = "outbound-direct", feature = "outbound-socks"))]
    #[tokio::test]
    async fn late_dispatch_success_error_and_eof_cannot_replace_a_new_generation() {
        use crate::util::DnsMessageExt;
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, UdpSocket};
        use tokio::time::timeout;

        for (outcome, idle_cleanup) in [
            ("success", false),
            ("error", false),
            ("eof", false),
            ("success", true),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let config = crate::config::Config::from_json(
                &serde_json::json!({
                    "dns": { "servers": [{ "type": "udp", "server": "127.0.0.1",
                        "server_port": upstream.local_addr().unwrap().port() }] },
                    "outbounds": [{ "type": "socks", "tag": "proxy", "server": "127.0.0.1",
                        "server_port": listener.local_addr().unwrap().port() }],
                    "route": { "rules": [{ "port": 53, "action": "hijack-dns" }], "final": "proxy" }
                })
                .to_string(),
            )
            .unwrap();
            let instance = instance(&config).await;
            let scope = instance.env.scope.clone();
            let mut records = instance.env.events.records();
            let nat = NatManager::new(instance.dispatcher.clone(), &config.inbounds);
            scope
                .enter(async {
                    let source = DatagramSource::new("192.0.2.1:50000".parse().unwrap(), None);
                    let key = NatKey::new("test", &source);
                    let (client, mut received) = mpsc::channel(1);
                    let packet = |data, port| {
                        UdpPacket::new(
                            data,
                            SocksAddr::Ip(source.address),
                            SocksAddr::Ip(std::net::SocketAddr::from(([203, 0, 113, 53], port))),
                        )
                    };
                    nat.send(None, &source, "test", &client, packet(vec![1], 80))
                        .await;
                    let (mut old_control, _) = timeout(Duration::from_secs(2), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                    let mut greeting = [0; 3];
                    old_control.read_exact(&mut greeting).await.unwrap();
                    assert_eq!(greeting, [5, 1, 0]);
                    old_control.write_all(&[5, 0]).await.unwrap();
                    let mut associate = [0; 10];
                    old_control.read_exact(&mut associate).await.unwrap();
                    assert_eq!(&associate[..4], &[5, 3, 0, 1]);
                    let old = nat.sessions.lock().await[&key].generation.clone();
                    assert_eq!(instance.dispatcher.test_live_sessions(), 1);
                    if idle_cleanup {
                        nat.sessions
                            .lock()
                            .await
                            .get_mut(&key)
                            .unwrap()
                            .idle_timeout = Duration::ZERO;
                        nat.test_next_cleanup().await;
                        assert!(!nat.sessions.lock().await.contains_key(&key));
                    } else {
                        assert!(nat.end_source("test", &source).await);
                    }
                    let mut query = Message::new(7, MessageType::Query, OpCode::Query);
                    query.add_query(Query::query(
                        Name::from_ascii(format!("{outcome}.example.")).unwrap(),
                        RecordType::A,
                    ));
                    nat.send(
                        None,
                        &source,
                        "test",
                        &client,
                        packet(query.to_vec().unwrap(), 53),
                    )
                    .await;
                    let mut buf = [0; 512];
                    let (n, dns_peer) =
                        timeout(Duration::from_secs(2), upstream.recv_from(&mut buf))
                            .await
                            .unwrap()
                            .unwrap();
                    let mut response = Message::from_vec(&buf[..n]).unwrap();
                    response.set_message_type(MessageType::Response);
                    let current = nat.sessions.lock().await[&key].generation.clone();
                    assert!(!current.same(&old));
                    assert!(!current.is_idle());
                    assert_eq!(instance.dispatcher.test_live_sessions(), 2);
                    if outcome == "eof" {
                        drop(old_control);
                    } else {
                        let mut response = vec![
                            5,
                            if outcome == "error" { 1 } else { 0 },
                            0,
                            1,
                            127,
                            0,
                            0,
                            1,
                        ];
                        response
                            .extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
                        old_control.write_all(&response).await.unwrap();
                        // On success the stale socket must be dropped, not split
                        // into a second relay. EOF observes that resource release.
                        let mut byte = [0];
                        let closed = timeout(Duration::from_secs(2), old_control.read(&mut byte))
                            .await
                            .unwrap();
                        assert!(
                            matches!(closed, Ok(0))
                                || closed.as_ref().is_err_and(|error| matches!(
                                    error.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::ConnectionAborted
                                )),
                            "the stale SOCKS control must close: {closed:?}"
                        );
                    }
                    timeout(Duration::from_secs(2), async {
                        while !old.is_idle() || instance.dispatcher.test_live_sessions() != 1 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .expect("stale dispatch must return its pending and Held place");
                    if outcome == "success" {
                        let closed = timeout(Duration::from_secs(2), async {
                            loop {
                                let record = records.recv().await.unwrap();
                                if record.destination.port() == 80
                                    && matches!(
                                        record.kind,
                                        crate::control::events::RecordKind::Closed(_)
                                    )
                                {
                                    break record;
                                }
                            }
                        })
                        .await
                        .unwrap();
                        assert_eq!(
                            closed.kind,
                            crate::control::events::RecordKind::Closed(if idle_cleanup {
                                crate::control::events::End::IdleTimeout
                            } else {
                                crate::control::events::End::Finished
                            })
                        );
                    }

                    {
                        let entries = nat.sessions.lock().await;
                        let entry = &entries[&key];
                        assert!(entry.generation.same(&current));
                        assert!(entry.pending.as_ref().unwrap().same(&current));
                        assert!(!current.is_idle());
                    }
                    upstream
                        .send_to(&response.to_vec().unwrap(), dns_peer)
                        .await
                        .unwrap();
                    let answer = timeout(Duration::from_secs(2), received.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    let answer = Message::from_vec(&answer.data).unwrap();
                    assert_eq!(answer.id(), 7);
                    assert_eq!(
                        answer.queries()[0].name().to_ascii(),
                        format!("{outcome}.example.")
                    );
                    assert!(nat.end_source("test", &source).await);
                    timeout(Duration::from_secs(2), async {
                        while !current.is_idle() || instance.dispatcher.test_live_sessions() != 0 {
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .unwrap();
                })
                .await;
            assert!(scope.stop(Duration::from_secs(1)).await.clean());
        }
    }
}

#[cfg(all(
    test,
    feature = "internal-udp-target-diagnostics",
    feature = "outbound-direct"
))]
mod udp_target_tests {
    use super::*;
    use crate::app::udp_target_diagnostics::{self as diag, QueueStatus, Stage};
    #[tokio::test]
    async fn udp_target_existing_nonfixture_entry_queue_reasons_and_packet_gate() {
        let config = crate::config::Config::from_json("{}").unwrap();
        let env = Arc::new(diag::test_env());
        let instance = env
            .scope
            .enter(async {
                crate::app::instance::Instance::build(
                    &config,
                    config.route.rules.clone(),
                    env.clone(),
                    Arc::default(),
                )
                .unwrap()
            })
            .await;
        let nat = NatManager::new(instance.dispatcher.clone(), &config.inbounds);
        let source = DatagramSource::new("127.0.0.1:50000".parse().unwrap(), None);
        let key = NatKey::new("test", &source);
        let (tx, rx) = mpsc::channel(1);
        let (abort, _) = oneshot::channel();
        nat.sessions.lock().await.insert(
            key.clone(),
            NatSession {
                diagnostic_trace: None,
                uplink: tx,
                abort,
                last_activity: Instant::now(),
                idle_timeout: Duration::from_secs(300),
                dns_answered: false,
                generation: PendingAnswers::default(),
                pending: None,
                admissions: None,
            },
        );
        let (down, _) = mpsc::channel(1);
        let fixture = SocksAddr::Ip(crate::app::udp_target_diagnostics::TEST_ADDR.into());
        let packet = |dst: SocksAddr| UdpPacket::new(vec![1], SocksAddr::Ip(source.address), dst);
        nat.send(None, &source, "test", &down, packet(fixture.clone()))
            .await;
        nat.send(None, &source, "test", &down, packet(fixture.clone()))
            .await;
        drop(rx);
        nat.send(None, &source, "test", &down, packet(fixture.clone()))
            .await;
        let pending = PendingAnswers::default();
        let (queue, owner) = QueuedAdmissions::new(pending);
        drop(owner);
        nat.sessions.lock().await.get_mut(&key).unwrap().admissions = Some(queue);
        nat.send(None, &source, "test", &down, packet(fixture.clone()))
            .await;
        let before = instance.dispatcher.internal_diagnostics(0).udp_target;
        let entry = before
            .events
            .iter()
            .find(|e| e.stage == Stage::NatEntry)
            .unwrap();
        assert!(entry.entry_hit && !entry.original_is_fixture && entry.coverage_missing);
        for status in [
            QueueStatus::Accepted,
            QueueStatus::Full,
            QueueStatus::Closed,
            QueueStatus::ReserveRefused,
        ] {
            assert!(before
                .events
                .iter()
                .any(|e| e.stage == Stage::NatQueue && e.queue_status == status));
        }
        assert!(!before
            .events
            .iter()
            .any(|e| matches!(e.stage, Stage::Route | Stage::AnyTls | Stage::Open)));
        for dst in [
            SocksAddr::Ip(std::net::SocketAddr::new(
                crate::app::udp_target_diagnostics::TEST_ADDR
                    .ip()
                    .to_owned()
                    .into(),
                crate::app::udp_target_diagnostics::TEST_ADDR.port() + 1,
            )),
            SocksAddr::Domain("secret.example".into(), diag::TEST_ADDR.port()),
        ] {
            nat.send(None, &source, "test", &down, packet(dst)).await;
        }
        assert_eq!(
            instance
                .dispatcher
                .internal_diagnostics(0)
                .udp_target
                .events,
            before.events
        );
        assert!(env.scope.stop(Duration::from_secs(1)).await.clean());
        assert!(instance.dispatcher.udp_target_trace(&fixture).is_some());
    }
}
