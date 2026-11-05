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
use crate::session::{DatagramSource, Network, Session, SocksAddr, UdpAssociation};

#[derive(Debug)]
pub struct UdpPacket {
    pub data: Vec<u8>,
    pub src_addr: SocksAddr,
    pub dst_addr: SocksAddr,
}

impl UdpPacket {
    pub fn new(data: Vec<u8>, src_addr: SocksAddr, dst_addr: SocksAddr) -> Self {
        Self {
            data,
            src_addr,
            dst_addr,
        }
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

/// Per session: the uplink, the downlink's abort signal (true when the
/// session stood idle too long, false when its client ended it), the last
/// activity, and how long the session may be idle.
type SessionMap = HashMap<NatKey, (Sender<UdpPacket>, oneshot::Sender<bool>, Instant, Duration)>;

/// Ends the sessions whose keys `ends` picks, returning how many.
async fn end_sessions(sessions: &Mutex<SessionMap>, ends: impl Fn(&NatKey) -> bool) -> usize {
    let mut sessions = sessions.lock().await;
    let keys: Vec<NatKey> = sessions.keys().filter(|k| ends(k)).cloned().collect();
    for key in &keys {
        if let Some(sess) = sessions.remove(key) {
            // The uplink ends with its channel, dropped with the entry; the
            // downlink is told to.
            let _ = sess.1.send(false);
            debug!("udp session {} ended", key);
        }
    }
    keys.len()
}

pub struct NatManager {
    sessions: Arc<Mutex<SessionMap>>,
    dispatcher: Arc<Dispatcher>,
    timeout_check_task: Mutex<Option<BoxFuture<'static, ()>>>,
    /// `udp_timeout` by inbound tag.
    udp_timeouts: HashMap<String, Duration>,
    /// The associations a task waits on to end their sessions, by id.
    watched: Arc<std::sync::Mutex<HashSet<u64>>>,
}

impl NatManager {
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
        let check_interval = dispatcher.env().options.udp.session_check_interval;

        // The task is lazy, will not run until any sessions added.
        let timeout_check_task: BoxFuture<'static, ()> = Box::pin(async move {
            loop {
                let mut sessions = sessions2.lock().await;
                let n_total = sessions.len();
                let now = Instant::now();
                let mut to_be_remove = Vec::new();
                for (key, val) in sessions.iter() {
                    if now.duration_since(val.2) >= val.3 {
                        to_be_remove.push(key.to_owned());
                    }
                }
                for key in to_be_remove.iter() {
                    if let Some(sess) = sessions.remove(key) {
                        // Sends a signal to abort downlink task, uplink task will
                        // end automatically when we drop the channel's tx side upon
                        // session removal.
                        if let Err(e) = sess.1.send(true) {
                            debug!("failed to send abort signal on session {}: {}", key, e);
                        }
                        debug!("udp session {} ended", key);
                    }
                }
                drop(to_be_remove); // drop explicitly
                let n_remaining = sessions.len();
                let n_removed = n_total - n_remaining;
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
            sessions,
            dispatcher,
            timeout_check_task: Mutex::new(Some(timeout_check_task)),
            udp_timeouts,
            watched: Default::default(),
        }
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
        crate::runtime::scope::spawn("nat association watch", async move {
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
            if let Err(err) = sess.0.try_send(pkt) {
                trace!("send uplink packet failed {}", err);
            }
            sess.2 = Instant::now(); // activity update
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
        let key = NatKey::new(inbound_tag, dgram_src);
        let mut guard = self.sessions.lock().await;

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
            crate::runtime::scope::spawn_essential("nat cleanup", task);
        }

        let (target_ch_tx, mut target_ch_rx) =
            mpsc::channel(self.dispatcher.env().options.udp.uplink_channel_size);
        let (downlink_abort_tx, downlink_abort_rx) = oneshot::channel();

        let udp_timeout = self
            .udp_timeouts
            .get(&sess.inbound_tag)
            .copied()
            .unwrap_or(crate::config::model::DEFAULT_UDP_TIMEOUT);
        let key = NatKey::new(&sess.inbound_tag, &raddr);
        guard.insert(
            key.clone(),
            (target_ch_tx, downlink_abort_tx, Instant::now(), udp_timeout),
        );

        let dispatcher = self.dispatcher.clone();
        let datagram_buffer_size = dispatcher.env().options.udp.datagram_buffer_size * 1024;
        let sessions = self.sessions.clone();

        // Spawns a new task for dispatching to avoid blocking the current task,
        // because we have stream type transports for UDP traffic, establishing a
        // TCP stream would block the task.
        let raddr_cloned = raddr.clone();
        let span = sess.span();
        crate::runtime::scope::spawn(
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
                        sessions.lock().await.remove(&key);
                        return;
                    }
                };
                let mut sniffer = DatagramSniffer::new(&mut target_ch_rx);
                let socket = dispatcher
                    .dispatch_datagram(sess, &mut sniffer)
                    .instrument(tracing::Span::current())
                    .await;
                let sniffed = sniffer.into_read();
                let (socket, listed) = match socket {
                    Ok((s, udp_timeout, listed)) => {
                        // A rule's udp_timeout, over the inbound's.
                        if let Some(udp_timeout) = udp_timeout {
                            if let Some(entry) = sessions.lock().await.get_mut(&key) {
                                entry.3 = udp_timeout;
                            }
                        }
                        (s, listed)
                    }
                    Err(e) => {
                        debug!("dispatch {} failed: {}", &raddr_cloned, e);
                        sessions.lock().await.remove(&key);
                        return;
                    }
                };

                let (mut target_sock_recv, mut target_sock_send) = socket.split();

                // downlink
                let raddr_downlink = raddr_cloned.clone();
                let key_downlink = key.clone();
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
                                );
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
                                    if let Some(sess) = sessions.get_mut(&key_downlink) {
                                        if addr.port() == 53 {
                                            // If the destination port is 53, we assume it's a
                                            // DNS query and set a negative timeout so it will
                                            // be removed on next check.
                                            if let Some(new_time) = sess.2.checked_sub(sess.3) {
                                                sess.2 = new_time;
                                            }
                                        } else {
                                            sess.2 = Instant::now();
                                        }
                                    }
                                }
                            }
                        }
                    }
                    sessions.lock().await.remove(&key_downlink);
                }
                .instrument(tracing::Span::current());

                let (downlink_task, downlink_task_handle) = abortable(downlink_task);
                crate::runtime::scope::spawn("nat downlink", downlink_task);

                // Runs a task to receive the abort signal: the session ended,
                // standing idle, or by its client.
                crate::runtime::scope::spawn("nat downlink abort", async move {
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
                crate::runtime::scope::spawn(
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
