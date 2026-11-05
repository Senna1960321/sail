use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::{abortable, BoxFuture};
use tokio::sync::{
    mpsc::{self, Sender},
    oneshot, Mutex, MutexGuard,
};
use tracing::{debug, error, trace, Instrument};

use crate::app::dispatcher::{DatagramSniffer, Dispatcher};
use crate::app::router::hijack_dns::PendingAnswers;
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

struct NatSession {
    uplink: Sender<UdpPacket>,
    /// True for idle expiry, false when the client ended its association.
    abort: oneshot::Sender<bool>,
    last_activity: Instant,
    idle_timeout: Duration,
    dns_answered: bool,
    pending: Option<PendingAnswers>,
}

impl NatSession {
    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_activity) >= self.idle_timeout
            || (self.dns_answered && self.pending.as_ref().is_none_or(PendingAnswers::is_idle))
    }
}

type SessionMap = HashMap<NatKey, NatSession>;

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
            if let Some(pending) = &sess.pending {
                pending.add(1);
            }
            if let Err(err) = sess.uplink.try_send(pkt) {
                if let Some(pending) = &sess.pending {
                    pending.finish(1);
                }
                trace!("send uplink packet failed {}", err);
            }
            sess.last_activity = Instant::now();
            sess.dns_answered = false;
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
        sess: Session,
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
            NatSession {
                uplink: target_ch_tx,
                abort: downlink_abort_tx,
                last_activity: Instant::now(),
                idle_timeout: udp_timeout,
                dns_answered: false,
                pending: None,
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
        crate::runtime::scope::spawn(
            "nat dispatch",
            async move {
                // new socket to communicate with the target. A sniff rule
                // reads the first datagrams off the uplink while routing;
                // they are sent before the rest.
                let mut sniffer = DatagramSniffer::new(&mut target_ch_rx);
                let socket = dispatcher
                    .dispatch_datagram_tracked(sess, &mut sniffer)
                    .instrument(tracing::Span::current())
                    .await;
                let sniffed = sniffer.into_read();
                let (socket, listed, pending) = match socket {
                    Ok((s, udp_timeout, listed, pending)) => {
                        // A rule's udp_timeout, over the inbound's.
                        let mut entries = sessions.lock().await;
                        if let Some(entry) = entries.get_mut(&key) {
                            if let Some(udp_timeout) = udp_timeout {
                                entry.idle_timeout = udp_timeout;
                            }
                            if let Some(pending) = &pending {
                                // Include admitted queries not yet handed to
                                // the DNS responder. Later admissions add under
                                // this same session lock.
                                pending.add(sniffed.len() + target_ch_rx.len());
                                entry.pending = Some(pending.clone());
                            }
                        } else {
                            // Its association ended while it was being routed.
                            return;
                        }
                        (s, listed, pending)
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
                                        // DNS sessions can be reclaimed promptly
                                        // once every admitted query's reply has
                                        // reached the client. A first answer must
                                        // not retire other queries on this socket.
                                        sess.last_activity = Instant::now();
                                        sess.dns_answered = addr.port() == 53;
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
                        let mut sniffed = sniffed.into_iter();
                        loop {
                            let pkt = match sniffed.next() {
                                Some(pkt) => pkt,
                                None => match target_ch_rx.recv().await {
                                    Some(pkt) => pkt,
                                    None => break,
                                },
                            };
                            trace!(
                                "outbound send udp packet dst={} len={}",
                                &pkt.dst_addr,
                                pkt.data.len()
                            );
                            let sent = target_sock_send.send_to(&pkt.data, &pkt.dst_addr).await;
                            if let Some(pending) = &pending {
                                // send_to created the answer's own guard before
                                // giving back this queued-query reservation.
                                pending.finish(1);
                            }
                            if let Err(e) = sent {
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

    #[cfg(feature = "outbound-direct")]
    fn instance(config: &crate::config::Config) -> crate::app::instance::Instance {
        let mut env = crate::runtime::RuntimeEnv::default();
        env.options.udp.session_check_interval = Duration::from_millis(20);
        crate::app::instance::Instance::build(
            config,
            config.route.rules.clone(),
            Arc::new(env),
            Arc::default(),
        )
        .unwrap()
    }

    #[cfg(feature = "outbound-direct")]
    #[tokio::test]
    async fn rejected_uplink_packets_do_not_leave_pending_answers() {
        let instance = instance(&crate::config::Config::from_json("{}").unwrap());
        let (uplink, mut receive) = mpsc::channel(1);
        let (abort, _aborted) = oneshot::channel();
        let pending = PendingAnswers::default();
        let source = DatagramSource::new("192.0.2.1:50000".parse().unwrap(), None);
        let key = NatKey::new("test", &source);
        let sessions = Mutex::new(HashMap::from([(
            key.clone(),
            NatSession {
                uplink,
                abort,
                last_activity: Instant::now(),
                idle_timeout: Duration::from_secs(30),
                dns_answered: false,
                pending: Some(pending.clone()),
            },
        )]));
        let mut entries = sessions.lock().await;
        for _ in 0..3 {
            instance.nat_manager._send(
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
        pending.finish(1);
        assert!(
            pending.is_idle(),
            "rejected packets must release their reservations"
        );
        drop(receive);
        instance.nat_manager._send(
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
            uplink,
            abort,
            last_activity: now,
            idle_timeout: Duration::from_millis(50),
            dns_answered: true,
            pending: Some(pending.clone()),
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
        let instance = instance(&config);
        let nat = &instance.nat_manager;
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
        sleep(Duration::from_millis(80)).await;
        assert_eq!(
            nat.sessions.lock().await.len(),
            1,
            "a fast answer must not retire pending queries"
        );
        for (answer, peer) in &queries[1..] {
            upstream.send_to(answer, peer).await.unwrap();
        }
        // One answer fills client_ch_tx; the other must remain protected
        // while the NAT's downlink waits for the client to make room.
        sleep(Duration::from_millis(80)).await;
        assert_eq!(
            nat.sessions.lock().await.len(),
            1,
            "a backpressured answer must keep its session"
        );
        for _ in 0..2 {
            let answer = timeout(Duration::from_secs(2), received.recv())
                .await
                .unwrap()
                .unwrap();
            ids.push(Message::from_vec(&answer.data).unwrap().id());
        }
        ids.sort();
        assert_eq!(ids, vec![0, 1, 2]);
        timeout(Duration::from_secs(1), async {
            while !nat.sessions.lock().await.is_empty() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("finished DNS sessions are reclaimed at the next cleanup");
    }
}
