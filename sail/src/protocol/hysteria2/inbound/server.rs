//! Serving Hysteria2 connections: the HTTP/3 authentication, then proxied
//! TCP streams and UDP sessions, handed on as they arrive.

use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::Stream;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, trace};

use crate::adapter::*;
use crate::session::{DatagramSource, Network, Session, SocksAddr, StreamId};
use crate::transport::quic::{endpoint_on, FragmentBudget, QuicStream, Side, MAX_FRAGMENT_BYTES};

use super::super::congestion::CongestionHandle;
use super::super::h3::{self, Field};
use super::super::proto::{self, Defragger, UdpMessage};
use super::super::quic;
use super::super::salamander::Salamander;
use super::masquerade::Masquerade;

/// Streams and sessions accepted and not yet taken.
const ACCEPT_QUEUE: usize = 1024;
/// How long a stream may wait for room in the accept queue.
const ACCEPT_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
/// UDP sessions one connection may have at once.
const MAX_UDP_SESSIONS: usize = 1024;
/// Packets queued for a UDP session before more are dropped.
const UDP_SESSION_QUEUE: usize = 256;
/// A UDP session without packets from the client for this long is closed.
/// The client may go on using its ID; that starts a new session.
const UDP_SESSION_IDLE: Duration = Duration::from_secs(300);

/// What every connection of the inbound is served with.
pub struct Server {
    /// The inbound's tag.
    pub tag: String,
    /// Users by password, with their names.
    pub users: HashMap<String, Option<crate::user::UserRef>>,
    /// What we send at most at to a client, bytes per second; zero if
    /// unlimited.
    pub send_bps: u64,
    /// What we can receive at, told to clients; zero if unlimited.
    pub recv_bps: u64,
    pub ignore_client_bandwidth: bool,
    pub masquerade: Masquerade,
    pub handshake_timeout: Duration,
    pub tuning: crate::runtime::options::Quic,
}

pub struct DatagramHandler {
    resource: crate::runtime::resource::HotResource<Resources>,
    obfs: Option<Salamander>,
    /// What refuses new connections under memory pressure, when it is on.
    admission: Option<Arc<crate::app::inbound::admission::Admission>>,
}

pub(crate) struct Resources {
    server_config: quinn::ServerConfig,
    server: Arc<Server>,
}

impl DatagramHandler {
    pub fn new(
        server_config: quinn::ServerConfig,
        obfs: Option<Salamander>,
        server: Arc<Server>,
    ) -> Self {
        Self {
            resource: crate::runtime::resource::HotResource::new(Resources {
                server_config,
                server,
            }),
            obfs,
            admission: None,
        }
    }

    pub(crate) fn reloadable(mut self, ctx: &crate::adapter::registry::InboundContext<'_>) -> Self {
        self.resource = ctx.resource(&ctx.state.hysteria2, self.resource.load());
        self.admission = ctx.env.admission.clone();
        self
    }
}

struct Incoming(mpsc::Receiver<AnyBaseInboundTransport>);

impl Stream for Incoming {
    type Item = AnyBaseInboundTransport;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

#[async_trait]
impl InboundDatagramHandler for DatagramHandler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        let socket = socket.into_std()?;
        let local_addr = socket.local_addr()?;
        let endpoint = {
            let resource = self.resource.load();
            let buffers = resource.server.tuning.udp_buffers();
            let socket = quic::wrap_socket(socket, self.obfs.as_ref(), buffers)?;
            endpoint_on(socket, Some(resource.server_config.clone()))?
        };
        let (tx, rx) = mpsc::channel(ACCEPT_QUEUE);
        let resource = self.resource.clone();
        let admission = self.admission.clone();
        crate::runtime::scope::spawn_essential("hysteria2 accept", async move {
            // The connections, stopped when the inbound stops.
            let mut connections = JoinSet::new();
            loop {
                let incoming = tokio::select! {
                    incoming = endpoint.accept() => incoming,
                    // Nobody takes what we accept any more.
                    _ = tx.closed() => None,
                    Some(_) = connections.join_next(), if !connections.is_empty() => continue,
                };
                let Some(incoming) = incoming else {
                    break;
                };
                // Under memory pressure, refused before its handshake,
                // which cannot be closed once under way (admission.rs).
                if admission
                    .as_ref()
                    .is_some_and(|a| a.refuses_quic(incoming.remote_address().ip()))
                {
                    incoming.refuse();
                    continue;
                }
                let generation = resource.load();
                let conn = Conn {
                    server: generation.server.clone(),
                    tx: tx.clone(),
                    local_addr,
                };
                let config = generation.server_config.clone();
                // The host's check, in the connection's own task.
                let host_check = admission.as_ref().filter(|a| a.checks_sources()).cloned();
                crate::runtime::scope::spawn_child(
                    &mut connections,
                    "hysteria2 connection",
                    async move {
                        let remote = incoming.remote_address();
                        if let Some(admission) = host_check {
                            if !admission.host_admits_source(remote, local_addr) {
                                incoming.refuse();
                                return;
                            }
                        }
                        if let Err(e) = conn.serve(incoming, config).await {
                            debug!("hysteria2 connection from {}: {}", remote, e);
                        }
                    },
                );
            }
            endpoint.close(0u32.into(), b"");
        });
        Ok(InboundTransport::Incoming(Box::new(Incoming(rx))))
    }
}

struct Conn {
    server: Arc<Server>,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
    local_addr: SocketAddr,
}

impl Conn {
    async fn serve(self, incoming: quinn::Incoming, config: quinn::ServerConfig) -> io::Result<()> {
        // A controller of its own, which the authentication will set.
        let congestion = CongestionHandle::default();
        let mut config = config;
        config.transport_config(Arc::new(quic::transport_config(
            &self.server.tuning,
            Side::Server,
            &congestion,
        )));
        let conn = crate::transport::quic::server_handshake(
            incoming
                .accept_with(Arc::new(config))
                .map_err(io::Error::other)?,
            self.server.tuning.server_handshake_timeout,
        )
        .await?;
        trace!(
            "hysteria2 accepted connection from {}",
            conn.remote_address()
        );
        let _control = quic::open_control_stream(&conn).await?;
        // What the connection runs, stopped with it: its streams' requests
        // among them.
        let mut tasks = JoinSet::new();
        crate::runtime::scope::spawn_child(
            &mut tasks,
            "hysteria2 uni streams",
            quic::drain_uni_streams(conn.clone()),
        );

        let state = Arc::new(ConnState {
            server: self.server,
            tx: self.tx,
            local_addr: self.local_addr,
            conn: conn.clone(),
            congestion,
            user: OnceLock::new(),
            carrier: OnceLock::new(),
            streams: crate::transport::quic::StreamLimit::bidi(&conn),
            udp_started: AtomicBool::new(false),
            start_udp: Notify::new(),
            sessions: Arc::new(UdpSessions::default()),
        });
        loop {
            let accepted = tokio::select! {
                accepted = conn.accept_bi() => accepted,
                _ = state.start_udp.notified() => {
                    crate::runtime::scope::spawn_child(&mut tasks, "hysteria2 datagrams", state.clone().serve_datagrams());
                    continue;
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
            };
            match accepted {
                Ok((send, recv)) => {
                    let state = state.clone();
                    let counted = state.streams.opened();
                    crate::runtime::scope::spawn_child(
                        &mut tasks,
                        "hysteria2 connection task",
                        async move {
                            if let Err(e) = state.handle_stream(send, recv, counted).await {
                                debug!("hysteria2 stream: {}", e);
                            }
                        },
                    );
                }
                Err(quinn::ConnectionError::ApplicationClosed(_))
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::TimedOut) => return Ok(()),
                Err(e) => return Err(io::Error::other(e)),
            }
        }
    }
}

struct ConnState {
    server: Arc<Server>,
    tx: mpsc::Sender<AnyBaseInboundTransport>,
    local_addr: SocketAddr,
    conn: quinn::Connection,
    congestion: CongestionHandle,
    /// Set once the connection authenticated: the user, by name.
    user: OnceLock<Option<crate::user::UserRef>>,
    /// Closes the connection when the user is shut out, or taken out.
    carrier: OnceLock<crate::user::Carrier>,
    /// How many streams the client may hold open at once.
    streams: Arc<crate::transport::quic::StreamLimit>,
    udp_started: AtomicBool,
    /// Tells the connection to serve UDP, once authenticated.
    start_udp: Notify,
    sessions: Arc<UdpSessions>,
}

impl ConnState {
    fn session(&self, network: Network) -> Session {
        Session {
            network,
            source: self.conn.remote_address(),
            local_addr: self.local_addr,
            user: self.user.get().cloned().flatten(),
            ..Default::default()
        }
    }

    async fn handle_stream(
        self: Arc<Self>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        counted: crate::transport::quic::StreamGuard,
    ) -> io::Result<()> {
        let handshake = self.server.handshake_timeout;
        let ty = timeout(handshake, proto::read_varint(&mut recv))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "stream handshake"))??;
        if ty == proto::FRAME_TYPE_TCP_REQUEST {
            if self.user.get().is_none() {
                // Not a proxy connection; to a web server, a frame it does
                // not know on a request stream is an error.
                let _ = recv.stop(0u32.into());
                let _ = send.reset(0u32.into());
                return Err(io::Error::other("TCP request before authentication"));
            }
            let destination = timeout(handshake, proto::read_tcp_request(&mut recv))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP request"))??;
            // Answered before the outbound connects: the reference client
            // waits for the answer before it sends anything, and a failed
            // connection is a closed stream all the same.
            send.write_all(&proto::tcp_response(true, ""))
                .await
                .map_err(io::Error::other)?;
            let mut sess = self.session(Network::Tcp);
            sess.destination = destination;
            sess.stream_id = Some(StreamId::U64(send.id().index()));
            let stream = Box::new(crate::transport::quic::Counted::new(
                QuicStream::new(send, recv),
                counted,
            ));
            return match timeout(
                ACCEPT_QUEUE_TIMEOUT,
                self.tx.send(BaseInboundTransport::Stream(stream, sess)),
            )
            .await
            {
                Ok(Ok(())) => Ok(()),
                Ok(Err(_)) => Ok(()),
                Err(_) => Err(io::Error::other("accept queue full")),
            };
        }

        let fields = timeout(handshake, h3::read_headers(&mut recv, Some(ty)))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request headers"))??;
        if is_auth_request(&fields) {
            // A connection authenticates once. A later request is answered
            // as the first was, whatever it says, as the reference answers
            // it: nothing is set again.
            if self.user.get().is_some() {
                return self.answer_auth(send).await;
            }
            let password = h3::field(&fields, proto::HEADER_AUTH).unwrap_or_default();
            let user = self.server.users.get(password);
            if let Some(user) = user.filter(|user| !crate::user::shut_out(user)) {
                return self.authenticated(user.clone(), &fields, send).await;
            }
        }
        self.server.masquerade.serve(fields, send, recv).await
    }

    /// Answers a good authentication, and makes the connection a proxy
    /// connection, unless another request made it one first.
    async fn authenticated(
        self: &Arc<Self>,
        user: Option<crate::user::UserRef>,
        fields: &[Field],
        send: quinn::SendStream,
    ) -> io::Result<()> {
        if self.user.set(user.clone()).is_err() {
            return self.answer_auth(send).await;
        }
        let server = &self.server;
        // Its bidirectional streams grow with its use from now on; HTTP/3
        // needs no more unidirectional ones than it has.
        self.streams.authenticated();
        if let Some(user) = &user {
            let conn = self.conn.clone();
            let _ = self
                .carrier
                .set(user.carry(&server.tag, move || conn.close(0u32.into(), b"")));
        }
        // As the reference server: we send at what the client says it can
        // receive, capped by what we may send at; not knowing, BBR.
        let client_rx: u64 = h3::field(fields, proto::HEADER_CC_RX)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let tx = if server.ignore_client_bandwidth {
            0
        } else if server.send_bps > 0 && client_rx > server.send_bps {
            server.send_bps
        } else {
            client_rx
        };
        if tx > 0 {
            debug!("hysteria2 sends with brutal at {} bytes/s", tx);
            self.congestion.set_brutal(tx);
        } else {
            self.congestion.set_bbr();
        }
        self.answer_auth(send).await?;
        if !self.udp_started.swap(true, Ordering::Relaxed) {
            self.start_udp.notify_one();
        }
        Ok(())
    }

    /// The answer to an authentication, the first or a later one.
    async fn answer_auth(&self, mut send: quinn::SendStream) -> io::Result<()> {
        let rx = if self.server.ignore_client_bandwidth {
            "auto".to_string()
        } else {
            self.server.recv_bps.to_string()
        };
        let padding = proto::padding(proto::AUTH_RESPONSE_PADDING);
        let status = proto::STATUS_AUTH_OK.to_string();
        h3::write_headers(
            &mut send,
            &[
                (":status", &status),
                (proto::HEADER_UDP, "true"),
                (proto::HEADER_CC_RX, &rx),
                (proto::HEADER_PADDING, &padding),
            ],
        )
        .await?;
        let _ = send.finish();
        Ok(())
    }

    /// Hands the datagrams of the connection to their sessions, starting a
    /// session for an ID it has not seen or has closed.
    async fn serve_datagrams(self: Arc<Self>) {
        let mut swept = Instant::now();
        while let Ok(datagram) = self.conn.read_datagram().await {
            let msg = match UdpMessage::decode(&datagram) {
                Ok(msg) => msg,
                Err(e) => {
                    debug!("hysteria2: invalid UDP message: {}", e);
                    continue;
                }
            };
            let known = {
                let sessions = self.sessions.lock();
                if !sessions.contains_key(&msg.session_id) && sessions.len() >= MAX_UDP_SESSIONS {
                    continue;
                }
                sessions.contains_key(&msg.session_id)
            };
            // Not under the lock: a session dropped at once takes it too.
            if !known {
                let Some(entry) = self.new_udp_session(msg.session_id) else {
                    continue;
                };
                self.sessions.lock().insert(msg.session_id, entry);
            }
            let mut sessions = self.sessions.lock();
            let now = Instant::now();
            // Unfinished packets of sessions gone quiet are dropped too.
            if now.saturating_duration_since(swept) >= proto::FRAGMENT_TIMEOUT {
                for entry in sessions.values_mut() {
                    entry.defragger.expire(now);
                }
                swept = now;
            }
            let Some(entry) = sessions.get_mut(&msg.session_id) else {
                continue;
            };
            let Some(packet) = entry.defragger.feed(&msg, now) else {
                continue;
            };
            let destination = match proto::parse_addr(msg.addr) {
                Ok(destination) => destination,
                Err(e) => {
                    debug!("hysteria2: invalid UDP destination: {}", e);
                    continue;
                }
            };
            // A session that does not keep up loses packets, as UDP would;
            // one that is gone is forgotten, and the next packet starts
            // another.
            if let Err(mpsc::error::TrySendError::Closed(_)) =
                entry.tx.try_send((packet, destination))
            {
                sessions.remove(&msg.session_id);
            }
        }
        // The connection is gone: so are its sessions, whose halves see
        // the end at once instead of idling out.
        self.sessions.lock().clear();
    }

    /// Starts the UDP session `id`, handing it on.
    fn new_udp_session(&self, id: u32) -> Option<UdpSessionEntry> {
        let (tx, rx) = mpsc::channel(UDP_SESSION_QUEUE);
        let serial = self.sessions.next_serial.fetch_add(1, Ordering::Relaxed);
        let mut sess = self.session(Network::Udp);
        // Sessions from one client address are told apart by this.
        sess.stream_id = Some(StreamId::Uuid(uuid::Uuid::new_v4()));
        let datagram = Datagram {
            rx,
            source: DatagramSource::new(sess.source, sess.stream_id),
            guard: SessionGuard {
                sessions: self.sessions.clone(),
                id,
                serial,
            },
            sender: UdpSender {
                conn: self.conn.clone(),
                id,
                next_packet: AtomicU32::new(0),
            },
        };
        // Taken or not, never waited on: this is the datagram loop.
        self.tx
            .try_send(BaseInboundTransport::Datagram(
                Box::new(datagram),
                Some(sess),
            ))
            .ok()?;
        Some(UdpSessionEntry {
            tx,
            defragger: Defragger::new(self.sessions.fragments.clone()),
            serial,
        })
    }
}

fn is_auth_request(fields: &[Field]) -> bool {
    h3::field(fields, ":method") == Some("POST")
        && h3::field(fields, ":authority") == Some(proto::AUTH_HOST)
        && h3::field(fields, ":path") == Some(proto::AUTH_PATH)
}

type Packet = (Vec<u8>, SocksAddr);

struct UdpSessionEntry {
    tx: mpsc::Sender<Packet>,
    defragger: Defragger,
    /// Tells this session from a later one under the same ID.
    serial: u64,
}

struct UdpSessions {
    map: Mutex<HashMap<u32, UdpSessionEntry>>,
    next_serial: AtomicU64,
    /// What the sessions' unfinished packets hold, together.
    fragments: Arc<FragmentBudget>,
}

impl Default for UdpSessions {
    fn default() -> Self {
        UdpSessions {
            map: Default::default(),
            next_serial: Default::default(),
            fragments: FragmentBudget::new(MAX_FRAGMENT_BYTES),
        }
    }
}

impl UdpSessions {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u32, UdpSessionEntry>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Closes the session when its receiving half goes: packets for the ID
/// then start a new one.
struct SessionGuard {
    sessions: Arc<UdpSessions>,
    id: u32,
    serial: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut sessions = self.sessions.lock();
        if sessions
            .get(&self.id)
            .is_some_and(|e| e.serial == self.serial)
        {
            sessions.remove(&self.id);
        }
    }
}

struct UdpSender {
    conn: quinn::Connection,
    id: u32,
    next_packet: AtomicU32,
}

impl UdpSender {
    fn send(&self, payload: &[u8], from: &SocksAddr) -> io::Result<()> {
        let max = self
            .conn
            .max_datagram_size()
            .ok_or_else(|| io::Error::other("hysteria2: the client takes no datagrams"))?;
        let packet_id = self.next_packet.fetch_add(1, Ordering::Relaxed) as u16;
        let addr = proto::format_addr(from);
        for fragment in proto::fragment(self.id, packet_id, &addr, payload, max)? {
            self.conn
                .send_datagram(Bytes::from(fragment))
                .map_err(io::Error::other)?;
        }
        Ok(())
    }
}

/// One UDP session of a client.
struct Datagram {
    rx: mpsc::Receiver<Packet>,
    source: DatagramSource,
    guard: SessionGuard,
    sender: UdpSender,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        (
            Box::new(DatagramRecvHalf {
                rx: self.rx,
                source: self.source,
                _guard: self.guard,
            }),
            Box::new(DatagramSendHalf(self.sender)),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("hysteria2 UDP session"))
    }
}

struct DatagramRecvHalf {
    rx: mpsc::Receiver<Packet>,
    source: DatagramSource,
    _guard: SessionGuard,
}

#[async_trait]
impl InboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let (packet, destination) = match timeout(UDP_SESSION_IDLE, self.rx.recv()).await {
            Ok(Some(p)) => p,
            Ok(None) => return Err(ProxyError::DatagramFatal(anyhow!("session closed"))),
            Err(_) => return Err(ProxyError::DatagramFatal(anyhow!("session idle"))),
        };
        if packet.len() > buf.len() {
            return Err(ProxyError::DatagramWarn(anyhow!(
                "UDP packet of {} bytes, buffer of {}",
                packet.len(),
                buf.len()
            )));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), self.source.clone(), destination))
    }
}

struct DatagramSendHalf(UdpSender);

#[async_trait]
impl InboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        self.0.send(buf, src_addr)?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::masquerade::{MasqueradeObject, MasqueradeOptions};
    use super::*;
    use crate::transport::quic::{
        alpn_protocols, client_crypto, endpoint, server_config, server_crypto,
    };
    use crate::transport::tls::roots::TrustRoots;
    use futures::StreamExt;

    struct Fixture {
        endpoint: quinn::Endpoint,
        server: SocketAddr,
        incoming: AnyIncomingTransport,
    }

    async fn serve(masquerade: Masquerade) -> Fixture {
        serve_admitted(masquerade, None).await
    }

    async fn serve_admitted(
        masquerade: Masquerade,
        admission: Option<Arc<crate::app::inbound::admission::Admission>>,
    ) -> Fixture {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let alpns = alpn_protocols(None, quic::DEFAULT_ALPN);
        let crypto = server_crypto(&cert.pem(), &key_pair.serialize_pem(), &alpns).unwrap();
        let config = server_config(crypto).unwrap();
        let server = Arc::new(Server {
            tag: "hy2".into(),
            users: [(
                "pw".to_string(),
                Some(crate::user::UserRef::unbound("alice")),
            )]
            .into(),
            send_bps: 0,
            recv_bps: 0,
            ignore_client_bandwidth: false,
            masquerade,
            handshake_timeout: Duration::from_secs(5),
            tuning: Default::default(),
        });
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let mut handler = DatagramHandler::new(config, None, server);
        handler.admission = admission;
        let transport = handler
            .handle(Box::new(crate::net::SimpleInboundDatagram(socket)))
            .await
            .unwrap();
        let InboundTransport::Incoming(incoming) = transport else {
            panic!("not incoming");
        };
        let crypto = client_crypto(
            Some(&cert.pem()),
            false,
            &alpns,
            &crate::transport::tls::tests::test_roots(),
        )
        .unwrap();
        let mut endpoint = endpoint(
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            None,
            Default::default(),
        )
        .unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        Fixture {
            endpoint,
            server: addr,
            incoming,
        }
    }

    impl Fixture {
        async fn connect(&self) -> quinn::Connection {
            self.endpoint
                .connect(self.server, "localhost")
                .unwrap()
                .await
                .unwrap()
        }
    }

    async fn request(conn: &quinn::Connection, fields: &[(&str, &str)]) -> (Vec<Field>, Vec<u8>) {
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        h3::write_headers(&mut send, fields).await.unwrap();
        send.finish().unwrap();
        let headers = h3::read_headers(&mut recv, None).await.unwrap();
        let body = h3::read_body(&mut recv, 1 << 20).await.unwrap();
        (headers, body)
    }

    fn auth(password: &str) -> Vec<(&str, &str)> {
        vec![
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "hysteria"),
            (":path", "/auth"),
            ("hysteria-auth", password),
            ("hysteria-cc-rx", "0"),
        ]
    }

    const GET: [(&str, &str); 4] = [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/"),
    ];

    /// Under memory pressure a new connection is refused before its
    /// handshake, and counted: at least once, as the client may resend its
    /// Initial before the refusal reaches it, and each one is refused.
    #[tokio::test]
    async fn a_connection_under_memory_pressure_is_refused() {
        let admission = crate::app::inbound::admission::Admission::under_pressure();
        let f = serve_admitted(Masquerade::NotFound, Some(admission.clone())).await;
        let refused = f
            .endpoint
            .connect(f.server, "localhost")
            .unwrap()
            .await
            .unwrap_err();
        assert!(
            matches!(refused, quinn::ConnectionError::ConnectionClosed(_)),
            "{:?}",
            refused
        );
        assert!(admission.info().refused_quic >= 1);
    }

    #[tokio::test]
    async fn strangers_see_a_web_server_that_has_nothing() {
        let f = serve(Masquerade::NotFound).await;
        let conn = f.connect().await;
        let (headers, _) = request(&conn, &GET).await;
        assert_eq!(h3::field(&headers, ":status"), Some("404"));
        let (headers, _) = request(&conn, &auth("wrong")).await;
        assert_eq!(h3::field(&headers, ":status"), Some("404"));

        // A TCP request before authenticating is refused.
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&proto::tcp_request(
            &SocksAddr::try_from(("example.com", 80)).unwrap(),
            b"",
        ))
        .await
        .unwrap();
        assert!(proto::read_tcp_response(&mut recv).await.is_err());
    }

    #[tokio::test]
    async fn a_fixed_masquerade_answers_strangers() {
        let masquerade = Masquerade::new(
            MasqueradeOptions::Object(MasqueradeObject::String {
                status_code: Some(200),
                headers: [("Content-Type".to_string(), "text/plain".to_string())].into(),
                content: "hello".into(),
            }),
            crate::net::InstanceDial::default().default_dialer(),
            &TrustRoots::default(),
        )
        .unwrap();
        let f = serve(masquerade).await;
        let conn = f.connect().await;
        let (headers, body) = request(&conn, &GET).await;
        assert_eq!(h3::field(&headers, ":status"), Some("200"));
        assert_eq!(h3::field(&headers, "content-type"), Some("text/plain"));
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn a_proxy_masquerade_passes_strangers_to_the_site_behind() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let site = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let site_addr = site.local_addr().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = site.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut buf).await.unwrap();
                request.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.0 200 OK\r\nX-Up: 1\r\nConnection: close\r\n\r\nupstream")
                .await
                .unwrap();
            let _ = seen_tx.send(String::from_utf8(request).unwrap());
        });
        let masquerade = Masquerade::new(
            MasqueradeOptions::Url(format!("http://{}/base", site_addr)),
            crate::net::InstanceDial::default().default_dialer(),
            &TrustRoots::default(),
        )
        .unwrap();
        let f = serve(masquerade).await;
        let conn = f.connect().await;
        let (headers, body) = request(&conn, &GET).await;
        assert_eq!(h3::field(&headers, ":status"), Some("200"));
        assert_eq!(h3::field(&headers, "x-up"), Some("1"));
        assert_eq!(h3::field(&headers, "connection"), None);
        assert_eq!(body, b"upstream");
        let seen = seen_rx.await.unwrap();
        assert!(seen.starts_with("GET /base/ HTTP/1.0\r\n"), "{}", seen);
        // The host asked for, as rewrite_host is off.
        assert!(seen.contains("host: example.com\r\n"), "{}", seen);
    }

    /// What an HTTPS site saw of the one request it answered: the
    /// method, path and host as HTTP/2 names them, and the headers.
    type Seen = Vec<(String, String)>;

    /// An HTTPS site on 127.0.0.1, its certificate self-signed, that
    /// answers one request over HTTP/2 if it is `h2`, else over HTTP/1.0;
    /// its address, its certificate, and what it saw.
    async fn https_site(h2: bool) -> (SocketAddr, String, tokio::sync::oneshot::Receiver<Seen>) {
        use crate::transport::tls::BoringConnection;
        use crate::transport::tls_stream::TlsStream;
        use btls::ssl::{AlpnError, Ssl, SslAcceptor, SslMethod};
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        builder
            .set_certificate(&btls::x509::X509::from_pem(cert.pem().as_bytes()).unwrap())
            .unwrap();
        builder
            .set_private_key(
                &btls::pkey::PKey::private_key_from_pem(key_pair.serialize_pem().as_bytes())
                    .unwrap(),
            )
            .unwrap();
        if h2 {
            builder.set_alpn_select_callback(|_, client| {
                btls::ssl::select_next_proto(b"\x02h2", client).ok_or(AlpnError::NOACK)
            });
        }
        let acceptor = builder.build();
        let site = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = site.local_addr().unwrap();
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (tcp, _) = site.accept().await.unwrap();
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut tls = TlsStream::new(BoringConnection::server(ssl).unwrap(), tcp, None);
            if tls.handshake().await.is_err() {
                return;
            }
            if h2 {
                serve_h2(tls, seen_tx).await
            } else {
                serve_http1(tls, seen_tx).await
            }
        });
        (addr, cert.pem(), seen_rx)
    }

    async fn serve_h2<S>(stream: S, seen_tx: tokio::sync::oneshot::Sender<Seen>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut conn = ::h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = conn.accept().await.unwrap().unwrap();
        let mut seen: Seen = vec![
            (":method".into(), request.method().to_string()),
            (":path".into(), request.uri().path().to_string()),
            (
                ":authority".into(),
                request.uri().authority().unwrap().to_string(),
            ),
        ];
        for (name, value) in request.headers() {
            seen.push((name.to_string(), value.to_str().unwrap().to_string()));
        }
        let response = http::Response::builder()
            .status(200)
            .header("x-up", "2")
            .header("proxy-authenticate", "Basic")
            .body(())
            .unwrap();
        respond
            .send_response(response, false)
            .unwrap()
            .send_data(bytes::Bytes::from_static(b"upstream over h2"), true)
            .unwrap();
        let _ = seen_tx.send(seen);
        while conn.accept().await.is_some() {}
    }

    async fn serve_http1<S>(mut stream: S, seen_tx: tokio::sync::oneshot::Sender<Seen>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut buf).await.unwrap();
            request.extend_from_slice(&buf[..n]);
        }
        let request = String::from_utf8(request).unwrap();
        let mut lines = request.trim_end().split("\r\n");
        let mut line = lines.next().unwrap().split(' ');
        let mut seen: Seen = vec![
            (":method".into(), line.next().unwrap().into()),
            (":path".into(), line.next().unwrap().into()),
        ];
        for header in lines {
            let (name, value) = header.split_once(": ").unwrap();
            let name = if name == "host" { ":authority" } else { name };
            seen.push((name.into(), value.into()));
        }
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nX-Up: 1\r\nConnection: close\r\n\r\nupstream over tls")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        let _ = seen_tx.send(seen);
    }

    /// Roots that trust `pem` alone.
    fn trusting(pem: &str) -> TrustRoots {
        let options = crate::config::model::CertificateOptions {
            store: crate::config::model::CertificateStore::None,
            certificate: vec![pem.to_string()],
            ..Default::default()
        };
        let roots = TrustRoots::default();
        roots.set(
            crate::transport::tls::roots::Roots::configured(
                &options,
                &crate::runtime::RuntimeEnv::default(),
            )
            .unwrap(),
        );
        roots
    }

    fn https_masquerade(url: String, rewrite_host: bool, roots: &TrustRoots) -> Masquerade {
        Masquerade::new(
            MasqueradeOptions::Object(MasqueradeObject::Proxy { url, rewrite_host }),
            crate::net::InstanceDial::default().default_dialer(),
            roots,
        )
        .unwrap()
    }

    fn seen<'a>(seen: &'a Seen, name: &str) -> Option<&'a str> {
        seen.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test]
    async fn an_https_masquerade_asks_the_site_over_http2() {
        let (addr, pem, seen_rx) = https_site(true).await;
        let f = serve(https_masquerade(
            format!("https://{}/base", addr),
            false,
            &trusting(&pem),
        ))
        .await;
        let conn = f.connect().await;
        let mut get = GET.to_vec();
        get.push(("x-forwarded-for", "1.2.3.4"));
        get.push(("accept", "text/html"));
        let (headers, body) = request(&conn, &get).await;
        assert_eq!(h3::field(&headers, ":status"), Some("200"));
        assert_eq!(h3::field(&headers, "x-up"), Some("2"));
        assert_eq!(h3::field(&headers, "proxy-authenticate"), None);
        assert_eq!(body, b"upstream over h2");
        let seen_ = seen_rx.await.unwrap();
        assert_eq!(seen(&seen_, ":method"), Some("GET"));
        assert_eq!(seen(&seen_, ":path"), Some("/base/"));
        // The host asked for, as rewrite_host is off.
        assert_eq!(seen(&seen_, ":authority"), Some("example.com"));
        assert_eq!(seen(&seen_, "accept"), Some("text/html"));
        assert_eq!(seen(&seen_, "x-forwarded-for"), None);
    }

    #[tokio::test]
    async fn an_https_site_without_http2_is_asked_over_http1() {
        let (addr, pem, seen_rx) = https_site(false).await;
        let f = serve(https_masquerade(
            format!("https://{}/", addr),
            false,
            &trusting(&pem),
        ))
        .await;
        let conn = f.connect().await;
        let (headers, body) = request(&conn, &GET).await;
        assert_eq!(h3::field(&headers, ":status"), Some("200"));
        assert_eq!(h3::field(&headers, "x-up"), Some("1"));
        assert_eq!(h3::field(&headers, "connection"), None);
        assert_eq!(body, b"upstream over tls");
        let seen_ = seen_rx.await.unwrap();
        assert_eq!(seen(&seen_, ":path"), Some("/"));
        assert_eq!(seen(&seen_, ":authority"), Some("example.com"));
    }

    #[tokio::test]
    async fn rewrite_host_sends_the_sites_own_host() {
        let (addr, pem, seen_rx) = https_site(true).await;
        let f = serve(https_masquerade(
            format!("https://{}/", addr),
            true,
            &trusting(&pem),
        ))
        .await;
        let conn = f.connect().await;
        let (headers, _) = request(&conn, &GET).await;
        assert_eq!(h3::field(&headers, ":status"), Some("200"));
        let seen_ = seen_rx.await.unwrap();
        assert_eq!(seen(&seen_, ":authority"), Some(addr.to_string().as_str()));
    }

    /// The site's certificate is checked, as Go's default transport checks
    /// it: one the roots do not trust is a bad gateway.
    #[tokio::test]
    async fn an_https_site_not_trusted_is_a_bad_gateway() {
        let (addr, _, _) = https_site(true).await;
        let roots = TrustRoots::default();
        roots.set(crate::transport::tls::tests::test_roots());
        let f = serve(https_masquerade(
            format!("https://{}/", addr),
            false,
            &roots,
        ))
        .await;
        let conn = f.connect().await;
        let (headers, body) = request(&conn, &GET).await;
        assert_eq!(h3::field(&headers, ":status"), Some("502"));
        assert!(body.is_empty());
    }

    /// A connection authenticates once: a later request is answered as
    /// the first was, whatever its password, and the connection stays the
    /// first user's.
    #[tokio::test]
    async fn a_later_authentication_is_answered_and_changes_nothing() {
        let mut f = serve(Masquerade::NotFound).await;
        let conn = f.connect().await;
        let (headers, _) = request(&conn, &auth("pw")).await;
        assert_eq!(h3::field(&headers, ":status"), Some("233"));
        for password in ["pw", "wrong"] {
            let mut fields = auth(password);
            fields.retain(|(name, _)| *name != "hysteria-cc-rx");
            fields.push(("hysteria-cc-rx", "1000000"));
            let (headers, _) = request(&conn, &fields).await;
            assert_eq!(h3::field(&headers, ":status"), Some("233"), "{}", password);
            assert_eq!(h3::field(&headers, "hysteria-udp"), Some("true"));
            assert_eq!(h3::field(&headers, "hysteria-cc-rx"), Some("0"));
        }
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let destination = SocksAddr::try_from(("example.com", 443)).unwrap();
        send.write_all(&proto::tcp_request(&destination, b""))
            .await
            .unwrap();
        proto::read_tcp_response(&mut recv).await.unwrap();
        let Some(BaseInboundTransport::Stream(_, sess)) = f.incoming.next().await else {
            panic!("no stream");
        };
        assert_eq!(crate::user::name(&sess.user), Some("alice"));
    }

    #[tokio::test]
    async fn an_authenticated_connection_proxies_tcp_as_the_user() {
        let mut f = serve(Masquerade::NotFound).await;
        let conn = f.connect().await;
        let (headers, _) = request(&conn, &auth("pw")).await;
        assert_eq!(h3::field(&headers, ":status"), Some("233"));
        assert_eq!(h3::field(&headers, "hysteria-udp"), Some("true"));
        assert_eq!(h3::field(&headers, "hysteria-cc-rx"), Some("0"));

        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let destination = SocksAddr::try_from(("example.com", 443)).unwrap();
        send.write_all(&proto::tcp_request(&destination, b"early"))
            .await
            .unwrap();
        proto::read_tcp_response(&mut recv).await.unwrap();
        let Some(BaseInboundTransport::Stream(mut stream, sess)) = f.incoming.next().await else {
            panic!("no stream");
        };
        assert_eq!(sess.destination, destination);
        assert_eq!(crate::user::name(&sess.user), Some("alice"));
        let mut buf = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"early");

        // A UDP message starts a session.
        let mut msg = bytes::BytesMut::new();
        UdpMessage {
            session_id: 7,
            packet_id: 0,
            fragment_id: 0,
            fragment_count: 1,
            addr: "1.2.3.4:53",
            payload: b"query",
        }
        .encode(&mut msg);
        conn.send_datagram(msg.freeze()).unwrap();
        let Some(BaseInboundTransport::Datagram(datagram, Some(sess))) = f.incoming.next().await
        else {
            panic!("no datagram");
        };
        assert_eq!(crate::user::name(&sess.user), Some("alice"));
        let (mut r, _s) = datagram.split();
        let mut buf = [0u8; 64];
        let (n, _, destination) = r.recv_from(&mut buf).await.ok().unwrap();
        assert_eq!(&buf[..n], b"query");
        assert_eq!(destination.to_string(), "1.2.3.4:53");
    }

    /// Before it authenticates, a client holds no more than
    /// `STREAMS_BEFORE_AUTH` streams at once; once it has, as many as it
    /// likes, as with sing-box's server.
    #[tokio::test]
    async fn streams_are_bounded_until_authentication() {
        use crate::transport::quic::STREAMS_BEFORE_AUTH;
        let f = serve(Masquerade::NotFound).await;
        let open = |conn: quinn::Connection| async move {
            tokio::time::timeout(Duration::from_millis(300), conn.open_bi())
                .await
                .is_ok()
        };
        let stranger = f.connect().await;
        let mut held = Vec::new();
        for _ in 0..STREAMS_BEFORE_AUTH {
            held.push(stranger.open_bi().await.unwrap());
        }
        assert!(!open(stranger.clone()).await, "one past the bound");

        // Authenticated, it holds as many as it opens: the limit grows
        // with the streams it keeps open.
        let mut f = f;
        let user = f.connect().await;
        let (headers, _) = request(&user, &auth("pw")).await;
        assert_eq!(h3::field(&headers, ":status"), Some("233"));
        let destination = SocksAddr::try_from(("example.com", 443)).unwrap();
        let mut proxied = Vec::new();
        for _ in 0..3 * STREAMS_BEFORE_AUTH {
            let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(5), user.open_bi())
                .await
                .expect("a stream past the bound once authenticated")
                .unwrap();
            send.write_all(&proto::tcp_request(&destination, b""))
                .await
                .unwrap();
            proto::read_tcp_response(&mut recv).await.unwrap();
            let Some(stream) = f.incoming.next().await else {
                panic!("no stream");
            };
            proxied.push((send, recv, stream));
        }
    }

    /// Disconnecting the user closes its QUIC connection, which carries
    /// its streams, so that the client connects again.
    #[tokio::test]
    async fn disconnecting_the_user_closes_its_connection() {
        let mut f = serve(Masquerade::NotFound).await;
        let conn = f.connect().await;
        let (headers, _) = request(&conn, &auth("pw")).await;
        assert_eq!(h3::field(&headers, ":status"), Some("233"));
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let destination = SocksAddr::try_from(("example.com", 443)).unwrap();
        send.write_all(&proto::tcp_request(&destination, b""))
            .await
            .unwrap();
        proto::read_tcp_response(&mut recv).await.unwrap();
        let Some(BaseInboundTransport::Stream(_, sess)) = f.incoming.next().await else {
            panic!("no stream");
        };
        sess.user.unwrap().disconnect();
        tokio::time::timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("the connection is closed");
    }
}
