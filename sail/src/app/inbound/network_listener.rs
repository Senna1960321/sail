use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use futures::stream::StreamExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::channel as tokio_channel;
use tokio::sync::mpsc::{Receiver as TokioReceiver, Sender as TokioSender};
use tokio::sync::watch;
use tokio::time::timeout;
use tracing::{debug, info, trace, warn, Instrument};

use crate::app::dispatcher::Dispatcher;
use crate::app::nat_manager::{NatManager, UdpPacket};
use crate::net::accept::AcceptBackoff;
use crate::runtime::scope::TaskClass;
use crate::session::{Network, Session, SocksAddr};
use crate::Runner;
use crate::{adapter::*, net::*};

#[cfg(feature = "inbound-nf")]
lazy_static::lazy_static! {
    pub static ref TCP_LISTENING_ADDRESSES: std::sync::RwLock<std::collections::HashMap<String, SocketAddr>> =
        std::sync::RwLock::new(std::collections::HashMap::new());
    pub static ref UDP_LISTENING_ADDRESSES: std::sync::RwLock<std::collections::HashMap<String, SocketAddr>> =
        std::sync::RwLock::new(std::collections::HashMap::new());
}

#[cfg(feature = "inbound-nf")]
pub fn get_network_listen_addr(tag: &str, kind: Network) -> Option<SocketAddr> {
    match kind {
        Network::Tcp => TCP_LISTENING_ADDRESSES
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(tag)
            .copied(),
        Network::Udp => UDP_LISTENING_ADDRESSES
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(tag)
            .copied(),
    }
}

// Handle an inbound datagram, which is similar to a UDP socket, managed by NAT
// manager. `lives` is how long it lives: as long as its inbound (an inbound's
// own UDP socket, essential) or one connection (a TCP-carried association,
// contained); its uplink task is of that class.
pub(super) async fn handle_inbound_datagram(
    inbound_tag: String,
    socket: Box<dyn InboundDatagram>,
    sess: Option<Session>,
    nat_manager: Arc<NatManager>,
    lives: TaskClass,
) {
    let mut sess = sess.unwrap_or_default();
    sess.network = Network::Udp;
    let span = sess.span();
    handle_inbound_datagram_inner(inbound_tag, socket, sess, nat_manager, lives)
        .instrument(span)
        .await
}

async fn handle_inbound_datagram_inner(
    inbound_tag: String,
    socket: Box<dyn InboundDatagram>,
    sess: Session,
    nat_manager: Arc<NatManager>,
    lives: TaskClass,
) {
    // Left-hand side socket, it's usually encapsulated with inbound protocol
    // layers.
    let (mut lr, mut ls) = socket.split();

    // Datagrams read from the left-hand side socket would go through the NAT
    // manager first, which maintains UDP sessions, the NAT manager creates the
    // right-hand side socket by dispatching UDP sessions, then datagrams are sent
    // to the socket by the NAT manager. When the NAT manager reads some packets
    // from the right-hand side socket, they would be sent back here through a
    // channel, then we can send them to left-hand side socket.
    let (l_tx, mut l_rx): (TokioSender<UdpPacket>, TokioReceiver<UdpPacket>) =
        tokio_channel(nat_manager.env().options.udp.uplink_channel_size);

    crate::runtime::scope::spawn_of(
        lives,
        "inbound datagram uplink",
        async move {
            while let Some(pkt) = l_rx.recv().await {
                let Some(dst_addr) = pkt.dst_addr.as_socket_addr() else {
                    debug!("drop udp packet to non-ip address {}", &pkt.dst_addr);
                    continue;
                };
                trace!("send udp packet dst={} len={}", &dst_addr, pkt.data.len());
                if let Err(e) = ls.send_to(&pkt.data[..], &pkt.src_addr, dst_addr).await {
                    debug!("send datagram failed: {}", e);
                }
            }
            if let Err(e) = ls.close().await {
                debug!("failed to close inbound datagram: {}", e);
            }
        }
        .instrument(sess.span()),
    );

    let mut buf = vec![0u8; nat_manager.env().options.udp.datagram_buffer_size * 1024];
    loop {
        match lr.recv_from(&mut buf).instrument(sess.span()).await {
            Err(ProxyError::DatagramFatal(e)) => {
                debug!("fatal error when receiving datagram: {}", e);
                break;
            }
            Err(ProxyError::DatagramWarn(e)) => {
                debug!("warning when receiving datagram: {}", e);
                continue;
            }
            Ok((n, dgram_src, dst_addr)) => {
                trace!("received udp packet src={} len={}", &dgram_src.address, n);
                let pkt = UdpPacket::new(
                    buf[..n].to_vec(),
                    SocksAddr::from(dgram_src.address),
                    dst_addr,
                );
                nat_manager
                    .send(Some(&sess), &dgram_src, &inbound_tag, &l_tx, pkt)
                    .instrument(sess.span())
                    .await;
            }
        }
    }
}

// Handle an inbound transport.
/// `lives`: how long a datagram transport lives (`handle_inbound_datagram`).
async fn handle_inbound_transport(
    transport: AnyInboundTransport,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    lives: TaskClass,
) {
    match transport {
        // A reliable transport.
        InboundTransport::Stream(stream, sess) => {
            let span = sess.span();
            super::magic::serve_stream(
                sess,
                stream,
                handler.tag().clone(),
                dispatcher,
                nat_manager,
            )
            .instrument(span)
            .await;
        }
        // An unreliable transport.
        InboundTransport::Datagram(socket, sess) => {
            let span = sess.as_ref().map(|x| x.span());
            if let Some(span) = span {
                handle_inbound_datagram(handler.tag().clone(), socket, sess, nat_manager, lives)
                    .instrument(span)
                    .await;
            } else {
                handle_inbound_datagram(handler.tag().clone(), socket, sess, nat_manager, lives)
                    .await;
            }
        }
        // A multiplexed transport.
        InboundTransport::Incoming(mut incoming) => {
            while let Some(transport) = incoming.next().await {
                match transport {
                    BaseInboundTransport::Stream(stream, mut sess) => {
                        sess.inbound_tag = handler.tag().clone();
                        let span = sess.span();
                        crate::runtime::scope::spawn(
                            "inbound stream",
                            super::magic::serve_stream(
                                sess,
                                stream,
                                handler.tag().clone(),
                                dispatcher.clone(),
                                nat_manager.clone(),
                            )
                            .instrument(span),
                        );
                    }
                    BaseInboundTransport::Datagram(socket, sess) => {
                        crate::runtime::scope::spawn(
                            "inbound datagram",
                            handle_inbound_datagram(
                                handler.tag().clone(),
                                socket,
                                sess,
                                nat_manager.clone(),
                                TaskClass::Contained,
                            ),
                        );
                    }
                    _ => (),
                }
            }
        }
        _ => (),
    }
}

/// Serves one session a host submitted with no listener of its own
/// (`embed::Instance::sessions`), as a session of a connection that carries
/// many is served: a stream routed and relayed, datagrams through the NAT.
pub(crate) async fn serve_submitted(
    transport: AnyBaseInboundTransport,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) {
    match transport {
        BaseInboundTransport::Stream(stream, sess) => {
            let span = sess.span();
            let tag = sess.inbound_tag.clone();
            super::magic::serve_stream(sess, stream, tag, dispatcher, nat_manager)
                .instrument(span)
                .await;
        }
        BaseInboundTransport::Datagram(socket, sess) => {
            let tag = sess
                .as_ref()
                .map(|sess| sess.inbound_tag.clone())
                .unwrap_or_default();
            handle_inbound_datagram(tag, socket, sess, nat_manager, TaskClass::Contained).await;
        }
        _ => (),
    }
}

// Handle an accepted inbound TCP stream, which holds `place` among its
// inbound's handshakes until it is a session or is closed.
async fn handle_inbound_tcp_stream(
    stream: TcpStream,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    mut place: super::HandshakePlace,
) -> io::Result<()> {
    // A connection without addresses has already gone away.
    let source = stream.peer_addr()?;
    let local_addr = stream.local_addr()?;
    let mut sess = Session {
        network: Network::Tcp,
        source,
        local_addr,
        inbound_tag: handler.tag().clone(),
        ..Default::default()
    };
    handler.accepted(socket2::SockRef::from(&stream), &mut sess)?;
    let span = sess.span();
    {
        let _g = span.enter();
        debug!(
            "handle inbound tcp stream src={} local={}",
            &source, &local_addr
        );
    }
    async move {
        // Its send buffer grows out of the transfer budget while it is
        // what holds the client back.
        let (base, max) = {
            let options = &dispatcher.env().options.inbound;
            (options.tcp_send_buffer, options.tcp_send_buffer_max)
        };
        let stream = crate::net::send_buffer::Growing::new(stream, base * 1024, max * 1024);
        // Transforms the TCP stream into an inbound transport.
        let mut transport = timeout(
            dispatcher.env().options.inbound.handshake_timeout,
            handler.stream()?.handle(sess, Box::new(stream)),
        )
        .instrument(tracing::Span::current())
        .await??;
        // It authenticated: admission under memory pressure leaves it be.
        place.succeeded();
        // A stream to be routed keeps its place until the dispatcher has
        // given it one among the sessions. Anything else, a UDP
        // association or a connection that carries many, is past its
        // handshake: the place is given back here, and what it carries
        // takes places among the sessions, each its own. The protocol's
        // handler never held it, so none can keep it.
        match &mut transport {
            InboundTransport::Stream(_, sess) => sess.handshake = Some(place),
            _ => drop(place),
        }
        handle_inbound_transport(
            transport,
            handler,
            dispatcher,
            nat_manager,
            TaskClass::Contained,
        )
        .instrument(tracing::Span::current())
        .await;
        Ok(())
    }
    .instrument(span)
    .await
}

// Handle inbounds which listen on TCP.
async fn handle_tcp_listen(
    listener: crate::net::TcpListener,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
    removed_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    let listen_addr = listener.io().local_addr()?;
    info!("listening tcp {}", &listen_addr);

    #[cfg(feature = "inbound-nf")]
    {
        TCP_LISTENING_ADDRESSES
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(handler.tag().clone(), listen_addr);
    }

    // Out of descriptors, say, is waited out: the listener outlives it.
    let mut backoff = AcceptBackoff::new(format!(
        "[{}] inbound: accept tcp {}",
        handler.tag(),
        listen_addr
    ));
    let handshakes =
        super::handshakes::Handshakes::new(handler.tag(), &dispatcher.env().options.inbound);
    let tag: Arc<str> = handler.tag().as_str().into();
    loop {
        let (stream, source) = match listener.accept().await {
            Ok(accepted) => {
                backoff.succeeded();
                accepted
            }
            Err(e) => {
                backoff.failed(e).await?;
                continue;
            }
        };
        // Under memory pressure, what has not authenticated is held back
        // (admission.rs): the stalled handshakes are closed, and this one
        // may be refused.
        let admission = dispatcher.admission();
        if let Some(admission) = admission {
            if admission.check(source.ip()).is_err() {
                continue;
            }
        }
        // One more than the inbound may have in their handshake is closed
        // at once: kept waiting, it would take what the limit spares.
        let Some(mut place) = handshakes.enter(source.ip()) else {
            // Its stalled handshakes make room for the next ones.
            if let Some(admission) = admission {
                admission.full(&tag);
            }
            continue;
        };
        if let Some(admission) = admission {
            place.admitted(admission.enter(source.ip(), &tag));
        }
        let eviction = place.eviction();
        // The host's check of it runs in its own task: a slow one holds
        // back this connection alone.
        let host_check = admission.filter(|a| a.checks_sources()).cloned();
        let handler_cloned = handler.clone();
        let dispatcher_cloned = dispatcher.clone();
        let nat_manager_cloned = nat_manager.clone();
        let removed = until_removed(removed_rx.clone());
        crate::runtime::scope::spawn("inbound tcp", async move {
            #[cfg(feature = "fault-injection")]
            fault_point!(crate::fault::Point::ContainedTask, "a connection's task");
            if let Some(admission) = host_check {
                let local = stream.local_addr().unwrap_or(listen_addr);
                if !admission.host_admits_source(source, local) {
                    debug!("connection from {} refused by the host", source);
                    return;
                }
            }
            // Handle each TCP stream, for as long as its inbound is there.
            tokio::select! {
                result = handle_inbound_tcp_stream(
                    stream,
                    handler_cloned,
                    dispatcher_cloned,
                    nat_manager_cloned,
                    place,
                ) => {
                    if let Err(e) = result {
                        debug!("handle inbound stream failed: {}", e);
                    }
                }
                _ = removed => {}
                // Stalled in its handshake under memory pressure.
                _ = async {
                    match eviction {
                        Some(eviction) => eviction.evicted().await,
                        None => std::future::pending().await,
                    }
                } => {
                    debug!("connection from {} closed in its handshake: stalled under memory pressure", source);
                }
            }
        });
    }
}

// Handle inbounds which bind on UDP.
async fn handle_udp_listen(
    socket: UdpSocket,
    handler: AnyInboundHandler,
    dispatcher: Arc<Dispatcher>,
    nat_manager: Arc<NatManager>,
) -> io::Result<()> {
    let listen_addr = socket.local_addr()?;
    info!("listening udp {}", &listen_addr);

    #[cfg(feature = "inbound-nf")]
    {
        UDP_LISTENING_ADDRESSES
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(handler.tag().clone(), listen_addr);
    }

    // Transforms the UDP socket into an inbound transport.
    let transport = handler
        .datagram()?
        .handle(Box::new(SimpleInboundDatagram(socket)))
        .await?;
    // The inbound's own socket: what carries its UDP lives as long as it.
    handle_inbound_transport(
        transport,
        handler,
        dispatcher,
        nat_manager,
        TaskClass::Essential,
    )
    .await;
    Ok(())
}

pub struct NetworkInboundListener {
    pub address: SocketAddr,
    /// Of the TCP connections it accepts.
    pub keepalive: Option<crate::net::TcpKeepAlive>,
    /// TCP Fast Open on its TCP port.
    pub fast_open: bool,
    /// Whether what its UDP port sends may be fragmented.
    pub udp_fragment: bool,
    pub handler: AnyInboundHandler,
    pub dispatcher: Arc<Dispatcher>,
    pub nat_manager: Arc<NatManager>,
    /// Set once the inbound is removed: the TCP connections it accepted
    /// end with it, those still in their handshake and those that carry
    /// streams among them, which are not yet, or never, among the
    /// connections the runtime lists. Stopping the listener alone leaves
    /// them going on.
    pub removed: Arc<watch::Sender<bool>>,
}

/// The TCP connections a removed inbound accepted, which go on until they
/// are disconnected.
pub struct Accepted(Option<Arc<watch::Sender<bool>>>);

impl Accepted {
    pub(super) fn of(listener: Option<&NetworkInboundListener>) -> Self {
        Accepted(listener.map(|l| l.removed.clone()))
    }

    /// Ends them: those in their handshake and those that carry streams
    /// too, which are not among the connections the runtime lists.
    pub fn disconnect(self) {
        if let Some(removed) = self.0 {
            removed.send_replace(true);
        }
    }
}

/// Ends once the inbound is removed, and not when its listener only goes.
async fn until_removed(mut removed: watch::Receiver<bool>) {
    let gone = removed.wait_for(|removed| *removed).await.is_err();
    if gone {
        std::future::pending::<()>().await;
    }
}

/// The UDP socket an inbound listens on at `addr`, its datagrams carrying
/// don't-fragment unless `fragment`.
fn udp_listen_socket(addr: &SocketAddr, fragment: bool) -> io::Result<std::net::UdpSocket> {
    let socket = crate::net::bind_udp(addr)?;
    socket.set_nonblocking(true)?;
    crate::net::fit_largest_datagram(socket2::SockRef::from(&socket))?;
    if !fragment {
        crate::net::dial::sockopt::dont_fragment(socket2::SockRef::from(&socket), addr.is_ipv6())?;
    }
    Ok(socket)
}

impl NetworkInboundListener {
    pub fn new(
        address: SocketAddr,
        keepalive: Option<crate::net::TcpKeepAlive>,
        handler: AnyInboundHandler,
        dispatcher: Arc<Dispatcher>,
        nat_manager: Arc<NatManager>,
    ) -> Self {
        NetworkInboundListener {
            address,
            keepalive,
            fast_open: false,
            udp_fragment: true,
            handler,
            dispatcher,
            nat_manager,
            removed: Arc::new(watch::channel(false).0),
        }
    }

    /// Binds every socket the inbound listens on, failing if any cannot be
    /// bound, and returns the tasks that serve them. Must be called from
    /// within a Tokio runtime.
    pub fn listen(&self) -> Result<Vec<Runner>> {
        let tag = self.handler.tag();
        let listen_addr = self.address;
        let bind_failed = |network: &str, e: io::Error| {
            anyhow!(
                "[{}] inbound: listen {} {}: {}",
                tag,
                network,
                listen_addr,
                e
            )
        };
        let mut runners: Vec<Runner> = Vec::new();
        if self.handler.stream().is_ok() {
            let listener = crate::net::TcpListener::bind_with(&listen_addr, self.fast_open)
                .map_err(|e| bind_failed("tcp", e))?
                .abort_on_close(self.dispatcher.env().options.inbound.tcp_abort_on_close)
                .send_buffer(self.dispatcher.env().options.inbound.tcp_send_buffer * 1024)
                .receive_buffer(self.dispatcher.env().options.inbound.tcp_receive_buffer * 1024)
                .congestion(&crate::net::congestion::Congestion::new(
                    &self.dispatcher.env().options.relay.tcp_congestion,
                ))
                .keepalive(self.keepalive);
            crate::net::mark_listener(socket2::SockRef::from(listener.io()), self.dispatcher.env())
                .map_err(|e| bind_failed("tcp", e))?;
            self.handler
                .prepare_listener(socket2::SockRef::from(listener.io()), Network::Tcp)
                .map_err(|e| bind_failed("tcp", e))?;
            let handler = self.handler.clone();
            let dispatcher = self.dispatcher.clone();
            let nat_manager = self.nat_manager.clone();
            let removed = self.removed.subscribe();
            runners.push(Box::pin(async move {
                if let Err(e) =
                    handle_tcp_listen(listener, handler, dispatcher, nat_manager, removed).await
                {
                    warn!("handler tcp listen failed: {}", e);
                }
            }));
        }
        if self.handler.datagram().is_ok() {
            let socket = udp_listen_socket(&listen_addr, self.udp_fragment)
                .and_then(|socket| {
                    crate::net::mark_listener(
                        socket2::SockRef::from(&socket),
                        self.dispatcher.env(),
                    )?;
                    UdpSocket::from_std(socket)
                })
                .map_err(|e| bind_failed("udp", e))?;
            self.handler
                .prepare_listener(socket2::SockRef::from(&socket), Network::Udp)
                .map_err(|e| bind_failed("udp", e))?;
            let handler = self.handler.clone();
            let dispatcher = self.dispatcher.clone();
            let nat_manager = self.nat_manager.clone();
            runners.push(Box::pin(async move {
                if let Err(e) = handle_udp_listen(socket, handler, dispatcher, nat_manager).await {
                    warn!("handler udp listen failed: {}", e);
                }
            }));
        }
        Ok(runners)
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    /// Whether "don't fragment" is set on `socket`, of IPv4.
    fn dont_fragment_set(socket: &std::net::UdpSocket) -> bool {
        let socket = socket2::SockRef::from(socket);
        #[cfg(target_os = "linux")]
        return crate::net::dial::sockopt::get_int(
            &socket,
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
        )
        .unwrap()
            == libc::IP_PMTUDISC_DO;
        #[cfg(target_os = "macos")]
        return crate::net::dial::sockopt::get_int(&socket, libc::IPPROTO_IP, libc::IP_DONTFRAG)
            .unwrap()
            != 0;
    }

    /// An inbound's UDP listen socket carries don't-fragment unless its
    /// `udp_fragment` lets its datagrams be fragmented.
    #[test]
    fn a_udp_listen_socket_is_not_fragmented_unless_its_inbound_says() {
        let addr = "127.0.0.1:0".parse().unwrap();
        assert!(dont_fragment_set(&udp_listen_socket(&addr, false).unwrap()));
        assert!(!dont_fragment_set(&udp_listen_socket(&addr, true).unwrap()));
    }
}
