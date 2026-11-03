//! The client: mux connections made by an outbound, and the streams handed
//! out over them.
//!
//! A mux connection is a connection of the outbound's whole stack -- its
//! protocol over its transport and TLS, through its detour -- to the magic
//! destination, which is why the outbound hands it over as a `Connector`
//! around the stack instead of being one more layer in it.
//!
//! Streams go to the connection with the fewest, as in sing-mux, and a new
//! connection is made when those are too busy: with `max_connections`,
//! while there are fewer than that many and the least busy carries at
//! least `min_streams`; with `max_streams`, when every connection carries
//! that many. Hard limits stand behind both: `MAX_CONNECTIONS` connections,
//! `muxcore::MAX_STREAMS` streams on one.
//!
//! With `brutal`, as in sing-mux, there is one connection for all streams,
//! and TCP Brutal is negotiated on it before it takes any (`brutal`).
//!
//! A stream holds its connection. A client that goes away, as an outbound
//! a reload or a provider's refresh removes does, closes the connections
//! without streams and makes no more; those with streams end when their
//! last stream does. So does a smux or h2mux connection retired because
//! one of its streams ended before the server finished it: it takes no new
//! streams, whose data would wait behind what that stream was still sent.
//! yamux resets such a stream, alone, and the connection goes on.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex as SyncMutex, Weak};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use futures::future::{abortable, AbortHandle, BoxFuture};
use futures::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, Instrument};

use crate::adapter::*;
use crate::net::dial::BoundInterface;
use crate::session::{Network, Session, SocksAddr};
use crate::transport::layers::Connector;
use crate::transport::muxcore::{self, Session as FrameSession, Tuning};

use super::brutal::{self, Brutal};
use super::h2mux::H2Client;
use super::packet::ClientDatagram;
use super::padding::PaddingStream;
use super::{
    encode_request, read_status, Protocol, StreamRequest, MAGIC_DOMAIN, MAGIC_PORT, STATUS_SUCCESS,
};

/// Connections one outbound keeps at most.
pub const MAX_CONNECTIONS: usize = 32;
/// How long making a mux connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the TCP Brutal exchange waits for the server to end its
/// stream: a judgment call, the end coming with the answer.
const EXCHANGE_END: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOptions {
    pub protocol: Protocol,
    pub padding: bool,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub brutal: Option<Brutal>,
}

impl ClientOptions {
    /// Checks the limits as sing-box does: `max_streams` excludes the
    /// other two. With none set, up to 4 connections, a new one while the
    /// least busy carries 4 streams or more. `max_connections` alone, as
    /// in sing-mux, means no `min_streams`: a busy connection takes no
    /// stream while there are fewer than that many.
    pub fn new(
        protocol: Protocol,
        padding: bool,
        max_connections: Option<usize>,
        min_streams: Option<usize>,
        max_streams: Option<usize>,
        brutal: Option<Brutal>,
    ) -> Result<Self, String> {
        let max_streams = max_streams.filter(|n| *n > 0);
        let max_connections = max_connections.filter(|n| *n > 0);
        let min_streams = min_streams.filter(|n| *n > 0);
        if max_streams.is_some() && (max_connections.is_some() || min_streams.is_some()) {
            return Err(
                "max_streams cannot be set with max_connections or min_streams".to_string(),
            );
        }
        if max_connections.is_some_and(|n| n > MAX_CONNECTIONS) {
            return Err(format!("max_connections cannot exceed {}", MAX_CONNECTIONS));
        }
        if max_streams.is_some_and(|n| n > muxcore::MAX_STREAMS) {
            return Err(format!(
                "max_streams cannot exceed {}",
                muxcore::MAX_STREAMS
            ));
        }
        let (max_connections, min_streams) = match max_streams {
            Some(_) => (0, 0),
            None => match max_connections {
                Some(n) => (n, min_streams.unwrap_or(0)),
                None => (4, min_streams.unwrap_or(4)),
            },
        };
        Ok(ClientOptions {
            protocol,
            padding,
            max_connections,
            min_streams,
            max_streams: max_streams.unwrap_or(0),
            brutal,
        })
    }
}

/// One mux connection.
enum Conn {
    Frames(FrameSession),
    H2(H2Client),
}

impl Conn {
    /// A new stream, which holds the connection.
    async fn open(self: &Arc<Self>) -> io::Result<AnyStream> {
        let stream: AnyStream = match &**self {
            Conn::Frames(session) => Box::new(session.open().await?),
            Conn::H2(client) => Box::new(client.open().await?),
        };
        Ok(Box::new(Held {
            stream,
            _conn: self.clone(),
        }))
    }

    fn num_streams(&self) -> usize {
        match self {
            Conn::Frames(session) => session.num_streams(),
            Conn::H2(client) => client.num_streams(),
        }
    }

    fn is_closed(&self) -> bool {
        match self {
            Conn::Frames(session) => session.is_closed(),
            Conn::H2(client) => client.is_closed(),
        }
    }

    /// Whether a new stream may go on the connection: not closed, nor
    /// retired.
    fn is_reusable(&self) -> bool {
        match self {
            Conn::Frames(session) => session.is_reusable(),
            Conn::H2(client) => client.is_reusable(),
        }
    }

    fn can_take_new_request(&self) -> bool {
        match self {
            Conn::Frames(session) => session.num_streams() < muxcore::MAX_STREAMS,
            Conn::H2(client) => client.can_take_new_request(),
        }
    }

    fn close(&self) {
        match self {
            Conn::Frames(session) => session.close(),
            Conn::H2(client) => client.close(),
        }
    }
}

struct Entry {
    conn: Arc<Conn>,
    /// What its dial recorded, which the streams on it after the first
    /// are given: they go out where it does.
    bound: Arc<BoundInterface>,
    /// Since when it has carried no streams, as last checked.
    idle_since: Option<Instant>,
}

impl Entry {
    /// The connection, for a stream that did not make it.
    fn offered(&self) -> (Arc<Conn>, Option<Arc<BoundInterface>>) {
        (self.conn.clone(), Some(self.bound.clone()))
    }
}

pub struct Client {
    connector: Connector,
    options: ClientOptions,
    tuning: Tuning,
    /// Who the connections serve, in their logs.
    label: String,
    /// Held while a connection is made, so that streams asking at once
    /// share it rather than each making their own, as in sing-mux.
    conns: tokio::sync::Mutex<Vec<Entry>>,
    /// The idle check, until the first connection starts it: outbounds are
    /// built outside a runtime.
    cleanup: SyncMutex<Option<BoxFuture<'static, ()>>>,
}

impl Client {
    /// The client, and the handle that stops its idle check.
    pub fn new(
        connector: Connector,
        options: ClientOptions,
        tuning: Tuning,
        label: String,
    ) -> (Arc<Client>, AbortHandle) {
        let client = Arc::new(Client {
            connector,
            options,
            tuning,
            label,
            conns: tokio::sync::Mutex::new(Vec::new()),
            cleanup: SyncMutex::new(None),
        });
        let weak: Weak<Client> = Arc::downgrade(&client);
        // How long a connection without streams is kept, looked for twice
        // as often.
        let every = tuning.idle_timeout / 2;
        let (check, handle) = abortable(async move {
            loop {
                tokio::time::sleep(every).await;
                let Some(client) = weak.upgrade() else {
                    return;
                };
                client.check_idle();
            }
        });
        if let Ok(mut cleanup) = client.cleanup.lock() {
            *cleanup = Some(check.map(|_| ()).boxed());
        }
        (client, handle)
    }

    fn check_idle(&self) {
        // Not while a connection is being made; the next check will do.
        let Ok(mut conns) = self.conns.try_lock() else {
            return;
        };
        let now = Instant::now();
        conns.retain_mut(|entry| {
            if !entry.conn.is_reusable() {
                return false;
            }
            if entry.conn.num_streams() > 0 {
                entry.idle_since = None;
                return true;
            }
            match entry.idle_since {
                None => {
                    entry.idle_since = Some(now);
                    true
                }
                Some(since) if now.duration_since(since) >= self.tuning.idle_timeout => {
                    entry.conn.close();
                    false
                }
                Some(_) => true,
            }
        });
    }

    /// Closes the connections without streams, at once.
    fn close_idle(self: &Arc<Self>) {
        fn close(conns: &mut Vec<Entry>) {
            conns.retain(|entry| {
                if entry.conn.num_streams() > 0 {
                    return true;
                }
                entry.conn.close();
                false
            });
        }
        match self.conns.try_lock() {
            Ok(mut conns) => close(&mut conns),
            // A connection is being made: once it is.
            Err(_) => {
                if tokio::runtime::Handle::try_current().is_ok() {
                    let client = self.clone();
                    crate::runtime::scope::spawn("mux close idle", async move {
                        close(&mut *client.conns.lock().await)
                    });
                }
            }
        }
    }

    /// Closes every connection, and the streams on them, as sing-mux's
    /// `Reset` does when the network changes: they were made on a network
    /// that may be gone. The next stream makes a new one.
    fn reset(self: &Arc<Self>) {
        fn close(conns: &mut Vec<Entry>) {
            for entry in conns.drain(..) {
                entry.conn.close();
            }
        }
        match self.conns.try_lock() {
            Ok(mut conns) => close(&mut conns),
            // A connection is being made: once it is, it goes too.
            Err(_) => {
                if tokio::runtime::Handle::try_current().is_ok() {
                    let client = self.clone();
                    crate::runtime::scope::spawn("mux reset", async move {
                        close(&mut *client.conns.lock().await)
                    });
                }
            }
        }
    }

    /// A new stream, before its request.
    async fn open_stream(&self, sess: &Session) -> io::Result<AnyStream> {
        if let Some(check) = self.cleanup.lock().ok().and_then(|mut c| c.take()) {
            crate::runtime::scope::spawn_essential("mux idle check", check);
        }
        let mut last = io::Error::other("mux: no connection");
        for _ in 0..2 {
            let (conn, bound) = match self.offer(sess).await {
                Ok(offered) => offered,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            match conn.open().await {
                Ok(stream) => {
                    if let Some(bound) = bound {
                        bound.onto(sess);
                    }
                    return Ok(stream);
                }
                Err(e) => {
                    debug!("mux open stream: {}", e);
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// The connection a new stream goes on, made if need be, and what its
    /// dial recorded, unless `sess` made it: it holds that already.
    async fn offer(&self, sess: &Session) -> io::Result<(Arc<Conn>, Option<Arc<BoundInterface>>)> {
        let mut conns = self.conns.lock().await;
        conns.retain(|entry| {
            if entry.conn.is_closed() {
                entry.conn.close();
                return false;
            }
            // Retired: its streams hold it, and it ends with the last.
            entry.conn.is_reusable()
        });
        if self.options.brutal.is_some() {
            if let Some(entry) = conns.first() {
                return Ok(entry.offered());
            }
        }
        let least = conns
            .iter()
            .filter(|e| e.conn.can_take_new_request())
            .min_by_key(|e| e.conn.num_streams());
        if let Some(entry) = least {
            if reuse(&self.options, entry.conn.num_streams(), conns.len()) {
                return Ok(entry.offered());
            }
        }
        if conns.len() >= MAX_CONNECTIONS {
            return least
                .map(Entry::offered)
                .ok_or_else(|| io::Error::other("mux: every connection is full"));
        }
        let (conn, bound) = tokio::time::timeout(CONNECT_TIMEOUT, self.connect(sess))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mux: connect timed out"))??;
        conns.push(Entry {
            conn: conn.clone(),
            bound: Arc::new(bound),
            idle_since: None,
        });
        Ok((conn, None))
    }

    /// A new connection, dialled in a copy of `sess`, and what the dial
    /// recorded on it.
    async fn connect(&self, sess: &Session) -> io::Result<(Arc<Conn>, BoundInterface)> {
        let mut sess = sess.clone();
        sess.network = Network::Tcp;
        sess.destination = SocksAddr::Domain(MAGIC_DOMAIN.to_string(), MAGIC_PORT);
        sess.forget_sniffed();
        let (mut conn, socket) = match self.options.brutal {
            Some(_) => {
                self.connector
                    .connect_on_socket(&sess)
                    .instrument(tracing::Span::current())
                    .await?
            }
            None => (
                self.connector
                    .connect(&sess)
                    .instrument(tracing::Span::current())
                    .await?,
                None,
            ),
        };
        conn.write_all(&encode_request(self.options.protocol, self.options.padding))
            .await?;
        let conn: AnyStream = if self.options.padding {
            Box::new(PaddingStream::new(conn))
        } else {
            conn
        };
        debug!("mux connection ({:?})", self.options.protocol);
        let conn = match self.options.protocol.codec() {
            Some(codec) => Conn::Frames(
                FrameSession::new(conn, codec, false, self.tuning, self.label.as_str()).0,
            ),
            None => Conn::H2(H2Client::new(conn, self.tuning, &self.label).await?),
        };
        let conn = Arc::new(conn);
        if let Some(brutal) = &self.options.brutal {
            if let Err(e) = brutal_exchange(&conn, brutal, socket.as_ref()).await {
                conn.close();
                return Err(io::Error::new(
                    e.kind(),
                    format!("mux: brutal exchange: {}", e),
                ));
            }
        }
        Ok((conn, BoundInterface::of(&sess)))
    }

    /// Opens a stream and sends `request` on it.
    async fn request(&self, sess: &Session, request: StreamRequest) -> io::Result<AnyStream> {
        let mut stream = self.open_stream(sess).await?;
        let mut buf = BytesMut::new();
        request.encode(&mut buf);
        stream.write_all(&buf).await?;
        Ok(stream)
    }
}

/// Negotiates TCP Brutal on a new connection, whose TCP connection is
/// `socket` if it is known, and sends over it at the rate agreed. Only the
/// server's refusal fails it: as in sing-mux, a client that cannot set the
/// rate goes on without.
async fn brutal_exchange(
    conn: &Arc<Conn>,
    brutal: &Brutal,
    socket: Option<&brutal::Socket>,
) -> io::Result<()> {
    let mut stream = conn.open().await?;
    let mut buf = BytesMut::new();
    StreamRequest::Tcp(brutal::exchange_destination()).encode(&mut buf);
    brutal::encode_request(brutal.receive_bps, &mut buf);
    stream.write_all(&buf).await?;
    read_status(&mut stream).await?;
    let server_receive_bps = brutal::read_response(&mut stream).await?;
    // The server ends the stream after its answer: dropped before that,
    // it would retire the connection. One that never ends it only does.
    let _ = tokio::time::timeout(EXCHANGE_END, stream.read_to_end(&mut Vec::new())).await;
    let send_bps = brutal.send_bps.min(server_receive_bps);
    match brutal::set(socket, send_bps) {
        Ok(()) => debug!("mux: TCP Brutal, sending at {} B/s", send_bps),
        Err(e) => debug!("mux: failed to enable TCP Brutal at client: {}", e),
    }
    Ok(())
}

/// Whether a stream goes on the least busy connection, which carries
/// `streams`, rather than a new one, with `conns` connections open.
fn reuse(o: &ClientOptions, streams: usize, conns: usize) -> bool {
    if streams == 0 {
        return true;
    }
    if o.max_connections > 0 {
        conns >= o.max_connections || streams < o.min_streams
    } else {
        o.max_streams > 0 && streams < o.max_streams
    }
}

/// A stream, and the connection it holds.
struct Held {
    stream: AnyStream,
    _conn: Arc<Conn>,
}

impl AsyncRead for Held {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Held {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// TCP through the mux.
pub struct StreamHandler {
    pub client: Arc<Client>,
}

#[async_trait]
impl OutboundStreamHandler for StreamHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    /// Its connections close, and the outbound beneath hears of it. The
    /// datagram handler shares the client, and leaves it to this one.
    fn network_changed(&self, change: &crate::net::network::NetworkChange) {
        self.client.reset();
        self.client.connector.network_changed(change);
    }

    /// As `network_changed`.
    fn close_idle(&self) {
        self.client.close_idle();
        self.client.connector.close_idle();
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let stream = self
            .client
            .request(sess, StreamRequest::Tcp(sess.destination.clone()))
            .await?;
        Ok(Box::new(ClientStream {
            inner: stream,
            status: [0],
            status_read: false,
        }))
    }
}

/// UDP through the mux, every packet with its address.
pub struct DatagramHandler {
    pub client: Arc<Client>,
}

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Reliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let stream = self
            .client
            .request(sess, StreamRequest::UdpAddr(sess.destination.clone()))
            .await?;
        Ok(Box::new(ClientDatagram { stream }))
    }
}

/// A TCP stream on the client, which reads the server's status before its
/// first data.
struct ClientStream {
    inner: AnyStream,
    status: [u8; 1],
    status_read: bool,
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.status_read {
            let mut status = ReadBuf::new(&mut me.status);
            ready!(Pin::new(&mut me.inner).poll_read(cx, &mut status))?;
            if status.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mux: stream closed before its status",
                )));
            }
            if me.status[0] != STATUS_SUCCESS {
                return Poll::Ready(Err(io::Error::other("mux: remote error")));
            }
            me.status_read = true;
        }
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// `layered`, the outbound's whole stack, with its TCP and UDP carried
/// over mux connections it makes.
pub fn outbound(
    tag: &str,
    layered: AnyOutboundHandler,
    dns_client: crate::app::SyncDnsClient,
    options: ClientOptions,
    tuning: Tuning,
    abort_handles: &mut Vec<AbortHandle>,
) -> AnyOutboundHandler {
    let (client, cleanup) = Client::new(
        Connector::around(layered, dns_client),
        options,
        tuning,
        format!("outbound={}", tag),
    );
    abort_handles.push(cleanup);
    crate::adapter::outbound::HandlerBuilder::default()
        .tag(tag.to_owned())
        .stream_handler(Arc::new(StreamHandler {
            client: client.clone(),
        }))
        .datagram_handler(Arc::new(DatagramHandler { client }))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(
        max_connections: Option<usize>,
        min_streams: Option<usize>,
        max_streams: Option<usize>,
    ) -> Result<ClientOptions, String> {
        ClientOptions::new(
            Protocol::Smux,
            false,
            max_connections,
            min_streams,
            max_streams,
            None,
        )
    }

    #[test]
    fn limits_are_checked_as_sing_box_does() {
        let o = options(None, None, None).unwrap();
        assert_eq!((o.max_connections, o.min_streams, o.max_streams), (4, 4, 0));
        let o = options(Some(4), None, None).unwrap();
        assert_eq!((o.max_connections, o.min_streams, o.max_streams), (4, 0, 0));
        let o = options(Some(4), Some(2), None).unwrap();
        assert_eq!((o.max_connections, o.min_streams, o.max_streams), (4, 2, 0));
        let o = options(None, None, Some(8)).unwrap();
        assert_eq!((o.max_connections, o.min_streams, o.max_streams), (0, 0, 8));
        assert!(options(Some(2), None, Some(8)).is_err());
        assert!(options(None, Some(2), Some(8)).is_err());
        assert!(options(Some(MAX_CONNECTIONS + 1), None, None).is_err());
        assert!(options(None, None, Some(100_000)).is_err());
    }

    /// Hands over a TCP connection to `port`.
    struct Direct(u16);

    #[async_trait]
    impl OutboundStreamHandler for Direct {
        fn connect_addr(&self) -> OutboundConnect {
            OutboundConnect::Proxy(
                Network::Tcp,
                "127.0.0.1".to_string(),
                self.0,
                crate::net::Dialer::system(),
            )
        }

        async fn handle<'a>(
            &'a self,
            _sess: &'a Session,
            _lhs: Option<&mut AnyStream>,
            stream: Option<AnyStream>,
        ) -> io::Result<AnyStream> {
            stream.ok_or_else(|| io::Error::other("nothing dialled"))
        }
    }

    /// A change of network closes the connections, as sing-mux's `Reset`:
    /// the next stream makes a new one, where it would share the first.
    #[tokio::test]
    async fn a_change_of_network_closes_the_connections() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = accepted.clone();
        // Takes the connections and what they send; answers nothing.
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut tcp, &mut tokio::io::sink()).await;
                });
            }
        });
        let dns = crate::app::dns::DnsClient::new(
            &Default::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let whole = crate::adapter::outbound::HandlerBuilder::default()
            .tag("test".to_owned())
            .stream_handler(Arc::new(Direct(port)))
            .build();
        let mux = outbound(
            "test",
            whole,
            dns,
            options(None, None, None).unwrap(),
            Tuning::default(),
            &mut Vec::new(),
        );
        let sess = Session {
            destination: SocksAddr::try_from(("example.com", 443)).unwrap(),
            ..Default::default()
        };
        let stream = mux.stream().unwrap();
        // The server counts a connection once it gets round to it.
        let counted = |n: usize| {
            let accepted = accepted.clone();
            async move {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while accepted.load(Ordering::SeqCst) < n {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .is_ok()
            }
        };
        let _first = stream.handle(&sess, None, None).await.unwrap();
        let _second = stream.handle(&sess, None, None).await.unwrap();
        assert!(counted(1).await);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        mux.network_changed(&crate::net::network::NetworkChange {
            generation: 1,
            reason: crate::net::network::ChangeReason::HostPush,
            old: Default::default(),
            new: Default::default(),
        });
        let _third = stream.handle(&sess, None, None).await.unwrap();
        assert!(counted(2).await, "no new connection after the change");
    }

    /// A mux server on a new port whose TCP streams echo: its port, how
    /// many of its connections have ended, and how many it took.
    async fn echo_server() -> (
        u16,
        Arc<std::sync::atomic::AtomicUsize>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ended = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = ended.clone();
        let taken = accepted.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                taken.fetch_add(1, Ordering::SeqCst);
                let counted = counted.clone();
                tokio::spawn(async move {
                    if let Ok(mut server) = super::super::server::Server::start(
                        Box::new(tcp),
                        Tuning::default(),
                        "test",
                    )
                    .await
                    {
                        while let Some(stream) = server.accept().await {
                            tokio::spawn(async move {
                                let Ok((_, stream)) =
                                    super::super::server::read_stream(stream).await
                                else {
                                    return;
                                };
                                let (mut r, mut w) = tokio::io::split(stream);
                                let _ = tokio::io::copy(&mut r, &mut w).await;
                                let _ = w.shutdown().await;
                            });
                        }
                    }
                    counted.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        (port, ended, accepted)
    }

    /// A mux outbound of `protocol` to the server on `port`.
    fn mux_to(port: u16, protocol: Protocol) -> AnyOutboundHandler {
        mux_over(Arc::new(Direct(port)), protocol)
    }

    /// A mux outbound of `protocol` whose connections `dial` hands over.
    fn mux_over(dial: Arc<dyn OutboundStreamHandler>, protocol: Protocol) -> AnyOutboundHandler {
        let dns = crate::app::dns::DnsClient::new(
            &Default::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let whole = crate::adapter::outbound::HandlerBuilder::default()
            .tag("test".to_owned())
            .stream_handler(dial)
            .build();
        outbound(
            "test",
            whole,
            dns,
            ClientOptions::new(protocol, false, None, None, None, None).unwrap(),
            Tuning::default(),
            &mut Vec::new(),
        )
    }

    fn echo_session() -> Session {
        Session {
            destination: SocksAddr::try_from(("example.com", 443)).unwrap(),
            ..Default::default()
        }
    }

    /// Whether `n` connections have ended by `within`.
    async fn ended_by(ended: &std::sync::atomic::AtomicUsize, n: usize, within: Duration) -> bool {
        use std::sync::atomic::Ordering;
        tokio::time::timeout(within, async {
            while ended.load(Ordering::SeqCst) < n {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
    }

    async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, what: &[u8]) {
        s.write_all(what).await.unwrap();
        let mut back = vec![0u8; what.len()];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(back, what);
    }

    /// A client a reload replaced: a connection relayed over its stream goes
    /// on, and once the user ends it, the relay ends and so does the
    /// session, long before any idle timeout. smux cannot half-close: its
    /// stream ends when shut down, or the relay waits on a server that
    /// never hears the user is done, and holds the session.
    async fn replaced_client_closes_with_its_last_stream(protocol: Protocol) {
        use std::sync::atomic::Ordering;
        let (port, ended, _) = echo_server().await;
        let mux = mux_to(port, protocol);
        let mut rhs = mux
            .stream()
            .unwrap()
            .handle(&echo_session(), None, None)
            .await
            .unwrap();
        let (mut user, mut lhs) = tokio::io::duplex(4096);
        let relay = tokio::spawn(async move {
            let relay = crate::runtime::options::Relay::default();
            let _ = crate::net::relay::copy_buf_bidirectional_with_timeout(
                &mut lhs,
                &mut rhs,
                1024,
                1024,
                crate::net::relay::RelayTimeouts {
                    write_stall: relay.write_stall_timeout,
                    a_to_b_idle: relay.uplink_idle_timeout,
                    b_to_a_idle: relay.downlink_idle_timeout,
                },
            )
            .await;
        });
        round_trip(&mut user, b"before").await;
        // The reload drops the outbound, and with it the client.
        drop(mux);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(ended.load(Ordering::SeqCst), 0, "cut with its stream open");
        round_trip(&mut user, b"after").await;
        drop(user);
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("the relay outlived its user")
            .unwrap();
        assert!(
            ended_by(&ended, 1, Duration::from_secs(5)).await,
            "the session outlived its last stream"
        );
    }

    #[tokio::test]
    async fn a_replaced_smux_client_closes_with_its_last_stream() {
        replaced_client_closes_with_its_last_stream(Protocol::Smux).await;
    }

    #[tokio::test]
    async fn a_replaced_h2mux_client_closes_with_its_last_stream() {
        replaced_client_closes_with_its_last_stream(Protocol::H2Mux).await;
    }

    /// A client that goes away closes its sessions without streams at once.
    async fn a_client_gone_closes_its_idle_sessions(protocol: Protocol) {
        use std::sync::atomic::Ordering;
        let (port, ended, _) = echo_server().await;
        let mux = mux_to(port, protocol);
        let mut stream = mux
            .stream()
            .unwrap()
            .handle(&echo_session(), None, None)
            .await
            .unwrap();
        round_trip(&mut stream, b"once").await;
        // Ended, and the end of the server's side read: dropped before
        // that, it would retire its session.
        stream.shutdown().await.unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
        drop(stream);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            ended.load(Ordering::SeqCst),
            0,
            "an idle session kept no while"
        );
        drop(mux);
        assert!(
            ended_by(&ended, 1, Duration::from_secs(2)).await,
            "an idle session outlived its client"
        );
    }

    #[tokio::test]
    async fn a_smux_client_gone_closes_its_idle_sessions() {
        a_client_gone_closes_its_idle_sessions(Protocol::Smux).await;
    }

    #[tokio::test]
    async fn a_h2mux_client_gone_closes_its_idle_sessions() {
        a_client_gone_closes_its_idle_sessions(Protocol::H2Mux).await;
    }

    /// A stream dropped before the server finished it retires its
    /// connection: the next stream goes on a new one, the streams still on
    /// it go on, and it ends with the last.
    async fn an_abandoned_stream_retires_its_connection(protocol: Protocol) {
        use std::sync::atomic::Ordering;
        let (port, ended, accepted) = echo_server().await;
        let mux = mux_to(port, protocol);
        let handler = mux.stream().unwrap();
        let mut kept = handler.handle(&echo_session(), None, None).await.unwrap();
        round_trip(&mut kept, b"kept").await;
        let mut cut = handler.handle(&echo_session(), None, None).await.unwrap();
        round_trip(&mut cut, b"cut").await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        // The server echoes until the client is done: not yet.
        drop(cut);
        let mut next = handler.handle(&echo_session(), None, None).await.unwrap();
        round_trip(&mut next, b"next").await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "the next stream went on the retired connection"
        );
        round_trip(&mut kept, b"still").await;
        assert_eq!(ended.load(Ordering::SeqCst), 0, "cut with a stream open");
        drop(kept);
        assert!(
            ended_by(&ended, 1, Duration::from_secs(5)).await,
            "the retired connection outlived its last stream"
        );
    }

    #[tokio::test]
    async fn an_abandoned_smux_stream_retires_its_connection() {
        an_abandoned_stream_retires_its_connection(Protocol::Smux).await;
    }

    #[tokio::test]
    async fn an_abandoned_h2mux_stream_retires_its_connection() {
        an_abandoned_stream_retires_its_connection(Protocol::H2Mux).await;
    }

    /// With yamux, a stream dropped before the server finished it is reset,
    /// alone: the next stream goes on the same connection.
    #[tokio::test]
    async fn an_abandoned_yamux_stream_keeps_its_connection() {
        use std::sync::atomic::Ordering;
        let (port, ended, accepted) = echo_server().await;
        let mux = mux_to(port, Protocol::Yamux);
        let handler = mux.stream().unwrap();
        let mut cut = handler.handle(&echo_session(), None, None).await.unwrap();
        round_trip(&mut cut, b"cut").await;
        drop(cut);
        let mut next = handler.handle(&echo_session(), None, None).await.unwrap();
        round_trip(&mut next, b"next").await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the next stream went on a new connection"
        );
        assert_eq!(ended.load(Ordering::SeqCst), 0);
    }

    /// A stream on a connection another session made goes out where the
    /// connection does, from and to its addresses: a change of network the
    /// connection survives, the default route moving while its interface
    /// stays, closes the stream no more than the connection.
    async fn a_later_stream_goes_out_where_its_connection_does(protocol: Protocol) {
        use crate::net::dial::testing::{default_route_moved, en9, BoundDirect};
        use std::sync::atomic::Ordering;
        let (port, _, accepted) = echo_server().await;
        let mux = mux_over(Arc::new(BoundDirect(port)), protocol);
        let handler = mux.stream().unwrap();
        let (first, second) = (echo_session(), echo_session());
        let mut made = handler.handle(&first, None, None).await.unwrap();
        round_trip(&mut made, b"first").await;
        let mut given = handler.handle(&second, None, None).await.unwrap();
        round_trip(&mut given, b"second").await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "not on one connection");
        let (made, given) = (
            first.state.get::<BoundInterface>(),
            second.state.get::<BoundInterface>(),
        );
        let change = default_route_moved();
        let closes =
            |b: &BoundInterface| change.closes(b.get().as_ref(), b.local().map(|a| a.ip()));
        assert!(!closes(&made));
        assert!(!closes(&given), "closed by a move its connection survives");
        assert_eq!(made.get(), Some(en9()));
        assert_eq!(given.get(), Some(en9()));
        assert_eq!(given.local(), made.local());
        assert_eq!(given.peer().map(|a| a.port()), Some(port));
    }

    #[tokio::test]
    async fn a_later_smux_stream_goes_out_where_its_connection_does() {
        a_later_stream_goes_out_where_its_connection_does(Protocol::Smux).await;
    }

    #[tokio::test]
    async fn a_later_yamux_stream_goes_out_where_its_connection_does() {
        a_later_stream_goes_out_where_its_connection_does(Protocol::Yamux).await;
    }

    #[tokio::test]
    async fn a_later_h2mux_stream_goes_out_where_its_connection_does() {
        a_later_stream_goes_out_where_its_connection_does(Protocol::H2Mux).await;
    }

    /// A connection made on its own socket, for TCP Brutal, records where
    /// it went out and its addresses on its session, as any does: what the
    /// streams on it are given.
    #[tokio::test]
    async fn a_connection_for_brutal_is_recorded_on_its_session() {
        use crate::net::dial::testing::{en9, BoundDirect};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let dns = crate::app::dns::DnsClient::new(
            &Default::default(),
            Default::default(),
            &Default::default(),
        )
        .unwrap()
        .into_shared();
        let whole = crate::adapter::outbound::HandlerBuilder::default()
            .tag("test".to_owned())
            .stream_handler(Arc::new(BoundDirect(server.port())))
            .build();
        let sess = Session::default();
        let _made = Connector::around(whole, dns)
            .connect_on_socket(&sess)
            .await
            .unwrap();
        let bound = sess.state.get::<BoundInterface>();
        assert_eq!(bound.get(), Some(en9()));
        assert_eq!(bound.peer(), Some(server));
    }

    #[test]
    fn a_new_connection_only_when_the_least_busy_is_busy_enough() {
        let o = options(Some(2), Some(3), None).unwrap();
        assert!(reuse(&o, 0, 1));
        assert!(reuse(&o, 2, 1));
        assert!(!reuse(&o, 3, 1));
        assert!(reuse(&o, 50, 2));
        // max_connections alone: a busy connection takes a stream only
        // once there are that many.
        let o = options(Some(4), None, None).unwrap();
        assert!(reuse(&o, 0, 1));
        assert!(!reuse(&o, 1, 1));
        assert!(!reuse(&o, 1, 3));
        assert!(reuse(&o, 1, 4));
        let o = options(None, None, Some(2)).unwrap();
        assert!(reuse(&o, 1, 10));
        assert!(!reuse(&o, 2, 1));
    }
}
