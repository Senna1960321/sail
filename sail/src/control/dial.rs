//! A connection through a named outbound, for the host: the rules never
//! see it, and it is counted and listed as a connection of its own
//! (inbound `control`) until it ends: for a host that steers an app's
//! flow to a node of its own choosing, or downloads past its own TUN.
//!
//! `dial` gives the stream or the datagrams themselves, for a host that
//! links sail; `dial_fd` gives one end of a socket pair that sail relays
//! through the outbound, for one that calls the C ABI: a stream for TCP,
//! one message per datagram for UDP (SOCK_SEQPACKET on Linux and Android,
//! where a closed peer of a datagram pair is never seen; SOCK_DGRAM on
//! Apple's, which have no SOCK_SEQPACKET). The host closing its end ends
//! the connection.

use std::sync::Arc;
use std::time::Duration;

use super::ControlError;
use crate::adapter::AnyOutboundDatagram;
use crate::adapter::AnyStream;
use crate::session::{Network, Session, SocksAddr};
use crate::RuntimeManager;

/// The inbound a dialled connection is listed under.
pub const DIAL_INBOUND: &str = "control";

/// What `dial` connects.
pub enum Dialed {
    /// TCP: the stream to the destination.
    Stream(AnyStream),
    /// UDP: datagrams to the destination, and from it.
    Datagram(AnyOutboundDatagram),
}

/// What dials through an instance's outbounds, from when they are built:
/// while the instance starts, before it runs, and for as long as it runs.
/// It holds the dispatcher weakly: it keeps no instance alive, and once
/// the run has ended its dials fail as those of a stopping instance.
#[derive(Clone)]
pub struct Dialer {
    dispatcher: std::sync::Weak<crate::app::dispatcher::Dispatcher>,
    nat_manager: std::sync::Weak<crate::app::nat_manager::NatManager>,
    env: Arc<crate::runtime::RuntimeEnv>,
    handle: tokio::runtime::Handle,
}

impl RuntimeManager {
    /// What dials through its outbounds.
    pub fn dialer(&self) -> Dialer {
        Dialer {
            dispatcher: self.dispatcher.clone(),
            nat_manager: self.nat_manager.clone(),
            env: self.env.clone(),
            handle: self.handle().clone(),
        }
    }

    /// Connects to `destination` through the outbound `outbound` alone,
    /// whatever the rules say, within `timeout`: the outbound's handshake
    /// done, its name resolved as a routed connection's would be.
    pub async fn dial(
        &self,
        outbound: &str,
        network: Network,
        destination: SocksAddr,
        timeout: Duration,
    ) -> Result<Dialed, ControlError> {
        self.dialer()
            .dial(outbound, network, destination, timeout)
            .await
    }

    /// `dial`, and one end of a socket pair sail relays through it on the
    /// instance's runtime until either end closes: the host's to own and
    /// close.
    #[cfg(unix)]
    pub async fn dial_fd(
        &self,
        outbound: &str,
        network: Network,
        destination: SocksAddr,
        timeout: Duration,
    ) -> Result<std::os::fd::OwnedFd, ControlError> {
        self.dialer()
            .dial_fd(outbound, network, destination, timeout)
            .await
    }
}

impl Dialer {
    pub(crate) fn new(
        dispatcher: &Arc<crate::app::dispatcher::Dispatcher>,
        nat_manager: &Arc<crate::app::nat_manager::NatManager>,
        env: Arc<crate::runtime::RuntimeEnv>,
        handle: tokio::runtime::Handle,
    ) -> Self {
        Dialer {
            dispatcher: Arc::downgrade(dispatcher),
            nat_manager: Arc::downgrade(nat_manager),
            env,
            handle,
        }
    }

    /// The instance's runtime, which its dials run on.
    pub fn handle(&self) -> &tokio::runtime::Handle {
        &self.handle
    }

    /// What the instance runs with.
    pub fn env(&self) -> &Arc<crate::runtime::RuntimeEnv> {
        &self.env
    }

    /// What routes sessions, and what their UDP goes through, while the
    /// instance runs.
    pub(crate) fn routing(
        &self,
    ) -> Option<(
        Arc<crate::app::dispatcher::Dispatcher>,
        Arc<crate::app::nat_manager::NatManager>,
    )> {
        Some((self.dispatcher.upgrade()?, self.nat_manager.upgrade()?))
    }

    /// Connects to `destination` through the outbound `outbound` alone,
    /// whatever the rules say, within `timeout`: the outbound's handshake
    /// done, its name resolved as a routed connection's would be.
    pub async fn dial(
        &self,
        outbound: &str,
        network: Network,
        destination: SocksAddr,
        timeout: Duration,
    ) -> Result<Dialed, ControlError> {
        let dispatcher = self.dispatcher.upgrade().ok_or(ControlError::Stopping)?;
        let sess = Session {
            network,
            destination,
            inbound_tag: DIAL_INBOUND.to_string(),
            inbound_type: DIAL_INBOUND,
            ..Default::default()
        };
        let dialed = async {
            match network {
                Network::Tcp => dispatcher
                    .dial_stream(outbound, sess)
                    .await
                    .map(Dialed::Stream),
                Network::Udp => dispatcher
                    .dial_datagram(outbound, sess)
                    .await
                    .map(Dialed::Datagram),
            }
        };
        // The instance's work, whoever's task awaits it: what the dial
        // spawns (a QUIC endpoint's driver) is in its scope.
        match tokio::time::timeout(timeout, self.env.scope.enter(dialed)).await {
            Ok(Ok(dialed)) => Ok(dialed),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ControlError::NotFound(outbound.to_string()))
            }
            Ok(Err(e)) => Err(ControlError::Failed(e.to_string())),
            Err(_) => Err(ControlError::Timeout),
        }
    }

    /// `dial`, and one end of a socket pair sail relays through it on the
    /// instance's runtime until either end closes: the host's to own and
    /// close.
    #[cfg(unix)]
    pub async fn dial_fd(
        &self,
        outbound: &str,
        network: Network,
        destination: SocksAddr,
        timeout: Duration,
    ) -> Result<std::os::fd::OwnedFd, ControlError> {
        let dialed = self
            .dial(outbound, network, destination.clone(), timeout)
            .await?;
        let failed = |e: std::io::Error| ControlError::Failed(format!("socket pair: {}", e));
        match dialed {
            Dialed::Stream(stream) => {
                let (host, ours) = std::os::unix::net::UnixStream::pair().map_err(failed)?;
                ours.set_nonblocking(true).map_err(failed)?;
                let ours = tokio::net::UnixStream::from_std(ours).map_err(failed)?;
                let relay = self.env.options.relay.clone();
                self.env
                    .scope
                    .spawn("dial relay", relay_stream(ours, stream, relay));
                Ok(host.into())
            }
            Dialed::Datagram(datagram) => {
                let (host, ours) = messages::pair().map_err(failed)?;
                let ours = tokio::io::unix::AsyncFd::new(ours).map_err(failed)?;
                self.env
                    .scope
                    .spawn("dial relay", messages::relay(ours, datagram, destination));
                Ok(host)
            }
        }
    }
}

/// The host's stream and the outbound's, relayed as a routed connection's.
#[cfg(unix)]
async fn relay_stream<H>(
    mut host: H,
    mut outbound: AnyStream,
    relay: crate::runtime::options::Relay,
) where
    H: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _ = crate::net::relay::copy_buf_bidirectional_with_timeout(
        &mut host,
        &mut outbound,
        relay.buffer_size * 1024,
        relay.buffer_max_size.max(relay.buffer_size) * 1024,
        crate::net::relay::RelayTimeouts {
            write_stall: relay.write_stall_timeout,
            a_to_b_idle: relay.uplink_idle_timeout,
            b_to_a_idle: relay.downlink_idle_timeout,
        },
    )
    .await;
}

/// A socket pair that keeps each datagram whole, and tells sail when the
/// host closed its end.
#[cfg(unix)]
mod messages {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use tokio::io::unix::AsyncFd;

    use crate::adapter::AnyOutboundDatagram;
    use crate::session::SocksAddr;

    /// The largest datagram either way, and so each end's buffers: room
    /// for any UDP payload.
    const BUFFER: usize = 256 * 1024;
    const LARGEST: usize = 65_535;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const KIND: libc::c_int = libc::SOCK_SEQPACKET;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const KIND: libc::c_int = libc::SOCK_DGRAM;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const NO_SIGNAL: libc::c_int = libc::MSG_NOSIGNAL;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const NO_SIGNAL: libc::c_int = 0;

    fn check(r: libc::c_int) -> io::Result<libc::c_int> {
        if r < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r)
        }
    }

    /// The host's end and sail's, the latter non-blocking.
    pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds has room for the two descriptors socketpair writes.
        check(unsafe { libc::socketpair(libc::AF_UNIX, KIND, 0, fds.as_mut_ptr()) })?;
        // SAFETY: socketpair succeeded, so both are open and ours.
        let (host, ours) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        for fd in [&host, &ours] {
            let raw = fd.as_raw_fd();
            for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
                let size = BUFFER as libc::c_int;
                // SAFETY: a valid descriptor and an int option of its size.
                check(unsafe {
                    libc::setsockopt(
                        raw,
                        libc::SOL_SOCKET,
                        option,
                        &size as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                })?;
            }
            // SAFETY: fcntl on a valid descriptor.
            check(unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) })?;
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let on: libc::c_int = 1;
            // SAFETY: as above; a closed host gives an error, not SIGPIPE.
            check(unsafe {
                libc::setsockopt(
                    ours.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            })?;
        }
        let raw = ours.as_raw_fd();
        // SAFETY: fcntl on a valid descriptor.
        let flags = check(unsafe { libc::fcntl(raw, libc::F_GETFL) })?;
        check(unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
        Ok((host, ours))
    }

    /// What reading from the host gave.
    enum Read {
        Datagram(usize),
        Closed,
    }

    /// How often a datagram pair is looked at for a host that closed its
    /// end, where nothing tells: Apple's kqueue raises no event when a
    /// datagram peer closes, and only a read sees it (ECONNRESET). Judged:
    /// a closed flow is noticed within a second, for one wakeup a second.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const CLOSED_CHECK: std::time::Duration = std::time::Duration::from_secs(1);

    /// Whether the host closed its end, looked at without taking a
    /// datagram.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn host_closed(fd: &AsyncFd<OwnedFd>) -> bool {
        let mut byte = 0u8;
        // SAFETY: one byte of room, peeked at only.
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                &mut byte as *mut u8 as *mut libc::c_void,
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::ConnectionReset
    }

    async fn read(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> io::Result<Read> {
        loop {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let mut guard = fd.readable().await?;
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let mut guard = loop {
                tokio::select! {
                    guard = fd.readable() => break guard?,
                    _ = tokio::time::sleep(CLOSED_CHECK) => {
                        if host_closed(fd) {
                            return Ok(Read::Closed);
                        }
                    }
                }
            };
            // SAFETY: buf is valid for writes of its length.
            let n = unsafe {
                libc::recv(
                    fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if n > 0 {
                return Ok(Read::Datagram(n as usize));
            }
            if n == 0 {
                // Empty, or the host gone: on Linux a closed peer reads
                // empty with the read side hung up, an empty datagram
                // without.
                return Ok(if guard.ready().is_read_closed() {
                    Read::Closed
                } else {
                    Read::Datagram(0)
                });
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => guard.clear_ready(),
                io::ErrorKind::Interrupted => {}
                // Apple's report a closed peer so.
                io::ErrorKind::ConnectionReset => return Ok(Read::Closed),
                _ => return Err(e),
            }
        }
    }

    async fn write(fd: &AsyncFd<OwnedFd>, data: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = fd.writable().await?;
            // SAFETY: data is valid for reads of its length.
            let n = unsafe {
                libc::send(
                    fd.as_raw_fd(),
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                    NO_SIGNAL,
                )
            };
            if n >= 0 {
                return Ok(());
            }
            let e = io::Error::last_os_error();
            match e.kind() {
                io::ErrorKind::WouldBlock => guard.clear_ready(),
                io::ErrorKind::Interrupted => {}
                _ => return Err(e),
            }
        }
    }

    /// The host's datagrams to `destination` through `datagram`, and its
    /// answers back, until either side ends.
    pub async fn relay(
        fd: AsyncFd<OwnedFd>,
        datagram: AnyOutboundDatagram,
        destination: SocksAddr,
    ) {
        let (mut recv, mut send) = datagram.split();
        let up = async {
            let mut buf = vec![0u8; LARGEST];
            while let Ok(Read::Datagram(n)) = read(&fd, &mut buf).await {
                if send.send_to(&buf[..n], &destination).await.is_err() {
                    break;
                }
            }
        };
        let down = async {
            let mut buf = vec![0u8; LARGEST];
            while let Ok((n, _)) = recv.recv_from(&mut buf).await {
                if write(&fd, &buf[..n]).await.is_err() {
                    break;
                }
            }
        };
        tokio::select! {
            _ = up => {}
            _ = down => {}
        }
        let _ = send.close().await;
    }
}
