//! Connections dialled through a named outbound, handed to the host: the
//! outbound's own stream or datagrams, read and written by the host with
//! no copy between, from any executor, on every platform: each poll is
//! made within the instance's runtime, which drives them. Once the
//! instance stops, they fail.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Handle;
use tokio::sync::Mutex;

use super::{Address, Error, Instance};
use crate::adapter::{AnyStream, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
use crate::control::Dialed;
use crate::session::Network;

/// The largest datagram either way: any UDP payload.
const LARGEST: usize = 65_535;

/// A TCP connection through an outbound: read, write, shut down. Dropping
/// it closes the connection.
pub struct DialStream {
    /// None only as it drops.
    stream: Option<AnyStream>,
    runtime: Handle,
}

impl DialStream {
    /// The runtime to poll within, and the stream.
    fn parts(&mut self) -> (&Handle, Pin<&mut AnyStream>) {
        let stream = self.stream.as_mut().expect("a stream until it drops");
        (&self.runtime, Pin::new(stream))
    }
}

impl Drop for DialStream {
    /// Within the instance's runtime, as what closes with the stream (a
    /// multiplexed stream's close) may spawn work there.
    fn drop(&mut self) {
        let _runtime = self.runtime.enter();
        self.stream.take();
    }
}

impl AsyncRead for DialStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let (runtime, stream) = self.parts();
        let _runtime = runtime.enter();
        stream.poll_read(cx, buf)
    }
}

impl AsyncWrite for DialStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let (runtime, stream) = self.parts();
        let _runtime = runtime.enter();
        stream.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (runtime, stream) = self.parts();
        let _runtime = runtime.enter();
        stream.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (runtime, stream) = self.parts();
        let _runtime = runtime.enter();
        stream.poll_shutdown(cx)
    }
}

/// `fut`, each poll within `runtime`.
struct Within<'a, F> {
    runtime: &'a Handle,
    fut: Pin<Box<F>>,
}

impl<F: Future> Future for Within<'_, F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let _runtime = self.runtime.enter();
        self.fut.as_mut().poll(cx)
    }
}

fn within<F: Future>(runtime: &Handle, fut: F) -> Within<'_, F> {
    Within {
        runtime,
        fut: Box::pin(fut),
    }
}

/// UDP through an outbound: datagrams to the address dialled, or another
/// the outbound reaches, and from them. Dropping it closes it.
pub struct DialDatagram {
    to: Address,
    send: Mutex<Box<dyn OutboundDatagramSendHalf>>,
    recv: Mutex<Box<dyn OutboundDatagramRecvHalf>>,
    runtime: Handle,
    scope: crate::runtime::scope::TaskScope,
}

impl DialDatagram {
    /// Sends `data` to the address dialled.
    pub async fn send(&self, data: &[u8]) -> io::Result<()> {
        let to = self.to.clone();
        self.send_to(data, &to).await
    }

    /// Sends `data` to `to`, through the same outbound.
    pub async fn send_to(&self, data: &[u8], to: &Address) -> io::Result<()> {
        if data.len() > LARGEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "larger than a datagram",
            ));
        }
        within(&self.runtime, async {
            self.send.lock().await.send_to(data, to).await.map(|_| ())
        })
        .await
    }

    /// The next datagram, into `buf`: its length, and where it came from.
    /// A `buf` of 65,535 bytes takes any; a datagram longer than a shorter
    /// one is cut, or fails, as the outbound reads it.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        within(&self.runtime, async {
            self.recv.lock().await.recv_from(buf).await
        })
        .await
    }
}

impl Drop for DialDatagram {
    /// Closes the outbound's datagrams as its relay would have, on the
    /// instance's runtime.
    fn drop(&mut self) {
        let mut send = std::mem::replace(self.send.get_mut(), Box::new(Closed));
        let recv = std::mem::replace(self.recv.get_mut(), Box::new(Closed));
        self.scope
            .spawn_on(&self.runtime, "dial datagrams close", async move {
                let _ = send.close().await;
                drop(recv);
            });
    }
}

/// What a dropped `DialDatagram` keeps in place of what it closes.
struct Closed;

#[async_trait::async_trait]
impl OutboundDatagramRecvHalf for Closed {
    async fn recv_from(&mut self, _: &mut [u8]) -> io::Result<(usize, crate::session::SocksAddr)> {
        Err(io::ErrorKind::BrokenPipe.into())
    }
}

#[async_trait::async_trait]
impl OutboundDatagramSendHalf for Closed {
    async fn send_to(&mut self, _: &[u8], _: &crate::session::SocksAddr) -> io::Result<usize> {
        Err(io::ErrorKind::BrokenPipe.into())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Instance {
    /// Connects to `to` over TCP through the outbound `outbound` alone,
    /// whatever the rules say, within `timeout`: its handshake done, the
    /// name resolved as a routed connection's would be. Listed among the
    /// connections under the inbound `control`.
    pub async fn dial_tcp(
        &self,
        outbound: &str,
        to: Address,
        timeout: Duration,
    ) -> Result<DialStream, Error> {
        let outbound = outbound.to_string();
        self.with_dialer(timeout, move |dialer, timeout| {
            Box::pin(async move {
                let Dialed::Stream(stream) =
                    dialer.dial(&outbound, Network::Tcp, to, timeout).await?
                else {
                    unreachable!("a TCP dial gives a stream");
                };
                Ok(DialStream {
                    stream: Some(stream),
                    runtime: dialer.handle().clone(),
                })
            })
        })
        .await?
    }

    /// `dial_tcp` or `dial_udp` as one end of a socket pair sail relays
    /// through the outbound, the host's to own: what the C ABI's dial
    /// gives. As those, it waits while the instance starts for its
    /// outbounds to be built.
    #[cfg(unix)]
    #[doc(hidden)]
    pub async fn dial_fd(
        &self,
        outbound: &str,
        network: Network,
        to: crate::session::SocksAddr,
        timeout: Duration,
    ) -> Result<std::os::fd::OwnedFd, Error> {
        let outbound = outbound.to_string();
        Ok(self
            .with_dialer(timeout, move |dialer, timeout| {
                Box::pin(async move { dialer.dial_fd(&outbound, network, to, timeout).await })
            })
            .await??)
    }

    /// Opens UDP to `to` through the outbound `outbound` alone, as
    /// `dial_tcp` does.
    pub async fn dial_udp(
        &self,
        outbound: &str,
        to: Address,
        timeout: Duration,
    ) -> Result<DialDatagram, Error> {
        let outbound = outbound.to_string();
        let dialled = to.clone();
        self.with_dialer(timeout, move |dialer, timeout| {
            Box::pin(async move {
                let Dialed::Datagram(datagram) = dialer
                    .dial(&outbound, Network::Udp, dialled, timeout)
                    .await?
                else {
                    unreachable!("a UDP dial gives datagrams");
                };
                let (recv, send) = datagram.split();
                Ok::<_, Error>(DialDatagram {
                    to,
                    send: Mutex::new(send),
                    recv: Mutex::new(recv),
                    runtime: dialer.handle().clone(),
                    scope: dialer.env().scope.clone(),
                })
            })
        })
        .await?
    }
}
