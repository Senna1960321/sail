//! Shadowsocks 2022 inbound handlers.

use std::io;
use std::net::SocketAddr;

use anyhow::anyhow;
use async_trait::async_trait;

use crate::{
    adapter::*,
    session::{DatagramSource, Session, SocksAddr},
};

use super::sip022::{
    stream::{self, ServerConfig},
    udp,
};
use crate::runtime::resource::HotResource;

pub(crate) struct Resources {
    pub(super) config: ServerConfig,
    pub(super) server: udp::Server,
}

pub struct StreamHandler {
    pub(super) resource: HotResource<Resources>,
}

#[async_trait]
impl InboundStreamHandler for StreamHandler {
    async fn handle<'a>(
        &'a self,
        mut sess: Session,
        stream: AnyStream,
    ) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound ss2022 stream");
        let generation = self.resource.load();
        let accepted = match stream::accept(stream, &generation.config).await {
            Ok(accepted) => accepted,
            Err(refused) => return Err(super::refuse(refused.inner, refused.error).await),
        };
        sess.destination = accepted.destination;
        sess.user = accepted.user;
        Ok(InboundTransport::Stream(Box::new(accepted.stream), sess))
    }
}

pub struct DatagramHandler {
    pub(super) resource: HotResource<Resources>,
}

#[async_trait]
impl InboundDatagramHandler for DatagramHandler {
    async fn handle<'a>(&'a self, socket: AnyInboundDatagram) -> io::Result<AnyInboundTransport> {
        tracing::trace!("handling inbound ss2022 datagram");
        Ok(InboundTransport::Datagram(
            Box::new(Datagram {
                resource: self.resource.clone(),
                socket,
            }),
            None,
        ))
    }
}

struct Datagram {
    resource: HotResource<Resources>,
    socket: AnyInboundDatagram,
}

impl InboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (rh, sh) = self.socket.split();
        (
            Box::new(RecvHalf {
                resource: self.resource.clone(),
                inner: rh,
                buf: Vec::new(),
            }),
            Box::new(SendHalf {
                resource: self.resource,
                inner: sh,
            }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("not a plain udp socket"))
    }
}

struct RecvHalf {
    resource: HotResource<Resources>,
    inner: Box<dyn InboundDatagramRecvHalf>,
    buf: Vec<u8>,
}

#[async_trait]
impl InboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        // The ciphertext is larger than the payload it carries, so receive
        // into a buffer with room for the overhead.
        self.buf.resize(buf.len() + 1024, 0);
        let (n, mut src, _) = self.inner.recv_from(&mut self.buf).await?;
        let packet = &mut self.buf[..n];
        let received = self
            .resource
            .load()
            .server
            .decode(src.address, packet)
            .map_err(|e| ProxyError::DatagramWarn(anyhow!("ss2022 packet: {}", e)))?;
        let payload = &packet[received.payload];
        if payload.len() > buf.len() {
            return Err(ProxyError::DatagramWarn(anyhow!("ss2022 packet too large")));
        }
        buf[..payload.len()].copy_from_slice(payload);
        // The authenticated peer owns both the NAT identity and reply
        // encryption. NAT must also carry this lease on queued replies.
        src.resource_lease = Some(received.lease);
        Ok((
            payload.len(),
            src.with_user(received.user),
            received.destination,
        ))
    }
}

struct SendHalf {
    resource: HotResource<Resources>,
    inner: Box<dyn InboundDatagramSendHalf>,
}

#[async_trait]
impl InboundDatagramSendHalf for SendHalf {
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let packet = self
            .resource
            .load()
            .server
            .encode(*dst_addr, src_addr, buf)?;
        self.inner.send_to(&packet, src_addr, dst_addr).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }
}
