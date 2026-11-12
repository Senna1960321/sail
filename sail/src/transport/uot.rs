//! UDP over TCP as sing-box speaks it (sing's common/uot): what a stream
//! to `sp.v2.udp-over-tcp.arpa`, version 2, or `sp.udp-over-tcp.arpa`,
//! version 1, carries. AnyTLS carries UDP this way, and so do Shadowsocks
//! and SOCKS outbounds with `udp_over_tcp`; a stream to either magic
//! address on any inbound is served as UDP in `app::inbound`.
//!
//! A version 2 stream starts with a request, `is_connect u8 |
//! destination`, the destination as a SOCKS5 address. Then come packets:
//! `length u16 | payload` in connect mode, where every packet goes to the
//! destination, and otherwise `address | length u16 | payload`, with the
//! address in UoT's own form: type `0` IPv4, `1` IPv6, `2` a
//! length-prefixed domain, then the port.
//!
//! A version 1 stream has no request: its packets are those of version 2
//! not in connect mode from the first byte (sing's uot/client.go:29,
//! uot/server.go:48).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use serde_derive::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::adapter::*;
use crate::session::{DatagramSource, Network, Session, SocksAddr, SocksAddrWireType};

/// The destination a UoT stream asks for.
pub const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
/// Version 1's.
pub const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

/// The destination of a UoT stream, as sing-box asks for it.
pub fn magic_destination() -> SocksAddr {
    SocksAddr::Domain(MAGIC_ADDRESS.to_string(), 0)
}

/// The destination of a stream of UoT `version`, as sing's
/// `RequestDestination` has it (uot/protocol.go:25).
pub fn request_destination(version: u8) -> SocksAddr {
    match version {
        1 => SocksAddr::Domain(LEGACY_MAGIC_ADDRESS.to_string(), 0),
        _ => magic_destination(),
    }
}

/// Which UoT version `destination` asks for, if any.
pub fn version(destination: &SocksAddr) -> Option<u8> {
    match destination {
        SocksAddr::Domain(domain, _) if domain == MAGIC_ADDRESS => Some(2),
        SocksAddr::Domain(domain, _) if domain == LEGACY_MAGIC_ADDRESS => Some(1),
        _ => None,
    }
}

const IPV4: u8 = 0x00;
const IPV6: u8 = 0x01;
const FQDN: u8 = 0x02;

/// The request that opens the stream.
pub fn put_request(buf: &mut BytesMut, is_connect: bool, destination: &SocksAddr) {
    buf.put_u8(is_connect as u8);
    destination.write_buf(buf, SocksAddrWireType::PortLast);
}

pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(bool, SocksAddr)> {
    let is_connect = match r.read_u8().await? {
        0 => false,
        1 => true,
        n => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("udp-over-tcp: invalid is_connect {}", n),
            ))
        }
    };
    let destination = SocksAddr::read_from(r, SocksAddrWireType::PortLast).await?;
    Ok((is_connect, destination))
}

/// A packet's address, in UoT's form.
pub fn put_addr(buf: &mut BytesMut, addr: &SocksAddr) -> io::Result<()> {
    match addr {
        SocksAddr::Ip(std::net::SocketAddr::V4(a)) => {
            buf.put_u8(IPV4);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
        SocksAddr::Ip(std::net::SocketAddr::V6(a)) => {
            buf.put_u8(IPV6);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
        SocksAddr::Domain(domain, port) => {
            let len = u8::try_from(domain.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "udp-over-tcp: domain too long")
            })?;
            buf.put_u8(FQDN);
            buf.put_u8(len);
            buf.put_slice(domain.as_bytes());
            buf.put_u16(*port);
        }
    }
    Ok(())
}

pub async fn read_addr<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<SocksAddr> {
    match r.read_u8().await? {
        IPV4 => {
            let ip = Ipv4Addr::from(r.read_u32().await?);
            Ok(SocksAddr::from((ip, r.read_u16().await?)))
        }
        IPV6 => {
            let ip = Ipv6Addr::from(r.read_u128().await?);
            Ok(SocksAddr::from((ip, r.read_u16().await?)))
        }
        FQDN => {
            let len = r.read_u8().await? as usize;
            let mut domain = vec![0; len];
            r.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "udp-over-tcp: invalid domain")
            })?;
            let port = r.read_u16().await?;
            SocksAddr::try_from((domain, port))
        }
        n => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("udp-over-tcp: invalid address type {}", n),
        )),
    }
}

/// A whole packet, ready to write.
pub fn encode_packet(addr: Option<&SocksAddr>, payload: &[u8]) -> io::Result<BytesMut> {
    let len = u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "udp-over-tcp: packet too large",
        )
    })?;
    let mut buf = BytesMut::with_capacity(1 + 1 + 255 + 2 + 2 + payload.len());
    if let Some(addr) = addr {
        put_addr(&mut buf, addr)?;
    }
    buf.put_u16(len);
    buf.put_slice(payload);
    Ok(buf)
}

/// Reads a packet's length and payload into `buf`. A payload larger than
/// `buf` is read and dropped, and reported as `Ok(None)`, so that the
/// stream stays in step.
pub async fn read_payload<R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &mut [u8],
) -> io::Result<Option<usize>> {
    let len = r.read_u16().await? as usize;
    if len > buf.len() {
        let mut rest = len;
        let mut scratch = [0u8; 1024];
        while rest > 0 {
            let n = rest.min(scratch.len());
            r.read_exact(&mut scratch[..n]).await?;
            rest -= n;
        }
        return Ok(None);
    }
    r.read_exact(&mut buf[..len]).await?;
    Ok(Some(len))
}

/// An inbound stream carrying UDP, its request already read.
pub struct InboundDatagram<S> {
    stream: S,
    /// The destination of every packet, in connect mode. Otherwise each
    /// packet names its own.
    connected: Option<SocksAddr>,
    source: DatagramSource,
}

impl<S> InboundDatagram<S> {
    pub fn new(stream: S, connected: Option<SocksAddr>, source: DatagramSource) -> Self {
        InboundDatagram {
            stream,
            connected,
            source,
        }
    }
}

impl<S> crate::adapter::InboundDatagram for InboundDatagram<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn InboundDatagramRecvHalf>,
        Box<dyn InboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        let connected = self.connected.is_some();
        (
            Box::new(InboundRecvHalf {
                r,
                connected: self.connected,
                source: self.source,
            }),
            Box::new(InboundSendHalf { w, connected }),
        )
    }

    fn into_std(self: Box<Self>) -> io::Result<std::net::UdpSocket> {
        Err(io::Error::other("stream transport"))
    }
}

struct InboundRecvHalf<S> {
    r: ReadHalf<S>,
    connected: Option<SocksAddr>,
    source: DatagramSource,
}

#[async_trait]
impl<S> InboundDatagramRecvHalf for InboundRecvHalf<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    async fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> ProxyResult<(usize, DatagramSource, SocksAddr)> {
        let destination = match &self.connected {
            Some(destination) => destination.clone(),
            None => read_addr(&mut self.r)
                .await
                .map_err(|e| ProxyError::DatagramFatal(e.into()))?,
        };
        match read_payload(&mut self.r, buf)
            .await
            .map_err(|e| ProxyError::DatagramFatal(e.into()))?
        {
            Some(n) => Ok((n, self.source.clone(), destination)),
            None => Err(ProxyError::DatagramWarn(anyhow!(
                "udp-over-tcp: dropped a packet too large"
            ))),
        }
    }
}

struct InboundSendHalf<S> {
    w: WriteHalf<S>,
    connected: bool,
}

#[async_trait]
impl<S> InboundDatagramSendHalf for InboundSendHalf<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    async fn send_to(
        &mut self,
        buf: &[u8],
        src_addr: &SocksAddr,
        _dst_addr: &SocketAddr,
    ) -> io::Result<usize> {
        let addr = (!self.connected).then_some(src_addr);
        let packet = encode_packet(addr, buf)?;
        self.w.write_all(&packet).await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        self.w.shutdown().await
    }
}

/// An outbound stream carrying UDP, its request already sent, not in
/// connect mode: every packet names its address, so that one stream can
/// reach any.
pub struct OutboundDatagram<S> {
    stream: S,
    #[cfg(feature = "internal-udp-target-diagnostics")]
    diagnostic_trace: Option<crate::app::udp_target_diagnostics::Trace>,
    /// A domain destination, which replies are reported as coming from, as
    /// the trojan outbound does: the server answers from the address it
    /// resolved.
    destination: Option<SocksAddr>,
}

impl<S> OutboundDatagram<S> {
    #[cfg(all(
        feature = "internal-udp-target-diagnostics",
        any(feature = "outbound-anytls", test)
    ))]
    pub(crate) fn with_diagnostic_trace(
        mut self,
        trace: Option<crate::app::udp_target_diagnostics::Trace>,
    ) -> Self {
        self.diagnostic_trace = trace;
        self
    }
    pub fn new(stream: S, destination: &SocksAddr) -> Self {
        OutboundDatagram {
            stream,
            destination: destination.is_domain().then(|| destination.clone()),
            #[cfg(feature = "internal-udp-target-diagnostics")]
            diagnostic_trace: None,
        }
    }
}

impl<S> crate::adapter::OutboundDatagram for OutboundDatagram<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let (r, w) = tokio::io::split(self.stream);
        (
            Box::new(OutboundRecvHalf {
                r,
                destination: self.destination,
            }),
            Box::new(OutboundSendHalf {
                w,
                #[cfg(feature = "internal-udp-target-diagnostics")]
                diagnostic_trace: self.diagnostic_trace,
            }),
        )
    }
}

struct OutboundRecvHalf<S> {
    r: ReadHalf<S>,
    destination: Option<SocksAddr>,
}

#[async_trait]
impl<S> OutboundDatagramRecvHalf for OutboundRecvHalf<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        loop {
            let addr = read_addr(&mut self.r).await?;
            match read_payload(&mut self.r, buf).await? {
                Some(n) => return Ok((n, self.destination.clone().unwrap_or(addr))),
                None => tracing::debug!("udp-over-tcp: dropped a packet too large"),
            }
        }
    }
}

struct OutboundSendHalf<S> {
    w: WriteHalf<S>,
    #[cfg(feature = "internal-udp-target-diagnostics")]
    diagnostic_trace: Option<crate::app::udp_target_diagnostics::Trace>,
}

#[async_trait]
impl<S> OutboundDatagramSendHalf for OutboundSendHalf<S>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        #[cfg(not(feature = "internal-udp-target-diagnostics"))]
        {
            let packet = encode_packet(Some(target), buf)?;
            self.w.write_all(&packet).await?;
            Ok(buf.len())
        }
        #[cfg(feature = "internal-udp-target-diagnostics")]
        {
            let result: io::Result<usize> = async {
                let packet = encode_packet(Some(target), buf)?;
                self.w.write_all(&packet).await?;
                Ok(buf.len())
            }
            .await;
            #[cfg(feature = "internal-udp-target-diagnostics")]
            if let Some(trace) = &self.diagnostic_trace {
                if trace.is_fixture(target) {
                    let mut event = trace.event(crate::app::udp_target_diagnostics::WRITE);
                    event.address_kind = crate::app::udp_target_diagnostics::address_kind(target);
                    event.matches_fixture = true;
                    event.bytes = u32::try_from(buf.len()).unwrap_or(u32::MAX);
                    match &result {
                        Ok(_) => {
                            event.result = crate::app::udp_target_diagnostics::Outcome::Accepted
                        }
                        Err(error) => {
                            event.result = crate::app::udp_target_diagnostics::Outcome::Failed;
                            event.error_kind =
                                crate::app::udp_target_diagnostics::error_kind(error.kind());
                        }
                    }
                    trace.emit(event);
                }
            }
            result
        }
    }

    async fn close(&mut self) -> io::Result<()> {
        self.w.shutdown().await
    }
}

/// The `udp_over_tcp` option of an outbound, as sing-box has it: a bool,
/// or `{enabled, version}`, version 1 or 2, 2 when unset.
#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum UdpOverTcpOptions {
    Enabled(bool),
    Options(UdpOverTcpFields),
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct UdpOverTcpFields {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub version: Option<u8>,
}

impl UdpOverTcpOptions {
    /// The version it speaks when on, 0 being 2 as in sing-box
    /// (option/udp_over_tcp.go:20); one but 1 and 2 is an error.
    pub fn version(&self, tag: &str) -> anyhow::Result<Option<u8>> {
        match self {
            UdpOverTcpOptions::Enabled(on) => Ok(on.then_some(2)),
            UdpOverTcpOptions::Options(fields) => {
                let version = match fields.version {
                    None | Some(0) | Some(2) => 2,
                    Some(1) => 1,
                    Some(v) => {
                        return Err(anyhow!(
                            "[{}] outbound: udp_over_tcp.version: {} is not one, 1 or 2",
                            tag,
                            v
                        ))
                    }
                };
                Ok(fields.enabled.then_some(version))
            }
        }
    }
}

/// `handler` with its UDP carried over its own TCP, in UoT `version`: a
/// stream to the magic address, made as the handler makes any other.
pub fn over_stream(handler: AnyOutboundHandler, version: u8) -> io::Result<AnyOutboundHandler> {
    let stream = handler.stream()?.clone();
    Ok(crate::adapter::outbound::HandlerBuilder::default()
        .tag(handler.tag().clone())
        .stream_handler(stream.clone())
        .datagram_handler(Arc::new(DatagramHandler { stream, version }))
        .build())
}

/// A datagram handler carrying UDP over `stream`, for a protocol whose
/// UDP goes over its streams only when asked to, such as TUIC's
/// `udp_over_stream`.
pub fn datagram_handler(stream: AnyOutboundStreamHandler) -> AnyOutboundDatagramHandler {
    Arc::new(DatagramHandler { stream, version: 2 })
}

/// UDP through a stream handler.
struct DatagramHandler {
    stream: AnyOutboundStreamHandler,
    /// 1 or 2.
    version: u8,
}

#[async_trait]
impl OutboundDatagramHandler for DatagramHandler {
    fn connect_addr(&self) -> OutboundConnect {
        self.stream.connect_addr()
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Reliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let stream = match transport {
            Some(OutboundTransport::Stream(stream)) => Some(stream),
            Some(OutboundTransport::Datagram(_)) => {
                return Err(io::Error::other("udp-over-tcp: needs a stream"))
            }
            None => None,
        };
        let mut magic = sess.clone();
        magic.network = Network::Tcp;
        magic.destination = request_destination(self.version);
        let mut stream = self.stream.handle(&magic, None, stream).await?;
        // Version 1 has no request: every packet names its address, as
        // here in version 2.
        if self.version == 2 {
            let mut request = BytesMut::new();
            put_request(&mut request, false, &sess.destination);
            stream.write_all(&request).await?;
        }
        Ok(Box::new(OutboundDatagram::new(stream, &sess.destination)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    #[test]
    fn options_take_a_bool_or_version_1_or_2() {
        let parse = |json: &str| serde_json::from_str::<UdpOverTcpOptions>(json).unwrap();
        let version = |json: &str| parse(json).version("t").unwrap();
        assert_eq!(version("true"), Some(2));
        assert_eq!(version("false"), None);
        assert_eq!(version(r#"{"enabled": true}"#), Some(2));
        assert_eq!(version(r#"{"enabled": true, "version": 2}"#), Some(2));
        assert_eq!(version(r#"{"enabled": true, "version": 1}"#), Some(1));
        assert_eq!(version(r#"{"enabled": false, "version": 1}"#), None);
        let err = parse(r#"{"enabled": true, "version": 3}"#)
            .version("t")
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "[t] outbound: udp_over_tcp.version: 3 is not one, 1 or 2"
        );
        assert!(serde_json::from_str::<UdpOverTcpOptions>(r#"{"enabled": true, "x": 1}"#).is_err());
    }

    #[test]
    fn magic_addresses() {
        assert_eq!(version(&magic_destination()), Some(2));
        assert_eq!(
            version(&SocksAddr::Domain(LEGACY_MAGIC_ADDRESS.into(), 0)),
            Some(1)
        );
        assert_eq!(version(&SocksAddr::Domain("example.com".into(), 0)), None);
    }

    #[test]
    fn addresses_use_uot_types() {
        let mut buf = BytesMut::new();
        put_addr(&mut buf, &SocksAddr::from((Ipv4Addr::new(1, 2, 3, 4), 53))).unwrap();
        assert_eq!(&buf[..], &[0, 1, 2, 3, 4, 0, 53]);
        let mut buf = BytesMut::new();
        put_addr(&mut buf, &SocksAddr::Domain("ab".into(), 80)).unwrap();
        assert_eq!(&buf[..], &[2, 2, b'a', b'b', 0, 80]);
    }

    #[test]
    fn packets_and_requests_round_trip() {
        runtime().block_on(async {
            let dest = SocksAddr::Domain("example.com".into(), 443);
            let mut buf = BytesMut::new();
            put_request(&mut buf, false, &dest);
            buf.extend_from_slice(&encode_packet(Some(&dest), b"hi").unwrap());
            let v6 = SocksAddr::from((Ipv6Addr::LOCALHOST, 9));
            buf.extend_from_slice(&encode_packet(Some(&v6), b"there").unwrap());
            buf.extend_from_slice(&encode_packet(Some(&v6), &[7; 10]).unwrap());
            let mut r = &buf[..];
            assert_eq!(read_request(&mut r).await.unwrap(), (false, dest.clone()));
            let mut out = [0u8; 8];
            assert_eq!(read_addr(&mut r).await.unwrap(), dest);
            assert_eq!(read_payload(&mut r, &mut out).await.unwrap(), Some(2));
            assert_eq!(&out[..2], b"hi");
            assert_eq!(read_addr(&mut r).await.unwrap(), v6);
            assert_eq!(read_payload(&mut r, &mut out).await.unwrap(), Some(5));
            // Too large for the buffer: dropped, and the stream stays in step.
            assert_eq!(read_addr(&mut r).await.unwrap(), v6);
            assert_eq!(read_payload(&mut r, &mut out).await.unwrap(), None);
            assert!(r.is_empty());
        });
    }
}
