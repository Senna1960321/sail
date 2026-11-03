//! sing-box's multiplex, sing-mux: many connections over one connection of
//! a proxy protocol.
//!
//! Unlike `amux`, which runs below a proxy protocol, sing-mux runs above
//! one. A client opens an ordinary proxy connection (Trojan, Shadowsocks,
//! VLESS, ...) to the magic destination `sp.mux.sing-box.arpa:444`, and
//! speaks over it:
//!
//! - a protocol request, `version u8 | protocol u8`, and with version 1
//!   `padding bool`, then when padding `length u16 | length random bytes`;
//! - then, padded or not (`padding`), smux, yamux or HTTP/2 (`h2mux`);
//! - on every stream, a stream request, `flags u16 | destination`, the
//!   destination as a SOCKS5 address; `flags` has `1` for UDP and `2` for
//!   UDP packets that each carry an address;
//! - from the server, before its first data on the stream, a status byte,
//!   `0` or `1` followed by an error message;
//! - with `brutal`, on a stream of its own to `_BrutalBwExchange`, the
//!   rates each end sends at over TCP Brutal (`brutal`).
//!
//! See <https://github.com/SagerNet/sing-mux>. What the server does with a
//! stream is up to whoever serves it: an inbound connection to the magic
//! destination is served in `app::inbound`, whatever inbound it came in
//! through, when that inbound's `multiplex` block allows it (`inbound`).

use std::io;

use bytes::{BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::session::{SocksAddr, SocksAddrWireType};

pub mod brutal;
pub mod client;
#[cfg(feature = "fuzzing")]
pub(crate) mod fuzz;
mod h2mux;
pub mod inbound;
pub mod packet;
mod padding;
pub mod server;
#[cfg(test)]
mod session_tests;
mod smux;
#[cfg(test)]
mod stall_tests;
mod yamux;
#[cfg(test)]
mod yamux_interop;

/// The destination a mux connection asks for.
pub const MAGIC_DOMAIN: &str = "sp.mux.sing-box.arpa";
pub const MAGIC_PORT: u16 = 444;

/// Whether `destination` asks for a mux connection.
pub fn is_magic(destination: &SocksAddr) -> bool {
    matches!(destination, SocksAddr::Domain(domain, _) if domain == MAGIC_DOMAIN)
}

/// The multiplexing protocol under the streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Smux = 0,
    Yamux = 1,
    H2Mux = 2,
}

impl Protocol {
    /// The frames of a protocol the session core carries; h2mux has
    /// sessions of its own.
    fn codec(self) -> Option<std::sync::Arc<dyn crate::transport::muxcore::Codec>> {
        match self {
            Protocol::Smux => Some(std::sync::Arc::new(smux::Smux)),
            Protocol::Yamux => Some(std::sync::Arc::new(yamux::Yamux)),
            Protocol::H2Mux => None,
        }
    }

    pub fn from_name(name: &str) -> Option<Protocol> {
        match name {
            "smux" => Some(Protocol::Smux),
            "yamux" => Some(Protocol::Yamux),
            "h2mux" => Some(Protocol::H2Mux),
            _ => None,
        }
    }

    fn from_byte(b: u8) -> io::Result<Protocol> {
        match b {
            0 => Ok(Protocol::Smux),
            1 => Ok(Protocol::Yamux),
            2 => Ok(Protocol::H2Mux),
            n => Err(invalid(format!("unknown protocol {}", n))),
        }
    }
}

const VERSION_0: u8 = 0;
const VERSION_1: u8 = 1;

/// The request that opens a mux connection. Version 1 when padded, as the
/// reference client sends it; version 0 has no padding flag.
pub fn encode_request(protocol: Protocol, padding: bool) -> BytesMut {
    let mut buf = BytesMut::with_capacity(5 + 768);
    buf.put_u8(if padding { VERSION_1 } else { VERSION_0 });
    buf.put_u8(protocol as u8);
    if padding {
        buf.put_u8(1);
        let len: u16 = rand::thread_rng().gen_range(256..768);
        buf.put_u16(len);
        buf.put_bytes(0, len as usize);
    }
    buf
}

/// Reads the request that opens a mux connection: the protocol, and
/// whether the connection is padded.
pub async fn read_request<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(Protocol, bool)> {
    let version = r.read_u8().await?;
    if version > VERSION_1 {
        return Err(invalid(format!("unsupported version {}", version)));
    }
    let protocol = Protocol::from_byte(r.read_u8().await?)?;
    let mut padding = false;
    if version == VERSION_1 {
        padding = match r.read_u8().await? {
            0 => false,
            1 => true,
            n => return Err(invalid(format!("invalid padding flag {}", n))),
        };
        if padding {
            let len = r.read_u16().await? as u64;
            let skipped = tokio::io::copy(&mut r.take(len), &mut tokio::io::sink()).await?;
            if skipped != len {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }
    Ok((protocol, padding))
}

const FLAG_UDP: u16 = 1;
const FLAG_ADDR: u16 = 2;

/// What a stream asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamRequest {
    Tcp(SocksAddr),
    /// UDP to one destination: packets carry no address.
    Udp(SocksAddr),
    /// UDP where every packet carries its address; the destination is
    /// where the first packets go, or the magic destination.
    UdpAddr(SocksAddr),
}

impl StreamRequest {
    pub fn destination(&self) -> &SocksAddr {
        match self {
            StreamRequest::Tcp(d) | StreamRequest::Udp(d) | StreamRequest::UdpAddr(d) => d,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let flags = match self {
            StreamRequest::Tcp(_) => 0,
            StreamRequest::Udp(_) => FLAG_UDP,
            StreamRequest::UdpAddr(_) => FLAG_UDP | FLAG_ADDR,
        };
        buf.put_u16(flags);
        self.destination()
            .write_buf(buf, SocksAddrWireType::PortLast);
    }

    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<StreamRequest> {
        let flags = r.read_u16().await?;
        let destination = SocksAddr::read_from(r, SocksAddrWireType::PortLast).await?;
        Ok(if flags & FLAG_UDP == 0 {
            StreamRequest::Tcp(destination)
        } else if flags & FLAG_ADDR == 0 {
            StreamRequest::Udp(destination)
        } else {
            StreamRequest::UdpAddr(destination)
        })
    }
}

/// The status a server sends before its first data on a stream.
pub const STATUS_SUCCESS: u8 = 0;
pub const STATUS_ERROR: u8 = 1;

/// The longest error message read from a server.
const MAX_ERROR_MESSAGE: u64 = 1024;

/// Reads a stream's status, failing with the server's message if it is
/// an error.
pub async fn read_status<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    match r.read_u8().await? {
        STATUS_SUCCESS => Ok(()),
        STATUS_ERROR => {
            let len = read_uvarint(r).await?;
            if len > MAX_ERROR_MESSAGE {
                return Err(io::Error::other("mux: remote error"));
            }
            let mut message = vec![0; len as usize];
            r.read_exact(&mut message).await?;
            Err(io::Error::other(format!(
                "mux: remote error: {}",
                String::from_utf8_lossy(&message)
            )))
        }
        n => Err(invalid(format!("invalid stream status {}", n))),
    }
}

async fn read_uvarint<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let b = r.read_u8().await?;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("varint overflows".to_string()))
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("mux: {}", message))
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
    fn requests_round_trip() {
        runtime().block_on(async {
            for protocol in [Protocol::Smux, Protocol::Yamux, Protocol::H2Mux] {
                for padding in [false, true] {
                    let buf = encode_request(protocol, padding);
                    if padding {
                        assert!(buf.len() >= 5 + 256, "{}", buf.len());
                        assert_eq!(buf[0], 1);
                    } else {
                        assert_eq!(&buf[..], &[0, protocol as u8]);
                    }
                    let mut r = &buf[..];
                    assert_eq!(read_request(&mut r).await.unwrap(), (protocol, padding));
                    assert!(r.is_empty());
                }
            }
            // Version 1 without padding, as the reference client never sends
            // it but may.
            let mut r = &[1u8, 2, 0][..];
            assert_eq!(
                read_request(&mut r).await.unwrap(),
                (Protocol::H2Mux, false)
            );
            assert!(read_request(&mut &[2u8, 0][..]).await.is_err());
            assert!(read_request(&mut &[0u8, 3][..]).await.is_err());
            assert!(read_request(&mut &[1u8, 0, 1, 0, 9, 1][..]).await.is_err());
        });
    }

    #[test]
    fn stream_requests_round_trip() {
        runtime().block_on(async {
            let dest = SocksAddr::Domain("example.com".into(), 443);
            for request in [
                StreamRequest::Tcp(dest.clone()),
                StreamRequest::Udp(SocksAddr::from((std::net::Ipv4Addr::new(1, 2, 3, 4), 53))),
                StreamRequest::UdpAddr(dest.clone()),
            ] {
                let mut buf = BytesMut::new();
                request.encode(&mut buf);
                let mut r = &buf[..];
                assert_eq!(StreamRequest::read(&mut r).await.unwrap(), request);
                assert!(r.is_empty());
            }
            let mut buf = BytesMut::new();
            StreamRequest::UdpAddr(dest).encode(&mut buf);
            assert_eq!(&buf[..3], &[0, 3, 3]);
        });
    }

    #[test]
    fn status() {
        runtime().block_on(async {
            assert!(read_status(&mut &[0u8][..]).await.is_ok());
            let err = read_status(&mut &[1u8, 3, b'b', b'a', b'd'][..])
                .await
                .unwrap_err();
            assert!(err.to_string().contains("bad"), "{}", err);
            assert!(read_status(&mut &[2u8][..]).await.is_err());
            // A message longer than allowed is not read.
            let err = read_status(&mut &[1u8, 0xff, 0xff, 0x03][..])
                .await
                .unwrap_err();
            assert_eq!(err.to_string(), "mux: remote error");
        });
    }
}
