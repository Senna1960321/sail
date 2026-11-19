//! Sail/1: sail's own protocol (sail#60). Streams over one TLS connection,
//! authenticated once by the session's prelude, with amux's frames
//! (`codec`): windows, half-close, a stream reset alone. A connection that
//! does not open with a valid prelude goes to the inbound's fallback, a web
//! server, with the bytes read of it.
//!
//! All integers are big-endian.
//!
//! - Prelude, client to server, once: `version u8 = 1 | token [32] |
//!   digest [8] | pad_len u16 | pad`. `digest` names the padding scheme
//!   the client holds; a server with another sends it a SCHEME frame.
//! - A stream begins, client to server, with `network u8 (1 TCP, 2 UDP) |
//!   atyp u8 (1 IPv4, 2 domain, 3 IPv6) | alen u8 (domain only) | addr |
//!   port u16`, its data right after: the client does not wait. A UDP
//!   stream is to `sp.v2.udp-over-tcp.arpa` and carries sing-box's UDP
//!   over TCP, version 2 (`transport::uot`): its request, then packets,
//!   each naming its address.
//! - The server's first byte on a stream is its status: 0 connected, its
//!   data after; else why not (`Status`), and the stream is reset.

// Each end uses its own part of these.
#![cfg_attr(
    not(all(feature = "inbound-sail", feature = "outbound-sail")),
    allow(dead_code)
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::session::SocksAddr;

pub(crate) mod codec;
#[cfg(feature = "outbound-sail")]
mod dials;
#[cfg(feature = "inbound-sail")]
pub mod inbound;
#[cfg(feature = "outbound-sail")]
pub mod outbound;
#[cfg(test)]
mod parking_tests;

/// The prelude's version.
pub(crate) const VERSION: u8 = 1;
/// The prelude before its padding: version, token, digest, pad_len.
pub(crate) const PRELUDE_HEAD: usize = 1 + 32 + 8 + 2;

/// A stream's network.
pub(crate) const NETWORK_TCP: u8 = 1;
pub(crate) const NETWORK_UDP: u8 = 2;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;

/// Why a server did not connect a stream: its first byte, after which the
/// stream is reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Status {
    Connected = 0,
    /// The server's rules refused it.
    Refused = 1,
    /// Not something the server does: a network and destination that do
    /// not agree.
    Unsupported = 2,
    /// The server's outbound failed to connect.
    UpstreamFailed = 3,
    TimedOut = 4,
    /// The server is out of room for it.
    Busy = 5,
}

impl Status {
    /// The status a server's failure to connect gives.
    pub(crate) fn of(e: &io::Error) -> Status {
        match e.kind() {
            io::ErrorKind::PermissionDenied => Status::Refused,
            io::ErrorKind::Unsupported => Status::Unsupported,
            io::ErrorKind::TimedOut => Status::TimedOut,
            io::ErrorKind::OutOfMemory | io::ErrorKind::WouldBlock => Status::Busy,
            _ => Status::UpstreamFailed,
        }
    }

    /// The error a client gives for a status other than `Connected`.
    pub(crate) fn error(byte: u8) -> io::Error {
        let (kind, why) = match byte {
            1 => (
                io::ErrorKind::PermissionDenied,
                "refused by the server's rules",
            ),
            2 => (io::ErrorKind::Unsupported, "not supported by the server"),
            3 => (
                io::ErrorKind::ConnectionRefused,
                "the server failed to connect",
            ),
            4 => (io::ErrorKind::TimedOut, "the server timed out connecting"),
            5 => (io::ErrorKind::ConnectionRefused, "the server is busy"),
            _ => (io::ErrorKind::InvalidData, "an unknown status"),
        };
        io::Error::new(kind, format!("sail: {} ({})", why, byte))
    }
}

/// A credential: 32 random bytes as canonical unpadded base64url (43
/// characters). Errors never repeat the text.
pub(crate) fn token(text: &str) -> anyhow::Result<[u8; 32]> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    anyhow::ensure!(
        text.len() == 43,
        "a sail token is 32 random bytes as unpadded base64url (43 characters)"
    );
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("a sail token is not base64url"))?;
    anyhow::ensure!(
        URL_SAFE_NO_PAD.encode(bytes) == text,
        "a sail token is not in canonical base64url"
    );
    Ok(bytes)
}

/// The prelude, its padding `pad` random bytes long.
pub(crate) fn prelude(token: &[u8; 32], digest: &[u8; 8], pad: usize) -> Vec<u8> {
    let pad = pad.min(u16::MAX as usize);
    let mut buf = Vec::with_capacity(PRELUDE_HEAD + pad);
    buf.push(VERSION);
    buf.extend_from_slice(token);
    buf.extend_from_slice(digest);
    buf.extend_from_slice(&(pad as u16).to_be_bytes());
    let mut padding = vec![0u8; pad];
    rand::Rng::fill(&mut rand::thread_rng(), &mut padding[..]);
    buf.extend_from_slice(&padding);
    buf
}

/// What the head of a prelude says: version, token, digest, pad_len.
pub(crate) struct Head {
    pub version: u8,
    pub token: [u8; 32],
    pub digest: [u8; 8],
    pub pad: usize,
}

impl Head {
    pub(crate) fn parse(head: &[u8; PRELUDE_HEAD]) -> Head {
        Head {
            version: head[0],
            token: head[1..33].try_into().expect("32 bytes"),
            digest: head[33..41].try_into().expect("8 bytes"),
            pad: u16::from_be_bytes([head[41], head[42]]).into(),
        }
    }
}

/// A stream's header for `network` and `destination`.
pub(crate) fn stream_header(network: u8, destination: &SocksAddr) -> io::Result<Vec<u8>> {
    let mut buf = vec![network];
    match destination {
        SocksAddr::Ip(SocketAddr::V4(a)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&a.ip().octets());
        }
        SocksAddr::Ip(SocketAddr::V6(a)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&a.ip().octets());
        }
        SocksAddr::Domain(name, _) => {
            let name = name.as_bytes();
            if name.is_empty() || name.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sail: a domain of 1 to 255 bytes",
                ));
            }
            buf.push(ATYP_DOMAIN);
            buf.push(name.len() as u8);
            buf.extend_from_slice(name);
        }
    }
    buf.extend_from_slice(&destination.port().to_be_bytes());
    Ok(buf)
}

/// Reads a stream's header: its network and destination.
pub(crate) async fn read_stream_header<R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<(u8, SocksAddr)> {
    let invalid = |why: &str| io::Error::new(io::ErrorKind::InvalidData, format!("sail: {}", why));
    let mut head = [0u8; 2];
    r.read_exact(&mut head).await?;
    let [network, atyp] = head;
    if network != NETWORK_TCP && network != NETWORK_UDP {
        return Err(invalid("an unknown network"));
    }
    let ip = match atyp {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            r.read_exact(&mut a).await?;
            Some(IpAddr::V4(Ipv4Addr::from(a)))
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            r.read_exact(&mut a).await?;
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        ATYP_DOMAIN => None,
        _ => return Err(invalid("an unknown address type")),
    };
    let name = match ip {
        Some(_) => None,
        None => {
            let len = r.read_u8().await? as usize;
            if len == 0 {
                return Err(invalid("an empty domain"));
            }
            let mut name = vec![0u8; len];
            r.read_exact(&mut name).await?;
            Some(String::from_utf8(name).map_err(|_| invalid("a domain not in UTF-8"))?)
        }
    };
    let port = r.read_u16().await?;
    // UoT's magic address has port 0, which no TCP destination has.
    if port == 0 && network != NETWORK_UDP {
        return Err(invalid("port 0"));
    }
    Ok((
        network,
        match (ip, name) {
            (Some(ip), _) => SocksAddr::Ip(SocketAddr::new(ip, port)),
            (None, Some(name)) => SocksAddr::Domain(name, port),
            (None, None) => unreachable!("an address or a domain"),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_canonical_base64url_and_errors_keep_it_out() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let text = URL_SAFE_NO_PAD.encode([0xa5; 32]);
        assert_eq!(token(&text).unwrap(), [0xa5; 32]);
        // The last character carries two unused bits: set, it is not
        // canonical.
        let mut loose = text.clone();
        loose.replace_range(42.., "B");
        for bad in [text.clone() + "=", "short".into(), "!".repeat(43), loose] {
            let error = token(&bad).unwrap_err().to_string();
            assert!(!error.contains(&bad), "{}", error);
        }
    }

    /// The prelude and stream headers, byte for byte.
    #[test]
    fn literal_prelude_and_headers() {
        let p = prelude(&[0x11; 32], &[0x22; 8], 3);
        assert_eq!(p.len(), PRELUDE_HEAD + 3);
        assert_eq!(p[0], 1);
        assert_eq!(&p[1..33], [0x11; 32]);
        assert_eq!(&p[33..41], [0x22; 8]);
        assert_eq!(&p[41..43], [0, 3]);
        let head = Head::parse(p[..PRELUDE_HEAD].try_into().unwrap());
        assert_eq!(
            (head.version, head.token, head.digest, head.pad),
            (1, [0x11; 32], [0x22; 8], 3)
        );

        let v4: SocksAddr = "127.0.0.1:443".parse::<SocketAddr>().unwrap().into();
        assert_eq!(stream_header(1, &v4).unwrap(), [1, 1, 127, 0, 0, 1, 1, 187]);
        let v6: SocksAddr = "[2001:db8::1]:8443".parse::<SocketAddr>().unwrap().into();
        let mut want = vec![1, 3, 0x20, 0x01, 0x0d, 0xb8];
        want.extend_from_slice(&[0; 11]);
        want.extend_from_slice(&[1, 0x20, 0xfb]);
        assert_eq!(stream_header(1, &v6).unwrap(), want);
        let name = SocksAddr::Domain("example.test".into(), 53);
        let mut want = vec![2, 2, 12];
        want.extend_from_slice(b"example.test");
        want.extend_from_slice(&[0, 53]);
        assert_eq!(stream_header(2, &name).unwrap(), want);
    }

    #[tokio::test]
    async fn headers_read_back_and_bad_ones_fail() {
        for (network, addr) in [
            (
                1,
                SocksAddr::from("10.0.0.1:80".parse::<SocketAddr>().unwrap()),
            ),
            (
                1,
                SocksAddr::from("[::1]:22".parse::<SocketAddr>().unwrap()),
            ),
            (2, SocksAddr::Domain("a.example".into(), 443)),
        ] {
            let bytes = stream_header(network, &addr).unwrap();
            let (n, a) = read_stream_header(&mut &bytes[..]).await.unwrap();
            assert_eq!((n, a), (network, addr));
        }
        // UDP's magic address, with its port 0.
        let magic = crate::transport::uot::magic_destination();
        let bytes = stream_header(NETWORK_UDP, &magic).unwrap();
        assert_eq!(
            read_stream_header(&mut &bytes[..]).await.unwrap(),
            (NETWORK_UDP, magic)
        );
        for bad in [
            &[3u8, 1, 1, 1, 1, 1, 0, 80][..],
            &[1, 9, 1, 1, 1, 1, 0, 80],
            &[1, 2, 0, 0, 80],
            &[1, 1, 1, 1, 1, 1, 0, 0],
            &[1, 2, 5, b'a'],
        ] {
            assert!(
                read_stream_header(&mut &bad[..]).await.is_err(),
                "{:?}",
                bad
            );
        }
    }

    #[test]
    fn statuses_round_trip_through_errors() {
        for (kind, status) in [
            (io::ErrorKind::PermissionDenied, Status::Refused),
            (io::ErrorKind::Unsupported, Status::Unsupported),
            (io::ErrorKind::TimedOut, Status::TimedOut),
            (io::ErrorKind::ConnectionRefused, Status::UpstreamFailed),
        ] {
            assert_eq!(Status::of(&kind.into()), status);
            assert_eq!(Status::error(status as u8).kind(), kind);
        }
        assert_eq!(Status::error(9).kind(), io::ErrorKind::InvalidData);
    }
}
