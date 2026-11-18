//! `tls_fragment` and `tls_record_fragment` (route options), and an
//! outbound's `tls.fragment` and `tls.record_fragment`: the first thing
//! written to a stream, when it is a TLS ClientHello, goes out cut in its
//! server name, so that a middlebox reading one segment or one record
//! does not see the whole name. As sing-box's `tf.Conn`, the cut falls at
//! random within the name's first label, after its first byte.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::session::TlsFragment;

const RECORD_HEADER_LEN: usize = 5;

/// The wait between segments unless one is configured, sing-box's.
pub(crate) const FALLBACK_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// Where the server name is in a ClientHello record, and the name.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ServerName {
    pub index: usize,
    pub name: String,
}

/// The server name of `payload`, when it is a whole TLS record holding a
/// ClientHello, as sing-box's `IndexTLSServerName` finds it.
pub(crate) fn index_server_name(payload: &[u8]) -> Option<ServerName> {
    if payload.len() < RECORD_HEADER_LEN || payload[0] != 22 {
        return None;
    }
    let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < RECORD_HEADER_LEN + record_len {
        return None;
    }
    let handshake = &payload[RECORD_HEADER_LEN..];
    // Type, length, version, random, session id length.
    if handshake.len() < 4 + 2 + 32 + 1 || handshake[0] != 1 {
        return None;
    }
    let handshake_len =
        (handshake[1] as usize) << 16 | (handshake[2] as usize) << 8 | handshake[3] as usize;
    if handshake.len() - 4 != handshake_len {
        return None;
    }
    let version = u16::from_be_bytes([handshake[4], handshake[5]]);
    if version & 0xfffc != 0x0300 && version != 0x0304 {
        return None;
    }
    let mut at = 4 + 2 + 32 + 1 + handshake[38] as usize;
    let suites_len = u16::from_be_bytes([*handshake.get(at)?, *handshake.get(at + 1)?]) as usize;
    at += 2 + suites_len;
    let compressions = *handshake.get(at)? as usize;
    at += 1 + compressions;
    let extensions_len =
        u16::from_be_bytes([*handshake.get(at)?, *handshake.get(at + 1)?]) as usize;
    at += 2;
    let extensions = handshake.get(at..at + extensions_len)?;
    let mut offset = 0;
    while offset + 4 <= extensions.len() {
        let kind = u16::from_be_bytes([extensions[offset], extensions[offset + 1]]);
        let len = u16::from_be_bytes([extensions[offset + 2], extensions[offset + 3]]) as usize;
        let body = extensions.get(offset + 4..offset + 4 + len)?;
        if kind == 0 {
            // A list length, a name type (a host name), the name's length.
            if body.len() < 5 || body[2] != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([body[3], body[4]]) as usize;
            let name = std::str::from_utf8(body.get(5..5 + name_len)?).ok()?;
            return Some(ServerName {
                index: RECORD_HEADER_LEN + at + offset + 4 + 5,
                name: name.to_string(),
            });
        }
        offset += 4 + len;
    }
    None
}

/// `hello` cut as `how` says: the pieces to write one after the other.
pub(crate) fn cut(hello: &[u8], how: TlsFragment) -> Option<Vec<Vec<u8>>> {
    let sni = index_server_name(hello)?;
    let first_label = sni.name.split('.').next().unwrap_or_default().len();
    if first_label == 0 {
        return None;
    }
    // Never before the name's first byte, as sing-box's may: the second
    // piece would then hold the whole name. A one-letter label is cut
    // before it all the same.
    let at = sni.index + rand::thread_rng().gen_range(1.min(first_label - 1)..first_label);
    let pieces = [&hello[..at], &hello[at..]];
    let pieces: Vec<Vec<u8>> = if how.records {
        // Each piece of the handshake in a record of its own, with the
        // first record's type and version.
        pieces
            .iter()
            .enumerate()
            .map(|(i, piece)| {
                let piece = if i == 0 {
                    &piece[RECORD_HEADER_LEN..]
                } else {
                    piece
                };
                let mut record = Vec::with_capacity(RECORD_HEADER_LEN + piece.len());
                record.extend_from_slice(&hello[..3]);
                record.extend_from_slice(&(piece.len() as u16).to_be_bytes());
                record.extend_from_slice(piece);
                record
            })
            .collect()
    } else {
        pieces.iter().map(|p| p.to_vec()).collect()
    };
    if how.segments.is_some() {
        Some(pieces)
    } else {
        // Records alone go out in one write.
        Some(vec![pieces.concat()])
    }
}

/// A stream whose first write, a ClientHello, goes out cut.
pub(crate) struct FragmentStream<S> {
    inner: S,
    how: TlsFragment,
    first: bool,
    /// The pieces not written yet, and how much of the front one is.
    pending: VecDeque<Vec<u8>>,
    written: usize,
    /// The length of the write the pieces stand for.
    accepted: usize,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> FragmentStream<S> {
    pub(crate) fn new(inner: S, how: TlsFragment) -> Self {
        FragmentStream {
            inner,
            how,
            first: true,
            pending: VecDeque::new(),
            written: 0,
            accepted: 0,
            delay: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> FragmentStream<S> {
    /// Writes the pieces left, each flushed to go out on its own, then
    /// `buf` as it is; once the pieces are out, the write they stand for is
    /// done.
    fn poll_pending(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        while let Some(piece) = self.pending.front() {
            if let Some(delay) = self.delay.as_mut() {
                futures::ready!(delay.as_mut().poll(cx));
                self.delay = None;
            }
            if self.written < piece.len() {
                let n = futures::ready!(
                    Pin::new(&mut self.inner).poll_write(cx, &piece[self.written..])
                )?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.written += n;
                continue;
            }
            // Each piece is flushed, to go out in a segment of its own.
            futures::ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
            self.pending.pop_front();
            self.written = 0;
            if let (false, Some(delay)) = (self.pending.is_empty(), self.how.segments) {
                self.delay = Some(Box::pin(tokio::time::sleep(delay)));
            }
            if self.pending.is_empty() {
                return Poll::Ready(Ok(self.accepted));
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.first && !buf.is_empty() {
            this.first = false;
            if let Some(pieces) = cut(buf, this.how) {
                this.pending = pieces.into();
                this.accepted = buf.len();
            }
        }
        this.poll_pending(cx, buf)
    }

    /// A ClientHello handed over in several buffers is cut whole.
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.first {
            let whole: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
            if whole.is_empty() {
                return Poll::Ready(Ok(0));
            }
            this.first = false;
            if let Some(pieces) = cut(&whole, this.how) {
                this.pending = pieces.into();
                this.accepted = whole.len();
                return this.poll_pending(cx, &[]);
            }
        }
        if !this.pending.is_empty() {
            return this.poll_pending(cx, &[]);
        }
        Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const RECORDS: TlsFragment = TlsFragment {
        records: true,
        segments: None,
    };

    fn segments(delay: Duration) -> TlsFragment {
        TlsFragment {
            records: false,
            segments: Some(delay),
        }
    }

    /// The records `bytes` holds, header and body each, in order.
    fn records_of(mut bytes: &[u8]) -> Vec<(&[u8], &[u8])> {
        let mut records = Vec::new();
        while bytes.len() >= RECORD_HEADER_LEN {
            let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
            let (record, rest) = bytes.split_at(RECORD_HEADER_LEN + len);
            records.push(record.split_at(RECORD_HEADER_LEN));
            bytes = rest;
        }
        assert!(bytes.is_empty(), "a record cut short");
        records
    }

    /// A ClientHello for `name`, as a client would send it.
    fn client_hello(name: &str) -> Vec<u8> {
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name.as_bytes());
        let mut extensions = Vec::new();
        // An extension before the name, to be skipped.
        extensions.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0];
        handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn the_server_name_is_found() {
        let hello = client_hello("www.example.com");
        let sni = index_server_name(&hello).unwrap();
        assert_eq!(sni.name, "www.example.com");
        assert_eq!(&hello[sni.index..sni.index + 15], b"www.example.com");
        assert!(index_server_name(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(index_server_name(&hello[..hello.len() - 1]).is_none());
        // Nothing past the end, whatever the bytes.
        for i in 0..hello.len() {
            let mut bad = hello.clone();
            bad[i] ^= 0xa5;
            let _ = index_server_name(&bad);
        }
    }

    #[test]
    fn segments_are_the_hello_cut_in_the_first_label() {
        let hello = client_hello("www.example.com");
        let index = index_server_name(&hello).unwrap().index;
        for _ in 0..20 {
            let pieces = cut(&hello, segments(Duration::ZERO)).unwrap();
            assert_eq!(pieces.len(), 2);
            assert_eq!(pieces.concat(), hello);
            assert!((index + 1..index + 3).contains(&pieces[0].len()));
        }
    }

    #[test]
    fn records_carry_the_handshake_in_two() {
        let hello = client_hello("www.example.com");
        let records = cut(&hello, RECORDS).unwrap().concat();
        assert_eq!(records.len(), hello.len() + RECORD_HEADER_LEN);
        let first_len = u16::from_be_bytes([records[3], records[4]]) as usize;
        let second = &records[RECORD_HEADER_LEN + first_len..];
        assert_eq!(&second[..3], &hello[..3]);
        let second_len = u16::from_be_bytes([second[3], second[4]]) as usize;
        assert_eq!(second.len(), RECORD_HEADER_LEN + second_len);
        let mut handshake = records[RECORD_HEADER_LEN..RECORD_HEADER_LEN + first_len].to_vec();
        handshake.extend_from_slice(&second[RECORD_HEADER_LEN..]);
        assert_eq!(handshake, hello[RECORD_HEADER_LEN..]);
    }

    /// Whatever the random cut, no piece after the first holds the whole
    /// name: the cut never falls before its first byte (sing-box's may).
    #[test]
    fn the_second_piece_never_holds_the_whole_name() {
        for name in ["ab.example.com", "www.example.com", "localhost"] {
            let hello = client_hello(name);
            for how in [
                segments(Duration::ZERO),
                TlsFragment {
                    records: true,
                    segments: Some(Duration::ZERO),
                },
            ] {
                for _ in 0..200 {
                    let pieces = cut(&hello, how).unwrap();
                    assert_eq!(pieces.len(), 2);
                    for piece in &pieces {
                        assert!(
                            !piece.windows(name.len()).any(|w| w == name.as_bytes()),
                            "a piece holds {}",
                            name
                        );
                    }
                }
            }
        }
    }

    /// Both: two records, each a piece of its own.
    #[test]
    fn records_and_segments_combine() {
        let hello = client_hello("www.example.com");
        let how = TlsFragment {
            records: true,
            segments: Some(Duration::ZERO),
        };
        let pieces = cut(&hello, how).unwrap();
        assert_eq!(pieces.len(), 2);
        let mut handshake = Vec::new();
        for piece in &pieces {
            let records = records_of(piece);
            assert_eq!(records.len(), 1);
            assert_eq!(&records[0].0[..3], &hello[..3]);
            handshake.extend_from_slice(records[0].1);
        }
        assert_eq!(handshake, hello[RECORD_HEADER_LEN..]);
        // Neither record holds the whole name.
        for piece in &pieces {
            assert!(!piece.windows(15).any(|w| w == b"www.example.com"));
        }
    }

    #[tokio::test]
    async fn the_stream_writes_the_pieces_then_the_rest_as_is() {
        for how in [
            segments(Duration::from_millis(20)),
            RECORDS,
            TlsFragment {
                records: true,
                segments: Some(Duration::from_millis(20)),
            },
        ] {
            let (near, mut far) = tokio::io::duplex(1 << 16);
            let mut stream = FragmentStream::new(near, how);
            let hello = client_hello("example.com");
            let start = tokio::time::Instant::now();
            stream.write_all(&hello).await.unwrap();
            stream.write_all(b"after").await.unwrap();
            drop(stream);
            let mut got = Vec::new();
            far.read_to_end(&mut got).await.unwrap();
            assert!(got.ends_with(b"after"));
            if let Some(delay) = how.segments {
                assert!(start.elapsed() >= delay);
            }
            if how.records {
                assert_eq!(got.len(), hello.len() + 5 + 5);
                assert_eq!(records_of(&got[..got.len() - 5]).len(), 2);
            } else {
                assert_eq!(&got[..hello.len()], hello);
            }
        }
        // What is not a ClientHello goes as it is.
        let (near, mut far) = tokio::io::duplex(1024);
        let mut stream = FragmentStream::new(near, RECORDS);
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        drop(stream);
        let mut got = Vec::new();
        far.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"GET / HTTP/1.1\r\n\r\n");
    }

    /// A ClientHello handed over as a vectored write, header and body
    /// apart, is cut whole.
    #[tokio::test]
    async fn a_vectored_hello_is_cut_whole() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let mut stream = FragmentStream::new(near, RECORDS);
        let hello = client_hello("www.example.com");
        let (head, body) = hello.split_at(RECORD_HEADER_LEN);
        let bufs = [io::IoSlice::new(head), io::IoSlice::new(body)];
        let n = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_write_vectored(cx, &bufs))
            .await
            .unwrap();
        assert_eq!(n, hello.len());
        drop(stream);
        let mut got = Vec::new();
        far.read_to_end(&mut got).await.unwrap();
        assert_eq!(records_of(&got).len(), 2);
    }
}
