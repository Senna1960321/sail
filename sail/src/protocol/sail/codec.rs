//! Sail/1's frames: amux's (`transport::amux`), all big-endian, with two
//! more, carried by the stream core (`transport::muxcore`):
//!
//! - `0x00 SYN | id u16`: the client opens a stream.
//! - `0x01 DATA | id u16 | len u16 | data`: at most `MAX_DATA` bytes, so
//!   that a frame and its header fill one TLS record.
//! - `0x02 FIN | id u16`: no more data this way; the other goes on.
//! - `0x03 WINDOW | id u16 | delta u32`.
//! - `0x04 RST | id u16`: the stream is abandoned both ways.
//! - `0x05 PING | ack u8 | opaque u32`.
//! - `0x06 PAD | len u16 | bytes`: padding, skipped by the reader.
//! - `0x07 SCHEME | len u16 | text`: the server's padding scheme, sent
//!   only to a client whose prelude named another; it pads its next
//!   sessions with it.
//!
//! Any other type ends the session: only PAD is ignored.

use std::io;
use std::sync::Arc;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::anytls::padding::{PaddingScheme, Size};
use crate::protocol::anytls::session::PaddingCell;
use crate::transport::muxcore::{Closing, Codec, Decoder, Event, Flow, Framing, Shaper};

pub(crate) const FRAME_SYN: u8 = 0x00;
pub(crate) const FRAME_DATA: u8 = 0x01;
pub(crate) const FRAME_FIN: u8 = 0x02;
pub(crate) const FRAME_WINDOW: u8 = 0x03;
pub(crate) const FRAME_RST: u8 = 0x04;
pub(crate) const FRAME_PING: u8 = 0x05;
pub(crate) const FRAME_PAD: u8 = 0x06;
pub(crate) const FRAME_SCHEME: u8 = 0x07;

/// The header of a DATA frame.
pub(crate) const DATA_HEADER: usize = 5;
/// The largest TLS record's plaintext.
pub(crate) const TLS_RECORD: usize = 16384;
/// The most data a DATA frame carries: with its header, one TLS record.
pub(crate) const MAX_DATA: usize = TLS_RECORD - DATA_HEADER;
/// The header of a PAD frame, and the most it carries.
const PAD_HEADER: usize = 3;
const MAX_PAD: usize = u16::MAX as usize;

fn short(kind: u8, id: u32) -> [u8; 3] {
    let id = (id as u16).to_be_bytes();
    [kind, id[0], id[1]]
}

pub(crate) fn put_data(buf: &mut BytesMut, id: u32, data: &[u8]) {
    for chunk in data.chunks(MAX_DATA) {
        buf.put_u8(FRAME_DATA);
        buf.put_u16(id as u16);
        buf.put_u16(chunk.len() as u16);
        buf.put_slice(chunk);
    }
}

/// A DATA frame of stream `id` carrying `data`.
pub(crate) fn data_frame(id: u32, data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(DATA_HEADER + data.len());
    put_data(&mut buf, id, data);
    buf.freeze()
}

/// A PAD frame `len` bytes long in all, header included (at least the
/// header's 3); random bytes.
pub(crate) fn pad_frame(len: usize) -> BytesMut {
    let body = len.saturating_sub(PAD_HEADER).min(MAX_PAD);
    let mut buf = BytesMut::with_capacity(PAD_HEADER + body);
    buf.put_u8(FRAME_PAD);
    buf.put_u16(body as u16);
    let mut bytes = vec![0u8; body];
    rand::Rng::fill(&mut rand::thread_rng(), &mut bytes[..]);
    buf.put_slice(&bytes);
    buf
}

/// The SCHEME frame carrying `scheme`'s text.
pub(crate) fn scheme_frame(scheme: &PaddingScheme) -> BytesMut {
    let raw = scheme.raw();
    let mut buf = BytesMut::with_capacity(3 + raw.len());
    buf.put_u8(FRAME_SCHEME);
    buf.put_u16(raw.len() as u16);
    buf.put_slice(raw);
    buf
}

/// Which end a session is, and the scheme it pads with.
#[derive(Clone)]
pub(crate) enum Role {
    /// A client: the scheme shared by its sessions, which a SCHEME frame
    /// replaces.
    Client(PaddingCell),
    Server(Arc<PaddingScheme>),
}

/// Sail/1's frames, for the core.
pub(crate) struct Sail {
    pub(crate) role: Role,
}

impl Codec for Sail {
    fn name(&self) -> &'static str {
        "sail"
    }

    fn flow(&self) -> Flow {
        Flow::Window
    }

    fn closing(&self) -> Closing {
        Closing::Half
    }

    fn max_data(&self) -> usize {
        MAX_DATA
    }

    fn first_id(&self, _server: bool) -> u32 {
        1
    }

    fn id_step(&self) -> u32 {
        1
    }

    fn max_id(&self) -> u32 {
        u16::MAX.into()
    }

    fn open(&self, id: u32, first: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(3 + DATA_HEADER + first.len());
        buf.put_slice(&short(FRAME_SYN, id));
        put_data(&mut buf, id, first);
        buf.freeze()
    }

    fn refuse(&self, id: u32) -> Bytes {
        Bytes::copy_from_slice(&short(FRAME_RST, id))
    }

    fn data(&self, id: u32, bytes: &[u8]) -> Bytes {
        data_frame(id, bytes)
    }

    fn fin(&self, id: u32) -> Bytes {
        Bytes::copy_from_slice(&short(FRAME_FIN, id))
    }

    fn reset(&self, id: u32) -> Bytes {
        Bytes::copy_from_slice(&short(FRAME_RST, id))
    }

    fn window_update(&self, id: u32, delta: u32) -> Option<Bytes> {
        let mut buf = BytesMut::with_capacity(7);
        buf.put_slice(&short(FRAME_WINDOW, id));
        buf.put_u32(delta);
        Some(buf.freeze())
    }

    fn ping(&self, ack: bool, opaque: u32) -> Option<Bytes> {
        let mut buf = BytesMut::with_capacity(6);
        buf.put_u8(FRAME_PING);
        buf.put_u8(ack as u8);
        buf.put_u32(opaque);
        Some(buf.freeze())
    }

    fn decoder(&self, _server: bool) -> Box<dyn Decoder> {
        Box::new(SailDecoder {
            framing: Framing::default(),
            scheme: match &self.role {
                Role::Client(cell) => Some(cell.clone()),
                Role::Server(_) => None,
            },
            scheme_text: None,
        })
    }

    fn shaper(&self) -> Option<Box<dyn Shaper>> {
        let scheme = match &self.role {
            Role::Client(cell) => cell.read().ok()?.clone(),
            Role::Server(scheme) => scheme.clone(),
        };
        Some(Box::new(Padder {
            scheme,
            // The prelude was the client's write 0, and the server's own
            // first write is its 1 as well: the two pad alike.
            pkt: 0,
            done: false,
        }))
    }
}

struct SailDecoder {
    framing: Framing,
    /// A client's: where a SCHEME frame's scheme goes.
    scheme: Option<PaddingCell>,
    /// A SCHEME frame's text, while it is read.
    scheme_text: Option<(BytesMut, usize)>,
}

fn invalid(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

impl Decoder for SailDecoder {
    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Event>> {
        loop {
            if let Some((text, left)) = &mut self.scheme_text {
                let n = (*left).min(buf.len());
                text.extend_from_slice(&buf.split_to(n));
                *left -= n;
                if *left > 0 {
                    return Ok(None);
                }
                let (text, _) = self.scheme_text.take().expect("a scheme being read");
                // A scheme that does not read, or asks too much, is not
                // taken: the client keeps the one it has.
                if let (Some(cell), Some(scheme)) = (&self.scheme, PaddingScheme::parse(&text)) {
                    if let Ok(mut held) = cell.write() {
                        *held = Arc::new(scheme);
                    }
                }
                continue;
            }
            if let Some(next) = self.framing.next(buf) {
                return Ok(next);
            }
            let Some(&kind) = buf.first() else {
                return Ok(None);
            };
            let len = match kind {
                FRAME_SYN | FRAME_FIN | FRAME_RST | FRAME_PAD | FRAME_SCHEME => 3,
                FRAME_DATA => DATA_HEADER,
                FRAME_WINDOW => 7,
                FRAME_PING => 6,
                kind => return Err(invalid(format!("sail: unknown frame type {}", kind))),
            };
            if buf.len() < len {
                return Ok(None);
            }
            let mut header = buf.split_to(len);
            header.advance(1);
            match kind {
                FRAME_PING => {
                    let ack = header.get_u8() != 0;
                    let opaque = header.get_u32();
                    let event = if ack {
                        Event::Pong(opaque)
                    } else {
                        Event::Ping(opaque)
                    };
                    self.framing.frame(&[event], None, &[]);
                }
                FRAME_PAD => self.framing.skip(usize::from(header.get_u16())),
                FRAME_SCHEME => {
                    // Only a server sends one.
                    if self.scheme.is_none() {
                        return Err(invalid("sail: a SCHEME frame from a client".into()));
                    }
                    let left = usize::from(header.get_u16());
                    self.scheme_text = Some((BytesMut::with_capacity(left), left));
                }
                _ => {
                    let id = u32::from(header.get_u16());
                    match kind {
                        FRAME_SYN => self.framing.frame(&[Event::Open(id)], None, &[]),
                        FRAME_DATA => {
                            let len = usize::from(header.get_u16());
                            if len > MAX_DATA {
                                return Err(invalid(format!("sail: a DATA frame of {}", len)));
                            }
                            self.framing.frame(&[], Some((id, len)), &[]);
                        }
                        FRAME_FIN => self.framing.frame(&[Event::Fin(id)], None, &[]),
                        FRAME_WINDOW => {
                            let delta = header.get_u32();
                            self.framing.frame(&[Event::Window(id, delta)], None, &[]);
                        }
                        _ => self.framing.frame(&[Event::Reset(id)], None, &[]),
                    }
                }
            }
        }
    }
}

/// Pads a session's first writes as its scheme says, with PAD frames.
struct Padder {
    scheme: Arc<PaddingScheme>,
    pkt: u32,
    done: bool,
}

impl Shaper for Padder {
    fn active(&mut self) -> bool {
        !self.done
    }

    fn shape(&mut self, write: BytesMut) -> Vec<BytesMut> {
        self.pkt = self.pkt.wrapping_add(1);
        if self.pkt < self.scheme.stop() {
            return pad(write, &self.scheme.sizes(self.pkt));
        }
        self.done = true;
        vec![write]
    }
}

/// The records `unit` is written in: payload first, padded out with PAD
/// frames where the payload runs short, as AnyTLS pads with waste frames.
fn pad(mut unit: BytesMut, sizes: &[Size]) -> Vec<BytesMut> {
    let mut records = Vec::new();
    for size in sizes {
        let record = match *size {
            Size::Check if unit.is_empty() => break,
            Size::Check => continue,
            Size::Record(n) => n,
        };
        let remaining = unit.len();
        if remaining > record {
            records.push(unit.split_to(record));
        } else if remaining > 0 {
            if record >= remaining + PAD_HEADER {
                unit.extend_from_slice(&pad_frame(record - remaining));
            }
            records.push(unit.split());
        } else {
            records.push(pad_frame(record));
        }
    }
    if !unit.is_empty() {
        records.push(unit);
    }
    records
}

/// The first 8 bytes of the SHA-256 of a scheme's text: what a client's
/// prelude names, and a server compares with its own.
pub(crate) fn digest(scheme: &PaddingScheme) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(scheme.raw());
    hash[..8].try_into().expect("8 of 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    fn client() -> (Sail, PaddingCell) {
        let cell: PaddingCell = Arc::new(RwLock::new(Arc::new(PaddingScheme::default_scheme())));
        (
            Sail {
                role: Role::Client(cell.clone()),
            },
            cell,
        )
    }

    fn decode_all(decoder: &mut dyn Decoder, bytes: &[u8]) -> io::Result<Vec<Event>> {
        let mut buf = BytesMut::from(bytes);
        let mut events = Vec::new();
        while let Some(event) = decoder.decode(&mut buf)? {
            events.push(event);
        }
        assert!(buf.is_empty(), "left undecoded: {:?}", buf);
        Ok(events)
    }

    /// A full DATA frame and its header are one TLS record, exactly.
    #[test]
    fn a_full_data_frame_is_one_tls_record() {
        assert_eq!(MAX_DATA + DATA_HEADER, 16384);
        let (codec, _) = client();
        assert_eq!(codec.max_data(), MAX_DATA);
        let frame = codec.data(1, &vec![7; MAX_DATA]);
        assert_eq!(frame.len(), TLS_RECORD);
        // More is cut into frames of that size.
        let frame = codec.data(1, &vec![7; MAX_DATA + 1]);
        assert_eq!(frame.len(), TLS_RECORD + DATA_HEADER + 1);
    }

    /// The frames, byte for byte.
    #[test]
    fn frames_are_amuxs_with_pad_and_scheme() {
        let (codec, _) = client();
        assert_eq!(
            &codec.open(3, b"hi")[..],
            [0, 0, 3, 1, 0, 3, 0, 2, b'h', b'i']
        );
        assert_eq!(&codec.fin(3)[..], [2, 0, 3]);
        assert_eq!(&codec.reset(3)[..], [4, 0, 3]);
        assert_eq!(
            &codec.window_update(3, 9).unwrap()[..],
            [3, 0, 3, 0, 0, 0, 9]
        );
        assert_eq!(&codec.ping(true, 5).unwrap()[..], [5, 1, 0, 0, 0, 5]);
        let pad = pad_frame(10);
        assert_eq!(pad.len(), 10);
        assert_eq!(&pad[..3], [6, 0, 7]);
    }

    /// PAD is skipped, wherever it falls; frames around it come through.
    #[test]
    fn pad_is_skipped() {
        let (codec, _) = client();
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&codec.open(1, b""));
        bytes.extend_from_slice(&pad_frame(40));
        bytes.extend_from_slice(&codec.data(1, b"abc"));
        bytes.extend_from_slice(&pad_frame(3));
        bytes.extend_from_slice(&codec.fin(1));
        let events = decode_all(&mut *codec.decoder(false), &bytes).unwrap();
        assert_eq!(
            events,
            [
                Event::Open(1),
                Event::Data(1, Bytes::from_static(b"abc")),
                Event::Fin(1)
            ]
        );
    }

    /// Unknown types, a DATA frame past the bound, and SCHEME from a client
    /// end the session.
    #[test]
    fn what_is_not_a_frame_fails_closed() {
        let (codec, _) = client();
        for kind in [8u8, 0x40, 0xff] {
            assert!(decode_all(&mut *codec.decoder(false), &[kind, 0, 1]).is_err());
        }
        let mut too_long = vec![FRAME_DATA, 0, 1];
        too_long.extend_from_slice(&((MAX_DATA + 1) as u16).to_be_bytes());
        assert!(decode_all(&mut *codec.decoder(false), &too_long).is_err());
        let server = Sail {
            role: Role::Server(Arc::new(PaddingScheme::default_scheme())),
        };
        let scheme = scheme_frame(&PaddingScheme::default_scheme());
        assert!(decode_all(&mut *server.decoder(true), &scheme).is_err());
    }

    /// A client takes the scheme a SCHEME frame carries, read in pieces;
    /// one that does not parse leaves its own.
    #[test]
    fn a_client_takes_the_servers_scheme() {
        let (codec, cell) = client();
        let new = PaddingScheme::parse_strict("stop=2\n0=30-30\n1=100-100").unwrap();
        let frame = scheme_frame(&new);
        let mut decoder = codec.decoder(false);
        let mut buf = BytesMut::new();
        for byte in frame.iter() {
            buf.put_u8(*byte);
            assert_eq!(decoder.decode(&mut buf).unwrap(), None);
        }
        assert_eq!(cell.read().unwrap().raw(), new.raw());

        let mut garbage = BytesMut::new();
        garbage.put_u8(FRAME_SCHEME);
        garbage.put_u16(5);
        garbage.put_slice(b"nope!");
        decode_all(&mut *codec.decoder(false), &garbage).unwrap();
        assert_eq!(cell.read().unwrap().raw(), new.raw());
    }

    /// A padded write comes out as the scheme's records, and decodes to
    /// what was written.
    #[test]
    fn writes_are_padded_to_the_schemes_sizes() {
        let scheme =
            PaddingScheme::parse_strict("stop=3\n0=30-30\n1=200-200\n2=50-50,c,60-60").unwrap();
        let codec = Sail {
            role: Role::Server(Arc::new(scheme)),
        };
        let mut shaper = codec.shaper().unwrap();
        let first = BytesMut::from(&codec.data(1, b"hello")[..]);
        let records = shaper.shape(first);
        assert_eq!(records.iter().map(|r| r.len()).collect::<Vec<_>>(), [200]);
        // Write 2: 50, a check (more is left), 60.
        let second = BytesMut::from(&codec.data(1, &[1; 70])[..]);
        let records = shaper.shape(second);
        assert_eq!(
            records.iter().map(|r| r.len()).collect::<Vec<_>>(),
            [50, 60]
        );
        assert!(shaper.active());
        let third = BytesMut::from(&codec.data(1, b"x")[..]);
        assert_eq!(shaper.shape(third).len(), 1);
        assert!(!shaper.active());

        let mut all = BytesMut::new();
        all.extend_from_slice(&codec.open(1, b""));
        all.extend_from_slice(
            &pad(
                BytesMut::from(&codec.data(1, b"hello")[..]),
                &[Size::Record(200)],
            )
            .concat(),
        );
        let events = decode_all(&mut *codec.decoder(true), &all).unwrap();
        assert_eq!(
            events,
            [Event::Open(1), Event::Data(1, Bytes::from_static(b"hello"))]
        );
    }
}
