//! yamux, as hashicorp/yamux speaks it: frames of `version u8 | type u8 |
//! flags u16 | stream id u32 | length u32`, big-endian. Data frames carry
//! `length` bytes; a window update's length is the window it grants; a
//! ping's is its opaque value. Every stream starts with a 256 KiB window
//! each way, which this end grows as the stream is read (`muxcore`): the
//! reference implementation takes whatever window it is granted.
//!
//! A server acknowledges a stream as soon as it takes it: the reference
//! client closes the whole session if a stream is not acknowledged within
//! its open timeout. A client opens no more than `muxcore::MAX_UNACKED`
//! streams the server has not acknowledged, as the reference client does:
//! the reference server resets those past its accept backlog of as many.
//!
//! See <https://github.com/hashicorp/yamux/blob/master/spec.md>.

use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::transport::muxcore::{Closing, Codec, Decoder, Event, Flow, Framing};

const VERSION: u8 = 0;
const TYPE_DATA: u8 = 0;
const TYPE_WINDOW_UPDATE: u8 = 1;
const TYPE_PING: u8 = 2;
const TYPE_GO_AWAY: u8 = 3;

const FLAG_SYN: u16 = 1;
const FLAG_ACK: u16 = 2;
const FLAG_FIN: u16 = 4;
const FLAG_RST: u16 = 8;

// Every stream starts with the window the spec gives it.
const _: () = assert!(crate::transport::muxcore::INITIAL_WINDOW == 256 << 10);
/// The largest data frame accepted, beyond which a peer is taken to be
/// misbehaving.
const MAX_DATA_FRAME: u32 = 16 << 20;
/// The largest data frame sent.
const MAX_FRAME_DATA: usize = 32 << 10;
const HEADER: usize = 12;

fn header(buf: &mut BytesMut, kind: u8, flags: u16, id: u32, len: u32) {
    buf.put_u8(VERSION);
    buf.put_u8(kind);
    buf.put_u16(flags);
    buf.put_u32(id);
    buf.put_u32(len);
}

fn window_update(flags: u16, id: u32, delta: u32) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER);
    header(&mut buf, TYPE_WINDOW_UPDATE, flags, id, delta);
    buf.freeze()
}

fn protocol_error(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("yamux: {}", message))
}

pub struct Yamux;

impl Codec for Yamux {
    fn name(&self) -> &'static str {
        "yamux"
    }

    fn flow(&self) -> Flow {
        Flow::Window
    }

    fn closing(&self) -> Closing {
        Closing::Half
    }

    fn max_data(&self) -> usize {
        MAX_FRAME_DATA
    }

    fn first_id(&self, server: bool) -> u32 {
        if server {
            2
        } else {
            1
        }
    }

    fn acknowledges(&self) -> bool {
        true
    }

    fn open(&self, id: u32, first: &[u8]) -> Bytes {
        let mut buf = BytesMut::from(&window_update(FLAG_SYN, id, 0)[..]);
        for chunk in first.chunks(MAX_FRAME_DATA) {
            buf.extend_from_slice(&self.data(id, chunk));
        }
        buf.freeze()
    }

    fn ack(&self, id: u32) -> Option<Bytes> {
        Some(window_update(FLAG_ACK, id, 0))
    }

    fn refuse(&self, id: u32) -> Bytes {
        window_update(FLAG_RST, id, 0)
    }

    fn data(&self, id: u32, data: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER + data.len());
        header(&mut buf, TYPE_DATA, 0, id, data.len() as u32);
        buf.put_slice(data);
        buf.freeze()
    }

    fn fin(&self, id: u32) -> Bytes {
        window_update(FLAG_FIN, id, 0)
    }

    fn reset(&self, id: u32) -> Bytes {
        window_update(FLAG_RST, id, 0)
    }

    fn window_update(&self, id: u32, delta: u32) -> Option<Bytes> {
        Some(window_update(0, id, delta))
    }

    fn ping(&self, ack: bool, opaque: u32) -> Option<Bytes> {
        let mut buf = BytesMut::with_capacity(HEADER);
        let flags = if ack { FLAG_ACK } else { FLAG_SYN };
        header(&mut buf, TYPE_PING, flags, 0, opaque);
        Some(buf.freeze())
    }

    fn decoder(&self, _server: bool) -> Box<dyn Decoder> {
        Box::<YamuxDecoder>::default()
    }
}

#[derive(Default)]
struct YamuxDecoder {
    framing: Framing,
}

impl Decoder for YamuxDecoder {
    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Event>> {
        loop {
            if let Some(next) = self.framing.next(buf) {
                return Ok(next);
            }
            if buf.len() < HEADER {
                return Ok(None);
            }
            if buf[0] != VERSION {
                return Err(protocol_error(format!("unsupported version {}", buf[0])));
            }
            let kind = buf[1];
            let flags = u16::from_be_bytes([buf[2], buf[3]]);
            let id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            let len = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
            buf.advance(HEADER);
            match kind {
                TYPE_DATA | TYPE_WINDOW_UPDATE => {
                    let mut before = Vec::with_capacity(3);
                    if flags & FLAG_SYN != 0 {
                        before.push(Event::Open(id));
                    }
                    if flags & FLAG_ACK != 0 {
                        before.push(Event::Ack(id));
                    }
                    let mut data = None;
                    if kind == TYPE_WINDOW_UPDATE && len > 0 {
                        before.push(Event::Window(id, len));
                    }
                    if kind == TYPE_DATA {
                        if len > MAX_DATA_FRAME {
                            return Err(protocol_error(format!("data frame of {} bytes", len)));
                        }
                        data = Some((id, len as usize));
                    }
                    let mut after = Vec::new();
                    if flags & FLAG_FIN != 0 {
                        after.push(Event::Fin(id));
                    }
                    if flags & FLAG_RST != 0 {
                        after.push(Event::Reset(id));
                    }
                    self.framing.frame(&before, data, &after);
                }
                TYPE_PING => {
                    if flags & FLAG_SYN != 0 {
                        self.framing.frame(&[Event::Ping(len)], None, &[]);
                    } else if flags & FLAG_ACK != 0 {
                        self.framing.frame(&[Event::Pong(len)], None, &[]);
                    }
                }
                TYPE_GO_AWAY => self.framing.frame(&[Event::GoAway], None, &[]),
                kind => return Err(protocol_error(format!("unknown frame type {}", kind))),
            }
        }
    }
}
