//! A consumer of an nf_tables `queue` -- NFQUEUE -- spoken over netlink
//! without libnetfilter_queue: `auto_redirect`'s pre-match, which judges a
//! flow by its first packet before the redirect takes it.
//!
//! ```ignore
//! let queue = Arc::new(Queue::open(100)?);
//! loop {
//!     let packet = queue.recv().await?;
//!     let verdict = match packet.flow {
//!         Some(flow) if flow.first_packet => judge(&flow),
//!         _ => Verdict::Accept,
//!     };
//!     queue.verdict(packet.id, verdict)?;
//! }
//! ```
//!
//! This follows sing-tun's handler as of v0.9.6 (`nfqueue_linux.go`), which
//! binds with florianl/go-nfqueue: the same bind sequence and queue
//! configuration, the same packet parsing, and `NF_REPEAT` with a mark as
//! the verdict that lets the queueing chain see what was decided. The
//! places this differs say why.
//!
//! The encoding and the parsing are plain bytes and build everywhere, so
//! their tests run on any host; the socket is Linux only.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;

use super::nft::netlink::{attr_be32, attrs, put_message, Attrs};
use super::nft::sys::{NLM_F_ACK, NLM_F_REQUEST};

// linux/netfilter/nfnetlink.h
const NFNL_SUBSYS_QUEUE: u16 = 3;

// enum nfqnl_msg_types
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;

// enum nfqnl_attr_type
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;
const NFQA_IFINDEX_INDEV: u16 = 5;
const NFQA_IFINDEX_OUTDEV: u16 = 6;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_CAP_LEN: u16 = 13;
const NFQA_SKB_INFO: u16 = 14;

// enum nfqnl_attr_config
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;

// enum nfqnl_msg_config_cmds
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_PF_BIND: u8 = 3;
const NFQNL_CFG_CMD_PF_UNBIND: u8 = 4;

// enum nfqnl_config_mode
const NFQNL_COPY_PACKET: u8 = 2;

// NFQA_CFG_F_*
const NFQA_CFG_F_FAIL_OPEN: u32 = 0x1;
const NFQA_CFG_F_GSO: u32 = 0x4;

// NFQA_SKB_*
const NFQA_SKB_GSO: u32 = 0x2;

// linux/netfilter.h
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NF_REPEAT: u32 = 4;

/// How much of each packet the kernel copies to us: all of it, as sing-tun
/// v0.9.6 asks. The kernel caps it at `0xffff - NLA_HDRLEN`.
const COPY_RANGE: u32 = 0xFFFF;

/// How many packets may wait for a verdict; past that the kernel accepts
/// them unjudged (`NFQA_CFG_F_FAIL_OPEN`).
const QUEUE_MAXLEN: u32 = 4096;

/// The queue's flags: accept rather than drop when the queue is full, and
/// hand over GSO packets whole instead of segmenting them first.
const QUEUE_FLAGS: u32 = NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO;

// Transport protocol numbers.
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_AH: u8 = 51;
const IPPROTO_ICMPV6: u8 = 58;
const IPPROTO_NONE: u8 = 59;
const IPPROTO_DSTOPTS: u8 = 60;

/// What becomes of a queued packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// On to the next hook: the rest of the chain that queued it is
    /// skipped.
    Accept,
    Drop,
    /// Marked, back to the start of the chain that queued it, so its rules
    /// can act on the mark (`NF_REPEAT` with `NFQA_MARK`). The chain must
    /// not queue the marked packet again, or it loops.
    Repeat {
        mark: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    /// An ICMP or ICMPv6 echo request.
    Icmp,
}

/// The flow a queued packet belongs to, as its headers tell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    pub protocol: Protocol,
    /// For an echo request, the addresses with its identifier as both
    /// ports.
    pub source: SocketAddr,
    pub destination: SocketAddr,
    /// Whether the packet opens the flow: a TCP SYN without ACK. A UDP
    /// datagram or an echo request cannot say, and counts as first; the
    /// ruleset queues only those of flows not judged yet.
    pub first_packet: bool,
    /// Where the transport payload is in the packet: UDP's as its length
    /// field bounds it, what follows TCP's header or the echo header.
    pub payload: Range<usize>,
}

/// A packet the kernel holds until it is given a verdict.
#[derive(Clone, Debug)]
pub struct Queued {
    /// The packet's id for [`Queue::verdict`].
    pub id: u32,
    /// The netfilter hook that queued it (`NF_INET_*`).
    pub hook: u8,
    /// The link-layer protocol, as an ethertype.
    pub hw_protocol: u16,
    /// Its mark; 0 when it has none.
    pub mark: u32,
    pub in_dev: Option<u32>,
    pub out_dev: Option<u32>,
    /// The packet from its IP header on; cut short when `truncated`.
    pub packet: Vec<u8>,
    /// The kernel copied less than the whole packet.
    pub truncated: bool,
    /// A GSO packet, handed over unsegmented.
    pub gso: bool,
    /// The packet's flow, or `None` for one [`parse`] does not make out,
    /// which is to be accepted.
    pub flow: Option<Flow>,
}

fn queue_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_QUEUE << 8) | msg
}

/// Appends one `NFQNL_MSG_CONFIG` for queue `num` (0 for none) to `out`,
/// the attributes `f` writes after the `nfgenmsg`. A request the kernel
/// acknowledges, as go-nfqueue's `setConfig` sends (go-nfqueue
/// v2.0.2 nfqueue.go:178-194).
fn put_config(out: &mut Vec<u8>, seq: u32, num: u16, f: impl FnOnce(&mut Attrs)) {
    // The family is AF_UNSPEC, as sing-tun configures it.
    let mut body = Attrs::nfgen(0, num);
    f(&mut body);
    put_message(
        out,
        queue_type(NFQNL_MSG_CONFIG),
        NLM_F_REQUEST | NLM_F_ACK,
        seq,
        &body.into_bytes(),
    );
}

/// `struct nfqnl_msg_config_cmd`: the command, a pad byte, and the
/// protocol family in network order -- AF_UNSPEC.
fn config_cmd(a: &mut Attrs, cmd: u8) {
    a.bytes(NFQA_CFG_CMD, &[cmd, 0, 0, 0]);
}

/// The messages that bind queue `num` and configure it, in order, each
/// with what it does for an error to say. go-nfqueue's
/// `RegisterWithErrorFunc` (v2.0.2 nfqueue.go:115-160) sends the same, one
/// at a time and each acknowledged: unbind and bind the family (no-ops
/// since Linux 3.8, sent all the same), bind the queue, set the copy mode
/// and range, then the flags, their mask and the queue length together.
fn bind_messages(num: u16, seq: u32) -> Vec<(Vec<u8>, &'static str)> {
    let mut msgs = Vec::new();
    let mut msg = |seq: u32, what, num, f: &dyn Fn(&mut Attrs)| {
        let mut out = Vec::new();
        put_config(&mut out, seq, num, |a| f(a));
        msgs.push((out, what));
    };
    msg(seq, "unbinding the family", 0, &|a| {
        config_cmd(a, NFQNL_CFG_CMD_PF_UNBIND)
    });
    msg(seq.wrapping_add(1), "binding the family", 0, &|a| {
        config_cmd(a, NFQNL_CFG_CMD_PF_BIND)
    });
    msg(seq.wrapping_add(2), "binding the queue", num, &|a| {
        config_cmd(a, NFQNL_CFG_CMD_BIND)
    });
    msg(seq.wrapping_add(3), "setting the copy mode", num, &|a| {
        // struct nfqnl_msg_config_params, packed: the range, the mode.
        let mut params = COPY_RANGE.to_be_bytes().to_vec();
        params.push(NFQNL_COPY_PACKET);
        a.bytes(NFQA_CFG_PARAMS, &params);
    });
    msg(seq.wrapping_add(4), "setting the queue flags", num, &|a| {
        a.be32(NFQA_CFG_FLAGS, QUEUE_FLAGS)
            .be32(NFQA_CFG_MASK, QUEUE_FLAGS)
            .be32(NFQA_CFG_QUEUE_MAXLEN, QUEUE_MAXLEN);
    });
    msgs
}

/// An `NFQNL_MSG_VERDICT` for packet `id` of queue `num`: the verdict
/// header, and the mark for a repeat. Not acknowledged, as go-nfqueue's
/// `setVerdict` sends it (v2.0.2 nfqueue.go:291-333, verdict.go:19-29); a
/// verdict the kernel refuses still comes back as an error.
fn verdict_message(num: u16, seq: u32, id: u32, verdict: Verdict) -> Vec<u8> {
    let (code, mark) = match verdict {
        Verdict::Accept => (NF_ACCEPT, None),
        Verdict::Drop => (NF_DROP, None),
        Verdict::Repeat { mark } => (NF_REPEAT, Some(mark)),
    };
    let mut body = Attrs::nfgen(0, num);
    // struct nfqnl_msg_verdict_hdr: the verdict, the id, both big-endian.
    let mut hdr = code.to_be_bytes().to_vec();
    hdr.extend_from_slice(&id.to_be_bytes());
    body.bytes(NFQA_VERDICT_HDR, &hdr);
    if let Some(mark) = mark {
        body.be32(NFQA_MARK, mark);
    }
    let mut out = Vec::new();
    put_message(
        &mut out,
        queue_type(NFQNL_MSG_VERDICT),
        NLM_F_REQUEST,
        seq,
        &body.into_bytes(),
    );
    out
}

/// A queued packet from an `NFQNL_MSG_PACKET`'s body, or `None` if it has
/// no packet header -- no id to give a verdict for.
fn parse_queued(body: &[u8]) -> Option<Queued> {
    let mut queued = Queued {
        id: 0,
        hook: 0,
        hw_protocol: 0,
        mark: 0,
        in_dev: None,
        out_dev: None,
        packet: Vec::new(),
        truncated: false,
        gso: false,
        flow: None,
    };
    let mut have_id = false;
    for (ty, payload) in attrs(body.get(4..)?) {
        match ty {
            NFQA_PACKET_HDR => {
                // struct nfqnl_msg_packet_hdr, packed: the id, the
                // ethertype, the hook.
                let hdr = payload.get(..7)?;
                queued.id = u32::from_be_bytes(hdr[0..4].try_into().unwrap());
                queued.hw_protocol = u16::from_be_bytes(hdr[4..6].try_into().unwrap());
                queued.hook = hdr[6];
                have_id = true;
            }
            NFQA_MARK => queued.mark = attr_be32(payload).unwrap_or(0),
            NFQA_IFINDEX_INDEV => queued.in_dev = attr_be32(payload),
            NFQA_IFINDEX_OUTDEV => queued.out_dev = attr_be32(payload),
            NFQA_PAYLOAD => queued.packet = payload.to_vec(),
            // Sent only when the packet was cut: its whole length.
            NFQA_CAP_LEN => queued.truncated = true,
            NFQA_SKB_INFO => {
                queued.gso = attr_be32(payload).unwrap_or(0) & NFQA_SKB_GSO != 0;
            }
            _ => {}
        }
    }
    if !have_id {
        return None;
    }
    queued.flow = parse(&queued.packet);
    Some(queued)
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

/// The flow of an IPv4 or IPv6 packet: TCP, UDP, or an ICMP or ICMPv6
/// echo request. `None` for anything else, or anything too short to tell,
/// as sing-tun v0.9.6's `parsePreMatchPacket` (nfqueue_linux.go:112-213)
/// has it; except that TCP other than a SYN is a flow too, `first_packet`
/// false, where sing-tun leaves it unparsed -- either way it is accepted.
pub fn parse(packet: &[u8]) -> Option<Flow> {
    let (protocol, offset, source, destination) = match packet.first()? >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            let total = be16(packet, 2) as usize;
            // Only a first fragment has the transport header; the flags'
            // bits are shifted out.
            let fragment_offset = be16(packet, 6) << 3;
            if ihl < 20 || ihl > packet.len() || total < ihl || fragment_offset != 0 {
                return None;
            }
            let src: [u8; 4] = packet[12..16].try_into().unwrap();
            let dst: [u8; 4] = packet[16..20].try_into().unwrap();
            (
                packet[9],
                ihl,
                IpAddr::V4(Ipv4Addr::from(src)),
                IpAddr::V4(Ipv4Addr::from(dst)),
            )
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let (protocol, offset) = ipv6_transport(packet)?;
            let src: [u8; 16] = packet[8..24].try_into().unwrap();
            let dst: [u8; 16] = packet[24..40].try_into().unwrap();
            (
                protocol,
                offset,
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
            )
        }
        _ => return None,
    };
    let transport = &packet[offset..];
    let flow = |protocol, sport, dport, first_packet, payload: Range<usize>| Flow {
        protocol,
        source: SocketAddr::new(source, sport),
        destination: SocketAddr::new(destination, dport),
        first_packet,
        payload: offset + payload.start..offset + payload.end,
    };
    match protocol {
        IPPROTO_TCP => {
            if transport.len() < 20 {
                return None;
            }
            let flags = transport[13];
            let syn_only = flags & 0x02 != 0 && flags & 0x10 == 0;
            let data = ((transport[12] >> 4) as usize * 4).clamp(20, transport.len());
            Some(flow(
                Protocol::Tcp,
                be16(transport, 0),
                be16(transport, 2),
                syn_only,
                data..transport.len(),
            ))
        }
        IPPROTO_UDP => {
            if transport.len() < 8 {
                return None;
            }
            let len = be16(transport, 4) as usize;
            if len < 8 {
                return None;
            }
            Some(flow(
                Protocol::Udp,
                be16(transport, 0),
                be16(transport, 2),
                true,
                8..len.min(transport.len()),
            ))
        }
        IPPROTO_ICMP if source.is_ipv4() => {
            echo(transport, 8).map(|id| flow(Protocol::Icmp, id, id, true, 8..transport.len()))
        }
        IPPROTO_ICMPV6 if source.is_ipv6() => {
            echo(transport, 128).map(|id| flow(Protocol::Icmp, id, id, true, 8..transport.len()))
        }
        _ => None,
    }
}

/// An echo request's identifier: of type `request`, code 0.
fn echo(icmp: &[u8], request: u8) -> Option<u16> {
    if icmp.len() < 8 || icmp[0] != request || icmp[1] != 0 {
        return None;
    }
    Some(be16(icmp, 4))
}

/// The transport protocol after an IPv6 header's extension headers, and
/// where its header starts: sing-tun's `parsePreMatchIPv6Transport`
/// (nfqueue_linux.go:215-266). A fragment other than the first, no next
/// header, or a header cut short gives `None`.
fn ipv6_transport(packet: &[u8]) -> Option<(u8, usize)> {
    let mut next = packet[6];
    let mut offset = 40;
    loop {
        match next {
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                let hdr = packet.get(offset..offset + 2)?;
                let len = (hdr[1] as usize + 1) * 8;
                if packet.len() < offset + len {
                    return None;
                }
                next = hdr[0];
                offset += len;
            }
            IPPROTO_FRAGMENT => {
                let hdr = packet.get(offset..offset + 8)?;
                if be16(hdr, 2) >> 3 != 0 {
                    return None;
                }
                next = hdr[0];
                offset += 8;
            }
            IPPROTO_AH => {
                let hdr = packet.get(offset..offset + 2)?;
                let len = (hdr[1] as usize + 2) * 4;
                if packet.len() < offset + len {
                    return None;
                }
                next = hdr[0];
                offset += len;
            }
            IPPROTO_NONE => return None,
            _ => return Some((next, offset)),
        }
    }
}

#[cfg(target_os = "linux")]
pub use self::linux::Queue;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::VecDeque;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use tokio::io::unix::AsyncFd;

    use super::*;
    use crate::platform::nft::netlink::messages;
    use crate::platform::nft::socket::{first_seq, parse_error, Socket};
    use crate::platform::nft::sys::NLMSG_ERROR;

    /// Room for one packet message: the packet itself, up to the copy
    /// range, and its attributes.
    const RECV_BUF: usize = 128 * 1024;

    /// A `NETLINK_NETFILTER` socket bound to one NFQUEUE queue. Closing it
    /// -- dropping the queue -- unbinds the queue, and the kernel drops
    /// what still waits for a verdict; with the `bypass` flag on the
    /// ruleset's `queue`, packets then pass unqueued.
    pub struct Queue {
        num: u16,
        socket: AsyncFd<Socket>,
        seq: AtomicU32,
        /// Packets read but not yet handed out: those that arrived while
        /// binding, and any after the first of a datagram.
        pending: Mutex<VecDeque<Queued>>,
        buf: Mutex<Vec<u8>>,
    }

    impl Queue {
        /// Binds queue `num`, configured as sing-tun v0.9.6 has it: whole
        /// packets copied, fail-open, GSO packets unsegmented, up to 4096
        /// waiting, and no `ENOBUFS` when the socket overflows. Fails with
        /// `EPERM` if another socket has the queue, as well as without
        /// CAP_NET_ADMIN. Must be called within a Tokio runtime.
        pub fn open(num: u16) -> io::Result<Queue> {
            let socket = Socket::open()?;
            // As go-nfqueue's SetOption(netlink.NoENOBUFS) (sing-tun
            // nfqueue_linux.go:84): an overflow is not reported. With
            // fail-open the kernel accepts what it could not queue.
            socket.set_int(libc::SOL_NETLINK, libc::NETLINK_NO_ENOBUFS, 1)?;
            let mut pending = VecDeque::new();
            let seq = first_seq();
            for (i, (msg, what)) in bind_messages(num, seq).into_iter().enumerate() {
                let seq = seq.wrapping_add(i as u32);
                socket
                    .send(&msg)
                    .and_then(|()| await_ack(&socket, seq, &mut pending))
                    .map_err(|e| {
                        io::Error::new(e.kind(), format!("nfqueue {}: {}: {}", num, what, e))
                    })?;
            }
            // SAFETY: fcntl(2) on a descriptor we own.
            let ret = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Queue {
                num,
                // SAFETY: Socket owns a live OwnedFd and always returns that
                // descriptor from AsRawFd. It is nonblocking above. Queue only
                // borrows Socket for I/O; no API closes or replaces its fd while
                // this private AsyncFd owns it, including during cancellation.
                socket: unsafe { AsyncFd::register(socket)? },
                seq: AtomicU32::new(seq.wrapping_add(5)),
                pending: Mutex::new(pending),
                buf: Mutex::new(vec![0; RECV_BUF]),
            })
        }

        pub fn num(&self) -> u16 {
            self.num
        }

        /// The next packet waiting for a verdict. Cancel safe: a datagram
        /// is read and its packets kept in one go, so dropping the future
        /// loses none. An error -- a truncated or unreadable datagram,
        /// `ENOBUFS` should the kernel report one -- leaves the queue
        /// usable; call again.
        pub async fn recv(&self) -> io::Result<Queued> {
            loop {
                if let Some(queued) =
                    crate::runtime::scope::instance_lock(&self.pending, "nfqueue pending")?
                        .pop_front()
                {
                    return Ok(queued);
                }
                let mut ready = self.socket.readable().await?;
                match ready.try_io(|socket| self.read(socket.get_ref())) {
                    Ok(result) => result?,
                    Err(_would_block) => continue,
                }
            }
        }

        /// Reads one datagram and keeps its packets.
        fn read(&self, socket: &Socket) -> io::Result<()> {
            let mut buf = crate::runtime::scope::instance_lock(&self.buf, "nfqueue buffer")?;
            let n = loop {
                // SAFETY: buf is valid for its length.
                let n = unsafe {
                    libc::recv(
                        socket.as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        libc::MSG_TRUNC,
                    )
                };
                if n >= 0 {
                    break n as usize;
                }
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            };
            if n > buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("nfqueue {}: a {}-byte datagram was cut", self.num, n),
                ));
            }
            let mut pending =
                crate::runtime::scope::instance_lock(&self.pending, "nfqueue pending")?;
            keep(self.num, &buf[..n], &mut pending, None)
        }

        /// Gives packet `id` its verdict. Takes `&self` and may be called
        /// from any task, while another waits in [`Queue::recv`]. The
        /// kernel does not acknowledge it; should it refuse it -- an id it
        /// does not hold -- that is only logged, by `recv`.
        pub fn verdict(&self, id: u32, verdict: Verdict) -> io::Result<()> {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            self.socket
                .get_ref()
                .send(&verdict_message(self.num, seq, id, verdict))
        }
    }

    /// Waits, blocking, for the acknowledgement of message `seq`, keeping
    /// the packets that come in meanwhile: the queue is live from its bind
    /// on.
    fn await_ack(socket: &Socket, seq: u32, pending: &mut VecDeque<Queued>) -> io::Result<()> {
        loop {
            let dgram = socket.recv().map_err(|e| {
                if e.kind() == io::ErrorKind::WouldBlock {
                    io::Error::new(io::ErrorKind::TimedOut, "no answer from the kernel")
                } else {
                    e
                }
            })?;
            let mut acked = false;
            keep(0, &dgram, pending, Some((seq, &mut acked)))?;
            if acked {
                return Ok(());
            }
        }
    }

    /// Keeps the packets of a datagram. An error message answering `ack`'s
    /// sequence number settles it; any other is a verdict the kernel
    /// refused, and is logged.
    fn keep(
        num: u16,
        dgram: &[u8],
        pending: &mut VecDeque<Queued>,
        mut ack: Option<(u32, &mut bool)>,
    ) -> io::Result<()> {
        for msg in messages(dgram) {
            let msg = msg.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if msg.ty == queue_type(NFQNL_MSG_PACKET) {
                match parse_queued(msg.body) {
                    Some(queued) => pending.push_back(queued),
                    None => tracing::debug!("nfqueue {}: a packet without an id", num),
                }
            } else if msg.ty == NLMSG_ERROR {
                let (errno, message) = parse_error(msg.flags, msg.body)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                match &mut ack {
                    Some((seq, acked)) if msg.seq == *seq => {
                        if errno != 0 {
                            let e = io::Error::from_raw_os_error(errno);
                            return Err(match message {
                                Some(m) => io::Error::new(e.kind(), format!("{}: {}", e, m)),
                                None => e,
                            });
                        }
                        **acked = true;
                    }
                    _ if errno != 0 => {
                        tracing::debug!(
                            "nfqueue {}: a verdict was refused: {}",
                            num,
                            io::Error::from_raw_os_error(errno)
                        );
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ne16(v: u16) -> [u8; 2] {
        v.to_ne_bytes()
    }

    fn ne32(v: u32) -> [u8; 4] {
        v.to_ne_bytes()
    }

    /// A netlink header: length, type, flags, sequence, port id 0.
    fn header(len: u32, ty: u16, flags: u16, seq: u32) -> Vec<u8> {
        [
            &ne32(len)[..],
            &ne16(ty),
            &ne16(flags),
            &ne32(seq),
            &ne32(0),
        ]
        .concat()
    }

    /// What go-nfqueue v2.0.2 sends to bind a queue, one message at a
    /// time. Type 0x0302 is NFNL_SUBSYS_QUEUE << 8 | NFQNL_MSG_CONFIG
    /// (nfqueue.go:187), flags REQUEST | ACK (nfqueue.go:188); the body is
    /// the nfgenmsg (AF_UNSPEC, version 0, the queue big-endian;
    /// nfqueue.go:172-176, 183) and the attributes.
    #[test]
    fn bind_sequence_is_go_nfqueues() {
        let msgs = bind_messages(0x1234, 7);
        let what: Vec<_> = msgs.iter().map(|(_, w)| *w).collect();
        assert_eq!(
            what,
            [
                "unbinding the family",
                "binding the family",
                "binding the queue",
                "setting the copy mode",
                "setting the queue flags"
            ]
        );
        // PF_UNBIND, resource 0: {cmd, 0, 0, family} (nfqueue.go:117-119).
        let want = [
            header(28, 0x0302, 0x5, 7),
            vec![0, 0, 0, 0],
            [&ne16(8)[..], &ne16(1), &[4, 0, 0, 0]].concat(),
        ]
        .concat();
        assert_eq!(msgs[0].0, want);
        // PF_BIND (nfqueue.go:125-127).
        let want = [
            header(28, 0x0302, 0x5, 8),
            vec![0, 0, 0, 0],
            [&ne16(8)[..], &ne16(1), &[3, 0, 0, 0]].concat(),
        ]
        .concat();
        assert_eq!(msgs[1].0, want);
        // BIND, to the queue (nfqueue.go:133-135).
        let want = [
            header(28, 0x0302, 0x5, 9),
            vec![0, 0, 0x12, 0x34],
            [&ne16(8)[..], &ne16(1), &[1, 0, 0, 0]].concat(),
        ]
        .concat();
        assert_eq!(msgs[2].0, want);
        // CFG_PARAMS: the range 0xFFFF big-endian, then NFQNL_COPY_PACKET;
        // 9 bytes, padded to 12 (nfqueue.go:141-144, 264-265).
        let want = [
            header(32, 0x0302, 0x5, 10),
            vec![0, 0, 0x12, 0x34],
            [&ne16(9)[..], &ne16(2), &[0, 0, 0xff, 0xff, 2, 0, 0, 0]].concat(),
        ]
        .concat();
        assert_eq!(msgs[3].0, want);
        // CFG_FLAGS, CFG_MASK, both FAIL_OPEN | GSO = 5, then
        // CFG_QUEUE_MAXLEN 4096, all big-endian (nfqueue.go:149-157,
        // 266-271; types.go:141-148).
        let want = [
            header(44, 0x0302, 0x5, 11),
            vec![0, 0, 0x12, 0x34],
            [&ne16(8)[..], &ne16(5), &[0, 0, 0, 5]].concat(),
            [&ne16(8)[..], &ne16(4), &[0, 0, 0, 5]].concat(),
            [&ne16(8)[..], &ne16(3), &[0, 0, 0x10, 0]].concat(),
        ]
        .concat();
        assert_eq!(msgs[4].0, want);
    }

    /// go-nfqueue's SetVerdictWithOption(id, NfRepeat, WithMark(m)): type
    /// 0x0301 (NFQNL_MSG_VERDICT), REQUEST only (nfqueue.go:315-326); the
    /// nfgenmsg with the queue (nfqueue.go:312); NFQA_VERDICT_HDR {0, 0, 0,
    /// verdict, id big-endian} (nfqueue.go:303-308), then NFQA_MARK
    /// big-endian (verdict.go:19-29).
    #[test]
    fn verdict_with_a_mark_is_go_nfqueues() {
        let got = verdict_message(100, 3, 0xdeadbeef, Verdict::Repeat { mark: 0x2024 });
        let want = [
            header(40, 0x0301, 0x1, 3),
            vec![0, 0, 0, 100],
            [
                &ne16(12)[..],
                &ne16(2),
                &[0, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef],
            ]
            .concat(),
            [&ne16(8)[..], &ne16(3), &[0, 0, 0x20, 0x24]].concat(),
        ]
        .concat();
        assert_eq!(got, want);
    }

    #[test]
    fn accept_and_drop_carry_no_mark() {
        let accept = verdict_message(1, 1, 9, Verdict::Accept);
        assert_eq!(accept.len(), 32);
        assert_eq!(&accept[24..], &[0, 0, 0, 1, 0, 0, 0, 9]);
        let drop = verdict_message(1, 1, 9, Verdict::Drop);
        assert_eq!(&drop[24..], &[0, 0, 0, 0, 0, 0, 0, 9]);
    }

    fn attr(ty: u16, data: &[u8]) -> Vec<u8> {
        let mut a = [&ne16(4 + data.len() as u16)[..], &ne16(ty), data].concat();
        a.resize((a.len() + 3) & !3, 0);
        a
    }

    #[test]
    fn packet_message_is_read() {
        let packet = tcp4([10, 0, 0, 1], 40000, [1, 1, 1, 1], 443, 0x02);
        let body = [
            vec![2, 0, 0, 100],
            attr(NFQA_PACKET_HDR, &[0, 0, 0, 42, 0x08, 0x00, 3]),
            attr(NFQA_MARK, &[0, 0, 0x20, 0x23]),
            attr(NFQA_IFINDEX_OUTDEV, &[0, 0, 0, 1]),
            attr(NFQA_SKB_INFO, &[0, 0, 0, 2]),
            attr(NFQA_PAYLOAD, &packet),
        ]
        .concat();
        let q = parse_queued(&body).unwrap();
        assert_eq!(q.id, 42);
        assert_eq!(q.hw_protocol, 0x0800);
        assert_eq!(q.hook, 3);
        assert_eq!(q.mark, 0x2023);
        assert_eq!((q.in_dev, q.out_dev), (None, Some(1)));
        assert!(q.gso);
        assert!(!q.truncated);
        assert_eq!(q.packet, packet);
        let flow = q.flow.unwrap();
        assert_eq!(flow.destination, "1.1.1.1:443".parse().unwrap());

        // Without the packet header there is no id: nothing to judge.
        let body = [vec![2, 0, 0, 100], attr(NFQA_PAYLOAD, &packet)].concat();
        assert!(parse_queued(&body).is_none());
    }

    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], transport: &[u8]) -> Vec<u8> {
        let total = 20 + transport.len() as u16;
        let mut p = vec![0x45, 0];
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(transport);
        p
    }

    fn ipv6(next: u8, src: &str, dst: &str, rest: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        p.extend_from_slice(&[next, 64]);
        p.extend_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(rest);
        p
    }

    fn tcp(sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&[0; 8]);
        t.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        t
    }

    fn tcp4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
        ipv4(IPPROTO_TCP, src, dst, &tcp(sport, dport, flags))
    }

    fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = Vec::new();
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        u
    }

    #[test]
    fn tcp_syn_is_first_but_not_syn_ack_or_data() {
        let syn = parse(&tcp4([10, 0, 0, 1], 40000, [1, 1, 1, 1], 443, 0x02)).unwrap();
        assert_eq!(syn.protocol, Protocol::Tcp);
        assert_eq!(syn.source, "10.0.0.1:40000".parse().unwrap());
        assert_eq!(syn.destination, "1.1.1.1:443".parse().unwrap());
        assert!(syn.first_packet);
        assert_eq!(syn.payload, 40..40);
        // SYN with ECN bits (ECE, CWR) is still a SYN.
        assert!(
            parse(&tcp4([10, 0, 0, 1], 1, [1, 1, 1, 1], 2, 0xc2))
                .unwrap()
                .first_packet
        );
        let syn_ack = parse(&tcp4([1, 1, 1, 1], 443, [10, 0, 0, 1], 40000, 0x12)).unwrap();
        assert!(!syn_ack.first_packet);
        let data = parse(&tcp4([10, 0, 0, 1], 40000, [1, 1, 1, 1], 443, 0x18)).unwrap();
        assert!(!data.first_packet);
    }

    #[test]
    fn tcp_payload_follows_the_options() {
        let mut t = tcp(1, 2, 0x02);
        t[12] = 0x60;
        t.extend_from_slice(&[2, 4, 5, 0xb4, b'h', b'i']);
        let flow = parse(&ipv4(IPPROTO_TCP, [1; 4], [2; 4], &t)).unwrap();
        assert_eq!(flow.payload, 44..46);
    }

    #[test]
    fn udp_payload_is_bounded_by_its_length() {
        let mut u = udp(5353, 53, b"query");
        u.extend_from_slice(b"trailer");
        let packet = ipv4(IPPROTO_UDP, [10, 0, 0, 1], [8, 8, 8, 8], &u);
        let flow = parse(&packet).unwrap();
        assert_eq!(flow.protocol, Protocol::Udp);
        assert_eq!(flow.source, "10.0.0.1:5353".parse().unwrap());
        assert_eq!(flow.destination, "8.8.8.8:53".parse().unwrap());
        assert!(flow.first_packet);
        assert_eq!(&packet[flow.payload], b"query");
        // A length below the header's own is nonsense.
        let mut bad = udp(1, 2, b"");
        bad[5] = 7;
        assert!(parse(&ipv4(IPPROTO_UDP, [1; 4], [2; 4], &bad)).is_none());
    }

    #[test]
    fn icmp_echo_has_its_identifier_as_ports() {
        let echo = [8, 0, 0, 0, 0x12, 0x34, 0, 1, b'p'];
        let flow = parse(&ipv4(IPPROTO_ICMP, [10, 0, 0, 1], [1, 1, 1, 1], &echo)).unwrap();
        assert_eq!(flow.protocol, Protocol::Icmp);
        assert_eq!(flow.source, "10.0.0.1:4660".parse().unwrap());
        assert_eq!(flow.destination, "1.1.1.1:4660".parse().unwrap());
        assert_eq!(flow.payload, 28..29);
        // A reply, or a code other than 0, is not a flow.
        let reply = [0, 0, 0, 0, 0x12, 0x34, 0, 1];
        assert!(parse(&ipv4(IPPROTO_ICMP, [1; 4], [2; 4], &reply)).is_none());
        let odd = [8, 1, 0, 0, 0x12, 0x34, 0, 1];
        assert!(parse(&ipv4(IPPROTO_ICMP, [1; 4], [2; 4], &odd)).is_none());

        let echo6 = [128, 0, 0, 0, 0xab, 0xcd, 0, 1];
        let flow = parse(&ipv6(IPPROTO_ICMPV6, "fd00::1", "2001:db8::1", &echo6)).unwrap();
        assert_eq!(flow.protocol, Protocol::Icmp);
        assert_eq!(flow.source, "[fd00::1]:43981".parse().unwrap());
        // ICMPv6 over IPv4, ICMP over IPv6: no.
        assert!(parse(&ipv4(IPPROTO_ICMPV6, [1; 4], [2; 4], &echo6)).is_none());
        assert!(parse(&ipv6(IPPROTO_ICMP, "::1", "::2", &echo)).is_none());
        // Short of the identifier.
        assert!(parse(&ipv6(IPPROTO_ICMPV6, "::1", "::2", &echo6[..6])).is_none());
    }

    #[test]
    fn ipv6_tcp() {
        let p = ipv6(
            IPPROTO_TCP,
            "fd00::1",
            "2001:db8::2",
            &tcp(40000, 443, 0x02),
        );
        let flow = parse(&p).unwrap();
        assert_eq!(flow.source, "[fd00::1]:40000".parse().unwrap());
        assert_eq!(flow.destination, "[2001:db8::2]:443".parse().unwrap());
        assert!(flow.first_packet);
        assert_eq!(flow.payload, 60..60);
    }

    #[test]
    fn ipv6_extension_headers_are_walked() {
        // Hop-by-hop (8 bytes), routing (24), a first fragment (8),
        // AH (payload length 4: (4 + 2) * 4 = 24), destination options (16).
        let mut rest = vec![IPPROTO_ROUTING, 0, 1, 4, 0, 0, 0, 0];
        rest.extend_from_slice(&[IPPROTO_FRAGMENT, 2]);
        rest.extend_from_slice(&[0; 22]);
        rest.extend_from_slice(&[IPPROTO_AH, 0, 0, 1, 0, 0, 0, 7]);
        rest.extend_from_slice(&[IPPROTO_DSTOPTS, 4]);
        rest.extend_from_slice(&[0; 22]);
        rest.extend_from_slice(&[IPPROTO_UDP, 1]);
        rest.extend_from_slice(&[0; 14]);
        rest.extend_from_slice(&udp(1000, 53, b"q"));
        let p = ipv6(IPPROTO_HOPOPTS, "fd00::1", "fd00::2", &rest);
        let flow = parse(&p).unwrap();
        assert_eq!(flow.protocol, Protocol::Udp);
        assert_eq!(flow.destination, "[fd00::2]:53".parse().unwrap());
        assert_eq!(&p[flow.payload], b"q");

        // A later fragment has no transport header.
        let mut frag = vec![IPPROTO_TCP, 0, 0, 8, 0, 0, 0, 1];
        frag.extend_from_slice(&tcp(1, 2, 0x02));
        assert!(parse(&ipv6(IPPROTO_FRAGMENT, "::1", "::2", &frag)).is_none());
        // No next header.
        assert!(parse(&ipv6(IPPROTO_NONE, "::1", "::2", &[0; 20])).is_none());
        // An extension header running past the packet.
        let long = [IPPROTO_TCP, 3, 0, 0, 0, 0, 0, 0];
        assert!(parse(&ipv6(IPPROTO_DSTOPTS, "::1", "::2", &long)).is_none());
        // An unknown next header is taken as the transport, and not one
        // this reads.
        assert!(parse(&ipv6(132, "::1", "::2", &[0; 20])).is_none());
    }

    #[test]
    fn truncated_or_odd_packets_are_not_flows() {
        let syn = tcp4([10, 0, 0, 1], 40000, [1, 1, 1, 1], 443, 0x02);
        for len in 0..40 {
            assert!(parse(&syn[..len]).is_none(), "{} bytes", len);
        }
        let syn6 = ipv6(IPPROTO_TCP, "::1", "::2", &tcp(1, 2, 0x02));
        for len in 0..60 {
            assert!(parse(&syn6[..len]).is_none(), "{} bytes", len);
        }
        let dgram = ipv4(IPPROTO_UDP, [1; 4], [2; 4], &udp(1, 2, b""));
        assert!(parse(&dgram[..27]).is_none());
        // Version 5.
        let mut odd = syn.clone();
        odd[0] = 0x55;
        assert!(parse(&odd).is_none());
        // A header length under 20, or past the packet.
        odd[0] = 0x44;
        assert!(parse(&odd).is_none());
        odd[0] = 0x4f;
        assert!(parse(&odd[..40]).is_none());
        // A total length under the header's.
        let mut odd = syn.clone();
        odd[2..4].copy_from_slice(&[0, 19]);
        assert!(parse(&odd).is_none());
        // A later fragment; a first one with more to come is fine, and DF
        // does not count.
        let mut frag = syn.clone();
        frag[6..8].copy_from_slice(&[0x20, 0x01]);
        assert!(parse(&frag).is_none());
        frag[6..8].copy_from_slice(&[0x60, 0x00]);
        assert!(parse(&frag).is_some());
        // Some other protocol.
        assert!(parse(&ipv4(47, [1; 4], [2; 4], &[0; 20])).is_none());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod kernel_tests {
    use std::io;
    use std::net::SocketAddr;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::platform::nft::{
        self, cmp, host_u32, meta_cmp, port, Batch, Chain, ChainType, CmpOp, Expr, Family, Hook,
        MetaKey, PayloadBase, Reg, RejectKind, Table, QUEUE_FLAG_BYPASS,
    };

    const QUEUE: u16 = 4242;
    const TABLE: &str = "sail-nfq-test";
    /// A repeat with this mark meets a rule that resets the connection.
    const MARK_RESET: u32 = 0x77;
    /// A repeat with this mark meets a rule that lets it through.
    const MARK_PASS: u32 = 0x78;

    /// In the output hook: marked SYNs are reset or passed, and any other
    /// TCP SYN to port 7 is queued, bypassed when no one listens.
    fn install_rules() {
        const TCP: u8 = 6;
        let t = Table::new(Family::Inet, TABLE);
        let mut b = Batch::new();
        b.del_table_if_exists(&t);
        b.add_table(&t);
        b.add_chain(
            &t,
            &Chain::base("output", ChainType::Filter, Hook::Output, 0),
        );
        let tcp = meta_cmp(MetaKey::L4Proto, CmpOp::Eq, vec![TCP]);
        let mut reset = tcp.to_vec();
        reset.extend(meta_cmp(MetaKey::Mark, CmpOp::Eq, host_u32(MARK_RESET)));
        reset.extend([
            Expr::Counter,
            Expr::Reject {
                kind: RejectKind::TcpRst,
                code: 0,
            },
        ]);
        b.add_rule(&t, "output", &reset);
        let mut pass = meta_cmp(MetaKey::Mark, CmpOp::Eq, host_u32(MARK_PASS)).to_vec();
        pass.extend([Expr::Counter, nft::verdict(nft::Verdict::Accept)]);
        b.add_rule(&t, "output", &pass);
        let mut queue = tcp.to_vec();
        queue.extend([
            Expr::Payload {
                base: PayloadBase::Transport,
                offset: 2,
                len: 2,
                dreg: Reg::R1,
            },
            cmp(CmpOp::Eq, port(7)),
            Expr::Payload {
                base: PayloadBase::Transport,
                offset: 13,
                len: 1,
                dreg: Reg::R1,
            },
            Expr::Bitwise {
                sreg: Reg::R1,
                dreg: Reg::R1,
                len: 1,
                mask: vec![0x12],
                xor: vec![0],
            },
            cmp(CmpOp::Eq, vec![0x02]),
            Expr::Counter,
            Expr::Queue {
                num: QUEUE,
                total: 1,
                flags: QUEUE_FLAG_BYPASS,
            },
        ]);
        b.add_rule(&t, "output", &queue);
        b.commit().unwrap_or_else(|e| panic!("commit: {}", e));
    }

    /// nft(8)'s listing of the table, if `$SAIL_NFT` names one: each mark
    /// rule met the one SYN repeated with its mark.
    fn check_counters() {
        if let Ok(nft) = std::env::var("SAIL_NFT") {
            let out = Command::new(nft)
                .args(["list", "table", "inet", TABLE])
                .output()
                .unwrap();
            let listing = String::from_utf8_lossy(&out.stdout);
            println!("{}", listing);
            for mark in [MARK_RESET, MARK_PASS] {
                let counted = format!("meta mark {:#010x} counter packets 1 ", mark);
                assert!(listing.contains(&counted), "{}", counted);
            }
        }
    }

    async fn connect(to: SocketAddr, within: Duration) -> io::Result<TcpStream> {
        timeout(within, TcpStream::connect(to))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))?
    }

    async fn next(rx: &mut mpsc::UnboundedReceiver<Queued>) -> Queued {
        timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("a packet is queued")
            .expect("the reader runs")
    }

    fn syn_to(q: &Queued, to: SocketAddr) -> Flow {
        let flow = q.flow.clone().expect("a flow");
        assert_eq!(flow.protocol, Protocol::Tcp);
        assert_eq!(flow.destination, to);
        assert!(flow.first_packet, "{:?}", flow);
        flow
    }

    /// Runs as root in a network namespace of its own, with nf_tables and
    /// nfnetlink_queue loaded:
    ///
    /// ```text
    /// modprobe nfnetlink_queue; modprobe nft_queue
    /// ip netns add sail-nfq-test
    /// ip netns exec sail-nfq-test <test binary> --ignored --exact --nocapture \
    ///     platform::nfqueue::kernel_tests::verdicts
    /// ip netns del sail-nfq-test
    /// ```
    #[test]
    #[ignore = "requires root, nf_tables and nfnetlink_queue"]
    fn verdicts() {
        let status = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap();
        assert!(status.success());
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:7").await.unwrap();
            let listener6 = TcpListener::bind("[::1]:7").await.unwrap();
            for l in [listener, listener6] {
                tokio::spawn(async move {
                    loop {
                        let _ = l.accept().await;
                    }
                });
            }
            let v4: SocketAddr = "127.0.0.1:7".parse().unwrap();
            let v6: SocketAddr = "[::1]:7".parse().unwrap();
            install_rules();

            // No queue bound: `bypass` lets the SYN through.
            connect(v4, Duration::from_secs(2))
                .await
                .expect("bypassed while no queue is bound");
            println!("unbound: bypassed");

            let queue = Arc::new(Queue::open(QUEUE).expect("open the queue"));
            // A second socket cannot have the same queue: the kernel says
            // EPERM, not EBUSY, when another port id holds it.
            let err = Queue::open(QUEUE).err().expect("the queue is taken");
            println!("second open: {}", err);
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

            // A task that only reads, forever pending in recv between
            // packets; the verdicts are given elsewhere.
            let (tx, mut rx) = mpsc::unbounded_channel();
            let reader = tokio::spawn({
                let queue = queue.clone();
                async move {
                    loop {
                        match queue.recv().await {
                            Ok(q) => {
                                if tx.send(q).is_err() {
                                    return;
                                }
                            }
                            Err(e) => println!("recv: {}", e),
                        }
                    }
                }
            });

            // Accept, given from this task.
            let client = tokio::spawn(connect(v4, Duration::from_secs(3)));
            let q = next(&mut rx).await;
            let flow = syn_to(&q, v4);
            println!("accept: queued {:?}", q);
            queue.verdict(q.id, Verdict::Accept).unwrap();
            let stream = client.await.unwrap().expect("accepted");
            assert_eq!(flow.source, stream.local_addr().unwrap());
            assert!(!reader.is_finished());

            // Accept, IPv6, given from a task of its own.
            let client = tokio::spawn(connect(v6, Duration::from_secs(3)));
            let q = next(&mut rx).await;
            let flow = syn_to(&q, v6);
            println!("accept v6: queued {:?}", flow);
            tokio::spawn({
                let queue = queue.clone();
                async move { queue.verdict(q.id, Verdict::Accept) }
            })
            .await
            .unwrap()
            .unwrap();
            let stream = client.await.unwrap().expect("accepted");
            assert_eq!(flow.source, stream.local_addr().unwrap());

            // Repeat with the pass mark: the chain runs again, and its
            // rule for the mark accepts the SYN before it is queued again.
            let client = tokio::spawn(connect(v4, Duration::from_secs(3)));
            let q = next(&mut rx).await;
            syn_to(&q, v4);
            queue
                .verdict(q.id, Verdict::Repeat { mark: MARK_PASS })
                .unwrap();
            client.await.unwrap().expect("passed by the mark");
            println!("repeat {:#x}: passed", MARK_PASS);

            // Repeat with the reset mark: the chain's rule for it answers
            // with a reset, so the mark was set and the chain re-run.
            let client = tokio::spawn(connect(v4, Duration::from_secs(3)));
            let q = next(&mut rx).await;
            syn_to(&q, v4);
            queue
                .verdict(q.id, Verdict::Repeat { mark: MARK_RESET })
                .unwrap();
            let err = client.await.unwrap().expect_err("reset by the mark");
            println!("repeat {:#x}: {}", MARK_RESET, err);
            assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);

            // Drop: the SYN and its retransmissions are dropped, and the
            // connect times out.
            let client = tokio::spawn(connect(v4, Duration::from_millis(2500)));
            let mut dropped = 0;
            while !client.is_finished() {
                if let Ok(Some(q)) = timeout(Duration::from_millis(100), rx.recv()).await {
                    syn_to(&q, v4);
                    queue.verdict(q.id, Verdict::Drop).unwrap();
                    dropped += 1;
                }
            }
            let err = client.await.unwrap().expect_err("dropped");
            println!("drop: {} SYNs dropped, {}", dropped, err);
            assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            // The first SYN and the retransmission a second later.
            assert!(dropped >= 2, "{}", dropped);

            check_counters();

            // Unbound again, by closing: bypassed again.
            reader.abort();
            let _ = reader.await;
            drop(rx);
            let queue = Arc::try_unwrap(queue).ok().expect("the last reference");
            drop(queue);
            connect(v4, Duration::from_secs(2))
                .await
                .expect("bypassed once the queue is closed");
            println!("closed: bypassed");

            let mut del = Batch::new();
            del.del_table(&Table::new(Family::Inet, TABLE));
            del.commit().unwrap();
        });
    }
}
