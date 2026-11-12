use std::io;

#[cfg(not(target_os = "windows"))]
use futures::FutureExt;
#[cfg(target_os = "linux")]
use sail_netstack::{parse_ip_packet, parse_tcp_segment};
use sail_netstack::{
    ChecksumCapabilities, Packet, PacketBatch, PacketCapabilities, PacketIo, PacketToken,
};
#[cfg(not(target_os = "windows"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(not(target_os = "windows"))]
use crate::net::accept::AcceptBackoff;

/// The tun crate borrows the transferred descriptor (`close_fd_on_drop(false)`).
/// This is its sole owner through construction, all actual I/O shards and Drop.
/// Field order matters: I/O releases all its borrowed handles before the FD.
#[cfg(unix)]
pub(crate) struct OwnedHostIo<I> {
    io: I,
    _descriptor: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl<I> OwnedHostIo<I> {
    pub(crate) fn open(
        descriptor: std::os::fd::OwnedFd,
        build: impl FnOnce(std::os::fd::RawFd) -> anyhow::Result<I>,
    ) -> anyhow::Result<Self> {
        use std::os::fd::AsRawFd;
        let io = build(descriptor.as_raw_fd())?;
        Ok(Self {
            io,
            _descriptor: descriptor,
        })
    }
}

#[cfg(unix)]
impl<I: PacketIo> PacketIo for OwnedHostIo<I> {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        self.io.recv(out).await
    }
    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        self.io.send(packets).await
    }
    fn capabilities(&self) -> PacketCapabilities {
        self.io.capabilities()
    }
    fn owns_flow(&self, endpoint: sail_netstack::IpEndpoint) -> bool {
        self.io.owns_flow(endpoint)
    }
}

#[cfg(not(target_os = "windows"))]
pub(crate) struct TunPacketIo {
    writer: tun::DeviceWriter,
    reader: tun::DeviceReader,
    recv_buffer: Vec<u8>,
    max_batch: usize,
    next_token: u64,
    pending_recv_error: Option<io::Error>,
    pending_send_error: Option<io::Error>,
    /// Waits out a failed read, so the TUN serves on through one.
    recv_backoff: AcceptBackoff,
}

#[cfg(not(target_os = "windows"))]
impl TunPacketIo {
    pub(crate) fn new(device: tun::AsyncDevice, mtu: usize, max_batch: usize) -> io::Result<Self> {
        if max_batch == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo batch size must be non-zero",
            ));
        }
        let (writer, reader) = device.split()?;
        Ok(Self {
            writer,
            reader,
            recv_buffer: vec![0; mtu],
            max_batch,
            next_token: 0,
            pending_recv_error: None,
            pending_send_error: None,
            recv_backoff: AcceptBackoff::new("tun: read"),
        })
    }

    fn push_received(&mut self, out: &mut PacketBatch, count: usize) -> io::Result<()> {
        let token = PacketToken::new(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        out.push(Packet::from_payload(token, 0, &self.recv_buffer[..count]))
            .map_err(|_| io::Error::other("native PacketIo receive batch is full"))
    }
}

#[cfg(not(target_os = "windows"))]
impl PacketIo for TunPacketIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        if let Some(error) = self.pending_recv_error.take() {
            // The device's end ends the runner; anything else is waited
            // out, and read past.
            self.recv_backoff.failed(error).await?;
        }
        let initial_len = out.len();
        let receive_limit = self.max_batch.min(out.limit().saturating_sub(initial_len));
        if receive_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo receive batch has no free slots",
            ));
        }
        let count = loop {
            match self.reader.read(&mut self.recv_buffer).await {
                Ok(count) => break count,
                Err(error) => self.recv_backoff.failed(error).await?,
            }
        };
        self.recv_backoff.succeeded();
        if count == 0 {
            return Ok(0);
        }
        self.push_received(out, count)?;
        while out.len().saturating_sub(initial_len) < receive_limit {
            match self.reader.read(&mut self.recv_buffer).now_or_never() {
                None => break,
                Some(Ok(0)) => {
                    self.pending_recv_error = Some(io::Error::from(io::ErrorKind::UnexpectedEof));
                    break;
                }
                Some(Ok(count)) => self.push_received(out, count)?,
                Some(Err(error)) => {
                    self.pending_recv_error = Some(error);
                    break;
                }
            }
        }
        Ok(out.len().saturating_sub(initial_len))
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        if let Some(error) = self.pending_send_error.take() {
            return Err(error);
        }
        let mut sent = 0;
        for packet in packets.iter() {
            // PacketIo cancellation: await only before the first packet is
            // accepted, then report a partial send instead of waiting.
            let result = if sent == 0 {
                self.writer.write(packet.payload()).await
            } else {
                match self.writer.write(packet.payload()).now_or_never() {
                    Some(result) => result,
                    None => break,
                }
            };
            let error = match result {
                Ok(written) if written == packet.payload().len() => {
                    sent += 1;
                    continue;
                }
                Ok(_) => io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TUN device accepted a partial packet",
                ),
                Err(error) => error,
            };
            if sent == 0 {
                return Err(error);
            }
            self.pending_send_error = Some(error);
            break;
        }
        Ok(sent)
    }

    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: self.max_batch,
            queue_count: 1,
            headroom: 0,
            vectored: false,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}

/// A wait on a blocking thread that outlives the future awaiting it: a
/// receive dropped while it waits, as the runtime drops it many times a
/// second, leaves the thread to the next receive rather than starting
/// another, so at most one is ever parked.
#[cfg(any(target_os = "windows", test))]
struct BlockingWait<T> {
    waiting: Option<tokio::task::JoinHandle<T>>,
}

#[cfg(any(target_os = "windows", test))]
impl<T: Send + 'static> BlockingWait<T> {
    fn new() -> Self {
        Self { waiting: None }
    }

    /// Waits for `wait`, run on a blocking thread, or for the one a
    /// dropped call started.
    async fn wait(&mut self, wait: impl FnOnce() -> T + Send + 'static) -> io::Result<T> {
        let waiting = self
            .waiting
            .get_or_insert_with(|| crate::runtime::scope::spawn_blocking("tun blocking io", wait));
        // Awaiting the handle by reference is cancel-safe: dropped here,
        // the same thread is awaited next time.
        let result = waiting.await;
        self.waiting = None;
        result.map_err(io::Error::other)
    }
}

/// The TUN of a wintun session (Windows): packets from its ring, waited
/// for on a blocking thread when there are none.
#[cfg(target_os = "windows")]
pub(crate) struct WintunPacketIo {
    session: std::sync::Arc<wintun_bindings::Session>,
    recv_buffer: Vec<u8>,
    max_batch: usize,
    next_token: u64,
    wait: BlockingWait<Result<(), wintun_bindings::Error>>,
}

#[cfg(target_os = "windows")]
impl WintunPacketIo {
    pub(crate) fn new(
        session: std::sync::Arc<wintun_bindings::Session>,
        max_batch: usize,
    ) -> io::Result<Self> {
        if max_batch == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo batch size must be non-zero",
            ));
        }
        Ok(Self {
            session,
            // wintun's largest packet (WINTUN_MAX_IP_PACKET_SIZE): Windows
            // may hand it one above the MTU, which a smaller buffer would
            // make it drop, with an error.
            recv_buffer: vec![0; usize::from(u16::MAX)],
            max_batch,
            next_token: 0,
            wait: BlockingWait::new(),
        })
    }

    fn push_received(&mut self, out: &mut PacketBatch, count: usize) -> io::Result<()> {
        let token = PacketToken::new(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        out.push(Packet::from_payload(token, 0, &self.recv_buffer[..count]))
            .map_err(|_| io::Error::other("native PacketIo receive batch is full"))
    }
}

#[cfg(target_os = "windows")]
impl Drop for WintunPacketIo {
    fn drop(&mut self) {
        // A thread waiting for packets returns.
        let _ = self.session.shutdown();
    }
}

#[cfg(target_os = "windows")]
impl PacketIo for WintunPacketIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        let initial_len = out.len();
        let receive_limit = self.max_batch.min(out.limit().saturating_sub(initial_len));
        if receive_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo receive batch has no free slots",
            ));
        }
        loop {
            match self.session.try_recv(&mut self.recv_buffer) {
                Ok(count) => {
                    self.push_received(out, count)?;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let session = self.session.clone();
                    self.wait
                        .wait(move || session.wait_read())
                        .await?
                        .map_err(io::Error::other)?;
                }
                // Too large for the buffer: wintun dropped it already.
                Err(e) if e.kind() == io::ErrorKind::InvalidInput => {}
                Err(e) => return Err(e),
            }
        }
        while out.len().saturating_sub(initial_len) < receive_limit {
            match self.session.try_recv(&mut self.recv_buffer) {
                Ok(count) => self.push_received(out, count)?,
                Err(_) => break,
            }
        }
        Ok(out.len().saturating_sub(initial_len))
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        let mut sent = 0;
        for packet in packets.iter() {
            match self.session.send(packet.payload()) {
                Ok(_) => sent += 1,
                // A full ring drops the packet, as a full queue does.
                Err(e) if crate::platform::windows::wintun::ring_full(&e) => sent += 1,
                Err(e) if sent == 0 => return Err(e),
                Err(_) => break,
            }
        }
        Ok(sent)
    }

    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: self.max_batch,
            queue_count: 1,
            headroom: 0,
            vectored: false,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}

/// The virtio-net header of one packet, not a GSO frame: its checksums
/// valid (sail computed them), and the length of its IP and TCP or UDP
/// headers, which the kernel then puts in the skb's linear part. With 0
/// there, the default, the kernel puts the whole packet in page fragments
/// and every layer after pulls the headers out of them again, which cost a
/// TUN's download about a fifth (measured: zero-window advertisements went
/// up eightfold).
#[cfg(target_os = "linux")]
fn plain_header(packet: &[u8]) -> [u8; tun_rs::VIRTIO_NET_HDR_LEN] {
    const DATA_VALID: u8 = 2;
    let headers = parse_ip_packet(packet, false).ok().map_or(0, |ip| {
        // Where the transport header starts: bytes after the IP packet's
        // own length are not headers.
        let ip_header = ip.payload.as_ptr() as usize - packet.as_ptr() as usize;
        let transport = match ip.next_header {
            6 => ip
                .payload
                .get(12)
                .map_or(0, |offset| usize::from(offset >> 4) * 4),
            17 => 8,
            _ => 0,
        };
        (ip_header + transport).min(packet.len())
    });
    let mut header = [0; tun_rs::VIRTIO_NET_HDR_LEN];
    let _ = tun_rs::VirtioNetHdr {
        flags: DATA_VALID,
        // VIRTIO_NET_HDR_GSO_NONE, which tun_rs does not export.
        gso_type: 0,
        hdr_len: u16::try_from(headers).unwrap_or(0),
        gso_size: 0,
        csum_start: 0,
        csum_offset: 0,
    }
    .encode(&mut header);
    header
}

/// A TCP segment with a payload: its flow, by addresses and ports. The
/// stack made it, so its checksums are not checked again.
#[cfg(target_os = "linux")]
fn tcp_flow(packet: &[u8]) -> Option<(std::net::SocketAddr, std::net::SocketAddr)> {
    let segment = parse_tcp_segment(parse_ip_packet(packet, false).ok()?, false).ok()?;
    (!segment.payload.is_empty()).then_some((segment.source, segment.destination))
}

/// A batch's packets as they go out: each flow's TCP segments together, at
/// its first segment's place, to be coalesced into one frame; anything
/// else alone. A batch of several flows coalesces flow by flow, as
/// wireguard-go's does, where one frame for all of it never can.
#[cfg(target_os = "linux")]
fn flow_groups(payloads: &[&[u8]]) -> Vec<Vec<usize>> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut flows: Vec<((std::net::SocketAddr, std::net::SocketAddr), usize)> = Vec::new();
    for (index, payload) in payloads.iter().enumerate() {
        let Some(flow) = tcp_flow(payload) else {
            groups.push(vec![index]);
            continue;
        };
        // A batch holds a few flows: a scan beats a map.
        match flows.iter().find(|(f, _)| *f == flow) {
            Some(&(_, group)) => groups[group].push(index),
            None => {
                flows.push((flow, groups.len()));
                groups.push(vec![index]);
            }
        }
    }
    groups
}

/// A flow's segments, in order, as the runs a GSO frame each can carry:
/// a frame holds at most 64 KiB (7 segments at an MTU of 9000), and GRO
/// ends one at a segment shorter than its first, or at one with PSH. A
/// flow's batch beyond one frame was written a segment at a time before:
/// at an MTU of 9000 nearly every download batch, which offload then cost
/// a tenth of the download (2026-10-14). Sequence numbers are not checked:
/// a run with a retransmitted segment in it does not coalesce, and goes
/// out a segment at a time, as rare as retransmissions are.
#[cfg(target_os = "linux")]
fn frame_runs(segments: &[&[u8]]) -> Vec<std::ops::Range<usize>> {
    const PSH: u8 = 0x08;
    // A segment's payload, the bytes before it, and whether it has PSH.
    let shape = |segment: &[u8]| {
        let tcp = parse_tcp_segment(parse_ip_packet(segment, false).ok()?, false).ok()?;
        let payload = tcp.payload.len();
        Some((
            payload,
            segment.len() - payload,
            tcp.meta.flags.bits() & PSH != 0,
        ))
    };
    let mut runs = Vec::new();
    let mut start = 0;
    while start < segments.len() {
        let mut end = start + 1;
        if let Some((first, headers, false)) = shape(segments[start]).filter(|s| s.0 > 0) {
            let mut length = headers + first;
            while let Some((size, _, push)) = segments.get(end).and_then(|s| shape(s)) {
                if size == 0 || size > first || length + size > usize::from(u16::MAX) {
                    break;
                }
                length += size;
                end += 1;
                if size < first || push {
                    break;
                }
            }
        }
        runs.push(start..end);
        start = end;
    }
    runs
}

/// Coalesces `payloads`, segments of one flow, into one GSO frame in
/// `buffers`: its index, or none if they do not make exactly one.
#[cfg(target_os = "linux")]
fn prepare_coalesced_tcp_batch(
    gro_table: &mut tun_rs::GROTable,
    buffers: &mut [Vec<u8>],
    payloads: &[&[u8]],
) -> Option<usize> {
    let count = payloads.len();
    if count < 2 || count > buffers.len() {
        return None;
    }
    let mut original_payload_bytes = 0_usize;
    for (buffer, payload) in buffers.iter_mut().zip(payloads).take(count) {
        let segment = parse_tcp_segment(parse_ip_packet(payload, false).ok()?, false).ok()?;
        if segment.payload.is_empty() {
            return None;
        }
        original_payload_bytes = original_payload_bytes.checked_add(segment.payload.len())?;
        buffer.clear();
        buffer.resize(tun_rs::VIRTIO_NET_HDR_LEN, 0);
        buffer.extend_from_slice(payload);
    }
    gro_table
        .apply_gro(&mut buffers[..count], tun_rs::VIRTIO_NET_HDR_LEN, false)
        .ok()?;

    let mut candidate = None;
    for (index, buffer) in buffers[..count].iter().enumerate() {
        let header = tun_rs::VirtioNetHdr::decode(buffer).ok()?;
        let gso_type = header.gso_type & 0x7f;
        if !matches!(
            gso_type,
            tun_rs::VIRTIO_NET_HDR_GSO_TCPV4 | tun_rs::VIRTIO_NET_HDR_GSO_TCPV6
        ) {
            continue;
        }
        if candidate.is_some() || header.gso_size == 0 {
            return None;
        }
        let header_bytes = usize::from(header.hdr_len);
        let payload_bytes = buffer
            .len()
            .checked_sub(tun_rs::VIRTIO_NET_HDR_LEN + header_bytes)?;
        let segment_size = usize::from(header.gso_size);
        if payload_bytes != original_payload_bytes || payload_bytes.div_ceil(segment_size) != count
        {
            return None;
        }
        candidate = Some(index);
    }
    candidate
}

#[cfg(target_os = "linux")]
pub(crate) struct TunRsPacketIo {
    device: tun_rs::AsyncDevice,
    recv_buffer: Vec<u8>,
    offload_buffer: Vec<u8>,
    offload_send_packets: Vec<Vec<u8>>,
    offload_packets: Vec<Vec<u8>>,
    offload_sizes: Vec<usize>,
    pending_packet_index: usize,
    pending_packet_count: usize,
    gro_table: tun_rs::GROTable,
    offload: bool,
    max_batch: usize,
    queue_count: usize,
    next_token: u64,
    pending_recv_error: Option<io::Error>,
    pending_send_error: Option<io::Error>,
    /// Waits out a failed read, so the TUN serves on through one.
    recv_backoff: AcceptBackoff,
}

#[cfg(target_os = "linux")]
impl TunRsPacketIo {
    pub(crate) fn new(
        device: tun_rs::AsyncDevice,
        mtu: usize,
        max_batch: usize,
        queue_count: usize,
        offload: bool,
    ) -> io::Result<Self> {
        if mtu == 0 || max_batch == 0 || queue_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo MTU, batch size, and queue count must be non-zero",
            ));
        }
        let required_segments = 65_535 / mtu + 1;
        if offload && max_batch < required_segments {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "native PacketIo offload requires at least {required_segments} packet buffers"
                ),
            ));
        }
        Ok(Self {
            device,
            recv_buffer: vec![0; mtu],
            offload_buffer: vec![0; tun_rs::VIRTIO_NET_HDR_LEN + 65_535],
            offload_send_packets: (0..max_batch)
                .map(|index| {
                    let packet_capacity = if index == 0 { 65_535 } else { mtu };
                    Vec::with_capacity(2 * tun_rs::VIRTIO_NET_HDR_LEN + packet_capacity)
                })
                .collect(),
            offload_packets: (0..max_batch).map(|_| vec![0; mtu]).collect(),
            offload_sizes: vec![0; max_batch],
            pending_packet_index: 0,
            pending_packet_count: 0,
            gro_table: tun_rs::GROTable::default(),
            offload,
            max_batch,
            queue_count,
            next_token: 0,
            pending_recv_error: None,
            pending_send_error: None,
            recv_backoff: AcceptBackoff::new("tun: read"),
        })
    }

    /// Sends `packets` with offload: each flow's TCP segments as one GSO
    /// frame where they make one, anything else a packet a write. Only the
    /// first write waits; a later one that would block ends the send, and
    /// the count is of the batch's packets written from its start. The
    /// frames go out flow by flow, so a send ended early may have written
    /// segments past that count too, which the retry sends again: the
    /// receiver takes them as TCP retransmissions. A TUN's write blocks
    /// only when the kernel is out of buffers.
    async fn send_coalesced(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        let payloads: Vec<&[u8]> = packets.iter().map(Packet::payload).collect();
        let mut written = vec![false; payloads.len()];
        let mut first = true;
        // Each run of a flow's segments that one frame can carry, a run
        // coalesced and written before the next is coalesced into the same
        // buffers.
        let runs: Vec<Vec<usize>> = flow_groups(&payloads)
            .into_iter()
            .flat_map(|group| {
                let segments: Vec<&[u8]> = group.iter().map(|&index| payloads[index]).collect();
                frame_runs(&segments)
                    .into_iter()
                    .map(|run| group[run].to_vec())
                    .collect::<Vec<_>>()
            })
            .collect();
        'groups: for group in runs {
            let segments: Vec<&[u8]> = group.iter().map(|&index| payloads[index]).collect();
            let frame = (segments.len() >= 2)
                .then(|| {
                    prepare_coalesced_tcp_batch(
                        &mut self.gro_table,
                        &mut self.offload_send_packets,
                        &segments,
                    )
                })
                .flatten();
            // One frame for the run (the buffer it is in), or each of its
            // packets alone (none: copied into the first buffer).
            let parts: Vec<(Option<usize>, &[usize])> = match frame {
                Some(index) => vec![(Some(index), &group[..])],
                None => group
                    .iter()
                    .map(|index| (None, std::slice::from_ref(index)))
                    .collect(),
            };
            for (coalesced, covers) in parts {
                // A frame coalesced in its buffer, or a packet alone behind
                // its own header, gathered by the write.
                let header;
                let frame: [&[u8]; 2] = match coalesced {
                    Some(index) => [&self.offload_send_packets[index], &[]],
                    None => {
                        header = plain_header(payloads[covers[0]]);
                        [&header, payloads[covers[0]]]
                    }
                };
                let length = frame[0].len() + frame[1].len();
                let slices = [io::IoSlice::new(frame[0]), io::IoSlice::new(frame[1])];
                let result = if first {
                    self.device.send_vectored(&slices).await
                } else {
                    self.device.try_send_vectored(&slices)
                };
                match result {
                    Ok(n) if n == length => {
                        first = false;
                        for &index in covers {
                            written[index] = true;
                        }
                    }
                    Ok(_) if first => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "TUN device accepted a partial frame",
                        ))
                    }
                    Ok(_) => {
                        self.pending_send_error = Some(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "TUN device accepted a partial frame",
                        ));
                        break 'groups;
                    }
                    Err(error) if first => return Err(error),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break 'groups,
                    Err(error) => {
                        self.pending_send_error = Some(error);
                        break 'groups;
                    }
                }
            }
        }
        Ok(written.iter().take_while(|&&w| w).count())
    }

    fn push_received(&mut self, out: &mut PacketBatch, count: usize) -> io::Result<()> {
        let token = PacketToken::new(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        out.push(Packet::from_payload(token, 0, &self.recv_buffer[..count]))
            .map_err(|_| io::Error::other("native PacketIo receive batch is full"))
    }

    fn push_offload_packet(&mut self, out: &mut PacketBatch, index: usize) -> io::Result<()> {
        let token = PacketToken::new(self.next_token);
        self.next_token = self.next_token.wrapping_add(1);
        let size = self.offload_sizes[index];
        let payload = self.offload_packets[index]
            .get(..size)
            .ok_or_else(|| io::Error::other("TUN offload produced an oversized segment"))?;
        out.push(Packet::from_payload(token, 0, payload))
            .map_err(|_| io::Error::other("native PacketIo receive batch is full"))
    }
}

#[cfg(target_os = "linux")]
impl PacketIo for TunRsPacketIo {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        if let Some(error) = self.pending_recv_error.take() {
            // The device's end ends the runner; anything else is waited
            // out, and read past.
            self.recv_backoff.failed(error).await?;
        }
        let initial_len = out.len();
        let receive_limit = self.max_batch.min(out.limit().saturating_sub(initial_len));
        if receive_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "native PacketIo receive batch has no free slots",
            ));
        }
        while self.pending_packet_index < self.pending_packet_count
            && out.len().saturating_sub(initial_len) < receive_limit
        {
            let index = self.pending_packet_index;
            self.pending_packet_index += 1;
            self.push_offload_packet(out, index)?;
        }
        if self.pending_packet_index == self.pending_packet_count {
            self.pending_packet_index = 0;
            self.pending_packet_count = 0;
        }
        if out.len() > initial_len {
            return Ok(out.len().saturating_sub(initial_len));
        }
        if self.offload {
            let count = loop {
                let received = self
                    .device
                    .recv_multiple(
                        &mut self.offload_buffer,
                        &mut self.offload_packets,
                        &mut self.offload_sizes,
                        0,
                    )
                    .await;
                match received {
                    Ok(count) => break count,
                    Err(error) => self.recv_backoff.failed(error).await?,
                }
            };
            self.recv_backoff.succeeded();
            if count > self.offload_packets.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TUN offload reported too many segments",
                ));
            }
            self.pending_packet_count = count;
            while self.pending_packet_index < self.pending_packet_count
                && out.len().saturating_sub(initial_len) < receive_limit
            {
                let index = self.pending_packet_index;
                self.pending_packet_index += 1;
                self.push_offload_packet(out, index)?;
            }
            if self.pending_packet_index == self.pending_packet_count {
                self.pending_packet_index = 0;
                self.pending_packet_count = 0;
            }
            return Ok(out.len().saturating_sub(initial_len));
        }
        let count = loop {
            match self.device.recv(&mut self.recv_buffer).await {
                Ok(count) => break count,
                Err(error) => self.recv_backoff.failed(error).await?,
            }
        };
        self.recv_backoff.succeeded();
        if count == 0 {
            return Ok(0);
        }
        self.push_received(out, count)?;
        while out.len().saturating_sub(initial_len) < receive_limit {
            match self.device.try_recv(&mut self.recv_buffer) {
                Ok(0) => {
                    self.pending_recv_error = Some(io::Error::from(io::ErrorKind::UnexpectedEof));
                    break;
                }
                Ok(count) => self.push_received(out, count)?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    self.pending_recv_error = Some(error);
                    break;
                }
            }
        }
        Ok(out.len().saturating_sub(initial_len))
    }

    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        if let Some(error) = self.pending_send_error.take() {
            return Err(error);
        }
        if self.offload && packets.len() >= 2 {
            return self.send_coalesced(packets).await;
        }
        let mut sent = 0;
        for packet in packets.iter() {
            let expected = if self.offload {
                tun_rs::VIRTIO_NET_HDR_LEN + packet.payload().len()
            } else {
                packet.payload().len()
            };
            // PacketIo cancellation: await only before the first packet is
            // accepted; later packets use a non-blocking send.
            // With offload, the packet behind its own header, gathered by
            // the write rather than copied behind it.
            let header = plain_header(packet.payload());
            let parts = [
                io::IoSlice::new(&header),
                io::IoSlice::new(packet.payload()),
            ];
            let result = if self.offload {
                if sent == 0 {
                    self.device.send_vectored(&parts).await
                } else {
                    self.device.try_send_vectored(&parts)
                }
            } else if sent == 0 {
                self.device.send(packet.payload()).await
            } else {
                self.device.try_send(packet.payload())
            };
            match result {
                Ok(written) if written == expected => {
                    sent += 1;
                }
                Ok(_) if sent == 0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TUN device accepted a partial packet",
                    ));
                }
                Ok(_) => {
                    self.pending_send_error = Some(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TUN device accepted a partial packet",
                    ));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && sent > 0 => break,
                Err(error) if sent == 0 => return Err(error),
                Err(error) => {
                    self.pending_send_error = Some(error);
                    break;
                }
            }
        }
        Ok(sent)
    }

    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: self.max_batch,
            queue_count: self.queue_count,
            headroom: 0,
            vectored: false,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}

/// Fuzzing (sail::fuzzing): the header written before a packet with
/// offload, on raw bytes and on TCP and UDP packets of both families built
/// from them. It always fits the packet, says DATA_VALID and nothing else,
/// and its hdr_len is where the TCP or UDP payload starts.
#[cfg(all(target_os = "linux", feature = "fuzzing"))]
pub(crate) fn fuzz_vnet_header(data: &[u8]) {
    use sail_netstack::{emit_tcp_segment_with_options, emit_udp_packet};
    check_header(data);
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    let (source, destination) = fuzz_endpoints(shape & 1 != 0, 0);
    let payload = &rest[..rest.len().min(8_000)];
    let packet = if shape & 2 != 0 {
        emit_udp_packet(source, destination, payload, 64, 1)
    } else {
        // 0 to 40 bytes of options: NOPs.
        let options = vec![1_u8; usize::from((shape >> 2) % 11) * 4];
        emit_tcp_segment_with_options(
            source,
            destination,
            fuzz_control(1, sail_netstack::TcpFlags::ACK),
            &options,
            payload,
            64,
            1,
        )
    };
    let Ok(packet) = packet else {
        return;
    };
    let header = check_header(&packet);
    assert_eq!(
        usize::from(header.hdr_len),
        packet.len() - payload.len(),
        "hdr_len of a packet sail built"
    );
}

#[cfg(all(target_os = "linux", feature = "fuzzing"))]
fn check_header(packet: &[u8]) -> tun_rs::VirtioNetHdr {
    let bytes = plain_header(packet);
    let header = tun_rs::VirtioNetHdr::decode(&bytes).expect("the header decodes");
    assert_eq!((header.flags, header.gso_type, header.gso_size), (2, 0, 0));
    assert!(
        usize::from(header.hdr_len) <= packet.len(),
        "hdr_len past the packet"
    );
    // Where each parser puts the payload: the same place.
    if let Ok(ip) = parse_ip_packet(packet, false) {
        let payload = match ip.next_header {
            6 => parse_tcp_segment(ip, false)
                .ok()
                .map(|segment| segment.payload),
            17 => sail_netstack::parse_udp_datagram(ip, false)
                .ok()
                .map(|datagram| datagram.payload),
            _ => None,
        };
        if let Some(payload) = payload {
            let offset = payload.as_ptr() as usize - packet.as_ptr() as usize;
            assert_eq!(
                usize::from(header.hdr_len),
                offset,
                "hdr_len is not the payload's offset"
            );
        }
    }
    header
}

#[cfg(all(target_os = "linux", feature = "fuzzing"))]
fn fuzz_endpoints(v6: bool, flow: u16) -> (std::net::SocketAddr, std::net::SocketAddr) {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    if v6 {
        (
            SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 443)),
            SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2), 40_000 + flow)),
        )
    } else {
        (
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 443)),
            SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40_000 + flow)),
        )
    }
}

#[cfg(all(target_os = "linux", feature = "fuzzing"))]
fn fuzz_control(sequence: u32, flags: sail_netstack::TcpFlags) -> sail_netstack::SendControl {
    sail_netstack::SendControl {
        sequence: sail_netstack::SeqNumber::new(sequence),
        acknowledgment: sail_netstack::SeqNumber::new(77),
        flags,
        window: 32_000,
    }
}

/// Fuzzing (sail::fuzzing): a batch of TCP segments of up to three flows,
/// any lengths, some with gaps or PSH, grouped flow by flow and coalesced.
/// The groups partition the batch in its order, one flow each; a group that
/// coalesces into one GSO frame splits back into exactly its segments.
#[cfg(all(target_os = "linux", feature = "fuzzing"))]
pub(crate) fn fuzz_coalesce(data: &[u8]) {
    use sail_netstack::{emit_tcp_segment, TcpFlags};
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    let v6 = shape & 1 != 0;
    let mut next = [1_000_u32, 50_000, 900_000];
    let mut wires = Vec::new();
    for op in rest.chunks_exact(3).take(64) {
        let flow = usize::from(op[0] % 3);
        let len = 1 + usize::from(u16::from_le_bytes([op[1], op[2]]) % 1_460);
        if op[0] & 0x80 != 0 {
            next[flow] = next[flow].wrapping_add(7);
        }
        // ACK, or ACK and PSH (0x08), which stops a coalesced run.
        let flags = if op[0] & 0x40 != 0 {
            TcpFlags::from_bits(TcpFlags::ACK.bits() | 0x08)
        } else {
            TcpFlags::ACK
        };
        let payload: Vec<u8> = (0..len).map(|i| (i as u8) ^ op[0]).collect();
        let (source, destination) = fuzz_endpoints(v6, flow as u16);
        let Ok(wire) = emit_tcp_segment(
            source,
            destination,
            fuzz_control(next[flow], flags),
            &payload,
            64,
            1,
        ) else {
            return;
        };
        next[flow] = next[flow].wrapping_add(len as u32);
        wires.push(wire);
    }
    let payloads: Vec<&[u8]> = wires.iter().map(Vec::as_slice).collect();
    let groups = flow_groups(&payloads);
    let mut seen = vec![false; payloads.len()];
    let mut firsts = Vec::new();
    for group in &groups {
        assert!(!group.is_empty());
        assert!(
            group.windows(2).all(|w| w[0] < w[1]),
            "a group out of order"
        );
        let flow = tcp_flow(payloads[group[0]]);
        for &index in group {
            assert!(
                !std::mem::replace(&mut seen[index], true),
                "a packet in two groups"
            );
            assert_eq!(tcp_flow(payloads[index]), flow, "two flows in a group");
        }
        firsts.push(group[0]);
    }
    assert!(seen.iter().all(|&s| s), "a packet in no group");
    assert!(
        firsts.windows(2).all(|w| w[0] < w[1]),
        "groups out of order"
    );

    let mut table = tun_rs::GROTable::default();
    let mut buffers: Vec<Vec<u8>> = (0..64).map(|_| Vec::new()).collect();
    for group in &groups {
        let flow: Vec<&[u8]> = group.iter().map(|&i| payloads[i]).collect();
        // The runs cover the flow's segments once, in order, none empty.
        let runs = frame_runs(&flow);
        assert!(
            runs.first().is_some_and(|r| r.start == 0),
            "runs from the first"
        );
        assert!(
            runs.windows(2).all(|w| w[0].end == w[1].start),
            "runs apart"
        );
        assert!(
            runs.iter().all(|r| !r.is_empty()) && runs.last().map(|r| r.end) == Some(flow.len())
        );
        for run in runs {
            let segments = &flow[run];
            let Some(index) = prepare_coalesced_tcp_batch(&mut table, &mut buffers, segments)
            else {
                continue;
            };
            let header = tun_rs::VirtioNetHdr::decode(&buffers[index]).expect("the header decodes");
            let mut frame = buffers[index][tun_rs::VIRTIO_NET_HDR_LEN..].to_vec();
            let mut split = vec![vec![0_u8; 1_600]; segments.len() + 1];
            let mut sizes = vec![0; segments.len() + 1];
            let count = tun_rs::gso_split(&mut frame, header, &mut split, &mut sizes, 0, v6)
                .expect("a coalesced frame splits");
            assert_eq!(
                count,
                segments.len(),
                "split into another number of segments"
            );
            for (k, original) in segments.iter().enumerate() {
                let got = parse_tcp_segment(
                    parse_ip_packet(&split[k][..sizes[k]], true).expect("a split segment parses"),
                    true,
                )
                .expect("a split segment is TCP, its checksums right");
                let want =
                    parse_tcp_segment(parse_ip_packet(original, false).unwrap(), false).unwrap();
                assert_eq!(got.payload, want.payload, "segment {k} changed");
                assert_eq!(got.meta.sequence, want.meta.sequence, "segment {k} moved");
            }
        }
    }
}

#[cfg(test)]
mod blocking_wait_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    use super::BlockingWait;

    /// Dropped while it waits, as the runtime drops a receive many times a
    /// second, the wait starts no second thread: the next call takes up
    /// the one there is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dropped_wait_is_taken_up_not_started_again() {
        let started = Arc::new(AtomicUsize::new(0));
        let (release, released) = mpsc::channel::<()>();
        let released = Arc::new(Mutex::new(released));
        let mut wait = BlockingWait::new();
        let waiter = || {
            let started = started.clone();
            let released = released.clone();
            move || {
                started.fetch_add(1, Ordering::SeqCst);
                released.lock().unwrap().recv().unwrap();
                7
            }
        };
        for _ in 0..20 {
            let dropped = tokio::time::timeout(Duration::from_millis(5), wait.wait(waiter())).await;
            assert!(dropped.is_err(), "nothing released it yet");
        }
        release.send(()).unwrap();
        assert_eq!(wait.wait(waiter()).await.unwrap(), 7);
        assert_eq!(started.load(Ordering::SeqCst), 1);
        // Done, the next wait is a new one.
        release.send(()).unwrap();
        assert_eq!(wait.wait(waiter()).await.unwrap(), 7);
        assert_eq!(started.load(Ordering::SeqCst), 2);
    }
}

// They drive the tun crates' devices, which Windows does not use.
#[cfg(all(test, not(target_os = "windows")))]
mod tests {
    #[cfg(target_os = "linux")]
    use crate::util::DnsMessageExt;
    use std::net::SocketAddr;
    #[cfg(target_os = "linux")]
    use std::sync::Arc;
    use std::time::Duration;
    #[cfg(target_os = "linux")]
    use std::time::Instant;

    use sail_netstack::{ResourceLedger, RunnerConfig};

    use super::*;
    #[cfg(target_os = "linux")]
    use crate::net::netstack::testing::tcp_packet;
    use crate::net::netstack::NativeRuntimeGroup;
    #[cfg(target_os = "linux")]
    use crate::net::netstack::{NativeConnection, NativeRuntimeControl};
    #[cfg(target_os = "linux")]
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RData, RecordType},
    };
    use sail_netstack::BudgetProfile;
    #[cfg(target_os = "linux")]
    use sail_netstack::{ResourceKind, TcpFlags};
    use std::net::Ipv4Addr;
    #[cfg(target_os = "linux")]
    use std::net::Ipv6Addr;
    #[cfg(target_os = "linux")]
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::timeout;

    #[cfg(target_os = "linux")]
    async fn fake_dns_lookup(
        socket: &tokio::net::UdpSocket,
        server: SocketAddr,
        id: u16,
        domain: &str,
    ) -> anyhow::Result<Ipv4Addr> {
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request
            .set_id(id)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true)
            .add_query(Query::query(Name::from_ascii(domain)?, RecordType::A));
        socket.send_to(&request.to_vec()?, server).await?;
        let mut buffer = [0_u8; 512];
        let (count, source) =
            timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await??;
        anyhow::ensure!(source == server, "fake DNS response source changed");
        let response = Message::from_vec(&buffer[..count])?;
        anyhow::ensure!(response.id() == id, "fake DNS response ID changed");
        response
            .answers()
            .iter()
            .find_map(|answer| match &answer.data {
                RData::A(address) => Some(address.0),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("fake DNS response has no A record"))
    }

    #[cfg(target_os = "linux")]
    type SegmentFilter = Box<dyn FnMut(&sail_netstack::ParsedTcpSegment<'_>) -> bool + Send>;

    /// Drops the TCP segments `drops` picks on their way out, and those
    /// `drops_received` picks on their way in.
    #[cfg(target_os = "linux")]
    struct DropTcpSegments<I> {
        inner: I,
        drops: SegmentFilter,
        drops_received: SegmentFilter,
        pending_send_error: Option<io::Error>,
    }

    #[cfg(target_os = "linux")]
    struct ReorderDuplicateTcpPayload<I> {
        inner: I,
        armed: Arc<AtomicBool>,
        completed: Arc<AtomicBool>,
        pending: Option<(PacketToken, Vec<u8>)>,
        release_at: Option<std::time::Instant>,
        pending_send_error: Option<io::Error>,
    }

    #[cfg(target_os = "linux")]
    impl<I: PacketIo> ReorderDuplicateTcpPayload<I> {
        fn new(inner: I, armed: Arc<AtomicBool>, completed: Arc<AtomicBool>) -> Self {
            Self {
                inner,
                armed,
                completed,
                pending: None,
                release_at: None,
                pending_send_error: None,
            }
        }

        fn is_tcp_payload(packet: &Packet) -> bool {
            parse_ip_packet(packet.payload(), true)
                .and_then(|ip| parse_tcp_segment(ip, true))
                .is_ok_and(|segment| !segment.payload.is_empty())
        }

        async fn send_one(&mut self, token: PacketToken, payload: &[u8]) -> io::Result<()> {
            let mut single = PacketBatch::with_limit(1);
            single
                .push(Packet::from_payload(token, 0, payload))
                .expect("single-packet batch has capacity");
            match self.inner.send(&single).await {
                Ok(1) => Ok(()),
                Ok(0) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test PacketIo reported more than one sent packet",
                )),
                Err(error) => Err(error),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl<I: PacketIo> PacketIo for ReorderDuplicateTcpPayload<I> {
        async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
            self.inner.recv(out).await
        }

        async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
            if let Some(error) = self.pending_send_error.take() {
                return Err(error);
            }
            let mut sent = 0;
            for packet in packets.iter() {
                let payload = Self::is_tcp_payload(packet);
                if payload && self.pending.is_none() && self.armed.swap(false, Ordering::SeqCst) {
                    // Holding the packet accepts it without an await.
                    self.pending = Some((packet.token(), packet.payload().to_vec()));
                    sent += 1;
                    continue;
                }

                if payload && self.pending.is_some() {
                    // PacketIo cancellation: the reordering delay must precede
                    // every acceptance in this call, so defer the trigger. The
                    // runtime drops a step on every timer tick, so the delay is
                    // a deadline rechecked on retry rather than an await.
                    if sent > 0 {
                        break;
                    }
                    let release_at = *self.release_at.get_or_insert_with(|| {
                        std::time::Instant::now() + Duration::from_millis(25)
                    });
                    if std::time::Instant::now() < release_at {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    self.release_at = None;
                    self.send_one(packet.token(), packet.payload()).await?;
                    sent = 1;
                    let (pending_token, pending_payload) =
                        self.pending.take().expect("checked above");
                    match self
                        .send_one(pending_token, &pending_payload)
                        .now_or_never()
                    {
                        Some(Ok(())) => {
                            let _ = self
                                .send_one(packet.token(), packet.payload())
                                .now_or_never();
                            self.completed.store(true, Ordering::SeqCst);
                        }
                        Some(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                            self.pending = Some((pending_token, pending_payload));
                        }
                        Some(Err(error)) => self.pending_send_error = Some(error),
                        None => self.pending = Some((pending_token, pending_payload)),
                    }
                    break;
                }

                let result = if sent == 0 {
                    self.send_one(packet.token(), packet.payload()).await
                } else {
                    match self
                        .send_one(packet.token(), packet.payload())
                        .now_or_never()
                    {
                        Some(result) => result,
                        None => break,
                    }
                };
                match result {
                    Ok(()) => sent += 1,
                    Err(error) if sent == 0 => return Err(error),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        self.pending_send_error = Some(error);
                        break;
                    }
                }
            }
            Ok(sent)
        }

        fn capabilities(&self) -> PacketCapabilities {
            self.inner.capabilities()
        }
    }

    #[cfg(target_os = "linux")]
    impl<I: PacketIo> DropTcpSegments<I> {
        fn new(inner: I, drops: SegmentFilter, drops_received: SegmentFilter) -> Self {
            Self {
                inner,
                drops,
                drops_received,
                pending_send_error: None,
            }
        }

        /// The first outgoing segment with payload while `armed`.
        fn payload(inner: I, armed: Arc<AtomicBool>) -> Self {
            Self::new(
                inner,
                Box::new(move |segment| {
                    !segment.payload.is_empty() && armed.swap(false, Ordering::SeqCst)
                }),
                Box::new(|_| false),
            )
        }

        /// The first outgoing SYN while `armed`.
        fn syn(inner: I, armed: Arc<AtomicBool>) -> Self {
            Self::new(
                inner,
                Box::new(move |segment| {
                    segment.meta.flags == TcpFlags::SYN && armed.swap(false, Ordering::SeqCst)
                }),
                Box::new(|_| false),
            )
        }

        /// About `per_mille` in a thousand segments each way, from a fixed
        /// seed so that a failure replays.
        fn lossy(inner: I, seed: u64, per_mille: u64) -> Self {
            let pick = move |state: &mut u64| {
                // xorshift64
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                *state % 1_000 < per_mille
            };
            let mut outgoing = seed | 1;
            let mut incoming = seed.rotate_left(32) | 1;
            Self::new(
                inner,
                Box::new(move |_| pick(&mut outgoing)),
                Box::new(move |_| pick(&mut incoming)),
            )
        }

        fn picked(filter: &mut SegmentFilter, packet: &Packet) -> bool {
            let Ok(ip) = parse_ip_packet(packet.payload(), true) else {
                return false;
            };
            let Ok(segment) = parse_tcp_segment(ip, true) else {
                return false;
            };
            filter(&segment)
        }
    }

    #[cfg(target_os = "linux")]
    impl<I: PacketIo> PacketIo for DropTcpSegments<I> {
        async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
            loop {
                let mut received = PacketBatch::with_limit(out.limit() - out.len());
                self.inner.recv(&mut received).await?;
                let mut kept = 0;
                for packet in received.iter() {
                    if !Self::picked(&mut self.drops_received, packet) {
                        out.push(Packet::from_payload(packet.token(), 0, packet.payload()))
                            .expect("the kept packets fit where all of them did");
                        kept += 1;
                    }
                }
                if kept > 0 {
                    return Ok(kept);
                }
            }
        }

        async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
            if let Some(error) = self.pending_send_error.take() {
                return Err(error);
            }
            let mut sent = 0;
            for packet in packets.iter() {
                if Self::picked(&mut self.drops, packet) {
                    sent += 1;
                    continue;
                }
                let mut single = PacketBatch::with_limit(1);
                single
                    .push(Packet::from_payload(packet.token(), 0, packet.payload()))
                    .expect("single-packet batch has capacity");
                // PacketIo cancellation: await only before the first accept.
                let result = if sent == 0 {
                    self.inner.send(&single).await
                } else {
                    match self.inner.send(&single).now_or_never() {
                        Some(result) => result,
                        None => break,
                    }
                };
                match result {
                    Ok(1) => sent += 1,
                    Ok(0) => break,
                    Ok(_) if sent == 0 => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "test PacketIo reported more than one sent packet",
                        ));
                    }
                    Ok(_) => {
                        self.pending_send_error = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "test PacketIo reported more than one sent packet",
                        ));
                        break;
                    }
                    Err(error) if sent == 0 => return Err(error),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        self.pending_send_error = Some(error);
                        break;
                    }
                }
            }
            Ok(sent)
        }

        fn capabilities(&self) -> PacketCapabilities {
            self.inner.capabilities()
        }
    }

    #[cfg(target_os = "linux")]
    fn gso_test_buffers(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                Vec::with_capacity(
                    2 * tun_rs::VIRTIO_NET_HDR_LEN + if index == 0 { 65_535 } else { 1_500 },
                )
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_offload_coalesces_a_complete_tcp_prefix_into_one_atomic_gso_frame() {
        let source = SocketAddr::from((Ipv4Addr::new(10, 20, 0, 1), 443));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 20, 0, 2), 50_000));
        let payloads = [vec![1; 512], vec![2; 512], vec![3; 128]];
        let mut batch = PacketBatch::with_limit(payloads.len());
        let mut sequence = 10_000_u32;
        for (index, payload) in payloads.iter().enumerate() {
            let wire = tcp_packet(source, destination, sequence, 77, TcpFlags::ACK, payload);
            batch
                .push(Packet::from_payload(
                    PacketToken::new(index as u64),
                    0,
                    &wire,
                ))
                .unwrap();
            sequence = sequence.wrapping_add(u32::try_from(payload.len()).unwrap());
        }
        let mut table = tun_rs::GROTable::default();
        let mut buffers = gso_test_buffers(payloads.len());
        let segments: Vec<&[u8]> = batch.iter().map(Packet::payload).collect();
        let index = prepare_coalesced_tcp_batch(&mut table, &mut buffers, &segments).unwrap();
        let header = tun_rs::VirtioNetHdr::decode(&buffers[index]).unwrap();
        assert_eq!(header.gso_type & 0x7f, tun_rs::VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(usize::from(header.gso_size), payloads[0].len());

        let mut coalesced = buffers[index][tun_rs::VIRTIO_NET_HDR_LEN..].to_vec();
        let mut split = vec![vec![0_u8; 1_500]; payloads.len()];
        let mut sizes = vec![0; payloads.len()];
        let count =
            tun_rs::gso_split(&mut coalesced, header, &mut split, &mut sizes, 0, false).unwrap();
        assert_eq!(count, payloads.len());
        for (index, expected) in payloads.iter().enumerate() {
            let ip = parse_ip_packet(&split[index][..sizes[index]], true).unwrap();
            assert_eq!(parse_tcp_segment(ip, true).unwrap().payload, expected);
        }
    }

    /// Two flows' segments interleaved, and a bare ACK between them: a
    /// group a flow, at its first segment's place, each coalescing into
    /// one frame; the ACK alone.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_offload_coalesces_a_mixed_batch_flow_by_flow() {
        let server = SocketAddr::from((Ipv4Addr::new(10, 22, 0, 1), 443));
        let one = SocketAddr::from((Ipv4Addr::new(10, 22, 0, 2), 50_000));
        let two = SocketAddr::from((Ipv4Addr::new(10, 22, 0, 2), 50_001));
        let mut wires = Vec::new();
        for i in 0..3_u32 {
            wires.push(tcp_packet(
                server,
                one,
                1_000 + i * 512,
                77,
                TcpFlags::ACK,
                &[1; 512],
            ));
            if i == 1 {
                wires.push(tcp_packet(server, one, 2_536, 77, TcpFlags::ACK, &[]));
            }
            wires.push(tcp_packet(
                server,
                two,
                9_000 + i * 512,
                77,
                TcpFlags::ACK,
                &[2; 512],
            ));
        }
        let payloads: Vec<&[u8]> = wires.iter().map(Vec::as_slice).collect();
        let groups = flow_groups(&payloads);
        assert_eq!(groups, vec![vec![0, 2, 5], vec![1, 4, 6], vec![3]]);
        let mut table = tun_rs::GROTable::default();
        for group in &groups[..2] {
            let mut buffers = gso_test_buffers(group.len());
            let segments: Vec<&[u8]> = group.iter().map(|&i| payloads[i]).collect();
            let index = prepare_coalesced_tcp_batch(&mut table, &mut buffers, &segments)
                .expect("a flow's segments make one frame");
            let header = tun_rs::VirtioNetHdr::decode(&buffers[index]).unwrap();
            assert_eq!(header.gso_type & 0x7f, tun_rs::VIRTIO_NET_HDR_GSO_TCPV4);
            assert_eq!(usize::from(header.gso_size), 512);
        }
    }

    /// More of a flow than one frame can carry: a frame a run, each of 64
    /// KiB at most, and each run's segments coalescing into one frame. A
    /// short segment, or one with PSH, ends its run.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_offload_coalesces_a_long_flow_into_frames_of_at_most_64_kib() {
        let server = SocketAddr::from((Ipv4Addr::new(10, 23, 0, 1), 443));
        let client = SocketAddr::from((Ipv4Addr::new(10, 23, 0, 2), 50_000));
        let mut sequence = 1_000_u32;
        let mut segment = |size: usize, flags: TcpFlags| {
            let wire = tcp_packet(server, client, sequence, 77, flags, &vec![7; size]);
            sequence = sequence.wrapping_add(u32::try_from(size).unwrap());
            wire
        };
        let push = TcpFlags::from_bits(TcpFlags::ACK.bits() | 0x08);
        // 10 of 8000 bytes: 8 fit in 64 KiB; then a short one ends a run,
        // and one with PSH ends the next.
        let mut wires: Vec<Vec<u8>> = (0..10).map(|_| segment(8_000, TcpFlags::ACK)).collect();
        wires.push(segment(3_000, TcpFlags::ACK));
        wires.push(segment(8_000, TcpFlags::ACK));
        wires.push(segment(8_000, push));
        wires.push(segment(8_000, TcpFlags::ACK));
        let segments: Vec<&[u8]> = wires.iter().map(Vec::as_slice).collect();
        let runs = frame_runs(&segments);
        assert_eq!(runs, vec![0..8, 8..11, 11..13, 13..14]);
        let mut table = tun_rs::GROTable::default();
        for run in runs.iter().filter(|run| run.len() >= 2) {
            let mut buffers = gso_test_buffers(run.len());
            let index =
                prepare_coalesced_tcp_batch(&mut table, &mut buffers, &segments[run.clone()])
                    .expect("a run makes one frame");
            let header = tun_rs::VirtioNetHdr::decode(&buffers[index]).unwrap();
            assert_eq!(header.gso_type & 0x7f, tun_rs::VIRTIO_NET_HDR_GSO_TCPV4);
            assert_eq!(usize::from(header.gso_size), 8_000);
            assert!(buffers[index].len() - tun_rs::VIRTIO_NET_HDR_LEN <= 65_535);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_offload_rejects_noncontiguous_tcp_batch_for_per_packet_fallback() {
        let source = SocketAddr::from((Ipv4Addr::new(10, 21, 0, 1), 443));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 21, 0, 2), 50_000));
        let wires = [
            tcp_packet(source, destination, 1_000, 77, TcpFlags::ACK, &[1; 64]),
            tcp_packet(source, destination, 2_000, 77, TcpFlags::ACK, &[2; 64]),
        ];
        let mut batch = PacketBatch::with_limit(wires.len());
        for (index, wire) in wires.iter().enumerate() {
            batch
                .push(Packet::from_payload(
                    PacketToken::new(index as u64),
                    0,
                    wire,
                ))
                .unwrap();
        }
        let mut table = tun_rs::GROTable::default();
        let mut buffers = gso_test_buffers(wires.len());
        let segments: Vec<&[u8]> = batch.iter().map(Packet::payload).collect();
        assert!(prepare_coalesced_tcp_batch(&mut table, &mut buffers, &segments).is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN"]
    async fn linux_kernel_accepts_one_atomic_tcp_gso_frame_for_a_complete_batch() {
        let device = tun_rs::DeviceBuilder::new()
            .name("sailns-gso")
            .ipv4("10.207.0.1", 24, None)
            .mtu(1_500)
            .enable(true)
            .offload(true)
            .build_async()
            .unwrap();
        let mut io = TunRsPacketIo::new(device, 1_500, 64, 1, true).unwrap();
        let source = SocketAddr::from((Ipv4Addr::new(10, 207, 0, 2), 50_000));
        let destination = SocketAddr::from((Ipv4Addr::new(10, 207, 0, 1), 443));
        let payloads = [vec![1; 512], vec![2; 512], vec![3; 128]];
        let mut packets = PacketBatch::with_limit(payloads.len());
        let mut sequence = 1_000_u32;
        for (index, payload) in payloads.iter().enumerate() {
            let wire = tcp_packet(source, destination, sequence, 9_000, TcpFlags::ACK, payload);
            packets
                .push(Packet::from_payload(
                    PacketToken::new(index as u64),
                    0,
                    &wire,
                ))
                .unwrap();
            sequence = sequence.wrapping_add(u32::try_from(payload.len()).unwrap());
        }

        let sent = timeout(Duration::from_secs(2), io.send(&packets))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sent, packets.len());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN"]
    async fn linux_multiqueue_kernel_tcp_udp_round_trips() {
        let first = tun_rs::DeviceBuilder::new()
            .name("sailns-smoke")
            .ipv4("10.203.0.1", 24, None)
            .ipv6("2001:db8:203::1", 64)
            .mtu(1_500)
            .enable(true)
            .multi_queue(true)
            .offload(true)
            .build_async()
            .unwrap();
        let second = first.try_clone().unwrap();
        let drop_tcp_payload = Arc::new(AtomicBool::new(false));
        let reorder_tcp_payload = Arc::new(AtomicBool::new(false));
        let reorder_completed = Arc::new(AtomicBool::new(false));
        let queues = vec![
            ReorderDuplicateTcpPayload::new(
                DropTcpSegments::payload(
                    TunRsPacketIo::new(first, 1_500, 64, 2, true).unwrap(),
                    Arc::clone(&drop_tcp_payload),
                ),
                Arc::clone(&reorder_tcp_payload),
                Arc::clone(&reorder_completed),
            ),
            ReorderDuplicateTcpPayload::new(
                DropTcpSegments::payload(
                    TunRsPacketIo::new(second, 1_500, 64, 2, true).unwrap(),
                    Arc::clone(&drop_tcp_payload),
                ),
                Arc::clone(&reorder_tcp_payload),
                Arc::clone(&reorder_completed),
            ),
        ];
        let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
        let (runtime, mut accepted, mut datagrams, mut udp_reply, mut control) =
            NativeRuntimeGroup::new(queues, ledger, RunnerConfig::default(), 8, 8, 8).unwrap();
        assert_eq!(runtime.shard_count(), 2);
        let runtime_task = tokio::spawn(runtime.run());
        let socket = tokio::net::UdpSocket::bind("10.203.0.1:0").await.unwrap();
        let client = socket.local_addr().unwrap();
        let remote = SocketAddr::from((Ipv4Addr::new(10, 203, 0, 2), 53_535));
        socket.send_to(b"kernel-uplink", remote).await.unwrap();

        let datagram = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(datagram.source, client);
        assert_eq!(datagram.destination, remote);
        assert_eq!(datagram.payload.to_vec(), b"kernel-uplink");
        udp_reply
            .send(datagram.token, remote, b"kernel-downlink".to_vec())
            .await
            .unwrap();

        let mut received = [0_u8; 32];
        let (count, source) = timeout(Duration::from_secs(1), socket.recv_from(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, remote);
        assert_eq!(&received[..count], b"kernel-downlink");

        let fragmented_payload = (0..4_096)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        socket.send_to(&fragmented_payload, remote).await.unwrap();
        let fragmented_datagram = timeout(Duration::from_secs(2), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fragmented_datagram.source, client);
        assert_eq!(fragmented_datagram.destination, remote);
        assert_eq!(fragmented_datagram.payload.to_vec(), fragmented_payload);
        udp_reply
            .send(
                fragmented_datagram.token,
                remote,
                fragmented_payload.clone(),
            )
            .await
            .unwrap();
        let mut fragmented_reply = vec![0_u8; fragmented_payload.len() + 64];
        let (count, source) = timeout(
            Duration::from_secs(2),
            socket.recv_from(&mut fragmented_reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(source, remote);
        assert_eq!(&fragmented_reply[..count], fragmented_payload);

        let tcp_remote = SocketAddr::from((Ipv4Addr::new(10, 203, 0, 2), 44_443));
        let (kernel_stream, accepted_stream) = timeout(Duration::from_secs(1), async {
            tokio::join!(tokio::net::TcpStream::connect(tcp_remote), accepted.recv())
        })
        .await
        .unwrap();
        let mut kernel_stream = kernel_stream.unwrap();
        let mut accepted_stream = accepted_stream.unwrap().stream;
        kernel_stream.write_all(b"kernel-tcp-uplink").await.unwrap();
        let mut uplink = [0_u8; 17];
        accepted_stream.read_exact(&mut uplink).await.unwrap();
        assert_eq!(&uplink, b"kernel-tcp-uplink");
        drop_tcp_payload.store(true, Ordering::SeqCst);
        accepted_stream
            .write_all(b"kernel-tcp-downlink")
            .await
            .unwrap();
        let mut downlink = [0_u8; 19];
        timeout(
            Duration::from_secs(3),
            kernel_stream.read_exact(&mut downlink),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!drop_tcp_payload.load(Ordering::SeqCst));
        assert_eq!(&downlink, b"kernel-tcp-downlink");

        let reordered_payload = (0..4_096)
            .map(|index| u8::try_from(index % 239).unwrap())
            .collect::<Vec<_>>();
        reorder_tcp_payload.store(true, Ordering::SeqCst);
        accepted_stream.write_all(&reordered_payload).await.unwrap();
        let mut reordered_reply = vec![0_u8; reordered_payload.len()];
        timeout(
            Duration::from_secs(3),
            kernel_stream.read_exact(&mut reordered_reply),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reordered_reply, reordered_payload);
        assert!(reorder_completed.load(Ordering::SeqCst));

        accepted_stream.shutdown().await.unwrap();
        let mut eof = [0_u8; 1];
        assert_eq!(
            timeout(Duration::from_secs(2), kernel_stream.read(&mut eof))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        kernel_stream.shutdown().await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), accepted_stream.read(&mut eof))
                .await
                .unwrap()
                .unwrap(),
            0
        );

        let socket_v6 = tokio::net::UdpSocket::bind(SocketAddr::from((
            "2001:db8:203::1".parse::<Ipv6Addr>().unwrap(),
            0,
        )))
        .await
        .unwrap();
        let client_v6 = socket_v6.local_addr().unwrap();
        let remote_v6 = SocketAddr::from(("2001:db8:203::2".parse::<Ipv6Addr>().unwrap(), 53_536));
        socket_v6
            .send_to(b"kernel-ipv6-uplink", remote_v6)
            .await
            .unwrap();
        let datagram_v6 = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(datagram_v6.source, client_v6);
        assert_eq!(datagram_v6.destination, remote_v6);
        assert_eq!(datagram_v6.payload.to_vec(), b"kernel-ipv6-uplink");
        udp_reply
            .send(
                datagram_v6.token,
                remote_v6,
                b"kernel-ipv6-downlink".to_vec(),
            )
            .await
            .unwrap();
        let mut received_v6 = [0_u8; 32];
        let (count, source) = timeout(
            Duration::from_secs(1),
            socket_v6.recv_from(&mut received_v6),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(source, remote_v6);
        assert_eq!(&received_v6[..count], b"kernel-ipv6-downlink");
        socket_v6
            .send_to(&fragmented_payload, remote_v6)
            .await
            .unwrap();
        let fragmented_datagram_v6 = timeout(Duration::from_secs(2), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fragmented_datagram_v6.source, client_v6);
        assert_eq!(fragmented_datagram_v6.destination, remote_v6);
        assert_eq!(fragmented_datagram_v6.payload.to_vec(), fragmented_payload);
        udp_reply
            .send(
                fragmented_datagram_v6.token,
                remote_v6,
                fragmented_payload.clone(),
            )
            .await
            .unwrap();
        let mut fragmented_reply_v6 = vec![0_u8; fragmented_payload.len() + 64];
        let (count, source) = timeout(
            Duration::from_secs(2),
            socket_v6.recv_from(&mut fragmented_reply_v6),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(source, remote_v6);
        assert_eq!(&fragmented_reply_v6[..count], fragmented_payload);

        let tcp_remote_v6 =
            SocketAddr::from(("2001:db8:203::2".parse::<Ipv6Addr>().unwrap(), 44_444));
        let (kernel_stream_v6, accepted_stream_v6) = timeout(Duration::from_secs(1), async {
            tokio::join!(
                tokio::net::TcpStream::connect(tcp_remote_v6),
                accepted.recv()
            )
        })
        .await
        .unwrap();
        let mut kernel_stream_v6 = kernel_stream_v6.unwrap();
        let mut accepted_stream_v6 = accepted_stream_v6.unwrap().stream;
        kernel_stream_v6
            .write_all(b"kernel-ipv6-tcp-uplink")
            .await
            .unwrap();
        let mut uplink_v6 = [0_u8; 22];
        accepted_stream_v6.read_exact(&mut uplink_v6).await.unwrap();
        assert_eq!(&uplink_v6, b"kernel-ipv6-tcp-uplink");
        accepted_stream_v6
            .write_all(b"kernel-ipv6-tcp-downlink")
            .await
            .unwrap();
        let mut downlink_v6 = [0_u8; 24];
        kernel_stream_v6.read_exact(&mut downlink_v6).await.unwrap();
        assert_eq!(&downlink_v6, b"kernel-ipv6-tcp-downlink");
        accepted_stream_v6.shutdown().await.unwrap();

        let reset_remote = SocketAddr::from((Ipv4Addr::new(10, 203, 0, 2), 44_445));
        let (kernel_reset, accepted_reset) = timeout(Duration::from_secs(1), async {
            tokio::join!(
                tokio::net::TcpStream::connect(reset_remote),
                accepted.recv()
            )
        })
        .await
        .unwrap();
        let kernel_reset = kernel_reset.unwrap().into_std().unwrap();
        socket2::SockRef::from(&kernel_reset)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(kernel_reset);
        let mut accepted_reset = accepted_reset.unwrap().stream;
        let reset_result = timeout(Duration::from_secs(2), accepted_reset.read(&mut eof))
            .await
            .unwrap();
        match reset_result {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("abrupt kernel reset did not terminate the native stream: {other:?}"),
        }

        control.abort().await.unwrap();
        control.wait_stopped().await.unwrap();
        runtime_task.await.unwrap().unwrap();
    }

    /// Long-running single-process soak over the real kernel path. Each
    /// iteration sends a fragmenting UDP round trip and a bidirectional TCP
    /// bulk transfer with an orderly close. `SAIL_NETSTACK_SOAK_SECONDS` sets
    /// the traffic duration (default 30); progress is printed every minute.
    /// After traffic stops, every flow, payload, and packet lease must return
    /// to zero; router metadata is a bounded cache and is only reported.
    /// Bytes both ends of a transfer agree on.
    #[cfg(target_os = "linux")]
    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from(index % 251).unwrap() ^ seed)
            .collect()
    }

    /// Binds once the kernel has finished duplicate address detection.
    #[cfg(target_os = "linux")]
    async fn bind_when_ready(address: SocketAddr) -> tokio::net::TcpListener {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match tokio::net::TcpListener::bind(address).await {
                Ok(listener) => return listener,
                Err(error)
                    if error.kind() == io::ErrorKind::AddrNotAvailable
                        && Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("bind {address}: {error}"),
            }
        }
    }

    /// Connects to `listener` through the stack, and returns both ends.
    #[cfg(target_os = "linux")]
    async fn connect_to_kernel(
        control: &mut NativeRuntimeControl,
        local: SocketAddr,
        listener: &tokio::net::TcpListener,
    ) -> (NativeConnection, tokio::net::TcpStream) {
        let remote = listener.local_addr().unwrap();
        let (opened, accepted) = timeout(Duration::from_secs(5), async {
            tokio::join!(control.connect(local, remote), listener.accept())
        })
        .await
        .expect("the kernel and the stack never connected");
        let opened = opened.unwrap();
        let (kernel, peer) = accepted.unwrap();
        assert_eq!(peer, opened.connection.source);
        assert_eq!(opened.connection.destination, remote);
        (opened, kernel)
    }

    /// Sends `outgoing` one way and `incoming` the other at once, each end
    /// closing its sending half when done, and checks what arrives.
    #[cfg(target_os = "linux")]
    async fn exchange(
        opened: NativeConnection,
        kernel: tokio::net::TcpStream,
        outgoing: &[u8],
        incoming: &[u8],
    ) {
        exchange_in_chunks(opened, kernel, outgoing, incoming, usize::MAX, None).await;
    }

    /// [`exchange`], the stack writing at most `chunk` bytes at a time.
    #[cfg(target_os = "linux")]
    async fn exchange_in_chunks(
        opened: NativeConnection,
        kernel: tokio::net::TcpStream,
        outgoing: &[u8],
        incoming: &[u8],
        chunk: usize,
        stack: Option<&mut NativeRuntimeControl>,
    ) {
        use std::sync::atomic::AtomicUsize;
        // How far each direction got, and whether each end closed its half,
        // for a transfer that stalls.
        let progress = [(); 6].map(|()| AtomicUsize::new(0));
        let [stack_sent, stack_received, kernel_sent, kernel_received, stack_closed, kernel_closed] =
            &progress;
        let control = stack;
        let mut stack = opened.stream;
        let (mut kernel_read, mut kernel_write) = kernel.into_split();
        let (mut stack_read, mut stack_write) = tokio::io::split(&mut stack);
        async fn read_all(
            mut read: impl AsyncReadExt + Unpin,
            counter: &AtomicUsize,
        ) -> io::Result<Vec<u8>> {
            let mut received = Vec::new();
            let mut buffer = vec![0_u8; 64 << 10];
            loop {
                let count = read.read(&mut buffer).await?;
                if count == 0 {
                    return Ok(received);
                }
                received.extend_from_slice(&buffer[..count]);
                counter.store(received.len(), Ordering::Relaxed);
            }
        }
        let stack_side = async {
            let (written, received) = tokio::join!(
                async {
                    for piece in outgoing.chunks(chunk) {
                        stack_write.write_all(piece).await?;
                        stack_sent.fetch_add(piece.len(), Ordering::Relaxed);
                    }
                    stack_write.shutdown().await?;
                    stack_closed.store(1, Ordering::Relaxed);
                    io::Result::Ok(())
                },
                read_all(&mut stack_read, stack_received)
            );
            written.unwrap();
            received.unwrap()
        };
        let kernel_side = async {
            let (written, received) = tokio::join!(
                async {
                    for piece in incoming.chunks(16 << 10) {
                        kernel_write.write_all(piece).await?;
                        kernel_sent.fetch_add(piece.len(), Ordering::Relaxed);
                    }
                    kernel_write.shutdown().await?;
                    kernel_closed.store(1, Ordering::Relaxed);
                    io::Result::Ok(())
                },
                read_all(&mut kernel_read, kernel_received)
            );
            written.unwrap();
            received.unwrap()
        };
        let Ok((at_stack, at_kernel)) = timeout(Duration::from_secs(60), async {
            tokio::join!(stack_side, kernel_side)
        })
        .await
        else {
            let [a, b, c, d, e, f] = progress.map(|p| p.into_inner());
            if let Some(control) = control {
                eprintln!("stack at the stall: {:#?}", control.stats_snapshot().await);
            }
            panic!(
                "the transfer stalled: stack sent {a} of {} and received {b} of {}, \
                 closed {e}; kernel sent {c} and received {d}, closed {f}",
                outgoing.len(),
                incoming.len()
            );
        };
        assert!(at_kernel == outgoing, "the kernel received other bytes");
        assert!(at_stack == incoming, "the stack received other bytes");
    }

    /// The stack opens connections to the kernel, a peer that offers every
    /// option. The kernel spreads its packets over the device's queues by
    /// flow hash, so each reply must be routed back to the shard that opened
    /// the connection.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN"]
    async fn linux_kernel_accepts_connections_the_stack_opens() {
        let first = tun_rs::DeviceBuilder::new()
            .name("sailns-conn")
            .ipv4("10.209.0.1", 24, None)
            .ipv6("2001:db8:209::1", 64)
            .mtu(1_500)
            .enable(true)
            .multi_queue(true)
            .offload(true)
            .build_async()
            .unwrap();
        let second = first.try_clone().unwrap();
        let drop_syn = Arc::new(AtomicBool::new(false));
        let queues = vec![
            DropTcpSegments::syn(
                TunRsPacketIo::new(first, 1_500, 64, 2, true).unwrap(),
                Arc::clone(&drop_syn),
            ),
            DropTcpSegments::syn(
                TunRsPacketIo::new(second, 1_500, 64, 2, true).unwrap(),
                Arc::clone(&drop_syn),
            ),
        ];
        let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
        let (runtime, _accepted, mut datagrams, mut udp_reply, mut control) =
            NativeRuntimeGroup::new(queues, ledger, RunnerConfig::default(), 64, 8, 8).unwrap();
        assert_eq!(runtime.shard_count(), 2);
        let runtime_task = tokio::spawn(runtime.run());
        let local = SocketAddr::from((Ipv4Addr::new(10, 209, 0, 2), 0));
        let listener = bind_when_ready(SocketAddr::from((Ipv4Addr::new(10, 209, 0, 1), 0))).await;

        // A megabyte each way at once, then a half-close from each end.
        let (opened, kernel) = connect_to_kernel(&mut control, local, &listener).await;
        assert!(opened.connection.source.port() >= 49_152);
        exchange(
            opened,
            kernel,
            &pattern(1 << 20, 0x5a),
            &pattern(1 << 20, 0xa5),
        )
        .await;

        // Many at once towards one listener: ports on both shards, none
        // shared. The kernel accepts them in its own order, so they pair up
        // by address.
        let remote = listener.local_addr().unwrap();
        let (opened, accepted) = timeout(Duration::from_secs(10), async {
            tokio::join!(
                futures::future::join_all((0..64).map(|_| {
                    let mut control = control.clone();
                    async move { control.connect(local, remote).await.unwrap() }
                })),
                async {
                    let mut accepted = std::collections::HashMap::new();
                    while accepted.len() < 64 {
                        let (kernel, peer) = listener.accept().await.unwrap();
                        accepted.insert(peer, kernel);
                    }
                    accepted
                }
            )
        })
        .await
        .expect("the concurrent connections never completed");
        let mut accepted = accepted;
        let mut ports = std::collections::HashSet::new();
        let exchanges = opened.into_iter().zip(0_u8..).map(|(opened, seed)| {
            let port = opened.connection.source.port();
            assert!(ports.insert(port), "port {port} was used twice");
            let kernel = accepted
                .remove(&opened.connection.source)
                .expect("the kernel accepted another address");
            async move {
                exchange(
                    opened,
                    kernel,
                    &pattern(4_096, seed),
                    &pattern(2_048, !seed),
                )
                .await;
            }
        });
        futures::future::join_all(exchanges).await;
        assert_eq!(ports.len(), 64);

        // A lost SYN is retransmitted after the initial RTO (RFC 6298).
        drop_syn.store(true, Ordering::SeqCst);
        let started = Instant::now();
        let (opened, kernel) = connect_to_kernel(&mut control, local, &listener).await;
        assert!(!drop_syn.load(Ordering::SeqCst), "no SYN was dropped");
        assert!(started.elapsed() >= Duration::from_millis(900));
        exchange(opened, kernel, b"after a lost SYN", b"answered").await;

        // Dropping the stream aborts the connection with a reset.
        let (opened, mut kernel) = connect_to_kernel(&mut control, local, &listener).await;
        drop(opened);
        let mut buffer = [0_u8; 16];
        let read = timeout(Duration::from_secs(5), kernel.read(&mut buffer))
            .await
            .expect("the kernel never saw the reset");
        assert_eq!(
            read.err().map(|error| error.kind()),
            Some(io::ErrorKind::ConnectionReset)
        );

        // A closed port answers the SYN with a reset.
        let closed = {
            let probe = bind_when_ready(SocketAddr::from((Ipv4Addr::new(10, 209, 0, 1), 0))).await;
            probe.local_addr().unwrap()
        };
        let refused = timeout(Duration::from_secs(5), control.connect(local, closed))
            .await
            .expect("the refusal never arrived");
        assert_eq!(
            refused.err().map(|error| error.kind()),
            Some(io::ErrorKind::ConnectionRefused)
        );

        // UDP: the stack sends first, and the kernel's answer comes back on
        // the flow that opened.
        let kernel_udp = tokio::net::UdpSocket::bind("10.209.0.1:0").await.unwrap();
        let kernel_address = kernel_udp.local_addr().unwrap();
        let (token, bound) = control
            .send_udp(local, kernel_address, b"stack-first".to_vec())
            .await
            .unwrap();
        let mut received = [0_u8; 32];
        let (count, source) = timeout(Duration::from_secs(1), kernel_udp.recv_from(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, bound);
        assert_eq!(&received[..count], b"stack-first");
        kernel_udp.send_to(b"kernel-answer", bound).await.unwrap();
        let answer = timeout(Duration::from_secs(1), datagrams.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(answer.token, token);
        assert_eq!(answer.source, kernel_address);
        assert_eq!(answer.destination, bound);
        assert_eq!(answer.payload.to_vec(), b"kernel-answer");
        udp_reply
            .send(token, bound, b"stack-again".to_vec())
            .await
            .unwrap();
        let (count, source) = timeout(Duration::from_secs(1), kernel_udp.recv_from(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, bound);
        assert_eq!(&received[..count], b"stack-again");

        // IPv6, once the kernel's address is usable.
        let listener_v6 = bind_when_ready(SocketAddr::from((
            "2001:db8:209::1".parse::<Ipv6Addr>().unwrap(),
            0,
        )))
        .await;
        let local_v6 = SocketAddr::from(("2001:db8:209::2".parse::<Ipv6Addr>().unwrap(), 0));
        let (opened, kernel) = connect_to_kernel(&mut control, local_v6, &listener_v6).await;
        exchange(
            opened,
            kernel,
            &pattern(256 << 10, 0x33),
            &pattern(256 << 10, 0xcc),
        )
        .await;

        runtime_task.abort();
    }

    /// Transfers finish when segments are lost both ways, with Nagle on and
    /// segments as large as the MTU allows. Held writes, SACK recovery, and
    /// full segments carrying SACK blocks all meet here: loss once stalled a
    /// held write for good, and a full segment with SACK blocks exceeded the
    /// MTU and failed the write.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN"]
    async fn linux_kernel_transfers_finish_under_loss_with_nagle() {
        let first = tun_rs::DeviceBuilder::new()
            .name("sailns-loss")
            .ipv4("10.211.0.1", 24, None)
            .ipv6("2001:db8:211::1", 64)
            .mtu(1_500)
            .enable(true)
            .multi_queue(true)
            .offload(true)
            .build_async()
            .unwrap();
        let second = first.try_clone().unwrap();
        let queues = vec![
            DropTcpSegments::lossy(
                TunRsPacketIo::new(first, 1_500, 64, 2, true).unwrap(),
                0x5eed_0001,
                20,
            ),
            DropTcpSegments::lossy(
                TunRsPacketIo::new(second, 1_500, 64, 2, true).unwrap(),
                0x5eed_0002,
                20,
            ),
        ];
        let mut config = RunnerConfig::default();
        config.tcp.nagle_enabled = true;
        config.tcp.max_segment_payload_bytes = 1_500 - sail_netstack::TCP_MAX_HEADER_BYTES;
        let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
        let (runtime, mut accepted, _datagrams, _udp_reply, mut control) =
            NativeRuntimeGroup::new(queues, ledger, config, 64, 8, 8).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let half_segment = config.tcp.max_segment_payload_bytes / 2;
        let size = 256 << 10;

        // The stack opens the connection, over IPv4 and IPv6.
        let listener = bind_when_ready(SocketAddr::from((Ipv4Addr::new(10, 211, 0, 1), 0))).await;
        let local = SocketAddr::from((Ipv4Addr::new(10, 211, 0, 2), 0));
        let (opened, kernel) = connect_to_kernel(&mut control, local, &listener).await;
        exchange_in_chunks(
            opened,
            kernel,
            &pattern(size, 0x11),
            &pattern(size, 0x22),
            half_segment,
            Some(&mut control),
        )
        .await;
        let listener_v6 = bind_when_ready(SocketAddr::from((
            "2001:db8:211::1".parse::<Ipv6Addr>().unwrap(),
            0,
        )))
        .await;
        let local_v6 = SocketAddr::from(("2001:db8:211::2".parse::<Ipv6Addr>().unwrap(), 0));
        let (opened, kernel) = connect_to_kernel(&mut control, local_v6, &listener_v6).await;
        exchange_in_chunks(
            opened,
            kernel,
            &pattern(size, 0x33),
            &pattern(size, 0x44),
            half_segment,
            Some(&mut control),
        )
        .await;

        // The kernel opens it.
        let remote = SocketAddr::from((Ipv4Addr::new(10, 211, 0, 2), 8_443));
        let (kernel, opened) = timeout(Duration::from_secs(10), async {
            tokio::join!(tokio::net::TcpStream::connect(remote), accepted.recv())
        })
        .await
        .expect("the kernel's connection never arrived");
        exchange_in_chunks(
            opened.unwrap(),
            kernel.unwrap(),
            &pattern(size, 0x55),
            &pattern(size, 0x66),
            half_segment,
            Some(&mut control),
        )
        .await;

        let stats = control.stats_snapshot().await.unwrap();
        assert!(
            stats.stack.tcp_sack_retransmitted_segments + stats.stack.tcp_retransmission_timeouts
                > 0,
            "nothing was lost: {stats:?}"
        );
        runtime_task.abort();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN; long-running"]
    async fn linux_native_kernel_soak() {
        fn resident_kib() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| {
                    status
                        .lines()
                        .find_map(|line| line.strip_prefix("VmRSS:"))
                        .and_then(|value| value.trim().trim_end_matches("kB").trim().parse().ok())
                })
                .unwrap_or(0)
        }

        let seconds = std::env::var("SAIL_NETSTACK_SOAK_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(30);
        // `SAIL_NETSTACK_SOAK_NET` (default 206) picks the 10.N.0.0/24 the
        // device takes, so that soaks can run side by side: two devices on
        // one subnet would receive each other's traffic.
        let net = std::env::var("SAIL_NETSTACK_SOAK_NET")
            .ok()
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or(206);
        let local = Ipv4Addr::new(10, net, 0, 1);
        let first = tun_rs::DeviceBuilder::new()
            .name(format!("sailns-soak{net}"))
            .ipv4(local, 24, None)
            .mtu(1_500)
            .enable(true)
            .multi_queue(true)
            .offload(true)
            .build_async()
            .unwrap();
        let second = first.try_clone().unwrap();
        let queues = vec![
            TunRsPacketIo::new(first, 1_500, 64, 2, true).unwrap(),
            TunRsPacketIo::new(second, 1_500, 64, 2, true).unwrap(),
        ];
        let ledger = ResourceLedger::new(BudgetProfile::Server.budget()).unwrap();
        let config = RunnerConfig {
            udp_idle_timeout_ms: 2_000,
            tcp: sail_netstack::TcpTableConfig {
                time_wait_ms: 2_000,
                ..sail_netstack::TcpTableConfig::default()
            },
            ..RunnerConfig::default()
        };
        let (runtime, mut accepted, mut datagrams, mut udp_reply, mut control) =
            NativeRuntimeGroup::new(queues, Arc::clone(&ledger), config, 8, 64, 64).unwrap();
        let runtime_task = tokio::spawn(runtime.run());
        let udp_remote = SocketAddr::from((Ipv4Addr::new(10, net, 0, 2), 53_000));
        let tcp_remote = SocketAddr::from((Ipv4Addr::new(10, net, 0, 2), 45_000));
        let started = std::time::Instant::now();
        let deadline = started + Duration::from_secs(seconds);
        let mut next_report = started;
        let mut iterations = 0_u64;
        let mut transferred = 0_u64;
        while std::time::Instant::now() < deadline {
            let seed = iterations;
            let socket = tokio::net::UdpSocket::bind(SocketAddr::from((local, 0)))
                .await
                .unwrap();
            let udp_size = 1 + usize::try_from(seed % 4_000).unwrap();
            let udp_payload = (0..udp_size)
                .map(|index| (index as u64 ^ seed) as u8)
                .collect::<Vec<_>>();
            socket.send_to(&udp_payload, udp_remote).await.unwrap();
            let datagram = timeout(Duration::from_secs(5), datagrams.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(datagram.payload.to_vec(), udp_payload);
            udp_reply
                .send(datagram.token, udp_remote, udp_payload.clone())
                .await
                .unwrap();
            let mut reply = vec![0_u8; udp_size + 64];
            let (count, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply[..count], udp_payload);

            let tcp_size = 1 + usize::try_from(seed.wrapping_mul(7_919) % 262_144).unwrap();
            let tcp_payload = (0..tcp_size)
                .map(|index| (index as u64 ^ seed.rotate_left(8)) as u8)
                .collect::<Vec<_>>();
            timeout(Duration::from_secs(30), async {
                let (kernel, accepted_stream) =
                    tokio::join!(tokio::net::TcpStream::connect(tcp_remote), accepted.recv());
                let mut kernel = kernel.unwrap();
                let mut accepted_stream = accepted_stream.unwrap().stream;
                let mut uplink = vec![0_u8; tcp_size];
                let (written, read) = tokio::join!(
                    kernel.write_all(&tcp_payload),
                    accepted_stream.read_exact(&mut uplink)
                );
                written.unwrap();
                read.unwrap();
                assert_eq!(uplink, tcp_payload);
                let mut downlink = vec![0_u8; tcp_size];
                let (written, read) = tokio::join!(
                    accepted_stream.write_all(&tcp_payload),
                    kernel.read_exact(&mut downlink)
                );
                written.unwrap();
                read.unwrap();
                assert_eq!(downlink, tcp_payload);
                let mut eof = [0_u8; 1];
                accepted_stream.shutdown().await.unwrap();
                assert_eq!(kernel.read(&mut eof).await.unwrap(), 0);
                kernel.shutdown().await.unwrap();
                assert_eq!(accepted_stream.read(&mut eof).await.unwrap(), 0);
            })
            .await
            .unwrap_or_else(|_| panic!("TCP soak iteration {iterations} timed out"));

            iterations += 1;
            transferred += 2 * (udp_size as u64 + tcp_size as u64);
            if std::time::Instant::now() >= next_report {
                let stats = control.stats_snapshot().await.unwrap().stack;
                eprintln!(
                    "soak elapsed_s={} iterations={iterations} bytes={transferred} rss_kib={} \
                     ledger_bytes={} tcp_flows={} time_wait={} udp_flows={} drops={} \
                     wire_drops={} resource_drops={} policy_drops={} \
                     udp_invalid_address_drops={} retransmission_timeouts={}",
                    started.elapsed().as_secs(),
                    resident_kib(),
                    stats.resources.total_bytes,
                    stats.tcp_active_flows,
                    stats.tcp_time_wait,
                    stats.udp_active_flows,
                    stats.dropped_packets,
                    stats.dropped_wire_packets,
                    stats.dropped_resource_packets,
                    stats.dropped_policy_packets,
                    stats.udp_invalid_address_drops,
                    stats.tcp_retransmission_timeouts,
                );
                next_report += Duration::from_secs(60);
            }
        }

        // Outlast TIME-WAIT and UDP idle expiry before checking reclamation.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let stats = control.stats_snapshot().await.unwrap().stack;
        let resources = ledger.snapshot();
        eprintln!(
            "soak done elapsed_s={} iterations={iterations} bytes={transferred} rss_kib={} \
             ledger_bytes={} metadata_bytes={} drops={}",
            started.elapsed().as_secs(),
            resident_kib(),
            resources.total_bytes,
            resources.used(ResourceKind::MetadataBytes),
            stats.dropped_packets,
        );
        assert!(iterations > 0);
        assert_eq!(stats.tcp_active_flows, 0);
        assert_eq!(stats.tcp_time_wait, 0);
        assert_eq!(stats.udp_active_flows, 0);
        for kind in [
            ResourceKind::TcpPayloadBytes,
            ResourceKind::PacketBytes,
            ResourceKind::ControlPacketBytes,
            ResourceKind::FragmentBytes,
            ResourceKind::TcpFlows,
            ResourceKind::SynReceived,
            ResourceKind::AcceptQueue,
            ResourceKind::UdpFlows,
            ResourceKind::Fragments,
            ResourceKind::TimeWait,
        ] {
            assert_eq!(resources.used(kind), 0, "{kind:?} leaked after soak");
        }

        control.abort().await.unwrap();
        control.wait_stopped().await.unwrap();
        runtime_task.await.unwrap().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires permission to configure a macOS utun interface and route"]
    async fn macos_kernel_tcp_udp_round_trips() -> anyhow::Result<()> {
        let mut configuration = tun::Configuration::default();
        configuration
            .address("10.204.0.1")
            .destination("10.204.0.2")
            .netmask("255.255.255.252")
            .mtu(1_500)
            .up();
        configuration.platform_config(|platform| {
            platform.enable_routing(true);
        });
        let device = tun::create_as_async(&configuration)?;
        let queue = TunPacketIo::new(device, 1_500, 32)?;
        let ledger = ResourceLedger::new(BudgetProfile::Desktop.budget())?;
        let (runtime, mut accepted, mut datagrams, mut udp_reply, mut control) =
            NativeRuntimeGroup::new(vec![queue], ledger, RunnerConfig::default(), 8, 8, 8)?;
        let runtime_task = tokio::spawn(runtime.run());

        let socket = tokio::net::UdpSocket::bind("10.204.0.1:0").await?;
        let client = socket.local_addr()?;
        let remote = SocketAddr::from((Ipv4Addr::new(10, 204, 0, 2), 53_535));
        socket.send_to(b"macos-kernel-uplink", remote).await?;
        let datagram = timeout(Duration::from_secs(2), datagrams.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("macOS native UDP channel closed"))?;
        anyhow::ensure!(datagram.source == client);
        anyhow::ensure!(datagram.destination == remote);
        anyhow::ensure!(datagram.payload.to_vec() == b"macos-kernel-uplink");
        udp_reply
            .send(datagram.token, remote, b"macos-kernel-downlink".to_vec())
            .await?;
        let mut udp_reply_buffer = [0_u8; 32];
        let (count, source) = timeout(
            Duration::from_secs(2),
            socket.recv_from(&mut udp_reply_buffer),
        )
        .await??;
        anyhow::ensure!(source == remote);
        anyhow::ensure!(&udp_reply_buffer[..count] == b"macos-kernel-downlink");

        let tcp_remote = SocketAddr::from((Ipv4Addr::new(10, 204, 0, 2), 44_443));
        let (kernel_stream, accepted_stream) = timeout(Duration::from_secs(2), async {
            tokio::join!(tokio::net::TcpStream::connect(tcp_remote), accepted.recv())
        })
        .await?;
        let mut kernel_stream = kernel_stream?;
        let mut accepted_stream = accepted_stream
            .ok_or_else(|| anyhow::anyhow!("macOS native TCP accept channel closed"))?
            .stream;
        kernel_stream.write_all(b"macos-kernel-tcp-uplink").await?;
        let mut tcp_uplink = [0_u8; 23];
        timeout(
            Duration::from_secs(2),
            accepted_stream.read_exact(&mut tcp_uplink),
        )
        .await??;
        anyhow::ensure!(&tcp_uplink == b"macos-kernel-tcp-uplink");
        accepted_stream
            .write_all(b"macos-kernel-tcp-downlink")
            .await?;
        let mut tcp_downlink = [0_u8; 25];
        timeout(
            Duration::from_secs(2),
            kernel_stream.read_exact(&mut tcp_downlink),
        )
        .await??;
        anyhow::ensure!(&tcp_downlink == b"macos-kernel-tcp-downlink");

        control.abort().await?;
        control.wait_stopped().await?;
        runtime_task.await??;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux /dev/net/tun and CAP_NET_ADMIN"]
    async fn linux_default_native_process_dispatcher_nat_fakeip_round_trips() -> anyhow::Result<()>
    {
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let tcp_port = tcp_listener.local_addr()?.port();
        let tcp_echo = tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await?;
            let mut payload = [0_u8; 64];
            let count = stream.read(&mut payload).await?;
            stream.write_all(&payload[..count]).await?;
            Ok::<_, io::Error>(())
        });
        let first_udp_echo_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let first_udp_port = first_udp_echo_socket.local_addr()?.port();
        let second_udp_echo_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let second_udp_port = second_udp_echo_socket.local_addr()?.port();
        let (release_first_udp, await_second_udp) = tokio::sync::oneshot::channel();
        let first_udp_echo = tokio::spawn(async move {
            let mut payload = [0_u8; 64];
            let (count, peer) = first_udp_echo_socket.recv_from(&mut payload).await?;
            await_second_udp.await.map_err(io::Error::other)?;
            first_udp_echo_socket
                .send_to(&payload[..count], peer)
                .await?;
            Ok::<_, io::Error>(())
        });
        let second_udp_echo = tokio::spawn(async move {
            let mut payload = [0_u8; 64];
            let (count, peer) = second_udp_echo_socket.recv_from(&mut payload).await?;
            second_udp_echo_socket
                .send_to(&payload[..count], peer)
                .await?;
            let _ = release_first_udp.send(());
            Ok::<_, io::Error>(())
        });

        // The fake IPs are inside the TUN's prefix, apart from its DNS
        // address, which would otherwise be taken for a fake IP.
        let runtime_id = 60_001;
        anyhow::ensure!(!crate::is_running(runtime_id), "test runtime ID is in use");
        let config = r#"{
                "inbounds": [{
                    "type": "tun",
                    "tag": "native-process-test",
                    "interface_name": "sailns-e2e",
                    "address": "198.19.255.254/15",
                    "mtu": 1500
                }],
                "outbounds": [{ "type": "direct", "tag": "direct" }],
                "route": {
                    "rules": [{ "port": 53, "action": "hijack-dns" }]
                },
                "dns": {
                    "servers": [
                        {
                            "type": "hosts", "tag": "hosts",
                            "predefined": { "netstack.test": "127.0.0.1" }
                        },
                        { "type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/16" }
                    ],
                    "rules": [{ "domain": "netstack.test", "server": "fake" }],
                    "final": "hosts"
                }
            }"#
        .to_string();
        let start_task = tokio::task::spawn_blocking(move || {
            crate::start(
                runtime_id,
                crate::StartOptions {
                    signals: false,
                    config: crate::Config::Str(config),
                    #[cfg(feature = "auto-reload")]
                    auto_reload: false,
                    runtime_opt: crate::RuntimeOption::MultiThread(4, 2 * 1024 * 1024),
                    runtime: Default::default(),
                    host: Default::default(),
                },
            )
        });

        let result = async {
            timeout(Duration::from_secs(5), async {
                while !crate::is_running(runtime_id) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .map_err(|_| anyhow::anyhow!("native sail process did not start"))?;

            let dns_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            let dns_server = SocketAddr::from((Ipv4Addr::new(198, 19, 255, 252), 53));
            // hijack-dns answers from the DNS rules: a fake IP, which the
            // dispatcher turns back into the domain.
            let fake_ip =
                fake_dns_lookup(&dns_socket, dns_server, 0x7002, "netstack.test.").await?;
            anyhow::ensure!(
                "198.18.0.0/16"
                    .parse::<cidr::Ipv4Cidr>()?
                    .contains(&fake_ip),
                "unexpected fake address {fake_ip}"
            );

            let mut tcp = timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(SocketAddr::from((fake_ip, tcp_port))),
            )
            .await??;
            tcp.write_all(b"dispatcher-tcp").await?;
            let mut tcp_reply = [0_u8; 14];
            timeout(Duration::from_secs(3), tcp.read_exact(&mut tcp_reply)).await??;
            anyhow::ensure!(&tcp_reply == b"dispatcher-tcp", "TCP echo changed payload");

            let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            let first_udp_target = SocketAddr::from((fake_ip, first_udp_port));
            let second_udp_target = SocketAddr::from((fake_ip, second_udp_port));
            udp.send_to(b"first-nat-udp", first_udp_target).await?;
            udp.send_to(b"second-nat-udp", second_udp_target).await?;
            let mut udp_reply = [0_u8; 32];
            for (expected_source, expected_payload) in [
                (second_udp_target, b"second-nat-udp".as_slice()),
                (first_udp_target, b"first-nat-udp".as_slice()),
            ] {
                let (count, source) =
                    timeout(Duration::from_secs(3), udp.recv_from(&mut udp_reply)).await??;
                anyhow::ensure!(
                    source == expected_source,
                    "UDP fake source was not restored: expected {expected_source}, got {source}"
                );
                anyhow::ensure!(
                    &udp_reply[..count] == expected_payload,
                    "UDP echo changed or reordered the mapped payload"
                );
            }

            tokio::task::spawn_blocking(move || crate::network_changed(runtime_id, Some(1_400)))
                .await??;
            // The call returns with the change handled: the TUN's flows are
            // reset already, so a query sent now reaches the new stack.
            let remapped = fake_dns_lookup(&dns_socket, dns_server, 0x7003, "netstack.test.")
                .await
                .map_err(|e| anyhow::anyhow!("no answer after the network changed: {e}"))?;
            anyhow::ensure!(
                remapped == fake_ip,
                "network reset changed the stable FakeIP mapping"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;

        // Release the registry lock before awaiting the shutdown.
        let manager = crate::runtime_managers().get(&runtime_id).cloned();
        if let Some(manager) = manager {
            manager.shutdown().await;
        }
        let process_result = timeout(Duration::from_secs(5), start_task)
            .await
            .map_err(|_| anyhow::anyhow!("native sail process did not stop"))??;
        tcp_echo.abort();
        first_udp_echo.abort();
        second_udp_echo.abort();
        process_result?;
        result
    }
}

/// These are descriptor-construction failure witnesses, deliberately not
/// device-identity positives. Production verifies the kernel identity first.
#[cfg(all(test, target_os = "linux"))]
mod owned_host_tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn duplicate(original: &impl AsRawFd) -> (i32, OwnedFd) {
        // SAFETY: the live source is borrowed; this creates a separately owned FD.
        let raw = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10000) };
        assert!(raw >= 10000);
        // SAFETY: a successful F_DUPFD_CLOEXEC transfers exactly this new owner.
        (raw, unsafe { OwnedFd::from_raw_fd(raw) })
    }
    fn closed(raw: i32) {
        // SAFETY: descriptor query only.
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }

    #[tokio::test]
    async fn failed_async_registration_closes_only_the_transferred_duplicate() {
        let original = std::fs::File::open("/dev/null").unwrap();
        let (raw, owned) = duplicate(&original);
        let reached_packet_io = std::cell::Cell::new(false);
        let result = OwnedHostIo::open(owned, |borrowed| {
            let mut config = tun::Configuration::default();
            config.raw_fd(borrowed).close_fd_on_drop(false);
            // Linux epoll refuses a regular character device. Exercise the
            // actual tun constructor/AsyncFd failure, not an injected Err.
            let device = tun::create_as_async(&config)?;
            reached_packet_io.set(true);
            TunPacketIo::new(device, 1500, 1).map_err(Into::into)
        });
        assert!(result.is_err());
        assert!(
            !reached_packet_io.get(),
            "the real AsyncFd registration must fail"
        );
        closed(raw);
        assert!(unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[tokio::test]
    async fn failed_packet_io_after_adoption_keeps_the_host_original_alive() {
        let (original, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let (raw, owned) = duplicate(&original);
        let registered = std::cell::Cell::new(false);
        let result = OwnedHostIo::open(owned, |borrowed| {
            let mut config = tun::Configuration::default();
            config.raw_fd(borrowed).close_fd_on_drop(false);
            let device = tun::create_as_async(&config)?;
            registered.set(true);
            // The actual next constructor rejects a zero batch. The tun's
            // borrowed internal handles must drop before the sole FD owner.
            TunPacketIo::new(device, 1500, 0).map_err(Into::into)
        });
        assert!(
            registered.get(),
            "the real tun/AsyncFd adoption must succeed first"
        );
        let error = match result {
            Ok(_) => panic!("zero batch was accepted"),
            Err(error) => error,
        };
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
        closed(raw);
        assert!(unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) } >= 0);
        peer.send(b"host original survives").unwrap();
        let mut buffer = [0; 64];
        let length = original.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..length], b"host original survives");
    }

    #[tokio::test]
    async fn failed_runtime_group_construction_releases_the_actual_io_owner() {
        let (original, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let (raw, owned) = duplicate(&original);
        let io = OwnedHostIo::open(owned, |borrowed| {
            let mut config = tun::Configuration::default();
            config.raw_fd(borrowed).close_fd_on_drop(false);
            let device = tun::create_as_async(&config)?;
            TunPacketIo::new(device, 1500, 1).map_err(Into::into)
        })
        .unwrap();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::net::netstack::NativeRuntimeGroup::new(
                vec![io],
                sail_netstack::ResourceLedger::new(sail_netstack::BudgetProfile::Mobile.budget())
                    .unwrap(),
                sail_netstack::RunnerConfig::default(),
                8,
                0,
                8,
            )
        }));
        assert!(
            failed.is_err(),
            "the actual runtime rejects zero accept capacity"
        );
        closed(raw);
        assert!(unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) } >= 0);
    }
}
