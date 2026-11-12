//! A bounded public IP-packet bridge, including iOS packetFlow hosts.
use std::io;
use std::sync::Weak;

use sail_netstack::{
    ChecksumCapabilities, Packet, PacketBatch, PacketCapabilities, PacketIo, PacketToken,
};
use tokio::sync::mpsc;

use super::{Error, ErrorKind, Instance};
use crate::RuntimeManager;

/// The explicit dynamic attachment's state. Static startup TUNs are separate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TunState {
    Detached,
    Prepared {
        tag: String,
    },
    Committing {
        tag: String,
    },
    Attached {
        tag: String,
    },
    /// The packet transport/stack failed locally; detach drains this generation.
    Failed {
        tag: String,
        reason: String,
    },
    /// Resources have not all ended. A new attachment is refused until drained.
    Draining {
        tag: String,
    },
}

/// IP packets entering Sail. Clones share a bounded queue.
#[derive(Clone, Debug)]
pub struct TunPacketSender {
    tx: mpsc::Sender<Vec<u8>>,
}
impl TunPacketSender {
    /// Sends one complete IPv4/IPv6 packet, without a platform address-family header.
    /// Backpressures when full. Cancellation accepts no packet; the supplied Vec
    /// is dropped. Detach wakes this call with BrokenPipe.
    pub async fn send(&self, packet: Vec<u8>) -> io::Result<()> {
        if packet.is_empty() || packet.len() > MAX_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IP packet length must be 1..=65535",
            ));
        }
        self.tx.send(packet).await.map_err(|_| closed())
    }
}

/// IP packets leaving Sail for the host's public packetFlow write API.
#[derive(Debug)]
pub struct TunPacketReceiver {
    rx: mpsc::Receiver<Vec<u8>>,
    ended: tokio::sync::watch::Receiver<bool>,
}
impl TunPacketReceiver {
    /// Receives a whole packet. None once the attachment ends, discarding
    /// any queued output of that generation. Cancel-safe. Drop to refuse output.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        if *self.ended.borrow() {
            self.rx.close();
            while self.rx.try_recv().is_ok() {}
            return None;
        }
        tokio::select! {
            biased;
            _ = self.ended.changed() => { self.rx.close(); while self.rx.try_recv().is_ok() {} None },
            packet = self.rx.recv() => packet,
        }
    }
}

/// Move the two ends into independent host read/write tasks. The host owns
/// its packetFlow and its OS routes/DNS; Sail never closes or changes them.
#[derive(Debug)]
#[non_exhaustive]
pub struct TunPacketFlow {
    pub uplink: TunPacketSender,
    pub downlink: TunPacketReceiver,
}

const MAX_PACKET: usize = 65_535;
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "TUN attachment ended")
}

pub(crate) struct PacketBridge {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    next: u64,
    ended: tokio::sync::watch::Sender<bool>,
}
impl PacketBridge {
    pub(crate) fn pair(capacity: usize) -> Result<(Self, TunPacketFlow), Error> {
        if !(1..=4096).contains(&capacity) {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "packet queue capacity must be 1..=4096",
            ));
        }
        let (uplink, rx) = mpsc::channel(capacity);
        let (tx, downlink) = mpsc::channel(capacity);
        let (ended, end) = tokio::sync::watch::channel(false);
        Ok((
            Self {
                rx,
                tx,
                next: 0,
                ended,
            },
            TunPacketFlow {
                uplink: TunPacketSender { tx: uplink },
                downlink: TunPacketReceiver {
                    rx: downlink,
                    ended: end,
                },
            },
        ))
    }
}
impl Drop for PacketBridge {
    fn drop(&mut self) {
        let _ = self.ended.send(true);
    }
}
impl PacketIo for PacketBridge {
    async fn recv(&mut self, out: &mut PacketBatch) -> io::Result<usize> {
        if out.len() == out.limit() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "full receive batch",
            ));
        }
        let packet = self.rx.recv().await.ok_or_else(closed)?;
        out.push(Packet::from_payload(
            PacketToken::new(self.next),
            0,
            &packet,
        ))
        .map_err(|_| io::Error::other("full receive batch"))?;
        self.next = self.next.wrapping_add(1);
        Ok(1)
    }
    async fn send(&mut self, packets: &PacketBatch) -> io::Result<usize> {
        let Some(packet) = packets.iter().next() else {
            return Ok(0);
        };
        if packet.payload().is_empty() || packet.payload().len() > MAX_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid output IP packet length",
            ));
        }
        // Reserve before accepting anything. Never await after enqueue: a
        // cancelled send cannot cause an already accepted packet to be retried.
        let permit = self.tx.reserve().await.map_err(|_| closed())?;
        permit.send(packet.payload().to_vec());
        Ok(1)
    }
    fn capabilities(&self) -> PacketCapabilities {
        PacketCapabilities {
            max_batch: 1,
            queue_count: 1,
            headroom: 0,
            vectored: false,
            rx_checksum: ChecksumCapabilities::default(),
            tx_checksum: ChecksumCapabilities::default(),
            gso: None,
        }
    }
}

/// A reservation in one run. Not cloneable; commit consumes it. Drop rolls
/// back a prepared attachment, even if its packet endpoints remain with the host.
pub struct PreparedTun {
    pub(crate) manager: Weak<RuntimeManager>,
    pub(crate) token: u64,
    pub(crate) armed: bool,
}
impl std::fmt::Debug for PreparedTun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedTun").finish_non_exhaustive()
    }
}
impl Drop for PreparedTun {
    fn drop(&mut self) {
        if self.armed {
            if let Some(manager) = self.manager.upgrade() {
                manager.cancel_prepared_tun(self.token);
            }
        }
    }
}
impl PreparedTun {
    /// Publishes this run's prepared ingress. Once polled, the operation
    /// continues on Sail's runtime if this await is cancelled. Use detach
    /// to reconcile an uncertain result. A stopped/restarted run rejects it.
    pub async fn commit(mut self) -> Result<(), Error> {
        let manager = self.manager.upgrade().ok_or_else(Error::not_running)?;
        let token = self.token;
        let scope = manager.prepared_tun_scope(token)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task_manager = manager.clone();
        scope.spawn_on(manager.handle(), "commit dynamic tun", async move {
            let result = task_manager.commit_prepared_tun(token).await;
            if result.is_err() {
                task_manager.cancel_prepared_tun(token);
            }
            let _ = tx.send(result);
        });
        self.armed = false;
        rx.await.map_err(|_| {
            Error::new(
                ErrorKind::Cancelled,
                "dynamic TUN commit cancelled by detach or instance stop",
            )
        })?
    }
}
impl Instance {
    /// Prepares an unrouted TUN with a public packet transport. `inbound_json`
    /// is one sing-box TUN inbound object. Requires Options::dynamic_tun(true).
    /// No OS device, routes or DNS are opened/changed. Both queues hold at
    /// most `capacity` packets of at most 65535 bytes, plus netstack budgets.
    pub async fn prepare_tun_packets(
        &self,
        inbound_json: &str,
        capacity: usize,
    ) -> Result<(PreparedTun, TunPacketFlow), Error> {
        let json = inbound_json.to_owned();
        self.with_manager(move |manager| {
            Box::pin(async move { manager.prepare_tun_packets(&json, capacity).await })
        })
        .await?
    }
    /// Validates/reserves a Unix device TUN. Commit opens it, using the
    /// Platform's open_tun when enabled; otherwise Sail creates an unrouted
    /// device. No OS routes/DNS are installed by Sail. A host callback must
    /// provide its own transaction for any host-side network changes.
    #[cfg(unix)]
    pub async fn prepare_tun_device(&self, inbound_json: &str) -> Result<PreparedTun, Error> {
        let json = inbound_json.to_owned();
        self.with_manager(move |manager| {
            Box::pin(async move { manager.prepare_tun_device(&json).await })
        })
        .await?
    }
    /// Stops only the dynamic attachment, including its captured TCP/UDP
    /// flows. Idempotent. Success with clean()==false explicitly reports
    /// resources not yet released; another attach is refused until drained.
    /// A cancelled await continues detaching on Sail's runtime.
    pub async fn detach_tun(&self) -> Result<crate::runtime::scope::StopReport, Error> {
        self.with_manager(|manager| Box::pin(async move { manager.detach_dynamic_tun().await }))
            .await?
    }
    pub fn tun_state(&self) -> Result<TunState, Error> {
        Ok(self.manager()?.dynamic_tun_state())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_packet_endpoints_wake_and_discard_the_ended_generation() {
        assert!(PacketBridge::pair(0).is_err());
        assert!(PacketBridge::pair(4097).is_err());
        let (bridge, mut flow) = PacketBridge::pair(1).unwrap();
        assert!(flow.uplink.send(Vec::new()).await.is_err());
        assert!(flow.uplink.send(vec![0; 65536]).await.is_err());
        flow.uplink.send(vec![0x45]).await.unwrap();
        let pending = flow.uplink.send(vec![0x60]);
        tokio::pin!(pending);
        assert!(futures::poll!(&mut pending).is_pending());
        bridge.tx.send(vec![0x45]).await.unwrap();
        drop(bridge);
        assert_eq!(pending.await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(
            flow.downlink.recv().await.is_none(),
            "ended output is not delivered to a later generation"
        );
    }
}
