//! Registration follows real queue resources, not runner/manager metadata.
use crate::net::network::OwnedInterfaceLease;
use sail_netstack::{PacketBatch, PacketCapabilities, PacketIo};
use std::sync::{Arc, Mutex, Weak};

pub(crate) struct Registration(Mutex<Option<OwnedInterfaceLease>>);

/// I/O must drop before this queue's registration reference. The final queue
/// releases the lease, including when outer runner metadata remains retained.
pub(crate) struct DeviceIo<I> {
    io: I,
    _registration: Arc<Registration>,
}

pub(crate) fn track<I>(queues: Vec<I>) -> (Vec<DeviceIo<I>>, Weak<Registration>) {
    let registration = Arc::new(Registration(Mutex::new(None)));
    let weak = Arc::downgrade(&registration);
    let queues = queues
        .into_iter()
        .map(|io| DeviceIo {
            io,
            _registration: registration.clone(),
        })
        .collect();
    (queues, weak)
}

/// Called only after the caller fences the current run/token and verifies the
/// device name. An expired queue handle refuses publication before acquisition.
pub(crate) fn publish(
    registration: &Weak<Registration>,
    acquire: impl FnOnce() -> OwnedInterfaceLease,
) -> std::io::Result<()> {
    let registration = registration.upgrade().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "dynamic device I/O ended before publication",
        )
    })?;
    let mut lease = registration
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if lease.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "dynamic device was already registered",
        ));
    }
    *lease = Some(acquire());
    Ok(())
}

impl<I: PacketIo> PacketIo for DeviceIo<I> {
    async fn recv(&mut self, out: &mut PacketBatch) -> std::io::Result<usize> {
        self.io.recv(out).await
    }
    async fn send(&mut self, packets: &PacketBatch) -> std::io::Result<usize> {
        self.io.send(packets).await
    }
    fn capabilities(&self) -> PacketCapabilities {
        self.io.capabilities()
    }
    fn owns_flow(&self, endpoint: sail_netstack::IpEndpoint) -> bool {
        self.io.owns_flow(endpoint)
    }
}

/// Resource-only witnesses use real descriptor/AsyncFd owners over Unix sockets.
/// Their names model registry keys; they are not kernel TUN identity positives.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::net::network::Network;
    use crate::protocol::tun::packet_io::{OwnedHostIo, TunPacketIo};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    struct Queue {
        io: OwnedHostIo<TunPacketIo>,
        network: Network,
        raw: i32,
    }
    impl Drop for Queue {
        fn drop(&mut self) {
            assert!(
                self.network
                    .egress_view()
                    .own
                    .iter()
                    .any(|name| name == "tunA"),
                "registration must outlive actual queue I/O"
            );
            assert!(unsafe { libc::fcntl(self.raw, libc::F_GETFD) } >= 0);
            // The io field now drops, closing the borrowed device and FD,
            // before DeviceIo releases its registration reference.
        }
    }
    impl PacketIo for Queue {
        async fn recv(&mut self, out: &mut PacketBatch) -> std::io::Result<usize> {
            self.io.recv(out).await
        }
        async fn send(&mut self, packets: &PacketBatch) -> std::io::Result<usize> {
            self.io.send(packets).await
        }
        fn capabilities(&self) -> PacketCapabilities {
            self.io.capabilities()
        }
    }
    fn queue(network: &Network) -> (Queue, std::os::unix::net::UnixDatagram) {
        let (original, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        // SAFETY: the original remains borrowed; only the new FD is transferred.
        let raw = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10000) };
        assert!(raw >= 10000);
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let io = OwnedHostIo::open(owned, |borrowed| {
            let mut config = tun::Configuration::default();
            config.raw_fd(borrowed).close_fd_on_drop(false);
            let device = tun::create_as_async(&config)?;
            TunPacketIo::new(device, 1500, 1).map_err(Into::into)
        })
        .unwrap();
        (
            Queue {
                io,
                network: network.clone(),
                raw,
            },
            original,
        )
    }
    fn closed(raw: i32) {
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[tokio::test]
    async fn only_the_last_actual_queue_releases_ownership_despite_retained_metadata() {
        let network = Network::default();
        let (first, original_a) = queue(&network);
        let (second, original_b) = queue(&network);
        let a = first.raw;
        let b = second.raw;
        let (mut queues, registration) = track(vec![first, second]);
        assert!(network.egress_view().own.is_empty());
        let before = network.snapshot_with_generation().generation;
        publish(&registration, || network.own_interface("tunA")).unwrap();
        let outer_metadata = registration.clone();
        drop(outer_metadata); // actual queues, not outer runner metadata, own it.
        let retained_manager_network = network.clone();
        drop(queues.pop());
        closed(b);
        assert!(network.egress_view().own.iter().any(|name| name == "tunA"));
        drop(queues.pop());
        closed(a);
        assert!(retained_manager_network.egress_view().own.is_empty());
        assert!(
            registration.upgrade().is_none(),
            "retained Weak metadata cannot extend ownership"
        );
        assert_eq!(network.snapshot_with_generation().generation, before);
        assert!(unsafe { libc::fcntl(original_a.as_raw_fd(), libc::F_GETFD) } >= 0);
        assert!(unsafe { libc::fcntl(original_b.as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[tokio::test]
    async fn old_same_named_queue_release_cannot_remove_the_new_lease() {
        let network = Network::default();
        let (a, _original_a) = queue(&network);
        let (b, _original_b) = queue(&network);
        let old_fd = a.raw;
        let new_fd = b.raw;
        let (old, old_metadata) = track(vec![a]);
        let (new, new_metadata) = track(vec![b]);
        publish(&old_metadata, || network.own_interface("tunA")).unwrap();
        publish(&new_metadata, || network.own_interface("tunA")).unwrap();
        assert_eq!(network.egress_view().own.len(), 2);
        drop(old);
        closed(old_fd);
        assert_eq!(network.egress_view().own, ["tunA"]);
        assert!(publish(&new_metadata, || panic!(
            "duplicate publication must not acquire"
        ))
        .is_err());
        drop(new);
        closed(new_fd);
        assert!(network.egress_view().own.is_empty());
    }

    #[test]
    fn expired_or_empty_queue_ownership_refuses_publication_before_acquiring() {
        let network = Network::default();
        let (queues, registration) = track(Vec::<()>::new());
        drop(queues);
        let called = std::cell::Cell::new(false);
        let error = publish(&registration, || {
            called.set(true);
            network.own_interface("tunA")
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(!called.get());
        assert!(network.egress_view().own.is_empty());
    }
}
