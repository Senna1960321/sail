//! Tells when the host's interfaces or their addresses change: an rtnetlink
//! socket in the link and address groups (Linux).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use tokio::io::unix::AsyncFd;

pub(crate) struct AddressMonitor {
    fd: AsyncFd<OwnedFd>,
}

impl AddressMonitor {
    /// Tells of interfaces and addresses. Needs a Tokio runtime.
    #[cfg_attr(not(feature = "inbound-tun"), allow(dead_code))]
    pub(crate) fn open() -> io::Result<AddressMonitor> {
        Self::open_groups(libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR)
    }

    /// Tells of routes too, which move the default interface.
    pub(crate) fn open_with_routes() -> io::Result<AddressMonitor> {
        Self::open_groups(
            libc::RTMGRP_LINK
                | libc::RTMGRP_IPV4_IFADDR
                | libc::RTMGRP_IPV6_IFADDR
                | libc::RTMGRP_IPV4_ROUTE
                | libc::RTMGRP_IPV6_ROUTE,
        )
    }

    fn open_groups(groups: libc::c_int) -> io::Result<AddressMonitor> {
        // SAFETY: plain socket(2); the descriptor is owned from here on.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a descriptor just opened, and owned by none else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zeroed sockaddr_nl is valid; the fields set are its own.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = groups as u32;
        // SAFETY: `addr` is a sockaddr_nl of the length given.
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if bound < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(AddressMonitor {
            // SAFETY: fd owns the live, nonblocking netlink socket above.
            // This private AsyncFd only lends shared references for recv;
            // nothing closes or replaces its descriptor before deregistration.
            fd: unsafe { AsyncFd::register(fd)? },
        })
    }

    /// Waits for a change, and takes every notice that came with it. A
    /// notice lost to an overrun still wakes it: it tells something
    /// changed.
    pub(crate) async fn changed(&self) -> io::Result<()> {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let mut guard = self.fd.readable().await?;
            let mut read_any = false;
            loop {
                // SAFETY: `buf` is writable for its length.
                let n = unsafe {
                    libc::recv(
                        self.fd.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                if n >= 0 {
                    read_any = true;
                    continue;
                }
                let e = io::Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EAGAIN) => break,
                    Some(libc::ENOBUFS) => read_any = true,
                    Some(libc::EINTR) => {}
                    _ => return Err(e),
                }
            }
            guard.clear_ready();
            if read_any {
                return Ok(());
            }
        }
    }
}
