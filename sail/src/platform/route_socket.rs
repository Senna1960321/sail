//! macOS's routing socket (PF_ROUTE) and routing table (sysctl
//! NET_RT_DUMP), spoken without route(8): adding and deleting the routes of
//! a TUN, and finding the interface of the default route.
//!
//! A message is an `rt_msghdr` followed by the socket addresses its
//! `rtm_addrs` names, in the order of their bits (destination, gateway,
//! netmask, ...), each padded to 4 bytes, as route(8) writes them.

// Adding routes is the TUN's; reading the default route is everyone's.
#![cfg_attr(not(feature = "inbound-tun"), allow(dead_code))]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTF_STATIC: i32 = 0x800;
const RTF_IFSCOPE: i32 = 0x100_0000;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
/// The address kinds a message may carry, in the order they follow it.
const RTAX_MAX: u32 = 8;

const HEADER: usize = std::mem::size_of::<libc::rt_msghdr>();

/// What a route message asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Add,
    Delete,
}

/// The message that adds or deletes the route to `dst` through `gateway`
/// (an address of the TUN: the kernel finds the interface from it), as
/// `route add -net DST GATEWAY` sends it.
#[cfg(test)]
fn message(change: Change, seq: i32, dst: (IpAddr, u8), gateway: IpAddr) -> Vec<u8> {
    message_via(
        change,
        seq,
        dst,
        Some(&Gateway::Ip(gateway)),
        RTF_UP | RTF_STATIC | RTF_GATEWAY,
    )
}

/// Where a route goes: a next hop, or an interface (a link address with
/// its index, as `route add -interface` sends it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Gateway {
    Ip(IpAddr),
    Link { index: u16, name: String },
}

impl std::fmt::Display for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Gateway::Ip(address) => write!(f, "{}", address),
            Gateway::Link { name, .. } => write!(f, "interface {}", name),
        }
    }
}

/// Appends a `sockaddr_dl` of interface `index`, named `name` when the
/// name fits.
fn push_link(out: &mut Vec<u8>, index: u16, name: &str) {
    // sdl_len, sdl_family, sdl_index, sdl_type, sdl_nlen, sdl_alen,
    // sdl_slen, sdl_data[12]
    let name = if name.len() <= 12 {
        name.as_bytes()
    } else {
        &[]
    };
    out.extend_from_slice(&[20, libc::AF_LINK as u8]);
    out.extend_from_slice(&index.to_ne_bytes());
    out.extend_from_slice(&[0, name.len() as u8, 0, 0]);
    let mut data = [0u8; 12];
    data[..name.len()].copy_from_slice(name);
    out.extend_from_slice(&data);
}

/// The message that adds or deletes the route to `dst` through `gateway`
/// with `flags`; a delete may name no gateway: the route to `dst` that is
/// not bound to an interface goes, whatever its next hop.
pub(crate) fn message_via(
    change: Change,
    seq: i32,
    dst: (IpAddr, u8),
    gateway: Option<&Gateway>,
    flags: i32,
) -> Vec<u8> {
    let (address, len) = dst;
    let mut addresses = Vec::new();
    push_sockaddr(&mut addresses, masked(address, len));
    match gateway {
        Some(Gateway::Ip(gateway)) => push_sockaddr(&mut addresses, *gateway),
        Some(Gateway::Link { index, name }) => push_link(&mut addresses, *index, name),
        None => {}
    }
    push_sockaddr(&mut addresses, mask(address.is_ipv6(), len));

    // SAFETY: a plain C struct, all zeros valid.
    let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
    header.rtm_msglen = (HEADER + addresses.len()) as u16;
    header.rtm_version = libc::RTM_VERSION as u8;
    header.rtm_type = match change {
        Change::Add => RTM_ADD,
        Change::Delete => RTM_DELETE,
    };
    header.rtm_flags = flags;
    header.rtm_addrs = RTA_DST | RTA_NETMASK | if gateway.is_some() { RTA_GATEWAY } else { 0 };
    header.rtm_seq = seq;
    let mut bytes = Vec::with_capacity(usize::from(header.rtm_msglen));
    // SAFETY: the header's bytes, for its size.
    bytes.extend_from_slice(unsafe {
        std::slice::from_raw_parts(&header as *const _ as *const u8, HEADER)
    });
    bytes.extend_from_slice(&addresses);
    bytes
}

fn masked(address: IpAddr, len: u8) -> IpAddr {
    match address {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            Ipv4Addr::from(u32::from(a) & mask).into()
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            Ipv6Addr::from(u128::from(a) & mask).into()
        }
    }
}

fn mask(v6: bool, len: u8) -> IpAddr {
    if v6 {
        Ipv6Addr::from(u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0)).into()
    } else {
        Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0)).into()
    }
}

/// Appends a `sockaddr_in` or `sockaddr_in6` holding `address`.
fn push_sockaddr(out: &mut Vec<u8>, address: IpAddr) {
    match address {
        IpAddr::V4(a) => {
            // sin_len, sin_family, sin_port, sin_addr, sin_zero
            out.extend_from_slice(&[16, libc::AF_INET as u8, 0, 0]);
            out.extend_from_slice(&a.octets());
            out.extend_from_slice(&[0; 8]);
        }
        IpAddr::V6(a) => {
            // sin6_len, sin6_family, sin6_port, sin6_flowinfo, sin6_addr,
            // sin6_scope_id
            out.extend_from_slice(&[28, libc::AF_INET6 as u8, 0, 0]);
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&a.octets());
            out.extend_from_slice(&[0; 4]);
        }
    }
}

/// The addresses a message carries, by kind (RTAX_DST = 0, ...), from the
/// bytes after its header.
fn sockaddrs(addrs: i32, mut bytes: &[u8]) -> [Option<IpAddr>; RTAX_MAX as usize] {
    let mut found = [None; RTAX_MAX as usize];
    for (kind, slot) in found.iter_mut().enumerate() {
        if addrs & (1 << kind) == 0 {
            continue;
        }
        let Some(&len) = bytes.first() else {
            break;
        };
        // An empty sockaddr still takes 4 bytes; the rest are padded to 4.
        let taken = if len == 0 {
            4
        } else {
            (usize::from(len) + 3) & !3
        };
        if bytes.len() >= 2 {
            *slot = match i32::from(bytes[1]) {
                libc::AF_INET if len >= 8 => {
                    Some(IpAddr::from([bytes[4], bytes[5], bytes[6], bytes[7]]))
                }
                // A netmask may be cut short: the missing bytes are zeros.
                libc::AF_INET => {
                    let mut octets = [0u8; 4];
                    for (i, byte) in bytes.iter().take(usize::from(len)).skip(4).enumerate() {
                        octets[i] = *byte;
                    }
                    Some(IpAddr::from(octets))
                }
                libc::AF_INET6 if len >= 24 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&bytes[8..24]);
                    Some(IpAddr::from(octets))
                }
                // A netmask cut short, as for IPv4.
                libc::AF_INET6 => {
                    let mut octets = [0u8; 16];
                    for (i, byte) in bytes.iter().take(usize::from(len)).skip(8).enumerate() {
                        octets[i] = *byte;
                    }
                    Some(IpAddr::from(octets))
                }
                _ => None,
            };
        }
        bytes = bytes.get(taken..).unwrap_or_default();
    }
    found
}

/// A default route of the table: the interface index, whether it is
/// scoped to its interface, and its gateway, if it is an IP address (an
/// interface's own route has a link address there).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DefaultRoute {
    pub(crate) index: u16,
    scoped: bool,
    pub(crate) gateway: Option<IpAddr>,
}

/// The IPv4 default routes, up and through a gateway, of a table dump, in
/// its order.
fn default_routes(mut dump: &[u8]) -> Vec<DefaultRoute> {
    let mut routes = Vec::new();
    while dump.len() >= HEADER {
        let len = usize::from(u16::from_ne_bytes([dump[0], dump[1]]));
        if len < HEADER || len > dump.len() {
            break;
        }
        // SAFETY: at least a header's bytes; read unaligned.
        let header: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(dump.as_ptr() as *const libc::rt_msghdr) };
        let flags = header.rtm_flags;
        if flags & (RTF_UP | RTF_GATEWAY) == RTF_UP | RTF_GATEWAY {
            let found = sockaddrs(header.rtm_addrs, &dump[HEADER..len]);
            let destination = found[0];
            let netmask = found[2];
            let default = destination == Some(Ipv4Addr::UNSPECIFIED.into())
                && netmask.is_none_or(|m| m == IpAddr::from(Ipv4Addr::UNSPECIFIED));
            if default {
                routes.push(DefaultRoute {
                    index: header.rtm_index,
                    scoped: flags & RTF_IFSCOPE != 0,
                    gateway: found[1],
                });
            }
        }
        dump = &dump[len..];
    }
    routes
}

/// The routing table of IPv4, as the kernel dumps it.
#[cfg(target_os = "macos")]
fn dump_ipv4() -> io::Result<Vec<u8>> {
    dump(libc::AF_INET)
}

/// RTF_WASCLONED: a host route the kernel cloned from another as a cache.
#[cfg(feature = "inbound-tun")]
const RTF_WASCLONED: i32 = 0x2_0000;

/// The length of the netmask a message carries, read whatever family its
/// sockaddr says (BSD writes masks with none); none without a netmask.
fn netmask_length(addrs: i32, mut bytes: &[u8], v6: bool) -> Option<u8> {
    for kind in 0..RTAX_MAX {
        if addrs & (1 << kind) == 0 {
            continue;
        }
        let &len = bytes.first()?;
        let taken = if len == 0 {
            4
        } else {
            (usize::from(len) + 3) & !3
        };
        if kind == 2 {
            let start = if v6 { 8 } else { 4 };
            let end = usize::from(len).min(bytes.len());
            let ones: u32 = bytes
                .get(start..end)
                .unwrap_or_default()
                .iter()
                .map(|b| b.count_ones())
                .sum();
            return Some(ones as u8);
        }
        bytes = bytes.get(taken..).unwrap_or_default();
    }
    None
}

/// The routes of a table dump that are up, each with its length (a route
/// without a netmask is a host's), the kernel's cached clones aside.
#[cfg(feature = "inbound-tun")]
fn table_routes(mut dump: &[u8]) -> Vec<crate::platform::integrity::Route> {
    let mut routes = Vec::new();
    while dump.len() >= HEADER {
        let len = usize::from(u16::from_ne_bytes([dump[0], dump[1]]));
        if len < HEADER || len > dump.len() {
            break;
        }
        // SAFETY: at least a header's bytes; read unaligned.
        let header: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(dump.as_ptr() as *const libc::rt_msghdr) };
        let flags = header.rtm_flags;
        let bytes = &dump[HEADER..len];
        if flags & RTF_UP != 0 && flags & RTF_WASCLONED == 0 {
            if let Some(dst) = sockaddrs(header.rtm_addrs, bytes)[0] {
                let full = if dst.is_ipv6() { 128 } else { 32 };
                let length = if flags & libc::RTF_HOST != 0 {
                    full
                } else {
                    netmask_length(header.rtm_addrs, bytes, dst.is_ipv6()).unwrap_or(full)
                };
                routes.push(crate::platform::integrity::Route {
                    dst: masked(dst, length),
                    len: length,
                    index: u32::from(header.rtm_index),
                    scoped: flags & RTF_IFSCOPE != 0,
                });
            }
        }
        dump = &dump[len..];
    }
    routes
}

/// The routes of the system's table of a family, up, the kernel's cached
/// clones aside.
#[cfg(all(target_os = "macos", feature = "inbound-tun"))]
pub(crate) fn table(v6: bool) -> io::Result<Vec<crate::platform::integrity::Route>> {
    dump(if v6 { libc::AF_INET6 } else { libc::AF_INET }).map(|d| table_routes(&d))
}

/// A route of the table to exactly a destination, not bound to an
/// interface: where it goes, its interface's index and its flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Exact {
    pub(crate) gateway: Option<Gateway>,
    pub(crate) index: u16,
    pub(crate) flags: i32,
}

/// The `n`th socket address a message carries, if it carries it: its
/// bytes.
fn nth_sockaddr(addrs: i32, mut bytes: &[u8], n: u32) -> Option<&[u8]> {
    for kind in 0..RTAX_MAX {
        if addrs & (1 << kind) == 0 {
            continue;
        }
        let &len = bytes.first()?;
        let taken = if len == 0 {
            4
        } else {
            (usize::from(len) + 3) & !3
        };
        if kind == n {
            return bytes.get(..usize::from(len).min(bytes.len()));
        }
        bytes = bytes.get(taken..).unwrap_or_default();
    }
    None
}

/// The routes of a table dump to exactly `dst` that are up and bound to no
/// interface; a route to an interface has a link address for gateway.
fn exact_in(mut dump: &[u8], dst: (IpAddr, u8)) -> Vec<Exact> {
    let want = masked(dst.0, dst.1);
    let full = if want.is_ipv6() { 128 } else { 32 };
    let mut routes = Vec::new();
    while dump.len() >= HEADER {
        let len = usize::from(u16::from_ne_bytes([dump[0], dump[1]]));
        if len < HEADER || len > dump.len() {
            break;
        }
        // SAFETY: at least a header's bytes; read unaligned.
        let header: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(dump.as_ptr() as *const libc::rt_msghdr) };
        let bytes = &dump[HEADER..len];
        let flags = header.rtm_flags;
        let found = sockaddrs(header.rtm_addrs, bytes);
        let length = if flags & libc::RTF_HOST != 0 {
            Some(full)
        } else {
            netmask_length(header.rtm_addrs, bytes, want.is_ipv6())
        };
        if found[0] == Some(want)
            && length.unwrap_or(full) == dst.1
            && flags & RTF_UP != 0
            && flags & RTF_IFSCOPE == 0
        {
            let gateway = match found[1] {
                Some(address) => Some(Gateway::Ip(address)),
                None => nth_sockaddr(header.rtm_addrs, bytes, 1)
                    .filter(|sa| sa.len() >= 4 && i32::from(sa[1]) == libc::AF_LINK)
                    .map(|sa| Gateway::Link {
                        index: u16::from_ne_bytes([sa[2], sa[3]]),
                        name: String::new(),
                    }),
            };
            routes.push(Exact {
                gateway,
                index: header.rtm_index,
                flags,
            });
        }
        dump = &dump[len..];
    }
    routes
}

/// The routes to exactly `dst` now, bound to no interface.
#[cfg(target_os = "macos")]
pub(crate) fn exact(dst: (IpAddr, u8)) -> io::Result<Vec<Exact>> {
    let family = if dst.0.is_ipv6() {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    dump(family).map(|d| exact_in(&d, dst))
}

/// This boot, as kern.boottime tells it: "seconds.microseconds".
#[cfg(target_os = "macos")]
pub(crate) fn boot() -> io::Result<String> {
    let mut time = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut size = std::mem::size_of::<libc::timeval>();
    // SAFETY: `time` is writable for `size` bytes.
    let ret = unsafe {
        libc::sysctlbyname(
            c"kern.boottime".as_ptr(),
            &mut time as *mut libc::timeval as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(format!("{}.{:06}", time.tv_sec, time.tv_usec))
}

/// The index of the interface `name`, and whether it is up; none if
/// there is no such interface.
#[cfg(target_os = "macos")]
pub(crate) fn interface_now(name: &str) -> Option<(u32, bool)> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: a C string that lives through the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return None;
    }
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Some((index, false));
    }
    let mut up = false;
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: a node of the list getifaddrs returned, not yet freed.
        let ifa = unsafe { &*entry };
        entry = ifa.ifa_next;
        // SAFETY: the name is a C string owned by the list.
        if unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_bytes() == name.as_bytes() {
            up |= ifa.ifa_flags & libc::IFF_UP as u32 != 0;
        }
    }
    // SAFETY: the list getifaddrs returned, freed once.
    unsafe { libc::freeifaddrs(list) };
    Some((index, up))
}

/// Puts `replaced` back where it should go back (sweep's `put_back`), now
/// that sail's own route to its destination is gone; says what it did.
/// An error is the kernel's refusal to add it.
#[cfg(target_os = "macos")]
pub(crate) fn put_back(
    replaced: &crate::platform::sweep::Replaced,
) -> io::Result<crate::platform::sweep::PutBack> {
    use crate::platform::sweep::PutBack;
    let taken = !exact(replaced.dst)?.is_empty();
    let decision = replaced.put_back(&boot()?, taken, interface_now(&replaced.interface));
    if decision != PutBack::Put {
        return Ok(decision);
    }
    let gateway = match replaced.gateway {
        Some(address) => Gateway::Ip(address),
        None => Gateway::Link {
            index: u16::try_from(replaced.index).unwrap_or(0),
            name: replaced.interface.clone(),
        },
    };
    // Its own flags but those the kernel sets itself.
    let flags = replaced.flags
        & (RTF_GATEWAY | RTF_STATIC | libc::RTF_REJECT | libc::RTF_BLACKHOLE)
        | RTF_UP;
    match RouteSocket::open()?.send_via(Change::Add, replaced.dst, Some(&gateway), flags) {
        // Added in between: someone's, which wins.
        Err(e) if errno(&e) == Some(libc::EEXIST) => Ok(PutBack::Taken),
        other => other.map(|()| PutBack::Put),
    }
}

/// The routing table of `family`, as the kernel dumps it.
#[cfg(target_os = "macos")]
fn dump(family: i32) -> io::Result<Vec<u8>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        family,
        libc::NET_RT_DUMP,
        0,
    ];
    loop {
        let mut size = 0usize;
        // SAFETY: asks for the size only.
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u8; size + size / 8 + 1024];
        let mut filled = buffer.len();
        // SAFETY: `buffer` is writable for `filled` bytes.
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buffer.as_mut_ptr() as *mut libc::c_void,
                &mut filled,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret == 0 {
            buffer.truncate(filled);
            return Ok(buffer);
        }
        let e = io::Error::last_os_error();
        // The table grew in between: ask again.
        if e.raw_os_error() != Some(libc::ENOMEM) {
            return Err(e);
        }
    }
}

/// The system's default route: the first unscoped IPv4 one, or else the
/// first, as sing-tun reads it from the table. A TUN's split routes are
/// never a default route.
#[cfg(target_os = "macos")]
pub(crate) fn default_route() -> io::Result<DefaultRoute> {
    let routes = default_routes(&dump_ipv4()?);
    routes
        .iter()
        .find(|r| !r.scoped)
        .or_else(|| routes.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no default route"))
}

/// The interface of the system's default route.
#[cfg(target_os = "macos")]
pub(crate) fn default_interface() -> io::Result<String> {
    interface_name(default_route()?.index)
}

/// The name of interface `index`.
#[cfg(target_os = "macos")]
pub(crate) fn interface_name(index: u16) -> io::Result<String> {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `name` holds IF_NAMESIZE bytes, as if_indextoname needs.
    let found = unsafe { libc::if_indextoname(u32::from(index), name.as_mut_ptr()) };
    if found.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: if_indextoname wrote a C string into `name`.
    Ok(unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

/// A routing socket, writing one message at a time and reading its answer.
#[cfg(target_os = "macos")]
pub(crate) struct RouteSocket {
    fd: std::os::fd::OwnedFd,
    seq: std::sync::atomic::AtomicI32,
}

#[cfg(target_os = "macos")]
impl RouteSocket {
    pub(crate) fn open() -> io::Result<RouteSocket> {
        use std::os::fd::FromRawFd;
        // SAFETY: plain socket(2); owned from here on.
        let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor just opened, owned by none else.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        Ok(RouteSocket {
            fd,
            seq: std::sync::atomic::AtomicI32::new(1),
        })
    }

    /// Adds the route to `dst` through `gateway`. One already there -- left
    /// by a run that died, another VPN's, or the kernel's for an address's
    /// own network -- is replaced, as sing-tun does (tun_darwin.go
    /// setRoutes); returns what was there, in words, when one was.
    /// Adds the route to `dst` through `gateway`; one there already is
    /// EEXIST, which `replace` deals with.
    pub(crate) fn add(&self, dst: (IpAddr, u8), gateway: IpAddr) -> io::Result<()> {
        self.send(Change::Add, dst, gateway)
    }

    /// Deletes the route to `dst` bound to no interface, whatever it goes
    /// through (`was`, for what is said), and adds sail's through
    /// `gateway`.
    pub(crate) fn replace(&self, dst: (IpAddr, u8), was: &str, gateway: IpAddr) -> io::Result<()> {
        let _ = self.send_via(Change::Delete, dst, None, RTF_UP);
        self.send(Change::Add, dst, gateway).map_err(|e| {
            // The table has changed all the same: say so.
            io::Error::new(
                e.kind(),
                Failed {
                    errno: errno(&e).unwrap_or(0),
                    message: format!("{}, after deleting the route that was there ({})", e, was),
                },
            )
        })
    }

    pub(crate) fn delete(&self, dst: (IpAddr, u8), gateway: IpAddr) -> io::Result<()> {
        self.send(Change::Delete, dst, gateway)
    }

    fn send(&self, change: Change, dst: (IpAddr, u8), gateway: IpAddr) -> io::Result<()> {
        self.send_via(
            change,
            dst,
            Some(&Gateway::Ip(gateway)),
            RTF_UP | RTF_STATIC | RTF_GATEWAY,
        )
    }

    fn send_via(
        &self,
        change: Change,
        dst: (IpAddr, u8),
        gateway: Option<&Gateway>,
        flags: i32,
    ) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let message = message_via(change, seq, dst, gateway, flags);
        // A write fails with the kernel's error for the message.
        // SAFETY: `message` is readable for its length.
        let written = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                message.as_ptr() as *const libc::c_void,
                message.len(),
            )
        };
        if written < 0 {
            return Err(failed(io::Error::last_os_error(), change, dst, gateway));
        }
        Ok(())
    }
}

/// A change the kernel refused: its words, and its errno, which a caller
/// reads with `errno`.
#[derive(Debug)]
struct Failed {
    errno: i32,
    message: String,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failed {}

/// `e`, the kernel's answer to `change`, with what was being changed; its
/// errno kept.
fn failed(e: io::Error, change: Change, dst: (IpAddr, u8), gateway: Option<&Gateway>) -> io::Error {
    let via = gateway.map(|g| format!(" via {}", g)).unwrap_or_default();
    io::Error::new(
        e.kind(),
        Failed {
            errno: e.raw_os_error().unwrap_or(0),
            message: format!(
                "{} route {}/{}{}: {}",
                match change {
                    Change::Add => "adding",
                    Change::Delete => "deleting",
                },
                dst.0,
                dst.1,
                via,
                e
            ),
        },
    )
}

/// The errno an error of a route change carries.
pub(crate) fn errno(e: &io::Error) -> Option<i32> {
    e.raw_os_error().or_else(|| {
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<Failed>())
            .map(|failed| failed.errno)
    })
}

/// Tells of changes to routes, interfaces and addresses: any message on a
/// routing socket, as sing-tun takes them (monitor_darwin.go:36-100).
#[cfg(target_os = "macos")]
pub(crate) struct RouteMonitor {
    fd: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}

#[cfg(target_os = "macos")]
impl RouteMonitor {
    /// Needs a Tokio runtime.
    pub(crate) fn open() -> io::Result<RouteMonitor> {
        use std::os::fd::{AsRawFd, FromRawFd};
        // SAFETY: plain socket(2); owned from here on.
        let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor just opened, owned by none else.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        // SAFETY: fcntl on a descriptor this owns.
        let set = unsafe {
            let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            flags >= 0
                && libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
                && libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) >= 0
        };
        if !set {
            return Err(io::Error::last_os_error());
        }
        Ok(RouteMonitor {
            // SAFETY: fd owns the live routing socket set nonblocking above.
            // This private AsyncFd only lends shared references for read;
            // nothing closes or replaces its descriptor before deregistration.
            fd: unsafe { tokio::io::unix::AsyncFd::register(fd)? },
        })
    }

    /// Waits for a change, and takes every message that came with it. A
    /// message lost to an overrun still wakes it: it tells something
    /// changed.
    pub(crate) async fn changed(&self) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let mut guard = self.fd.readable().await?;
            let mut read_any = false;
            loop {
                // SAFETY: `buf` is writable for its length.
                let n = unsafe {
                    libc::read(
                        self.fd.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n > 0 {
                    read_any = true;
                    continue;
                }
                if n == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
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

#[cfg(test)]
mod tests {
    #[test]
    fn a_route_change_s_errno_survives_its_words() {
        for errno_ in [libc::EEXIST, libc::ESRCH] {
            let e = super::failed(
                io::Error::from_raw_os_error(errno_),
                Change::Add,
                ("10.0.0.0".parse().unwrap(), 8),
                Some(&Gateway::Ip("172.19.0.1".parse().unwrap())),
            );
            assert_eq!(super::errno(&e), Some(errno_));
            assert!(
                e.to_string()
                    .starts_with("adding route 10.0.0.0/8 via 172.19.0.1: "),
                "{e}"
            );
        }
    }

    /// Opens on this Mac without changing its routes: whether a change
    /// wakes it is seen in the network tests, never by changing a route
    /// here.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn the_monitor_opens() {
        let monitor = RouteMonitor::open().unwrap();
        // Nothing need change in a moment; it only must not fail.
        if let Ok(woke) =
            tokio::time::timeout(std::time::Duration::from_millis(50), monitor.changed()).await
        {
            woke.unwrap();
        }
    }

    use super::*;

    /// `route add -net 1.0.0.0/8 172.19.0.1`: the header, then the
    /// destination, the gateway and the netmask.
    #[test]
    fn an_added_ipv4_route_is_what_route_8_sends() {
        let bytes = message(
            Change::Add,
            7,
            ("1.2.3.4".parse().unwrap(), 8),
            "172.19.0.1".parse().unwrap(),
        );
        assert_eq!(bytes.len(), HEADER + 48);
        assert_eq!(
            u16::from_ne_bytes([bytes[0], bytes[1]]) as usize,
            bytes.len()
        );
        assert_eq!(bytes[2], 5); // RTM_VERSION
        assert_eq!(bytes[3], RTM_ADD);
        // SAFETY: at least a header's bytes.
        let header: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const libc::rt_msghdr) };
        assert_eq!(header.rtm_flags, RTF_UP | RTF_STATIC | RTF_GATEWAY);
        assert_eq!(header.rtm_addrs, RTA_DST | RTA_GATEWAY | RTA_NETMASK);
        assert_eq!(header.rtm_seq, 7);
        assert_eq!(
            &bytes[HEADER..],
            [
                16, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1.0.0.0
                16, 2, 0, 0, 172, 19, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, // 172.19.0.1
                16, 2, 0, 0, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 255.0.0.0
            ]
        );
    }

    #[test]
    fn an_ipv6_route_carries_sockaddr_in6() {
        let bytes = message(
            Change::Delete,
            1,
            ("8000::".parse().unwrap(), 1),
            "fdfe:dcba:9876::1".parse().unwrap(),
        );
        assert_eq!(bytes[3], RTM_DELETE);
        let found = sockaddrs(RTA_DST | RTA_GATEWAY | RTA_NETMASK, &bytes[HEADER..]);
        assert_eq!(found[0], Some("8000::".parse().unwrap()));
        assert_eq!(found[1], Some("fdfe:dcba:9876::1".parse().unwrap()));
        assert_eq!(found[2], Some("8000::".parse().unwrap()));
        assert_eq!(bytes.len(), HEADER + 3 * 28);
    }

    /// A dump holds a scoped default route first, then the primary one; a
    /// cut-short netmask of zeros is a default route's.
    #[test]
    fn the_default_route_is_found_in_a_dump() {
        let entry = |index: u16, flags: i32, dst: &str, netmask: &[u8]| {
            let mut addresses = Vec::new();
            push_sockaddr(&mut addresses, dst.parse().unwrap());
            push_sockaddr(&mut addresses, "192.168.1.1".parse().unwrap());
            addresses.extend_from_slice(netmask);
            // SAFETY: a plain C struct, all zeros valid.
            let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
            header.rtm_msglen = (HEADER + addresses.len()) as u16;
            header.rtm_index = index;
            header.rtm_flags = flags;
            header.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
            let mut bytes =
                unsafe { std::slice::from_raw_parts(&header as *const _ as *const u8, HEADER) }
                    .to_vec();
            bytes.extend_from_slice(&addresses);
            bytes
        };
        let mut dump = entry(
            9,
            RTF_UP | RTF_GATEWAY | RTF_IFSCOPE,
            "0.0.0.0",
            &[0, 0, 0, 0],
        );
        dump.extend(entry(
            4,
            RTF_UP | RTF_GATEWAY,
            "1.0.0.0",
            &[5, 2, 0, 0, 255, 0, 0, 0],
        ));
        dump.extend(entry(
            6,
            RTF_UP | RTF_GATEWAY | RTF_STATIC,
            "0.0.0.0",
            &[0, 0, 0, 0],
        ));
        dump.extend(entry(7, RTF_UP, "0.0.0.0", &[0, 0, 0, 0]));
        assert_eq!(
            default_routes(&dump),
            [
                DefaultRoute {
                    index: 9,
                    scoped: true,
                    gateway: Some("192.168.1.1".parse().unwrap()),
                },
                DefaultRoute {
                    index: 6,
                    scoped: false,
                    gateway: Some("192.168.1.1".parse().unwrap()),
                },
            ]
        );
    }

    /// Routes of a dump with their lengths: a netmask cut short or with
    /// no family, a host route, a scoped one; clones and routes down are
    /// left out.
    #[cfg(feature = "inbound-tun")]
    #[test]
    fn a_dump_s_routes_have_their_lengths() {
        let entry = |index: u16, flags: i32, dst: &str, netmask: Option<&[u8]>| {
            let mut addresses = Vec::new();
            push_sockaddr(&mut addresses, dst.parse().unwrap());
            push_sockaddr(&mut addresses, "192.168.1.1".parse().unwrap());
            let mut addrs = RTA_DST | RTA_GATEWAY;
            if let Some(netmask) = netmask {
                addresses.extend_from_slice(netmask);
                addrs |= RTA_NETMASK;
            }
            // SAFETY: a plain C struct, all zeros valid.
            let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
            header.rtm_msglen = (HEADER + addresses.len()) as u16;
            header.rtm_index = index;
            header.rtm_flags = flags;
            header.rtm_addrs = addrs;
            let mut bytes =
                unsafe { std::slice::from_raw_parts(&header as *const _ as *const u8, HEADER) }
                    .to_vec();
            bytes.extend_from_slice(&addresses);
            bytes
        };
        let mut dump = entry(4, RTF_UP | RTF_GATEWAY, "0.0.0.0", Some(&[0, 0, 0, 0]));
        dump.extend(entry(
            9,
            RTF_UP,
            "128.0.0.0",
            Some(&[5, 0, 0, 0, 128, 0, 0, 0]),
        ));
        dump.extend(entry(
            9,
            RTF_UP,
            "4.0.0.0",
            Some(&[6, 2, 0, 0, 252, 0, 0, 0]),
        ));
        dump.extend(entry(4, RTF_UP | libc::RTF_HOST, "1.1.1.1", None));
        dump.extend(entry(
            4,
            RTF_UP | RTF_GATEWAY | RTF_IFSCOPE,
            "0.0.0.0",
            Some(&[0, 0, 0, 0]),
        ));
        dump.extend(entry(
            4,
            RTF_UP | RTF_WASCLONED | libc::RTF_HOST,
            "1.0.0.1",
            None,
        ));
        dump.extend(entry(4, 0, "10.0.0.0", Some(&[5, 0, 0, 0, 255, 0, 0, 0])));
        let route = |dst: &str, len, index, scoped| crate::platform::integrity::Route {
            dst: dst.parse().unwrap(),
            len,
            index,
            scoped,
        };
        assert_eq!(
            table_routes(&dump),
            [
                route("0.0.0.0", 0, 4, false),
                route("128.0.0.0", 1, 9, false),
                route("4.0.0.0", 6, 9, false),
                route("1.1.1.1", 32, 4, false),
                route("0.0.0.0", 0, 4, true),
            ]
        );
    }

    /// A route to an interface carries a link address for gateway, with
    /// the interface's index, and no RTF_GATEWAY; a delete may carry no
    /// gateway at all.
    #[test]
    fn a_route_to_an_interface_carries_its_link() {
        let lo0 = Gateway::Link {
            index: 1,
            name: "lo0".into(),
        };
        let bytes = message_via(
            Change::Add,
            7,
            ("198.18.0.0".parse().unwrap(), 15),
            Some(&lo0),
            RTF_UP | RTF_STATIC,
        );
        // SAFETY: at least a header's bytes; read unaligned.
        let header: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const libc::rt_msghdr) };
        assert_eq!(header.rtm_flags, RTF_UP | RTF_STATIC);
        assert_eq!(header.rtm_addrs, RTA_DST | RTA_GATEWAY | RTA_NETMASK);
        let link = &bytes[HEADER + 16..HEADER + 36];
        assert_eq!(&link[..4], &[20, libc::AF_LINK as u8, 1, 0]);
        assert_eq!(&link[5..6], &[3]);
        assert_eq!(&link[8..11], b"lo0");
        assert_eq!(bytes.len(), HEADER + 16 + 20 + 16);

        let delete = message_via(
            Change::Delete,
            8,
            ("198.18.0.0".parse().unwrap(), 15),
            None,
            RTF_UP,
        );
        assert_eq!(delete.len(), HEADER + 16 + 16);
        // The route as a dump gives it back: its link, index and flags.
        let dump = bytes;
        let found = exact_in(&dump, ("198.18.0.0".parse().unwrap(), 15));
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].gateway,
            Some(Gateway::Link {
                index: 1,
                name: String::new()
            })
        );
        assert!(exact_in(&dump, ("198.18.0.0".parse().unwrap(), 16)).is_empty());
    }

    /// Reading this host's table changes nothing: whatever it holds, the
    /// dump parses, and a host with a network has a default interface.
    #[cfg(target_os = "macos")]
    #[test]
    fn this_host_s_table_is_read() {
        let dump = dump_ipv4().unwrap();
        assert!(!dump.is_empty());
        if let Ok(name) = default_interface() {
            assert!(!name.is_empty());
        }
    }
}
