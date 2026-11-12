//! Kernel-verified identity for a dynamic device, never a configuration hint.
use std::os::fd::RawFd;

#[derive(Debug)]
pub(crate) struct VerifiedDeviceName(String);
impl VerifiedDeviceName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DeviceIdentityError {
    #[error("dynamic TUN kernel identity query failed: {0}")]
    Query(#[source] std::io::Error),
    #[error(
        "dynamic TUN device identity mismatch: expected [{expected}], kernel returned [{actual}]"
    )]
    Mismatch { expected: String, actual: String },
}
impl DeviceIdentityError {
    pub(crate) fn kind(&self) -> std::io::ErrorKind {
        match self {
            Self::Query(error) => error.kind(),
            Self::Mismatch { .. } => std::io::ErrorKind::InvalidInput,
        }
    }
}

fn checked_name(expected: &str, actual: String) -> Result<VerifiedDeviceName, DeviceIdentityError> {
    if actual.is_empty() {
        return Err(DeviceIdentityError::Query(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "kernel returned an empty device name",
        )));
    }
    if actual != expected {
        return Err(DeviceIdentityError::Mismatch {
            expected: expected.into(),
            actual,
        });
    }
    Ok(VerifiedDeviceName(actual))
}

/// Borrows a live descriptor for a read-only kernel query. It never duplicates,
/// closes, configures or adopts the descriptor. The caller owns it throughout.
pub(crate) fn verify(fd: RawFd, expected: &str) -> Result<VerifiedDeviceName, DeviceIdentityError> {
    checked_name(
        expected,
        kernel_name(fd).map_err(DeviceIdentityError::Query)?,
    )
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn decode_name(bytes: &[libc::c_char]) -> std::io::Result<String> {
    let length = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unterminated kernel interface name",
        )
    })?;
    let bytes = bytes[..length]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn kernel_name(fd: RawFd) -> std::io::Result<String> {
    // SAFETY: ifreq is a C request buffer; zero is valid for all its fields.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    // SAFETY: TUNGETIFF only fills this live, correctly sized request buffer.
    if unsafe { libc::ioctl(fd, libc::TUNGETIFF, &mut request) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    decode_name(&request.ifr_name)
}

#[cfg(target_vendor = "apple")]
fn kernel_name(fd: RawFd) -> std::io::Result<String> {
    // Darwin's public utun socket option (net/if_utun.h).
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    // SAFETY: name and length are live output buffers of the advertised size.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let length = usize::try_from(length)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if length > name.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized kernel interface name",
        ));
    }
    decode_name(&name[..length])
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn kernel_name(_: RawFd) -> std::io::Result<String> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "dynamic device identity querying is not implemented on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verified_identity_requires_a_nonempty_exact_kernel_name() {
        assert!(checked_name("", String::new()).is_err());
        assert!(matches!(
            checked_name("tunA", "tunB".into()),
            Err(DeviceIdentityError::Mismatch { .. })
        ));
        assert_eq!(
            checked_name("tunA", "tunA".into()).unwrap().as_str(),
            "tunA"
        );
    }
    #[test]
    fn a_socket_cannot_be_registered_as_a_tun_using_a_name_hint() {
        use std::os::fd::AsRawFd;
        let (socket, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        assert!(matches!(
            verify(socket.as_raw_fd(), "tunA"),
            Err(DeviceIdentityError::Query(_))
        ));
        assert!(
            socket.local_addr().is_ok(),
            "query never consumes the host descriptor"
        );
    }
}
