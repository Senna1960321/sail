#[cfg(target_os = "linux")]
pub(crate) mod auto_redirect;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) mod auto_route;
#[cfg(unix)]
pub(crate) mod device_identity;
#[cfg(unix)]
pub(crate) mod device_registration;
pub mod inbound;
mod packet_io;
#[cfg(all(target_os = "linux", feature = "fuzzing"))]
pub(crate) use packet_io::{fuzz_coalesce, fuzz_vnet_header};
#[cfg(target_os = "linux")]
mod prematch;
