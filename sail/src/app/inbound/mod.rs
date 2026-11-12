#[doc(hidden)]
pub mod admission;
#[cfg(feature = "inbound-tun")]
pub(crate) mod dynamic_tun;
#[cfg(feature = "auto-reload")]
pub(crate) mod follow;
pub(crate) mod handshakes;
pub use admission::AdmissionInfo;
mod magic;
pub use handshakes::HandshakePlace;
pub mod network_listener;
mod resource;

#[cfg(feature = "inbound-tun")]
mod tun_listener;

#[cfg(feature = "inbound-cat")]
mod cat_listener;

pub mod manager;

#[cfg(feature = "inbound-nf")]
pub use network_listener::get_network_listen_addr;
