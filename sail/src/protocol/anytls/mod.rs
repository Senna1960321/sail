//! AnyTLS: streams multiplexed over a TLS connection, with the first writes
//! of each connection padded to sizes the server chooses.
//!
//! See <https://github.com/anytls/anytls-go/blob/main/docs/protocol.md>.
//! This follows `sing-anytls`, which sing-box and mihomo use, including UDP
//! as UDP over TCP (version 2) to `sp.v2.udp-over-tcp.arpa`
//! (`transport::uot`): the inbound hands such a stream on like any other,
//! and it is served where every inbound's are.

// Each end uses its own part of these.
#[cfg_attr(
    not(all(feature = "inbound-anytls", feature = "outbound-anytls")),
    allow(dead_code)
)]
mod frame;
#[cfg_attr(
    not(all(feature = "inbound-anytls", feature = "outbound-anytls")),
    allow(dead_code)
)]
pub(crate) mod padding;
#[cfg_attr(
    not(all(feature = "inbound-anytls", feature = "outbound-anytls")),
    allow(dead_code)
)]
pub(crate) mod session;

/// Fuzzing (sail::fuzzing): see `session::fuzz`.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz(data: &[u8]) {
    session::fuzz(data);
}

#[cfg(feature = "inbound-anytls")]
pub mod inbound;
#[cfg(feature = "outbound-anytls")]
pub mod outbound;

#[cfg(all(test, feature = "inbound-anytls"))]
mod stall_tests;
