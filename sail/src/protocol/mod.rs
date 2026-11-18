//! Proxy protocols. Each protocol keeps its inbound and outbound side
//! together in one directory.

#[cfg(any(feature = "inbound-anytls", feature = "outbound-anytls"))]
pub mod anytls;
#[cfg(any(feature = "inbound-direct", feature = "outbound-direct"))]
pub mod direct;
#[cfg(feature = "outbound-drop")]
pub mod drop;
#[cfg(any(
    feature = "inbound-anytls",
    feature = "inbound-trojan",
    feature = "inbound-vless",
    feature = "inbound-shadowtls"
))]
pub mod fallback;
#[cfg(feature = "inbound-hc")]
pub mod hc;
#[cfg(any(feature = "inbound-http", feature = "outbound-http"))]
pub mod http;
#[cfg(any(feature = "inbound-hysteria2", feature = "outbound-hysteria2"))]
pub mod hysteria2;
#[cfg(feature = "inbound-mixed")]
pub mod mixed;
#[cfg(any(feature = "inbound-mptp", feature = "outbound-mptp"))]
pub mod mptp;
#[cfg(all(feature = "inbound-nf", windows))]
pub mod nf;
#[cfg(feature = "outbound-pass")]
pub mod pass;
#[cfg(any(feature = "inbound-redirect", feature = "outbound-redirect"))]
pub mod redirect;
#[cfg(any(feature = "inbound-sail", feature = "outbound-sail"))]
pub mod sail;
#[cfg(any(feature = "inbound-shadowsocks", feature = "outbound-shadowsocks"))]
pub mod shadowsocks;
#[cfg(any(feature = "inbound-shadowtls", feature = "outbound-shadowtls"))]
pub mod shadowtls;
#[cfg(any(feature = "inbound-socks", feature = "outbound-socks"))]
pub mod socks;
#[cfg(feature = "inbound-tproxy")]
pub mod tproxy;
#[cfg(any(feature = "inbound-trojan", feature = "outbound-trojan"))]
pub mod trojan;
#[cfg(any(
    feature = "inbound-tuic",
    feature = "outbound-tuic",
    feature = "fuzzing"
))]
pub mod tuic;
#[cfg(feature = "inbound-tun")]
pub mod tun;
#[cfg(any(feature = "inbound-vless", feature = "outbound-vless"))]
pub mod vless;
#[cfg(feature = "wireguard")]
pub mod wireguard;
// XUDP lives with VMess and serves VLESS too.
#[cfg(any(
    feature = "inbound-vless",
    feature = "outbound-vless",
    feature = "inbound-vmess",
    feature = "outbound-vmess",
    feature = "fuzzing"
))]
pub mod vmess;

pub mod group;
