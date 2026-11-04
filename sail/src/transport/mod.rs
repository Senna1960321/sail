//! Layers a protocol runs over: security, framing, multiplexing and
//! obfuscation.

#[cfg(any(feature = "inbound-amux", feature = "outbound-amux"))]
pub mod amux;
#[cfg(any(feature = "inbound-grpc", feature = "outbound-grpc"))]
pub mod grpc;
#[cfg(any(feature = "mux", feature = "outbound-http", feature = "inbound-http"))]
pub mod h2connect;
#[cfg(any(
    feature = "inbound-grpc",
    feature = "outbound-grpc",
    feature = "inbound-http",
    feature = "outbound-http"
))]
pub mod h2pool;
#[cfg(any(
    feature = "inbound-ws",
    feature = "outbound-ws",
    feature = "inbound-httpupgrade",
    feature = "outbound-httpupgrade"
))]
pub mod httpupgrade;
#[cfg(any(
    feature = "outbound-hysteria2",
    feature = "outbound-quic",
    feature = "outbound-grpc",
    feature = "outbound-http",
    feature = "outbound-amux"
))]
pub mod idle;
#[cfg(feature = "mux")]
pub mod mux;
#[cfg(any(
    feature = "mux",
    feature = "inbound-amux",
    feature = "outbound-amux",
    feature = "inbound-anytls",
    feature = "outbound-anytls",
    feature = "inbound-http",
    feature = "outbound-http",
    feature = "quic",
    feature = "muxcore"
))]
pub mod muxcore;
#[cfg(feature = "outbound-obfs")]
pub mod obfs;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(any(feature = "inbound-reality", feature = "outbound-reality"))]
pub mod reality;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "tls")]
pub mod tls_stream;
#[cfg(any(feature = "inbound-ws", feature = "outbound-ws"))]
pub mod ws;

pub mod layers;
pub mod uot;
#[cfg(any(
    feature = "inbound-vless",
    feature = "outbound-vless",
    feature = "outbound-reality",
    feature = "tls"
))]
pub mod vision;
