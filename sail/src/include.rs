//! Which inbound, outbound and endpoint protocols this build has.
//!
//! This is the one list of them. A protocol registers itself from its own
//! directory; adding one means adding its line here, under its feature.
//!
//! Transports (tls, reality, ws, quic, amux, obfs) and chains are not
//! protocols of their own: they are blocks of the protocols they carry, see
//! `transport::layers`.

use std::sync::LazyLock;

use crate::adapter::registry::{EndpointRegistry, InboundRegistry, OutboundRegistry, Registry};

/// Inbound protocols served by a listener of their own rather than by a
/// handler behind a network listener.
pub(crate) const LISTENER_INBOUNDS: &[&str] = &[
    #[cfg(feature = "inbound-tun")]
    "tun",
    #[cfg(feature = "inbound-cat")]
    "cat",
];

pub(crate) static OUTBOUNDS: LazyLock<OutboundRegistry> = LazyLock::new(|| {
    #[allow(unused_mut)]
    let mut registry = Registry::new("outbound");

    #[cfg(feature = "outbound-direct")]
    crate::protocol::direct::outbound::register(&mut registry);
    #[cfg(feature = "outbound-drop")]
    crate::protocol::drop::register(&mut registry);
    #[cfg(feature = "outbound-pass")]
    crate::protocol::pass::register(&mut registry);
    #[cfg(feature = "outbound-redirect")]
    crate::protocol::redirect::outbound::register(&mut registry);
    #[cfg(feature = "outbound-socks")]
    crate::protocol::socks::outbound::register(&mut registry);
    #[cfg(feature = "outbound-shadowsocks")]
    crate::protocol::shadowsocks::outbound::register(&mut registry);
    #[cfg(feature = "outbound-trojan")]
    crate::protocol::trojan::outbound::register(&mut registry);
    #[cfg(feature = "outbound-vmess")]
    crate::protocol::vmess::outbound::register(&mut registry);
    #[cfg(feature = "outbound-vless")]
    crate::protocol::vless::outbound::register(&mut registry);
    #[cfg(feature = "outbound-mptp")]
    crate::protocol::mptp::outbound::register(&mut registry);
    #[cfg(feature = "outbound-http")]
    crate::protocol::http::outbound::register(&mut registry);
    #[cfg(feature = "outbound-hysteria2")]
    crate::protocol::hysteria2::outbound::register(&mut registry);
    #[cfg(feature = "outbound-tuic")]
    crate::protocol::tuic::outbound::register(&mut registry);
    #[cfg(feature = "outbound-anytls")]
    crate::protocol::anytls::outbound::register(&mut registry);
    #[cfg(feature = "outbound-sail")]
    crate::protocol::sail::outbound::register(&mut registry);
    #[cfg(feature = "outbound-shadowtls")]
    crate::protocol::shadowtls::outbound::register(&mut registry);

    #[cfg(feature = "outbound-fallback")]
    crate::protocol::group::fallback::register(&mut registry);
    #[cfg(feature = "outbound-load-balance")]
    crate::protocol::group::load_balance::register(&mut registry);
    #[cfg(feature = "outbound-select")]
    crate::protocol::group::selector::register(&mut registry);
    #[cfg(feature = "outbound-smart")]
    crate::protocol::group::smart::register(&mut registry);
    #[cfg(feature = "outbound-tryall")]
    crate::protocol::group::tryall::register(&mut registry);
    #[cfg(feature = "outbound-network-group")]
    crate::protocol::group::network::register(&mut registry);
    #[cfg(feature = "outbound-urltest")]
    crate::protocol::group::urltest::register(&mut registry);

    #[cfg(feature = "plugin")]
    crate::app::outbound::plugin::register(&mut registry);

    registry
});

pub(crate) static INBOUNDS: LazyLock<InboundRegistry> = LazyLock::new(|| {
    #[allow(unused_mut)]
    let mut registry = Registry::new("inbound");

    #[cfg(feature = "inbound-direct")]
    crate::protocol::direct::inbound::register(&mut registry);
    #[cfg(feature = "inbound-socks")]
    crate::protocol::socks::inbound::register(&mut registry);
    #[cfg(feature = "inbound-http")]
    crate::protocol::http::inbound::register(&mut registry);
    #[cfg(feature = "inbound-shadowsocks")]
    crate::protocol::shadowsocks::inbound::register(&mut registry);
    #[cfg(feature = "inbound-trojan")]
    crate::protocol::trojan::inbound::register(&mut registry);
    #[cfg(feature = "inbound-vless")]
    crate::protocol::vless::inbound::register(&mut registry);
    #[cfg(feature = "inbound-vmess")]
    crate::protocol::vmess::inbound::register(&mut registry);
    #[cfg(feature = "inbound-mptp")]
    crate::protocol::mptp::inbound::register(&mut registry);
    #[cfg(feature = "inbound-hc")]
    crate::protocol::hc::inbound::register(&mut registry);
    #[cfg(feature = "inbound-mixed")]
    crate::protocol::mixed::inbound::register(&mut registry);
    #[cfg(feature = "inbound-hysteria2")]
    crate::protocol::hysteria2::inbound::register(&mut registry);
    #[cfg(feature = "inbound-tuic")]
    crate::protocol::tuic::inbound::register(&mut registry);
    #[cfg(feature = "inbound-anytls")]
    crate::protocol::anytls::inbound::register(&mut registry);
    #[cfg(feature = "inbound-sail")]
    crate::protocol::sail::inbound::register(&mut registry);
    #[cfg(feature = "inbound-shadowtls")]
    crate::protocol::shadowtls::inbound::register(&mut registry);
    #[cfg(all(feature = "inbound-nf", windows))]
    crate::protocol::nf::inbound::register(&mut registry);
    #[cfg(feature = "inbound-redirect")]
    crate::protocol::redirect::inbound::register(&mut registry);
    #[cfg(feature = "inbound-tproxy")]
    crate::protocol::tproxy::register(&mut registry);

    registry
});

/// Endpoints: an outbound and an inbound under one tag.
pub(crate) static ENDPOINTS: LazyLock<EndpointRegistry> = LazyLock::new(|| {
    #[allow(unused_mut)]
    let mut registry = Registry::new("endpoint");

    #[cfg(feature = "wireguard")]
    crate::protocol::wireguard::endpoint::register(&mut registry);

    registry
});

/// The inbound protocol `protocol`, as registered, as a listener inbound,
/// or as an endpoint, if it is any.
pub(crate) fn inbound_protocol(protocol: &str) -> Option<&'static str> {
    INBOUNDS
        .name(protocol)
        .or_else(|| LISTENER_INBOUNDS.iter().copied().find(|p| *p == protocol))
        .or_else(|| ENDPOINTS.name(protocol))
}
