use std::sync::Arc;

pub mod dispatcher;
pub mod dns;
pub mod healthcheck;
#[cfg(feature = "http-client")]
pub(crate) mod http;
/// Without a client, downloads cannot be configured.
#[cfg(not(feature = "http-client"))]
pub(crate) mod http {
    /// What downloads would go with.
    pub(crate) struct HttpClients;

    impl HttpClients {
        pub(crate) fn new(
            _config: &crate::config::Config,
            _dial: std::sync::Arc<crate::net::DialDefaults>,
        ) -> Self {
            HttpClients
        }
    }
}
pub mod inbound;
pub mod instance;
pub mod logger;
pub mod nat_manager;
pub mod ntp;
pub mod outbound;
pub(crate) mod owner;
#[cfg(feature = "outbound-provider")]
pub(crate) mod provider;
pub(crate) mod recheck;
pub mod router;
pub mod sessions;
pub mod stat_manager;
#[cfg(feature = "internal-udp-target-diagnostics")]
#[doc(hidden)]
pub mod udp_target_diagnostics;

#[cfg(feature = "api")]
pub mod api;

#[cfg(feature = "clash-api")]
pub(crate) mod clash_api;
pub mod clash_mode;
pub mod fake_dns;

pub mod dns_client {
    pub use super::dns::*;
}

/// The DNS client of an instance. A reload replaces it whole; readers take
/// the current one without locking.
pub type SyncDnsClient = Arc<arc_swap::ArcSwap<dns::DnsClient>>;

/// The routing of an instance, replaced whole on reload.
pub type SyncRouter = Arc<arc_swap::ArcSwap<router::Router>>;

/// The outbounds of an instance, replaced whole on reload.
pub type SyncOutboundManager = Arc<arc_swap::ArcSwap<outbound::manager::OutboundManager>>;

pub use stat_manager::SyncStatManager;
