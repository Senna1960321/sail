#[cfg(feature = "outbound-select")]
use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "outbound-select")]
use tokio::sync::RwLock;

pub mod manager;

#[cfg(feature = "plugin")]
pub mod plugin;
#[cfg(feature = "outbound-select")]
pub mod selector;

#[cfg(feature = "outbound-select")]
pub type Selectors = HashMap<String, Arc<RwLock<selector::OutboundSelector>>>;

/// The checkers of the groups that test their members, by tag: a reload
/// carries what they found over to the groups that replace them.
#[cfg(any(
    feature = "outbound-urltest",
    feature = "outbound-load-balance",
    feature = "outbound-fallback"
))]
pub(crate) type Checkers =
    std::collections::HashMap<String, std::sync::Arc<dyn crate::protocol::group::health::Kept>>;
