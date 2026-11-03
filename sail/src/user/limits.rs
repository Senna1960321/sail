//! What `user_limits` sets for a user, and what it shuts the user out for.

use std::fmt;
use std::time::{Duration, SystemTime};

/// How often expiry is checked even when no user is due: the system clock
/// may jump. Chosen as the counts are written, every minute; a connection
/// is refused at once however late the check.
pub(super) const RECHECK: Duration = Duration::from_secs(60);

/// A user's limits; none limits nothing. Made from `Default` and set field
/// by field: fields are added.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// How many connections it may have live at once: TCP connections, UDP
    /// sessions and the streams of multiplexed ones, each one.
    pub max_connections: Option<u32>,
    /// How many of them may be TCP at once: TCP connections and the
    /// streams of multiplexed ones, its UDP sessions not counted. With
    /// `max_connections` too, both apply.
    pub max_tcp_connections: Option<u32>,
    /// How many bytes, up and down together, it may send and receive.
    pub quota_bytes: Option<u64>,
    /// When it may no longer connect.
    pub expire_at: Option<SystemTime>,
    /// Its rate up, what its clients send, in Mbps.
    pub up_mbps: Option<u64>,
    /// Its rate down, what its clients receive, in Mbps.
    pub down_mbps: Option<u64>,
    /// Its rate up and down together, in Mbps: a byte either way passes
    /// when this and the rate its way, where set, both allow it.
    pub total_mbps: Option<u64>,
}

impl Limits {
    /// The limits `user_limits` sets for one user.
    pub fn from_config(limits: &crate::config::UserLimits) -> Self {
        Limits {
            max_connections: limits.max_connections,
            max_tcp_connections: limits.max_tcp_connections,
            quota_bytes: limits.quota_bytes,
            expire_at: limits.expire_at().map(SystemTime::from),
            up_mbps: limits.up_mbps,
            down_mbps: limits.down_mbps,
            total_mbps: limits.total_mbps,
        }
    }
}

/// What shuts a user out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status(u8);

impl Status {
    /// Over its quota.
    pub const EXHAUSTED: u8 = 1;
    /// Past its expiry.
    pub const EXPIRED: u8 = 2;

    pub fn from_bits(bits: u8) -> Self {
        Status(bits)
    }

    pub fn active(self) -> bool {
        self.0 == 0
    }

    pub fn exhausted(self) -> bool {
        self.0 & Self::EXHAUSTED != 0
    }

    pub fn expired(self) -> bool {
        self.0 & Self::EXPIRED != 0
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match (self.exhausted(), self.expired()) {
            (false, false) => f.write_str("active"),
            (true, false) => f.write_str("over its quota"),
            (false, true) => f.write_str("expired"),
            (true, true) => f.write_str("over its quota and expired"),
        }
    }
}
