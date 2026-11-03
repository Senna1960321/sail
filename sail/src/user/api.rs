//! What a host, or a management service, reads of the users and does to
//! them, as sing-box's ssm-api does for Shadowsocks users, but for any
//! inbound: list them and their traffic, read the traffic and clear it,
//! change a user's limits, reset its quota, disconnect it, and add or take
//! out a user of an inbound.
//!
//! None of it is kept: the configuration file is what a restart or a
//! reload goes by.

use super::{Counts, Limits, Status, UserRef};
use crate::app::stat_manager::TrafficReport;
use crate::{Error, RuntimeManager};
use anyhow::anyhow;

/// How many events a subscriber may fall behind by before it misses some.
/// A choice: events come a few at a time, when users are shut out or
/// taken out.
pub(super) const EVENTS: usize = 256;

/// What happened to a user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserEvent {
    /// It went over its quota, or past its expiry, and was disconnected.
    Shut { user: String, status: Status },
    /// It was taken out of an inbound, and disconnected from it.
    Removed { user: String, inbound: String },
}

/// A user as it is now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSnapshot {
    pub name: String,
    /// The inbounds whose configuration has it.
    pub inbounds: Vec<String>,
    pub status: Status,
    pub limits: Limits,
    /// Since it was first counted, across restarts with the cache file.
    pub traffic: Counts,
    /// Its live connections.
    pub live: usize,
    /// Up and down together since its quota was last reset.
    pub quota_used: u64,
}

fn snapshot(user: &UserRef, inbounds: Vec<String>) -> UserSnapshot {
    UserSnapshot {
        name: user.name().to_string(),
        inbounds,
        status: user.status(),
        limits: user.limits(),
        traffic: user.traffic().counts(),
        live: user.live(),
        quota_used: user.quota_used(),
    }
}

impl RuntimeManager {
    fn user_ref(&self, name: &str) -> Result<UserRef, Error> {
        self.env
            .users
            .get(name)
            .ok_or_else(|| Error::Config(anyhow!("user [{}]: there is none", name)))
    }

    /// The inbounds whose configuration has the user `name`.
    fn inbounds_of(&self, name: &str) -> Result<Vec<String>, Error> {
        let inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?;
        Ok(inbounds.inbounds_of(name))
    }

    /// Every user there is, by name.
    pub fn users(&self) -> Result<Vec<UserSnapshot>, Error> {
        let mut users = self
            .env
            .users
            .users()
            .iter()
            .map(|user| Ok(snapshot(user, self.inbounds_of(user.name())?)))
            .collect::<Result<Vec<_>, Error>>()?;
        users.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(users)
    }

    /// The user `name`, if there is one.
    pub fn user(&self, name: &str) -> Result<Option<UserSnapshot>, Error> {
        match self.env.users.get(name) {
            Some(user) => Ok(Some(snapshot(&user, self.inbounds_of(name)?))),
            None => Ok(None),
        }
    }

    /// The traffic of every user, inbound and outbound since the last
    /// read that cleared it, as ssm-api's `?clear=true` reads; `clear`
    /// starts the next read from now. The quotas do not count from it.
    pub fn read_traffic(&self, clear: bool) -> TrafficReport {
        self.stat_manager.read_traffic(clear)
    }

    /// Limits the user `name` by `limits` from now on, over those the
    /// configuration sets, until a reload changes what it sets for the
    /// user.
    pub fn set_user_limits(&self, name: &str, limits: Limits) -> Result<(), Error> {
        let user = self.user_ref(name)?;
        self.env.users.set_limit(&user, limits);
        Ok(())
    }

    /// Limits the user `name` by what the configuration sets again,
    /// undoing `set_user_limits`.
    pub fn restore_user_limits(&self, name: &str) -> Result<(), Error> {
        let user = self.user_ref(name)?;
        self.env.users.restore_limit(&user);
        Ok(())
    }

    /// Resets the quota of the user `name`: what it used so far no longer
    /// counts. Not kept across a restart.
    pub fn reset_quota(&self, name: &str) -> Result<(), Error> {
        self.user_ref(name)?.reset_quota();
        Ok(())
    }

    /// Closes the connections of the user `name`, and what carries them;
    /// how many there were. It may connect again.
    pub fn disconnect_user(&self, name: &str) -> Result<usize, Error> {
        Ok(self.user_ref(name)?.disconnect())
    }

    /// Limits each user named by its limits from now on, over those the
    /// configuration sets, until a reload changes what it sets for the
    /// user: a user not made yet takes them when it is (embed's
    /// `set_user_limits`).
    pub fn set_users_limits(&self, limits: impl IntoIterator<Item = (String, Limits)>) {
        self.env.users.set_limits_named(limits);
    }

    /// Limits the user `name` by what the configuration sets again, made
    /// or not yet.
    pub fn restore_user_limits_named(&self, name: &str) {
        self.env.users.restore_limit_named(name);
    }

    /// Closes the connections of the user `name`, if there is one; how
    /// many there were.
    pub fn disconnect_user_named(&self, name: &str) -> usize {
        self.env.users.get(name).map_or(0, |user| user.disconnect())
    }

    /// Adds `user`, an entry of the inbound's `users` as its protocol has
    /// them, with a name, to the inbound `tag`, as `update_inbound_resources`
    /// would.
    pub async fn add_user(&self, tag: &str, user: serde_json::Value) -> Result<(), Error> {
        self.add_inbound_user(tag, user).await.map_err(plain)
    }

    /// Takes the user `name` out of the inbound `tag`: its entries there go,
    /// and so do its connections through it. False when it had none.
    pub async fn remove_user(&self, tag: &str, name: &str) -> Result<bool, Error> {
        match self.remove_inbound_user(tag, name).await {
            Ok(()) => Ok(true),
            Err(crate::control::InboundError::NoUser(..)) => Ok(false),
            Err(e) => Err(plain(e)),
        }
    }

    /// What happens to users from now on: shut out, or taken out of an
    /// inbound.
    pub fn user_events(&self) -> tokio::sync::broadcast::Receiver<UserEvent> {
        self.env.users.subscribe()
    }
}

/// `e` as the rest of this API tells an error.
fn plain(e: crate::control::InboundError) -> Error {
    match e {
        crate::control::InboundError::Failed(e) => e,
        e => Error::Config(anyhow!("{}", e)),
    }
}
