//! Outbound providers: outbounds given together, downloaded, read from a
//! file or written in place, that groups take as members (a sail
//! extension, `outbound_providers`, with the semantics of Mihomo's
//! proxy-providers).
//!
//! A provider is read before the outbounds are built, so that the groups
//! that take its members can follow them; its members are built once the
//! outbounds are, since they may dial through one (`detour`). Each is
//! built as an outbound of its own, under a tag no configuration takes
//! (`<provider>/<name>`), and is the member its name names.
//!
//! A provider downloaded, or a file read, again brings members anew: those
//! unchanged, and dialling through no other outbound, keep their handler,
//! and with it their connections; the others are retired, and their tasks
//! stop once nothing holds them any more. A download that fails, or that
//! holds no outbound sail can use, leaves the members as they are.
//!
//! A member may be an endpoint (a WireGuard one): its tasks are the
//! provider's, contained, so that one that ends or panics fails that
//! member alone, never the instance. Its running side starts once the
//! instance can run it (`Providers::start_members`), and stops as soon as
//! the member is retired.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use futures::future::AbortHandle;

use crate::adapter::registry::{AnyEndpointServer, MemberRun};
use crate::adapter::AnyOutboundHandler;
use crate::app::dispatcher::Dispatcher;
use crate::app::http::HttpClients;
use crate::app::nat_manager::NatManager;
use crate::app::SyncDnsClient;
use crate::config::model::OutboundProvider;
use crate::net::DialDefaults;
use crate::protocol::group::members::Members;
use crate::runtime::scope::TaskScope;
use crate::runtime::RuntimeEnv;

mod one;

pub(crate) use one::Provider;

/// What starts a member that is an endpoint, with the instance's
/// dispatcher, NAT and task scope, which there are once it starts. Held
/// as a function: the dispatcher reaches the providers, and a type that
/// held it here would be one the compiler cannot prove `Send`. It holds
/// them weakly, as the providers are the instance's: held strongly, the
/// instance would hold itself, and never go.
#[derive(Clone)]
pub(crate) struct StartContext(Arc<StartMember>);

/// Starts a member's running side.
type StartMember = dyn Fn(&AnyEndpointServer) -> Result<MemberRun> + Send + Sync;

impl StartContext {
    pub(crate) fn new(
        dispatcher: &Arc<Dispatcher>,
        nat: &Arc<NatManager>,
        scope: TaskScope,
    ) -> Self {
        let (dispatcher, nat) = (Arc::downgrade(dispatcher), Arc::downgrade(nat));
        StartContext(Arc::new(move |server| {
            let (Some(dispatcher), Some(nat)) = (dispatcher.upgrade(), nat.upgrade()) else {
                anyhow::bail!("the instance has stopped");
            };
            crate::adapter::registry::start_member(server, dispatcher, nat, &scope)
        }))
    }
}

/// The start context, once there is one: the providers', and those of the
/// providers a reload makes.
#[derive(Default)]
pub(crate) struct Starter(Mutex<Option<StartContext>>);

impl Starter {
    fn get(&self) -> Option<StartContext> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// A member that is an endpoint: its running side, which runs from when
/// the instance can run it until the member is retired.
pub(crate) struct EndpointMember {
    tag: String,
    server: AnyEndpointServer,
    run: Mutex<Option<MemberRun>>,
}

impl EndpointMember {
    fn new(tag: String, server: AnyEndpointServer) -> Self {
        EndpointMember {
            tag,
            server,
            run: Mutex::new(None),
        }
    }

    fn running(&self) -> std::sync::MutexGuard<'_, Option<MemberRun>> {
        self.run.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts it, unless it runs. One that does not start fails its dials,
    /// as one that stopped does.
    fn start(&self, start: &StartContext) {
        let mut run = self.running();
        if run.is_some() {
            return;
        }
        match (start.0)(&self.server) {
            Ok(started) => *run = Some(started),
            Err(e) => tracing::warn!("[{}] endpoint: not started: {:#}", self.tag, e),
        }
    }

    /// Stops it: its socket and its stack go at once, and its dials fail.
    fn stop(&self) {
        if let Some(run) = self.running().take() {
            run.stop();
        }
    }
}

/// How often members retired are checked on, to stop their tasks once
/// nothing holds them.
const RETIRED_CHECK: Duration = Duration::from_secs(60);

/// The outbound providers of a configuration.
#[derive(Default)]
pub(crate) struct Providers {
    providers: Vec<Arc<Provider>>,
    retired: Arc<Retired>,
    starter: Arc<Starter>,
}

impl Providers {
    /// Reads the providers of `configs`: a remote one from its cached copy,
    /// if there is one, a local one from its file. Those of `previous`, the
    /// providers a reload replaces, that are configured as they were go
    /// on as they are, members and all, and are not read again.
    pub(crate) fn load(
        configs: &[OutboundProvider],
        clients: &HttpClients,
        dial_defaults: Arc<DialDefaults>,
        env: &RuntimeEnv,
        previous: Option<&Providers>,
    ) -> Result<Self> {
        let retired = Arc::new(Retired::default());
        // The instance runs on: what starts members is the same.
        let starter = previous.map(|p| p.starter.clone()).unwrap_or_default();
        let mut providers = Vec::new();
        for (i, config) in configs.iter().enumerate() {
            let previous = previous
                .and_then(|p| p.providers.iter().find(|p| p.config() == config))
                .map(|p| &**p);
            let provider = Provider::load(
                config,
                clients,
                dial_defaults.clone(),
                env,
                previous,
                retired.clone(),
                starter.clone(),
            )
            .with_context(|| format!("outbound_providers[{}]: [{}]", i, config.tag))?;
            providers.push(Arc::new(provider));
        }
        if let Some(previous) = previous {
            // What is gone is retired, and what was retired stays so.
            for gone in &previous.providers {
                if !providers
                    .iter()
                    .any(|kept| Arc::ptr_eq(&kept.members(), &gone.members()))
                {
                    gone.retire_all(&retired);
                }
            }
            retired.take_over(&previous.retired);
        }
        Ok(Self {
            providers,
            retired,
            starter,
        })
    }

    /// Starts the members that are endpoints, as the instance starts: with
    /// `start`, from here on, each built later starts as it is built.
    pub(crate) fn start_members(&self, start: StartContext) {
        *self.starter.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(start.clone());
        for provider in &self.providers {
            provider.start_endpoints(&start);
        }
    }

    /// Each provider, in the configuration's order.
    pub(crate) fn all(&self) -> &[Arc<Provider>] {
        &self.providers
    }

    /// The members of each provider, by its tag.
    pub(crate) fn members(&self) -> HashMap<String, Arc<Members>> {
        self.providers
            .iter()
            .map(|p| (p.tag.to_string(), p.members()))
            .collect()
    }

    /// Builds the members of every provider onto `handlers`, the outbounds
    /// they may dial through, and publishes them.
    pub(crate) fn build(
        &self,
        handlers: &HashMap<String, AnyOutboundHandler>,
        dns_client: &SyncDnsClient,
        env: &RuntimeEnv,
    ) -> Result<()> {
        for provider in &self.providers {
            provider.build(handlers, dns_client, env)?;
        }
        self.retired.check();
        Ok(())
    }

    /// Downloads the remote providers that have no copy yet. One that
    /// fails is left without members until the next try, as in Mihomo.
    pub(crate) async fn fetch_missing(&self, dispatcher: &Dispatcher) {
        let missing = self.providers.iter().filter(|p| !p.is_loaded());
        let downloads = missing.map(|provider| async move {
            if let Err(e) = provider.update(dispatcher).await {
                tracing::warn!(
                    "outbound provider [{}]: download failed: {:#}",
                    provider.tag,
                    e
                );
            }
        });
        futures::future::join_all(downloads).await;
    }

    /// Downloads the remote providers, and reads the local ones with an
    /// interval, again as each falls due, and stops the tasks of the
    /// members retired once nothing holds them; stopped by aborting the
    /// task.
    pub(crate) fn spawn_updater(
        self: &Arc<Self>,
        dispatcher: Weak<Dispatcher>,
    ) -> Option<tokio::task::AbortHandle> {
        if self.providers.is_empty() && self.retired.is_empty() {
            return None;
        }
        let providers = self.clone();
        let task = crate::runtime::scope::spawn_essential("provider updater", async move {
            let Some(network) = dispatcher.upgrade().map(|d| d.env().network.clone()) else {
                return;
            };
            let mut changes = network.changes();
            loop {
                until_due(&providers.providers, &network, &mut changes, || {
                    providers.retired.check()
                })
                .await;
                let Some(dispatcher) = dispatcher.upgrade() else {
                    return;
                };
                let now = SystemTime::now();
                for provider in providers
                    .providers
                    .iter()
                    .filter(|p| p.due_in(now).is_some_and(|d| d.is_zero()))
                {
                    if let Err(e) = provider.update(&dispatcher).await {
                        tracing::warn!(
                            "outbound provider [{}]: update failed, keeping its outbounds: {:#}",
                            provider.tag,
                            e
                        );
                    }
                }
                providers.retired.check();
            }
        });
        Some(task.abort_handle())
    }
}

/// Waits until one of `providers` falls due, or it is time to let the
/// retired go (`retired`), while the network is up. While it is down,
/// downloads wait rather than fail, and the retired are let go meanwhile;
/// the change that ends it sends those due by then at once.
async fn until_due(
    providers: &[Arc<one::Provider>],
    network: &crate::net::network::Network,
    changes: &mut tokio::sync::watch::Receiver<Option<Arc<crate::net::network::NetworkChange>>>,
    retired: impl Fn(),
) {
    loop {
        changes.borrow_and_update();
        if network.is_down() {
            tracing::debug!("outbound providers: the network is down, updates wait for it");
            if tokio::time::timeout(RETIRED_CHECK, changes.changed())
                .await
                .is_err()
            {
                retired();
            }
            continue;
        }
        let now = SystemTime::now();
        let next = providers
            .iter()
            .filter_map(|p| p.due_in(now))
            .min()
            .unwrap_or(RETIRED_CHECK)
            .min(RETIRED_CHECK);
        // At least a second apart, whatever the clock does.
        tokio::time::sleep(next.max(Duration::from_secs(1))).await;
        if !network.is_down() {
            return;
        }
    }
}

/// The handlers of members replaced or removed, with the tasks they
/// spawned: the tasks stop once nothing else holds the handler, no group
/// and no connection.
#[derive(Default)]
pub(crate) struct Retired {
    members: Mutex<Vec<(AnyOutboundHandler, Vec<AbortHandle>)>>,
}

impl Retired {
    fn members(&self) -> std::sync::MutexGuard<'_, Vec<(AnyOutboundHandler, Vec<AbortHandle>)>> {
        self.members.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn add(&self, handler: AnyOutboundHandler, tasks: Vec<AbortHandle>) {
        if !tasks.is_empty() {
            self.members().push((handler, tasks));
        }
    }

    fn is_empty(&self) -> bool {
        self.members().is_empty()
    }

    /// Adds what `other`, the providers' before a reload, retired.
    fn take_over(&self, other: &Retired) {
        let theirs = other.members().clone();
        self.members().extend(theirs);
    }

    /// Stops the tasks of the members nothing holds any more.
    pub(crate) fn check(&self) {
        self.members().retain(|(handler, tasks)| {
            let held = Arc::strong_count(handler) > 1;
            if !held {
                tasks.iter().for_each(AbortHandle::abort);
            }
            held
        });
    }
}
