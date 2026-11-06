//! One outbound provider: where its outbounds come from, the copy kept of
//! a remote one, and its members.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Result};
use futures::future::AbortHandle;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use super::{EndpointMember, Retired, StartContext, Starter};
use crate::adapter::registry::{self, OutboundBuildState};
use crate::adapter::AnyOutboundHandler;
use crate::app::dispatcher::Dispatcher;
use crate::app::http::{self, HttpClients};
use crate::app::http::{file_name, write_atomically};
use crate::app::SyncDnsClient;
use crate::config::clash::subscription::{self, Selection};
use crate::config::model::{Endpoint, Outbound, OutboundProvider, OutboundProviderKind};
use crate::net::DialDefaults;
use crate::protocol::group::members::{Member, MemberKey, Members};
use crate::protocol::group::merge::{mihomo_type, Sources};
use crate::runtime::scope::TaskClass;
use crate::runtime::RuntimeEnv;

/// How often a remote provider is downloaded again by default: Mihomo's
/// and sing-box's rule-sets' day.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after a failed download the next one is tried; a local
/// file's failed read, at most this long.
const RETRY: Duration = Duration::from_secs(5 * 60);

pub(crate) struct Provider {
    pub tag: Arc<str>,
    config: OutboundProvider,
    source: Source,
    /// Which of what it holds it takes, and what it changes in them.
    selection: Selection,
    /// What its members dial with where their dial fields leave off.
    dial_defaults: Arc<DialDefaults>,
    members: Arc<Members>,
    state: Mutex<State>,
    /// One update at a time.
    updating: tokio::sync::Mutex<()>,
    retired: Arc<Retired>,
    starter: Arc<Starter>,
}

enum Source {
    Remote {
        url: String,
        client: http::Client,
        interval: Duration,
        /// Where the downloaded copy is kept; none when there is nowhere
        /// to.
        cache: Option<PathBuf>,
    },
    Local {
        path: String,
        interval: Option<Duration>,
    },
    Inline,
}

/// What is known of what it holds.
#[derive(Clone, Default)]
struct State {
    /// Whether it holds anything yet.
    loaded: bool,
    /// Its outbounds, each by name, as last read.
    proxies: Arc<Vec<(String, Value)>>,
    /// A hash of the file last read, to tell whether it changed.
    read: Option<u64>,
    meta: Meta,
    /// The last update's failure, until one succeeds.
    failed: Option<crate::control::Failure>,
    /// Its members, as built from `proxies`.
    built: Vec<Built>,
}

/// What is kept beside a remote provider's copy.
#[derive(Clone, Default, Serialize, Deserialize)]
struct Meta {
    etag: Option<String>,
    /// When it was downloaded, or last found unchanged; for a local one,
    /// when the file was last read.
    #[serde(default)]
    updated: Option<SystemTime>,
    /// The last `subscription-userinfo` the server gave, which Mihomo
    /// keeps across restarts too.
    #[serde(default)]
    userinfo: Option<String>,
}

/// A member, as built.
#[derive(Clone)]
struct Built {
    name: Arc<str>,
    /// The outbound it was built from, to tell whether it changed.
    outbound: Value,
    handler: AnyOutboundHandler,
    tasks: Vec<AbortHandle>,
    /// Its running side, when it is an endpoint.
    endpoint: Option<Arc<EndpointMember>>,
}

impl Built {
    /// Retires it onto `retired`: an endpoint stops at once, the tasks of
    /// the rest once nothing holds it.
    fn retire(self, retired: &Retired) {
        if let Some(endpoint) = &self.endpoint {
            endpoint.stop();
        }
        retired.add(self.handler, self.tasks);
    }
}

impl Provider {
    /// The provider of `config`, read as `Providers::load` says.
    pub(super) fn load(
        config: &OutboundProvider,
        clients: &HttpClients,
        dial_defaults: Arc<DialDefaults>,
        env: &RuntimeEnv,
        previous: Option<&Provider>,
        retired: Arc<Retired>,
        starter: Arc<Starter>,
    ) -> Result<Self> {
        let source = match config.kind {
            OutboundProviderKind::Remote => {
                let url = env
                    .host
                    .download_url(config.url.as_deref().unwrap_or_default())
                    .map_err(|e| anyhow!("url: {}", e))?;
                let cache = env.host.cache_dir.as_ref().map(|dir| {
                    // The full tag and effective URL identify the source.
                    // Length-prefix the tag to keep the inputs unambiguous;
                    // hashing bounds filenames and hides subscription tokens.
                    let mut source = Sha256::new();
                    source.update((config.tag.len() as u64).to_be_bytes());
                    source.update(config.tag.as_bytes());
                    source.update(url.as_bytes());
                    // Legacy tag-only entries cannot identify their source.
                    // Their sanitized names cannot start with a dot, so none
                    // can collide with this directory or the files within it.
                    dir.join("provider")
                        .join(".by-source")
                        .join(format!("{:x}", source.finalize()))
                });
                Source::Remote {
                    url,
                    client: clients.client(
                        config.http_client.as_ref(),
                        config.download_detour.as_deref(),
                    )?,
                    interval: config.update_interval.unwrap_or(DEFAULT_INTERVAL),
                    cache,
                }
            }
            OutboundProviderKind::Local => Source::Local {
                path: env.data_path(config.path.as_deref().unwrap_or_default()),
                interval: config.update_interval,
            },
            OutboundProviderKind::Inline => Source::Inline,
        };
        let mut warnings = Vec::new();
        let selection = Selection::of(
            &config.filter,
            &config.exclude_filter,
            &config.exclude_type,
            config.detour.as_deref(),
            config.overrides.as_ref(),
            &mut warnings,
        )?;
        let mut provider = Provider {
            tag: config.tag.as_str().into(),
            config: config.clone(),
            source,
            selection,
            dial_defaults,
            members: Members::of(Vec::new()),
            state: Mutex::new(State::default()),
            updating: tokio::sync::Mutex::new(()),
            retired,
            starter,
        };
        for warning in warnings {
            warn!("outbound provider [{}]: {}", provider.tag, warning);
        }
        // Configured as it was, and still from the same effective URL:
        // a host's Sub-Store rewrite may change without changing config.
        if let Some(previous) =
            previous.filter(|previous| match (&previous.source, &provider.source) {
                (Source::Remote { url: before, .. }, Source::Remote { url, .. }) => before == url,
                _ => true,
            })
        {
            provider.members = previous.members.clone();
            *provider.state.get_mut().unwrap_or_else(|e| e.into_inner()) = previous.state().clone();
            return Ok(provider);
        }
        match &provider.source {
            Source::Remote { cache, .. } => {
                // A cached copy that does not read is as good as none.
                if let Some(cache) = cache {
                    if let Ok(body) = std::fs::read(cache) {
                        match provider.read(&body) {
                            Ok(proxies) => {
                                let meta = std::fs::read(meta_path(cache))
                                    .ok()
                                    .and_then(|m| serde_json::from_slice(&m).ok())
                                    .unwrap_or_default();
                                let state =
                                    provider.state.get_mut().unwrap_or_else(|e| e.into_inner());
                                state.proxies = Arc::new(proxies);
                                state.loaded = true;
                                state.meta = meta;
                                debug!(
                                    "outbound provider [{}]: from {}",
                                    provider.tag,
                                    cache.display()
                                );
                            }
                            Err(e) => warn!(
                                "outbound provider [{}]: cached {}: {:#}",
                                provider.tag,
                                cache.display(),
                                e
                            ),
                        }
                    } else if env.host.cache_dir.as_ref().is_some_and(|dir| {
                        dir.join("provider").join(file_name(&config.tag)).is_file()
                    }) {
                        debug!(
                            "outbound provider [{}]: ignored legacy cache without source identity",
                            provider.tag
                        );
                    }
                }
            }
            Source::Local { path, .. } => {
                let body = std::fs::read(path).map_err(|e| anyhow!("path: {}: {}", path, e))?;
                let proxies = provider
                    .read(&body)
                    .map_err(|e| anyhow!("path: {}: {:#}", path, e))?;
                let state = provider.state.get_mut().unwrap_or_else(|e| e.into_inner());
                state.proxies = Arc::new(proxies);
                state.loaded = true;
                state.read = Some(hash(&body));
                state.meta.updated = Some(SystemTime::now());
            }
            Source::Inline => {
                let proxies = config
                    .outbounds
                    .iter()
                    .map(|o| Ok((o.tag.clone(), serde_json::to_value(o)?)))
                    .collect::<Result<Vec<_>>>()?;
                let state = provider.state.get_mut().unwrap_or_else(|e| e.into_inner());
                state.proxies = Arc::new(proxies);
                state.loaded = true;
            }
        }
        Ok(provider)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn config(&self) -> &OutboundProvider {
        &self.config
    }

    pub(crate) fn members(&self) -> Arc<Members> {
        self.members.clone()
    }

    /// What it is now, for the host and the APIs.
    pub(crate) fn info(&self, now: SystemTime) -> crate::control::ProviderInfo {
        let due = self.due_in(now);
        let state = self.state();
        crate::control::ProviderInfo {
            tag: self.tag.to_string(),
            source: match self.source {
                Source::Remote { .. } => crate::control::SourceKind::Remote,
                Source::Local { .. } => crate::control::SourceKind::Local,
                Source::Inline => crate::control::SourceKind::Inline,
            },
            members: self.members.load().members.len(),
            updated: state.meta.updated,
            next_update: due.map(|due| now + due),
            failure: state.failed.clone(),
            subscription: state
                .meta
                .userinfo
                .as_deref()
                .map(crate::control::SubscriptionInfo::parse),
        }
    }

    pub(super) fn is_loaded(&self) -> bool {
        self.state().loaded
    }

    /// The outbounds `body` holds, as Mihomo reads a provider's; its
    /// warnings are logged, naming the provider.
    fn read(&self, body: &[u8]) -> Result<Vec<(String, Value)>> {
        let body = String::from_utf8_lossy(body);
        let read = subscription::read(&body, &self.selection)?;
        for warning in &read.warnings {
            warn!("outbound provider [{}]: {}", self.tag, warning);
        }
        Ok(read.proxies)
    }

    /// How long until it is due for an update, zero when due now; none
    /// when it is never updated.
    pub(super) fn due_in(&self, now: SystemTime) -> Option<Duration> {
        let interval = match &self.source {
            Source::Remote { interval, .. } => *interval,
            Source::Local {
                interval: Some(interval),
                ..
            } => *interval,
            Source::Local { interval: None, .. } | Source::Inline => return None,
        };
        let state = self.state();
        if let Some(failed) = &state.failed {
            // A file read while it was being written is read again at its
            // own interval, as Mihomo does: a read costs nothing, unlike a
            // download.
            let retry = match &self.source {
                Source::Local { .. } => interval.min(RETRY),
                _ => RETRY,
            };
            return Some(retry.saturating_sub(now.duration_since(failed.at).unwrap_or_default()));
        }
        Some(match state.meta.updated {
            None => Duration::ZERO,
            Some(updated) => {
                interval.saturating_sub(now.duration_since(updated).unwrap_or_default())
            }
        })
    }

    /// Downloads it, or reads its file, again, and builds and publishes
    /// the members of what it now holds, if that changed.
    pub(crate) async fn update(&self, dispatcher: &Dispatcher) -> Result<()> {
        let _updating = self.updating.lock().await;
        let result = match &self.source {
            Source::Remote { .. } => self.download(dispatcher).await,
            Source::Local { path, .. } => self.read_again(path),
            Source::Inline => Ok(false),
        };
        self.state().failed = result.as_ref().err().map(crate::control::Failure::now);
        if result? {
            let manager = dispatcher.outbound_manager.load();
            self.build(
                manager.handler_map(),
                &dispatcher.dns_client(),
                dispatcher.env(),
            )?;
            self.retired.check();
            // The groups that take its members, at once rather than when
            // their tasks come to it.
            manager.merge_groups();
            // The document read and dropped: what it took may go back.
            crate::runtime::memory::freed();
        }
        Ok(())
    }

    /// Downloads it; whether what it holds changed.
    async fn download(&self, dispatcher: &Dispatcher) -> Result<bool> {
        let Source::Remote {
            url, client, cache, ..
        } = &self.source
        else {
            unreachable!("a remote provider is downloaded")
        };
        let via = match &client.via {
            Some(via) => via.clone(),
            None => http::Via::Outbound(
                dispatcher
                    .default_outbound()
                    .ok_or_else(|| anyhow!("no outbound to download through"))?,
            ),
        };
        let etag = {
            let state = self.state();
            state.loaded.then(|| state.meta.etag.clone()).flatten()
        };
        let changed = match http::get(
            dispatcher,
            &via,
            &client.headers,
            url,
            etag.as_deref(),
            self.config.size_limit,
        )
        .await?
        {
            http::Response::NotModified => {
                debug!("outbound provider [{}]: unchanged", self.tag);
                self.state().meta.updated = Some(SystemTime::now());
                false
            }
            http::Response::Body {
                data,
                etag,
                userinfo,
            } => {
                let proxies = self.read(&data)?;
                {
                    let mut state = self.state();
                    state.proxies = Arc::new(proxies);
                    state.loaded = true;
                    // A server that says nothing of it this time keeps
                    // what it said before, as in Mihomo.
                    let userinfo = userinfo.or(state.meta.userinfo.take());
                    state.meta = Meta {
                        etag,
                        updated: Some(SystemTime::now()),
                        userinfo,
                    };
                }
                info!(
                    "outbound provider [{}]: downloaded, {} bytes",
                    self.tag,
                    data.len()
                );
                if let Some(cache) = cache {
                    if let Err(e) = write_atomically(cache, &data) {
                        warn!("outbound provider [{}]: not cached: {}", self.tag, e);
                    }
                }
                true
            }
        };
        if let Some(cache) = cache {
            let meta = serde_json::to_vec(&self.state().meta)?;
            if let Err(e) = write_atomically(&meta_path(cache), &meta) {
                warn!("outbound provider [{}]: not cached: {}", self.tag, e);
            }
        }
        Ok(changed)
    }

    /// Reads its file again; whether what it holds changed.
    fn read_again(&self, path: &str) -> Result<bool> {
        let body = std::fs::read(path).map_err(|e| anyhow!("{}: {}", path, e))?;
        let read = hash(&body);
        if self.state().read == Some(read) {
            self.state().meta.updated = Some(SystemTime::now());
            return Ok(false);
        }
        let proxies = self.read(&body).map_err(|e| anyhow!("{}: {:#}", path, e))?;
        let mut state = self.state();
        state.proxies = Arc::new(proxies);
        state.read = Some(read);
        state.meta.updated = Some(SystemTime::now());
        Ok(true)
    }

    /// Builds its members onto `handlers`, the outbounds they may dial
    /// through, and publishes them. A member that is as it was and dials
    /// through no other outbound keeps its handler; one that does not
    /// build is left out, with a warning, but of an inline provider,
    /// whose outbounds are the configuration's, it is an error.
    pub(super) fn build(
        &self,
        handlers: &HashMap<String, AnyOutboundHandler>,
        dns_client: &SyncDnsClient,
        env: &RuntimeEnv,
    ) -> Result<()> {
        let mut state = self.state();
        let proxies = state.proxies.clone();
        let mut before: HashMap<Arc<str>, Built> =
            state.built.drain(..).map(|b| (b.name.clone(), b)).collect();
        let mut handlers = handlers.clone();
        let mut built: Vec<Built> = Vec::with_capacity(proxies.len());
        let mut failed = Vec::new();
        for (name, outbound) in proxies.iter() {
            if built.iter().any(|b| &*b.name == name) {
                failed.push(format!("{:?}: another is so named", name));
                continue;
            }
            if let Some(kept) = before.remove(name.as_str()) {
                if kept.outbound == *outbound && outbound.get("detour").is_none() {
                    built.push(kept);
                    continue;
                }
                kept.retire(&self.retired);
            }
            match self.build_one(name, outbound, &mut handlers, dns_client, env) {
                Ok((handler, tasks, endpoint)) => built.push(Built {
                    name: name.as_str().into(),
                    outbound: outbound.clone(),
                    handler,
                    tasks,
                    endpoint,
                }),
                Err(e) if self.config.kind == OutboundProviderKind::Inline => {
                    return Err(anyhow!("outbound_providers: [{}]: {:#}", self.tag, e));
                }
                Err(e) => failed.push(format!("{:?}: {:#}", name, e)),
            }
        }
        for gone in before.into_values() {
            gone.retire(&self.retired);
        }
        // Once the instance can run them; until then, as it starts.
        if let Some(start) = self.starter.get() {
            for endpoint in built.iter().filter_map(|b| b.endpoint.as_ref()) {
                endpoint.start(&start);
            }
        }
        if !failed.is_empty() {
            warn!(
                "outbound provider [{}]: {} outbounds left out: {}",
                self.tag,
                failed.len(),
                failed.join("; ")
            );
        }
        let members = built
            .iter()
            .map(|b| Member {
                key: MemberKey {
                    source: Some(self.tag.clone()),
                    name: b.name.clone(),
                },
                handler: b.handler.clone(),
                kind: b
                    .outbound
                    .get("type")
                    .and_then(Value::as_str)
                    .map(mihomo_type)
                    .unwrap_or("Unknown"),
            })
            .collect();
        state.built = built;
        drop(state);
        self.members.publish(members);
        Ok(())
    }

    /// Builds the member `name` of `outbound` onto `handlers`, under a tag
    /// of its own, and takes it out again: members do not dial through
    /// each other. Its tasks are contained: one that ends or panics fails
    /// the member alone. An endpoint (a WireGuard one) comes with its
    /// running side, to start.
    #[allow(clippy::type_complexity)]
    fn build_one(
        &self,
        name: &str,
        outbound: &Value,
        handlers: &mut HashMap<String, AnyOutboundHandler>,
        dns_client: &SyncDnsClient,
        env: &RuntimeEnv,
    ) -> Result<(
        AnyOutboundHandler,
        Vec<AbortHandle>,
        Option<Arc<EndpointMember>>,
    )> {
        let tag = format!("{}/{}", self.tag, name);
        let protocol = outbound
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (outbounds, endpoints) = match crate::include::ENDPOINTS.get(protocol) {
            Some(_) => {
                let mut endpoint: Endpoint = serde_json::from_value(outbound.clone())?;
                endpoint.tag = tag.clone();
                (Vec::new(), vec![endpoint])
            }
            None => {
                let mut outbound: Outbound = serde_json::from_value(outbound.clone())?;
                // A plugin's library would be unloaded with what builds it here.
                if crate::config::model::GROUP_PROTOCOLS.contains(&outbound.protocol.as_str())
                    || outbound.protocol == "plugin"
                    || outbound.protocol == "pass"
                {
                    return Err(anyhow!(
                        "a group, a plugin or a pass outbound is not a provider's outbound"
                    ));
                }
                outbound.tag = tag.clone();
                (vec![outbound], Vec::new())
            }
        };
        let mut abort_handles = HashMap::new();
        #[cfg(feature = "outbound-select")]
        let mut selectors = Default::default();
        #[cfg(feature = "plugin")]
        let mut external_handlers = crate::app::outbound::plugin::ExternalHandlers::new();
        let built = registry::build_outbounds_as(
            TaskClass::Contained,
            &crate::include::OUTBOUNDS,
            &crate::include::ENDPOINTS,
            &outbounds,
            &endpoints,
            OutboundBuildState {
                dns_client,
                dial_defaults: &self.dial_defaults,
                env,
                handlers,
                abort_handles: &mut abort_handles,
                dependencies: &mut HashMap::new(),
                endpoints: &mut HashMap::new(),
                #[cfg(feature = "outbound-select")]
                selectors: &mut selectors,
                #[cfg(feature = "plugin")]
                external_handlers: &mut external_handlers,
                providers: &mut Sources::default(),
                #[cfg(any(
                    feature = "outbound-urltest",
                    feature = "outbound-load-balance",
                    feature = "outbound-fallback"
                ))]
                checkers: &mut HashMap::new(),
            },
        )?;
        let handler = handlers
            .remove(&tag)
            .ok_or_else(|| anyhow!("[{}] outbound: not built", tag))?;
        let endpoint = built
            .servers
            .into_iter()
            .find(|(built, _)| *built == tag)
            .map(|(tag, server)| Arc::new(EndpointMember::new(tag, server)));
        Ok((
            handler,
            abort_handles.remove(&tag).unwrap_or_default(),
            endpoint,
        ))
    }

    /// Starts its members that are endpoints, those that do not run.
    pub(super) fn start_endpoints(&self, start: &StartContext) {
        for endpoint in self
            .state()
            .built
            .iter()
            .filter_map(|b| b.endpoint.as_ref())
        {
            endpoint.start(start);
        }
    }

    /// Retires all its members, as it is gone.
    pub(super) fn retire_all(&self, retired: &Retired) {
        for built in self.state().built.iter() {
            built.clone().retire(retired);
        }
    }
}

fn meta_path(cache: &std::path::Path) -> PathBuf {
    let mut path = cache.as_os_str().to_owned();
    path.push(".meta.json");
    path.into()
}

fn hash(body: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    body.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "outbound-direct")]
    fn dns_client() -> SyncDnsClient {
        crate::app::dns::DnsClient::new(
            &Default::default(),
            Arc::new(DialDefaults::default()),
            &Default::default(),
        )
        .unwrap()
        .into_shared()
    }

    fn config(json: serde_json::Value) -> OutboundProvider {
        serde_json::from_value(json).unwrap()
    }

    /// While the network is down, a provider due waits for it rather than
    /// fail, and goes the moment it is back.
    #[tokio::test]
    async fn updates_wait_while_the_network_is_down() {
        use crate::net::network::{Network, NetworkState, NetworkType};
        let env = RuntimeEnv::default();
        let config = config(serde_json::json!({
            "type": "remote", "tag": "p", "url": "https://a.example/p"
        }));
        // Never downloaded: due at once.
        let providers = vec![Arc::new(load(&config, &env, None))];
        assert_eq!(providers[0].due_in(SystemTime::now()), Some(Duration::ZERO));
        let network = Network::default();
        let up = NetworkState {
            interface: Some("en0".into()),
            kind: Some(NetworkType::Wifi),
            ..Default::default()
        };
        network.push(up.clone());
        network.push(NetworkState::default());
        assert!(network.is_down());
        let mut changes = network.changes();
        let wait = super::super::until_due(&providers, &network, &mut changes, || {});
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(1500), &mut wait)
                .await
                .is_err(),
            "due, but the network is down"
        );
        network.push(up);
        tokio::time::timeout(Duration::from_secs(3), wait)
            .await
            .expect("the network is back: it goes");
    }

    fn load(config: &OutboundProvider, env: &RuntimeEnv, previous: Option<&Provider>) -> Provider {
        Provider::load(
            config,
            &HttpClients::default(),
            Arc::new(DialDefaults::default()),
            env,
            previous,
            Default::default(),
            Default::default(),
        )
        .unwrap()
    }

    fn cache_path(provider: &Provider) -> &std::path::Path {
        match &provider.source {
            Source::Remote {
                cache: Some(path), ..
            } => path,
            _ => panic!("remote provider with a cache"),
        }
    }

    fn cache_env(name: &str) -> RuntimeEnv {
        RuntimeEnv {
            host: crate::runtime::Host {
                cache_dir: Some(std::env::temp_dir().join(format!(
                    "sail-provider-{}-{}-{:?}",
                    name,
                    std::process::id(),
                    std::thread::current().id()
                ))),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn write_cache(provider: &Provider, name: &str) {
        let body = format!(
            "proxies:\n  - {{name: {}, type: socks5, server: a.example, port: 1080}}\n",
            name
        );
        write_atomically(cache_path(provider), body.as_bytes()).unwrap();
        let meta = Meta {
            etag: Some(format!("\"{}\"", name)),
            updated: Some(SystemTime::now()),
            userinfo: Some("upload=1; download=2; total=100".into()),
        };
        write_atomically(
            &meta_path(cache_path(provider)),
            &serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn provider_source_caches_are_isolated() {
        let env = cache_env("sources");
        let old_config = config(serde_json::json!({
            "type": "remote", "tag": "s", "url": "https://example.com/old?token=old-secret"
        }));
        let mut new_config = old_config.clone();
        new_config.url = Some("https://example.com/new?token=new-secret".into());
        let old = load(&old_config, &env, None);
        write_cache(&old, "old");
        let old = load(&old_config, &env, None);
        assert!(old.is_loaded());
        let new = load(&new_config, &env, None);
        assert!(!new.is_loaded(), "loaded nodes from the previous source");
        assert!(new.state().meta.etag.is_none());
        assert!(new.state().meta.userinfo.is_none());
        assert!(new.state().meta.updated.is_none());
        assert_eq!(new.due_in(SystemTime::now()), Some(Duration::ZERO));
        assert_ne!(cache_path(&old), cache_path(&new));
        assert!(!cache_path(&new).to_string_lossy().contains("secret"));

        // A replaced source can finish a download late. Neither its body
        // nor its metadata may overwrite the new source's cache.
        write_cache(&new, "new");
        write_cache(&old, "late-old");
        let cached = load(&new_config, &env, None);
        assert_eq!(cached.state().proxies[0].0, "new");
        assert_eq!(cached.state().meta.etag.as_deref(), Some("\"new\""));
        let reused = load(&new_config, &env, Some(&cached));
        assert!(Arc::ptr_eq(&cached.members(), &reused.members()));
        std::fs::remove_dir_all(env.host.cache_dir.unwrap()).unwrap();
    }

    #[test]
    fn provider_legacy_cache_without_source_is_ignored() {
        let env = cache_env("legacy");
        let path = env.host.cache_dir.as_ref().unwrap().join("provider/s");
        write_atomically(
            &path,
            b"proxies:\n  - {name: old, type: socks5, server: a.example, port: 1080}\n",
        )
        .unwrap();
        let meta = Meta {
            etag: Some("\"old\"".into()),
            updated: Some(SystemTime::now()),
            userinfo: Some("upload=1; download=2; total=100".into()),
        };
        write_atomically(&meta_path(&path), &serde_json::to_vec(&meta).unwrap()).unwrap();
        let config = config(serde_json::json!({
            "type": "remote", "tag": "s", "url": "https://example.com/new"
        }));
        let provider = load(&config, &env, None);
        assert!(!provider.is_loaded());
        assert!(provider.state().meta.etag.is_none());
        assert!(provider.state().meta.userinfo.is_none());
        assert_eq!(provider.due_in(SystemTime::now()), Some(Duration::ZERO));
        std::fs::remove_dir_all(env.host.cache_dir.unwrap()).unwrap();
    }

    #[test]
    fn provider_tags_keep_body_metadata_and_temporary_paths_apart() {
        let env = cache_env("tags");
        let mut paths = std::collections::HashSet::new();
        for tag in [
            "a".repeat(200),
            "b".repeat(300),
            "界".repeat(200),
            "a/b".into(),
            "a_b".into(),
            "p".into(),
            "p.meta.json".into(),
            "p.one".into(),
            "p.two".into(),
        ] {
            let config = config(serde_json::json!({
                "type": "remote", "tag": tag, "url": "https://example.com/sub"
            }));
            let provider = load(&config, &env, None);
            let cache = cache_path(&provider);
            for path in [
                cache.to_path_buf(),
                meta_path(cache),
                cache.with_extension("partial"),
                meta_path(cache).with_extension("partial"),
            ] {
                assert!(
                    paths.insert(path),
                    "tag or metadata/temporary path collision"
                );
            }
            write_cache(&provider, "cached");
            let cached = load(&config, &env, None);
            assert!(cached.is_loaded());
            assert_eq!(cached.state().meta.etag.as_deref(), Some("\"cached\""));
        }
        std::fs::remove_dir_all(env.host.cache_dir.unwrap()).unwrap();
    }

    #[cfg(feature = "outbound-direct")]
    fn names(provider: &Provider) -> Vec<String> {
        let snapshot = provider.members().load();
        snapshot
            .members
            .iter()
            .map(|m| m.key.name.to_string())
            .collect()
    }

    #[cfg(feature = "outbound-direct")]
    fn handler(provider: &Provider, name: &str) -> AnyOutboundHandler {
        provider
            .members()
            .load()
            .find(name)
            .unwrap()
            .handler
            .clone()
    }

    /// A local file read half-written, as a rewrite truncates it first,
    /// is read again at the provider's interval, not after `RETRY`.
    #[test]
    fn a_local_file_read_half_written_is_read_again_at_its_interval() {
        let dir = std::env::temp_dir().join(format!(
            "sail-provider-local-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proxies.yaml");
        let full = "proxies:\n  - { name: A, type: socks5, server: a.example, port: 1080 }\n";
        std::fs::write(&path, full).unwrap();
        let config = |interval: &str| {
            config(serde_json::json!({
                "type": "local", "tag": "local", "path": path.to_str().unwrap(),
                "update_interval": interval
            }))
        };
        for (interval, retry) in [("1s", Duration::from_secs(1)), ("1h", RETRY)] {
            let provider = load(&config(interval), &RuntimeEnv::default(), None);
            assert!(provider.is_loaded());
            std::fs::write(&path, "").unwrap();
            let error = provider.read_again(path.to_str().unwrap()).unwrap_err();
            provider.state().failed = Some(crate::control::Failure::now(&error));
            let due = provider.due_in(SystemTime::now()).unwrap();
            assert!(due <= retry && due > retry / 2, "{}: {:?}", interval, due);
            std::fs::write(&path, full).unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_cached_copy_is_read_until_due() {
        let dir = std::env::temp_dir().join(format!(
            "sail-provider-cache-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                cache_dir: Some(dir.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        let config = config(serde_json::json!({
            "type": "remote", "tag": "sub/1", "url": "https://example.com/s",
            "update_interval": "1h", "exclude_filter": "JP"
        }));
        let provider = load(&config, &env, None);
        assert!(!provider.is_loaded());
        assert!(provider.due_in(SystemTime::now()).unwrap().is_zero());

        let cache = cache_path(&provider).to_path_buf();
        write_atomically(
            &cache,
            b"proxies:\n  - { name: HK, type: socks5, server: a.example, port: 1080 }\n  \
              - { name: JP, type: socks5, server: b.example, port: 1080 }\n",
        )
        .unwrap();
        let meta = Meta {
            etag: Some("\"x\"".into()),
            updated: Some(SystemTime::now()),
            userinfo: Some("upload=1; download=2; total=3".into()),
        };
        write_atomically(&meta_path(&cache), &serde_json::to_vec(&meta).unwrap()).unwrap();
        let provider = load(&config, &env, None);
        assert!(provider.is_loaded());
        let due = provider.due_in(SystemTime::now()).unwrap();
        assert!(due > Duration::from_secs(3500), "{:?}", due);
        assert_eq!(provider.state().meta.etag.as_deref(), Some("\"x\""));
        // What the subscription said of itself, kept across restarts.
        let info = provider.info(SystemTime::now());
        assert_eq!(
            info.subscription,
            Some(crate::control::SubscriptionInfo::parse(
                "upload=1; download=2; total=3"
            ))
        );
        assert!(info.next_update.is_some() && info.failure.is_none());
        let proxies = provider.state().proxies.clone();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].0, "HK");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Members as they were keep their handlers; those replaced or gone
    /// are retired, and their tasks stop once nothing holds them.
    #[cfg(all(feature = "outbound-anytls", feature = "outbound-direct"))]
    #[tokio::test]
    async fn members_unchanged_are_kept_and_the_others_retired() {
        let env = RuntimeEnv::default();
        let dns = dns_client();
        let anytls = serde_json::json!({
            "type": "anytls", "tag": "any", "server": "127.0.0.1", "server_port": 1,
            "password": "p", "tls": { "enabled": true, "server_name": "localhost" }
        });
        let config = config(serde_json::json!({
            "type": "inline", "tag": "p",
            "outbounds": [anytls, { "type": "direct", "tag": "d" }]
        }));
        let provider = load(&config, &env, None);
        provider.build(&HashMap::new(), &dns, &env).unwrap();
        assert_eq!(names(&provider), ["any", "d"]);
        let key = provider.members().load().members[0].key.clone();
        assert_eq!(key.source.as_deref(), Some("p"));
        assert_eq!(provider.members().load().members[0].kind, "AnyTLS");
        let any = handler(&provider, "any");
        let direct = handler(&provider, "d");
        assert_eq!(any.tag(), "p/any");
        let tasks = provider.state().built[0].tasks.clone();
        assert!(!tasks.is_empty(), "anytls spawns its cleanup");

        // Built again from the same outbounds: the same handlers.
        provider.build(&HashMap::new(), &dns, &env).unwrap();
        assert!(Arc::ptr_eq(&any, &handler(&provider, "any")));
        assert!(Arc::ptr_eq(&direct, &handler(&provider, "d")));

        // Without it: retired, its tasks going on while it is held.
        let rest = provider.state().proxies[1..].to_vec();
        provider.state().proxies = Arc::new(rest);
        provider.build(&HashMap::new(), &dns, &env).unwrap();
        assert_eq!(names(&provider), ["d"]);
        assert!(Arc::ptr_eq(&direct, &handler(&provider, "d")));
        provider.retired.check();
        assert!(!tasks[0].is_aborted(), "held here still");
        drop(any);
        provider.retired.check();
        assert!(tasks[0].is_aborted());
    }

    /// A reload keeps a provider configured as it was, members and all.
    #[cfg(feature = "outbound-direct")]
    #[test]
    fn a_provider_configured_as_it_was_goes_on() {
        let env = RuntimeEnv::default();
        let dns = dns_client();
        let config = config(serde_json::json!({
            "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "d" }]
        }));
        let first = load(&config, &env, None);
        first.build(&HashMap::new(), &dns, &env).unwrap();
        let next = load(&config, &env, Some(&first));
        assert!(Arc::ptr_eq(&first.members(), &next.members()));
        next.build(&HashMap::new(), &dns, &env).unwrap();
        assert_eq!(names(&next), ["d"]);
        assert!(Arc::ptr_eq(&handler(&first, "d"), &handler(&next, "d")));
    }

    #[cfg(all(feature = "outbound-anytls", feature = "outbound-direct"))]
    #[tokio::test]
    async fn a_provider_with_a_changed_effective_url_retires_old_members() {
        use super::super::Providers;

        let mut env = cache_env("host-source");
        env.host.sub_store = Some(crate::runtime::SubStore("https://old.example".into()));
        let config = config(serde_json::json!({
            "type": "remote", "tag": "p", "url": "https://sub.store/sub"
        }));
        let configs = [config];
        let clients = HttpClients::default();
        let dial = Arc::new(DialDefaults::default());
        let first = Providers::load(&configs, &clients, dial.clone(), &env, None).unwrap();
        {
            let mut state = first.providers[0].state();
            state.loaded = true;
            state.proxies = Arc::new(vec![(
                "any".into(),
                serde_json::json!({
                    "type": "anytls", "tag": "any", "server": "127.0.0.1", "server_port": 1,
                    "password": "p", "tls": { "enabled": true, "server_name": "localhost" }
                }),
            )]);
        }
        first.build(&HashMap::new(), &dns_client(), &env).unwrap();
        let held = handler(&first.providers[0], "any");
        let tasks = first.providers[0].state().built[0].tasks.clone();
        assert!(!tasks.is_empty());
        let same = Providers::load(&configs, &clients, dial.clone(), &env, Some(&first)).unwrap();
        assert!(Arc::ptr_eq(
            &first.providers[0].members(),
            &same.providers[0].members()
        ));
        drop(same);

        // The configuration is unchanged, but the host now sends its
        // Sub-Store requests to a different backend.
        env.host.sub_store = Some(crate::runtime::SubStore("https://new.example".into()));
        let next = Providers::load(&configs, &clients, dial, &env, Some(&first)).unwrap();
        assert!(!next.providers[0].is_loaded());
        assert_ne!(
            cache_path(&first.providers[0]),
            cache_path(&next.providers[0])
        );
        drop(first);
        next.retired.check();
        assert!(
            !tasks[0].is_aborted(),
            "a live connection still holds the old member"
        );
        drop(held);
        next.retired.check();
        assert!(
            tasks[0].is_aborted(),
            "the replaced source's cleanup task was not retired"
        );
    }

    #[cfg(feature = "outbound-direct")]
    #[test]
    fn an_inline_outbound_that_does_not_build_is_an_error() {
        let env = RuntimeEnv::default();
        let config = config(serde_json::json!({
            "type": "inline", "tag": "p",
            "outbounds": [{ "type": "direct", "tag": "d", "no_such_field": 1 }]
        }));
        let err = load(&config, &env, None)
            .build(&HashMap::new(), &dns_client(), &env)
            .unwrap_err();
        assert!(err.to_string().contains("[p]"), "{:#}", err);
    }

    /// A provider of `sub.store` is downloaded from the host's Sub-Store,
    /// and fails without one.
    #[test]
    fn sub_store_is_the_host_s() {
        let config = config(serde_json::json!({
            "type": "remote", "tag": "s", "url": "https://sub.store/download/all?target=Surge"
        }));
        let err = Provider::load(
            &config,
            &HttpClients::default(),
            Arc::new(DialDefaults::default()),
            &RuntimeEnv::default(),
            None,
            Default::default(),
            Default::default(),
        )
        .err()
        .unwrap();
        assert!(format!("{:#}", err).contains("set sub_store"), "{:#}", err);
        let env = RuntimeEnv {
            host: crate::runtime::Host {
                sub_store: Some(crate::runtime::SubStore(
                    "https://sub.example.com/secret".into(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };
        let Source::Remote { url, .. } = load(&config, &env, None).source else {
            unreachable!("a remote provider")
        };
        assert_eq!(
            url,
            "https://sub.example.com/secret/download/all?target=Surge"
        );
    }
}
