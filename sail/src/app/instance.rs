//! An instance: the components a configuration describes, built in
//! dependency order, started in stages, and stopped in reverse.

use crate::app::http::HttpClients;
use crate::app::router::rule_set::RuleSets;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;

use super::dispatcher::Dispatcher;
use super::dns::DnsClient;
use super::inbound::manager::InboundManager;
use super::nat_manager::NatManager;
use super::outbound::manager::OutboundManager;
use super::router::Router;
use super::stat_manager::StatManager;
use super::{SyncDnsClient, SyncOutboundManager, SyncRouter, SyncStatManager};
use crate::config::Config;
use crate::net::{DialDefaults, InstanceDial, SharedDialDefaults};
use crate::runtime::SyncRuntimeEnv;
use crate::Runner;

pub struct Instance {
    pub env: SyncRuntimeEnv,
    pub dns_client: SyncDnsClient,
    pub outbound_manager: SyncOutboundManager,
    pub router: SyncRouter,
    pub stat_manager: SyncStatManager,
    pub dispatcher: Arc<Dispatcher>,
    /// The rule-sets the rules name.
    pub(crate) rule_sets: RuleSets,
    pub inbound_manager: Arc<std::sync::Mutex<InboundManager>>,
    /// Serves the UDP of the inbounds, and of the endpoints once started.
    pub(crate) nat_manager: Arc<NatManager>,
    /// What the instance dials with where the dial fields leave off, which
    /// a reload replaces.
    pub(crate) dial_defaults: SharedDialDefaults,
    /// `ntp`'s service, until the start runs it.
    ntp: Option<crate::app::ntp::NtpService>,
    /// Controls the TUN inbound's stack once it is started.
    #[cfg(feature = "inbound-tun")]
    pub(crate) tun_control: Option<crate::net::netstack::NativeRuntimeControl>,
    /// A TUN inbound's tag and settings, when the instance routes into it
    /// (auto_route, or auto_redirect on Linux); once started, what that
    /// set up.
    #[cfg(all(
        feature = "inbound-tun",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    routed_tun: Option<(String, crate::protocol::tun::inbound::TunSettings)>,
    #[cfg(all(
        feature = "inbound-tun",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    tun_routing: Option<TunRouting>,
}

impl Instance {
    /// Builds what `config` describes, each component after those it uses:
    /// DNS, outbounds and endpoints, routing, statistics, the dispatcher, NAT, inbounds.
    /// Nothing listens, connects or changes on the system yet, so a
    /// configuration that cannot run fails here and leaves no trace.
    ///
    /// Handlers may start background tasks: this runs within a runtime.
    /// The router takes `rules`, `config`'s route rules taken out of it, and
    /// drops each once built.
    pub fn build(
        config: &Config,
        rules: Vec<crate::config::Rule>,
        env: SyncRuntimeEnv,
        dial_defaults: Arc<DialDefaults>,
    ) -> Result<Self> {
        // Closed again if the build fails.
        let cache_file = env
            .cache_file
            .replace(config.experimental.cache_file.as_ref(), &env)?;
        env.clash_mode.configure(
            config.clash_api.as_ref(),
            env.host.clash_modes,
            env.cache_file.get().as_deref(),
        );
        #[cfg(feature = "tls")]
        env.tls_roots.set(crate::transport::tls::roots::configured(
            config.certificate.as_ref(),
            &env,
        )?);
        let http_clients = HttpClients::new(config, dial_defaults.clone());
        let rule_sets = RuleSets::load(&config.route.rule_set, &http_clients, &env, None)?;
        #[cfg(feature = "outbound-provider")]
        let providers = crate::app::provider::Providers::load(
            &config.outbound_providers,
            &http_clients,
            dial_defaults.clone(),
            &env,
            None,
        )?;
        let dns_client =
            DnsClient::with_rule_sets(&config.dns, dial_defaults.clone(), &env, &rule_sets)?;
        dns_client.check_loops(config)?;
        let dns_client = dns_client.into_shared();
        let outbound_manager: SyncOutboundManager =
            Arc::new(ArcSwap::from_pointee(OutboundManager::with_endpoints(
                &config.outbounds,
                &config.endpoints,
                #[cfg(feature = "outbound-provider")]
                providers,
                &dial_defaults,
                &env,
                dns_client.clone(),
            )?));
        // The detours of DNS servers and HTTP clients, built before the
        // outbounds, find them here.
        dial_defaults.env.outbounds.set(&outbound_manager);
        let router: SyncRouter = Arc::new(ArcSwap::from_pointee(Router::with_rule_sets(
            &config.route,
            rules,
            dns_client.clone(),
            &env,
            &rule_sets,
            &dial_defaults,
        )?));
        let stat_manager = Arc::new(
            StatManager::new(env.options.stats.max_recent_connections, env.users.clone())
                .numbered(env.numbering.clone())
                .recording(env.events.clone()),
        );
        // Before the inbounds bind their users.
        if let Some(cache) = env.cache_file.get() {
            match cache.load_traffic() {
                Ok(kept) => stat_manager.restore(kept),
                Err(e) => tracing::warn!("cache_file: traffic not read: {:#}", e),
            }
        }
        env.users
            .set_limits(crate::user::UserRegistry::configured(config));
        let dispatcher = Arc::new(Dispatcher::new(
            outbound_manager.clone(),
            router.clone(),
            dns_client.clone(),
            stat_manager.clone(),
            env.clone(),
        ));
        dns_client
            .load()
            .set_dispatcher(Arc::downgrade(&dispatcher));
        // An endpoint is an inbound too.
        let inbounds: Vec<crate::config::Inbound> = config
            .inbounds
            .iter()
            .cloned()
            .chain(config.endpoints.iter().map(|e| e.as_inbound()))
            .collect();
        for inbound in &inbounds {
            dispatcher.set_inbound_type(&inbound.tag, Some(&inbound.protocol));
        }
        let nat_manager = Arc::new(NatManager::new(dispatcher.clone(), &inbounds));
        // Inbounds outlive a reload, and follow the defaults it brings.
        let shared_dial_defaults: SharedDialDefaults = Arc::new(ArcSwap::new(dial_defaults));
        let ntp = match &config.ntp {
            Some(ntp) => crate::app::ntp::NtpService::new(
                ntp,
                &InstanceDial {
                    defaults: shared_dial_defaults.clone(),
                    dns: dns_client.clone(),
                },
            )?,
            None => None,
        };
        let inbound_manager = Arc::new(std::sync::Mutex::new(InboundManager::new(
            &config.inbounds,
            &env,
            dispatcher.clone(),
            nat_manager.clone(),
            InstanceDial {
                defaults: shared_dial_defaults.clone(),
                dns: dns_client.clone(),
            },
        )?));
        #[cfg(all(
            feature = "inbound-tun",
            any(target_os = "linux", target_os = "macos", target_os = "windows")
        ))]
        let routed_tun = config
            .inbounds
            .iter()
            .find(|i| i.protocol == "tun")
            .map(|i| {
                crate::protocol::tun::inbound::options(i, &env.host)
                    .map(|settings| (i.tag.clone(), settings))
            })
            .transpose()?
            .filter(|(_, settings)| {
                settings.auto_redirect.is_some() || (settings.auto_route && !host_opens_tun(&env))
            });
        cache_file.keep();
        Ok(Instance {
            env,
            dns_client,
            outbound_manager,
            router,
            stat_manager,
            dispatcher,
            rule_sets,
            inbound_manager,
            nat_manager,
            dial_defaults: shared_dial_defaults,
            ntp,
            #[cfg(feature = "inbound-tun")]
            tun_control: None,
            #[cfg(all(
                feature = "inbound-tun",
                any(target_os = "linux", target_os = "macos", target_os = "windows")
            ))]
            routed_tun,
            #[cfg(all(
                feature = "inbound-tun",
                any(target_os = "linux", target_os = "macos", target_os = "windows")
            ))]
            tun_routing: None,
        })
    }

    /// Starts serving: the listeners first, so that a port in use fails the
    /// start before the system is touched; then the TUN device, and the
    /// routes into it. Returns what runs the instance.
    pub fn start(&mut self) -> Result<Vec<Runner>> {
        let mut runners = vec![
            StatManager::store_task(self.stat_manager.clone(), self.env.cache_file.clone()),
            StatManager::report_task(self.stat_manager.clone()),
            self.env.cache_file.kept_task(),
            self.env.users.expiry_task(),
        ];
        runners.extend(self.ntp.take().map(|ntp| ntp.runner()));
        let inbound_manager = self.inbound_manager.clone();
        let mut inbounds = inbound_manager.lock().unwrap_or_else(|e| e.into_inner());
        inbounds.start_network_listeners()?;
        for (tag, server) in self.outbound_manager.load().endpoint_servers() {
            let runner = server
                .start(self.dispatcher.clone(), self.nat_manager.clone())
                .map_err(|e| anyhow::anyhow!("[{}] endpoint: {}", tag, e))?;
            runners.push(runner);
        }
        // A provider's members that are endpoints run contained, in the
        // instance's scope, from here; those built later as they are.
        #[cfg(feature = "outbound-provider")]
        match crate::runtime::scope::TaskScope::current() {
            Some(scope) => self.outbound_manager.load().providers().start_members(
                crate::app::provider::StartContext::new(
                    &self.dispatcher,
                    &self.nat_manager,
                    scope,
                ),
            ),
            None => tracing::warn!(
                "outbound providers: started outside the instance's scope; their endpoints do not run"
            ),
        }

        #[cfg(feature = "inbound-tun")]
        if let Some(tun) = inbounds.get_tun_runner() {
            let tun = tun?;
            runners.push(tun.runner);
            self.tun_control = Some(tun.control);
        }
        #[cfg(feature = "inbound-cat")]
        if let Some(runner) = inbounds.get_cat_runner() {
            runners.push(runner?);
        }
        // After the device, whose routes it adds; what fails is undone.
        #[cfg(all(
            feature = "inbound-tun",
            any(target_os = "linux", target_os = "macos", target_os = "windows")
        ))]
        if let Some((tag, settings)) = &self.routed_tun {
            // The name the device got: a chosen one may have changed at open.
            let mut settings = settings.clone();
            if let Some(name) = self
                .dispatcher
                .env()
                .tun_names
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(tag)
            {
                settings.name = name.name.clone();
            }
            let settings = &settings;
            let started = match &settings.auto_redirect {
                #[cfg(target_os = "linux")]
                Some(options) => crate::protocol::tun::auto_redirect::AutoRedirect::start(
                    tag,
                    settings,
                    options,
                    self.dispatcher.clone(),
                    &self.rule_sets,
                )
                .map(|(routing, runner)| (TunRouting::Redirect(routing), runner)),
                // auto_redirect is Linux only: `options` refuses it elsewhere.
                #[cfg(not(target_os = "linux"))]
                Some(_) => unreachable!("auto_redirect off Linux"),
                None => crate::protocol::tun::auto_route::AutoRoute::start(
                    tag,
                    settings,
                    &self.rule_sets,
                    self.dispatcher.env(),
                )
                .map(|(routing, runner)| (TunRouting::Route(routing), runner)),
            };
            match started {
                Ok((routing, runner)) => {
                    runners.push(runner);
                    self.tun_routing = Some(routing);
                }
                Err(e) => {
                    self.tun_control = None;
                    drop(runners);
                    return Err(e);
                }
            }
        }
        // A test's fault: the start fails once the TUN is routed.
        #[cfg(feature = "fault-injection")]
        if crate::fault::take(|point| matches!(point, crate::fault::Point::StartFails)) {
            self.tun_control = None;
            drop(runners);
            anyhow::bail!("fault injected: the start fails once the TUN is routed");
        }
        Ok(runners)
    }

    /// Lets go of the rule-sets it was built with, once it is started and
    /// their updater spawned: the router, the DNS rules and the updater
    /// hold those in use, and a reload replaces them there. Held here they
    /// would stay, unused, until the instance stops.
    pub(crate) fn let_go_of_rule_sets(&mut self) {
        let _ = std::mem::take(&mut self.rule_sets);
    }

    /// What a reload hands its rule-sets to, when the instance routes
    /// into the TUN.
    #[cfg(all(
        feature = "inbound-tun",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    pub(crate) fn tun_rule_sets(&self) -> Option<TunRuleSets> {
        self.tun_routing.as_ref().map(|routing| match routing {
            #[cfg(target_os = "linux")]
            TunRouting::Redirect(r) => TunRuleSets::Redirect(r.rule_set_feed()),
            TunRouting::Route(r) => TunRuleSets::Route(r.rule_set_feed()),
        })
    }

    /// Undoes what `start` did to the system.
    pub fn stop(&mut self) {
        // What it kept is written, and the file freed for the next start.
        self.stat_manager.store(&self.env.cache_file);
        self.env.cache_file.store_kept();
        self.env.cache_file.close();
        // Before the device goes, as sing-box closes it.
        #[cfg(all(
            feature = "inbound-tun",
            any(target_os = "linux", target_os = "macos", target_os = "windows")
        ))]
        drop(self.tun_routing.take());
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Whether a host that runs the VPN opens the TUN, and routes it.
#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn host_opens_tun(env: &crate::runtime::RuntimeEnv) -> bool {
    env.host
        .platform
        .as_ref()
        .is_some_and(|platform| platform.opens_tun())
}

/// How the instance routes into the TUN (Linux).
#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
enum TunRouting {
    #[cfg(target_os = "linux")]
    Redirect(crate::protocol::tun::auto_redirect::AutoRedirect),
    Route(crate::protocol::tun::auto_route::AutoRoute),
}

/// Where a reload's rule-sets go for the TUN's routing.
#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
#[derive(Clone)]
pub(crate) enum TunRuleSets {
    #[cfg(target_os = "linux")]
    Redirect(crate::protocol::tun::auto_redirect::RuleSetFeed),
    Route(crate::protocol::tun::auto_route::RouteSetFeed),
}

#[cfg(all(
    feature = "inbound-tun",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
impl TunRuleSets {
    /// Whether `rule_sets` has every rule-set the TUN names.
    pub(crate) fn check(&self, rule_sets: &RuleSets) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            TunRuleSets::Redirect(feed) => feed.check(rule_sets),
            TunRuleSets::Route(feed) => feed.check(rule_sets),
        }
    }

    pub(crate) fn publish(&self, rule_sets: RuleSets) {
        match self {
            #[cfg(target_os = "linux")]
            TunRuleSets::Redirect(feed) => feed.publish(rule_sets),
            TunRuleSets::Route(feed) => feed.publish(rule_sets),
        }
    }
}

#[cfg(all(test, feature = "rule-set"))]
mod tests {
    use super::*;

    /// The rule-sets an instance was built with are the router's once it
    /// is started: a router that replaces it, as a reload's does, leaves
    /// nothing holding them.
    #[tokio::test]
    async fn a_started_instance_holds_its_rule_sets_only_where_they_are_used() {
        let config = Config::from_json(
            r#"{ "outbounds": [{ "type": "direct", "tag": "d" }],
                 "route": { "rule_set": [{ "type": "inline", "tag": "s",
                                           "rules": [{ "domain": ["a.example"] }] }],
                            "rules": [{ "rule_set": "s", "outbound": "d" }] } }"#,
        )
        .unwrap();
        let mut instance = Instance::build(
            &config,
            config.route.rules.clone(),
            Arc::default(),
            Arc::default(),
        )
        .unwrap();
        let set = Arc::downgrade(&instance.rule_sets.get("s").unwrap().load());
        instance.let_go_of_rule_sets();
        assert!(set.upgrade().is_some(), "the router matches against it");
        instance.router.store(Arc::new(
            Router::new(
                &Default::default(),
                instance.dns_client.clone(),
                &instance.env,
            )
            .unwrap(),
        ));
        assert!(
            set.upgrade().is_none(),
            "something of the instance holds it"
        );
    }
}
