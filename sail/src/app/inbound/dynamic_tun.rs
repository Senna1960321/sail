//! One opt-in ingress transaction on an existing forwarding core.
use std::sync::{Arc, Mutex};

use crate::embed::tun::{PacketBridge, PreparedTun, TunPacketFlow, TunState};
use crate::embed::{Error, ErrorKind};
use crate::net::netstack::NativeRuntimeControl;
use crate::protocol::tun::inbound::TunRunner;
use crate::runtime::scope::{StopReport, TaskScope};
use crate::runtime::teardown::{LeftKind, Step, Teardown};
use crate::RuntimeManager;

#[derive(Default)]
pub(crate) struct DynamicTun {
    state: Mutex<State>,
    // Stop must be able to close/drain publication without joining a
    // suspended reload that owns RuntimeManager::update.
    drain: tokio::sync::Mutex<()>,
}
#[derive(Default)]
struct State {
    closed: bool,
    next: u64,
    entry: Option<Entry>,
    // Failed publication may finish before its controller's registration.
    // Keep that generation reserved until every actual owner is gone.
    retired: Vec<Generation>,
}
struct Entry {
    id: u64,
    tag: String,
    phase: Phase,
    owner: TaskScope,
    undo: Teardown,
    source: Option<Source>,
    control: Option<NativeRuntimeControl>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Prepared,
    Committing,
    Attached,
    Draining,
}
enum Source {
    Packets(TunRunner),
    #[cfg(unix)]
    Device(Box<crate::config::Inbound>),
}
#[derive(Clone)]
struct Generation {
    id: u64,
    tag: String,
    owner: TaskScope,
    undo: Teardown,
}
impl From<&Entry> for Generation {
    fn from(entry: &Entry) -> Self {
        Self {
            id: entry.id,
            tag: entry.tag.clone(),
            owner: entry.owner.clone(),
            undo: entry.undo.clone(),
        }
    }
}
// The runner/device must drop before its registration, even when a
// blocking task's completed output is waiting in an unjoined JoinHandle.
struct Opened {
    runner: TunRunner,
    _held: crate::runtime::scope::TaskResource,
}
impl DynamicTun {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.retired.retain(|g| !g.owner.is_empty());
        state
    }
}
impl Drop for DynamicTun {
    fn drop(&mut self) {
        let state = self.lock();
        if let Some(entry) = &state.entry {
            entry.owner.abort_all();
        }
        for generation in &state.retired {
            generation.owner.abort_all();
        }
    }
}
impl RuntimeManager {
    pub(crate) fn check_dynamic_inbounds(
        &self,
        inbounds: &[crate::config::Inbound],
    ) -> Result<(), crate::Error> {
        let state = self.dynamic_tun.lock();
        let tag = state
            .entry
            .as_ref()
            .map(|entry| &entry.tag)
            .or_else(|| state.retired.first().map(|generation| &generation.tag));
        let Some(tag) = tag else {
            return Ok(());
        };
        if inbounds.iter().any(|i| i.protocol == "tun") {
            return Err(crate::Error::NeedsRestart(
                "a static TUN requires restart; detach the dynamic TUN first".into(),
            ));
        }
        if inbounds.iter().any(|i| &i.tag == tag) {
            return Err(crate::Error::Config(anyhow::anyhow!(
                "dynamic TUN reserves inbound tag [{}] until detached",
                tag
            )));
        }
        Ok(())
    }

    pub(crate) fn current_tun_control(&self) -> Option<NativeRuntimeControl> {
        self.dynamic_tun
            .lock()
            .entry
            .as_ref()
            .filter(|e| e.phase == Phase::Attached && e.owner.failure().is_none())
            .and_then(|e| e.control.clone())
            .or_else(|| self.tun_control.clone())
    }

    pub(crate) fn dynamic_tun_state(&self) -> TunState {
        let state = self.dynamic_tun.lock();
        let Some(entry) = &state.entry else {
            return state
                .retired
                .first()
                .map_or(TunState::Detached, |g| TunState::Draining {
                    tag: g.tag.clone(),
                });
        };
        let tag = entry.tag.clone();
        match entry.phase {
            Phase::Prepared => TunState::Prepared { tag },
            Phase::Committing => TunState::Committing { tag },
            Phase::Draining => TunState::Draining { tag },
            Phase::Attached => match entry.owner.failure() {
                None => TunState::Attached { tag },
                Some(reason) => TunState::Failed { tag, reason },
            },
        }
    }

    fn check_capture(&self, tag: &str) -> Result<(), Error> {
        if !self.env.host.kinds.dynamic_tun_enabled() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "dynamic TUN is disabled",
            ));
        }
        let inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::state("inbound manager poisoned"))?;
        if inbounds
            .configs()
            .iter()
            .any(|i| i.protocol == "tun" || i.tag == tag)
        {
            return Err(Error::state("static TUN or inbound tag already exists"));
        }
        Ok(())
    }

    fn decode_capture(&self, json: &str) -> Result<crate::config::Inbound, Error> {
        let config = crate::config::from_string(&format!("{{\"inbounds\":[{json}]}}"))
            .map_err(|e| Error::new(ErrorKind::Config, format!("{e:#}")))?;
        if config.inbounds.len() != 1 {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "exactly one TUN inbound required",
            ));
        }
        let inbound = config
            .inbounds
            .into_iter()
            .next()
            .ok_or_else(|| Error::state("missing TUN inbound"))?;
        if inbound.protocol != "tun"
            || inbound.tag.is_empty()
            || inbound.listen.is_some()
            || inbound.listen_port.is_some()
        {
            return Err(Error::new(
                ErrorKind::InvalidArgument,
                "one named TUN inbound without a listen address required",
            ));
        }
        self.check_capture(&inbound.tag)?;
        let state = self.dynamic_tun.lock();
        if state.closed {
            return Err(Error::not_running());
        }
        if state.entry.is_some() || !state.retired.is_empty() {
            return Err(Error::state("TUN slot is already reserved"));
        }
        Ok(inbound)
    }

    fn reserve_capture(
        self: &Arc<Self>,
        tag: String,
        owner: TaskScope,
        source: Source,
    ) -> Result<PreparedTun, Error> {
        let mut state = self.dynamic_tun.lock();
        if state.closed {
            return Err(Error::not_running());
        }
        if state.entry.is_some() || !state.retired.is_empty() {
            return Err(Error::state("TUN slot is already reserved"));
        }
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| Error::state("TUN generation exhausted"))?;
        let id = state.next;
        state.entry = Some(Entry {
            id,
            tag,
            phase: Phase::Prepared,
            owner,
            undo: Teardown::default(),
            source: Some(source),
            control: None,
        });
        Ok(PreparedTun {
            manager: Arc::downgrade(self),
            token: id,
            armed: true,
        })
    }

    pub(crate) async fn prepare_tun_packets(
        self: &Arc<Self>,
        json: &str,
        capacity: usize,
    ) -> Result<(PreparedTun, TunPacketFlow), Error> {
        let _update = self.update.lock().await;
        let inbound = self.decode_capture(json)?;
        let settings = crate::protocol::tun::inbound::options(&inbound, &self.env.host)
            .map_err(|e| Error::new(ErrorKind::Config, format!("{e:#}")))?;
        if settings.auto_route || settings.auto_redirect.is_some() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "dynamic packet TUN leaves routes and DNS to the host",
            ));
        }
        let (io, flow) = PacketBridge::pair(capacity)?;
        let dispatcher = self.dispatcher.upgrade().ok_or_else(Error::not_running)?;
        let owner = self.env.scope.isolated();
        let nat = Arc::new(crate::app::nat_manager::NatManager::new_scoped(
            dispatcher.clone(),
            std::slice::from_ref(&inbound),
            owner.clone(),
        ));
        let tag = inbound.tag.clone();
        let runner = owner
            .enter_sync(|| {
                crate::protocol::tun::inbound::run(
                    inbound,
                    dispatcher,
                    nat,
                    vec![io],
                    usize::from(settings.mtu),
                    &self.env.options.netstack,
                    settings.endpoint_independent_nat,
                )
            })
            .map_err(|e| Error::new(ErrorKind::Failed, format!("{e:#}")))?;
        let prepared = self.reserve_capture(tag, owner, Source::Packets(runner))?;
        Ok((prepared, flow))
    }

    #[cfg(unix)]
    pub(crate) async fn prepare_tun_device(
        self: &Arc<Self>,
        json: &str,
    ) -> Result<PreparedTun, Error> {
        let _update = self.update.lock().await;
        let inbound = self.decode_capture(json)?;
        crate::protocol::tun::inbound::dynamic_options(&inbound, &self.env.host)
            .map_err(|e| Error::new(ErrorKind::Config, format!("{e:#}")))?;
        self.reserve_capture(
            inbound.tag.clone(),
            self.env.scope.isolated(),
            Source::Device(Box::new(inbound)),
        )
    }

    pub(crate) fn prepared_tun_scope(&self, id: u64) -> Result<TaskScope, Error> {
        let state = self.dynamic_tun.lock();
        if state.closed {
            return Err(Error::not_running());
        }
        state
            .entry
            .as_ref()
            .filter(|e| e.id == id && e.phase == Phase::Prepared)
            .map(|e| e.owner.clone())
            .ok_or_else(|| Error::state("stale TUN preparation"))
    }

    pub(crate) fn cancel_prepared_tun(&self, id: u64) {
        let discarded = {
            let mut state = self.dynamic_tun.lock();
            if state
                .entry
                .as_ref()
                .is_some_and(|e| e.id == id && e.phase == Phase::Prepared)
            {
                state.entry.take()
            } else {
                None
            }
        };
        drop(discarded);
    }

    pub(crate) async fn commit_prepared_tun(&self, id: u64) -> Result<(), Error> {
        let (generation, source) = {
            let _update = self.update.lock().await;
            let mut state = self.dynamic_tun.lock();
            if state.closed {
                return Err(Error::not_running());
            }
            let entry = state
                .entry
                .as_mut()
                .filter(|e| e.id == id && e.phase == Phase::Prepared)
                .ok_or_else(|| Error::state("stale TUN preparation"))?;
            self.check_capture(&entry.tag)?;
            entry.phase = Phase::Committing;
            let source = entry
                .source
                .take()
                .ok_or_else(|| Error::state("missing TUN source"))?;
            (Generation::from(&*entry), source)
        };
        let held = generation
            .owner
            .hold_resource("dynamic TUN opening resource");
        let opened = match source {
            Source::Packets(runner) => Ok(Opened {
                runner,
                _held: held,
            }),
            #[cfg(unix)]
            Source::Device(inbound) => {
                let Some(dispatcher) = self.dispatcher.upgrade() else {
                    drop(held);
                    return self
                        .rollback_capture(&generation, Error::not_running())
                        .await;
                };
                let nat = Arc::new(crate::app::nat_manager::NatManager::new_scoped(
                    dispatcher.clone(),
                    std::slice::from_ref(inbound.as_ref()),
                    generation.owner.clone(),
                ));
                let handle = self.handle.clone();
                let owner = generation.owner.clone();
                let undo = generation.undo.clone();
                generation
                    .owner
                    .spawn_blocking("dynamic TUN open", move || {
                        let _runtime = handle.enter();
                        owner
                            .enter_sync(|| {
                                crate::protocol::tun::inbound::new_dynamic(
                                    *inbound, dispatcher, nat, undo,
                                )
                            })
                            .map(|runner| Opened {
                                runner,
                                _held: held,
                            })
                    })
                    .await
                    .map_err(|e| Error::new(ErrorKind::Failed, format!("TUN open task ended: {e}")))
                    .and_then(|r| r.map_err(device_open_error))
            }
        };
        // Drop a late/unjoined result before waiting on update or drain;
        // those operations may be waiting for its owned-resource guard.
        let current = {
            let state = self.dynamic_tun.lock();
            !state.closed
                && state
                    .entry
                    .as_ref()
                    .is_some_and(|e| e.id == id && e.phase == Phase::Committing)
        };
        if !current {
            drop(opened);
            return self
                .rollback_capture(
                    &generation,
                    Error::new(
                        ErrorKind::Cancelled,
                        "TUN commit cancelled by detach or stop",
                    ),
                )
                .await;
        }
        let opened = match opened {
            Ok(opened) => opened,
            Err(error) => return self.rollback_capture(&generation, error).await,
        };
        let update = self.update.lock().await;
        let rejected = {
            let mut state = self.dynamic_tun.lock();
            if state.closed
                || !state
                    .entry
                    .as_ref()
                    .is_some_and(|e| e.id == id && e.phase == Phase::Committing)
            {
                Some(opened)
            } else {
                let Opened { runner, _held } = opened;
                let entry = state.entry.as_mut().expect("current entry checked");
                dispatcher_type(&self.dispatcher, &generation.tag, Some("tun"));
                entry.control = Some(runner.control);
                let observed = generation.owner.clone();
                generation
                    .owner
                    .spawn_essential("dynamic TUN runner", async move {
                        runner.runner.await;
                        observed.fail("dynamic TUN runner ended".into());
                    });
                entry.phase = Phase::Attached;
                drop(_held);
                None
            }
        };
        drop(update);
        if let Some(opened) = rejected {
            drop(opened);
            return self
                .rollback_capture(
                    &generation,
                    Error::new(ErrorKind::Cancelled, "stale TUN open result"),
                )
                .await;
        }
        Ok(())
    }

    async fn rollback_capture(&self, generation: &Generation, error: Error) -> Result<(), Error> {
        let left = {
            let _drain = self.dynamic_tun.drain.lock().await;
            generation.undo.run_all();
            generation.undo.check_all();
            generation.undo.left()
        };
        let _update = self.update.lock().await;
        let mut state = self.dynamic_tun.lock();
        if state.entry.as_ref().is_some_and(|e| e.id == generation.id) {
            if left.is_empty() {
                state.entry = None;
                state.retired.push(generation.clone());
            } else if let Some(entry) = state.entry.as_mut() {
                entry.phase = Phase::Draining;
            }
        }
        Err(error.with_left(left))
    }

    pub(crate) async fn detach_dynamic_tun(&self) -> Result<StopReport, Error> {
        let _update = self.update.lock().await;
        let _drain = self.dynamic_tun.drain.lock().await;
        self.drain_capture().await
    }

    async fn drain_capture(&self) -> Result<StopReport, Error> {
        let within = self
            .env
            .host
            .stop_within
            .unwrap_or(crate::runtime::scope::STOP_WITHIN);
        let retired = self.dynamic_tun.lock().retired.clone();
        if !retired.is_empty() {
            let mut combined = StopReport::default();
            for generation in retired {
                let report = generation.owner.stop(within).await;
                combined.tasks.extend(report.tasks);
                combined.left.extend(report.left);
                combined.waited += report.waited;
            }
            return Ok(combined);
        }
        let (generation, source) = {
            let mut state = self.dynamic_tun.lock();
            let Some(entry) = state.entry.as_mut() else {
                return Ok(StopReport::default());
            };
            entry.phase = Phase::Draining;
            entry.control = None;
            (Generation::from(&*entry), entry.source.take())
        };
        drop(source);
        generation.undo.run_all();
        let mut report = generation.owner.stop(within).await;
        if report.tasks.is_empty() {
            generation.undo.check_all();
        }
        report.left = generation.undo.left();
        if report.clean() {
            let mut state = self.dynamic_tun.lock();
            if state.entry.as_ref().is_some_and(|e| e.id == generation.id) {
                state.entry = None;
                dispatcher_type(&self.dispatcher, &generation.tag, None);
            }
        }
        Ok(report)
    }

    pub(crate) async fn stop_dynamic_tun(&self) {
        self.dynamic_tun.lock().closed = true;
        let _drain = self.dynamic_tun.drain.lock().await;
        match self.drain_capture().await {
            Ok(report) if !report.clean() => {
                for left in report.left {
                    let mut check = Step::new(left.kind, left.resource, move || {
                        Err(std::io::Error::other(left.why))
                    });
                    if let Some(clear) = left.clear {
                        check = check.clear(clear);
                    }
                    self.env.teardown.push_check(check);
                }
                for (name, count) in report.tasks {
                    self.env.teardown.push_check(Step::new(
                        LeftKind::Task,
                        format!("{count} dynamic TUN tasks: {name}"),
                        || {
                            Err(std::io::Error::other(
                                "attachment did not drain before instance stop",
                            ))
                        },
                    ));
                }
            }
            Err(error) => tracing::warn!("stopping dynamic TUN: {error}"),
            _ => {}
        }
    }
}

fn dispatcher_type(
    dispatcher: &std::sync::Weak<crate::app::dispatcher::Dispatcher>,
    tag: &str,
    kind: Option<&str>,
) {
    if let Some(dispatcher) = dispatcher.upgrade() {
        dispatcher.set_inbound_type(tag, kind);
    }
}

#[cfg(unix)]
fn device_open_error(error: anyhow::Error) -> Error {
    use crate::protocol::tun::device_identity::DeviceIdentityError;
    let kind = match error
        .downcast_ref::<DeviceIdentityError>()
        .map(DeviceIdentityError::kind)
    {
        Some(std::io::ErrorKind::Unsupported) => ErrorKind::Unsupported,
        Some(std::io::ErrorKind::InvalidInput) => ErrorKind::InvalidArgument,
        _ => ErrorKind::Failed,
    };
    Error::new(kind, format!("{error:#}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[test]
    fn device_identity_errors_keep_their_public_error_category() {
        use crate::protocol::tun::device_identity::DeviceIdentityError;
        let mismatch = DeviceIdentityError::Mismatch {
            expected: "tunA".into(),
            actual: "tunB".into(),
        };
        assert_eq!(
            device_open_error(mismatch.into()).kind(),
            ErrorKind::InvalidArgument
        );
        let unsupported = DeviceIdentityError::Query(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "controlled unsupported platform",
        ));
        assert_eq!(
            device_open_error(unsupported.into()).kind(),
            ErrorKind::Unsupported
        );
        let query = DeviceIdentityError::Query(std::io::Error::other("controlled query failure"));
        assert_eq!(device_open_error(query.into()).kind(), ErrorKind::Failed);
    }

    #[cfg(feature = "outbound-direct")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_commit_keeps_the_same_run_reserved_until_its_resources_end() {
        use crate::embed::{Config, Instance, Options, Platform, Runtime};
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Refuse(AtomicUsize);
        impl Platform for Refuse {
            fn log(&self, _: &str) {}
            fn opens_tun(&self) -> bool {
                true
            }
            fn open_tun(&self, _: &crate::embed::TunRequest) -> std::io::Result<i32> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::other("controlled open refusal"))
            }
        }
        let host = Arc::new(Refuse(AtomicUsize::new(0)));
        let i = Instance::new(
            Options::new()
                .dynamic_tun(true)
                .platform(host.clone())
                .runtime(Runtime::Host(tokio::runtime::Handle::current()))
                .stop_within(std::time::Duration::from_millis(20)),
        )
        .unwrap();
        i.start(Config::Json(
            r#"{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"#.into(),
        ))
        .await
        .unwrap();
        let manager = i.manager().unwrap();
        let config = r#"{"type":"tun","tag":"capture","address":["10.19.0.1/24"]}"#;
        let prepared = i.prepare_tun_device(config).await.unwrap();
        assert_eq!(
            host.0.load(Ordering::SeqCst),
            0,
            "prepare cannot open or duplicate"
        );
        let owner = manager
            .dynamic_tun
            .lock()
            .entry
            .as_ref()
            .unwrap()
            .owner
            .clone();
        let held = owner.hold_resource("test prior capture resource");
        assert!(prepared.commit().await.is_err());
        assert_eq!(host.0.load(Ordering::SeqCst), 1);
        let draining = matches!(i.tun_state().unwrap(), TunState::Draining { .. });
        let refused = i.prepare_tun_device(config).await.is_err();
        let incoming = crate::config::from_string(&format!("{{\"inbounds\":[{config}]}}")).unwrap();
        let static_refused = manager.check_dynamic_inbounds(&incoming.inbounds).is_err();
        let report = i.detach_tun().await.unwrap();
        // Release before assertions, including when used as a negative control.
        drop(held);
        assert!(i.detach_tun().await.unwrap().clean());
        assert!(
            draining,
            "a failed commit must retain a live old resource barrier"
        );
        assert!(
            refused,
            "new preparation cannot reuse an unsettled host slot"
        );
        assert!(!report.clean());
        assert!(
            static_refused,
            "failed capture cleanup also reserves static TUN and tag conflicts"
        );
        assert!(report
            .tasks
            .iter()
            .any(|(name, _)| *name == "test prior capture resource"));
        let next = i.prepare_tun_device(config).await.unwrap();
        assert_eq!(
            host.0.load(Ordering::SeqCst),
            1,
            "the next reservation still has no OS effect"
        );
        drop(next);
        assert!(Arc::ptr_eq(&manager, &i.manager().unwrap()));
        i.stop().await.unwrap();
    }

    #[tokio::test]
    async fn a_completed_unjoined_open_keeps_its_transferred_fd_and_resource_barrier() {
        let scope = TaskScope::default();
        let (original, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        // A distinct owned transfer, with the host's original retained.
        let fd = unsafe { libc::fcntl(original.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10000) };
        assert!(fd >= 10000);
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let (bridge, _flow) = PacketBridge::pair(1).unwrap();
        let (runtime, _accepted, _datagrams, _reply, control) =
            crate::net::netstack::NativeRuntimeGroup::new(
                vec![bridge],
                sail_netstack::ResourceLedger::new(sail_netstack::BudgetProfile::Mobile.budget())
                    .unwrap(),
                sail_netstack::RunnerConfig::default(),
                8,
                8,
                8,
            )
            .unwrap();
        let runner = TunRunner {
            verified_name: None,
            runner: Box::pin(async move {
                let _owned = (runtime, owned);
                std::future::pending::<()>().await;
            }),
            control,
        };
        let held = scope.hold_resource("dynamic TUN opening resource");
        let result = scope.spawn_blocking("dynamic TUN open", move || Opened {
            runner,
            _held: held,
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !result.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let report = scope.stop(std::time::Duration::from_millis(20)).await;
        assert_eq!(report.tasks, [("dynamic TUN opening resource", 1)]);
        assert!(
            !report.clean(),
            "completed but unjoined output still owns the descriptor"
        );
        assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
        drop(result); // Opened drops its runner/FD before its resource registration.
        assert!(scope.is_empty());
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        assert!(unsafe { libc::fcntl(original.as_raw_fd(), libc::F_GETFD) } >= 0);
    }
}
