//! Controlled transport boundaries around the production NAT/dispatcher/Held
//! path. These tests do not substitute a model of session ownership.

use super::{
    DatagramRecv, DatagramSend, Datagrams, HostKinds, HostOutbound, HostStream, SessionInfo, Via,
};
use crate::app::nat_manager::UdpPacket;
use crate::embed::Address;
use crate::session::DatagramSource;
use futures::future::BoxFuture;
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Notify};

struct Probe {
    fail: bool,
    release_error: Notify,
    send_calls: AtomicUsize,
    close_calls: AtomicUsize,
    recv_polled: AtomicBool,
    recv_dropped: AtomicBool,
    send_dropped: AtomicBool,
}

impl Probe {
    fn new(fail: bool) -> Arc<Self> {
        Arc::new(Self {
            fail,
            release_error: Notify::new(),
            send_calls: AtomicUsize::new(0),
            close_calls: AtomicUsize::new(0),
            recv_polled: AtomicBool::new(false),
            recv_dropped: AtomicBool::new(false),
            send_dropped: AtomicBool::new(false),
        })
    }

    fn halves_dropped(&self) -> bool {
        self.recv_dropped.load(Ordering::SeqCst) && self.send_dropped.load(Ordering::SeqCst)
    }
}

struct NeverReceive(Arc<Probe>);

impl DatagramRecv for NeverReceive {
    fn recv_from<'a>(
        &'a mut self,
        _buf: &'a mut [u8],
    ) -> BoxFuture<'a, io::Result<(usize, Address)>> {
        Box::pin(async move {
            self.0.recv_polled.store(true, Ordering::SeqCst);
            std::future::pending().await
        })
    }
}

impl Drop for NeverReceive {
    fn drop(&mut self) {
        self.0.recv_dropped.store(true, Ordering::SeqCst);
    }
}

struct ControlledSend(Arc<Probe>);

impl DatagramSend for ControlledSend {
    fn send_to<'a>(
        &'a mut self,
        _data: &'a [u8],
        _address: &'a Address,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.0.send_calls.fetch_add(1, Ordering::SeqCst);
            if self.0.fail {
                self.0.release_error.notified().await;
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "terminal test send",
                ))
            } else {
                Ok(())
            }
        })
    }

    fn close(&mut self) -> BoxFuture<'_, io::Result<()>> {
        Box::pin(async move {
            self.0.close_calls.fetch_add(1, Ordering::SeqCst);
            if self.0.fail {
                // The fix must drop the failed half, never await this.
                std::future::pending().await
            } else {
                Ok(())
            }
        })
    }
}

impl Drop for ControlledSend {
    fn drop(&mut self) {
        self.0.send_dropped.store(true, Ordering::SeqCst);
    }
}

struct ControlledOutbound(Mutex<VecDeque<Arc<Probe>>>);

impl HostOutbound for ControlledOutbound {
    fn stream<'a>(
        &'a self,
        _session: &'a SessionInfo,
        _via: &'a Via,
    ) -> BoxFuture<'a, io::Result<HostStream>> {
        Box::pin(async { Err(io::Error::from(io::ErrorKind::Unsupported)) })
    }

    fn datagrams<'a>(
        &'a self,
        _session: &'a SessionInfo,
        _via: &'a Via,
    ) -> BoxFuture<'a, io::Result<Datagrams>> {
        let probe = self.0.lock().unwrap().pop_front();
        Box::pin(async move {
            let probe = probe.ok_or_else(|| io::Error::other("unexpected new NAT session"))?;
            Ok(Datagrams {
                recv: Box::new(NeverReceive(probe.clone())),
                send: Box::new(ControlledSend(probe)),
            })
        })
    }
}

async fn until(mut done: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !done() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("owner lifecycle did not complete before any sweep/idle deadline");
}

async fn instance(probes: Vec<Arc<Probe>>, limit: usize) -> crate::app::instance::Instance {
    let outbound = Arc::new(ControlledOutbound(Mutex::new(probes.into())));
    let mut env = crate::runtime::RuntimeEnv::default();
    env.options.inbound.max_connections = limit;
    // The first lazy cleanup can run immediately; no later tick can rescue
    // a failed test. Ordinary UDP's idle deadline is also beyond the test.
    env.options.udp.session_check_interval = Duration::from_secs(3_600);
    env.host.kinds = HostKinds::default()
        .with_outbound(
            "test-terminal-udp",
            Arc::new(move |_| Ok(outbound.clone() as Arc<dyn HostOutbound>)),
        )
        .unwrap();
    let config = crate::config::Config::from_json(
        &serde_json::json!({
            "outbounds": [{"type":"test-terminal-udp", "tag":"controlled"}],
            "route": {"final":"controlled"}
        })
        .to_string(),
    )
    .unwrap();
    let env = Arc::new(env);
    env.scope
        .enter(async {
            crate::app::instance::Instance::build(
                &config,
                config.route.rules.clone(),
                env.clone(),
                Arc::default(),
            )
            .unwrap()
        })
        .await
}

fn packet(source: &DatagramSource) -> UdpPacket {
    UdpPacket::new(
        vec![1],
        Address::Ip(source.address),
        Address::Ip("203.0.113.53:80".parse().unwrap()),
    )
}

#[tokio::test]
async fn terminal_udp_send_error_reclaims_nat_and_both_held_halves_without_close() {
    let failed = Probe::new(true);
    let healthy = Probe::new(false);
    let instance = instance(vec![failed.clone(), healthy.clone()], 1).await;
    let root = instance.env.scope.clone();
    let nat = instance.nat_manager.clone();
    root.enter(async {
        let source = DatagramSource::new("192.0.2.1:50000".parse().unwrap(), None);
        let (client, _receive) = mpsc::channel(1);
        nat.send(None, &source, "test", &client, packet(&source))
            .await;
        until(|| {
            failed.send_calls.load(Ordering::SeqCst) == 1
                && failed.recv_polled.load(Ordering::SeqCst)
        })
        .await;
        assert_eq!(instance.dispatcher.test_live_sessions(), 1);
        failed.release_error.notify_one();
        until(|| failed.halves_dropped()).await;
        assert_eq!(instance.dispatcher.test_live_sessions(), 0);
        assert_eq!(failed.close_calls.load(Ordering::SeqCst), 0);
        assert!(
            !nat.end_source("test", &source).await,
            "failed generation remained in NAT"
        );

        // Reuse the same source and the sole permit through the actual
        // dispatcher. A healthy sender must retain its ordinary close path.
        nat.send(None, &source, "test", &client, packet(&source))
            .await;
        until(|| {
            healthy.send_calls.load(Ordering::SeqCst) == 1
                && healthy.recv_polled.load(Ordering::SeqCst)
        })
        .await;
        assert_eq!(instance.dispatcher.test_live_sessions(), 1);
        assert!(nat.end_source("test", &source).await);
        until(|| healthy.halves_dropped()).await;
        assert_eq!(healthy.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(instance.dispatcher.test_live_sessions(), 0);
    })
    .await;
    assert!(root.stop(Duration::from_secs(1)).await.clean());
}

#[tokio::test]
async fn terminal_udp_old_send_error_cannot_remove_replacement_generation() {
    let old = Probe::new(true);
    let replacement = Probe::new(false);
    let instance = instance(vec![old.clone(), replacement.clone()], 2).await;
    let root = instance.env.scope.clone();
    let nat = instance.nat_manager.clone();
    root.enter(async {
        let source = DatagramSource::new("192.0.2.1:50000".parse().unwrap(), None);
        let (client, _receive) = mpsc::channel(1);
        nat.send(None, &source, "test", &client, packet(&source))
            .await;
        until(|| {
            old.send_calls.load(Ordering::SeqCst) == 1 && old.recv_polled.load(Ordering::SeqCst)
        })
        .await;
        assert!(nat.end_source("test", &source).await);
        until(|| old.recv_dropped.load(Ordering::SeqCst)).await;
        assert!(!old.send_dropped.load(Ordering::SeqCst));
        assert_eq!(
            instance.dispatcher.test_live_sessions(),
            1,
            "old sender retains the real Held permit while its send is pending"
        );

        nat.send(None, &source, "test", &client, packet(&source))
            .await;
        until(|| {
            replacement.send_calls.load(Ordering::SeqCst) == 1
                && replacement.recv_polled.load(Ordering::SeqCst)
        })
        .await;
        assert_eq!(instance.dispatcher.test_live_sessions(), 2);
        old.release_error.notify_one();
        until(|| old.halves_dropped()).await;
        assert_eq!(old.close_calls.load(Ordering::SeqCst), 0);
        assert_eq!(instance.dispatcher.test_live_sessions(), 1);
        assert!(!replacement.recv_dropped.load(Ordering::SeqCst));

        // A second packet must reach the existing replacement; a wrong
        // removal would attempt an unexpected third factory allocation.
        nat.send(None, &source, "test", &client, packet(&source))
            .await;
        until(|| replacement.send_calls.load(Ordering::SeqCst) == 2).await;
        assert!(nat.end_source("test", &source).await);
        until(|| replacement.halves_dropped()).await;
        assert_eq!(replacement.close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(instance.dispatcher.test_live_sessions(), 0);
    })
    .await;
    assert!(root.stop(Duration::from_secs(1)).await.clean());
}
