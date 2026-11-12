use super::*;
use crate::adapter::OutboundDatagram;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
fn fixture() -> SocksAddr {
    SocksAddr::Ip(TEST_ADDR.into())
}

#[test]
fn udp_target_policy_validation_and_debug_never_disclose_input() {
    use std::net::{Ipv4Addr, SocketAddrV4};
    for target in [
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1),
        SocketAddrV4::new(Ipv4Addr::BROADCAST, 1),
        SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 1), 1),
    ] {
        let error = InternalUdpTargetPolicy::new(target).unwrap_err();
        assert_eq!(error.kind(), crate::embed::ErrorKind::InvalidArgument);
        let text = format!("{error:?} {error} {error:#}");
        assert!(!text.contains(&target.to_string()));
        assert!(!text.contains(&target.ip().to_string()));
    }
    let policy = test_policy();
    assert_eq!(format!("{policy:?}"), "InternalUdpTargetPolicy { .. }");
    let kinds = crate::embed::HostKinds::default().with_internal_udp_target_policy(policy);
    assert!(!format!("{kinds:?}").contains(&TEST_ADDR.ip().to_string()));
}

#[test]
fn udp_target_rejects_wrong_epoch_and_flow_events() {
    let sink = Sink::new(98, test_policy());
    let trace = sink.begin(&fixture()).unwrap();
    let mut wrong_epoch = trace.event(NATIVE);
    wrong_epoch.epoch += 1;
    trace.emit(wrong_epoch);
    let mut wrong_flow = trace.event(NATIVE);
    wrong_flow.flow_id += 1;
    trace.emit(wrong_flow);
    let snapshot = sink.snapshot();
    assert!(snapshot.events.is_empty());
    assert_eq!(snapshot.dropped, 2);
}

#[test]
fn udp_target_exact_gate_rejects_nearby_domain_and_mapped_v6() {
    let sink = Sink::new(11, crate::app::udp_target_diagnostics::test_policy());
    assert!(sink.begin(&fixture()).is_some());
    let mut nearby_ip = TEST_ADDR;
    let mut octets = TEST_ADDR.ip().octets();
    octets[3] = octets[3].wrapping_add(1);
    nearby_ip.set_ip(octets.into());
    let mut nearby_port = TEST_ADDR;
    nearby_port.set_port(TEST_ADDR.port() + 1);
    for address in [
        SocksAddr::Ip(nearby_ip.into()),
        SocksAddr::Ip(nearby_port.into()),
        SocksAddr::Ip(std::net::SocketAddr::new(
            TEST_ADDR.ip().to_ipv6_mapped().into(),
            TEST_ADDR.port(),
        )),
        SocksAddr::Domain(TEST_ADDR.ip().to_string(), TEST_ADDR.port()),
        SocksAddr::Domain("secret.example".into(), TEST_ADDR.port()),
    ] {
        assert!(sink.begin(&address).is_none());
    }
    assert_eq!(sink.next.load(Ordering::Relaxed), 2);
    assert!(sink.snapshot().events.is_empty());
}
#[test]
fn udp_target_fixed_ring_overflow_and_contention_drop() {
    assert_eq!(std::mem::size_of::<Slot>(), 512);
    assert_eq!(std::mem::size_of::<[Slot; 16]>(), 8192);
    let sink = Sink::new(12, crate::app::udp_target_diagnostics::test_policy());
    let trace = sink.begin(&fixture()).unwrap();
    {
        let _guard = sink.ring.lock().unwrap();
        trace.emit(trace.event(NATIVE));
        assert!(sink.snapshot().snapshot_contended);
    }
    for _ in 0..19 {
        trace.emit(trace.event(NATIVE));
    }
    let snapshot = sink.snapshot();
    assert_eq!(snapshot.events.len(), 16);
    assert_eq!(snapshot.dropped, 4);
}
#[test]
fn udp_target_owner_epochs_and_context_are_isolated() {
    let old = Sink::new(13, crate::app::udp_target_diagnostics::test_policy());
    let new = Sink::new(14, crate::app::udp_target_diagnostics::test_policy());
    let trace = old.begin(&fixture()).unwrap();
    assert!(old.owns(&trace));
    assert!(!new.owns(&trace));
    trace.emit(trace.event(NATIVE));
    assert_eq!(old.snapshot().events.len(), 1);
    assert!(new.snapshot().events.is_empty());
}
#[test]
fn udp_target_opaque_chain_privacy_and_bound() {
    let sink = Sink::new(15, crate::app::udp_target_diagnostics::test_policy());
    let trace = sink.begin(&fixture()).unwrap();
    let chain = Chain::default();
    for tag in [
        "account-secret",
        "selected-but-secret",
        "password-secret",
        "ignored-secret",
    ] {
        chain.push(tag);
    }
    trace.chain("selected", &chain);
    trace.chain("selected", &chain);
    let snap = sink.snapshot();
    let event = snap.events[0];
    assert_eq!(event.hop_count, 4);
    assert!(event.chain_truncated);
    assert!(event.hops[0].selected);
    assert!(!event.hops[2].selected);
    assert_eq!(event.hops, snap.events[1].hops);
    let encoded = serde_json::to_string(&snap).unwrap();
    for secret in [
        "account-secret",
        "selected-but-secret",
        "password-secret",
        "ignored-secret",
    ] {
        assert!(!encoded.contains(secret));
    }
}
#[test]
fn udp_target_json_export_has_a_separate_bounded_budget() {
    let event = Event {
        epoch: u64::MAX,
        flow_id: u64::MAX,
        parent_flow_id: u64::MAX,
        stage: Stage::Authenticate,
        result: Outcome::Failed,
        queue_status: QueueStatus::ReserveRefused,
        error_kind: ErrorCode::Unclassified,
        bytes: u32::MAX,
        router_generation: u64::MAX,
        source_rule_index: u32::MAX,
        action: Action::HijackDns,
        hops: [Hop {
            selected: false,
            opaque: u64::MAX,
        }; 4],
        hop_count: 4,
        chain_truncated: false,
        chain_available: false,
        address_kind: 3,
        matches_fixture: false,
        entry_hit: false,
        original_is_fixture: false,
        coverage_missing: false,
        carrier_reused: false,
        transport_present: false,
    };
    let event_bytes = serde_json::to_vec(&event).unwrap().len();
    assert!(event_bytes <= 1024);
    let snapshot = Snapshot {
        schema_version: 2,
        fixture: FIXTURE,
        configured: false,
        epoch: u64::MAX,
        dropped: u64::MAX,
        snapshot_contended: false,
        events: vec![event; 16],
    };
    let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap().len();
    assert!(snapshot_bytes <= 16640);
    eprintln!("UDP_MAX_EXPORT event={event_bytes} snapshot={snapshot_bytes}");
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains(&TEST_ADDR.ip().to_string()));
    assert!(!encoded.contains(&TEST_ADDR.to_string()));
    let value = serde_json::to_value(event).unwrap();
    for field in ["stage", "result", "action", "error_kind"] {
        assert!(value[field].is_number());
    }
}
struct Mock {
    fail: bool,
}
impl AsyncRead for Mock {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Mock {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(if self.fail {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "raw-secret-error account=secret.example",
            ))
        } else {
            Ok(buf.len())
        })
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn udp_target_uot_checks_every_packet_and_redacts_errors() {
    let sink = Sink::new(16, crate::app::udp_target_diagnostics::test_policy());
    let trace = sink.begin(&fixture()).unwrap();
    let datagram = crate::transport::uot::OutboundDatagram::new(Mock { fail: false }, &fixture())
        .with_diagnostic_trace(Some(trace.clone()));
    let (_, mut sender) = Box::new(datagram).split();
    sender.send_to(b"secret-payload", &fixture()).await.unwrap();
    let count = sink.snapshot().events.len();
    for address in [
        SocksAddr::Ip(std::net::SocketAddr::new(
            TEST_ADDR.ip().to_owned().into(),
            TEST_ADDR.port() + 1,
        )),
        SocksAddr::Domain("private.example".into(), TEST_ADDR.port()),
    ] {
        sender
            .send_to(b"other-private-payload", &address)
            .await
            .unwrap();
    }
    assert_eq!(sink.snapshot().events.len(), count);
    let datagram = crate::transport::uot::OutboundDatagram::new(Mock { fail: true }, &fixture())
        .with_diagnostic_trace(Some(trace));
    let (_, mut sender) = Box::new(datagram).split();
    assert!(sender
        .send_to(b"private-payload", &fixture())
        .await
        .is_err());
    let snapshot = sink.snapshot();
    assert_eq!(snapshot.events[1].error_kind, ErrorCode::PermissionDenied);
    let encoded = serde_json::to_string(&snapshot).unwrap();
    for secret in [
        "secret-payload",
        "private-payload",
        "raw-secret-error",
        "account=",
        "secret.example",
        "private.example",
    ] {
        assert!(!encoded.contains(secret));
    }
}

#[cfg(feature = "outbound-direct")]
#[tokio::test]
async fn udp_target_getter_restart_returns_only_current_owner() {
    use crate::embed::{Config, Instance, Options, Threads};
    let instance = Instance::new(
        Options::new()
            .threads(Threads::One)
            .internal_udp_target_policy(test_policy()),
    )
    .unwrap();
    assert!(instance.internal_diagnostics().is_err());
    let config = r#"{"outbounds":[{"type":"direct"}]}"#;
    instance.start(Config::Json(config.into())).await.unwrap();
    let old = instance.manager().unwrap().dispatcher().unwrap();
    let old_trace = old.udp_target_trace(&fixture()).unwrap();
    old_trace.emit(old_trace.event(NATIVE));
    let first = instance.internal_diagnostics().unwrap();
    assert_eq!(first.udp_target.events.len(), 1);
    instance.stop().await.unwrap();
    assert!(instance.internal_diagnostics().is_err());
    instance.start(Config::Json(config.into())).await.unwrap();
    old_trace.emit(old_trace.event(NATIVE));
    let next = instance.internal_diagnostics().unwrap();
    assert_ne!(first.epoch, next.epoch);
    assert!(next.udp_target.events.is_empty());
    instance.stop().await.unwrap();
}
