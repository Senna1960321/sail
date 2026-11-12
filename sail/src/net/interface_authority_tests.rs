use super::*;
use crate::net::network::{Network, NetworkInterface, NetworkState, NetworkType};

fn initial() -> io::Result<String> {
    Ok("en0".into())
}
fn host(name: &str) -> NetworkState {
    NetworkState {
        interface: Some(name.into()),
        addresses: vec!["192.0.0.2/16".parse().unwrap()],
        ..Default::default()
    }
}
fn row(name: &str, addresses: &[&str]) -> NetworkInterface {
    NetworkInterface {
        name: name.into(),
        index: None,
        kind: NetworkType::Other,
        addresses: addresses.iter().map(|s| s.parse().unwrap()).collect(),
        expensive: false,
        constrained: false,
    }
}
fn capture_cache(auto: &AutoInterface) {
    auto.state.store(Arc::new(State {
        default: Some("utun91".into()),
        subnets: vec![("192.0.2.9".parse().unwrap(), 32, "utun91".into())],
    }));
}

#[test]
fn a_host_push_before_or_after_construction_excludes_unknown_os_capture_routes() {
    for before in [true, false] {
        let network = Network::default();
        if before {
            network.push(host("en0"));
        }
        let auto = AutoInterface::with_network(vec![], initial, network.clone());
        capture_cache(&auto);
        if !before {
            network.push(host("en0"));
        }
        assert_eq!(auto.current().as_deref(), Some("en0"));
        for target in [
            "192.0.2.9",
            "::ffff:192.0.2.9",
            "203.0.113.1",
            "2001:db8::1",
        ] {
            assert_eq!(
                auto.for_target(target.parse().unwrap()).as_deref(),
                Some("en0")
            );
        }
        assert!(!auto.refresh_from(|| panic!("host authority must avoid the OS query")));
        network.push(host("en1"));
        assert_eq!(auto.current().as_deref(), Some("en1"));
        network.push(NetworkState::default());
        assert_eq!(auto.current(), None);
        assert_eq!(
            auto.for_target("192.0.2.9".parse().unwrap()),
            None,
            "offline cannot fall back to cached capture"
        );
    }
}

#[test]
fn host_listed_subnets_win_by_prefix_but_known_own_names_are_excluded_exactly() {
    let network = Network::default();
    let auto = AutoInterface::with_network(vec![], initial, network.clone());
    let mut state = host("en0");
    state.interfaces = vec![
        row("en0", &["192.0.0.2/16"]),
        row("en1", &["192.0.2.2/24", "2001:db8:1::2/64"]),
        row("utun91", &["192.0.2.9/32"]),
        row("utun92", &["198.51.100.2/24"]),
    ];
    network.set_own_interfaces(vec!["utun91".into()]);
    network.push(state.normalized().unwrap());
    capture_cache(&auto);
    for target in ["192.0.2.9", "::ffff:192.0.2.9", "2001:db8:1::9"] {
        assert_eq!(
            auto.for_target(target.parse().unwrap()).as_deref(),
            Some("en1")
        );
    }
    assert_eq!(
        auto.for_target("192.0.3.9".parse().unwrap()).as_deref(),
        Some("en0")
    );
    assert_eq!(
        auto.for_target("198.51.100.9".parse().unwrap()).as_deref(),
        Some("utun92"),
        "an explicit other VPN is not excluded by prefix"
    );
    assert!(!network
        .snapshot()
        .interfaces
        .iter()
        .any(|r| r.name == "utun91"));
    // Egress keeps exact raw declarations independently of the rule snapshot.
    network.set_own_interfaces(vec![]);
    assert_eq!(
        auto.for_target("192.0.2.9".parse().unwrap()).as_deref(),
        Some("utun91")
    );
    network.set_own_interfaces(vec!["utun91".into()]);
    network.push(host("utun91"));
    assert_eq!(auto.current(), None);
    assert_eq!(auto.for_target("192.0.2.9".parse().unwrap()), None);
    assert_eq!(auto.for_target("203.0.113.9".parse().unwrap()), None);
}

#[test]
fn a_late_os_lookup_cannot_publish_after_host_authority_begins() {
    let network = Network::default();
    let auto = AutoInterface::with_network(vec![], initial, network.clone());
    auto.refresh_from(|| (Ok("en0".into()), vec![]));
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let querying = auto.clone();
    let task = std::thread::spawn(move || {
        querying.refresh_from(|| {
            entered_tx.send(()).unwrap();
            released.recv().unwrap();
            (
                Ok("utun91".into()),
                vec![("192.0.2.9".parse().unwrap(), 32, "utun91".into())],
            )
        })
    });
    entered.recv().unwrap();
    network.push(host("en1"));
    release.send(()).unwrap();
    assert!(!task.join().unwrap());
    assert_eq!(
        auto.state.load().default.as_deref(),
        Some("en0"),
        "late cache result must be discarded too"
    );
    assert_eq!(auto.current().as_deref(), Some("en1"));
}

#[test]
fn a_late_lookup_rechecks_new_owned_names_without_a_host_push() {
    let network = Network::default();
    let auto = AutoInterface::with_network(vec![], initial, network.clone());
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let querying = auto.clone();
    let task = std::thread::spawn(move || {
        querying.refresh_from(|| {
            entered_tx.send(()).unwrap();
            released.recv().unwrap();
            (
                Ok("utun91".into()),
                vec![("192.0.2.9".parse().unwrap(), 32, "utun91".into())],
            )
        })
    });
    entered.recv().unwrap();
    network.set_own_interfaces(vec!["utun91".into()]);
    release.send(()).unwrap();
    task.join().unwrap();
    assert_eq!(auto.current(), None);
    assert_eq!(auto.for_target("192.0.2.9".parse().unwrap()), None);
}

#[test]
fn no_push_keeps_os_default_and_direct_subnet_selection() {
    let network = Network::default();
    let auto = AutoInterface::with_network(vec![], initial, network.clone());
    assert!(auto.refresh_from(|| (
        Ok("en1".into()),
        vec![("192.0.2.0".parse().unwrap(), 24, "en2".into())]
    )));
    assert_eq!(auto.current().as_deref(), Some("en1"));
    assert_eq!(
        auto.for_target("192.0.2.9".parse().unwrap()).as_deref(),
        Some("en2")
    );
    assert_eq!(
        auto.for_target("203.0.113.9".parse().unwrap()).as_deref(),
        Some("en1")
    );
    network.set_own_interfaces(vec!["en2".into()]);
    assert_eq!(
        auto.for_target("192.0.2.9".parse().unwrap()).as_deref(),
        Some("en1"),
        "live exclusion applies before the next refresh"
    );
    assert!(!network.pushed());
}

#[test]
fn dynamic_owned_leases_mask_host_default_and_subnets_before_after_creation() {
    for before in [true, false] {
        let network = Network::default();
        let old = before.then(|| network.own_interface("utun91"));
        let mut state = host("utun91");
        state.interfaces = vec![
            row("utun91", &["192.0.2.9/32"]),
            row("utun92", &["198.51.100.2/24"]),
        ];
        network.push(state);
        let auto = AutoInterface::with_network(vec![], initial, network.clone());
        let old = old.unwrap_or_else(|| network.own_interface("utun91"));
        let new = network.own_interface("utun91");
        assert_eq!(auto.current(), None);
        assert_eq!(auto.for_target("192.0.2.9".parse().unwrap()), None);
        assert_eq!(
            auto.for_target("198.51.100.9".parse().unwrap()).as_deref(),
            Some("utun92"),
            "a different explicit VPN stays eligible"
        );
        drop(old);
        assert_eq!(auto.current(), None);
        assert_eq!(auto.for_target("192.0.2.9".parse().unwrap()), None);
        drop(new);
        assert_eq!(auto.current().as_deref(), Some("utun91"));
        assert_eq!(
            auto.for_target("192.0.2.9".parse().unwrap()).as_deref(),
            Some("utun91"),
            "raw host declaration survives the mask without another push"
        );
    }
}

#[test]
fn dynamic_owned_leases_filter_existing_os_cache_without_refresh() {
    let network = Network::default();
    let auto = AutoInterface::with_network(vec![], initial, network.clone());
    capture_cache(&auto);
    let lease = network.own_interface("utun91");
    assert_eq!(auto.current(), None);
    assert_eq!(auto.for_target("192.0.2.9".parse().unwrap()), None);
    auto.refresh_from(|| {
        (
            Ok("utun91".into()),
            vec![("192.0.2.9".parse().unwrap(), 32, "utun91".into())],
        )
    });
    assert_eq!(auto.current(), None);
    assert_eq!(auto.for_target("192.0.2.9".parse().unwrap()), None);
    drop(lease);
    assert_eq!(auto.current().as_deref(), Some("utun91"));
    assert_eq!(
        auto.for_target("192.0.2.9".parse().unwrap()).as_deref(),
        Some("utun91")
    );
}
