use std::sync::Arc;

/// A run's environment with a dynamic TUN, whose host network authority
/// automatic egress follows.
fn dynamic_env() -> crate::runtime::RuntimeEnv {
    let mut env = crate::runtime::RuntimeEnv::default();
    env.host.kinds = env.host.kinds.with_dynamic_tun(true);
    env
}

#[test]
fn automatic_dialers_keep_this_runs_authority_before_after_creation_and_reload() {
    let config = crate::config::Config::from_json(
        r#"{"route":{"auto_detect_interface":true},"outbounds":[{"type":"direct"}]}"#,
    )
    .unwrap();
    for before in [true, false] {
        let env = dynamic_env();
        let physical = || crate::net::network::NetworkState {
            interface: Some("en0".into()),
            ..Default::default()
        };
        if before {
            env.network.push(physical());
        }
        let first = crate::dial_defaults(&config, &env).unwrap();
        let auto = first.env.auto_interface.as_ref().unwrap();
        if !before {
            env.network.push(physical());
        }
        assert_eq!(auto.current().as_deref(), Some("en0"));
        assert_eq!(
            auto.for_target("192.0.2.9".parse().unwrap()).as_deref(),
            Some("en0")
        );
        let reloaded = crate::dial_defaults(&config, &env).unwrap();
        assert!(Arc::ptr_eq(
            auto,
            reloaded.env.auto_interface.as_ref().unwrap()
        ));
        env.network.push(crate::net::network::NetworkState {
            interface: Some("en1".into()),
            ..Default::default()
        });
        assert_eq!(auto.current().as_deref(), Some("en1"));
        let next_run = dynamic_env();
        next_run.network.push(crate::net::network::NetworkState {
            interface: Some("en2".into()),
            ..Default::default()
        });
        let next = crate::dial_defaults(&config, &next_run).unwrap();
        let fresh = next.env.auto_interface.as_ref().unwrap();
        assert!(!Arc::ptr_eq(auto, fresh));
        assert_eq!(fresh.current().as_deref(), Some("en2"));
        assert_eq!(
            auto.current().as_deref(),
            Some("en1"),
            "retained old run cannot read the new authority"
        );
    }
}

/// Without a dynamic TUN, a host's push does not take automatic egress
/// over: the interface is detected as before.
#[test]
fn without_a_dynamic_tun_automatic_egress_is_detected_as_before() {
    let config = crate::config::Config::from_json(
        r#"{"route":{"auto_detect_interface":true},"outbounds":[{"type":"direct"}]}"#,
    )
    .unwrap();
    let env = crate::runtime::RuntimeEnv::default();
    env.network.push(crate::net::network::NetworkState {
        interface: Some("sail-test-if0".into()),
        ..Default::default()
    });
    let defaults = crate::dial_defaults(&config, &env).unwrap();
    let auto = defaults.env.auto_interface.as_ref().unwrap();
    assert_ne!(auto.current().as_deref(), Some("sail-test-if0"));
    assert_ne!(
        auto.for_target("192.0.2.9".parse().unwrap()).as_deref(),
        Some("sail-test-if0")
    );
}
