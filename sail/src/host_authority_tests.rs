use std::sync::Arc;

#[test]
fn automatic_dialers_keep_this_runs_authority_before_after_creation_and_reload() {
    let config = crate::config::Config::from_json(
        r#"{"route":{"auto_detect_interface":true},"outbounds":[{"type":"direct"}]}"#,
    )
    .unwrap();
    for before in [true, false] {
        let env = crate::runtime::RuntimeEnv::default();
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
        let next_run = crate::runtime::RuntimeEnv::default();
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
