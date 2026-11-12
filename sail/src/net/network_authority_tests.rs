use super::*;

fn physical(name: &str, address: &str) -> NetworkState {
    NetworkState {
        interface: Some(name.into()),
        addresses: vec![address.parse().unwrap()],
        ..Default::default()
    }
}

#[test]
fn a_detected_publication_queued_before_push_cannot_overwrite_it() {
    let network = Network::default();
    network.settle_first(Some(physical("en0", "192.0.2.2/24")));
    let (queried_tx, queried) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let late = network.clone();
    let thread = std::thread::spawn(move || {
        let result = physical("utun91", "10.19.0.1/24");
        // The old detector already passed its !pushed fast check. Invoke
        // its actual publication critical section after the controlled gap.
        queried_tx.send(()).unwrap();
        released.recv().unwrap();
        late.set(result, ChangeReason::State)
    });
    queried.recv().unwrap();
    network.push(physical("en1", "198.51.100.2/24"));
    let generation = network.snapshot_with_generation().generation;
    release.send(()).unwrap();
    assert!(!thread.join().unwrap());
    network.settle_first(Some(physical("utun91", "10.19.0.1/24")));
    assert_eq!(network.snapshot().interface.as_deref(), Some("en1"));
    assert_eq!(
        network.egress_view().host.unwrap().interface.as_deref(),
        Some("en1")
    );
    assert_eq!(network.snapshot_with_generation().generation, generation);
}

#[test]
fn a_late_automatic_notice_neither_resets_nor_consumes_the_host_fold() {
    let network = Network::default();
    network.settle_first(Some(physical("en0", "192.0.2.2/24")));
    let (observed_tx, observed) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let late = network.clone();
    let thread = std::thread::spawn(move || {
        // Models follow_default_interface after refresh returned moved,
        // before its fallback announce. No sleep/order assumption.
        observed_tx.send(()).unwrap();
        released.recv().unwrap();
        late.announce(ChangeReason::DefaultInterface)
    });
    observed.recv().unwrap();
    network.push(physical("en0", "192.0.2.2/24"));
    let generation = network.snapshot_with_generation().generation;
    let mut changes = network.change_events();
    release.send(()).unwrap();
    assert_eq!(thread.join().unwrap(), None);
    assert_eq!(network.announce(ChangeReason::State), None);
    assert!(matches!(
        changes.try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(network.snapshot_with_generation().generation, generation);
    // The automatic notice must retain the token even on a slow runner.
    // Refresh only its timestamp after checking ownership, so this fold
    // assertion does not assume wall-clock scheduling inside two seconds.
    assert!(network.pushed_at.lock().unwrap().is_some());
    *network.pushed_at.lock().unwrap() = Some(std::time::Instant::now());
    assert_eq!(
        network.announce(ChangeReason::HostPush),
        None,
        "automatic notice must not take the fold token"
    );
    assert_eq!(
        network.announce(ChangeReason::HostPush),
        Some(generation + 1),
        "a second explicit reset still executes"
    );
    let reset = changes.try_recv().unwrap();
    assert_eq!(reset.reason, ChangeReason::HostPush);
    assert!(reset.old.differences(&reset.new).is_empty());
    assert!(reset.closes(None, None));
}

#[test]
fn real_host_moves_offline_restore_and_wake_keep_their_generations() {
    let network = Network::default();
    let first = physical("en0", "192.0.2.2/24");
    network.settle_first(Some(first.clone()));
    network.push(first);
    let start = network.snapshot_with_generation().generation;
    let mut changes = network.change_events();
    network.push(physical("en1", "198.51.100.2/24"));
    let moved = changes.try_recv().unwrap();
    assert_eq!(moved.generation, start + 1);
    assert_eq!(moved.reason, ChangeReason::HostPush);
    assert!(moved.closes(
        Some(&Egress::Interface {
            name: "en0".into(),
            index: None
        }),
        None
    ));
    network.push(NetworkState::default());
    let offline = changes.try_recv().unwrap();
    assert_eq!(offline.generation, start + 2);
    assert!(offline.new.interface.is_none());
    network.push(physical("en0", "192.0.2.2/24"));
    assert_eq!(changes.try_recv().unwrap().generation, start + 3);
    network.detected_wake(std::time::Duration::from_secs(130));
    let wake = changes.try_recv().unwrap();
    assert_eq!(wake.generation, start + 4);
    assert_eq!(wake.reason, ChangeReason::Wake);
    assert_eq!(
        network.last_sleep(),
        Some(std::time::Duration::from_secs(130))
    );
}

#[test]
fn without_a_push_detection_and_same_state_automatic_notice_still_work() {
    let network = Network::default();
    network.settle_first(Some(physical("en0", "192.0.2.2/24")));
    assert!(network.detected(physical("en1", "198.51.100.2/24"), ChangeReason::State));
    let generation = network.snapshot_with_generation().generation;
    assert_eq!(
        network.announce(ChangeReason::DefaultInterface),
        Some(generation + 1)
    );
    assert!(!network.pushed());
    assert!(network.egress_view().host.is_none());
}

#[test]
fn overlapping_owned_leases_release_only_their_registration_without_resets() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<OwnedInterfaceLease>();
    let network = Network::default();
    network.push(physical("en0", "192.0.2.2/24"));
    let state = network.snapshot_with_generation();
    let states = network.subscribe();
    let mut events = network.change_events();
    let epoch = network.own.lock().unwrap().epoch;
    let old = network.own_interface("utun91");
    let new = network.own_interface("utun91");
    assert_ne!(old.id, new.id);
    assert_eq!(network.own.lock().unwrap().epoch, epoch + 2);
    drop(old);
    assert!(network.egress_view().own.iter().any(|n| n == "utun91"));
    assert_eq!(network.own.lock().unwrap().epoch, epoch + 3);
    // A retained Network/manager does not retain dynamic registrations.
    let retained = network.clone();
    drop(new);
    assert!(retained.egress_view().own.is_empty());
    assert_eq!(network.own.lock().unwrap().epoch, epoch + 4);
    assert_eq!(
        network.snapshot_with_generation().generation,
        state.generation
    );
    assert!(!states.has_changed().unwrap());
    assert!(matches!(
        events.try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    ));
    assert!(network.changes().borrow().is_none());
}

#[test]
fn replacing_static_names_cannot_clear_a_dynamic_lease() {
    let network = Network::default();
    network.set_own_interfaces(vec!["utun91".into(), "utun92".into()]);
    let published = network.own_interface("utun91");
    network.set_own_interfaces(vec!["utun93".into()]);
    let names = network.egress_view().own;
    assert!(names.iter().any(|n| n == "utun91"));
    assert!(names.iter().any(|n| n == "utun93"));
    assert!(!names.iter().any(|n| n == "utun92"));
    network.set_own_interfaces(vec![]);
    assert_eq!(network.egress_view().own, vec!["utun91"]);
    drop(published);
    assert!(network.egress_view().own.is_empty());
}

#[test]
fn an_old_run_lease_cannot_clear_a_new_runs_same_named_device() {
    let old_run = Network::default();
    let old = old_run.own_interface("utun91");
    let new_run = Network::default();
    let new = new_run.own_interface("utun91");
    drop(old_run);
    drop(old);
    assert_eq!(new_run.egress_view().own, vec!["utun91"]);
    drop(new);
    assert!(new_run.egress_view().own.is_empty());
}
