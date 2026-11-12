use super::*;

// Per-variant expected business semantics, not a diagnostic policy knob.
const EXPECTED_WAITING_AFTER_CANCEL: usize = 0;

#[tokio::test]
async fn diagnostics_do_not_repair_cancelled_waiting_budget() {
    let sessions = Sessions::new(1).unwrap();
    let held = sessions.enter(Duration::ZERO).await.unwrap();
    let unpolled = Box::pin(sessions.enter(Duration::from_secs(1)));
    drop(unpolled);
    assert_eq!(sessions.waiting.load(Ordering::Acquire), 0);
    #[cfg(feature = "internal-diagnostics")]
    assert_eq!(
        sessions.diagnostics_snapshot().wait_cancelled_total,
        Some(0)
    );
    let mut queued = Box::pin(sessions.enter(Duration::from_secs(1)));
    assert!(futures::poll!(queued.as_mut()).is_pending());
    assert_eq!(sessions.waiting.load(Ordering::Acquire), 1);
    drop(queued);
    assert_eq!(
        sessions.waiting.load(Ordering::Acquire),
        EXPECTED_WAITING_AFTER_CANCEL
    );
    #[cfg(feature = "internal-diagnostics")]
    {
        let snapshot = sessions.diagnostics_snapshot();
        assert_eq!(snapshot.live, Some(1));
        assert_eq!(snapshot.waiting, Some(EXPECTED_WAITING_AFTER_CANCEL));
        assert_eq!(snapshot.admitted_total, Some(1));
        assert_eq!(snapshot.refused_total, Some(0));
        assert_eq!(snapshot.wait_cancelled_total, Some(1));
        assert_eq!(snapshot.wait_timeout_total, Some(0));
        assert_eq!(snapshot.active_cancel_total, None);
    }
    drop(held);
}

#[tokio::test]
async fn diagnostics_preserve_cancel_after_a_permit_is_released() {
    let sessions = Sessions::new(1).unwrap();
    let held = sessions.enter(Duration::ZERO).await.unwrap();
    let mut queued = Box::pin(sessions.enter(Duration::from_secs(1)));
    assert!(futures::poll!(queued.as_mut()).is_pending());
    drop(held);
    drop(queued); // Woken, but never polled to a terminal grant.
    assert_eq!(sessions.live(), 0);
    assert_eq!(
        sessions.waiting.load(Ordering::Acquire),
        EXPECTED_WAITING_AFTER_CANCEL
    );
    #[cfg(feature = "internal-diagnostics")]
    {
        let snapshot = sessions.diagnostics_snapshot();
        assert_eq!(snapshot.admitted_total, Some(1));
        assert_eq!(snapshot.wait_cancelled_total, Some(1));
    }
    let next = sessions.enter(Duration::ZERO).await.unwrap();
    drop(next);
    assert_eq!(sessions.live(), 0);
}

#[cfg(feature = "internal-diagnostics")]
#[tokio::test]
async fn diagnostics_keep_refusal_totals_across_warning_window_resets() {
    let sessions = Sessions::new(1).unwrap();
    let _held = sessions.enter(Duration::ZERO).await.unwrap();
    for expected in 1..=3 {
        // A warning may reset the old window; never the new total.
        *sessions.warned.lock().unwrap() = None;
        assert!(sessions.enter(Duration::from_millis(5)).await.is_none());
        let snapshot = sessions.diagnostics_snapshot();
        assert_eq!(snapshot.refused_total, Some(expected));
        assert_eq!(snapshot.wait_timeout_total, Some(expected));
        assert_eq!(snapshot.wait_cancelled_total, Some(0));
        assert_eq!(snapshot.waiting, Some(0));
        assert_eq!(sessions.refused.load(Ordering::Relaxed), 0);
    }
}

#[cfg(feature = "internal-diagnostics")]
#[tokio::test]
async fn diagnostics_distinguish_wait_overflow_and_closed_from_timeout_or_cancel() {
    let sessions = Sessions::new(1).unwrap();
    let held = sessions.enter(Duration::ZERO).await.unwrap();
    let mut queued = Box::pin(sessions.enter(Duration::from_secs(1)));
    assert!(futures::poll!(queued.as_mut()).is_pending());
    assert!(sessions.enter(Duration::ZERO).await.is_none());
    let snapshot = sessions.diagnostics_snapshot();
    assert_eq!(snapshot.refused_total, Some(1));
    assert_eq!(snapshot.wait_timeout_total, Some(0));
    assert_eq!(snapshot.wait_cancelled_total, Some(0));
    drop(queued);
    drop(held);
    let closed = Sessions::new(1).unwrap();
    closed.places.close();
    assert!(closed.enter(Duration::from_secs(1)).await.is_none());
    let snapshot = closed.diagnostics_snapshot();
    assert_eq!(snapshot.refused_total, Some(1));
    assert_eq!(snapshot.wait_timeout_total, Some(0));
    assert_eq!(snapshot.wait_cancelled_total, Some(0));
}
