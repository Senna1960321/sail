use super::*;
use crate::control::events::{End, Outcome, RecordKind};
use crate::session::{Network, SocksAddr};
use std::time::Duration;

fn record(id: u64, up: u64, closed: bool) -> Arc<ConnectionRecord> {
    let at = std::time::UNIX_EPOCH + Duration::from_secs(1000 + id);
    Arc::new(ConnectionRecord {
        id,
        parent_id: None,
        run: std::time::UNIX_EPOCH,
        seq: 0,
        kind: match closed {
            true => RecordKind::Closed(End::Finished),
            false => RecordKind::Interim,
        },
        outcome: closed.then_some(Outcome::Ok),
        reason: None,
        network: Network::Tcp,
        user: Some("a".into()),
        inbound: "in".into(),
        source: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:2".parse().unwrap(),
        destination: SocksAddr::any(),
        request_destination: None,
        domain: None,
        domain_source: None,
        outbound: Some("g".into()),
        chain: vec!["g".into(), "out".into()],
        up_total: up,
        down_total: up * 10,
        start: at,
        at,
    })
}

fn drain(reader: &mut RecordStream) -> Vec<u64> {
    std::iter::from_fn(|| reader.try_next())
        .map(|r| r.id)
        .collect()
}

/// Past the cap every closed record is still kept, in order; interim
/// records of a timed pass are dropped and counted, and those of a pass
/// the host asked for kept.
#[test]
fn closed_records_are_kept_past_the_cap_and_only_interim_ones_dropped() {
    let sink = LosslessRecords::new(2);
    let mut reader = sink.reader().unwrap();
    sink.push(record(1, 1, false), true);
    sink.push(record(2, 2, true), true);
    // Full: a timed interim record goes, a closed one and an asked one stay.
    sink.push(record(3, 4, false), true);
    sink.push(record(4, 8, true), true);
    sink.push(record(5, 16, false), false);
    assert_eq!((reader.queued(), reader.dropped()), (4, 1));
    assert_eq!(drain(&mut reader), [1, 2, 4, 5]);
    // Drained: an interim record is queued again.
    sink.push(record(6, 32, false), true);
    assert_eq!(drain(&mut reader), [6]);
    assert_eq!(reader.dropped(), 1);
}

/// While `cap` closed records wait, new connections are refused and
/// counted; once the reader takes one, they are let in again. Interim
/// records waiting do not refuse anyone.
#[test]
fn closed_records_at_the_cap_refuse_new_connections_until_read() {
    let sink = LosslessRecords::new(2);
    let mut reader = sink.reader().unwrap();
    sink.push(record(1, 1, false), false);
    sink.push(record(2, 1, false), false);
    sink.push(record(3, 1, true), true);
    assert!(!sink.refuse());
    sink.push(record(4, 1, true), true);
    assert!(sink.refuse());
    assert!(sink.refuse());
    assert_eq!(reader.refused(), 2);
    // The interim records go first: still refused.
    assert_eq!(reader.try_next().unwrap().id, 1);
    assert_eq!(reader.try_next().unwrap().id, 2);
    assert!(sink.refuse());
    assert_eq!(reader.try_next().unwrap().id, 3);
    assert!(!sink.refuse());
    assert_eq!(reader.refused(), 3);
}

/// One reader at a time; another once it is dropped.
#[test]
fn one_reader_at_a_time() {
    let sink = LosslessRecords::new(4);
    let reader = sink.reader().unwrap();
    assert!(sink.reader().is_none());
    drop(reader);
    assert!(sink.reader().is_some());
}

/// A reader waiting is woken by a record.
#[tokio::test]
async fn a_waiting_reader_is_woken() {
    let sink = LosslessRecords::new(4);
    let mut reader = sink.reader().unwrap();
    let waiting = tokio::spawn(async move { reader.next().await });
    tokio::task::yield_now().await;
    sink.push(record(1, 1, true), true);
    let got = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.id, 1);
}

#[test]
fn an_envelope_owns_its_binding_until_the_reader_finishes_with_it() {
    use crate::control::context::ContextPool;
    let pool = ContextPool::new(1);
    let context = pool.bind(|| String::from("private binding")).unwrap();
    let sink = LosslessRecords::new(1);
    let mut reader = sink.reader().unwrap();
    let closed = record(1, 4, true);
    sink.push_envelope(
        RecordEnvelope {
            record: closed.clone(),
            context: Some(context),
        },
        false,
    );
    assert!(pool.bind(|| ()).is_none(), "queue owns the binding");
    let envelope = reader.try_next_envelope().unwrap();
    assert!(Arc::ptr_eq(&envelope.record, &closed));
    assert_eq!(
        envelope.context.as_ref().unwrap().get::<String>().unwrap(),
        "private binding"
    );
    assert!(reader.try_next_envelope().is_none());
    assert!(!sink.refuse(), "queue gate reopens when the record is read");
    assert!(
        pool.bind(|| ()).is_none(),
        "reader batch is still in flight"
    );
    let copy = envelope.clone();
    drop(envelope);
    assert!(
        pool.bind(|| ()).is_none(),
        "failed spool handoff may retain an envelope"
    );
    drop(copy);
    assert!(pool.bind(|| ()).is_some(), "last owner releases the slot");
}
