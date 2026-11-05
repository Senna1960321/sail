use super::*;
use crate::adapter::{OutboundDatagram, OutboundDatagramRecvHalf, OutboundDatagramSendHalf};
use crate::session::SocksAddr;
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

struct MockStream {
    data: Vec<u8>,
    read_pos: usize,
}

impl AsyncRead for MockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let rem = self.data.len() - self.read_pos;
        if rem == 0 {
            return Poll::Ready(Ok(()));
        }
        let to_read = std::cmp::min(rem, buf.remaining());
        buf.put_slice(&self.data[self.read_pos..self.read_pos + to_read]);
        self.read_pos += to_read;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn mock(data: &[u8]) -> AnyStream {
    Box::new(MockStream {
        data: data.to_vec(),
        read_pos: 0,
    })
}

struct MockRecv(usize);

#[async_trait]
impl OutboundDatagramRecvHalf for MockRecv {
    async fn recv_from(&mut self, _buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        match std::mem::take(&mut self.0) {
            0 => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
            n => Ok((n, SocksAddr::any())),
        }
    }
}

struct MockSend;

#[async_trait]
impl OutboundDatagramSendHalf for MockSend {
    async fn send_to(&mut self, buf: &[u8], _dst_addr: &SocksAddr) -> io::Result<usize> {
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A datagram whose receiving half gets one datagram of `.0` bytes.
struct MockDatagram(usize);

impl OutboundDatagram for MockDatagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (Box::new(MockRecv(self.0)), Box::new(MockSend))
    }
}

fn session(inbound: &str, outbound: &str, user: Option<&UserRef>, network: Network) -> Session {
    Session {
        inbound_tag: inbound.into(),
        outbound_tag: outbound.into(),
        user: user.cloned(),
        network,
        destination: SocksAddr::from(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8001)),
        ..Default::default()
    }
}

fn counts(up: u64, down: u64, tcp: u64, udp: u64) -> Counts {
    Counts { up, down, tcp, udp }
}

fn find<'a>(counts: &'a [(String, Counts)], name: &str) -> Option<&'a Counts> {
    counts.iter().find(|(n, _)| n == name).map(|(_, c)| c)
}

#[tokio::test]
async fn test_stat_stream_non_empty_buf() {
    let sm = StatManager::default();
    let mut stream = sm.stat_stream(mock(&[1, 2, 3, 4, 5]), Session::default());

    let mut data = vec![0u8; 20];
    // Simulate existing data in buffer
    let mut buf = ReadBuf::new(&mut data);
    buf.put_slice(&[0xAA; 5]);
    futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut buf))
        .await
        .unwrap();

    assert_eq!(buf.filled().len(), 10);
    assert_eq!(sm.connections()[0].bytes_recvd(), 5);
}

/// A connection the API closes fails its reads and writes, waiting
/// ones too.
#[tokio::test]
async fn a_closed_connection_fails_its_reads_and_writes() {
    let sm = StatManager::default();
    let (a, _b) = tokio::io::duplex(64);
    let mut stream = sm.stat_stream(Box::new(a), Session::default());
    let id = sm.connections()[0].id;
    let reading = tokio::spawn(async move {
        let mut buf = [0u8; 8];
        let read = stream.read(&mut buf).await;
        (read, stream.write_all(b"x").await)
    });
    tokio::task::yield_now().await;
    assert!(sm.close(id));
    let (read, write) = reading.await.unwrap();
    assert_eq!(read.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(write.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
    assert!(!sm.close(id + 1));
}

#[test]
fn a_datagram_session_ends_when_both_halves_are_dropped() {
    let sm = StatManager::default();
    let dgram = sm.stat_outbound_datagram(
        Box::new(MockDatagram(0)),
        session("in", "out", None, Network::Udp),
    );
    assert_eq!(sm.live(), 1);
    let (recv_half, send_half) = dgram.split();
    assert_eq!(sm.live(), 1);
    drop(recv_half);
    assert_eq!(sm.live(), 1);
    drop(send_half);
    assert_eq!(sm.live(), 0);

    // One never split ends when it is dropped.
    drop(sm.stat_outbound_datagram(
        Box::new(MockDatagram(0)),
        session("in", "out", None, Network::Udp),
    ));
    assert_eq!(sm.live(), 0);
}

/// A connection leaves the live ones as it is dropped, with no task to
/// clean up after it.
#[tokio::test]
async fn a_stream_is_retired_when_dropped() {
    let sm = StatManager::new(10, UserRegistry::default());
    let stream = sm.stat_stream(mock(b""), Session::default());
    assert_eq!(sm.live(), 1);
    drop(stream);
    assert_eq!(sm.live(), 0);
    assert_eq!(sm.recent().len(), 1);
}

/// The outbound's side counts what it writes as up and what it reads as
/// down; the client's side the other way round; a datagram what it sends
/// as up. Each connection counts to its user, inbound and outbound.
#[tokio::test]
async fn bytes_count_to_the_user_inbound_and_outbound_each_way() {
    let users = UserRegistry::default();
    let alice = users.bind("alice");
    let sm = StatManager::new(0, users.clone());

    let mut out = sm.stat_stream(
        mock(b"12345"),
        session("in", "out", Some(&alice), Network::Tcp),
    );
    out.write_all(b"abc").await.unwrap();
    let mut buf = Vec::new();
    out.read_to_end(&mut buf).await.unwrap();

    let mut client = sm.stat_inbound_stream(
        mock(b"1234567"),
        session("in", "direct", None, Network::Tcp),
    );
    client.write_all(b"ab").await.unwrap();
    client.read_to_end(&mut buf).await.unwrap();

    let dgram = sm.stat_outbound_datagram(
        Box::new(MockDatagram(11)),
        session("in2", "out", Some(&alice), Network::Udp),
    );
    let (mut recv, mut send) = dgram.split();
    send.send_to(b"xyzw", &SocksAddr::any()).await.unwrap();
    let mut dbuf = [0u8; 64];
    recv.recv_from(&mut dbuf).await.unwrap();

    assert_eq!(alice.traffic().counts(), counts(3 + 4, 5 + 11, 1, 1));
    let report = sm.traffic();
    assert_eq!(find(&report.users, "alice"), Some(&counts(7, 16, 1, 1)));
    assert_eq!(
        find(&report.inbounds, "in"),
        Some(&counts(3 + 7, 5 + 2, 2, 0))
    );
    assert_eq!(find(&report.inbounds, "in2"), Some(&counts(4, 11, 0, 1)));
    assert_eq!(find(&report.outbounds, "out"), Some(&counts(7, 16, 1, 1)));
    assert_eq!(find(&report.outbounds, "direct"), Some(&counts(7, 2, 1, 0)));
    assert_eq!(sm.totals(), (3 + 7 + 4, 5 + 2 + 11));

    // They stay once the connections are gone.
    drop((out, client, recv, send));
    assert_eq!(sm.live(), 0);
    assert_eq!(sm.totals(), (14, 18));
    assert_eq!(alice.traffic().counts().up, 7);
}

/// The counts a cache file kept go on, users' too, but the totals count
/// from the start.
#[tokio::test]
async fn kept_counts_go_on_but_not_in_the_totals() {
    let users = UserRegistry::default();
    let sm = StatManager::new(0, users.clone());
    sm.restore(TrafficReport {
        users: vec![("alice".into(), counts(100, 200, 3, 4))],
        inbounds: vec![
            ("in".into(), counts(1000, 2000, 5, 6)),
            ("gone".into(), counts(7, 7, 7, 7)),
        ],
        outbounds: vec![("out".into(), counts(10, 20, 1, 1))],
    });
    let alice = users.bind("alice");
    let mut s = sm.stat_stream(mock(b""), session("in", "out", Some(&alice), Network::Tcp));
    s.write_all(b"abc").await.unwrap();
    assert_eq!(alice.traffic().counts(), counts(103, 200, 4, 4));
    let report = sm.traffic();
    assert_eq!(
        find(&report.inbounds, "in"),
        Some(&counts(1003, 2000, 6, 6))
    );
    assert_eq!(find(&report.outbounds, "out"), Some(&counts(13, 20, 2, 1)));
    assert_eq!(sm.totals(), (3, 0));
    // A user not kept starts from nothing.
    assert_eq!(users.bind("bob").traffic().counts(), Counts::default());
}

/// The counts of a tag no longer configured go once nothing counts to it,
/// and stay in the totals.
#[tokio::test]
async fn unconfigured_tags_are_pruned_once_idle() {
    let sm = StatManager::default();
    let mut s = sm.stat_stream(mock(b""), session("old", "gone", None, Network::Tcp));
    s.write_all(b"abcd").await.unwrap();
    let only = |tags: &[&str]| tags.iter().map(|t| t.to_string()).collect::<HashSet<_>>();

    sm.configure(&only(&["new"]), &only(&["kept"]));
    assert!(
        find(&sm.traffic().outbounds, "gone").is_some(),
        "still counted to"
    );
    drop(s);
    sm.configure(&only(&["new"]), &only(&["kept"]));
    let report = sm.traffic();
    assert!(find(&report.outbounds, "gone").is_none());
    assert!(find(&report.inbounds, "old").is_none());
    assert_eq!(sm.totals(), (4, 0));
}

/// Only TCP connections not finished both ways are still to drain.
#[tokio::test]
async fn open_streams_counts_tcp_not_finished_both_ways() {
    let sm = StatManager::default();
    let mut done = sm.stat_stream(mock(b""), session("in", "out", None, Network::Tcp));
    let _open = sm.stat_stream(mock(b"x"), session("in", "out", None, Network::Tcp));
    let _udp = sm.stat_outbound_datagram(
        Box::new(MockDatagram(0)),
        session("in", "out", None, Network::Udp),
    );
    assert_eq!(sm.open_streams(), 2);
    let mut buf = [0u8; 4];
    assert_eq!(done.read(&mut buf).await.unwrap(), 0);
    done.shutdown().await.unwrap();
    assert_eq!(sm.open_streams(), 1);
    assert_eq!(sm.live(), 3);
}

#[tokio::test]
async fn recent_keeps_the_latest_finished() {
    let sm = StatManager::new(3, UserRegistry::default());
    for _ in 0..(SHARDS * 2 + 5) {
        drop(sm.stat_stream(mock(b""), Session::default()));
    }
    let recent = sm.recent();
    assert_eq!(recent.len(), 3);
    let last = (SHARDS * 2 + 5) as u64;
    assert_eq!(recent.last().unwrap().id, last);
    assert!(recent.windows(2).all(|w| w[0].id < w[1].id));
}

#[test]
fn striped_counts_sum_across_threads() {
    let traffic = Arc::new(Traffic::new(counts(5, 0, 0, 0)));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let traffic = traffic.clone();
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    traffic.up.add(2);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(traffic.counts().up, 5 + 8 * 1000 * 2);
    assert_eq!(traffic.since_start().0, 8 * 1000 * 2);
}

/// A stream whose reads fail with `.0`.
struct FailingStream(io::ErrorKind);

impl AsyncRead for FailingStream {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context, _: &mut ReadBuf) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(self.0)))
    }
}

impl AsyncWrite for FailingStream {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A stat manager telling its records to `events`.
fn recording(events: &EventHub, users: &UserRegistry) -> StatManager {
    StatManager::new(0, users.clone()).recording(events.clone())
}

/// The next record told, without waiting.
fn next(
    records: &mut crate::control::events::Subscription<Arc<ConnectionRecord>>,
) -> ConnectionRecord {
    let record = futures::FutureExt::now_or_never(records.recv())
        .expect("a record was told")
        .expect("not lagged");
    (*record).clone()
}

/// A connection's closed record tells what it sent and received, which is
/// what its user, inbound and outbound were counted, its user, and how it
/// ended; a UDP session's too.
#[tokio::test]
async fn a_closed_record_tells_what_its_user_was_counted() {
    let (events, users) = (EventHub::default(), UserRegistry::default());
    let alice = users.bind("alice");
    let sm = recording(&events, &users);
    let mut records = events.records();

    let mut s = sm.stat_stream(
        mock(b"12345"),
        session("in", "out", Some(&alice), Network::Tcp),
    );
    s.write_all(b"abc").await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    s.shutdown().await.unwrap();
    drop(s);
    let record = next(&mut records);
    assert_eq!(record.kind, RecordKind::Closed(End::Finished));
    assert_eq!(record.outcome, Some(Outcome::Ok));
    assert_eq!((record.up_total, record.down_total), (3, 5));
    assert_eq!(record.seq, 0);
    assert_eq!(record.parent_id, None);
    assert_eq!(record.user.as_deref(), Some("alice"));
    assert_eq!(record.inbound, "in");
    assert_eq!(record.outbound.as_deref(), Some("out"));
    assert_eq!(record.chain, vec!["out".to_string()]);
    assert_eq!(record.network, Network::Tcp);
    assert!(record.start <= record.at);

    let dgram = sm.stat_outbound_datagram(
        Box::new(MockDatagram(11)),
        session("in", "out", Some(&alice), Network::Udp),
    );
    let (mut recv, mut send) = dgram.split();
    send.send_to(b"xyzw", &SocksAddr::any()).await.unwrap();
    let mut dbuf = [0u8; 64];
    recv.recv_from(&mut dbuf).await.unwrap();
    drop((recv, send));
    let udp = next(&mut records);
    assert_eq!(udp.kind, RecordKind::Closed(End::Finished));
    assert_eq!((udp.up_total, udp.down_total), (4, 11));

    let counted = alice.traffic().counts();
    assert_eq!(
        (counted.up, counted.down),
        (
            record.up_total + udp.up_total,
            record.down_total + udp.down_total
        )
    );
    assert_ne!(record.id, udp.id);
}

/// A rejected target's parent is metadata only: the attempt retains its
/// own id and run, and its zero-byte Host/User rejection survives the
/// unlisted-session copy used when the attempt is dropped.
#[test]
fn rejected_attempt_records_keep_the_parent_and_json_run() {
    let (events, users) = (EventHub::default(), UserRegistry::default());
    let sm = recording(&events, &users);
    let mut records = events.records();
    let mut root = Session::default();
    sm.numbering().number(&mut root);
    let parent = root.number.as_ref().unwrap().id();
    for (by, reason) in [
        (ClosedBy::Host, Some("blocked".to_string())),
        (ClosedBy::Host, None), // The hook panicked: no host-supplied reason.
        (ClosedBy::User, None),
    ] {
        let mut sess = Session {
            network: Network::Udp,
            parent_id: Some(parent),
            ..Session::default()
        };
        sm.numbering().number(&mut sess);
        let number = sess.number.as_ref().unwrap();
        let id = number.id();
        match by {
            ClosedBy::Host => number.refused_by_host(&sess, reason.clone()),
            _ => number.closed(&sess, Outcome::Rejected, End::Closed(by)),
        }
        let saved = sess.clone();
        drop(sess);
        drop(saved);
        let record = next(&mut records);
        assert_ne!(id, parent);
        assert_eq!(record.id, id);
        assert_eq!(record.parent_id, Some(parent));
        assert_eq!(record.run, sm.recorder.run);
        assert_eq!(record.kind, RecordKind::Closed(End::Closed(by)));
        assert_eq!(record.outcome, Some(Outcome::Rejected));
        assert_eq!(record.reason, reason);
        assert_eq!((record.up_total, record.down_total), (0, 0));
        let json =
            serde_json::to_value(crate::control::json::ConnectionRecord::of(&record)).unwrap();
        assert_eq!(json["id"], id);
        assert_eq!(json["parent_id"], parent);
        assert_eq!(
            json["run_ms"],
            record
                .run
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
        );
    }
    assert_eq!(root.parent_id, None);
}

#[test]
fn a_numbers_run_is_the_recorder_it_captured_not_a_later_binding() {
    let numbering = Numbering::default();
    let recorder = |seconds| {
        Arc::new(Recorder {
            events: EventHub::default(),
            run: std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds),
            stopping: AtomicBool::new(false),
        })
    };
    let old = recorder(100);
    numbering.record_to(&old);
    let mut before = Session::default();
    numbering.number(&mut before);
    let new = recorder(200);
    numbering.record_to(&new);
    let mut after = Session::default();
    numbering.number(&mut after);
    assert_eq!(before.number.as_ref().unwrap().run(), Some(old.run));
    assert_eq!(after.number.as_ref().unwrap().run(), Some(new.run));
}

/// What a connection writes after its last read is in its closed record.
#[tokio::test]
async fn a_write_after_the_last_read_is_in_the_closed_record() {
    let (events, users) = (EventHub::default(), UserRegistry::default());
    let sm = recording(&events, &users);
    let mut records = events.records();
    let mut s = sm.stat_stream(mock(b"12"), session("in", "out", None, Network::Tcp));
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    s.write_all(b"written last").await.unwrap();
    drop(s);
    let record = next(&mut records);
    assert_eq!((record.up_total, record.down_total), (12, 2));
}

/// Nothing is built while no one listens; bytes counted before someone
/// does are in the connection's next record.
#[tokio::test]
async fn records_are_built_only_while_someone_listens() {
    let (events, users) = (EventHub::default(), UserRegistry::default());
    let sm = recording(&events, &users);
    let mut s = sm.stat_stream(mock(b""), session("in", "out", None, Network::Tcp));
    s.write_all(b"abc").await.unwrap();
    drop(sm.stat_stream(mock(b""), session("in", "out", None, Network::Tcp)));
    assert_eq!(events.records_built(), 0);

    let mut records = events.records();
    s.write_all(b"de").await.unwrap();
    drop(s);
    let record = next(&mut records);
    assert_eq!(record.up_total, 5);
    assert_eq!(events.records_built(), 1);
}

/// A closed record tells how the connection ended: why sail closed it,
/// a failure, what its relay told, the stop, or nothing telling.
#[tokio::test]
async fn a_closed_record_tells_how_it_ended() {
    let (events, users) = (EventHub::default(), UserRegistry::default());
    let sm = recording(&events, &users);
    let mut records = events.records();
    let tcp = || session("in", "out", None, Network::Tcp);

    let (s, counter) = sm.stat_stream_id(mock(b"x"), tcp());
    sm.close_by(counter.id, ClosedBy::User);
    // A failure its closing made does not tell over why.
    counter.failed(&closed_by_api());
    drop(s);
    assert_eq!(
        next(&mut records).kind,
        RecordKind::Closed(End::Closed(ClosedBy::User))
    );

    let mut s = sm.stat_stream(
        Box::new(FailingStream(io::ErrorKind::ConnectionReset)),
        tcp(),
    );
    let mut buf = [0u8; 8];
    assert!(s.read(&mut buf).await.is_err());
    drop(s);
    assert_eq!(
        next(&mut records).kind,
        RecordKind::Closed(End::Error(io::ErrorKind::ConnectionReset))
    );

    let (s, counter) = sm.stat_stream_id(mock(b"x"), tcp());
    counter.ended(End::WriteStall);
    counter.ended(End::Error(io::ErrorKind::TimedOut));
    drop(s);
    assert_eq!(next(&mut records).kind, RecordKind::Closed(End::WriteStall));

    // Open both ways, and nothing told: its task ended under it.
    drop(sm.stat_stream(mock(b"x"), tcp()));
    assert_eq!(next(&mut records).kind, RecordKind::Closed(End::Aborted));

    let (s, counter) = sm.stat_outbound_datagram_id(
        Box::new(MockDatagram(0)),
        session("in", "out", None, Network::Udp),
    );
    counter.ended(End::IdleTimeout);
    drop(s);
    assert_eq!(
        next(&mut records).kind,
        RecordKind::Closed(End::IdleTimeout)
    );

    sm.stopping();
    drop(sm.stat_stream(mock(b"x"), tcp()));
    assert_eq!(
        next(&mut records).kind,
        RecordKind::Closed(End::Closed(ClosedBy::Stopped))
    );
    drop(sm.stat_outbound_datagram(
        Box::new(MockDatagram(0)),
        session("in", "out", None, Network::Udp),
    ));
    assert_eq!(
        next(&mut records).kind,
        RecordKind::Closed(End::Closed(ClosedBy::Stopped))
    );
}

/// A subscriber that falls behind is told how many records it missed, and
/// the connections do not wait for it.
#[tokio::test]
async fn a_slow_subscriber_lags_and_no_connection_waits() {
    let (events, users) = (EventHub::with_record_capacity(2), UserRegistry::default());
    let sm = recording(&events, &users);
    let mut records = events.records();
    for _ in 0..5 {
        drop(sm.stat_stream(mock(b""), session("in", "out", None, Network::Tcp)));
    }
    match futures::FutureExt::now_or_never(records.recv()) {
        Some(Err(tokio::sync::broadcast::error::RecvError::Lagged(3))) => {}
        other => panic!("not lagged by 3: {:?}", other.map(|r| r.map(|r| r.id))),
    }
    assert_eq!(next(&mut records).id, 4);
    assert_eq!(next(&mut records).id, 5);
}

/// Each way of closing tells its reason, the first told standing.
#[test]
fn a_closer_tells_the_first_reason() {
    let closer = Closer::default();
    assert_eq!(closer.closed_by(), None);
    closer.close_by(ClosedBy::Network);
    closer.close();
    assert!(closer.is_closed());
    assert_eq!(closer.closed_by(), Some(ClosedBy::Network));
    for by in CLOSED_BY {
        let closer = Closer::default();
        closer.close_by(by);
        assert_eq!(closer.closed_by(), Some(by));
    }
}

/// Interim records tell the bytes since the connection started; a timed
/// pass skips a connection with nothing new, and one the host asks for
/// records every connection, idle ones too. Its closed record holds its
/// totals.
#[tokio::test]
async fn interim_records_are_cumulative_and_an_asked_pass_records_every_one() {
    let (events, users) = (EventHub::default(), UserRegistry::default());
    let sm = recording(&events, &users);
    let mut records = events.records();
    let mut s = sm.stat_stream(mock(b"12345"), session("in", "out", None, Network::Tcp));
    let (_idle, idle) = sm.stat_stream_id(mock(b""), session("in", "out", None, Network::Tcp));

    s.write_all(b"abc").await.unwrap();
    assert_eq!(sm.report(false), 1, "the idle one is skipped");
    let first = next(&mut records);
    assert_eq!(first.kind, RecordKind::Interim);
    assert_eq!(first.outcome, None);
    assert_eq!((first.seq, first.up_total, first.down_total), (0, 3, 0));
    assert_eq!(sm.report(false), 0, "nothing new");

    s.write_all(b"de").await.unwrap();
    let mut buf = [0u8; 1];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(sm.report(false), 1);
    let second = next(&mut records);
    assert_eq!((second.seq, second.up_total, second.down_total), (1, 5, 1));

    // Asked for: both, nothing new or not.
    assert_eq!(sm.report(true), 2);
    let mut asked = [next(&mut records), next(&mut records)];
    asked.sort_by_key(|r| r.id);
    assert_eq!((asked[0].seq, asked[0].up_total), (2, 5));
    assert_eq!(
        (asked[1].id, asked[1].seq, asked[1].up_total),
        (idle.id, 0, 0)
    );

    let mut rest = Vec::new();
    s.read_to_end(&mut rest).await.unwrap();
    drop(s);
    let closed = next(&mut records);
    assert!(matches!(closed.kind, RecordKind::Closed(_)));
    assert_eq!((closed.seq, closed.up_total, closed.down_total), (3, 5, 5));
}

/// A connection counted before its outbound's handshake that never ended
/// well is a failed dial; one its user refuses as it is counted is
/// rejected.
#[tokio::test]
async fn a_closed_record_tells_how_the_connection_was_used() {
    let (events, users) = (EventHub::default(), UserRegistry::default());
    let sm = recording(&events, &users);
    let mut records = events.records();
    let tcp = || session("in", "out", None, Network::Tcp);

    let (s, counter) = sm.stat_stream_id(mock(b""), tcp());
    counter.dialing();
    drop(s);
    assert_eq!(next(&mut records).outcome, Some(Outcome::DialFailed));

    let (s, counter) = sm.stat_stream_id(mock(b""), tcp());
    counter.dialing();
    counter.connected();
    drop(s);
    assert_eq!(next(&mut records).outcome, Some(Outcome::Ok));

    let bob = users.bind("bob");
    users.set_limits(HashMap::from([(
        "bob".to_string(),
        crate::user::Limits {
            max_tcp_connections: Some(1),
            ..Default::default()
        },
    )]));
    let _first = sm.stat_stream(mock(b""), session("in", "out", Some(&bob), Network::Tcp));
    drop(sm.stat_stream(mock(b""), session("in", "out", Some(&bob), Network::Tcp)));
    let refused = next(&mut records);
    assert_eq!(refused.outcome, Some(Outcome::Rejected));
    assert_eq!(
        refused.kind,
        RecordKind::Closed(End::Closed(ClosedBy::User))
    );
}

/// Passes running while the connection relays and closes count each byte
/// once: its records come in order, the closed one last, and add up.
#[test]
fn passes_racing_the_close_count_no_byte_twice() {
    let (events, users) = (
        EventHub::with_record_capacity(1 << 16),
        UserRegistry::default(),
    );
    let sm = Arc::new(recording(&events, &users));
    let mut records = events.records();
    let mut s = sm.stat_stream(mock(b""), session("in", "out", None, Network::Tcp));
    let done = Arc::new(AtomicBool::new(false));
    let passes: Vec<_> = (0..4)
        .map(|_| {
            let (sm, done) = (sm.clone(), done.clone());
            std::thread::spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    sm.report(false);
                }
            })
        })
        .collect();
    for _ in 0..2000 {
        futures::executor::block_on(s.write_all(b"x")).unwrap();
    }
    drop(s);
    // Passes after the close tell nothing more of it.
    std::thread::sleep(std::time::Duration::from_millis(20));
    done.store(true, Ordering::Relaxed);
    for pass in passes {
        pass.join().unwrap();
    }
    let mut told = Vec::new();
    while let Some(record) = futures::FutureExt::now_or_never(records.recv()) {
        told.push(record.expect("not lagged"));
    }
    assert!(told.windows(2).all(|w| w[1].seq == w[0].seq + 1));
    let last = told.last().unwrap();
    assert!(matches!(last.kind, RecordKind::Closed(_)));
    assert!(told[..told.len() - 1]
        .iter()
        .all(|r| r.kind == RecordKind::Interim));
    assert!(told.windows(2).all(|w| w[0].up_total <= w[1].up_total));
    assert_eq!(last.up_total, 2000);
}

/// The interim passes come as often as the host sets, and stop when it
/// unsets them.
#[tokio::test(start_paused = true)]
async fn interim_passes_come_as_often_as_set() {
    let (events, users) = (EventHub::default(), UserRegistry::default());
    let sm = Arc::new(recording(&events, &users));
    let mut records = events.records();
    let passes = tokio::spawn(StatManager::report_task(sm.clone()));
    let mut s = sm.stat_stream(mock(b""), session("in", "out", None, Network::Tcp));
    s.write_all(b"ab").await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert!(
        futures::FutureExt::now_or_never(records.recv()).is_none(),
        "none set"
    );

    // Under the least, the least.
    events.set_record_interval(Some(std::time::Duration::from_millis(10)));
    tokio::time::sleep(
        crate::control::events::RECORD_INTERVAL_MIN + std::time::Duration::from_millis(10),
    )
    .await;
    assert_eq!(next(&mut records).up_total, 2);
    s.write_all(b"c").await.unwrap();
    tokio::time::sleep(crate::control::events::RECORD_INTERVAL_MIN).await;
    assert_eq!(next(&mut records).up_total, 3);

    events.set_record_interval(None);
    s.write_all(b"d").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert!(
        futures::FutureExt::now_or_never(records.recv()).is_none(),
        "unset"
    );
    passes.abort();
}

/// Every routed session holds its number for as long as it lives, so the
/// number is a few words: the copy of a session told to a host is boxed.
#[test]
fn a_number_is_a_few_words() {
    assert!(std::mem::size_of::<Number>() <= 64);
}

/// A session is numbered before it is counted, and listed by that number:
/// a number the host was told and never listed has a closed record of its
/// own once the session's last copy goes, telling how its dial failed; one
/// listed has only its connection's; a second copy counted, as another
/// attempt of a dial, is listed by a number of its own.
#[tokio::test]
async fn a_number_told_has_one_closed_record() {
    let (events, users) = (EventHub::default(), UserRegistry::default());
    let sm = recording(&events, &users);
    let mut records = events.records();

    let mut sess = session("in", "out", None, Network::Tcp);
    sm.numbering().number(&mut sess);
    let id = sess.number.as_ref().unwrap().id();
    sess.number.as_ref().unwrap().told(&sess);
    let s = sm.stat_stream(mock(b""), sess.clone());
    let again = sm.stat_stream(mock(b""), sess.clone());
    drop(sess);
    drop(s);
    let record = next(&mut records);
    assert_eq!(record.id, id);
    drop(again);
    assert_ne!(next(&mut records).id, id);
    assert!(futures::FutureExt::now_or_never(records.recv()).is_none());

    let mut refused = session("in", "out", None, Network::Udp);
    sm.numbering().number(&mut refused);
    let number = refused.number.clone().unwrap();
    number.told(&refused);
    number.failed(&refused, io::ErrorKind::ConnectionRefused);
    let copy = refused.clone();
    drop((refused, number));
    assert!(futures::FutureExt::now_or_never(records.recv()).is_none());
    let id = copy.number.as_ref().unwrap().id();
    drop(copy);
    let record = next(&mut records);
    assert_eq!(record.id, id);
    assert_eq!(
        record.kind,
        RecordKind::Closed(End::Error(io::ErrorKind::ConnectionRefused))
    );
    assert_eq!(record.outcome, Some(Outcome::DialFailed));
    assert_eq!((record.up_total, record.down_total), (0, 0));
    assert_eq!(record.network, Network::Udp);

    // Not told the host, and nothing telling how it ended: nothing.
    let mut untold = session("in", "out", None, Network::Tcp);
    sm.numbering().number(&mut untold);
    drop(untold);
    assert!(futures::FutureExt::now_or_never(records.recv()).is_none());

    // Not told the host, but blocked: its closed record, once.
    let mut blocked = session("in", "", None, Network::Tcp);
    sm.numbering().number(&mut blocked);
    let id = blocked.number.as_ref().unwrap().id();
    blocked.number.as_ref().unwrap().closed(
        &blocked,
        Outcome::Blocked,
        End::Closed(ClosedBy::Rules),
    );
    drop(blocked);
    let record = next(&mut records);
    assert_eq!(record.id, id);
    assert_eq!(record.outcome, Some(Outcome::Blocked));
    assert_eq!(
        record.kind,
        RecordKind::Closed(End::Closed(ClosedBy::Rules))
    );
    assert_eq!(record.outbound, None);
    assert!(futures::FutureExt::now_or_never(records.recv()).is_none());
}

#[test]
fn recent_statistics_must_not_hold_binding_slots() {
    let pool = crate::control::context::ContextPool::new(1);
    let events = EventHub::with_records(16, Some(16));
    let mut reader = events.lossless_records().unwrap().reader().unwrap();
    let sm = StatManager::new(256, UserRegistry::default()).recording(events);
    let mut sess = Session {
        record_context: pool.bind(|| 7_u64),
        ..Default::default()
    };
    sm.numbering().number(&mut sess);
    sess.number.as_ref().unwrap().told(&sess);
    let accounts = sm.register(sess);
    let id = accounts.counter.id;
    accounts.sent(3);
    accounts.recvd(5);
    drop(accounts);
    let recent = sm.recent();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].id, id);
    assert_eq!((recent[0].bytes_sent(), recent[0].bytes_recvd()), (3, 5));
    let envelope = reader.try_next_envelope().unwrap();
    assert_eq!(envelope.context.as_ref().unwrap().get::<u64>(), Some(&7));
    assert!(pool.bind(|| 8_u64).is_none(), "reader still owns the slot");
    drop(envelope);
    assert!(
        pool.bind(|| 8_u64).is_some(),
        "finished UI statistics must not block new admission"
    );
    assert!(recent[0].sess.record_context.is_none());
    assert!(recent[0].sess.number.is_none());
}

#[cfg(any(
    feature = "inbound-shadowsocks",
    feature = "inbound-vless",
    feature = "inbound-anytls"
))]
#[test]
fn recent_statistics_must_not_hold_authentication_rows() {
    let rows = crate::control::context::ContextPool::new(1);
    let user = UserRef::unbound("alice").with_credential_context(rows.bind(|| 7_u64).unwrap());
    let sm = StatManager::new(256, UserRegistry::default());
    let accounts = sm.register(Session {
        user: Some(user),
        ..Default::default()
    });
    drop(accounts);
    let recent = sm.recent();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].sess.user.as_ref().unwrap().name(), "alice");
    assert!(
        rows.bind(|| 8_u64).is_some(),
        "UI history must not own a retired credential row"
    );
    assert!(recent[0]
        .sess
        .user
        .as_ref()
        .unwrap()
        .credential_context()
        .is_none());
}
