//! Sail/1's streams nobody reads are parked, not reset (`Tuning::parking`):
//! kept as a TCP connection whose reader paused is, each charged its
//! window in the transfer budget, so that together they hold no more than
//! the budget. One the budget has no room for is reset, as every other
//! protocol's are; new streams still open. A session kept open by parked
//! streams still ends once its peer stops answering pings.
//!
//! The stall timeout and the ping timeout are a second and two here,
//! rather than a minute and thirty seconds.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

use super::codec::{Role, Sail};
use crate::protocol::anytls::padding::PaddingScheme;
use crate::protocol::anytls::session::PaddingCell;
use crate::runtime::transfer_budget::TransferBudget;
use crate::transport::muxcore::{Codec, Session, Stream, Tuning, INITIAL_WINDOW};

/// What each server stream sends: twice its window, so that the rest
/// waits at the sender until the stream is read.
const SENT: usize = 2 * INITIAL_WINDOW as usize;
/// Longer than the stall timeout and the checks after it.
const PARK: Duration = Duration::from_millis(2500);
const PATIENCE: Duration = Duration::from_secs(10);

fn tuning() -> Tuning {
    Tuning {
        stall_timeout: Duration::from_secs(1),
        ping_timeout: Some(Duration::from_secs(2)),
        ..Tuning::default().parking()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn codec(server: bool) -> Arc<dyn Codec> {
    let scheme = Arc::new(PaddingScheme::default_scheme());
    let role = if server {
        Role::Server(scheme)
    } else {
        let cell: PaddingCell = Arc::new(RwLock::new(scheme));
        Role::Client(cell)
    };
    Arc::new(Sail { role })
}

/// A test's own budget of `windows` initial windows.
fn budget(windows: u64) -> &'static TransferBudget {
    Box::leak(Box::new(TransferBudget::limited(
        windows * u64::from(INITIAL_WINDOW),
    )))
}

/// A client and a server session, the client's parking against `budget`.
fn sessions(
    budget: &'static TransferBudget,
) -> (
    Session,
    Session,
    tokio::sync::mpsc::UnboundedReceiver<Stream>,
) {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (client, _) = Session::new(a, codec(false), false, tuning(), "test");
    client.park_against(budget);
    let (server, accept) = Session::new(b, codec(true), true, tuning(), "test");
    (client, server, accept.unwrap())
}

/// The byte at `i` of what a server stream sends.
fn byte(i: usize) -> u8 {
    (i % 251) as u8
}

/// Opens `count` streams, each of which the server answers with `SENT`
/// bytes and a FIN; none of them is read.
async fn unread(
    client: &Session,
    accept: &mut tokio::sync::mpsc::UnboundedReceiver<Stream>,
    count: usize,
) -> Vec<Stream> {
    let mut streams = Vec::new();
    for _ in 0..count {
        let mut stream = client.open().await.unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut served = accept.recv().await.unwrap();
        let mut first = [0u8; 1];
        served.read_exact(&mut first).await.unwrap();
        tokio::spawn(async move {
            let data: Vec<u8> = (0..SENT).map(byte).collect();
            if served.write_all(&data).await.is_ok() {
                let _ = served.shutdown().await;
            }
        });
        streams.push(stream);
    }
    streams
}

/// Reads `stream` to its end: whether all that was sent came, in order.
async fn read_whole(stream: &mut Stream) -> std::io::Result<bool> {
    let mut got = Vec::new();
    timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .expect("a parked stream reads to its end")?;
    Ok(got.len() == SENT && got.iter().enumerate().all(|(i, b)| *b == byte(i)))
}

/// Five streams fill their windows unread with room for three: three are
/// parked, holding the budget and no more, and read back whole; two are
/// reset. A new stream opens meanwhile. Once the parked are done, the
/// budget is back.
#[test]
fn parked_streams_hold_no_more_than_the_budget() {
    runtime().block_on(async {
        let budget = budget(3);
        let (client, _server, mut accept) = sessions(budget);
        let mut streams = unread(&client, &mut accept, 5).await;
        sleep(PARK).await;
        assert_eq!(budget.held(), 3 * u64::from(INITIAL_WINDOW));
        assert!(budget.peak() <= 3 * u64::from(INITIAL_WINDOW));

        // The budget spent, a new stream still opens and carries data.
        let mut fresh = unread(&client, &mut accept, 1).await.pop().unwrap();
        assert!(read_whole(&mut fresh).await.unwrap());

        let (mut whole, mut reset) = (0, 0);
        for stream in &mut streams {
            match read_whole(stream).await {
                Ok(true) => whole += 1,
                Ok(false) => panic!("a parked stream lost data"),
                Err(_) => reset += 1,
            }
        }
        assert_eq!((whole, reset), (3, 2));
        drop(streams);
        assert_eq!(budget.held(), 0);
        assert!(!client.is_closed());
    });
}

/// Hysteria2's and TUIC's windows grow out of the same budget
/// (`transport::quic::common`): while parked streams hold all of it, a
/// growth is refused, as it is when anything else holds it; once the
/// stream reads, it is granted again.
#[test]
fn a_growth_is_refused_while_parked_streams_hold_the_budget() {
    runtime().block_on(async {
        let budget = budget(1);
        let (client, _server, mut accept) = sessions(budget);
        let mut stream = unread(&client, &mut accept, 1).await.pop().unwrap();
        sleep(PARK).await;
        assert_eq!(budget.held(), u64::from(INITIAL_WINDOW));
        let refused = budget.refused();
        assert!(!budget.try_grow(1));
        assert_eq!(budget.refused(), refused + 1);

        let mut first = [0u8; 1];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(budget.held(), 0);
        assert!(budget.try_grow(1));
        budget.release(1);
    });
}

/// A parked stream keeps its session open past the ping timeout while
/// the peer answers; a session whose peer is gone ends at the timeout
/// whatever its streams.
#[test]
fn only_an_unanswered_ping_ends_a_parking_session() {
    runtime().block_on(async {
        let budget = budget(4);
        let (client, _server, mut accept) = sessions(budget);
        let mut stream = unread(&client, &mut accept, 1).await.pop().unwrap();
        sleep(Duration::from_secs(5)).await;
        assert_eq!(budget.held(), u64::from(INITIAL_WINDOW));
        assert!(!client.is_closed());
        assert!(read_whole(&mut stream).await.unwrap());

        // A peer that reads nothing and answers nothing.
        let (a, _silent) = tokio::io::duplex(1 << 20);
        let (lonely, _) = Session::new(a, codec(false), false, tuning(), "test");
        lonely.park_against(budget);
        let _stream = lonely.open().await.unwrap();
        timeout(Duration::from_secs(5), async {
            while !lonely.is_closed() {
                sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the session ends once its ping goes unanswered");
    });
}
