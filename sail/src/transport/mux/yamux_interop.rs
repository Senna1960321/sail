//! muxcore's yamux against hashicorp/yamux, the reference, with its
//! default configuration: `scripts/yamux-peer`, built and given as
//! `YAMUX_PEER`. Ignored by default:
//!
//! ```text
//! (cd scripts/yamux-peer && go build -o /tmp/yamux-peer .)
//! YAMUX_PEER=/tmp/yamux-peer cargo test -p sail --lib yamux_interop -- --ignored
//! ```

use std::io::BufRead;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use crate::transport::muxcore::yamux::Yamux;
use crate::transport::muxcore::{Session, Tuning};

/// Streams opened at once, past the reference's accept backlog of 256.
const STREAMS: usize = 500;
/// What each stream sends and reads back.
const SIZE: usize = 64 << 10;
const PATIENCE: Duration = Duration::from_secs(60);

fn peer() -> Command {
    let path = std::env::var_os("YAMUX_PEER").expect("YAMUX_PEER: the built scripts/yamux-peer");
    Command::new(path)
}

/// The reference, killed when dropped.
struct Reference(Child);

impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The reference serving echo, and a client session to it.
async fn to_reference() -> (Reference, Session) {
    let mut child = peer().arg("serve").stdout(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let port: u16 = line
        .trim()
        .strip_prefix("listening ")
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("yamux-peer said {:?}", line));
    let conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (session, _) = Session::new(conn, Arc::new(Yamux), false, Tuning::default(), "test");
    (Reference(child), session)
}

/// Sends `SIZE` bytes of `seed` on a new stream, finishes it, and reads
/// them back.
async fn echo(session: &Session, seed: u8) -> std::io::Result<()> {
    let stream = session.open().await?;
    let (mut r, mut w) = tokio::io::split(stream);
    let data = vec![seed; SIZE];
    let send = async {
        w.write_all(&data).await?;
        w.shutdown().await
    };
    let mut back = Vec::new();
    let (sent, read) = tokio::join!(send, r.read_to_end(&mut back));
    sent?;
    read?;
    if back != data {
        return Err(std::io::Error::other(format!(
            "{} bytes back of {}",
            back.len(),
            SIZE
        )));
    }
    Ok(())
}

/// 500 streams opened at once all complete: no more than 256 wait to be
/// acknowledged, and the reference resets none past its backlog.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs YAMUX_PEER"]
async fn five_hundred_streams_at_once_to_the_reference_complete() {
    let (_child, session) = to_reference().await;
    let results = timeout(
        PATIENCE,
        join_all((0..STREAMS).map(|i| echo(&session, i as u8))),
    )
    .await
    .expect("the streams did not complete");
    let failed: Vec<_> = results.iter().filter_map(|r| r.as_ref().err()).collect();
    assert!(
        failed.is_empty(),
        "{} of {} failed, first: {}",
        failed.len(),
        STREAMS,
        failed[0]
    );
    assert!(session.is_reusable());
}

/// A stream dropped mid-transfer is reset, alone: the session goes on, and
/// the next stream on it completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs YAMUX_PEER"]
async fn a_stream_dropped_mid_transfer_keeps_the_session_with_the_reference() {
    let (_child, session) = to_reference().await;
    let mut cut = session.open().await.unwrap();
    // The reference echoes as it reads: more than a window is on its way
    // back once the stream is dropped.
    cut.write_all(&vec![1u8; 4 * SIZE]).await.unwrap();
    let mut first = [0u8; 4];
    timeout(PATIENCE, cut.read_exact(&mut first))
        .await
        .expect("nothing came back")
        .unwrap();
    drop(cut);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(session.is_reusable(), "a reset stream retired the session");
    for seed in 0..4 {
        timeout(PATIENCE, echo(&session, seed))
            .await
            .expect("the next stream did not complete")
            .unwrap();
    }
    assert!(session.is_reusable());
    assert!(!session.is_closed());
}

/// The reference's client opens 500 streams at once on a muxcore server:
/// all come back whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs YAMUX_PEER"]
async fn five_hundred_streams_at_once_from_the_reference_complete() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (conn, _) = listener.accept().await.unwrap();
        let (_session, accept) =
            Session::new(conn, Arc::new(Yamux), true, Tuning::default(), "test");
        let mut accept = accept.unwrap();
        while let Some(stream) = accept.recv().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    let mut dial = peer();
    dial.args(["dial", "-addr", &format!("127.0.0.1:{}", port)])
        .args(["-streams", &STREAMS.to_string(), "-size", &SIZE.to_string()]);
    let output = timeout(PATIENCE, tokio::task::spawn_blocking(move || dial.output()))
        .await
        .expect("the reference's streams did not complete")
        .unwrap()
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "yamux-peer said {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert_eq!(result["whole"], STREAMS, "{}", result);
}
