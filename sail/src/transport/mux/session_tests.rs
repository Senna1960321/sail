//! smux and yamux sessions against each other, over a pipe.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::transport::muxcore::{Codec, Session, Tuning};

use super::smux::Smux;
use super::yamux::Yamux;

#[derive(Clone, Copy)]
enum Flavor {
    Smux,
    Yamux,
}

impl Flavor {
    fn codec(self) -> Arc<dyn Codec> {
        match self {
            Flavor::Smux => Arc::new(Smux),
            Flavor::Yamux => Arc::new(Yamux),
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Streams echo on the server; each client stream sends `size` bytes
/// and reads them back.
async fn echo(flavor: Flavor, streams: usize, size: usize) {
    let (a, b) = tokio::io::duplex(64 << 10);
    let (client, _) = Session::new(a, flavor.codec(), false, Tuning::default(), "test");
    let (_server, accept) = Session::new(b, flavor.codec(), true, Tuning::default(), "test");
    let mut accept = accept.unwrap();
    tokio::spawn(async move {
        while let Some(stream) = accept.recv().await {
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
                // smux cannot half-close: keep the stream until the
                // client is done with it.
                tokio::time::sleep(Duration::from_millis(500)).await;
            });
        }
    });
    let mut tasks = Vec::new();
    for i in 0..streams {
        let stream = client.open().unwrap();
        tasks.push(tokio::spawn(async move {
            let data: Vec<u8> = (0..size).map(|j| (i + j) as u8).collect();
            let (mut r, mut w) = tokio::io::split(stream);
            let expected = data.clone();
            let writer = tokio::spawn(async move {
                w.write_all(&data).await.unwrap();
                w
            });
            let mut got = vec![0u8; size];
            r.read_exact(&mut got).await.unwrap();
            assert!(got == expected, "stream {} garbled", i);
            drop(writer.await.unwrap());
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[test]
fn smux_streams_carry_data_both_ways() {
    runtime().block_on(echo(Flavor::Smux, 16, 300 << 10));
}

#[test]
fn yamux_streams_carry_more_than_a_window() {
    runtime().block_on(echo(Flavor::Yamux, 16, 1 << 20));
}

#[test]
fn yamux_half_close_and_reset() {
    runtime().block_on(async {
        let (a, b) = tokio::io::duplex(64 << 10);
        let (client, _) = Session::new(a, Flavor::Yamux.codec(), false, Tuning::default(), "test");
        let (_server, accept) =
            Session::new(b, Flavor::Yamux.codec(), true, Tuning::default(), "test");
        let mut accept = accept.unwrap();
        let mut stream = client.open().unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut served = accept.recv().await.unwrap();
        let mut got = Vec::new();
        served.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");
        // Still writable after the client finished.
        served.write_all(b"pong").await.unwrap();
        served.shutdown().await.unwrap();
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"pong");
        // Dropped before the peer finished: reset.
        let stream = client.open().unwrap();
        let mut served = accept.recv().await.unwrap();
        drop(stream);
        let err = served.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(client.num_streams(), 1);
    });
}

/// smux cannot half-close: a stream shut down is over both ways, and the
/// peer reads its end, as sing-box closes a connection that cannot
/// half-close. Left open, a relay would wait on a peer that never hears
/// the end.
#[test]
fn smux_shutdown_ends_the_stream() {
    runtime().block_on(async {
        let (a, b) = tokio::io::duplex(64 << 10);
        let (client, _) = Session::new(a, Flavor::Smux.codec(), false, Tuning::default(), "test");
        let (_server, accept) =
            Session::new(b, Flavor::Smux.codec(), true, Tuning::default(), "test");
        let mut accept = accept.unwrap();
        let mut stream = client.open().unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut served = accept.recv().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), served.read_to_end(&mut got))
            .await
            .expect("the peer never heard the end")
            .unwrap();
        assert_eq!(got, b"ping");
        let n = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut [0u8; 4]))
            .await
            .expect("still open the other way")
            .unwrap();
        assert_eq!(n, 0);
    });
}

#[test]
fn a_closed_connection_fails_the_streams() {
    runtime().block_on(async {
        let (a, b) = tokio::io::duplex(64 << 10);
        let (client, _) = Session::new(a, Flavor::Smux.codec(), false, Tuning::default(), "test");
        let mut stream = client.open().unwrap();
        drop(b);
        let err = stream.read(&mut [0u8; 4]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(client.is_closed());
        assert!(client.open().is_err());
    });
}

/// Without half-close, a client's stream dropped before the peer finished
/// it retires its session: what the peer sent it is still on its way,
/// ahead of what a new stream would get. The session takes no new streams,
/// the others go on, and it ends with the last. A stream the peer ended
/// leaves it reusable, and so does any stream on a server's session.
#[test]
fn an_abrupt_end_retires_a_smux_session() {
    runtime().block_on(async {
        let flavor = Flavor::Smux;
        let (a, b) = tokio::io::duplex(64 << 10);
        let (client, _) = Session::new(a, flavor.codec(), false, Tuning::default(), "test");
        let (server, accept) = Session::new(b, flavor.codec(), true, Tuning::default(), "test");
        let mut accept = accept.unwrap();
        // Finished by the peer before it is dropped on the server, while
        // the client has not finished.
        let mut ended = client.open().unwrap();
        ended.write_all(b"x").await.unwrap();
        let mut served = accept.recv().await.unwrap();
        served.write_all(b"bye").await.unwrap();
        drop(served);
        let mut got = Vec::new();
        let _ = ended.read_to_end(&mut got).await;
        assert_eq!(got, b"bye");
        drop(ended);
        assert!(
            client.is_reusable(),
            "a stream the peer ended retired the session"
        );
        assert!(
            server.is_reusable(),
            "a server's stream retired its session"
        );
        // Two streams, and one dropped while the peer still sends.
        let mut kept = client.open().unwrap();
        kept.write_all(b"k").await.unwrap();
        let mut kept_served = accept.recv().await.unwrap();
        let mut cut = client.open().unwrap();
        cut.write_all(b"c").await.unwrap();
        let mut cut_served = accept.recv().await.unwrap();
        cut_served.write_all(b"more").await.unwrap();
        let mut first = [0u8; 4];
        cut.read_exact(&mut first).await.unwrap();
        drop(cut);
        assert!(
            !client.is_reusable(),
            "a stream cut short left the session reusable"
        );
        assert!(!client.is_closed(), "the session ended with a stream open");
        assert!(
            client.open().is_err(),
            "a retired session took a new stream"
        );
        kept_served.write_all(b"on").await.unwrap();
        let mut on = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), kept.read_exact(&mut on))
            .await
            .expect("the other stream stopped")
            .unwrap();
        assert_eq!(&on, b"on");
        drop(kept);
        assert!(
            client.is_closed(),
            "a retired session outlived its last stream"
        );
    });
}

/// With half-close, a client's stream dropped while the peer still sends
/// is reset, alone: what the peer sent meanwhile is dropped, and the
/// session goes on, the next stream on it as any other. A stream the peer
/// reset leaves it reusable too.
#[test]
fn a_reset_stream_keeps_a_yamux_session() {
    runtime().block_on(async {
        let (a, b) = tokio::io::duplex(64 << 10);
        let (client, _) = Session::new(a, Flavor::Yamux.codec(), false, Tuning::default(), "test");
        let (_server, accept) =
            Session::new(b, Flavor::Yamux.codec(), true, Tuning::default(), "test");
        let mut accept = accept.unwrap();
        // Reset by the peer.
        let mut ended = client.open().unwrap();
        ended.write_all(b"x").await.unwrap();
        drop(accept.recv().await.unwrap());
        let _ = ended.read_to_end(&mut Vec::new()).await;
        drop(ended);
        assert!(
            client.is_reusable(),
            "a stream the peer reset retired the session"
        );
        // Dropped mid-transfer.
        let mut cut = client.open().unwrap();
        cut.write_all(b"c").await.unwrap();
        let mut cut_served = accept.recv().await.unwrap();
        let sender = tokio::spawn(async move {
            let chunk = vec![7u8; 16 << 10];
            while cut_served.write_all(&chunk).await.is_ok() {}
        });
        let mut first = [0u8; 4];
        cut.read_exact(&mut first).await.unwrap();
        drop(cut);
        tokio::time::timeout(Duration::from_secs(5), sender)
            .await
            .expect("the peer's stream was not reset")
            .unwrap();
        assert!(client.is_reusable(), "a reset stream retired the session");
        let mut next = client.open().unwrap();
        next.write_all(b"next").await.unwrap();
        next.shutdown().await.unwrap();
        let mut served = accept.recv().await.unwrap();
        let mut got = Vec::new();
        served.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"next");
        served.write_all(b"done").await.unwrap();
        served.shutdown().await.unwrap();
        let mut back = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), next.read_to_end(&mut back))
            .await
            .expect("the next stream stopped")
            .unwrap();
        assert_eq!(back, b"done");
        drop(next);
        drop(served);
        assert!(client.is_reusable());
        assert!(!client.is_closed());
    });
}

/// A client session over a pipe whose peer writes raw smux frames, and
/// the peer's end to write them on.
async fn raw_smux_peer() -> (Session, tokio::io::WriteHalf<tokio::io::DuplexStream>) {
    let (a, b) = tokio::io::duplex(64 << 10);
    let (client, _) = Session::new(a, Flavor::Smux.codec(), false, Tuning::default(), "test");
    let (mut r, w) = tokio::io::split(b);
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut r, &mut tokio::io::sink()).await;
    });
    (client, w)
}

/// Waits up to five seconds for `done`.
async fn until(done: impl Fn() -> bool) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

/// Without half-close the peer never answers this end's FIN: a client's
/// stream shut down and dropped leaves its session reusable, unless data
/// still came after the FIN, or comes once the stream is gone.
#[test]
fn smux_data_past_a_fin_retires_the_session() {
    runtime().block_on(async {
        let smux = Flavor::Smux.codec();
        // Nothing after the FIN.
        let (client, _peer) = raw_smux_peer().await;
        let mut stream = client.open().unwrap();
        stream.write_all(b"x").await.unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        assert!(
            client.is_reusable(),
            "a stream shut down retired its session"
        );
        // Data after the FIN, while the stream is held.
        let (client, mut peer) = raw_smux_peer().await;
        let mut stream = client.open().unwrap();
        stream.write_all(b"x").await.unwrap();
        stream.shutdown().await.unwrap();
        peer.write_all(&smux.data(stream.id(), b"late"))
            .await
            .unwrap();
        assert!(
            until(|| client.received() >= 4).await,
            "the data never came"
        );
        drop(stream);
        assert!(
            !client.is_reusable(),
            "data past the FIN left the session reusable"
        );
        // Data once the stream is gone: the session, without streams, ends.
        let (client, mut peer) = raw_smux_peer().await;
        let mut stream = client.open().unwrap();
        stream.write_all(b"x").await.unwrap();
        stream.shutdown().await.unwrap();
        let id = stream.id();
        drop(stream);
        assert!(client.is_reusable());
        peer.write_all(&smux.data(id, b"late")).await.unwrap();
        assert!(
            until(|| client.is_closed()).await,
            "data for a stream gone left the session open"
        );
    });
}

/// A client and a server session over a pipe, and a stream between them:
/// the client's end, and the server's.
async fn pair(
    flavor: Flavor,
    tuning: Tuning,
) -> (
    Session,
    Session,
    crate::transport::muxcore::Stream,
    crate::transport::muxcore::Stream,
) {
    let (a, b) = tokio::io::duplex(64 << 10);
    let (client, _) = Session::new(a, flavor.codec(), false, tuning, "test");
    let (server, accept) = Session::new(b, flavor.codec(), true, tuning, "test");
    let mut accept = accept.unwrap();
    let mut stream = client.open().unwrap();
    // smux opens a stream the peer sees only once it is written to.
    stream.write_all(b"x").await.unwrap();
    let mut served = accept.recv().await.unwrap();
    let mut first = [0u8; 1];
    served.read_exact(&mut first).await.unwrap();
    (client, server, stream, served)
}

/// Writes on `stream` for as long as it takes, and says when writing
/// failed.
fn flood(
    mut stream: crate::transport::muxcore::Stream,
) -> tokio::task::JoinHandle<(tokio::time::Instant, io::Error)> {
    tokio::spawn(async move {
        let chunk = vec![7u8; 16 << 10];
        loop {
            if let Err(e) = stream.write_all(&chunk).await {
                return (tokio::time::Instant::now(), e);
            }
        }
    })
}

/// A stream read a little every 10 s for two minutes is never taken to
/// have stalled, with a window or without.
#[tokio::test(start_paused = true)]
async fn a_slow_but_steady_reader_is_never_reset() {
    for flavor in [Flavor::Smux, Flavor::Yamux] {
        let (_client, _server, stream, mut served) = pair(flavor, Tuning::default()).await;
        let writer = flood(stream);
        let start = tokio::time::Instant::now();
        let mut buf = [0u8; 1024];
        while start.elapsed() < Duration::from_secs(120) {
            tokio::time::sleep(Duration::from_secs(10)).await;
            served.read_exact(&mut buf).await.unwrap();
            assert!(buf.iter().all(|b| *b == 7));
        }
        assert!(!writer.is_finished());
        writer.abort();
    }
}

/// A stream nothing reads is reset once its data has waited the stall
/// timeout, and its peer told.
#[tokio::test(start_paused = true)]
async fn a_stuck_stream_is_reset_after_the_stall_timeout() {
    for flavor in [Flavor::Smux, Flavor::Yamux] {
        let (_client, _server, stream, mut served) = pair(flavor, Tuning::default()).await;
        let start = tokio::time::Instant::now();
        let writer = flood(stream);
        tokio::time::sleep(Duration::from_secs(55)).await;
        assert!(!writer.is_finished());
        let (failed, e) = writer.await.unwrap();
        let after = failed - start;
        assert!(
            after >= Duration::from_secs(60) && after <= Duration::from_secs(66),
            "reset after {:?}",
            after
        );
        let kind = match flavor {
            // No reset in smux: its FIN ends the stream both ways.
            Flavor::Smux => io::ErrorKind::BrokenPipe,
            Flavor::Yamux => io::ErrorKind::ConnectionReset,
        };
        assert_eq!(e.kind(), kind);
        let err = served.read(&mut [0u8; 16]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}

/// A thousand streams opened at once, before the server takes any, are
/// all accepted and served.
#[test]
fn a_burst_of_a_thousand_streams_is_all_accepted() {
    for flavor in [Flavor::Smux, Flavor::Yamux] {
        runtime().block_on(async {
            let (a, b) = tokio::io::duplex(64 << 10);
            let (client, _) = Session::new(a, flavor.codec(), false, Tuning::default(), "test");
            let (_server, accept) =
                Session::new(b, flavor.codec(), true, Tuning::default(), "test");
            let mut accept = accept.unwrap();
            let mut clients = Vec::new();
            for i in 0..1000u32 {
                let mut stream = client.open().unwrap();
                clients.push(tokio::spawn(async move {
                    stream.write_all(&i.to_be_bytes()).await?;
                    let mut echo = [0u8; 4];
                    stream.read_exact(&mut echo).await?;
                    assert_eq!(u32::from_be_bytes(echo), i);
                    Ok::<_, io::Error>(stream)
                }));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            tokio::spawn(async move {
                while let Some(mut stream) = accept.recv().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 4];
                        stream.read_exact(&mut buf).await?;
                        stream.write_all(&buf).await?;
                        std::future::pending::<()>().await;
                        Ok::<_, io::Error>(())
                    });
                }
            });
            let mut served = 0;
            for task in clients {
                tokio::time::timeout(Duration::from_secs(10), task)
                    .await
                    .expect("a stream of the burst was not served")
                    .unwrap()
                    .unwrap();
                served += 1;
            }
            assert_eq!(served, 1000);
        });
    }
}

/// A session whose handle is dropped carries its streams on until they
/// end, then ends.
#[test]
fn a_dropped_session_keeps_its_streams_until_they_end() {
    for flavor in [Flavor::Smux, Flavor::Yamux] {
        runtime().block_on(async {
            let (a, b) = tokio::io::duplex(64 << 10);
            let (client, _) = Session::new(a, flavor.codec(), false, Tuning::default(), "test");
            let (_server, accept) =
                Session::new(b, flavor.codec(), true, Tuning::default(), "test");
            let mut accept = accept.unwrap();
            let mut stream = client.open().unwrap();
            stream.write_all(b"x").await.unwrap();
            let mut served = accept.recv().await.unwrap();
            drop(client);
            // The stream goes on both ways.
            let data = vec![3u8; 1 << 20];
            let expected = data.clone();
            let (mut r, mut w) = tokio::io::split(stream);
            let writer = tokio::spawn(async move {
                w.write_all(&data).await.unwrap();
                w
            });
            let mut got = vec![0u8; 1 + (1 << 20)];
            served.read_exact(&mut got).await.unwrap();
            assert_eq!(&got[1..], &expected[..]);
            served.write_all(b"done").await.unwrap();
            let mut done = [0u8; 4];
            r.read_exact(&mut done).await.unwrap();
            assert_eq!(&done, b"done");
            // Once it ends, so does the session: the server takes no more.
            drop(r.unsplit(writer.await.unwrap()));
            let next = tokio::time::timeout(Duration::from_secs(5), accept.recv())
                .await
                .expect("the session outlived its last stream");
            assert!(next.is_none());
        });
    }
}

/// A stream whose window is read faster than a round trip lets it in has
/// it doubled, up to the largest allowed; one read slower keeps it.
#[test]
fn windows_grow_while_read_fast() {
    for (rtt, grown) in [
        (Duration::from_secs(1), 2 << 20),
        (Duration::from_nanos(1), 256 << 10),
    ] {
        runtime().block_on(async {
            let tuning = Tuning {
                window_max: 2 << 20,
                ..Tuning::default()
            };
            let (_client, _server, stream, mut served) = pair(Flavor::Yamux, tuning).await;
            served.pin_rtt(rtt);
            let writer = flood(stream);
            let mut buf = vec![0u8; 64 << 10];
            for _ in 0..(16 << 20) / buf.len() {
                served.read_exact(&mut buf).await.unwrap();
            }
            assert_eq!(served.window(), grown, "with a round trip of {:?}", rtt);
            writer.abort();
        });
    }
}

/// Sends `len` bytes on `stream`, then keeps it open, idle.
fn send(
    mut stream: crate::transport::muxcore::Stream,
    len: usize,
) -> tokio::task::JoinHandle<crate::transport::muxcore::Stream> {
    tokio::spawn(async move {
        let chunk = vec![7u8; 16 << 10];
        for _ in 0..len / chunk.len() {
            stream.write_all(&chunk).await.unwrap();
        }
        stream
    })
}

/// A download on a new stream: the server sends 16 MiB and the client
/// reads it all, fast enough for its window to grow. Both ends are kept.
async fn download(
    client: &Session,
    accept: &mut tokio::sync::mpsc::UnboundedReceiver<crate::transport::muxcore::Stream>,
) -> (
    crate::transport::muxcore::Stream,
    crate::transport::muxcore::Stream,
) {
    let mut stream = client.open().unwrap();
    stream.write_all(b"x").await.unwrap();
    stream.pin_rtt(Duration::from_secs(1));
    let served = accept.recv().await.unwrap();
    let sender = send(served, 16 << 20);
    let mut buf = vec![0u8; 64 << 10];
    for _ in 0..(16 << 20) / buf.len() {
        stream.read_exact(&mut buf).await.unwrap();
    }
    (stream, sender.await.unwrap())
}

/// Windows that grew on streams now idle go back to the session's growth
/// budget once another stream needs it: a keep-alive connection that once
/// downloaded fast does not keep the next download at a small window.
#[tokio::test(start_paused = true)]
async fn idle_streams_give_their_grown_windows_back() {
    const MAX: u32 = 2 << 20;
    let tuning = Tuning {
        window_max: MAX,
        ..Tuning::default()
    };
    let (a, b) = tokio::io::duplex(64 << 10);
    let (client, _) = Session::new(a, Flavor::Yamux.codec(), false, tuning, "test");
    let (_server, accept) = Session::new(b, Flavor::Yamux.codec(), true, tuning, "test");
    let mut accept = accept.unwrap();
    // As many as the budget lets grow all the way, then left idle.
    let mut idle = Vec::new();
    for _ in 0..4 {
        let (stream, served) = download(&client, &mut accept).await;
        assert_eq!(stream.window(), MAX);
        idle.push((stream, served));
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
    let (stream, _served) = download(&client, &mut accept).await;
    assert_eq!(stream.window(), MAX, "the budget went to idle streams");
    // A stream whose window was taken back still reads all it is sent,
    // its peer held to what it was granted.
    let taken = idle
        .iter()
        .position(|(stream, _)| stream.window() == 256 << 10)
        .expect("no idle stream gave its window back");
    let (mut stream, served) = idle.swap_remove(taken);
    let sender = send(served, 16 << 20);
    let mut buf = vec![0u8; 64 << 10];
    for _ in 0..(16 << 20) / buf.len() {
        stream.read_exact(&mut buf).await.unwrap();
    }
    sender.await.unwrap();
}

/// A connection read from a pipe, which takes what is written to it a
/// byte every `every`, or, without, never.
struct Stuck {
    read: tokio::io::DuplexStream,
    every: Option<Duration>,
    next: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl tokio::io::AsyncRead for Stuck {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Stuck {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        use std::future::Future;
        let Some(every) = self.every else {
            return std::task::Poll::Pending;
        };
        std::task::ready!(self.next.as_mut().poll(cx));
        let next = tokio::time::Instant::now() + every;
        self.next.as_mut().reset(next);
        std::task::Poll::Ready(Ok(buf.len().min(1)))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// A smux client session over a `Stuck` connection taking a byte every
/// `every`, or nothing, with a stream that has written to it; when
/// `fill`, the peer has sent the stream more than its inbox holds, which
/// nothing reads, and the session stops reading.
async fn stuck_session(
    every: Option<Duration>,
    fill: bool,
    tuning: Tuning,
) -> (Session, crate::transport::muxcore::Stream) {
    let smux = Flavor::Smux.codec();
    let (read, mut peer) = tokio::io::duplex(256 << 10);
    let conn = Stuck {
        read,
        every,
        next: Box::pin(tokio::time::sleep(Duration::ZERO)),
    };
    let (client, _) = Session::new(conn, smux.clone(), false, tuning, "test");
    let mut stream = client.open().unwrap();
    stream.write_all(&[1u8; 32 << 10]).await.unwrap();
    if fill {
        let chunk = vec![2u8; 8 << 10];
        for _ in 0..(2 * tuning.inbox) / chunk.len() {
            peer.write_all(&smux.data(stream.id(), &chunk))
                .await
                .unwrap();
        }
        // The reader stops once the inbox is full, before all of it.
        let full = tuning.inbox as u64;
        assert!(
            until(|| client.received() >= full).await,
            "the data never came"
        );
    }
    // The peer stays: its end gone, the session would read the end.
    tokio::spawn(async move {
        let _peer = peer;
        std::future::pending::<()>().await;
    });
    (client, stream)
}

fn small_inbox() -> Tuning {
    Tuning {
        inbox: 16 << 10,
        ..Tuning::default()
    }
}

/// A connection that takes nothing written to it while the session has
/// stopped reading it, for a full inbox, ends the session after the write
/// stall timeout, though the stall timer resets the stream and reading
/// starts again: neither end reading, a TCP connection may never move
/// again.
#[tokio::test(start_paused = true)]
async fn a_connection_that_takes_nothing_while_not_read_ends_the_session() {
    let tuning = small_inbox();
    let start = tokio::time::Instant::now();
    let (client, _stream) = stuck_session(None, true, tuning).await;
    tokio::time::sleep_until(start + tuning.write_stall - Duration::from_secs(10)).await;
    assert!(!client.is_closed(), "ended before the write stall timeout");
    tokio::time::sleep_until(start + tuning.write_stall + Duration::from_secs(10)).await;
    assert!(
        client.is_closed(),
        "still open past the write stall timeout"
    );
    let Err(err) = client.open() else {
        panic!("a stream opened on the session ended");
    };
    assert!(err.to_string().contains("write timed out"), "{}", err);
}

/// A session goes on with a connection that takes nothing while its
/// reader does not stop, or that takes what it is given slowly while the
/// reader has stopped.
#[tokio::test(start_paused = true)]
async fn a_slow_connection_or_one_still_read_keeps_the_session() {
    let tuning = small_inbox();
    let (unpaused, _a) = stuck_session(None, false, tuning).await;
    // Paused throughout: the stream is never reset for stalling.
    let paused = Tuning {
        stall_timeout: Duration::from_secs(3600),
        ..tuning
    };
    let slow = Some(tuning.write_stall / 3);
    let (slowly, _b) = stuck_session(slow, true, paused).await;
    tokio::time::sleep(tuning.write_stall * 3).await;
    assert!(!unpaused.is_closed(), "ended while still reading");
    assert!(!slowly.is_closed(), "ended while writes moved");
}
