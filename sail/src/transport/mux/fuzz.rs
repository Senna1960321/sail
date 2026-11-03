//! Fuzzing (sail::fuzzing): what a sing-mux peer sends.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::FutureExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::transport::muxcore::{Codec, Decoder, Session, Tuning};

use super::server::{read_stream, Server};
use super::{read_request, read_status, smux::Smux, yamux::Yamux, StreamRequest};

/// Feeds `data` to `decoder` in pieces of `step`, as a connection gives
/// it, until it fails. A frame gives a few events at most: the bound only
/// stops a decoder that would give them for ever.
pub(crate) fn decode_all(decoder: &mut dyn Decoder, data: &[u8], step: usize) {
    let mut buf = BytesMut::new();
    'feed: for chunk in data.chunks(step) {
        buf.extend_from_slice(chunk);
        for _ in 0..chunk.len() + 64 {
            match decoder.decode(&mut buf) {
                Ok(Some(_)) => {}
                Ok(None) => continue 'feed,
                Err(_) => break 'feed,
            }
        }
        panic!("the decoder gives events without end");
    }
}

/// The requests a mux connection and its streams open with, a stream's
/// status, smux's and yamux's frames at each end, and amux's.
pub(crate) fn frames(data: &[u8]) {
    let _ = read_request(&mut &data[..]).now_or_never();
    let _ = read_status(&mut &data[..]).now_or_never();
    if let Some(Ok(request)) = StreamRequest::read(&mut &data[..]).now_or_never() {
        let mut wire = BytesMut::new();
        request.encode(&mut wire);
        let again = StreamRequest::read(&mut &wire[..]).now_or_never();
        assert!(
            matches!(again, Some(Ok(ref r)) if *r == request),
            "a stream request read back otherwise"
        );
    }
    let step = 1 + usize::from(data.first().copied().unwrap_or(0) % 97);
    let codecs: [Arc<dyn Codec>; 2] = [Arc::new(Smux), Arc::new(Yamux)];
    for codec in codecs {
        for server in [false, true] {
            decode_all(&mut *codec.decoder(server), data, step);
        }
    }
    #[cfg(any(feature = "inbound-amux", feature = "outbound-amux"))]
    crate::transport::amux::fuzz_frames(data, step);
}

/// A whole session against a peer that sends `data`'s rest: by its first
/// byte, a sing-mux server (what an inbound serves: the request, padding,
/// smux, yamux or h2mux, and each stream's request), or a client session
/// of smux or yamux that opens streams. The peer writes in pieces, reads
/// whatever comes back, and then leaves or stays. Time is paused, so the
/// session's timers (stalls, idle, pings) come at once; a session must
/// end once its peer has left.
pub(crate) fn session(data: &[u8]) {
    let Some((&selector, wire)) = data.split_first() else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("a runtime");
    // A session's tasks go through an instance's scope, as an inbound's do.
    let scope = crate::runtime::scope::TaskScope::new(Default::default());
    runtime.block_on(scope.enter(async {
        let (ours, peer) = tokio::io::duplex(64 << 10);
        let step = 1 + usize::from(selector >> 3);
        let stays = selector & 4 != 0;
        let peer = async move {
            let (mut read, mut write) = tokio::io::split(peer);
            let drain = async move {
                let mut buffer = vec![0; 64 << 10];
                while matches!(read.read(&mut buffer).await, Ok(n) if n > 0) {}
            };
            let send = async move {
                for chunk in wire.chunks(step) {
                    if write.write_all(chunk).await.is_err() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
                if stays {
                    tokio::time::sleep(Duration::from_secs(600)).await;
                }
                let _ = write.shutdown().await;
            };
            tokio::join!(drain, send);
        };
        let ours = async move {
            let tuning = Tuning::default();
            if selector & 1 == 0 {
                let Ok(mut server) = Server::start(Box::new(ours), tuning, "fuzz").await else {
                    return;
                };
                let mut streams = FuturesUnordered::new();
                loop {
                    tokio::select! {
                        stream = server.accept() => {
                            let Some(stream) = stream else { break };
                            streams.push(async move {
                                if let Ok((_, mut stream)) = read_stream(stream).await {
                                    let mut buffer = [0; 4096];
                                    let _ = stream.read(&mut buffer).await;
                                    let _ = stream.write_all(b"served").await;
                                }
                            });
                        }
                        Some(()) = streams.next(), if !streams.is_empty() => {}
                    }
                }
                while streams.next().await.is_some() {}
            } else {
                let codec: Arc<dyn Codec> = if selector & 2 == 0 {
                    Arc::new(Smux)
                } else {
                    Arc::new(Yamux)
                };
                let (session, _) = Session::new(ours, codec, false, tuning, "fuzz");
                let mut streams = FuturesUnordered::new();
                for _ in 0..3 {
                    if let Ok(mut stream) = session.open_with(b"request").await {
                        streams.push(async move {
                            let mut buffer = [0; 4096];
                            let _ = stream.read(&mut buffer).await;
                            let _ = stream.shutdown().await;
                        });
                    }
                }
                while streams.next().await.is_some() {}
                while !session.is_closed() {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        };
        let ended = tokio::time::timeout(Duration::from_secs(3_600), async {
            tokio::join!(peer, ours);
        })
        .await;
        assert!(ended.is_ok(), "a session outlived its peer by an hour");
    }));
}
