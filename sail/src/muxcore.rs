//! Streams over one connection, for a host that runs links of its own:
//! sail's stream multiplexer, the one its yamux, smux, amux and AnyTLS are
//! built on (feature `muxcore`).
//!
//! A [`Session`] runs over any `AsyncRead + AsyncWrite`: a client opens
//! streams on it, a server accepts them ([`Incoming`]). A stream reset or
//! dropped early is reset alone and its session goes on; no more than
//! [`MAX_UNACKED`] streams the peer has not acknowledged are open at once,
//! as hashicorp/yamux takes them; every buffer is bounded. docs/embed.md
//! says what holds.
//!
//! What only grows here, as in `sail::embed`: the types (`non_exhaustive`)
//! and the functions. A break raises the minor version before 1.0, and is
//! in the release notes.
//!
//! ```
//! use sail::muxcore::{Config, Protocol, Session};
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> std::io::Result<()> {
//! let (near, far) = tokio::io::duplex(64 << 10);
//!
//! // The server echoes each stream it accepts.
//! let (_server, mut incoming) = Session::server(far, Config::new(Protocol::Yamux));
//! tokio::spawn(async move {
//!     while let Some(mut stream) = incoming.accept().await {
//!         tokio::spawn(async move {
//!             let mut data = Vec::new();
//!             stream.read_to_end(&mut data).await?;
//!             stream.write_all(&data).await?;
//!             stream.shutdown().await
//!         });
//!     }
//! });
//!
//! let client = Session::client(near, Config::new(Protocol::Yamux).label("node-2"));
//! let mut stream = client.open().await?;
//! stream.write_all(b"ping").await?;
//! stream.shutdown().await?;
//! let mut echoed = Vec::new();
//! stream.read_to_end(&mut echoed).await?;
//! assert_eq!(echoed, b"ping");
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::runtime::options::{Profile, RuntimeOptions};
use crate::transport::muxcore::{yamux::Yamux, Codec, Tuning};

pub use crate::transport::muxcore::{Session, Stream, INITIAL_WINDOW, MAX_STREAMS, MAX_UNACKED};

/// The protocol a session speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Protocol {
    /// yamux, as hashicorp/yamux speaks it: windows of `INITIAL_WINDOW`
    /// that grow as a stream is read, half-close, and streams acknowledged
    /// as the peer accepts them.
    Yamux,
}

impl Protocol {
    fn codec(self) -> Arc<dyn Codec> {
        match self {
            Protocol::Yamux => Arc::new(Yamux),
        }
    }
}

/// How a session runs: `Config::new(protocol)`, then its setters.
#[derive(Debug, Clone)]
pub struct Config {
    protocol: Protocol,
    tuning: Tuning,
    label: Arc<str>,
}

impl Config {
    /// `protocol` as sail's desktop profile runs it: windows that grow to
    /// 16 MiB, streams reset after 60 s with data nothing reads.
    pub fn new(protocol: Protocol) -> Self {
        Config {
            protocol,
            tuning: Tuning::from(&RuntimeOptions::profile(Profile::Desktop)),
            label: Arc::from("host"),
        }
    }

    /// The largest a stream's receive window grows to: what one stream
    /// may hold unread, and how fast it goes over a long link. No less
    /// than `INITIAL_WINDOW`.
    pub fn window_max(mut self, bytes: u32) -> Self {
        self.tuning.window_max = bytes.max(INITIAL_WINDOW);
        self
    }

    /// A stream whose received data nothing reads for this long is reset,
    /// alone, so that it holds up neither the session nor its memory. No
    /// less than a second.
    pub fn stall_timeout(mut self, timeout: Duration) -> Self {
        self.tuning.stall_timeout = timeout.max(Duration::from_secs(1));
        self
    }

    /// Who the session serves, in sail's logs: `host` by default.
    pub fn label(mut self, label: &str) -> Self {
        self.label = Arc::from(label);
        self
    }
}

/// The streams a server's peer opens, in the order it opens them.
pub struct Incoming(mpsc::UnboundedReceiver<Stream>);

impl Incoming {
    /// The next stream the peer opens; `None` once the session has ended
    /// or its `Session` was dropped.
    pub async fn accept(&mut self) -> Option<Stream> {
        self.0.recv().await
    }
}

impl Session {
    /// A client's session over `conn`, which opens streams. Its task runs
    /// on the current tokio runtime, the host's, until the connection ends,
    /// `close()`, or the last of its streams is done once it is dropped.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime with I/O and timers enabled.
    pub fn client<S>(conn: S, config: Config) -> Session
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        Self::host(conn, config, false).0
    }

    /// A server's session over `conn`, and the streams its peer opens. Its
    /// task runs as a client's does.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime with I/O and timers enabled.
    pub fn server<S>(conn: S, config: Config) -> (Session, Incoming)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (session, accept) = Self::host(conn, config, true);
        let accept = accept.expect("a server's session gets the streams its peer opens");
        (session, Incoming(accept))
    }

    fn host<S>(
        conn: S,
        config: Config,
        server: bool,
    ) -> (Session, Option<mpsc::UnboundedReceiver<Stream>>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (session, accept, driver) = Self::start(
            conn,
            config.protocol.codec(),
            server,
            config.tuning,
            config.label,
        );
        // The host's session, not an instance's: no instance's stop is to
        // end it.
        #[allow(clippy::disallowed_methods)]
        tokio::spawn(driver);
        (session, accept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn a_server_accepts_what_a_client_opens_until_the_client_goes() {
        let (near, far) = tokio::io::duplex(64 << 10);
        let (_server, mut incoming) = Session::server(far, Config::new(Protocol::Yamux));
        let client = Session::client(near, Config::new(Protocol::Yamux));
        let mut opened = client.open().await.unwrap();
        opened.write_all(b"one").await.unwrap();
        let mut accepted = incoming.accept().await.unwrap();
        let mut got = [0u8; 3];
        accepted.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"one");
        drop(opened);
        drop(accepted);
        client.close();
        assert!(incoming.accept().await.is_none());
    }

    #[test]
    fn a_config_keeps_windows_and_stalls_within_bounds() {
        let config = Config::new(Protocol::Yamux)
            .window_max(1)
            .stall_timeout(Duration::ZERO);
        assert_eq!(config.tuning.window_max, INITIAL_WINDOW);
        assert_eq!(config.tuning.stall_timeout, Duration::from_secs(1));
    }
}
