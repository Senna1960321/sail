//! DNS over TLS (RFC 7858), with RFC 7766 pipelining. One reader dispatches
//! replies by a connection-local ID; one writer owns framing even when a
//! caller is cancelled halfway through a write.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tracing::debug;

use super::{kept_timed_out, kept_wait, Upstream, IDLE_TIMEOUT};
use crate::adapter::AnyStream;
use crate::app::dns::DnsClient;

// Normally all queries use one connection. Retired connections may still
// have queries after close_idle, an ID rollover, or a retry on a fresh
// connection. Count those too, not just the connection kept in the pool.
const MAX_CONNECTIONS: usize = 4;
const MAX_IN_FLIGHT: usize = 64;

pub(super) struct Pool {
    state: AsyncMutex<PoolState>,
    dialing: AsyncMutex<()>,
    generation: watch::Sender<u64>,
    connections: Arc<Semaphore>,
    queries: Semaphore,
}

#[derive(Default)]
struct PoolState {
    kept: Option<Arc<Connection>>,
    live: Vec<Weak<Connection>>,
}

impl PoolState {
    fn retire(&mut self, failed: &Weak<Connection>) {
        // A concurrent query (or a network reset) may already have replaced
        // this connection. A late timeout must not retire its replacement.
        if self
            .kept
            .as_ref()
            .is_some_and(|connection| Weak::ptr_eq(&Arc::downgrade(connection), failed))
        {
            self.kept = None;
        }
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            state: AsyncMutex::new(PoolState::default()),
            dialing: AsyncMutex::new(()),
            generation: watch::channel(0).0,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            queries: Semaphore::new(MAX_IN_FLIGHT),
        }
    }
}

type Answer = std::result::Result<Vec<u8>, String>;

struct Pending {
    original_id: [u8; 2],
    response: oneshot::Sender<Answer>,
}

struct Shared {
    pending: HashMap<u16, Pending>,
    // All queries in a batch share its origin: a fresh pipeline must not
    // become an idle-connection probe merely because a sibling joined it.
    probing: bool,
    // IDs are never reused on a connection. A late reply to a cancelled
    // query therefore cannot be mistaken for a new query with that ID.
    next_id: u32,
    closed: bool,
    used: Instant,
}

struct Connection {
    shared: Arc<Mutex<Shared>>,
    send: mpsc::Sender<(u16, Vec<u8>)>,
    driver: tokio::task::AbortHandle,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

// Also runs on task cancellation, including a reset before the task was
// first polled. Wake every waiter and release the live-connection slot.
struct DriverLife {
    shared: Arc<Mutex<Shared>>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for DriverLife {
    fn drop(&mut self) {
        let mut state = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        for (_, pending) in state.pending.drain() {
            let _ = pending.response.send(Err("DoT connection closed".into()));
        }
    }
}

impl Connection {
    fn new(stream: AnyStream, permit: OwnedSemaphorePermit, write_timeout: Duration) -> Arc<Self> {
        let shared = Arc::new(Mutex::new(Shared {
            pending: HashMap::new(),
            probing: false,
            next_id: 0,
            closed: false,
            used: Instant::now(),
        }));
        let (send, mut receive) = mpsc::channel::<(u16, Vec<u8>)>(MAX_IN_FLIGHT);
        let life = DriverLife {
            shared: shared.clone(),
            _permit: permit,
        };
        let state = shared.clone();
        let task = crate::runtime::scope::spawn("dns tls connection", async move {
            let _life = life;
            let (mut reader, mut writer) = tokio::io::split(stream);
            let read = async {
                loop {
                    let len = reader.read_u16().await? as usize;
                    if len < 12 {
                        return Err::<(), _>(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "short DNS response",
                        ));
                    }
                    let mut response = vec![0; len];
                    reader.read_exact(&mut response).await?;
                    let id = u16::from_be_bytes([response[0], response[1]]);
                    let pending = {
                        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                        state.used = Instant::now();
                        state.pending.remove(&id)
                    };
                    if let Some(pending) = pending {
                        response[..2].copy_from_slice(&pending.original_id);
                        let _ = pending.response.send(Ok(response));
                    }
                    // Unknown IDs include replies to cancelled queries.
                }
            };
            let write = async {
                while let Some((id, request)) = receive.recv().await {
                    if !state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .pending
                        .contains_key(&id)
                    {
                        continue;
                    }
                    timeout(write_timeout, async {
                        writer.write_all(&request).await?;
                        writer.flush().await
                    })
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "DoT write timed out")
                    })??;
                }
                Ok::<(), std::io::Error>(())
            };
            if let Err(error) = tokio::try_join!(read, write) {
                debug!("DoT connection ended: {error}");
            }
        });
        Arc::new(Self {
            shared,
            send,
            driver: task.abort_handle(),
        })
    }

    fn reserve(self: &Arc<Self>, request: &[u8], kept: bool) -> Option<Query> {
        let mut state = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed
            || self.driver.is_finished()
            || state.next_id > u16::MAX as u32
            || (state.pending.is_empty() && state.used.elapsed() >= IDLE_TIMEOUT)
        {
            return None;
        }
        if state.pending.is_empty() {
            state.probing = kept;
        }
        let id = state.next_id as u16;
        state.next_id += 1;
        let (send, response) = oneshot::channel();
        state.pending.insert(
            id,
            Pending {
                original_id: [request[0], request[1]],
                response: send,
            },
        );
        let mut framed = Vec::with_capacity(request.len() + 2);
        framed.extend_from_slice(&(request.len() as u16).to_be_bytes());
        framed.extend_from_slice(&id.to_be_bytes());
        framed.extend_from_slice(&request[2..]);
        Some(Query {
            connection: self.clone(),
            probing: state.probing,
            id,
            request: Some(framed),
            response,
        })
    }
}

struct Query {
    connection: Arc<Connection>,
    probing: bool,
    id: u16,
    request: Option<Vec<u8>>,
    response: oneshot::Receiver<Answer>,
}

impl Query {
    async fn exchange(mut self) -> Result<Vec<u8>> {
        self.connection
            .send
            .send((self.id, self.request.take().unwrap()))
            .await
            .map_err(|_| anyhow!("DoT writer closed"))?;
        (&mut self.response)
            .await
            .map_err(|_| anyhow!("DoT reader closed"))?
            .map_err(|e| anyhow!(e))
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        let mut state = self
            .connection
            .shared
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state.pending.remove(&self.id);
        state.used = Instant::now();
    }
}

impl Pool {
    pub(super) async fn clear(&self) {
        let mut state = self.state.lock().await;
        // Cancel connection-slot waits and handshakes too. Neither holds
        // the state lock, so a dead network cannot delay its own reset.
        self.generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        for connection in state.live.drain(..).filter_map(|c| c.upgrade()) {
            connection.driver.abort();
        }
        state.kept = None;
    }

    pub(super) async fn close_idle(&self) {
        // Active queries keep their connection until they finish.
        self.state.lock().await.kept = None;
    }

    async fn retire(&self, failed: &Weak<Connection>) {
        self.state.lock().await.retire(failed);
    }

    async fn query(
        &self,
        client: &DnsClient,
        upstream: &Upstream,
        addr: SocketAddr,
        request: &[u8],
        failed: Option<&Weak<Connection>>,
    ) -> Result<(Query, bool)> {
        let mut generation = self.generation.subscribe();
        let started = *generation.borrow();
        let connect = async {
            // Only creation is serialised. In particular clear() must not
            // wait for a connection permit or a peer's TLS handshake.
            let _dialing = self.dialing.lock().await;
            {
                let mut state = self.state.lock().await;
                if let Some(failed) = failed {
                    state.retire(failed);
                }
                if let Some(query) = state.kept.as_ref().and_then(|c| c.reserve(request, true)) {
                    let probing = query.probing;
                    return Ok((query, probing));
                }
                state.kept = None;
                state.live.retain(|c| c.strong_count() != 0);
            }
            let permit = self.connections.clone().acquire_owned().await?;
            let stream = client.dial_stream(&upstream.dialer, addr).await?;
            let stream: AnyStream = Box::new(
                upstream
                    .tls_client()?
                    .connect(&upstream.server_name, stream, None, None)
                    .await
                    .map_err(|e| anyhow!("tls handshake failed: {}", e))?,
            );
            let mut state = self.state.lock().await;
            // A reset could win just as the handshake completed. Never
            // insert that old network's connection into the new pool.
            if *self.generation.borrow() != started {
                return Err(anyhow!("DoT network changed"));
            }
            let connection = Connection::new(stream, permit, client.timeout);
            let query = connection
                .reserve(request, false)
                .ok_or_else(|| anyhow!("DoT connection closed"))?;
            state.live.push(Arc::downgrade(&connection));
            state.kept = Some(connection);
            Ok((query, false))
        };
        tokio::select! {
            biased;
            _ = generation.changed() => Err(anyhow!("DoT network changed")),
            result = connect => result,
        }
    }
}

impl DnsClient {
    pub(super) async fn exchange_dot(
        &self,
        upstream: &Upstream,
        pool: &Pool,
        addr: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        if !(12..=u16::MAX as usize).contains(&request.len()) {
            return Err(anyhow!("invalid DNS query length"));
        }
        // Subscribe before waiting for the query quota. A reset cancels
        // every pre-reset exchange, including queued queries and retries,
        // rather than letting them create work on the new network.
        let mut generation = pool.generation.subscribe();
        tokio::select! {
            biased;
            _ = generation.changed() => Err(anyhow!("DoT network changed")),
            result = self.exchange_dot_on_network(upstream, pool, addr, request) => result,
        }
    }

    async fn exchange_dot_on_network(
        &self,
        upstream: &Upstream,
        pool: &Pool,
        addr: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let _slot = pool.queries.acquire().await?;
        let wait = kept_wait(self.reused_connection_timeout());
        let (query, probing) = pool.query(self, upstream, addr, request, None).await?;
        // A sequential fresh attempt has its full outer budget. Another
        // waiter may already have opened its replacement; share that one.
        // Every query joining a fresh pipeline keeps its normal deadline.
        if !probing || wait.is_none() {
            return query.exchange().await;
        }
        let failed = Arc::downgrade(&query.connection);
        match timeout(
            wait.expect("reused connection has a timeout"),
            query.exchange(),
        )
        .await
        {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(e)) => debug!("{}: kept connection failed: {}", upstream, e),
            Err(_) => {
                debug!("{}: kept connection timed out", upstream);
                if kept_timed_out() {
                    // Retire this connection before yielding to the outer
                    // retry. Its siblings must not each discard the fresh
                    // replacement when their own retry starts.
                    pool.retire(&failed).await;
                    return Err(anyhow!("{}: kept connection timed out", upstream));
                }
            }
        }
        // Another query may already have replaced this failed connection.
        // Its replacement can be used; do not open one retry per waiter.
        let (query, _) = pool
            .query(self, upstream, addr, request, Some(&failed))
            .await?;
        query.exchange().await
    }
}
