use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use futures::channel::{mpsc, oneshot};
use futures::{Sink, Stream};
use sail_netstack::{BudgetLease, NetworkGeneration, StackStats, TcpFlowToken, UdpFlowToken};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc as tokio_mpsc, Notify};

use super::runtime::NativeConnection;

/// What a read brings: the bytes, and the budget's charge for those beyond
/// what was asked for, held while the stream keeps them.
pub(super) type ReadReply = io::Result<(Vec<u8>, Option<BudgetLease>)>;

pub(super) enum TcpCommand {
    Read {
        token: TcpFlowToken,
        max_bytes: usize,
        response: oneshot::Sender<ReadReply>,
    },
    ReserveWrite {
        token: TcpFlowToken,
        max_bytes: usize,
        response: oneshot::Sender<io::Result<usize>>,
    },
    CommitWrite {
        token: TcpFlowToken,
        payload: Vec<u8>,
        response: oneshot::Sender<io::Result<usize>>,
    },
    Close {
        token: TcpFlowToken,
        response: oneshot::Sender<io::Result<()>>,
    },
    UdpReply {
        token: UdpFlowToken,
        source: SocketAddr,
        payload: Vec<u8>,
        response: oneshot::Sender<io::Result<()>>,
    },
    Shutdown {
        grace_period_ms: u64,
        response: oneshot::Sender<()>,
    },
    ControlAbort {
        response: oneshot::Sender<()>,
    },
    ResetNetwork {
        generation: NetworkGeneration,
        response: oneshot::Sender<()>,
    },
    UpdateMtu {
        mtu: usize,
        response: oneshot::Sender<Result<(), sail_netstack::RunnerError>>,
    },
    StatsSnapshot {
        response: oneshot::Sender<StackStats>,
    },
    #[cfg(feature = "internal-diagnostics")]
    FlowSamples {
        response: oneshot::Sender<Vec<sail_netstack::tcp::TcpFlowSample>>,
    },
    Connect {
        local: SocketAddr,
        remote: SocketAddr,
        response: oneshot::Sender<io::Result<NativeConnection>>,
    },
    UdpOriginate {
        local: SocketAddr,
        remote: SocketAddr,
        payload: Vec<u8>,
        response: oneshot::Sender<io::Result<(UdpFlowToken, SocketAddr)>>,
    },
}

pub(crate) struct NativeTcpStream {
    token: TcpFlowToken,
    commands: mpsc::Sender<TcpCommand>,
    cleanup: tokio_mpsc::Sender<TcpFlowToken>,
    cleanup_overflow: Arc<Notify>,
    cleanup_active: Arc<AtomicBool>,
    /// What the last read brought that the caller had no room for, from
    /// `read_offset` on. Bytes go straight from it to the caller's buffer:
    /// a queue in between copied every byte once more.
    read_buffer: Vec<u8>,
    read_offset: usize,
    /// The budget's charge for the bytes read ahead, no more than are left
    /// in `read_buffer`.
    read_ahead: Option<BudgetLease>,
    pending_read: Option<oneshot::Receiver<ReadReply>>,
    pending_write_reservation: Option<oneshot::Receiver<io::Result<usize>>>,
    write_reservation: Option<usize>,
    pending_write_completion: Option<oneshot::Receiver<io::Result<usize>>>,
    pending_close: Option<oneshot::Receiver<io::Result<()>>>,
    eof: bool,
    closed: bool,
}

impl NativeTcpStream {
    pub(super) fn new(
        token: TcpFlowToken,
        commands: mpsc::Sender<TcpCommand>,
        cleanup: tokio_mpsc::Sender<TcpFlowToken>,
        cleanup_overflow: Arc<Notify>,
        cleanup_active: Arc<AtomicBool>,
    ) -> Self {
        Self {
            token,
            commands,
            cleanup,
            cleanup_overflow,
            cleanup_active,
            read_buffer: Vec::new(),
            read_offset: 0,
            read_ahead: None,
            pending_read: None,
            pending_write_reservation: None,
            write_reservation: None,
            pending_write_completion: None,
            pending_close: None,
            eof: false,
            closed: false,
        }
    }

    fn poll_command_ready(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.commands)
            .poll_ready(context)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TCP runner stopped"))
    }

    fn start_command(&mut self, command: TcpCommand) -> io::Result<()> {
        Pin::new(&mut self.commands)
            .start_send(command)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "TCP runner stopped"))
    }

    fn copy_read_buffer(&mut self, buffer: &mut ReadBuf<'_>) {
        let rest = &self.read_buffer[self.read_offset..];
        let amount = buffer.remaining().min(rest.len());
        buffer.put_slice(&rest[..amount]);
        self.read_offset += amount;
        let left = self.read_buffer.len() - self.read_offset;
        if let Some(lease) = &mut self.read_ahead {
            if lease.amount() > left {
                lease.shrink_to(left);
            }
        }
        if left == 0 {
            self.read_buffer = Vec::new();
            self.read_offset = 0;
            self.read_ahead = None;
        }
    }

    fn cancelled() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "TCP runner dropped response")
    }

    #[cfg(test)]
    pub(super) fn saturate_command_channel_for_test(&mut self) {
        let (response, _receiver) = oneshot::channel();
        self.commands
            .try_send(TcpCommand::StatsSnapshot { response })
            .expect("test command channel should have one free slot");
    }
}

pub(super) fn command_channel(
    capacity: usize,
) -> (mpsc::Sender<TcpCommand>, mpsc::Receiver<TcpCommand>) {
    assert!(capacity > 0, "TCP command capacity must be non-zero");
    mpsc::channel(capacity)
}

impl AsyncRead for NativeTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_offset < self.read_buffer.len() {
            self.copy_read_buffer(buffer);
            return Poll::Ready(Ok(()));
        }
        if self.eof || buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(response) = &mut self.pending_read {
            let (bytes, lease) =
                ready!(Pin::new(response).poll(context)).map_err(|_| Self::cancelled())??;
            self.pending_read = None;
            if bytes.is_empty() {
                self.eof = true;
                return Poll::Ready(Ok(()));
            }
            self.read_buffer = bytes;
            self.read_offset = 0;
            self.read_ahead = lease;
            self.copy_read_buffer(buffer);
            return Poll::Ready(Ok(()));
        }
        ready!(self.poll_command_ready(context))?;
        let (response, receiver) = oneshot::channel();
        let max_bytes = buffer.remaining().max(1);
        let token = self.token;
        self.start_command(TcpCommand::Read {
            token,
            max_bytes,
            response,
        })?;
        self.pending_read = Some(receiver);
        // Polling the reply registers this task for it: waking itself
        // instead cost a reschedule per read, and with more than one
        // worker often a futex to wake another.
        self.poll_read(context, buffer)
    }
}

impl AsyncWrite for NativeTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP stream is closed",
            )));
        }
        // The last commit's result is taken when it is there, but the next
        // reservation does not wait for it: the runtime answers commands in
        // order, so it finds room only after that commit, and only the next
        // commit waits for it.
        if let Some(response) = &mut self.pending_write_completion {
            if let Poll::Ready(result) = Pin::new(response).poll(context) {
                self.pending_write_completion = None;
                result.map_err(|_| Self::cancelled())??;
            }
        }
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(response) = &mut self.pending_write_reservation {
            let amount =
                ready!(Pin::new(response).poll(context)).map_err(|_| Self::cancelled())??;
            self.pending_write_reservation = None;
            self.write_reservation = Some(amount);
        }
        if let Some(reserved) = self.write_reservation {
            if let Some(response) = &mut self.pending_write_completion {
                ready!(Pin::new(response).poll(context)).map_err(|_| Self::cancelled())??;
                self.pending_write_completion = None;
            }
            ready!(self.poll_command_ready(context))?;
            let amount = buffer.len().min(reserved);
            let (response, receiver) = oneshot::channel();
            let token = self.token;
            self.start_command(TcpCommand::CommitWrite {
                token,
                payload: buffer[..amount].to_vec(),
                response,
            })?;
            self.write_reservation = None;
            self.pending_write_completion = Some(receiver);
            return Poll::Ready(Ok(amount));
        }
        ready!(self.poll_command_ready(context))?;
        // As much as the caller has: the runtime grants what the windows
        // allow, and the stack cuts it into segments.
        let amount = buffer.len();
        let (response, receiver) = oneshot::channel();
        let token = self.token;
        self.start_command(TcpCommand::ReserveWrite {
            token,
            max_bytes: amount,
            response,
        })?;
        self.pending_write_reservation = Some(receiver);
        // As for a read: the reply wakes it.
        self.poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(response) = &mut self.pending_write_completion {
            ready!(Pin::new(response).poll(context)).map_err(|_| Self::cancelled())??;
            self.pending_write_completion = None;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(context))?;
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        if let Some(response) = &mut self.pending_close {
            let result = ready!(Pin::new(response).poll(context)).map_err(|_| Self::cancelled())?;
            self.pending_close = None;
            self.closed = result.is_ok();
            return Poll::Ready(result);
        }
        ready!(self.poll_command_ready(context))?;
        let (response, receiver) = oneshot::channel();
        let token = self.token;
        self.start_command(TcpCommand::Close { token, response })?;
        self.pending_close = Some(receiver);
        self.poll_shutdown(context)
    }
}

impl Drop for NativeTcpStream {
    /// Tells the runtime the stream is gone: one closed first is let go of,
    /// to finish its close alone; any other is aborted.
    fn drop(&mut self) {
        if self.cleanup_active.swap(false, Ordering::AcqRel) {
            match self.cleanup.try_send(self.token) {
                Ok(()) | Err(tokio_mpsc::error::TrySendError::Closed(_)) => {}
                Err(tokio_mpsc::error::TrySendError::Full(_)) => {
                    // The bounded O(1) path is saturated. Notify coalesces
                    // overflow into constant memory; the owner scans its
                    // hard-budgeted flow table once after waking.
                    self.cleanup_overflow.notify_one();
                }
            }
        }
    }
}

pub(super) async fn next_command(commands: &mut mpsc::Receiver<TcpCommand>) -> Option<TcpCommand> {
    futures::future::poll_fn(|context| Pin::new(&mut *commands).poll_next(context)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use sail_netstack::{FlowId, NetworkGeneration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{timeout, Duration};

    fn pair() -> (NativeTcpStream, mpsc::Receiver<TcpCommand>) {
        let (sender, receiver) = command_channel(1);
        let (cleanup, _cleanup_rx) = tokio_mpsc::channel(1);
        let cleanup_overflow = Arc::new(Notify::new());
        (
            NativeTcpStream::new(
                TcpFlowToken::new(FlowId::new(7), NetworkGeneration::new(3)),
                sender,
                cleanup,
                cleanup_overflow,
                Arc::new(AtomicBool::new(true)),
            ),
            receiver,
        )
    }

    #[tokio::test]
    async fn bounded_bridge_drives_read_write_and_shutdown() {
        let (mut stream, mut commands) = pair();
        let application = tokio::spawn(async move {
            let mut read = [0_u8; 8];
            let count = stream.read(&mut read).await.unwrap();
            assert_eq!(&read[..count], b"hello");
            assert_eq!(stream.write(b"abcdef").await.unwrap(), 4);
            stream.shutdown().await.unwrap();
        });

        match next_command(&mut commands).await.unwrap() {
            TcpCommand::Read {
                max_bytes,
                response,
                ..
            } => {
                assert_eq!(max_bytes, 8);
                response.send(Ok((b"hello".to_vec(), None))).unwrap();
            }
            _ => panic!("expected read command"),
        }
        match next_command(&mut commands).await.unwrap() {
            TcpCommand::ReserveWrite {
                max_bytes,
                response,
                ..
            } => {
                // The whole buffer is asked for; the grant bounds the write.
                assert_eq!(max_bytes, 6);
                response.send(Ok(4)).unwrap();
            }
            _ => panic!("expected write reservation command"),
        }
        match next_command(&mut commands).await.unwrap() {
            TcpCommand::CommitWrite {
                payload, response, ..
            } => {
                assert_eq!(payload, b"abcd");
                response.send(Ok(payload.len())).unwrap();
            }
            _ => panic!("expected write command"),
        }
        match next_command(&mut commands).await.unwrap() {
            TcpCommand::Close { response, .. } => response.send(Ok(())).unwrap(),
            _ => panic!("expected close command"),
        }
        application.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_write_never_commits_the_cancelled_buffer() {
        let (mut stream, mut commands) = pair();

        assert!(stream.write(b"old").now_or_never().is_none());
        match next_command(&mut commands).await.unwrap() {
            TcpCommand::ReserveWrite {
                max_bytes,
                response,
                ..
            } => {
                assert_eq!(max_bytes, 3);
                response.send(Ok(max_bytes)).unwrap();
            }
            _ => panic!("expected write reservation command"),
        }

        assert_eq!(stream.write(b"x").await.unwrap(), 1);
        match next_command(&mut commands).await.unwrap() {
            TcpCommand::CommitWrite {
                payload, response, ..
            } => {
                assert_eq!(payload, b"x");
                response.send(Ok(payload.len())).unwrap();
            }
            _ => panic!("expected write commit command"),
        }
        stream.flush().await.unwrap();
    }

    #[tokio::test]
    async fn the_next_reservation_goes_before_the_last_commit_is_answered() {
        let (mut stream, mut commands) = pair();
        let application = tokio::spawn(async move {
            assert_eq!(stream.write(b"ab").await.unwrap(), 2);
            assert_eq!(stream.write(b"cd").await.unwrap(), 2);
            stream.flush().await.unwrap();
        });

        match next_command(&mut commands).await.unwrap() {
            TcpCommand::ReserveWrite { response, .. } => response.send(Ok(2)).unwrap(),
            _ => panic!("expected write reservation command"),
        }
        let first_commit = match next_command(&mut commands).await.unwrap() {
            TcpCommand::CommitWrite {
                payload, response, ..
            } => {
                assert_eq!(payload, b"ab");
                response
            }
            _ => panic!("expected write commit command"),
        };
        // The first commit is still unanswered.
        let second_reservation = match next_command(&mut commands).await.unwrap() {
            TcpCommand::ReserveWrite { response, .. } => response,
            _ => panic!("expected the second reservation before the first commit's answer"),
        };
        second_reservation.send(Ok(2)).unwrap();
        // The second commit waits for the first's answer.
        assert!(
            timeout(Duration::from_millis(50), next_command(&mut commands))
                .await
                .is_err()
        );
        first_commit.send(Ok(2)).unwrap();
        match next_command(&mut commands).await.unwrap() {
            TcpCommand::CommitWrite {
                payload, response, ..
            } => {
                assert_eq!(payload, b"cd");
                response.send(Ok(2)).unwrap();
            }
            _ => panic!("expected write commit command"),
        }
        application.await.unwrap();
    }

    #[tokio::test]
    async fn bytes_read_ahead_stay_charged_only_while_the_stream_holds_them() {
        use sail_netstack::{BudgetProfile, ResourceKind, ResourceLedger};
        let ledger = ResourceLedger::new(BudgetProfile::Mobile.budget()).unwrap();
        let held = || ledger.snapshot().used(ResourceKind::TcpPayloadBytes);
        let (mut stream, mut commands) = pair();
        let mut read = [0_u8; 4];
        let reading = tokio::spawn(async move {
            let count = stream.read(&mut read).await.unwrap();
            (stream, read, count)
        });
        match next_command(&mut commands).await.unwrap() {
            TcpCommand::Read {
                max_bytes,
                response,
                ..
            } => {
                assert_eq!(max_bytes, 4);
                // Ten bytes for a reader of four: six read ahead, charged.
                let lease = ledger
                    .try_acquire(ResourceKind::TcpPayloadBytes, 6)
                    .unwrap();
                response
                    .send(Ok((b"0123456789".to_vec(), Some(lease))))
                    .unwrap();
            }
            _ => panic!("expected read command"),
        }
        let (mut stream, read, count) = reading.await.unwrap();
        assert_eq!(&read[..count], b"0123");
        assert_eq!(held(), 6);
        let mut next = [0_u8; 3];
        assert_eq!(stream.read(&mut next).await.unwrap(), 3);
        assert_eq!(&next, b"456");
        assert_eq!(held(), 3);
        // Dropped with bytes still held: the charge goes with them.
        drop(stream);
        assert_eq!(held(), 0);
    }

    #[test]
    fn stream_meets_dispatcher_thread_safety_bounds() {
        fn assert_bounds<T: Send + Sync + Unpin>() {}
        assert_bounds::<NativeTcpStream>();
    }

    #[tokio::test]
    async fn drop_cleanup_bypasses_a_saturated_command_channel() {
        let token = TcpFlowToken::new(FlowId::new(7), NetworkGeneration::new(3));
        let (mut commands, _command_rx) = command_channel(1);
        let (cleanup, mut cleanup_rx) = tokio_mpsc::channel(1);
        let cleanup_overflow = Arc::new(Notify::new());
        let stream = NativeTcpStream::new(
            token,
            commands.clone(),
            cleanup,
            cleanup_overflow,
            Arc::new(AtomicBool::new(true)),
        );

        let (response, _receiver) = oneshot::channel();
        commands
            .try_send(TcpCommand::StatsSnapshot { response })
            .expect("test command queue should accept its first command");
        drop(stream);

        assert_eq!(cleanup_rx.recv().await, Some(token));
    }

    #[tokio::test]
    async fn stream_closed_by_runtime_does_not_signal_stale_cleanup() {
        let token = TcpFlowToken::new(FlowId::new(7), NetworkGeneration::new(3));
        let (commands, _command_rx) = command_channel(1);
        let (cleanup, mut cleanup_rx) = tokio_mpsc::channel(1);
        let cleanup_overflow = Arc::new(Notify::new());
        let active = Arc::new(AtomicBool::new(true));
        let stream = NativeTcpStream::new(
            token,
            commands,
            cleanup,
            Arc::clone(&cleanup_overflow),
            Arc::clone(&active),
        );

        active.store(false, Ordering::Release);
        drop(stream);

        assert!(matches!(
            cleanup_rx.try_recv(),
            Err(tokio_mpsc::error::TryRecvError::Empty
                | tokio_mpsc::error::TryRecvError::Disconnected)
        ));
        assert!(
            timeout(Duration::from_millis(1), cleanup_overflow.notified())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cleanup_queue_overflow_coalesces_into_a_bounded_wakeup() {
        let token = TcpFlowToken::new(FlowId::new(7), NetworkGeneration::new(3));
        let occupied = TcpFlowToken::new(FlowId::new(8), NetworkGeneration::new(3));
        let (commands, _command_rx) = command_channel(1);
        let (cleanup, _cleanup_rx) = tokio_mpsc::channel(1);
        cleanup.try_send(occupied).unwrap();
        let cleanup_overflow = Arc::new(Notify::new());
        let stream = NativeTcpStream::new(
            token,
            commands,
            cleanup,
            Arc::clone(&cleanup_overflow),
            Arc::new(AtomicBool::new(true)),
        );

        drop(stream);

        timeout(Duration::from_secs(1), cleanup_overflow.notified())
            .await
            .expect("full cleanup queue must trigger the bounded fallback wakeup");
    }
}
