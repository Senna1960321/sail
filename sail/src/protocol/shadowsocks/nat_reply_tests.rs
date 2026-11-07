//! NAT-to-inbound ownership regression. Uses the actual NAT downlink queue
//! and the production delivery helper, not a manually retained Received.
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use super::sip022::{udp, Method, User, Users};
use crate::adapter::InboundDatagramSendHalf;
use crate::app::nat_manager::UdpPacket;
use crate::control::events::EventHub;
use crate::runtime::RuntimeEnv;
use crate::session::{DatagramSource, SocksAddr};

struct PausedEncoder {
    server: Arc<udp::Server>,
    socket: Arc<UdpSocket>,
    entered: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<()>,
    fail: bool,
}

#[async_trait]
impl InboundDatagramSendHalf for PausedEncoder {
    async fn send_to(
        &mut self,
        data: &[u8],
        from: &SocksAddr,
        to: &SocketAddr,
    ) -> io::Result<usize> {
        self.entered.take().unwrap().send(()).unwrap();
        (&mut self.release)
            .await
            .map_err(|_| io::ErrorKind::Interrupted)?;
        if self.fail {
            return Err(io::Error::other("socket send failed"));
        }
        let wire = self.server.encode(*to, from, data)?;
        self.socket.send_to(&wire, to).await?;
        Ok(data.len())
    }
    async fn close(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum Finish {
    Sent,
    Failed,
    Cancelled,
    QueueDropped,
}

async fn bounded<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("event handshake timed out")
}

async fn queued_reply(finish: Finish, with_context: bool) {
    let method = Method::Aes128Gcm;
    let identity = vec![0x11; 16];
    let old_key = vec![0x22; 16];
    let new_key = vec![0x33; 16];
    let encode_key = |key: &[u8]| base64::engine::general_purpose::STANDARD.encode(key);
    let config = crate::config::Config::from_json(
        &serde_json::json!({
            "inbounds": [{"type":"shadowsocks", "tag":"in", "listen":"127.0.0.1", "listen_port":0,
                "method":"2022-blake3-aes-128-gcm", "password":encode_key(&identity),
                "users":[{"name":"alice","password":encode_key(&old_key)},
                         {"name":"alice","password":encode_key(&new_key)}]}],
            "outbounds": [{"type":"direct", "tag":"direct"}]
        })
        .to_string(),
    )
    .unwrap();
    let events = EventHub::with_records(16, Some(16));
    let admission = if with_context {
        use crate::app::inbound::admission::{Admission, HostHooks, HostHooksRef};
        let rows = crate::control::context::ContextPool::new(8);
        let sessions = crate::control::context::ContextPool::new(8);
        let old_credential = encode_key(&old_key);
        let hooks = HostHooks {
            credential: Some(Box::new(move |row| {
                let marker = if row.credential == old_credential {
                    "A"
                } else {
                    "B"
                };
                rows.bind(|| marker).ok_or("rows full".into())
            })),
            bind: Some(Box::new(move |session| {
                let row = session.user.as_ref().unwrap().credential_context().unwrap();
                let marker = *row.get::<&'static str>().unwrap();
                sessions
                    .bind_with_credential(Some(row.clone()), || marker)
                    .ok_or("sessions full".into())
            })),
            ..Default::default()
        };
        Admission::new(
            &Default::default(),
            events.clone(),
            Some(&HostHooksRef(Arc::new(hooks))),
        )
    } else {
        None
    };
    let env = Arc::new(RuntimeEnv {
        events,
        admission,
        ..Default::default()
    });
    let mut records = env.events.lossless_records().unwrap().reader().unwrap();
    let scope = env.scope.clone();
    let core = scope
        .enter(async {
            crate::app::instance::Instance::build(&config, Vec::new(), env.clone(), Arc::default())
                .unwrap()
        })
        .await;
    let bind_user = |key: &[u8]| match &env.admission {
        Some(admission) => admission
            .bind_credential(
                &env.users,
                "shadowsocks",
                "in",
                Some("alice"),
                &encode_key(key),
            )
            .unwrap(),
        None => Some(env.users.bind("alice")),
    };
    let server = Arc::new(
        udp::Server::new(
            method,
            identity.clone(),
            Some(
                Users::new(vec![
                    User {
                        name: bind_user(&old_key),
                        psk: old_key.clone(),
                    },
                    User {
                        name: bind_user(&new_key),
                        psk: new_key.clone(),
                    },
                ])
                .unwrap(),
            ),
        )
        .unwrap(),
    );
    let inbound = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = SocksAddr::from(echo.local_addr().unwrap());
    let echo_task = tokio::spawn(async move {
        let mut buf = [0_u8; 128];
        let (n, from) = echo.recv_from(&mut buf).await.unwrap();
        echo.send_to(&buf[..n], from).await.unwrap();
    });
    let (mut old_tx, mut old_rx) = udp::client(method, &[identity.clone(), old_key]).unwrap();
    let (mut new_tx, mut new_rx) = udp::client(method, &[identity, new_key]).unwrap();
    client
        .send_to(
            &old_tx.encode(&target, b"old reply").unwrap(),
            inbound.local_addr().unwrap(),
        )
        .await
        .unwrap();
    let mut wire = [0_u8; 4096];
    let (n, address) = bounded(inbound.recv_from(&mut wire)).await.unwrap();
    let received = server.decode(address, &mut wire[..n]).unwrap();
    assert_eq!(
        received
            .user
            .as_ref()
            .unwrap()
            .credential_context()
            .and_then(|c| c.get::<&str>())
            .copied(),
        with_context.then_some("A")
    );
    let data = wire[received.payload.clone()].to_vec();
    let destination = received.destination;
    let mut source = DatagramSource::new(address, None).with_user(received.user);
    source.resource_lease = Some(received.lease);
    let (replies, mut queue) = mpsc::channel(1);
    scope
        .enter(core.nat_manager.send(
            None,
            &source,
            "in",
            &replies,
            UdpPacket::new(data, SocksAddr::from(address), destination),
        ))
        .await;
    // This packet was produced by real NAT downlink and read from its
    // bounded channel. No Received/source token is saved for the assertion.
    let packet = bounded(queue.recv()).await.unwrap();
    assert_eq!(packet.data, b"old reply");
    // Observe ownership without retaining a strong source/peer token.
    let peer = Arc::downgrade(&source.resource_lease.as_ref().unwrap().0);
    assert!(core.nat_manager.end_source("in", &source).await);
    drop(source);
    // End only this association, retaining the same core and task scope
    // so that B can traverse NAT and its session hook after A releases.
    bounded(async {
        while scope
            .tasks()
            .iter()
            .any(|(name, count)| name.starts_with("nat ") && *name != "nat cleanup" && *count > 0)
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    bounded(echo_task).await.unwrap();
    assert_eq!(
        peer.strong_count(),
        2,
        "only the server table and queued plaintext may pin A"
    );
    let root_a = loop {
        let envelope = bounded(records.next_envelope()).await;
        if matches!(
            envelope.record.kind,
            crate::control::events::RecordKind::Closed(_)
        ) {
            assert_eq!(envelope.record.parent_id, None);
            assert_eq!(
                envelope
                    .context
                    .as_ref()
                    .and_then(|c| c.get::<&str>())
                    .copied(),
                with_context.then_some("A")
            );
            break envelope;
        }
    };
    assert!(core.stat_manager.connections().is_empty());
    assert_eq!(env.users.bind("alice").live(), 0);
    // Use a fresh packet for every rejection/retry: replay checks remain active.
    let mut replacement = new_tx.encode(&target, b"replacement").unwrap();
    assert!(
        server.decode(address, &mut replacement).is_err(),
        "queued plaintext is the remaining owner: {finish:?}"
    );
    if matches!(finish, Finish::QueueDropped) {
        let (park, parked) = mpsc::channel(1);
        park.send(packet).await.unwrap();
        drop(parked); // cancellation of a bounded consumer drops queued packets
    } else {
        let (entered, waiting) = oneshot::channel();
        let (release, resumed) = oneshot::channel();
        let mut sender = PausedEncoder {
            server: server.clone(),
            socket: inbound.clone(),
            entered: Some(entered),
            release: resumed,
            fail: matches!(finish, Finish::Failed),
        };
        let delivery = tokio::spawn(async move { packet.send_through(&mut sender).await });
        bounded(waiting).await.unwrap();
        let mut replacement = new_tx.encode(&target, b"during send").unwrap();
        assert!(
            server.decode(address, &mut replacement).is_err(),
            "lease must span the delivery await"
        );
        match finish {
            Finish::Cancelled => {
                delivery.abort();
                assert!(bounded(delivery).await.unwrap_err().is_cancelled());
                drop(release);
            }
            Finish::Sent | Finish::Failed => {
                release.send(()).unwrap();
                let result = bounded(delivery).await.unwrap();
                if matches!(finish, Finish::Failed) {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap(), b"old reply".len());
                    let (n, _) = bounded(client.recv_from(&mut wire)).await.unwrap();
                    let mut wrong = wire[..n].to_vec();
                    assert!(new_rx.decode(&mut wrong).is_err());
                    let (_, body) = old_rx.decode(&mut wire[..n]).unwrap();
                    assert_eq!(&wire[body], b"old reply");
                }
            }
            Finish::QueueDropped => unreachable!(),
        }
    }
    // B retries through the real socket and the SAME NAT/core; decode
    // success alone would not prove its session hook or root envelope.
    let echo_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_b = SocksAddr::from(echo_b.local_addr().unwrap());
    let echo_task_b = tokio::spawn(async move {
        let mut buf = [0_u8; 128];
        let (n, from) = echo_b.recv_from(&mut buf).await.unwrap();
        echo_b.send_to(&buf[..n], from).await.unwrap();
    });
    client
        .send_to(
            &new_tx.encode(&target_b, b"new reply").unwrap(),
            inbound.local_addr().unwrap(),
        )
        .await
        .unwrap();
    let (n, same_address) = bounded(inbound.recv_from(&mut wire)).await.unwrap();
    assert_eq!(address, same_address);
    let accepted = server
        .decode(address, &mut wire[..n])
        .expect("replacement works after queue/delivery owner releases");
    assert_eq!(
        accepted
            .user
            .as_ref()
            .unwrap()
            .credential_context()
            .and_then(|c| c.get::<&str>())
            .copied(),
        with_context.then_some("B")
    );
    let data = wire[accepted.payload].to_vec();
    let mut source_b = DatagramSource::new(address, None).with_user(accepted.user);
    source_b.resource_lease = Some(accepted.lease);
    let (replies_b, mut queue_b) = mpsc::channel(1);
    scope
        .enter(core.nat_manager.send(
            None,
            &source_b,
            "in",
            &replies_b,
            UdpPacket::new(data, SocksAddr::from(address), accepted.destination),
        ))
        .await;
    let packet_b = bounded(queue_b.recv()).await.unwrap();
    assert_eq!(packet_b.data, b"new reply");
    assert_eq!(core.stat_manager.connections().len(), 1);
    assert_eq!(
        env.users.bind("alice").live(),
        1,
        "the one-place cap was released by A and acquired once by B"
    );
    let (entered, waiting) = oneshot::channel();
    let (release, resumed) = oneshot::channel();
    release.send(()).unwrap();
    let mut sender = PausedEncoder {
        server: server.clone(),
        socket: inbound.clone(),
        entered: Some(entered),
        release: resumed,
        fail: false,
    };
    assert_eq!(
        bounded(packet_b.send_through(&mut sender)).await.unwrap(),
        b"new reply".len()
    );
    bounded(waiting).await.unwrap();
    let (n, _) = bounded(client.recv_from(&mut wire)).await.unwrap();
    let mut wrong = wire[..n].to_vec();
    assert!(old_rx.decode(&mut wrong).is_err());
    let (_, body) = new_rx.decode(&mut wire[..n]).unwrap();
    assert_eq!(&wire[body], b"new reply");
    assert!(core.nat_manager.end_source("in", &source_b).await);
    drop(source_b);
    bounded(echo_task_b).await.unwrap();
    let root_b = loop {
        let envelope = bounded(records.next_envelope()).await;
        if matches!(
            envelope.record.kind,
            crate::control::events::RecordKind::Closed(_)
        ) {
            assert_eq!(envelope.record.parent_id, None);
            assert_eq!(
                envelope
                    .context
                    .as_ref()
                    .and_then(|c| c.get::<&str>())
                    .copied(),
                with_context.then_some("B")
            );
            break envelope;
        }
    };
    assert_ne!(root_a.record.id, root_b.record.id);
    assert_eq!(root_a.record.run, root_b.record.run);
    assert_eq!((root_a.record.up_total, root_a.record.down_total), (9, 9));
    assert_eq!((root_b.record.up_total, root_b.record.down_total), (9, 9));
    scope.stop(Duration::from_secs(5)).await;
    assert!(scope.is_empty());
    assert!(core.stat_manager.connections().is_empty());
    assert_eq!(env.users.bind("alice").live(), 0);
    assert!(
        records.try_next_envelope().is_none(),
        "no duplicate root close"
    );
}

#[tokio::test]
async fn a_nat_reply_pins_credentials_through_successful_delivery() {
    queued_reply(Finish::Sent, false).await;
}
#[tokio::test]
async fn a_nat_reply_releases_credentials_after_send_error() {
    queued_reply(Finish::Failed, false).await;
}
#[tokio::test]
async fn a_nat_reply_releases_credentials_after_cancelled_delivery() {
    queued_reply(Finish::Cancelled, false).await;
}
#[tokio::test]
async fn a_nat_reply_releases_credentials_when_its_queue_is_dropped() {
    queued_reply(Finish::QueueDropped, false).await;
}

#[tokio::test]
async fn a_context_bound_nat_reply_pins_credentials_through_successful_delivery() {
    queued_reply(Finish::Sent, true).await;
}
#[tokio::test]
async fn a_context_bound_nat_reply_releases_credentials_after_send_error() {
    queued_reply(Finish::Failed, true).await;
}
#[tokio::test]
async fn a_context_bound_nat_reply_releases_credentials_after_cancelled_delivery() {
    queued_reply(Finish::Cancelled, true).await;
}
#[tokio::test]
async fn a_context_bound_nat_reply_releases_credentials_when_its_queue_is_dropped() {
    queued_reply(Finish::QueueDropped, true).await;
}
