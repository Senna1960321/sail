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

async fn queued_reply(finish: Finish) {
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
    let env = Arc::new(RuntimeEnv {
        events: EventHub::with_records(16, Some(16)),
        ..Default::default()
    });
    let scope = env.scope.clone();
    let core = scope
        .enter(async {
            crate::app::instance::Instance::build(&config, Vec::new(), env.clone(), Arc::default())
                .unwrap()
        })
        .await;
    let alice = env.users.bind("alice");
    let server = Arc::new(
        udp::Server::new(
            method,
            identity.clone(),
            Some(
                Users::new(vec![
                    User {
                        name: Some(alice.clone()),
                        psk: old_key.clone(),
                    },
                    User {
                        name: Some(alice),
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
    assert!(core.nat_manager.end_source("in", &source).await);
    drop(source);
    // A completed scope stop is a task-drop barrier, not a guessed delay.
    // The inbound consumer below is deliberately outside that NAT scope.
    scope.stop(Duration::from_secs(5)).await;
    assert!(
        scope.is_empty(),
        "all NAT task copies of the source must be gone"
    );
    bounded(echo_task).await.unwrap();
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
    let mut retry = new_tx.encode(&target, b"retry after release").unwrap();
    let accepted = server
        .decode(address, &mut retry)
        .expect("replacement works after queue/delivery owner releases");
    assert_eq!(&retry[accepted.payload], b"retry after release");
    let mut response = server.encode(address, &target, b"new reply").unwrap();
    let (_, body) = new_rx.decode(&mut response).unwrap();
    assert_eq!(&response[body], b"new reply");
}

#[tokio::test]
async fn a_nat_reply_pins_credentials_through_successful_delivery() {
    queued_reply(Finish::Sent).await;
}
#[tokio::test]
async fn a_nat_reply_releases_credentials_after_send_error() {
    queued_reply(Finish::Failed).await;
}
#[tokio::test]
async fn a_nat_reply_releases_credentials_after_cancelled_delivery() {
    queued_reply(Finish::Cancelled).await;
}
#[tokio::test]
async fn a_nat_reply_releases_credentials_when_its_queue_is_dropped() {
    queued_reply(Finish::QueueDropped).await;
}
