use super::*;
use super::super::User;

/// Actual UDP socket/cipher path: a replacement must not change how a
/// delayed response for the still-owned old authenticated session is sealed.
#[tokio::test]
async fn a_pinned_same_name_session_rejects_new_credentials_before_reply() {
    let method = Method::Aes128Gcm;
    let identity = vec![0x11; 16];
    let old_key = vec![0x22; 16];
    let new_key = vec![0x33; 16];
    let server = Server::new(method, identity.clone(), Some(Users::new(vec![
        User { name: Some(crate::user::UserRef::unbound("alice")), psk: old_key.clone() },
        User { name: Some(crate::user::UserRef::unbound("alice")), psk: new_key.clone() },
    ]).unwrap())).unwrap();
    let inbound = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = SocksAddr::Domain("echo.example".into(), 8080);
    let (mut old_tx, mut old_rx) = client(method, &[identity.clone(), old_key]).unwrap();
    let (mut new_tx, mut new_rx) = client(method, &[identity, new_key]).unwrap();
    let mut wire = vec![0; 2048];
    client_socket.send_to(&old_tx.encode(&target, b"old").unwrap(), inbound.local_addr().unwrap()).await.unwrap();
    let (n, source) = inbound.recv_from(&mut wire).await.unwrap();
    let held_old = server.decode(source, &mut wire[..n]).unwrap();
    assert_eq!(&wire[held_old.payload.clone()], b"old");
    client_socket.send_to(&new_tx.encode(&target, b"new").unwrap(), inbound.local_addr().unwrap()).await.unwrap();
    let (n, same_source) = inbound.recv_from(&mut wire).await.unwrap();
    assert_eq!(source, same_source);
    assert!(server.decode(source, &mut wire[..n]).is_err(), "must reject before replacing the old encryption peer");
    let reply = server.encode(source, &target, b"late-old").unwrap();
    inbound.send_to(&reply, source).await.unwrap();
    let (n, _) = client_socket.recv_from(&mut wire).await.unwrap();
    let mut wrong = wire[..n].to_vec();
    assert!(new_rx.decode(&mut wrong).is_err());
    let (_, body) = old_rx.decode(&mut wire[..n]).unwrap();
    assert_eq!(&wire[body], b"late-old");
    drop(held_old);
    let mut retry = new_tx.encode(&target, b"retry").unwrap();
    let accepted_new = server.decode(source, &mut retry).unwrap();
    assert_eq!(&retry[accepted_new.payload.clone()], b"retry");
    let mut reply = server.encode(source, &target, b"new-reply").unwrap();
    let (_, body) = new_rx.decode(&mut reply).unwrap();
    assert_eq!(&reply[body], b"new-reply");
}
