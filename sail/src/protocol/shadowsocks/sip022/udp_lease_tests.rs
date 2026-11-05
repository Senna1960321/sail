use super::super::User;
use super::*;

/// Actual UDP socket/cipher path: a replacement must not change how a
/// delayed response for the still-owned old authenticated session is sealed.
#[tokio::test]
async fn a_pinned_same_name_session_rejects_new_credentials_before_reply() {
    let method = Method::Aes128Gcm;
    let identity = vec![0x11; 16];
    let old_key = vec![0x22; 16];
    let new_key = vec![0x33; 16];
    let server = Server::new(
        method,
        identity.clone(),
        Some(
            Users::new(vec![
                User {
                    name: Some(crate::user::UserRef::unbound("alice")),
                    psk: old_key.clone(),
                },
                User {
                    name: Some(crate::user::UserRef::unbound("alice")),
                    psk: new_key.clone(),
                },
            ])
            .unwrap(),
        ),
    )
    .unwrap();
    let inbound = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = SocksAddr::Domain("echo.example".into(), 8080);
    let (mut old_tx, mut old_rx) = client(method, &[identity.clone(), old_key]).unwrap();
    let (mut new_tx, mut new_rx) = client(method, &[identity, new_key]).unwrap();
    let mut wire = vec![0; 2048];
    client_socket
        .send_to(
            &old_tx.encode(&target, b"old").unwrap(),
            inbound.local_addr().unwrap(),
        )
        .await
        .unwrap();
    let (n, source) = inbound.recv_from(&mut wire).await.unwrap();
    let held_old = server.decode(source, &mut wire[..n]).unwrap();
    assert_eq!(&wire[held_old.payload.clone()], b"old");
    client_socket
        .send_to(
            &new_tx.encode(&target, b"new").unwrap(),
            inbound.local_addr().unwrap(),
        )
        .await
        .unwrap();
    let (n, same_source) = inbound.recv_from(&mut wire).await.unwrap();
    assert_eq!(source, same_source);
    assert!(
        server.decode(source, &mut wire[..n]).is_err(),
        "must reject before replacing the old encryption peer"
    );
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

#[test]
fn a_same_client_id_under_another_user_cannot_replace_a_pinned_peer() {
    for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
        let identity = vec![0x11; method.key_len()];
        let a = vec![0x22; method.key_len()];
        let b = vec![0x33; method.key_len()];
        let server = Server::new(
            method,
            identity.clone(),
            Some(
                Users::new(vec![
                    User {
                        name: Some(crate::user::UserRef::unbound("alice")),
                        psk: a.clone(),
                    },
                    User {
                        name: Some(crate::user::UserRef::unbound("alice")),
                        psk: b.clone(),
                    },
                ])
                .unwrap(),
            ),
        )
        .unwrap();
        let source = "127.0.0.1:5000".parse().unwrap();
        let target = SocksAddr::Domain("echo.example".into(), 80);
        let (mut old, mut old_rx) = client(method, &[identity.clone(), a]).unwrap();
        let held = server
            .decode(source, &mut old.encode(&target, b"old").unwrap())
            .unwrap();
        let (mut new, mut new_rx) = client(method, &[identity, b.clone()]).unwrap();
        new.session_id = old.session_id;
        new_rx.session_id = old.session_id;
        if let SendCipher::Aes { body, .. } = &mut new.cipher {
            *body = session_aead(method, &b, old.session_id).unwrap();
        }
        let mut packet = new.encode(&target, b"new").unwrap();
        let error = server.decode(source, &mut packet).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        let mut reply = server.encode(source, &target, b"old-reply").unwrap();
        assert!(old_rx.decode(&mut reply).is_ok());
        // A queued reply independently keeps the generation alive after
        // the source/Received owner has gone.
        let queued_reply = held.lease.clone();
        drop(held);
        assert!(server
            .decode(source, &mut new.encode(&target, b"still busy").unwrap())
            .is_err());
        drop(queued_reply);
        let new_received = server
            .decode(source, &mut new.encode(&target, b"retry").unwrap())
            .unwrap();
        assert_eq!(crate::user::name(&new_received.user), Some("alice"));
        let mut reply = server.encode(source, &target, b"new-reply").unwrap();
        assert!(new_rx.decode(&mut reply).is_ok());
    }
}

#[test]
fn ttl_and_lru_cannot_remove_a_pinned_encryption_peer() {
    let method = Method::Aes128Gcm;
    let key = vec![0x11; 16];
    let server = Server::new(method, key.clone(), None).unwrap();
    let source = "127.0.0.1:5000".parse().unwrap();
    let target = SocksAddr::Domain("echo.example".into(), 80);
    let (mut old, _) = client(method, std::slice::from_ref(&key)).unwrap();
    let held = server
        .decode(source, &mut old.encode(&target, b"old").unwrap())
        .unwrap();
    server
        .lock()
        .unwrap()
        .sessions
        .get_mut(&source)
        .unwrap()
        .last_seen = Instant::now() - SERVER_SESSION_TTL;
    let (mut new, _) = client(method, std::slice::from_ref(&key)).unwrap();
    assert_eq!(
        server
            .decode(source, &mut new.encode(&target, b"new").unwrap())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    // Same session still works, even beyond TTL, with one stable lease.
    let next = server
        .decode(source, &mut old.encode(&target, b"next").unwrap())
        .unwrap();
    assert_eq!(held.lease, next.lease);
    drop(next);
    // Fill with synthetic idle peers to exercise cleanup without a timer.
    {
        let mut state = server.lock().unwrap();
        state.sessions.get_mut(&source).unwrap().last_seen = Instant::now() - SERVER_SESSION_TTL;
        for port in 0..MAX_SERVER_SESSIONS as u16 {
            let address = SocketAddr::from(([127, 0, 0, 2], port));
            if state.sessions.len() == MAX_SERVER_SESSIONS {
                break;
            }
            state.sessions.insert(
                address,
                server.new_session(port as u64, None, None).unwrap(),
            );
        }
        make_room(&mut state.sessions, Instant::now()).unwrap();
        assert!(state.sessions.contains_key(&source));
        assert_eq!(state.sessions.len(), MAX_SERVER_SESSIONS - 1);
    }
    drop(held);
    assert!(server
        .decode(source, &mut new.encode(&target, b"retry").unwrap())
        .is_ok());
}

#[test]
fn a_full_pinned_table_refuses_then_reuses_a_released_slot() {
    let server = Server::new(Method::Aes128Gcm, vec![0x11; 16], None).unwrap();
    let mut pins = Vec::new();
    {
        let mut state = server.lock().unwrap();
        for port in 0..MAX_SERVER_SESSIONS as u16 {
            let session = server.new_session(port as u64, None, None).unwrap();
            pins.push(session.lease.clone());
            state
                .sessions
                .insert(SocketAddr::from(([127, 0, 0, 1], port)), session);
        }
        assert_eq!(
            make_room(&mut state.sessions, Instant::now())
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(state.sessions.len(), MAX_SERVER_SESSIONS);
        pins.pop();
        make_room(&mut state.sessions, Instant::now()).unwrap();
        assert_eq!(state.sessions.len(), MAX_SERVER_SESSIONS - 1);
    }
    let (mut sender, _) = client(Method::Aes128Gcm, &[vec![0x11; 16]]).unwrap();
    let source = "127.0.0.2:5000".parse().unwrap();
    let target = SocksAddr::Domain("echo.example".into(), 80);
    assert!(server
        .decode(source, &mut sender.encode(&target, b"new peer").unwrap())
        .is_ok());
    assert_eq!(server.lock().unwrap().sessions.len(), MAX_SERVER_SESSIONS);
}

#[test]
fn anonymous_sessions_are_also_pinned_for_every_cipher() {
    for method in [
        Method::Aes128Gcm,
        Method::Aes256Gcm,
        Method::ChaCha20Poly1305,
    ] {
        let key = vec![0x44; method.key_len()];
        let server = Server::new(method, key.clone(), None).unwrap();
        let source = "127.0.0.1:5010".parse().unwrap();
        let first_target = SocksAddr::Domain("one.example".into(), 80);
        let second_target = SocksAddr::Domain("two.example".into(), 81);
        let (mut old, mut old_rx) = client(method, std::slice::from_ref(&key)).unwrap();
        let held = server
            .decode(source, &mut old.encode(&first_target, b"one").unwrap())
            .unwrap();
        assert!(held.user.is_none());
        let second = server
            .decode(source, &mut old.encode(&second_target, b"two").unwrap())
            .unwrap();
        assert_eq!(held.lease, second.lease);
        let (mut new, mut new_rx) = client(method, std::slice::from_ref(&key)).unwrap();
        assert_eq!(
            server
                .decode(
                    source,
                    &mut new.encode(&first_target, b"replacement").unwrap()
                )
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let mut reply = server.encode(source, &first_target, b"old reply").unwrap();
        assert!(old_rx.decode(&mut reply).is_ok());
        drop(held);
        assert!(server
            .decode(
                source,
                &mut new.encode(&first_target, b"still held").unwrap()
            )
            .is_err());
        drop(second);
        let _new = server
            .decode(source, &mut new.encode(&first_target, b"retry").unwrap())
            .unwrap();
        let mut reply = server.encode(source, &first_target, b"new reply").unwrap();
        assert!(new_rx.decode(&mut reply).is_ok());
    }
}
