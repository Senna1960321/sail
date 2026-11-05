//! The Shadowsocks 2022 UDP packet codec.
//!
//! AES methods: a separate header (session ID, packet ID) encrypted as one
//! AES block under the PSK, identity headers when the server has users,
//! then the body sealed with the session's subkey and the last 12 bytes of
//! the plain separate header as nonce.
//!
//! ChaCha method: a random 24-byte nonce, then everything, session and
//! packet ID included, sealed with XChaCha20-Poly1305 under the PSK.
//!
//! The client body is type, timestamp, padding, address, payload; the
//! server's adds the client's session ID after the timestamp.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use rand::{Rng, RngCore};

use crate::session::{SocksAddr, SocksAddrWireType};

use super::{
    check_timestamp, crypto_err, now_secs, psk_hash, session_subkey, Aead, AesBlock, Method,
    ReplayWindow, Users, EIH_LEN, HEADER_TYPE_CLIENT, HEADER_TYPE_SERVER, MAX_PADDING, TAG_LEN,
};

const NONCE_LEN: usize = 24;
const SEPARATE_HEADER_LEN: usize = 16;
/// How long a client keeps an old server session after the server moved
/// on, and how often it lets the server move on.
const SERVER_SESSION_GRACE: Duration = Duration::from_secs(60);
/// UDP sessions a server keeps, and how long an idle one lives.
const MAX_SERVER_SESSIONS: usize = 16 * 1024;
const SERVER_SESSION_TTL: Duration = Duration::from_secs(300);

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn read_u64(b: &[u8]) -> io::Result<u64> {
    let bytes: [u8; 8] = b
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| bad("short packet"))?;
    Ok(u64::from_be_bytes(bytes))
}

/// Padding for a packet: only DNS, whose small messages are the easiest to
/// fingerprint by size, gets it, as other implementations do.
fn udp_padding(target: &SocksAddr, payload_len: usize) -> usize {
    if target.port() == 53 && payload_len < MAX_PADDING {
        rand::thread_rng().gen_range(1..=MAX_PADDING - payload_len)
    } else {
        0
    }
}

/// Appends padding length, padding, address and payload.
fn put_tail(out: &mut Vec<u8>, target: &SocksAddr, payload: &[u8]) {
    let padding = udp_padding(target, payload.len());
    out.extend_from_slice(&(padding as u16).to_be_bytes());
    out.resize(out.len() + padding, 0);
    let mut addr = BytesMut::new();
    target.write_buf(&mut addr, SocksAddrWireType::PortLast);
    out.extend_from_slice(&addr);
    out.extend_from_slice(payload);
}

/// Parses padding length, padding and address from `body`, returning the
/// address and where the payload starts.
fn parse_tail(body: &[u8]) -> io::Result<(SocksAddr, usize)> {
    if body.len() < 2 {
        return Err(bad("short packet"));
    }
    let padding = u16::from_be_bytes([body[0], body[1]]) as usize;
    let start = 2 + padding;
    if padding > MAX_PADDING || start > body.len() {
        return Err(bad("bad padding"));
    }
    let addr = SocksAddr::try_from((&body[start..], SocksAddrWireType::PortLast))?;
    Ok((addr.clone(), start + addr.size()))
}

fn session_aead(method: Method, psk: &[u8], session_id: u64) -> io::Result<Aead> {
    Aead::session(method, &session_subkey(psk, &session_id.to_be_bytes()))
}

fn aes(key: &[u8]) -> io::Result<AesBlock> {
    AesBlock::new(key).map_err(|_| crypto_err())
}

/// Builds the two halves of one client UDP session, with the key chain of
/// [`super::decode_psk_list`].
pub fn client(method: Method, psks: &[Vec<u8>]) -> io::Result<(ClientSender, ClientReceiver)> {
    let first = psks
        .first()
        .ok_or_else(|| io::Error::other("missing PSK"))?;
    let user = psks.last().ok_or_else(|| io::Error::other("missing PSK"))?;
    let session_id = rand::thread_rng().next_u64();
    let sender = if method == Method::ChaCha20Poly1305 {
        ClientSender {
            session_id,
            packet_id: 0,
            cipher: SendCipher::XChaCha(Aead::xchacha(first)?),
        }
    } else {
        let eih = psks
            .windows(2)
            .map(|pair| Ok((aes(&pair[0])?, psk_hash(&pair[1]))))
            .collect::<io::Result<Vec<_>>>()?;
        ClientSender {
            session_id,
            packet_id: 0,
            cipher: SendCipher::Aes {
                header: aes(first)?,
                eih,
                body: session_aead(method, user, session_id)?,
            },
        }
    };
    let receiver = ClientReceiver {
        method,
        session_id,
        psk: user.clone(),
        cipher: if method == Method::ChaCha20Poly1305 {
            RecvCipher::XChaCha(Aead::xchacha(first)?)
        } else {
            RecvCipher::Aes(aes(user)?)
        },
        current: None,
        previous: None,
    };
    Ok((sender, receiver))
}

enum SendCipher {
    XChaCha(Aead),
    Aes {
        /// Encrypts the separate header, under the first key.
        header: AesBlock,
        /// Each key but the last, with the hash of the key after it.
        eih: Vec<(AesBlock, [u8; EIH_LEN])>,
        body: Aead,
    },
}

pub struct ClientSender {
    session_id: u64,
    packet_id: u64,
    cipher: SendCipher,
}

impl ClientSender {
    pub fn encode(&mut self, target: &SocksAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
        let packet_id = self.packet_id;
        self.packet_id = self.packet_id.checked_add(1).ok_or_else(crypto_err)?;
        let mut out = Vec::with_capacity(payload.len() + 128);
        match &mut self.cipher {
            SendCipher::XChaCha(aead) => {
                let mut nonce = [0u8; NONCE_LEN];
                rand::thread_rng().fill_bytes(&mut nonce);
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&self.session_id.to_be_bytes());
                out.extend_from_slice(&packet_id.to_be_bytes());
                out.push(HEADER_TYPE_CLIENT);
                out.extend_from_slice(&now_secs().to_be_bytes());
                put_tail(&mut out, target, payload);
                aead.seal(&nonce, &mut out, NONCE_LEN)?;
            }
            SendCipher::Aes { header, eih, body } => {
                let mut sep = [0u8; SEPARATE_HEADER_LEN];
                sep[..8].copy_from_slice(&self.session_id.to_be_bytes());
                sep[8..].copy_from_slice(&packet_id.to_be_bytes());
                out.extend_from_slice(&sep);
                for (key, hash) in eih.iter() {
                    let mut block = *hash;
                    block.iter_mut().zip(sep.iter()).for_each(|(b, s)| *b ^= s);
                    key.encrypt(&mut block)?;
                    out.extend_from_slice(&block);
                }
                let start = out.len();
                out.push(HEADER_TYPE_CLIENT);
                out.extend_from_slice(&now_secs().to_be_bytes());
                put_tail(&mut out, target, payload);
                body.seal(&sep[4..], &mut out, start)?;
                header.encrypt(&mut out[..SEPARATE_HEADER_LEN])?;
            }
        }
        Ok(out)
    }
}

enum RecvCipher {
    XChaCha(Aead),
    /// Decrypts the separate header, under the user's key.
    Aes(AesBlock),
}

/// A server session as a client sees it.
struct RemoteSession {
    id: u64,
    aead: Option<Aead>,
    window: ReplayWindow,
    last_seen: Instant,
}

pub struct ClientReceiver {
    method: Method,
    session_id: u64,
    psk: Vec<u8>,
    cipher: RecvCipher,
    current: Option<RemoteSession>,
    previous: Option<RemoteSession>,
}

impl ClientReceiver {
    /// Decrypts a server packet in place; returns the source address and
    /// where the payload is in `packet`.
    pub fn decode(&mut self, packet: &mut [u8]) -> io::Result<(SocksAddr, Range<usize>)> {
        let (server_id, packet_id, body) = match &mut self.cipher {
            RecvCipher::XChaCha(aead) => {
                if packet.len() < NONCE_LEN + SEPARATE_HEADER_LEN + TAG_LEN {
                    return Err(bad("short packet"));
                }
                let (nonce, rest) = packet.split_at_mut(NONCE_LEN);
                let n = aead.open(nonce, rest)?;
                let id = read_u64(&rest[..])?;
                let pid = read_u64(&rest[8..])?;
                let known = [&self.current, &self.previous]
                    .into_iter()
                    .flatten()
                    .find(|s| s.id == id);
                if known.is_some_and(|s| !s.window.check(pid)) {
                    return Err(bad("repeated packet"));
                }
                (id, pid, NONCE_LEN + SEPARATE_HEADER_LEN..NONCE_LEN + n)
            }
            RecvCipher::Aes(block) => {
                if packet.len() < SEPARATE_HEADER_LEN + TAG_LEN {
                    return Err(bad("short packet"));
                }
                block.decrypt(&mut packet[..SEPARATE_HEADER_LEN])?;
                let id = read_u64(&packet[..])?;
                let pid = read_u64(&packet[8..])?;
                let (sep, rest) = packet.split_at_mut(SEPARATE_HEADER_LEN);
                let known = [&mut self.current, &mut self.previous]
                    .into_iter()
                    .flatten()
                    .find(|s| s.id == id);
                let n = match known {
                    Some(s) => {
                        if !s.window.check(pid) {
                            return Err(bad("repeated packet"));
                        }
                        s.aead
                            .as_mut()
                            .ok_or_else(crypto_err)?
                            .open(&sep[4..], rest)?
                    }
                    None => session_aead(self.method, &self.psk, id)?.open(&sep[4..], rest)?,
                };
                (id, pid, SEPARATE_HEADER_LEN..SEPARATE_HEADER_LEN + n)
            }
        };

        let b = &packet[body.clone()];
        if b.len() < 1 + 8 + 8 {
            return Err(bad("short packet"));
        }
        if b[0] != HEADER_TYPE_SERVER {
            return Err(bad("bad header type"));
        }
        check_timestamp(read_u64(&b[1..])?)?;
        if read_u64(&b[9..])? != self.session_id {
            return Err(bad("packet for another client session"));
        }
        let (addr, offset) = parse_tail(&b[17..])?;
        self.record(server_id, packet_id)?;
        Ok((addr, body.start + 17 + offset..body.end))
    }

    /// Records an authenticated packet of server session `id`, following
    /// the server to a new session at most once per grace period.
    fn record(&mut self, id: u64, packet_id: u64) -> io::Result<()> {
        let now = Instant::now();
        for s in [&mut self.current, &mut self.previous]
            .into_iter()
            .flatten()
        {
            if s.id == id {
                s.window.add(packet_id);
                s.last_seen = now;
                return Ok(());
            }
        }
        if let Some(prev) = &self.previous {
            if now.duration_since(prev.last_seen) < SERVER_SESSION_GRACE {
                return Err(bad("server session changed more than once in a minute"));
            }
        }
        let aead = match self.cipher {
            RecvCipher::XChaCha(_) => None,
            RecvCipher::Aes(_) => Some(session_aead(self.method, &self.psk, id)?),
        };
        let mut window = ReplayWindow::new();
        window.add(packet_id);
        let new = RemoteSession {
            id,
            aead,
            window,
            last_seen: now,
        };
        self.previous = self.current.replace(new);
        Ok(())
    }
}

/// The server side of UDP: one per inbound, shared by both halves.
pub struct Server {
    method: Method,
    psk: Vec<u8>,
    users: Option<Users>,
    state: Arc<Mutex<ServerState>>,
}

struct ServerState {
    xchacha: Option<Aead>,
    /// By the client's address, which is what replies are sent to.
    sessions: HashMap<SocketAddr, ServerSession>,
}

struct ServerSession {
    client_id: u64,
    user: Option<[u8; EIH_LEN]>,
    name: Option<crate::user::UserRef>,
    /// Opens the client's packets (AES methods).
    client_aead: Option<Aead>,
    window: ReplayWindow,
    server_id: u64,
    packet_id: u64,
    /// Seals our packets and encrypts their separate header (AES methods).
    server_aead: Option<Aead>,
    header: Option<AesBlock>,
    last_seen: Instant,
}

/// A packet a server accepted.
pub struct Received {
    pub destination: SocksAddr,
    pub payload: Range<usize>,
    pub user: Option<crate::user::UserRef>,
}

impl Server {
    pub fn new(method: Method, psk: Vec<u8>, users: Option<Users>) -> io::Result<Self> {
        let xchacha = if method == Method::ChaCha20Poly1305 {
            Some(Aead::xchacha(&psk)?)
        } else {
            None
        };
        Ok(Server {
            method,
            psk,
            users,
            state: Arc::new(Mutex::new(ServerState {
                xchacha,
                sessions: HashMap::new(),
            })),
        })
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, ServerState>> {
        self.state
            .lock()
            .map_err(|_| io::Error::other("udp session table poisoned"))
    }

    /// Credentials change without forgetting authenticated UDP sessions or
    /// their replay windows. Method, identity PSK and EIH framing stay static.
    #[cfg(any(feature = "inbound-shadowsocks", test))]
    pub(crate) fn with_users(&self, users: Option<Users>) -> Self {
        Self {
            method: self.method,
            psk: self.psk.clone(),
            users,
            state: self.state.clone(),
        }
    }

    fn user_psk(&self, user: Option<[u8; EIH_LEN]>) -> io::Result<&[u8]> {
        match (user, &self.users) {
            (None, _) => Ok(&self.psk),
            (Some(hash), Some(users)) => Ok(&users
                .find(&hash)
                .filter(|(_, user)| !crate::user::shut_out(&user.name))
                .ok_or_else(crypto_err)?
                .1
                .psk),
            (Some(_), None) => Err(crypto_err()),
        }
    }

    /// Decrypts a client packet from `from` in place.
    pub fn decode(&self, from: SocketAddr, packet: &mut [u8]) -> io::Result<Received> {
        let mut state = self.lock()?;
        let state = &mut *state;
        if state
            .sessions
            .get(&from)
            .is_some_and(|s| s.last_seen.elapsed() >= SERVER_SESSION_TTL)
        {
            state.sessions.remove(&from);
        }
        let (client_id, packet_id, user, body, new_aead) = if let Some(aead) = &mut state.xchacha {
            if packet.len() < NONCE_LEN + SEPARATE_HEADER_LEN + TAG_LEN {
                return Err(bad("short packet"));
            }
            let (nonce, rest) = packet.split_at_mut(NONCE_LEN);
            let n = aead.open(nonce, rest)?;
            let id = read_u64(&rest[..])?;
            let pid = read_u64(&rest[8..])?;
            if let Some(s) = state.sessions.get(&from).filter(|s| s.client_id == id) {
                if !s.window.check(pid) {
                    return Err(bad("repeated packet"));
                }
            }
            (
                id,
                pid,
                None,
                NONCE_LEN + SEPARATE_HEADER_LEN..NONCE_LEN + n,
                None,
            )
        } else {
            let eih_len = if self.users.is_some() { EIH_LEN } else { 0 };
            if packet.len() < SEPARATE_HEADER_LEN + eih_len + TAG_LEN {
                return Err(bad("short packet"));
            }
            let block = aes(&self.psk)?;
            block.decrypt(&mut packet[..SEPARATE_HEADER_LEN])?;
            let id = read_u64(&packet[..])?;
            let pid = read_u64(&packet[8..])?;
            let user = match &self.users {
                None => None,
                Some(_) => {
                    let mut hash = [0u8; EIH_LEN];
                    hash.copy_from_slice(
                        &packet[SEPARATE_HEADER_LEN..SEPARATE_HEADER_LEN + EIH_LEN],
                    );
                    block.decrypt(&mut hash)?;
                    hash.iter_mut()
                        .zip(packet.iter())
                        .for_each(|(h, p)| *h ^= p);
                    Some(hash)
                }
            };
            let start = SEPARATE_HEADER_LEN + eih_len;
            let (head, rest) = packet.split_at_mut(start);
            let nonce = &head[4..SEPARATE_HEADER_LEN];
            let known = state
                .sessions
                .get_mut(&from)
                .filter(|s| s.client_id == id && s.user == user);
            let (n, new_aead) = match known {
                Some(s) => {
                    if !s.window.check(pid) {
                        return Err(bad("repeated packet"));
                    }
                    let aead = s.client_aead.as_mut().ok_or_else(crypto_err)?;
                    (aead.open(nonce, rest)?, None)
                }
                None => {
                    let mut aead = session_aead(self.method, self.user_psk(user)?, id)?;
                    (aead.open(nonce, rest)?, Some(aead))
                }
            };
            (id, pid, user, start..start + n, new_aead)
        };

        let b = &packet[body.clone()];
        if b.len() < 1 + 8 {
            return Err(bad("short packet"));
        }
        if b[0] != HEADER_TYPE_CLIENT {
            return Err(bad("bad header type"));
        }
        check_timestamp(read_u64(&b[1..])?)?;
        let (destination, offset) = parse_tail(&b[9..])?;

        // Authenticated: record the packet, starting a session if it is
        // the first of a new one from this address.
        let now = Instant::now();
        let fresh = !matches!(
            state.sessions.get(&from),
            Some(s) if s.client_id == client_id && s.user == user
        );
        if fresh {
            let session = self.new_session(client_id, user, new_aead)?;
            if !state.sessions.contains_key(&from) {
                make_room(&mut state.sessions, now);
            }
            state.sessions.insert(from, session);
        }
        let session = state.sessions.get_mut(&from).ok_or_else(crypto_err)?;
        session.window.add(packet_id);
        session.last_seen = now;

        let user = session.name.clone();
        Ok(Received {
            destination,
            payload: body.start + 9 + offset..body.end,
            user,
        })
    }

    fn new_session(
        &self,
        client_id: u64,
        user: Option<[u8; EIH_LEN]>,
        client_aead: Option<Aead>,
    ) -> io::Result<ServerSession> {
        let server_id = rand::thread_rng().next_u64();
        let (server_aead, header) = if self.method == Method::ChaCha20Poly1305 {
            (None, None)
        } else {
            let psk = self.user_psk(user)?;
            (
                Some(session_aead(self.method, psk, server_id)?),
                Some(aes(psk)?),
            )
        };
        Ok(ServerSession {
            client_id,
            user,
            name: user.and_then(|hash| self.users.as_ref()?.find(&hash)?.1.name.clone()),
            client_aead,
            window: ReplayWindow::new(),
            server_id,
            packet_id: 0,
            server_aead,
            header,
            last_seen: Instant::now(),
        })
    }

    /// Seals a reply to the client at `to`, from `source`.
    pub fn encode(
        &self,
        to: SocketAddr,
        source: &SocksAddr,
        payload: &[u8],
    ) -> io::Result<Vec<u8>> {
        let mut state = self.lock()?;
        let state = &mut *state;
        let session = state
            .sessions
            .get_mut(&to)
            .ok_or_else(|| io::Error::other("no udp session for the client"))?;
        let packet_id = session.packet_id;
        session.packet_id = packet_id.checked_add(1).ok_or_else(crypto_err)?;
        let mut out = Vec::with_capacity(payload.len() + 128);
        let body = |out: &mut Vec<u8>| {
            out.push(HEADER_TYPE_SERVER);
            out.extend_from_slice(&now_secs().to_be_bytes());
            out.extend_from_slice(&session.client_id.to_be_bytes());
            put_tail(out, source, payload);
        };
        match &mut state.xchacha {
            Some(aead) => {
                let mut nonce = [0u8; NONCE_LEN];
                rand::thread_rng().fill_bytes(&mut nonce);
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&session.server_id.to_be_bytes());
                out.extend_from_slice(&packet_id.to_be_bytes());
                body(&mut out);
                aead.seal(&nonce, &mut out, NONCE_LEN)?;
            }
            None => {
                let mut sep = [0u8; SEPARATE_HEADER_LEN];
                sep[..8].copy_from_slice(&session.server_id.to_be_bytes());
                sep[8..].copy_from_slice(&packet_id.to_be_bytes());
                out.extend_from_slice(&sep);
                body(&mut out);
                let aead = session.server_aead.as_mut().ok_or_else(crypto_err)?;
                aead.seal(&sep[4..], &mut out, SEPARATE_HEADER_LEN)?;
                let header = session.header.as_ref().ok_or_else(crypto_err)?;
                header.encrypt(&mut out[..SEPARATE_HEADER_LEN])?;
            }
        }
        Ok(out)
    }
}

/// Makes room for one more session: drops idle ones, and if the table is
/// still full, the least recently used.
fn make_room(sessions: &mut HashMap<SocketAddr, ServerSession>, now: Instant) {
    if sessions.len() < MAX_SERVER_SESSIONS {
        return;
    }
    sessions.retain(|_, s| now.duration_since(s.last_seen) < SERVER_SESSION_TTL);
    if sessions.len() >= MAX_SERVER_SESSIONS {
        if let Some(oldest) = sessions
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(a, _)| *a)
        {
            sessions.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::User;
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:5000".parse().unwrap()
    }

    fn exchange(method: Method, psks: Vec<Vec<u8>>, server: Server, want_user: Option<&str>) {
        let (mut tx, mut rx) = client(method, &psks).unwrap();
        let target = SocksAddr::try_from(("example.com", 53)).unwrap();
        for i in 0..3u8 {
            let mut pkt = tx.encode(&target, &[i; 10]).unwrap();
            let got = server.decode(addr(), &mut pkt).unwrap();
            assert_eq!(got.destination, target);
            assert_eq!(&pkt[got.payload], &[i; 10]);
            assert_eq!(crate::user::name(&got.user), want_user);

            let from = SocksAddr::from(addr());
            let mut reply = server.encode(addr(), &from, &[i + 1; 7]).unwrap();
            let (src, range) = rx.decode(&mut reply).unwrap();
            assert_eq!(src, from);
            assert_eq!(&reply[range], &[i + 1; 7]);
        }
    }

    #[test]
    fn single_user_all_methods() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
        ] {
            let psk = vec![0x11; method.key_len()];
            let server = Server::new(method, psk.clone(), None).unwrap();
            exchange(method, vec![psk], server, None);
        }
    }

    #[test]
    fn multi_user() {
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let ipsk = vec![0x11; method.key_len()];
            let users = Users::new(vec![
                User {
                    name: Some(crate::user::UserRef::unbound("alice")),
                    psk: vec![0x22; method.key_len()],
                },
                User {
                    name: Some(crate::user::UserRef::unbound("bob")),
                    psk: vec![0x33; method.key_len()],
                },
            ])
            .unwrap();
            let server = Server::new(method, ipsk.clone(), Some(users)).unwrap();
            exchange(
                method,
                vec![ipsk, vec![0x22; method.key_len()]],
                server,
                Some("alice"),
            );
        }
    }

    #[test]
    fn replayed_packet_rejected() {
        for method in [Method::Aes128Gcm, Method::ChaCha20Poly1305] {
            let psk = vec![0x11; method.key_len()];
            let server = Server::new(method, psk.clone(), None).unwrap();
            let (mut tx, mut rx) = client(method, &[psk]).unwrap();
            let target = SocksAddr::try_from(("example.com", 80)).unwrap();
            let pkt = tx.encode(&target, b"once").unwrap();
            server.decode(addr(), &mut pkt.clone()).unwrap();
            let err = server.decode(addr(), &mut pkt.clone()).err().unwrap();
            assert!(err.to_string().contains("repeated"), "{}", err);

            let reply = server.encode(addr(), &target, b"r").unwrap();
            rx.decode(&mut reply.clone()).unwrap();
            let err = rx.decode(&mut reply.clone()).err().unwrap();
            assert!(err.to_string().contains("repeated"), "{}", err);
        }
    }

    #[test]
    fn user_rotation_preserves_sessions_identity_and_replay() {
        let method = Method::Aes128Gcm;
        let identity = vec![0x11; 16];
        let alice = User {
            name: Some(crate::user::UserRef::unbound("alice")),
            psk: vec![0x22; 16],
        };
        let bob = User {
            name: Some(crate::user::UserRef::unbound("bob")),
            psk: vec![0x33; 16],
        };
        let server = Server::new(
            method,
            identity.clone(),
            Some(Users::new(vec![alice.clone(), bob.clone()]).unwrap()),
        )
        .unwrap();
        let (mut tx, mut rx) = client(method, &[identity.clone(), alice.psk.clone()]).unwrap();
        let target = SocksAddr::from(addr());
        let packet = tx.encode(&target, b"first").unwrap();
        assert_eq!(
            server
                .decode(addr(), &mut packet.clone())
                .unwrap()
                .user
                .as_ref()
                .map(|u| u.to_string())
                .as_deref(),
            Some("alice")
        );
        // Reordering and renaming must not reattribute an established session.
        let mut renamed = alice.clone();
        renamed.name = Some(crate::user::UserRef::unbound("renamed"));
        let reordered = server.with_users(Some(Users::new(vec![bob.clone(), renamed]).unwrap()));
        assert!(reordered.decode(addr(), &mut packet.clone()).is_err());
        let mut next = tx.encode(&target, b"next").unwrap();
        assert_eq!(
            crate::user::name(&reordered.decode(addr(), &mut next).unwrap().user),
            Some("alice")
        );
        let empty = reordered.with_users(Some(Users::new(vec![]).unwrap()));
        let mut next = tx.encode(&target, b"old session").unwrap();
        assert_eq!(
            crate::user::name(&empty.decode(addr(), &mut next).unwrap().user),
            Some("alice")
        );
        let mut reply = empty.encode(addr(), &target, b"reply").unwrap();
        let (_, payload) = rx.decode(&mut reply).unwrap();
        assert_eq!(&reply[payload], b"reply");
        let (mut fresh, _) = client(method, &[identity, alice.psk]).unwrap();
        assert!(empty
            .decode(addr(), &mut fresh.encode(&target, b"new session").unwrap())
            .is_err());
        let restored = empty.with_users(Some(Users::new(vec![bob]).unwrap()));
        assert!(restored.decode(addr(), &mut packet.clone()).is_err());
        // Idle sessions cannot indefinitely extend removed credentials.
        empty
            .lock()
            .unwrap()
            .sessions
            .get_mut(&addr())
            .unwrap()
            .last_seen = Instant::now() - SERVER_SESSION_TTL;
        assert!(empty
            .decode(addr(), &mut tx.encode(&target, b"expired").unwrap())
            .is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let method = Method::Aes256Gcm;
        let server = Server::new(method, vec![0x11; 32], None).unwrap();
        let (mut tx, _) = client(method, &[vec![0x12; 32]]).unwrap();
        let target = SocksAddr::try_from(("example.com", 80)).unwrap();
        let mut pkt = tx.encode(&target, b"x").unwrap();
        assert!(server.decode(addr(), &mut pkt).is_err());
        // A failed packet does not open a session.
        assert!(server.encode(addr(), &target, b"y").is_err());
    }

    #[test]
    fn session_table_bounded() {
        let method = Method::Aes128Gcm;
        let psk = vec![0x11; 16];
        let server = Server::new(method, psk.clone(), None).unwrap();
        let target = SocksAddr::try_from(("example.com", 80)).unwrap();
        for port in 0..(MAX_SERVER_SESSIONS as u16 + 10) {
            let (mut tx, _) = client(method, std::slice::from_ref(&psk)).unwrap();
            let mut pkt = tx.encode(&target, b"x").unwrap();
            let from = SocketAddr::from(([127, 0, 0, 1], port));
            server.decode(from, &mut pkt).unwrap();
        }
        assert_eq!(server.lock().unwrap().sessions.len(), MAX_SERVER_SESSIONS);
    }
}

#[cfg(test)]
#[path = "udp_lease_tests.rs"]
mod lease_tests;
