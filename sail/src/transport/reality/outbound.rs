//! The REALITY client over BoringSSL.
//!
//! The ClientHello session ID carries the client's credentials: a short ID
//! and a timestamp, sealed with a key from X25519 between the client's key
//! share and the server's public key. The server answers an authenticated
//! client with a throwaway Ed25519 certificate whose signature is an HMAC
//! under that key, and relays everyone else to the real site it imitates.

use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::UNIX_EPOCH;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use btls::ex_data::Index;
use btls::pkey::Id;
use btls::ssl::{Ssl, SslAlert, SslConnector, SslMethod, SslRef, SslVerifyError, SslVerifyMode};
use foreign_types::ForeignTypeRef;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use super::{parse_key, parse_short_id, CLIENT_VERSION};
use crate::adapter::*;
use crate::session::Session;
use crate::transport::tls::{BoringConnection, Fingerprint};
use crate::transport::tls_stream::TlsStream;
use crate::transport::vision::VisionState;

pub struct Handler {
    server_name: String,
    public_key: [u8; 32],
    short_id: [u8; 8],
    connector: SslConnector,
    fingerprint: Fingerprint,
    alpn: Vec<String>,
    /// How the ClientHello is cut, if it is.
    fragment: Option<crate::session::TlsFragment>,
}

/// What the ClientHello hook and the certificate check of one connection
/// share.
struct Auth {
    public_key: [u8; 32],
    short_id: [u8; 8],
    // Set by the ClientHello hook, read by the certificate check.
    key: Mutex<Option<[u8; 32]>>,
}

fn auth_index() -> Index<Ssl, Arc<Auth>> {
    static INDEX: OnceLock<Index<Ssl, Arc<Auth>>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("allocate an SSL ex_data index"))
}

impl Handler {
    /// `public_key` is the server's X25519 key, hex or base64url; `short_id`
    /// is up to 16 hex digits. The ClientHello is `fingerprint`'s, with the
    /// browser's ALPN.
    pub fn new(
        server_name: String,
        public_key: &str,
        short_id: &str,
        fingerprint: Fingerprint,
    ) -> Result<Self> {
        if server_name.is_empty() {
            return Err(anyhow!("server_name is required"));
        }
        let mut builder = SslConnector::bare_builder(SslMethod::tls())?;
        fingerprint.configure(&mut builder)?;
        let alpn: Vec<String> = fingerprint
            .default_alpn()
            .iter()
            .map(|p| p.to_string())
            .collect();
        builder.set_alpn_protos(&super::super::tls::client::alpn_wire(&alpn)?)?;
        Ok(Self {
            server_name,
            public_key: parse_key("public_key", public_key)?,
            short_id: parse_short_id(short_id)?,
            connector: builder.build(),
            fingerprint,
            alpn,
            fragment: None,
        })
    }

    /// The ClientHello cut as `fragment` says (`tls.fragment`,
    /// `tls.record_fragment`).
    pub fn with_fragment(mut self, fragment: Option<crate::session::TlsFragment>) -> Self {
        self.fragment = fragment;
        self
    }

    pub(crate) fn connection(&self) -> io::Result<BoringConnection> {
        let mut config = self.connector.configure().map_err(io::Error::other)?;
        // The certificate is checked against the REALITY key instead.
        config.set_verify_hostname(false);
        let mut ssl = config
            .into_ssl(&self.server_name)
            .map_err(io::Error::other)?;
        // The browser's key shares include X25519MLKEM768, which REALITY
        // servers require, and X25519.
        self.fingerprint
            .configure_connection(&mut ssl, &self.alpn, false)
            .map_err(io::Error::other)?;
        // The server signs with its Ed25519 certificate, which the ClientHello
        // does not offer; accept it without listing it.
        let ed25519 = [btls_sys::SSL_SIGN_ED25519 as u16];
        // SAFETY: `ssl` is a valid SSL and `ed25519` outlives the call.
        if unsafe {
            btls_sys::SSL_set_extra_peer_verify_algorithms(ssl.as_ptr(), ed25519.as_ptr(), 1)
        } != 1
        {
            return Err(io::Error::other("set extra verify algorithms failed"));
        }
        let auth = Arc::new(Auth {
            public_key: self.public_key,
            short_id: self.short_id,
            key: Mutex::new(None),
        });
        ssl.set_ex_data(auth_index(), auth.clone());
        // SAFETY: `ssl` is a valid SSL; the callback only reads what BoringSSL
        // passes it and the ex_data set above.
        unsafe {
            btls_sys::SSL_set_client_hello_finalize_cb(ssl.as_ptr(), Some(finalize_client_hello));
        }
        ssl.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            crate::transport::tls::guarded(
                || Err(SslVerifyError::Invalid(SslAlert::INTERNAL_ERROR)),
                || {
                    verify_certificate(ssl, &auth).map_err(|e| {
                        tracing::debug!("reality: {}", e);
                        SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE)
                    })
                },
            )
        });
        BoringConnection::client(ssl)
    }
}

/// The session ID: the version, a timestamp and the short ID, sealed under
/// the key the client derives with the server's public key.
fn seal_session_id(
    auth: &Auth,
    hello: &[u8],
    random: &[u8; 32],
    x25519_private_key: &[u8; 32],
    unix_time: u32,
) -> Option<([u8; 32], [u8; 32])> {
    let mut shared = [0u8; 32];
    // SAFETY: all three buffers are 32 bytes.
    let ok = unsafe {
        btls_sys::X25519(
            shared.as_mut_ptr(),
            x25519_private_key.as_ptr(),
            auth.public_key.as_ptr(),
        )
    };
    if ok != 1 {
        return None;
    }
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(&random[..20]), &shared)
        .expand(b"REALITY", &mut key)
        .ok()?;

    let mut plaintext = Vec::with_capacity(32);
    plaintext.extend_from_slice(&CLIENT_VERSION);
    plaintext.push(0);
    plaintext.extend_from_slice(&unix_time.to_be_bytes());
    plaintext.extend_from_slice(&auth.short_id);
    Aes256Gcm::new(&key.into())
        .encrypt_in_place(random[20..].into(), hello, &mut plaintext)
        .ok()?;
    Some((plaintext.try_into().ok()?, key))
}

unsafe extern "C" fn finalize_client_hello(
    ssl: *mut btls_sys::SSL,
    hello: *const u8,
    hello_len: usize,
    client_random: *const u8,
    x25519_private_key: *const u8,
    out_session_id: *mut u8,
) -> std::os::raw::c_int {
    crate::transport::tls::guarded(
        || 0,
        // SAFETY: as the body's.
        || unsafe {
            seal_client_hello(
                ssl,
                hello,
                hello_len,
                client_random,
                x25519_private_key,
                out_session_id,
            )
        },
    )
}

/// `finalize_client_hello`'s body.
unsafe fn seal_client_hello(
    ssl: *mut btls_sys::SSL,
    hello: *const u8,
    hello_len: usize,
    client_random: *const u8,
    x25519_private_key: *const u8,
    out_session_id: *mut u8,
) -> std::os::raw::c_int {
    // SAFETY: BoringSSL passes a live SSL and buffers of the documented sizes.
    let (ssl, hello, random, private_key) = unsafe {
        (
            SslRef::from_ptr(ssl),
            std::slice::from_raw_parts(hello, hello_len),
            &*(client_random as *const [u8; 32]),
            &*(x25519_private_key as *const [u8; 32]),
        )
    };
    let Some(auth) = ssl.ex_data(auth_index()) else {
        return 0;
    };
    let now = crate::clock::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    match seal_session_id(auth, hello, random, private_key, now) {
        Some((session_id, key)) => {
            // SAFETY: `out_session_id` is 32 writable bytes.
            unsafe { std::ptr::copy_nonoverlapping(session_id.as_ptr(), out_session_id, 32) };
            *auth.key.lock().unwrap_or_else(|e| e.into_inner()) = Some(key);
            1
        }
        None => 0,
    }
}

/// Accepts only the server's throwaway Ed25519 certificate signed with the
/// connection's key. Anything else is the real site answering in the
/// server's place: the client was not authenticated.
fn verify_certificate(ssl: &mut SslRef, auth: &Auth) -> Result<()> {
    let key = auth
        .key
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .ok_or_else(|| anyhow!("no session key"))?;
    let cert = ssl
        .peer_certificate()
        .ok_or_else(|| anyhow!("no server certificate"))?;
    let public_key = cert.public_key()?;
    if public_key.id() != Id::ED25519 {
        return Err(anyhow!(
            "not authenticated: the server sent the real site's certificate"
        ));
    }
    let mut raw = [0u8; 32];
    let raw = public_key.raw_public_key(&mut raw)?;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&key).expect("HMAC takes any key size");
    mac.update(raw);
    mac.verify_slice(cert.signature().as_slice()).map_err(|_| {
        anyhow!("not authenticated: the certificate is not signed with the session key")
    })
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Next
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let mut stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        if let Some(how) = self.fragment {
            stream = Box::new(crate::transport::fragment::FragmentStream::new(stream, how));
        }
        let mut stream = TlsStream::new(self.connection()?, stream, Some(VisionState::of(sess)));
        stream
            .handshake()
            .await
            .map_err(|e| io::Error::other(format!("reality handshake failed: {}", e)))?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The REALITY ClientHello is the browser's, session ID aside.
    #[test]
    fn test_client_hello_is_the_browsers() {
        use crate::transport::tls::hello::{assert_same_hello, fixture};
        for (fingerprint, capture) in [
            (Fingerprint::Chrome, "chrome-154"),
            (Fingerprint::Firefox, "firefox-156"),
            (Fingerprint::Safari, "safari-26"),
        ] {
            let handler = Handler::new(
                "www.example.com".to_string(),
                &hex::encode([7u8; 32]),
                "ab12",
                fingerprint,
            )
            .unwrap();
            let mut conn = handler.connection().unwrap();
            let hello = crate::transport::tls::tests::first_hello(&mut conn);
            assert_same_hello(&hello, &fixture(capture));
            assert!(auth_key_set(&conn), "{:?}", fingerprint);
        }
    }

    fn auth_key_set(conn: &BoringConnection) -> bool {
        let auth = conn.ssl().ex_data(auth_index()).unwrap();
        let set = auth.key.lock().unwrap().is_some();
        set
    }

    // The server side of the derivation, as Xray does it: it must recover
    // the short ID from what the client sealed.
    #[test]
    fn test_session_id_opens_on_the_server() {
        let server_private = [3u8; 32];
        let mut server_public = [0u8; 32];
        let client_private = [5u8; 32];
        let mut client_public = [0u8; 32];
        unsafe {
            btls_sys::X25519_public_from_private(
                server_public.as_mut_ptr(),
                server_private.as_ptr(),
            );
            btls_sys::X25519_public_from_private(
                client_public.as_mut_ptr(),
                client_private.as_ptr(),
            );
        }
        let auth = Auth {
            public_key: server_public,
            short_id: [0xab, 0xcd, 0, 0, 0, 0, 0, 0],
            key: Mutex::new(None),
        };
        let random = [9u8; 32];
        let hello = vec![0x01u8; 300];
        let (session_id, key) =
            seal_session_id(&auth, &hello, &random, &client_private, 1_700_000_000).unwrap();

        // Server: ECDH with its private key, same HKDF, open with the hello
        // (session ID zeroed) as associated data.
        let mut shared = [0u8; 32];
        unsafe {
            btls_sys::X25519(
                shared.as_mut_ptr(),
                server_private.as_ptr(),
                client_public.as_ptr(),
            );
        }
        let mut server_key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&random[..20]), &shared)
            .expand(b"REALITY", &mut server_key)
            .unwrap();
        assert_eq!(server_key, key);
        let mut opened = session_id.to_vec();
        Aes256Gcm::new(&server_key.into())
            .decrypt_in_place(random[20..].into(), &hello, &mut opened)
            .unwrap();
        assert_eq!(&opened[..3], &CLIENT_VERSION);
        assert_eq!(&opened[4..8], &1_700_000_000u32.to_be_bytes());
        assert_eq!(&opened[8..16], &auth.short_id);
    }
}
