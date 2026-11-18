//! The ShadowTLS outbound: a TLS handshake with the site the server
//! imitates, in the ClientHello of which the client authenticates, then the
//! data phase over the same connection. Another outbound goes through it by
//! naming it as its `detour`, as in sing-box.

use std::io;
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use btls::ex_data::Index;
use btls::ssl::{Ssl, SslRef};
use bytes::BytesMut;
use foreign_types::ForeignTypeRef;
use serde_derive::Deserialize;
use tokio::io::AsyncWriteExt;

use super::{
    check_version, data_hmac, server_random, Records, SiteRecords, VerifiedStream,
    APPLICATION_DATA, HANDSHAKE, HEADER_LEN, SERVER_HELLO,
};
use crate::adapter::outbound::HandlerBuilder;
use crate::adapter::registry::{OutboundContext, OutboundFactory, OutboundRegistry};
use crate::adapter::*;
use crate::session::{Network, Session};
use crate::transport::layers::{trusted_certificate, Blocks, Listable, OutboundTls};
use crate::transport::tls::{BoringConnection, TlsClient};
use crate::transport::tls_stream::TlsConnection;

pub(crate) fn register(registry: &mut OutboundRegistry) {
    registry.register(
        "shadowtls",
        OutboundFactory::standalone(build).with_blocks(Blocks::DIALER),
    );
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowTlsOutboundOptions {
    server: String,
    server_port: u16,
    /// Must be 3: versions 1 and 2 are not supported. sing-box's default
    /// is 1.
    #[serde(default = "version_one")]
    version: u32,
    /// Cannot be empty.
    #[serde(default)]
    password: String,
    /// Must be enabled: the handshake with the site the server imitates,
    /// `server_name` being the site's (the server's address when unset).
    /// A browser fingerprint, disable_sni and a client certificate apply
    /// as for TLS; REALITY and ECH do not.
    #[serde(default)]
    tls: Option<OutboundTls>,
}

fn version_one() -> u32 {
    1
}

fn build(ctx: &mut OutboundContext<'_>) -> Result<AnyOutboundHandler> {
    let tag = ctx.tag;
    let options: ShadowTlsOutboundOptions = ctx.options()?;
    check_version(options.version).map_err(|e| anyhow!("[{}] outbound: version: {}", tag, e))?;
    if options.password.is_empty() {
        return Err(anyhow!("[{}] outbound: password: cannot be empty", tag));
    }
    let tls = options
        .tls
        .filter(|t| t.enabled)
        .ok_or_else(|| anyhow!("[{}] outbound: tls: ShadowTLS needs it enabled", tag))?;
    if tls.reality.as_ref().is_some_and(|r| r.enabled) {
        return Err(anyhow!(
            "[{}] outbound: tls.reality: not with ShadowTLS, which authenticates in the session ID itself",
            tag
        ));
    }
    if tls.ech.as_ref().is_some_and(|e| e.enabled) {
        return Err(anyhow!(
            "[{}] outbound: tls.ech: not with ShadowTLS, whose ClientHello the server reads",
            tag
        ));
    }
    if tls.fragment || tls.record_fragment {
        return Err(anyhow!(
            "[{}] outbound: tls.fragment, tls.record_fragment: not with ShadowTLS, whose \
             ClientHello the server reads",
            tag
        ));
    }
    let identity = tls
        .client_identity(ctx.env)
        .map_err(|e| anyhow!("[{}] outbound: tls.{}", tag, e))?;
    let tls_options = tls
        .stream_options(&format!("[{}] outbound", tag))
        .map_err(|e| anyhow!("[{}] outbound: tls.{}", tag, e))?;
    let mut client = TlsClient::with_options(
        &tls.alpn.clone().map(Listable::into_vec).unwrap_or_default(),
        trusted_certificate(&tls, ctx.env).as_deref(),
        tls.insecure,
        tls.fingerprint(tag)?,
        &ctx.env.tls_roots.get()?,
        identity.as_ref(),
        &tls_options,
    )
    .map_err(|e| anyhow!("[{}] outbound: tls: {}", tag, e))?;
    if tls.disable_sni {
        client = client.without_sni();
    }
    let handler = Handler {
        server: options.server.clone(),
        port: options.server_port,
        dialer: ctx.dialer.clone(),
        server_name: tls.server_name.clone().unwrap_or(options.server),
        password: options.password.into_bytes().into(),
        client,
    };
    Ok(HandlerBuilder::default()
        .tag(tag.to_owned())
        .stream_handler(Arc::new(handler))
        .build())
}

pub struct Handler {
    server: String,
    port: u16,
    dialer: crate::net::Dialer,
    server_name: String,
    password: Arc<[u8]>,
    client: TlsClient,
}

fn password_index() -> Index<Ssl, Arc<[u8]>> {
    static INDEX: OnceLock<Index<Ssl, Arc<[u8]>>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().expect("allocate an SSL ex_data index"))
}

/// Signs the ClientHello: see `super::session_id`.
unsafe extern "C" fn finalize_client_hello(
    ssl: *mut btls_sys::SSL,
    hello: *const u8,
    hello_len: usize,
    _client_random: *const u8,
    _x25519_private_key: *const u8,
    out_session_id: *mut u8,
) -> std::os::raw::c_int {
    crate::transport::tls::guarded(
        || 0,
        // SAFETY: as the body's.
        || unsafe { sign_client_hello(ssl, hello, hello_len, out_session_id) },
    )
}

/// `finalize_client_hello`'s body.
unsafe fn sign_client_hello(
    ssl: *mut btls_sys::SSL,
    hello: *const u8,
    hello_len: usize,
    out_session_id: *mut u8,
) -> std::os::raw::c_int {
    // SAFETY: BoringSSL passes a live SSL and buffers of the documented sizes.
    let (ssl, hello) = unsafe {
        (
            SslRef::from_ptr(ssl),
            std::slice::from_raw_parts(hello, hello_len),
        )
    };
    let Some(password) = ssl.ex_data(password_index()) else {
        return 0;
    };
    let random: [u8; 28] = rand::random();
    match super::session_id(password, hello, random) {
        Ok(session_id) => {
            // SAFETY: `out_session_id` is 32 writable bytes.
            unsafe { std::ptr::copy_nonoverlapping(session_id.as_ptr(), out_session_id, 32) };
            1
        }
        Err(_) => 0,
    }
}

impl Handler {
    fn connection(&self) -> io::Result<BoringConnection> {
        let password = self.password.clone();
        self.client
            .connection_with(&self.server_name, None, move |ssl| {
                ssl.set_ex_data(password_index(), password);
                // SAFETY: `ssl` is a valid SSL; the callback reads only what
                // BoringSSL passes it and the ex_data set above.
                unsafe {
                    btls_sys::SSL_set_client_hello_finalize_cb(
                        ssl.as_ptr(),
                        Some(finalize_client_hello),
                    );
                }
                Ok(())
            })
    }

    /// Runs the handshake over `stream` and returns the connection for the
    /// data phase.
    pub(crate) async fn connect<S>(&self, mut stream: S) -> io::Result<VerifiedStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut conn = self.connection()?;
        let mut records = Records::default();
        // Set by the ServerHello.
        let mut site: Option<(SiteRecords, [u8; 32])> = None;
        let mut authorized = false;
        loop {
            while conn.wants_write() {
                let mut out = Vec::new();
                conn.write_tls(&mut out)?;
                stream.write_all(&out).await?;
            }
            if !conn.is_handshaking() {
                break;
            }
            let mut record = records.expect(&mut stream).await?;
            match record[0] {
                // Only the first: after a HelloRetryRequest the server keeps
                // the chain it started.
                HANDSHAKE if site.is_none() && record.get(HEADER_LEN) == Some(&SERVER_HELLO) => {
                    if let Some(random) = server_random(&record) {
                        if !super::picks_tls13(&record) {
                            authorized = true;
                        }
                        site = Some((SiteRecords::new(&self.password, &random), random));
                    }
                }
                APPLICATION_DATA => {
                    authorized = false;
                    if let Some((marks, _)) = &mut site {
                        if record.len() > super::TAGGED_HEADER_LEN {
                            record = marks.unmark(record).ok_or_else(|| {
                                io::Error::other(
                                    "shadowtls: the site's record is not marked: \
                                     wrong password, or not a ShadowTLS v3 server",
                                )
                            })?;
                            authorized = true;
                        }
                    }
                }
                _ => {}
            }
            let mut rest = &record[..];
            while !rest.is_empty() {
                if conn.read_tls(&mut rest)? == 0 {
                    return Err(io::Error::other("shadowtls: TLS read buffer full"));
                }
                conn.process_new_packets()?;
            }
            conn.process_new_packets()?;
        }
        let Some((marks, random)) = site.filter(|_| authorized) else {
            return Err(io::Error::other(
                "shadowtls: the handshake was not the server's: traffic hijacked",
            ));
        };
        Ok(VerifiedStream::new(
            stream,
            data_hmac(&self.password, &random, b"C"),
            data_hmac(&self.password, &random, b"S"),
            Some(marks),
            records.into_inner(),
            BytesMut::new(),
        ))
    }
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Proxy(
            Network::Tcp,
            self.server.clone(),
            self.port,
            self.dialer.clone(),
        )
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        tracing::trace!("handling outbound stream");
        let stream = stream.ok_or_else(|| io::Error::other("invalid input"))?;
        Ok(Box::new(self.connect(stream).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler(fingerprint: Option<crate::transport::tls::Fingerprint>) -> Handler {
        Handler {
            server: "127.0.0.1".into(),
            port: 443,
            dialer: crate::net::Dialer::system(),
            server_name: "www.example.com".into(),
            password: Arc::from(&b"pw"[..]),
            client: TlsClient::new(
                &[],
                None,
                false,
                fingerprint,
                &crate::transport::tls::tests::test_roots(),
            )
            .unwrap(),
        }
    }

    // The ClientHello is signed, with each browser fingerprint and with
    // BoringSSL's own, and is otherwise the browser's.
    #[test]
    fn test_client_hello_is_signed() {
        use crate::transport::tls::hello::{assert_same_hello, fixture, ClientHello};
        use crate::transport::tls::Fingerprint;
        for (fingerprint, capture) in [
            (None, None),
            (Some(Fingerprint::Chrome), Some("chrome-154")),
            (Some(Fingerprint::Firefox), Some("firefox-156")),
            (Some(Fingerprint::Safari), Some("safari-26")),
        ] {
            let mut conn = handler(fingerprint).connection().unwrap();
            let mut frame = vec![];
            while conn.wants_write() {
                conn.write_tls(&mut frame).unwrap();
            }
            let passwords: [&[u8]; 1] = [b"pw"];
            assert_eq!(
                super::super::authenticate(&frame, passwords),
                Ok(0),
                "{:?}",
                fingerprint
            );
            assert_eq!(
                super::super::server_name(&frame).as_deref(),
                Some("www.example.com")
            );
            if let Some(capture) = capture {
                assert_same_hello(&ClientHello::from_records(&frame), &fixture(capture));
            }
        }
    }
}
