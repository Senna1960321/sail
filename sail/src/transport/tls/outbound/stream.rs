use std::io;

use anyhow::Result;
use async_trait::async_trait;
use tracing::trace;

use super::super::client::{Identity, TlsClient};
use super::super::ech::decode_ech_config_list;
use super::super::fingerprint::Fingerprint;
use super::super::options::ClientOptions;
use super::super::BoringConnection;
use crate::transport::tls_stream::TlsStream;
use crate::{adapter::*, app::SyncDnsClient, session::Session, transport::vision::VisionState};

pub struct Handler {
    server_name: String,
    client: TlsClient,
    ech: Option<Ech>,
    dns_client: SyncDnsClient,
    /// How the ClientHello is cut, if it is.
    fragment: Option<crate::session::TlsFragment>,
}

struct Ech {
    /// The configured ECHConfigList: when set, the only one offered.
    config_list: Option<Vec<u8>>,
    disable_dns_lookup: bool,
}

impl Handler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_name: String,
        alpns: Vec<String>,
        certificate: Option<String>,
        insecure: bool,
        fingerprint: Option<Fingerprint>,
        disable_sni: bool,
        identity: Option<&Identity>,
        ech: bool,
        ech_disable_dns_lookup: bool,
        ech_config_list: Option<String>,
        dns_client: SyncDnsClient,
        roots: &crate::transport::tls::roots::Roots,
        options: &ClientOptions,
    ) -> Result<Self> {
        let ech_config_list = ech_config_list
            .as_deref()
            .map(decode_ech_config_list)
            .transpose()?;
        let mut client = TlsClient::with_options(
            &alpns,
            certificate.as_deref(),
            insecure,
            fingerprint,
            roots,
            identity,
            options,
        )?;
        if disable_sni {
            client = client.without_sni();
        }
        Ok(Handler {
            server_name,
            client,
            ech: ech.then_some(Ech {
                config_list: ech_config_list,
                disable_dns_lookup: ech_disable_dns_lookup,
            }),
            dns_client,
            fragment: None,
        })
    }

    /// The ClientHello cut as `fragment` says (`tls.fragment`,
    /// `tls.record_fragment`).
    pub fn with_fragment(mut self, fragment: Option<crate::session::TlsFragment>) -> Self {
        self.fragment = fragment;
        self
    }

    /// TLS over `stream` for `sess`, as `handle` makes it, the stream as it
    /// is: for a protocol that reads what the handshake negotiated, its
    /// ALPN.
    pub async fn connect_tls(
        &self,
        sess: &Session,
        stream: AnyStream,
    ) -> io::Result<TlsStream<BoringConnection, AnyStream>> {
        let name = if !self.server_name.is_empty() {
            self.server_name.clone()
        } else {
            sess.destination.host()
        };
        let ech_config_list = self.select_ech_config_list(&name, sess).await?;
        let stream: AnyStream = match self.fragment {
            Some(how) => Box::new(crate::transport::fragment::FragmentStream::new(stream, how)),
            None => stream,
        };
        trace!(
            "handling TLS {}, ech_enabled={}, ech_config_selected={}",
            &name,
            self.ech.is_some(),
            ech_config_list.is_some()
        );
        let tls_stream = self
            .client
            .connect(
                &name,
                stream,
                Some(VisionState::of(sess)),
                ech_config_list.as_deref(),
            )
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("connect tls failed: {}", e),
                )
            })?;
        Ok(tls_stream)
    }

    /// The DNS client's own connections must not look ECH up in DNS.
    fn should_skip_ech_dns_lookup_for_session(sess: &Session) -> bool {
        sess.inbound_tag == "dnsclient"
    }

    /// The ECHConfigList to offer to `name`, if any. As in sing-box, a
    /// configured one is used as it is, and DNS is asked only without one
    /// (its common/tls/ech.go, parseECHClientConfig): no HTTPS record to
    /// override it, nor any query to give the name away. What DNS fails to
    /// give fails the connection, as there.
    async fn select_ech_config_list(
        &self,
        name: &str,
        sess: &Session,
    ) -> io::Result<Option<Vec<u8>>> {
        let Some(ech) = &self.ech else {
            return Ok(None);
        };
        if let Some(list) = &ech.config_list {
            trace!("ech source for {}: the configured one", name);
            return Ok(Some(list.clone()));
        }
        if ech.disable_dns_lookup || Self::should_skip_ech_dns_lookup_for_session(sess) {
            trace!("ech source for {}: none (no dns lookup)", name);
            return Ok(None);
        }
        let dns_client = self.dns_client.load_full();
        let list = dns_client
            .lookup_ech_config_list(name)
            .await
            .map_err(|e| io::Error::other(format!("ech fetch failed for {}: {}", name, e)))?;
        trace!("ech source for {}: https/svcb dns record", name);
        decode_ech_config_list(&list).map(Some)
    }
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
        trace!("handling outbound stream");
        let stream = stream.ok_or_else(|| io::Error::other("invalid tls input"))?;
        Ok(Box::new(self.connect_tls(sess, stream).await?))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use crate::app::{dns::DnsClient, SyncDnsClient};
    use crate::session::Session;

    use super::Handler;

    fn new_test_dns_client() -> SyncDnsClient {
        let dns = crate::config::Dns::default();
        DnsClient::new(&dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared()
    }

    /// A UDP DNS server answering every query NXDOMAIN, and the queries it
    /// has had.
    async fn counting_server() -> (u16, Arc<AtomicUsize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let queries = Arc::new(AtomicUsize::new(0));
        let counted = queries.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                counted.fetch_add(1, Ordering::SeqCst);
                // The query, as a response with NXDOMAIN.
                let mut reply = buf[..n].to_vec();
                reply[2] |= 0x80;
                reply[3] = (reply[3] & 0xf0) | 3;
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        (port, queries)
    }

    fn ech_handler(port: u16, ech_config: Option<&str>, disable_dns_lookup: bool) -> Handler {
        let config = crate::config::Config::from_json(
            &serde_json::json!({ "dns": { "timeout": "2s", "servers": [
                { "type": "udp", "tag": "u", "server": "127.0.0.1", "server_port": port },
            ] } })
            .to_string(),
        )
        .unwrap();
        let dns = DnsClient::new(&config.dns, Default::default(), &Default::default())
            .unwrap()
            .into_shared();
        Handler::new(
            "example.com".to_string(),
            vec![],
            None,
            false,
            None,
            false,
            None,
            true,
            disable_dns_lookup,
            ech_config.map(str::to_string),
            dns,
            &crate::transport::tls::tests::test_roots(),
            &Default::default(),
        )
        .unwrap()
    }

    /// As in sing-box, a configured ECHConfigList is the one offered, and
    /// DNS is not asked for another.
    #[tokio::test]
    async fn a_configured_ech_config_is_used_without_asking_dns() {
        let (port, queries) = counting_server().await;
        let handler = ech_handler(port, Some("AAT+DQBB"), false);
        let list = handler
            .select_ech_config_list("example.com", &Session::default())
            .await
            .unwrap();
        assert_eq!(list, Some(vec![0x00, 0x04, 0xfe, 0x0d, 0x00, 0x41]));
        assert_eq!(queries.load(Ordering::SeqCst), 0, "DNS was asked");
    }

    /// Without one, DNS is asked, and a failed lookup fails the connection,
    /// as in sing-box, rather than going without ECH.
    #[tokio::test]
    async fn without_a_configured_ech_config_a_failed_lookup_fails() {
        let (port, queries) = counting_server().await;
        let handler = ech_handler(port, None, false);
        let err = handler
            .select_ech_config_list("example.com", &Session::default())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("ech fetch failed for example.com"),
            "{}",
            err
        );
        assert!(queries.load(Ordering::SeqCst) > 0);
    }

    /// `disable_dns_lookup` keeps DNS out of it.
    #[tokio::test]
    async fn with_the_dns_lookup_disabled_dns_is_not_asked() {
        let (port, queries) = counting_server().await;
        let handler = ech_handler(port, None, true);
        let list = handler
            .select_ech_config_list("example.com", &Session::default())
            .await
            .unwrap();
        assert_eq!(list, None);
        assert_eq!(queries.load(Ordering::SeqCst), 0, "DNS was asked");
    }

    /// A transport that keeps what each write handed it, apart.
    struct Tap {
        inner: tokio::io::DuplexStream,
        writes: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl tokio::io::AsyncRead for Tap {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for Tap {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = &mut *self;
            let n = futures::ready!(std::pin::Pin::new(&mut this.inner).poll_write(cx, buf))?;
            this.writes.lock().unwrap().push(buf[..n].to_vec());
            std::task::Poll::Ready(Ok(n))
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// The TLS records `bytes` begins with, type and body each, as far as
    /// they are whole.
    fn records(mut bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut records = Vec::new();
        while bytes.len() >= 5 {
            let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
            if bytes.len() < 5 + len {
                break;
            }
            records.push((bytes[0], bytes[5..5 + len].to_vec()));
            bytes = &bytes[5 + len..];
        }
        records
    }

    /// The writes a real TLS client made with `fragment`, against a real
    /// server, after the handshake and a round trip.
    async fn handshake_cut(fragment: crate::session::TlsFragment) -> Vec<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (acceptor, pem) =
            crate::transport::tls::tests::acceptor_picking(b"h2", Default::default());
        let handler = Handler::new(
            "localhost".to_string(),
            vec![],
            Some(pem),
            false,
            Some(crate::transport::tls::Fingerprint::Chrome),
            false,
            None,
            false,
            false,
            None,
            new_test_dns_client(),
            &crate::transport::tls::tests::test_roots(),
            &Default::default(),
        )
        .unwrap()
        .with_fragment(Some(fragment));
        let (c, s) = tokio::io::duplex(64 * 1024);
        let writes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let tap = Tap {
            inner: c,
            writes: writes.clone(),
        };
        let sess = Session::default();
        let (client, server) = tokio::join!(
            handler.connect_tls(&sess, Box::new(tap)),
            crate::transport::tls::tests::accept(&acceptor, s),
        );
        let (mut client, mut server) = (client.unwrap(), server.unwrap());
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        let mut made = Vec::new();
        made.extend(writes.lock().unwrap().iter().cloned());
        made
    }

    /// The ClientHello the handshake records of `bytes` carry, checked to
    /// name `localhost` whole while no record does.
    fn assert_hello_cut(records: &[(u8, Vec<u8>)]) {
        assert!(records.len() >= 2, "{} records", records.len());
        let mut handshake = Vec::new();
        for (kind, body) in records {
            assert_eq!(*kind, 22, "a handshake record");
            assert!(
                !body.windows(9).any(|w| w == b"localhost"),
                "a record holds the whole name"
            );
            handshake.extend_from_slice(body);
        }
        assert_eq!(handshake[0], 1, "a ClientHello");
        let len =
            (handshake[1] as usize) << 16 | (handshake[2] as usize) << 8 | handshake[3] as usize;
        assert_eq!(
            handshake.len(),
            4 + len,
            "the whole ClientHello and no more"
        );
        assert!(handshake.windows(9).any(|w| w == b"localhost"));
    }

    /// `record_fragment`: the ClientHello goes out as two TLS records in one
    /// write, and the handshake completes.
    #[tokio::test]
    async fn record_fragment_sends_the_hello_as_records_in_one_write() {
        let writes = handshake_cut(crate::session::TlsFragment {
            records: true,
            segments: None,
        })
        .await;
        let first = records(&writes[0]);
        assert_eq!(first.len(), 2);
        assert_eq!(
            first.iter().map(|(_, b)| 5 + b.len()).sum::<usize>(),
            writes[0].len(),
            "the first write is the two records and nothing else"
        );
        assert_hello_cut(&first);
    }

    /// `fragment` with `record_fragment`: each record a write of its own.
    #[tokio::test]
    async fn fragment_and_record_fragment_send_a_record_a_write() {
        let writes = handshake_cut(crate::session::TlsFragment {
            records: true,
            segments: Some(std::time::Duration::from_millis(10)),
        })
        .await;
        let mut cut = Vec::new();
        for write in &writes[..2] {
            let records = records(write);
            assert_eq!(records.len(), 1);
            assert_eq!(5 + records[0].1.len(), write.len());
            cut.extend(records);
        }
        assert_hello_cut(&cut);
    }

    /// `fragment` alone: one record, cut across two writes.
    #[tokio::test]
    async fn fragment_sends_one_record_in_two_writes() {
        let writes = handshake_cut(crate::session::TlsFragment {
            records: false,
            segments: Some(std::time::Duration::from_millis(10)),
        })
        .await;
        for write in &writes[..2] {
            assert!(!write.windows(9).any(|w| w == b"localhost"));
        }
        let joined = [writes[0].clone(), writes[1].clone()].concat();
        let hello = records(&joined);
        assert_eq!(hello.len(), 1);
        assert_eq!(5 + hello[0].1.len(), joined.len());
        assert!(hello[0].1.windows(9).any(|w| w == b"localhost"));
    }

    #[test]
    fn test_should_skip_ech_dns_lookup_for_dnsclient_session() {
        let sess = |tag: &str| Session {
            inbound_tag: tag.to_string(),
            ..Default::default()
        };
        assert!(Handler::should_skip_ech_dns_lookup_for_session(&sess(
            "dnsclient"
        )));
        assert!(!Handler::should_skip_ech_dns_lookup_for_session(&sess(
            "socks"
        )));
    }

    #[test]
    fn test_new_with_invalid_ech_config_list_fails() {
        let result = Handler::new(
            "localhost".to_string(),
            vec![],
            None,
            false,
            None,
            false,
            None,
            true,
            false,
            Some("$$$".to_string()),
            new_test_dns_client(),
            &crate::transport::tls::tests::test_roots(),
            &Default::default(),
        );
        assert!(result.is_err());
    }
}
