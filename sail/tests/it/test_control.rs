//! The control facade (`sail::control`) on an instance without a Clash
//! API: what hosts read and change through the FFI and the command
//! service, from the same sources the Clash API reads.
#![cfg(all(
    feature = "outbound-select",
    feature = "outbound-direct",
    feature = "inbound-socks"
))]

use std::time::Duration;

use sail::control::ControlError;
use sail::session::{Session, SocksAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common;

/// A server answering every request `204 No Content`, as a delay test's
/// URL does.
async fn no_content_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    addr
}

#[test]
fn an_instance_is_controlled_without_a_clash_api() {
    let socks_port = common::free_port();
    let config = serde_json::json!({
        "inbounds": [{
            "type": "socks", "tag": "socks-in",
            "listen": "127.0.0.1", "listen_port": socks_port,
        }],
        "outbounds": [
            { "type": "selector", "tag": "sel", "outbounds": ["a", "b"] },
            { "type": "direct", "tag": "a" },
            { "type": "direct", "tag": "b" },
        ],
        "route": { "final": "sel" },
    })
    .to_string();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ids = common::run_sail_instances(&rt, vec![config]).unwrap();
    let rm = sail::runtime_managers().get(&ids[0]).cloned().unwrap();

    rt.block_on(async {
        // The outbounds, in the configuration's order.
        let tags: Vec<String> = rm.outbounds().await.into_iter().map(|o| o.tag).collect();
        assert_eq!(tags, ["sel", "a", "b"]);
        // The group and its members.
        let groups = rm.groups().await;
        assert_eq!(groups.len(), 1);
        let sel = groups[0].group.clone().unwrap();
        assert_eq!(groups[0].kind, "Selector");
        assert_eq!((sel.selected.as_str(), sel.selectable), ("a", true));
        assert_eq!(sel.members, ["a", "b"]);
        assert_eq!(
            rm.outbound("b").await.unwrap().protocol.as_deref(),
            Some("direct")
        );
        assert!(rm.outbound("nothing").await.is_none());

        // Selecting.
        rm.select("sel", "b").await.unwrap();
        assert_eq!(
            rm.outbound("sel").await.unwrap().group.unwrap().selected,
            "b"
        );
        assert!(matches!(
            rm.select("sel", "c").await,
            Err(ControlError::Rejected(_))
        ));
        assert!(matches!(
            rm.select("a", "b").await,
            Err(ControlError::NotSelector(_))
        ));
        assert!(matches!(
            rm.select("nothing", "a").await,
            Err(ControlError::NotFound(_))
        ));

        // Delays are kept, a failure too, without a Clash API to keep them.
        let server = no_content_server().await;
        let url = format!("http://{}/generate_204", server);
        let delay = rm
            .url_test("a", Some(&url), Duration::from_secs(5))
            .await
            .unwrap();
        assert!(delay >= Duration::from_millis(1));
        let closed = format!("http://127.0.0.1:{}/", common::free_port());
        assert!(matches!(
            rm.url_test("a", Some(&closed), Duration::from_secs(5))
                .await,
            Err(ControlError::Failed(_))
        ));
        let history = rm.outbound("a").await.unwrap().history;
        assert_eq!(history.len(), 2);
        assert!(history[0].delay.is_some() && history[1].delay.is_none());
        assert!(matches!(
            rm.url_test("nothing", Some(&url), Duration::from_secs(5))
                .await,
            Err(ControlError::NotFound(_))
        ));
        let members = rm
            .url_test_members("sel", Some(&url), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.iter().all(|(_, d)| d.is_ok()));

        // No Clash API: no mode, as in sing-box.
        assert_eq!(rm.mode(), None);
        assert!(matches!(rm.set_mode("Global"), Err(ControlError::NoModes)));

        // A connection, counted, listed and closed.
        let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await.unwrap();
        tokio::spawn(serve);
        let sess = Session {
            destination: SocksAddr::from(echo),
            ..Default::default()
        };
        let mut s = common::new_socks_stream("127.0.0.1", socks_port, &sess, None, None)
            .await
            .unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        let connections = rm.connections().await;
        assert_eq!(connections.len(), 1);
        let c = &connections[0];
        assert_eq!(c.inbound_tag, "socks-in");
        assert_eq!(c.destination, SocksAddr::from(echo));
        assert_eq!(c.chains.last().map(String::as_str), Some("sel"));
        let counts = common::settled((4, 4), || async {
            let c = &rm.connections().await[0];
            (c.upload, c.download)
        })
        .await;
        assert_eq!(counts, (4, 4));
        let traffic = rm.traffic().await;
        assert_eq!(traffic.connections, 1);
        assert!(traffic.up_total >= 4 && traffic.down_total >= 4);
        assert!(rm.close_connection(c.id).await);
        assert!(!rm.close_connection(u64::MAX).await);
        // Closed: the relay ends, and the client reads the end.
        let read = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))), "{:?}", read);
    });

    common::shutdown_instances(&rt, ids);
}
