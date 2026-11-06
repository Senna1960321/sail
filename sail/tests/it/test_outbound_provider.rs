#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

#[cfg(all(
    feature = "outbound-direct",
    feature = "outbound-socks",
    feature = "outbound-select",
    feature = "outbound-provider"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_provider_urls_are_fetched_on_restart_and_reload() -> anyhow::Result<()> {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use sail::embed::{Config, Instance, Options, Threads};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut byte = [0];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read_exact(&mut byte).await.is_err() {
                    return;
                }
                head.push(byte[0]);
                assert!(head.len() < 8192);
            }
            let head = String::from_utf8(head).unwrap();
            let path = head.split_whitespace().nth(1).unwrap().to_string();
            let etag = head.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("If-None-Match")
                    .then(|| value.trim().to_string())
            });
            observed.lock().unwrap().push((path.clone(), etag.clone()));
            let version = format!("\"{}\"", path);
            let response = if etag.as_deref() == Some(version.as_str()) {
                "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n".to_string()
            } else {
                let names: &[&str] = if path == "/old.yaml" {
                    &["old-node"]
                } else {
                    &["new-node-a", "new-node-b"]
                };
                let mut body = "proxies:\n".to_string();
                for name in names {
                    body.push_str(&format!(
                        "  - {{name: {}, type: socks5, server: 127.0.0.1, port: 12345}}\n",
                        name
                    ));
                }
                let userinfo = if path == "/old.yaml" {
                    "Subscription-Userinfo: upload=1; download=2; total=100\r\n"
                } else {
                    ""
                };
                format!(
                    "HTTP/1.1 200 OK\r\nETag: {}\r\n{}Content-Length: {}\r\n\r\n{}",
                    version,
                    userinfo,
                    body.len(),
                    body
                )
            };
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    let config = |path: &str| {
        Config::Json(
            serde_json::json!({
                "outbounds": [
                    { "type": "direct", "tag": "direct" },
                    { "type": "selector", "tag": "pick", "providers": "subscription" }
                ],
                "outbound_providers": [{
                    "type": "remote", "tag": "subscription",
                    "url": format!("http://{}{}", addr, path), "update_interval": "24h"
                }]
            })
            .to_string(),
        )
    };

    for reload in [false, true] {
        let dir = common::TempDir::new("provider-url")?;
        let options = || Options::new().threads(Threads::One).cache_dir(dir.path());
        let instance = Instance::new(options())?;
        requests.lock().unwrap().clear();
        tokio::time::timeout(Duration::from_secs(5), instance.start(config("/old.yaml"))).await??;
        assert_eq!(instance.providers().await?[0].members, 1);
        assert!(instance.providers().await?[0].subscription.is_some());
        let instance = if reload {
            tokio::time::timeout(
                Duration::from_secs(5),
                instance.reload(Some(config("/new.yaml"))),
            )
            .await??;
            instance
        } else {
            instance.stop().await?;
            let instance = Instance::new(options())?;
            tokio::time::timeout(Duration::from_secs(5), instance.start(config("/new.yaml")))
                .await??;
            instance
        };
        // At a live reload, providers with no copy are fetched by the
        // updater, which waits at least a second between runs. They may
        // be empty meanwhile, but must never serve the previous source.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let members = instance
                    .outbound("pick")
                    .await?
                    .unwrap()
                    .group
                    .unwrap()
                    .members;
                if members == ["new-node-a", "new-node-b"] {
                    break anyhow::Ok(());
                }
                assert!(
                    members.is_empty(),
                    "reload={reload}: kept old nodes: {members:?}"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        assert!(instance.providers().await?[0].subscription.is_none());
        assert_eq!(
            *requests.lock().unwrap(),
            [
                ("/old.yaml".to_string(), None),
                ("/new.yaml".to_string(), None),
            ]
        );
        instance.stop().await?;

        // A valid same-source cache still avoids a fetch at startup and
        // supplies its ETag for a later conditional update.
        let cached = Instance::new(options())?;
        tokio::time::timeout(Duration::from_secs(5), cached.start(config("/new.yaml"))).await??;
        assert_eq!(cached.providers().await?[0].members, 2);
        assert_eq!(requests.lock().unwrap().len(), 2);
        tokio::time::timeout(
            Duration::from_secs(5),
            cached.update_provider("subscription"),
        )
        .await??;
        assert_eq!(
            requests.lock().unwrap().last().unwrap(),
            &("/new.yaml".to_string(), Some("\"/new.yaml\"".to_string()))
        );
        assert_eq!(cached.providers().await?[0].members, 2);
        cached.stop().await?;
    }
    server.abort();
    Ok(())
}

// A selector over the members of a local provider: traffic passes through
// the one selected; one gone from the file leaves the selection to the
// default until it is back; a reload keeps the members and the selection.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-select",
    feature = "outbound-provider"
))]
#[test]
fn a_selector_follows_its_provider() -> anyhow::Result<()> {
    common::retry_port_clash(|| {
        let [port, first, second] = common::free_ports();
        a_selector_follows_its_provider_on(port, first, second)
    })
}

/// The test above, with the instance's inbound on `port`, and the socks
/// servers the provider gives on `first` and `second`.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-socks",
    feature = "outbound-direct",
    feature = "outbound-select",
    feature = "outbound-provider"
))]
fn a_selector_follows_its_provider_on(port: u16, first: u16, second: u16) -> anyhow::Result<()> {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = common::TempDir::new("provider")?;
    let proxies = dir.join("proxies.yaml");
    let write_proxies = |names: &[&str]| {
        let lines: Vec<String> = names
            .iter()
            .map(|name| {
                let port = if *name == "A" { first } else { second };
                format!(
                    "  - {{ name: {}, type: socks5, server: 127.0.0.1, port: {} }}\n",
                    name, port
                )
            })
            .collect();
        std::fs::write(&proxies, format!("proxies:\n{}", lines.concat()))
    };
    write_proxies(&["A", "B"])?;
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        format!(
            r#"{{
                "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {port} }}],
                "outbounds": [
                    {{ "type": "selector", "tag": "pick", "providers": "subscription",
                       "default": "A" }},
                    {{ "type": "direct" }}
                ],
                "outbound_providers": [{{
                    "type": "local", "tag": "subscription", "path": "{}",
                    "update_interval": "1s"
                }}]
            }}"#,
            crate::common::json_path(&proxies)
        ),
    )?;
    let server = |port: u16| {
        format!(
            r#"{{
                "inbounds": [{{ "type": "socks", "listen": "127.0.0.1", "listen_port": {port} }}],
                "outbounds": [{{ "type": "direct" }}]
            }}"#
        )
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let servers = common::run_sail_instances(&rt, vec![server(first), server(second)])?;
    let id = common::next_rt_id();
    let opts = sail::StartOptions {
        signals: false,
        config: sail::Config::File(path.to_string_lossy().to_string()),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: sail::RuntimeOption::SingleThread,
        runtime: common::runtime_options(),
        // The selection is kept here.
        host: sail::runtime::Host {
            data_dir: Some(dir.path().to_path_buf()),
            cache_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        },
    };
    if let Err(e) = common::start_instance(id, opts) {
        common::shutdown_instances(&rt, servers);
        return Err(e);
    }
    let manager = sail::runtime_managers()
        .get(&id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no runtime manager"))?;

    let result = rt.block_on(async {
        let (echo_addr, echo) = common::run_tcp_echo_server("127.0.0.1:0").await?;
        tokio::spawn(echo);
        let sess = sail::session::Session {
            destination: sail::session::SocksAddr::from(echo_addr),
            ..Default::default()
        };
        let relayed = || async {
            let mut stream = common::new_socks_stream("127.0.0.1", port, &sess, None, None).await?;
            stream.write_all(b"ping").await?;
            let mut buf = [0u8; 4];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf)).await??;
            anyhow::ensure!(&buf == b"ping", "echoed {:?}", buf);
            anyhow::Ok(())
        };
        let members = || async {
            manager
                .get_outbound_selects("pick")
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))
        };
        let selected = || async {
            manager
                .get_outbound_selected("pick")
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))
        };
        // The file is read again every second.
        let members_become = |expected: &'static [&'static str]| async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let now = members().await?;
                if now == expected {
                    return anyhow::Ok(());
                }
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "members {:?}, not {:?}",
                    now,
                    expected
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        anyhow::ensure!(members().await? == ["A", "B"]);
        anyhow::ensure!(selected().await? == "A", "the default first");
        relayed().await?;

        manager
            .set_outbound_selected("pick", "B")
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        anyhow::ensure!(selected().await? == "B");
        relayed().await?;

        write_proxies(&["A"])?;
        members_become(&["A"]).await?;
        anyhow::ensure!(selected().await? == "A", "the default while B is gone");
        relayed().await?;

        write_proxies(&["A", "B"])?;
        members_become(&["A", "B"]).await?;
        anyhow::ensure!(selected().await? == "B", "B again once it is back");
        relayed().await?;

        let reload = tokio::task::spawn_blocking(move || sail::reload(id)).await?;
        anyhow::ensure!(reload.is_ok(), "the reload failed: {:?}", reload.err());
        anyhow::ensure!(members().await? == ["A", "B"], "kept across the reload");
        anyhow::ensure!(selected().await? == "B", "selected across the reload");
        relayed().await?;
        anyhow::Ok(())
    });
    assert!(sail::shutdown(id));
    common::shutdown_instances(&rt, servers);
    result
}
