#[allow(unused_imports)] // Unused where features leave out every test.
use crate::common;

// A changed URL must fetch its own rules even while the previous URL's
// cache is fresh. Exercise both the restart and live-reload paths, with
// real conditional HTTP requests through the instance.
#[cfg(all(feature = "outbound-direct", feature = "rule-set"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_rule_set_urls_are_fetched_on_restart_and_reload() -> anyhow::Result<()> {
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
                let rules = if path == "/old.json" {
                    serde_json::json!([{ "domain": "old.example" }])
                } else {
                    serde_json::json!([{ "domain": "new.example" }, { "domain": "other.example" }])
                };
                let body = serde_json::json!({ "version": 3, "rules": rules }).to_string();
                format!(
                    "HTTP/1.1 200 OK\r\nETag: {}\r\nContent-Length: {}\r\n\r\n{}",
                    version,
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
                "outbounds": [{ "type": "direct", "tag": "direct" }],
                "route": { "rule_set": [{
                    "type": "remote", "tag": "s", "format": "source",
                    "url": format!("http://{}{}", addr, path), "update_interval": "24h"
                }] }
            })
            .to_string(),
        )
    };

    for reload in [false, true] {
        let dir = common::TempDir::new("rule-set-url")?;
        let options = || Options::new().threads(Threads::One).cache_dir(dir.path());
        let instance = Instance::new(options())?;
        requests.lock().unwrap().clear();
        tokio::time::timeout(Duration::from_secs(5), instance.start(config("/old.json"))).await??;
        assert_eq!(instance.rule_sets().await?[0].rules, 1);
        let instance = if reload {
            tokio::time::timeout(
                Duration::from_secs(5),
                instance.reload(Some(config("/new.json"))),
            )
            .await??;
            instance
        } else {
            instance.stop().await?;
            let instance = Instance::new(options())?;
            tokio::time::timeout(Duration::from_secs(5), instance.start(config("/new.json")))
                .await??;
            instance
        };
        let rules = instance.rule_sets().await?;
        assert_eq!(
            rules[0].rules, 2,
            "reload={reload}: still using the old URL's rules"
        );
        assert_eq!(
            *requests.lock().unwrap(),
            [
                ("/old.json".to_string(), None),
                ("/new.json".to_string(), None),
            ]
        );
        instance.stop().await?;

        // The new source remains cached through another restart. A
        // manual update sends that source's ETag and accepts its 304.
        let cached = Instance::new(options())?;
        tokio::time::timeout(Duration::from_secs(5), cached.start(config("/new.json"))).await??;
        assert_eq!(cached.rule_sets().await?[0].rules, 2);
        assert_eq!(requests.lock().unwrap().len(), 2);
        tokio::time::timeout(Duration::from_secs(5), cached.update_rule_set("s")).await??;
        assert_eq!(
            requests.lock().unwrap().last().unwrap(),
            &("/new.json".to_string(), Some("\"/new.json\"".to_string()))
        );
        assert_eq!(cached.rule_sets().await?[0].rules, 2);
        cached.stop().await?;
    }
    server.abort();
    Ok(())
}

// app(socks) -> (socks)sail(route by rule-set) -> echo
//
// A rule-set holding the echo server's address makes the rule reject the
// connection; one that does not lets it through.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "rule-set"
))]
#[test]
fn a_rule_set_decides_the_route() -> anyhow::Result<()> {
    let dir = common::TempDir::new("rule-set")?;
    let file = |name: &str, cidr: &str| {
        let path = dir.join(name);
        std::fs::write(
            &path,
            serde_json::json!({ "version": 3, "rules": [{ "ip_cidr": cidr }] }).to_string(),
        )
        .unwrap();
        path
    };
    let loopback = file("loopback.json", "127.0.0.0/8");
    let elsewhere = file("elsewhere.json", "192.0.2.0/24");
    for (rule_set, rejected) in [
        (
            serde_json::json!({ "type": "local", "tag": "s", "path": loopback }),
            true,
        ),
        (
            serde_json::json!({ "type": "local", "tag": "s", "path": elsewhere }),
            false,
        ),
        (
            serde_json::json!({ "tag": "s", "rules": [{ "ip_cidr": "127.0.0.1/32" }] }),
            true,
        ),
    ] {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            let config = serde_json::json!({
                "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
                "outbounds": [{ "type": "direct" }],
                "route": {
                    "rule_set": [rule_set],
                    "rules": [{ "rule_set": "s", "action": "reject" }]
                }
            });
            common::test_configs(vec![config.to_string()], "127.0.0.1", port)
        });
        assert_eq!(result.is_err(), rejected, "{}: {:?}", rule_set, result);
    }
    Ok(())
}

/// Serves `/s.json` as a redirect to `/rules.json`, which answers chunked,
/// and anything else as 404; counts the requests for the rules.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "rule-set"
))]
fn rule_set_server(body: &'static str) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    rule_set_server_requiring(body, None)
}

/// `rule_set_server`, answering 403 to requests without the header line
/// `required`.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "rule-set"
))]
fn rule_set_server_requiring(
    body: &'static str,
    required: Option<&'static str>,
) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let fetched = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = fetched.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            // The rest of the head.
            let mut found = required.is_none();
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).is_err() || header == "\r\n" {
                    break;
                }
                found |= required.is_some_and(|r| header.trim_end().eq_ignore_ascii_case(r));
            }
            let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
            let response = match path.as_str() {
                _ if !found => "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_string(),
                "/s.json" => {
                    "HTTP/1.1 302 Found\r\nLocation: /rules.json\r\nContent-Length: 0\r\n\r\n"
                        .to_string()
                }
                "/rules.json" => {
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let (a, b) = body.split_at(body.len() / 2);
                    format!(
                        "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nTransfer-Encoding: chunked\r\n\r\n\
                         {:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                        a.len(),
                        a,
                        b.len(),
                        b
                    )
                }
                _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (port, fetched)
}

// A remote rule-set is downloaded, through the redirect and in chunks,
// before the first connection: holding the echo server's address, it
// rejects that connection. One that cannot be downloaded fails the start.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "rule-set"
))]
#[test]
fn a_remote_rule_set_is_downloaded_before_the_first_connection() -> anyhow::Result<()> {
    let (http_port, fetched) =
        rule_set_server(r#"{ "version": 3, "rules": [{ "ip_cidr": "127.0.0.0/8" }] }"#);
    let (other_port, _) =
        rule_set_server(r#"{ "version": 3, "rules": [{ "ip_cidr": "192.0.2.0/24" }] }"#);
    let config = |http_port: u16, path: &str, port: u16| {
        serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [{ "type": "direct" }],
            "route": {
                "rule_set": [{
                    "type": "remote", "tag": "s", "format": "source",
                    "url": format!("http://127.0.0.1:{}{}", http_port, path)
                }],
                "rules": [{ "rule_set": "s", "action": "reject" }]
            }
        })
        .to_string()
    };
    let result = common::retry_port_clash(|| {
        let [port] = common::free_ports();
        common::test_configs(vec![config(http_port, "/s.json", port)], "127.0.0.1", port)
    });
    assert!(
        result.is_err(),
        "not rejected: the rule-set was not in place"
    );
    assert!(fetched.load(std::sync::atomic::Ordering::SeqCst) >= 1);
    // The same, with a rule-set that does not hold the address, runs.
    common::retry_port_clash(|| {
        let [port] = common::free_ports();
        common::test_configs(vec![config(other_port, "/s.json", port)], "127.0.0.1", port)
    })?;

    let rt = tokio::runtime::Runtime::new()?;
    let [port] = common::free_ports();
    let err = common::run_sail_instances(&rt, vec![config(http_port, "/missing.json", port)])
        .expect_err("started without its rule-set");
    assert!(
        format!("{:#}", err).contains("rule-set [s]: download: http status 404"),
        "{:#}",
        err
    );
    Ok(())
}

// An HTTP client without a detour dials the server itself, with its
// headers: the default outbound, a SOCKS server that is not there, would
// fail the download, and so does the server, without the header. The
// first of `http_clients` is the default; `download_detour` goes before
// it, and a rule-set's own `http_client` before that.
#[cfg(all(
    feature = "inbound-socks",
    feature = "outbound-direct",
    feature = "outbound-socks",
    feature = "rule-set"
))]
#[test]
fn a_rule_set_is_downloaded_with_its_http_client() -> anyhow::Result<()> {
    let (http_port, fetched) = rule_set_server_requiring(
        r#"{ "version": 3, "rules": [{ "ip_cidr": "127.0.0.0/8" }] }"#,
        Some("Authorization: Bearer t"),
    );
    let [dead] = common::free_ports();
    let config = |port: u16, http_clients: serde_json::Value, rule_set: serde_json::Value| {
        let mut rule_set_config = serde_json::json!({
            "type": "remote", "tag": "s", "format": "source",
            "url": format!("http://127.0.0.1:{}/s.json", http_port)
        });
        rule_set_config
            .as_object_mut()
            .unwrap()
            .extend(rule_set.as_object().unwrap().clone());
        serde_json::json!({
            "inbounds": [{ "type": "socks", "listen": "127.0.0.1", "listen_port": port }],
            "outbounds": [
                { "type": "socks", "tag": "nowhere", "server": "127.0.0.1", "server_port": dead },
                { "type": "direct", "tag": "direct" }
            ],
            "http_clients": http_clients,
            "route": {
                "rule_set": [rule_set_config],
                "rules": [{ "rule_set": "s", "action": "reject" }],
                "final": "direct"
            }
        })
        .to_string()
    };
    let headers = serde_json::json!({ "Authorization": "Bearer t" });
    let downloaded = [
        // The default, the first.
        (
            serde_json::json!([{ "tag": "c", "headers": headers }]),
            serde_json::json!({}),
        ),
        // Its own, in place, through an outbound.
        (
            serde_json::json!([]),
            serde_json::json!({ "http_client": { "detour": "direct", "headers": headers } }),
        ),
        // Its own, by tag, over the default.
        (
            serde_json::json!([{ "tag": "c" }, { "tag": "d", "headers": headers }]),
            serde_json::json!({ "http_client": "d" }),
        ),
    ];
    for (http_clients, rule_set) in downloaded {
        let result = common::retry_port_clash(|| {
            let [port] = common::free_ports();
            common::test_configs(
                vec![config(port, http_clients.clone(), rule_set.clone())],
                "127.0.0.1",
                port,
            )
        });
        assert!(
            result.is_err(),
            "{} {}: not rejected: the rule-set was not in place",
            http_clients,
            rule_set
        );
    }
    assert!(fetched.load(std::sync::atomic::Ordering::SeqCst) >= 3);

    let not_downloaded = [
        // No client: the default outbound.
        (serde_json::json!([]), serde_json::json!({}), "connect"),
        // Through the outbound, over the default client.
        (
            serde_json::json!([{ "tag": "c", "headers": headers }]),
            serde_json::json!({ "download_detour": "nowhere" }),
            "connect",
        ),
        // Without the header.
        (
            serde_json::json!([{ "tag": "c" }]),
            serde_json::json!({}),
            "http status 403",
        ),
    ];
    let rt = tokio::runtime::Runtime::new()?;
    for (http_clients, rule_set, message) in not_downloaded {
        let [port] = common::free_ports();
        let err = common::run_sail_instances(
            &rt,
            vec![config(port, http_clients.clone(), rule_set.clone())],
        )
        .expect_err("started without its rule-set");
        assert!(
            format!("{:#}", err).contains(message),
            "{} {}: {:#}",
            http_clients,
            rule_set,
            err
        );
    }
    Ok(())
}
