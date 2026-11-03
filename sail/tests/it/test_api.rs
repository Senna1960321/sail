// The control API: served on a unix socket, or on loopback behind a
// secret; what it refuses, and why, in its JSON errors.

#![cfg(all(feature = "api", feature = "outbound-direct"))]

#[allow(unused_imports)] // Unused where features leave out the tests that wait.
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::common;

const SECRET: &str = "Zq3Lp8Rk1Vn6Xc2Bm7Ws4Ty9Hd5Gf0Ja";

/// Where the API is reached.
enum At {
    Port(u16),
    #[cfg(unix)]
    Socket(std::path::PathBuf),
}

/// One call: its status, `Www-Authenticate`'s presence, and its body.
fn call(
    rt: &tokio::runtime::Runtime,
    at: &At,
    secret: Option<&str>,
    method: &str,
    path: &str,
    body: &str,
) -> anyhow::Result<(u16, bool, serde_json::Value)> {
    let auth = secret.map_or(String::new(), |s| {
        format!("Authorization: Bearer {}\r\n", s)
    });
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: sail\r\nContent-Type: application/json\r\n{}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        method,
        path,
        auth,
        body.len(),
        body
    );
    async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
        mut s: S,
        request: &str,
    ) -> anyhow::Result<String> {
        s.write_all(request.as_bytes()).await?;
        let mut reply = String::new();
        s.read_to_string(&mut reply).await?;
        Ok(reply)
    }
    let reply = rt.block_on(async {
        match at {
            At::Port(port) => {
                exchange(
                    tokio::net::TcpStream::connect(("127.0.0.1", *port)).await?,
                    &request,
                )
                .await
            }
            #[cfg(unix)]
            At::Socket(path) => {
                exchange(tokio::net::UnixStream::connect(path).await?, &request).await
            }
        }
    })?;
    let status = reply
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let (head, body) = reply.split_once("\r\n\r\n").unwrap_or((&reply, ""));
    let challenged = head
        .to_ascii_lowercase()
        .contains("www-authenticate: bearer");
    let body = serde_json::from_str(body).unwrap_or(serde_json::Value::String(body.to_owned()));
    Ok((status, challenged, body))
}

/// The error a body carries: its code and message.
fn error(body: &serde_json::Value) -> (&str, &str) {
    (
        body["error"]["code"].as_str().unwrap_or_default(),
        body["error"]["message"].as_str().unwrap_or_default(),
    )
}

#[cfg(feature = "inbound-mixed")]
#[test]
fn the_api_on_loopback_needs_its_secret_and_refuses_an_inbound_on_no_port() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, api_port, mixed_port) = common::retry_port_clash(|| {
        let [api_port, mixed_port] = common::free_ports();
        let config = serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            api_port,
            mixed_port,
        ))
    })?;
    let at = At::Port(api_port);
    let result = (|| {
        let assets = "/api/v1/runtime/assets";
        for secret in [None, Some("not-the-secret"), Some(&SECRET[1..])] {
            let (status, challenged, body) = call(&rt, &at, secret, "GET", assets, "")?;
            anyhow::ensure!(
                status == 401 && challenged,
                "{:?}: {} {}",
                secret,
                status,
                body
            );
            anyhow::ensure!(error(&body).0 == "unauthenticated", "{}", body);
        }
        // Refused before it is read: nothing changes without the secret.
        let (status, _, body) = call(&rt, &at, None, "POST", "/api/v1/runtime/shutdown", "")?;
        anyhow::ensure!(status == 401, "{} {}", status, body);
        let (status, _, body) = call(&rt, &at, Some(SECRET), "GET", assets, "")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);

        // An inbound with no port listens on nothing: refused, and why.
        let inbounds = "/api/v1/runtime/inbounds";
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "POST",
            inbounds,
            r#"{ "type": "mixed", "tag": "system-proxy" }"#,
        )?;
        anyhow::ensure!(status == 400, "{} {}", status, body);
        let (code, message) = error(&body);
        anyhow::ensure!(
            code == "invalid"
                && message.starts_with("[system-proxy] inbound: listen_port: missing"),
            "{}",
            body
        );
        let inbound = serde_json::json!({
            "type": "mixed", "tag": "system-proxy",
            "listen": "127.0.0.1", "listen_port": mixed_port,
        });
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "POST",
            inbounds,
            &inbound.to_string(),
        )?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        rt.block_on(tokio::net::TcpStream::connect(("127.0.0.1", mixed_port)))?;
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    result
}

#[cfg(unix)]
#[test]
fn the_api_is_on_a_socket_of_the_users_own_in_the_data_directory() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Short: a socket's path is at most 103 bytes on macOS.
    let dir = std::path::PathBuf::from(format!("/tmp/sail-api-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let config = serde_json::json!({ "api": {}, "outbounds": [{ "type": "direct" }] });
    let ids = common::run_sail_instances_in(&rt, vec![config.to_string()], Some(&dir))?;
    let socket = dir.join("api.sock");
    let result = (|| {
        let mode = std::fs::metadata(&socket)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "{:o}", mode);
        let (status, _, body) = call(
            &rt,
            &At::Socket(socket.clone()),
            None,
            "GET",
            "/api/v1/runtime/assets",
            "",
        )?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    let _ = std::fs::remove_dir_all(&dir);
    result
}

#[test]
fn a_reload_that_fails_says_why_and_keeps_what_runs() -> anyhow::Result<()> {
    let dir = common::TempDir::new("api-reload")?;
    let path = dir.join("config.json");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let id = common::next_rt_id();
    let config = |api_port: u16, outbounds: serde_json::Value| {
        serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "outbounds": outbounds,
        })
        .to_string()
    };
    let api_port = common::retry_port_clash(|| {
        let [api_port] = common::free_ports();
        std::fs::write(
            &path,
            config(api_port, serde_json::json!([{ "type": "direct" }])),
        )?;
        let opts = sail::StartOptions {
            signals: false,
            config: sail::Config::File(path.to_string_lossy().to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: sail::RuntimeOption::SingleThread,
            runtime: common::runtime_options(),
            host: sail::runtime::Host {
                data_dir: Some(dir.path().to_path_buf()),
                cache_dir: Some(dir.path().to_path_buf()),
                ..Default::default()
            },
        };
        common::start_instance(id, opts)?;
        Ok(api_port)
    })?;
    let at = At::Port(api_port);
    let reload = "/api/v1/runtime/reload";
    let result = (|| {
        std::fs::write(
            &path,
            config(api_port, serde_json::json!([{ "type": "nope" }])),
        )?;
        let (status, _, body) = call(&rt, &at, Some(SECRET), "POST", reload, "")?;
        anyhow::ensure!(status == 400, "{} {}", status, body);
        let (code, message) = error(&body);
        anyhow::ensure!(
            code == "invalid" && message.starts_with("[nope] outbound: unknown protocol"),
            "{}",
            body
        );
        // What ran runs on.
        anyhow::ensure!(sail::is_running(id));
        let (status, _, body) = call(&rt, &at, Some(SECRET), "GET", "/api/v1/runtime/assets", "")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);

        std::fs::write(
            &path,
            config(
                api_port,
                serde_json::json!([{ "type": "direct", "tag": "d" }]),
            ),
        )?;
        let (status, _, body) = call(&rt, &at, Some(SECRET), "POST", reload, "")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        anyhow::ensure!(body.get("recheck").is_none(), "{}", body);

        // Asked to, a reload rechecks the connections open, and tells so;
        // an option it does not know is refused, and nothing reloaded.
        let options = r#"{"recheck_open":"close_rejected"}"#;
        let (status, _, body) = call(&rt, &at, Some(SECRET), "POST", reload, options)?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        anyhow::ensure!(
            body["recheck"] == serde_json::json!({ "closed": [], "differ": [] }),
            "{}",
            body
        );
        let unknown = r#"{"recheck":"close_rejected"}"#;
        let (status, _, body) = call(&rt, &at, Some(SECRET), "POST", reload, unknown)?;
        anyhow::ensure!(status == 400, "{} {}", status, body);
        anyhow::ensure!(error(&body).0 == "invalid", "{}", body);

        // A reload tells what became of each inbound: one the file adds,
        // then one it no longer has.
        #[cfg(feature = "inbound-socks")]
        {
            let [socks_port] = common::free_ports();
            let with_inbounds = |inbounds: serde_json::Value| {
                let mut config: serde_json::Value = serde_json::from_str(&config(
                    api_port,
                    serde_json::json!([{ "type": "direct", "tag": "d" }]),
                ))
                .unwrap();
                config["inbounds"] = inbounds;
                config.to_string()
            };
            let changes = |body: &serde_json::Value| -> Vec<(String, String)> {
                body["inbounds"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|i| {
                        (
                            i["tag"].as_str().unwrap_or_default().to_string(),
                            i["change"].as_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect()
            };
            std::fs::write(
                &path,
                with_inbounds(serde_json::json!([{ "type": "socks", "tag": "s",
                    "listen": "127.0.0.1", "listen_port": socks_port }])),
            )?;
            let (status, _, body) = call(&rt, &at, Some(SECRET), "POST", reload, "")?;
            anyhow::ensure!(status == 200, "{} {}", status, body);
            anyhow::ensure!(
                changes(&body) == [("s".to_string(), "added".to_string())],
                "{}",
                body
            );
            std::fs::write(&path, with_inbounds(serde_json::json!([])))?;
            let (status, _, body) = call(&rt, &at, Some(SECRET), "POST", reload, "")?;
            anyhow::ensure!(status == 200, "{} {}", status, body);
            anyhow::ensure!(
                changes(&body) == [("s".to_string(), "removed".to_string())],
                "{}",
                body
            );
        }
        Ok(())
    })();
    sail::shutdown(id);
    result
}

#[cfg(feature = "inbound-trojan")]
#[test]
fn the_api_reads_and_changes_users_and_connections() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, api_port) = common::retry_port_clash(|| {
        let [api_port, trojan_port] = common::free_ports();
        let config = serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "inbounds": [{ "type": "trojan", "tag": "t", "listen": "127.0.0.1",
                           "listen_port": trojan_port,
                           "users": [{ "name": "alice", "password": "a" }] }],
            "outbounds": [{ "type": "direct" }],
            "user_limits": { "alice": { "max_connections": 2 } },
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            api_port,
        ))
    })?;
    let at = At::Port(api_port);
    let get = |path: &str| call(&rt, &at, Some(SECRET), "GET", path, "");
    let result = (|| {
        let (status, _, body) = get("/api/v1")?;
        anyhow::ensure!(
            status == 200
                && body["version"] == env!("CARGO_PKG_VERSION")
                && body["features"].is_array()
                && body.get("api_version").is_none(),
            "{} {}",
            status,
            body
        );

        let (status, _, body) = get("/api/v1/runtime/users")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        let alice = &body["users"][0];
        anyhow::ensure!(
            alice["name"] == "alice"
                && alice["inbounds"] == serde_json::json!(["t"])
                && alice["active"] == true
                && alice["limits"]["max_connections"] == 2,
            "{}",
            body
        );
        let (status, _, body) = get("/api/v1/runtime/users/bob")?;
        anyhow::ensure!(
            status == 404 && error(&body).0 == "not_found",
            "{} {}",
            status,
            body
        );

        let limits = "/api/v1/runtime/users/alice/limits";
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "PUT",
            limits,
            r#"{ "max_connections": 0 }"#,
        )?;
        anyhow::ensure!(
            status == 400 && error(&body).0 == "invalid",
            "{} {}",
            status,
            body
        );
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "PUT",
            limits,
            r#"{ "max_connections": 5, "up_mbps": 10 }"#,
        )?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, body) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(
            body["limits"]["max_connections"] == 5 && body["limits"]["up_mbps"] == 10,
            "{}",
            body
        );
        // Back to what the configuration sets.
        let (status, _, body) = call(&rt, &at, Some(SECRET), "DELETE", limits, "")?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, body) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(
            body["limits"]["max_connections"] == 2 && body["limits"]["up_mbps"].is_null(),
            "{}",
            body
        );
        // A time in milliseconds goes back as it came; one in RFC 3339 is
        // taken as user_limits has it; both at once is a mistake.
        let expire_at_ms = 4_102_444_800_123u64;
        let put = |body: &str| call(&rt, &at, Some(SECRET), "PUT", limits, body);
        let (status, _, body) = put(&format!(r#"{{ "expire_at_ms": {} }}"#, expire_at_ms))?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, got) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(got["limits"]["expire_at_ms"] == expire_at_ms, "{}", got);
        let (status, _, body) = put(&got["limits"].to_string())?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, again) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(again["limits"] == got["limits"], "{} {}", got, again);
        let (status, _, body) = put(r#"{ "expire_at": "2100-01-01T00:00:00Z" }"#)?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, got) = get("/api/v1/runtime/users/alice")?;
        anyhow::ensure!(
            got["limits"]["expire_at_ms"] == 4_102_444_800_000u64,
            "{}",
            got
        );
        let (status, _, body) = put(&format!(
            r#"{{ "expire_at": "2100-01-01T00:00:00Z", "expire_at_ms": {} }}"#,
            expire_at_ms
        ))?;
        anyhow::ensure!(
            status == 400 && error(&body).0 == "invalid",
            "{} {}",
            status,
            body
        );
        let (status, _, _) = call(&rt, &at, Some(SECRET), "DELETE", limits, "")?;
        anyhow::ensure!(status == 204);

        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "PUT",
            "/api/v1/runtime/users/bob/limits",
            r#"{ "max_connections": 5 }"#,
        )?;
        anyhow::ensure!(status == 404, "{} {}", status, body);

        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "POST",
            "/api/v1/runtime/users/alice/quota/reset",
            "",
        )?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "POST",
            "/api/v1/runtime/users/alice/disconnect",
            "",
        )?;
        anyhow::ensure!(status == 200 && body["closed"] == 0, "{} {}", status, body);

        for path in ["/api/v1/runtime/stats", "/api/v1/runtime/stats?clear=true"] {
            let (status, _, body) = get(path)?;
            anyhow::ensure!(
                status == 200 && body["users"].is_object() && body["inbounds"].is_object(),
                "{}: {} {}",
                path,
                status,
                body
            );
        }
        let (status, _, body) = get("/api/v1/runtime/status")?;
        anyhow::ensure!(
            status == 200 && body["connections"].is_number() && body["memory"].is_number(),
            "{} {}",
            status,
            body
        );
        let (status, _, body) = get("/api/v1/runtime/connections")?;
        anyhow::ensure!(
            status == 200 && body["connections"].is_array(),
            "{} {}",
            status,
            body
        );
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "DELETE",
            "/api/v1/runtime/connections/999999",
            "",
        )?;
        anyhow::ensure!(status == 404, "{} {}", status, body);
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "DELETE",
            "/api/v1/runtime/connections",
            "",
        )?;
        anyhow::ensure!(
            status == 200 && body["closed"].is_number(),
            "{} {}",
            status,
            body
        );

        // The pages /connections replaced are gone.
        let (status, _, _) = get("/api/v1/runtime/stat/json")?;
        anyhow::ensure!(status == 404, "{}", status);
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    result
}

#[cfg(all(feature = "inbound-trojan", feature = "inbound-direct"))]
#[test]
fn the_api_changes_an_inbounds_users_one_change_at_a_time() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, api_port, trojan_port) = common::retry_port_clash(|| {
        let [api_port, trojan_port, direct_port] = common::free_ports();
        let config = serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "inbounds": [
                { "type": "trojan", "tag": "t", "listen": "127.0.0.1", "listen_port": trojan_port,
                  "users": [{ "name": "alice", "password": "a" }] },
                { "type": "direct", "tag": "d", "listen": "127.0.0.1", "listen_port": direct_port,
                  "override_address": "127.0.0.1", "override_port": 9 },
            ],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            api_port,
            trojan_port,
        ))
    })?;
    let at = At::Port(api_port);
    let send =
        |method: &str, path: &str, body: &str| call(&rt, &at, Some(SECRET), method, path, body);
    let users = "/api/v1/runtime/inbounds/t/users";
    let result = (|| {
        let (status, _, body) = send("GET", "/api/v1/runtime/inbounds", "")?;
        anyhow::ensure!(status == 200, "{} {}", status, body);
        let inbounds = body["inbounds"].as_array().cloned().unwrap_or_default();
        anyhow::ensure!(
            inbounds.len() == 2
                && inbounds[0]["tag"] == "d"
                && inbounds[0]["reloadable"] == false
                && inbounds[1]["tag"] == "t"
                && inbounds[1]["protocol"] == "trojan"
                && inbounds[1]["listen_port"] == trojan_port
                && inbounds[1]["reloadable"] == true,
            "{}",
            body
        );

        let names = |body: &serde_json::Value| body["users"].clone();
        let (status, _, body) = send("GET", users, "")?;
        anyhow::ensure!(
            status == 200 && names(&body) == serde_json::json!(["alice"]),
            "{}",
            body
        );
        let (status, _, body) = send("GET", "/api/v1/runtime/inbounds/x/users", "")?;
        anyhow::ensure!(
            status == 404 && error(&body).0 == "not_found",
            "{} {}",
            status,
            body
        );

        let (status, _, body) = send("POST", users, r#"{ "name": "bob", "password": "b" }"#)?;
        anyhow::ensure!(status == 201, "{} {}", status, body);
        let (status, _, body) = send("POST", users, r#"{ "name": "bob", "password": "c" }"#)?;
        anyhow::ensure!(
            status == 409 && error(&body).0 == "exists",
            "{} {}",
            status,
            body
        );
        let (status, _, body) = send("POST", users, r#"{ "password": "anonymous" }"#)?;
        anyhow::ensure!(
            status == 400 && error(&body).0 == "invalid",
            "{} {}",
            status,
            body
        );
        let (_, _, body) = send("GET", users, "")?;
        anyhow::ensure!(
            names(&body) == serde_json::json!(["alice", "bob"]),
            "{}",
            body
        );

        // A password changed; the name stays, from the path.
        let (status, _, body) = send("PUT", &format!("{}/bob", users), r#"{ "password": "b2" }"#)?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (status, _, body) = send(
            "PUT",
            &format!("{}/bob", users),
            r#"{ "name": "carol", "password": "b3" }"#,
        )?;
        anyhow::ensure!(status == 400, "{} {}", status, body);
        let (status, _, body) = send("PUT", &format!("{}/carol", users), r#"{ "password": "c" }"#)?;
        anyhow::ensure!(status == 404, "{} {}", status, body);

        let (status, _, body) = send("DELETE", &format!("{}/bob", users), "")?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (status, _, body) = send("DELETE", &format!("{}/bob", users), "")?;
        anyhow::ensure!(status == 404, "{} {}", status, body);

        // An inbound whose users do not change while it runs says so.
        let (status, _, body) = send(
            "POST",
            "/api/v1/runtime/inbounds/d/users",
            r#"{ "name": "eve", "password": "e" }"#,
        )?;
        anyhow::ensure!(
            status == 422 && error(&body).0 == "unsupported",
            "{} {}",
            status,
            body
        );

        // The whole inbound replaced: the same socket, other users.
        let inbound = serde_json::json!({
            "type": "trojan", "tag": "t", "listen": "127.0.0.1", "listen_port": trojan_port,
            "users": [{ "name": "frank", "password": "f" }],
        });
        let (status, _, body) = send("PUT", "/api/v1/runtime/inbounds/t", &inbound.to_string())?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let (_, _, body) = send("GET", users, "")?;
        anyhow::ensure!(names(&body) == serde_json::json!(["frank"]), "{}", body);
        let (status, _, body) = send("PUT", "/api/v1/runtime/inbounds/u", &inbound.to_string())?;
        anyhow::ensure!(status == 400, "{} {}", status, body);
        let mut other = inbound.clone();
        other["tag"] = "nope".into();
        let (status, _, body) = send("PUT", "/api/v1/runtime/inbounds/nope", &other.to_string())?;
        anyhow::ensure!(status == 404, "{} {}", status, body);

        // Ten at once adding one user: one is added, the rest find it there.
        let statuses: Vec<u16> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..10)
                .map(|_| {
                    scope.spawn(|| -> anyhow::Result<u16> {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        let (status, _, _) = call(
                            &rt,
                            &At::Port(api_port),
                            Some(SECRET),
                            "POST",
                            users,
                            r#"{ "name": "dave", "password": "d" }"#,
                        )?;
                        Ok(status)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap().unwrap_or(0))
                .collect()
        });
        anyhow::ensure!(
            statuses.iter().filter(|s| **s == 201).count() == 1
                && statuses.iter().filter(|s| **s == 409).count() == 9,
            "{:?}",
            statuses
        );
        let (_, _, body) = send("GET", users, "")?;
        anyhow::ensure!(
            names(&body) == serde_json::json!(["dave", "frank"]),
            "{}",
            body
        );
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    result
}

#[cfg(feature = "inbound-trojan")]
#[test]
fn the_api_streams_what_happens_to_users() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (ids, api_port) = common::retry_port_clash(|| {
        let [api_port, trojan_port] = common::free_ports();
        let config = serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "inbounds": [{ "type": "trojan", "tag": "t", "listen": "127.0.0.1",
                           "listen_port": trojan_port,
                           "users": [{ "name": "alice", "password": "a" }] }],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            api_port,
        ))
    })?;
    let result = (|| {
        // The stream, read on a thread of its own until both events came.
        let (opened, open) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || -> anyhow::Result<String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let mut s = tokio::net::TcpStream::connect(("127.0.0.1", api_port)).await?;
                let request = format!(
                    "GET /api/v1/runtime/events HTTP/1.1\r\nHost: sail\r\n\
                     Authorization: Bearer {}\r\n\r\n",
                    SECRET
                );
                s.write_all(request.as_bytes()).await?;
                let mut got = String::new();
                let mut buf = [0u8; 4096];
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                let mut told = false;
                while !(got.contains("event: removed") && got.contains("event: shut")) {
                    let n = tokio::time::timeout_at(deadline, s.read(&mut buf))
                        .await
                        .map_err(|_| anyhow::anyhow!("no more within 10s: {:?}", got))??;
                    anyhow::ensure!(n > 0, "the stream ended: {}", got);
                    got.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if !told && got.contains("\r\n\r\n") {
                        told = true;
                        let _ = opened.send(());
                    }
                }
                Ok(got)
            })
        });
        open.recv_timeout(Duration::from_secs(10))?;
        let at = At::Port(api_port);
        let send =
            |method: &str, path: &str, body: &str| call(&rt, &at, Some(SECRET), method, path, body);
        let users = "/api/v1/runtime/inbounds/t/users";
        let (status, _, body) = send("POST", users, r#"{ "name": "bob", "password": "b" }"#)?;
        anyhow::ensure!(status == 201, "{} {}", status, body);
        let (status, _, body) = send("DELETE", &format!("{}/bob", users), "")?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        // Expired long ago: shut out at once.
        let (status, _, body) = send(
            "PUT",
            "/api/v1/runtime/users/alice/limits",
            r#"{ "expire_at_ms": 1 }"#,
        )?;
        anyhow::ensure!(status == 204, "{} {}", status, body);
        let got = reader
            .join()
            .map_err(|_| anyhow::anyhow!("the reader panicked"))??;
        anyhow::ensure!(
            got.to_ascii_lowercase()
                .contains("content-type: text/event-stream"),
            "{}",
            got
        );
        let data = |event: &str| -> anyhow::Result<serde_json::Value> {
            let at = got.find(&format!("event: {}", event)).unwrap();
            let line = got[at..]
                .lines()
                .find_map(|l| l.strip_prefix("data: "))
                .ok_or_else(|| anyhow::anyhow!("no data: {}", got))?;
            Ok(serde_json::from_str(line)?)
        };
        let removed = data("removed")?;
        anyhow::ensure!(
            removed["user"] == "bob" && removed["inbound"] == "t",
            "{}",
            removed
        );
        let shut = data("shut")?;
        anyhow::ensure!(
            shut["user"] == "alice" && shut["expired"] == true && shut["over_quota"] == false,
            "{}",
            shut
        );
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    result
}

/// Removing an inbound through the API disconnects its own connections at
/// once and frees its port; another inbound's connections go on.
#[cfg(feature = "inbound-socks")]
#[test]
fn removing_an_inbound_disconnects_its_connections_only() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (ids, api_port, kept_port, removed_port) = common::retry_port_clash(|| {
        let [api_port, kept_port, removed_port] = common::free_ports();
        let config = serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "inbounds": [
                { "type": "socks", "tag": "kept", "listen": "127.0.0.1", "listen_port": kept_port },
                { "type": "socks", "tag": "removed", "listen": "127.0.0.1", "listen_port": removed_port },
            ],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            api_port,
            kept_port,
            removed_port,
        ))
    })?;
    let at = At::Port(api_port);
    async fn round_trip(s: &mut sail::adapter::AnyStream, what: &[u8]) -> anyhow::Result<()> {
        s.write_all(what).await?;
        let mut back = vec![0u8; what.len()];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back)).await??;
        anyhow::ensure!(back == what, "an echo of what was sent");
        Ok(())
    }
    let result = (|| {
        let (mut kept, mut removed) = rt.block_on(async {
            let (echo, serve) = common::run_tcp_echo_server("127.0.0.1:0").await?;
            tokio::spawn(serve);
            let sess = sail::session::Session {
                destination: echo.into(),
                ..Default::default()
            };
            let mut kept =
                common::new_socks_stream("127.0.0.1", kept_port, &sess, None, None).await?;
            let mut removed =
                common::new_socks_stream("127.0.0.1", removed_port, &sess, None, None).await?;
            round_trip(&mut kept, b"kept").await?;
            round_trip(&mut removed, b"removed").await?;
            anyhow::Ok((kept, removed))
        })?;
        let (status, _, _) = call(
            &rt,
            &at,
            Some(SECRET),
            "DELETE",
            "/api/v1/runtime/inbounds/removed",
            "",
        )?;
        anyhow::ensure!(status == 200, "removed: {}", status);
        rt.block_on(async {
            let mut buf = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(5), removed.read(&mut buf)).await?;
            anyhow::ensure!(
                matches!(read, Ok(0) | Err(_)),
                "its own connection ends at once"
            );
            round_trip(&mut kept, b"still here").await
        })?;
        std::net::TcpListener::bind(("127.0.0.1", removed_port))?;
        Ok(())
    })();
    common::shutdown_instances(&rt, ids);
    result
}

/// `?kinds=connection` streams each connection's record as it closes: its
/// bytes each way, how it ended; a kind there is not is refused.
#[cfg(feature = "inbound-socks")]
#[test]
fn the_api_streams_connection_records() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (echo, serve) = rt.block_on(common::run_tcp_echo_server("127.0.0.1:0"))?;
    let echo_thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(serve)
    });
    let (ids, api_port, socks_port) = common::retry_port_clash(|| {
        let [api_port, socks_port] = common::free_ports();
        let config = serde_json::json!({
            "api": { "listen": format!("127.0.0.1:{}", api_port), "secret": SECRET },
            "inbounds": [{ "type": "socks", "tag": "s", "listen": "127.0.0.1",
                           "listen_port": socks_port }],
            "outbounds": [{ "type": "direct" }],
        });
        Ok((
            common::run_sail_instances(&rt, vec![config.to_string()])?,
            api_port,
            socks_port,
        ))
    })?;
    let result = (|| {
        let at = At::Port(api_port);
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "GET",
            "/api/v1/runtime/events?kinds=user,dns",
            "",
        )?;
        anyhow::ensure!(
            status == 400 && body.to_string().contains("dns"),
            "{} {}",
            status,
            body
        );
        // Admission under memory pressure is off on this profile.
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "GET",
            "/api/v1/runtime/admission",
            "",
        )?;
        anyhow::ensure!(
            status == 200 && body["level"] == "off" && body["evicted"] == 0,
            "{} {}",
            status,
            body
        );
        // An interim pass with no one listening tells nothing.
        let (status, _, body) = call(
            &rt,
            &at,
            Some(SECRET),
            "POST",
            "/api/v1/runtime/connections/report",
            "",
        )?;
        anyhow::ensure!(
            status == 200 && body == serde_json::json!({ "recorded": 0 }),
            "{} {}",
            status,
            body
        );
        let (opened, open) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || -> anyhow::Result<String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async {
                let mut s = tokio::net::TcpStream::connect(("127.0.0.1", api_port)).await?;
                let request = format!(
                    "GET /api/v1/runtime/events?kinds=connection HTTP/1.1\r\nHost: sail\r\n\
                     Authorization: Bearer {}\r\n\r\n",
                    SECRET
                );
                s.write_all(request.as_bytes()).await?;
                let mut got = String::new();
                let mut buf = [0u8; 4096];
                let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
                let mut told = false;
                while !(got.contains("event: connection") && got.contains("data: {")) {
                    let n = tokio::time::timeout_at(deadline, s.read(&mut buf))
                        .await
                        .map_err(|_| anyhow::anyhow!("no more within 10s: {:?}", got))??;
                    anyhow::ensure!(n > 0, "the stream ended: {}", got);
                    got.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if !told && got.contains("\r\n\r\n") {
                        told = true;
                        let _ = opened.send(());
                    }
                }
                // The rest of the event's line.
                while !got[got.find("event: connection").unwrap()..].contains("}\n") {
                    let n = tokio::time::timeout_at(deadline, s.read(&mut buf)).await??;
                    anyhow::ensure!(n > 0, "the stream ended: {}", got);
                    got.push_str(&String::from_utf8_lossy(&buf[..n]));
                }
                Ok(got)
            })
        });
        open.recv_timeout(Duration::from_secs(10))?;
        // A connection through SOCKS to the echo server, a round trip, and
        // both ends closed.
        rt.block_on(async {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await?;
            s.write_all(&[5, 1, 0]).await?;
            let mut greeted = [0u8; 2];
            s.read_exact(&mut greeted).await?;
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend(echo.port().to_be_bytes());
            s.write_all(&request).await?;
            let mut reply = [0u8; 10];
            s.read_exact(&mut reply).await?;
            anyhow::ensure!(reply[1] == 0, "{:?}", reply);
            s.write_all(b"hello").await?;
            let mut back = [0u8; 5];
            s.read_exact(&mut back).await?;
            s.shutdown().await?;
            let mut rest = Vec::new();
            s.read_to_end(&mut rest).await?;
            anyhow::Ok(())
        })?;
        let got = reader
            .join()
            .map_err(|_| anyhow::anyhow!("the reader panicked"))??;
        let at = got.find("event: connection").unwrap();
        let line = got[at..]
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .ok_or_else(|| anyhow::anyhow!("no data: {}", got))?;
        let record: serde_json::Value = serde_json::from_str(line)?;
        anyhow::ensure!(
            record["kind"] == "closed"
                && record["end"] == "finished"
                && record["inbound"] == "s"
                && record["outcome"] == "ok"
                && record["up_total"] == 5
                && record["down_total"] == 5
                && record["seq"] == 0,
            "{}",
            record
        );
        Ok(())
    })();
    for id in ids {
        sail::shutdown(id);
    }
    drop(echo_thread);
    result
}
