use std::convert::Infallible;
use std::sync::Arc;

use anyhow::{anyhow, bail};
use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use tracing::{info, warn};

use crate::control::json;
use crate::control::listen::{self, Listener};

#[cfg(feature = "outbound-select")]
use axum::extract::Query;

use crate::RuntimeManager;

mod models {
    use serde_derive::{Deserialize, Serialize};

    #[cfg(feature = "outbound-select")]
    #[derive(Debug, Deserialize)]
    pub struct SelectOptions {
        pub outbound: Option<String>,
        pub select: Option<String>,
    }

    #[cfg(feature = "outbound-select")]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct SelectReply {
        pub selected: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct LastPeerActive {
        pub tag: String,
        pub last_peer_active: Option<u32>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct SinceLastPeerActive {
        pub tag: String,
        pub since_last_peer_active: Option<u32>,
    }

    /// Where an asset is downloaded from, and through; the host's source
    /// for it, and the default outbound, when not given.
    #[cfg(feature = "http-client")]
    #[derive(Debug, Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AssetUpdate {
        pub url: Option<String>,
        pub detour: Option<String>,
    }

    /// A user's limits, as the management API takes them.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Limits {
        #[serde(default)]
        pub max_connections: Option<u32>,
        #[serde(default)]
        pub max_tcp_connections: Option<u32>,
        #[serde(default)]
        pub quota_bytes: Option<u64>,
        /// Milliseconds since the epoch, as the API answers with it.
        #[serde(default)]
        pub expire_at_ms: Option<u64>,
        /// RFC 3339, as `user_limits` takes it.
        #[serde(default)]
        pub expire_at: Option<String>,
        #[serde(default)]
        pub up_mbps: Option<u64>,
        #[serde(default)]
        pub down_mbps: Option<u64>,
    }

    impl Limits {
        /// As `user_limits` has them, which checks them.
        pub fn configured(self) -> Result<crate::config::UserLimits, String> {
            let expire_at = match (self.expire_at, self.expire_at_ms) {
                (Some(_), Some(_)) => {
                    return Err("expire_at, expire_at_ms: give one of them".into())
                }
                (Some(at), None) => Some(at),
                (None, Some(ms)) => {
                    let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                        i64::try_from(ms).map_err(|_| "expire_at_ms: too far".to_string())?,
                    )
                    .ok_or_else(|| "expire_at_ms: too far".to_string())?;
                    Some(at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
                }
                (None, None) => None,
            };
            Ok(crate::config::UserLimits {
                max_connections: self.max_connections,
                max_tcp_connections: self.max_tcp_connections,
                quota_bytes: self.quota_bytes,
                expire_at,
                up_mbps: self.up_mbps,
                down_mbps: self.down_mbps,
            })
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct OutboundHealthCheck {
        pub tag: String,
        pub tcp_ms: Option<u128>,
        pub udp_ms: Option<u128>,
    }
}

mod handlers {
    use super::*;

    #[cfg(feature = "outbound-select")]
    pub async fn select_update(
        Query(opts): Query<models::SelectOptions>,
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<StatusCode, Infallible> {
        if let models::SelectOptions {
            outbound: Some(outbound),
            select: Some(select),
        } = opts
        {
            if rm.set_outbound_selected(&outbound, &select).await.is_ok() {
                return Ok(StatusCode::OK);
            }
        }
        Ok(StatusCode::ACCEPTED)
    }

    #[cfg(feature = "outbound-select")]
    pub async fn select_get(
        Query(opts): Query<models::SelectOptions>,
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<Json<models::SelectReply>, Infallible> {
        if let models::SelectOptions {
            outbound: Some(outbound),
            ..
        } = opts
        {
            if let Ok(selected) = rm.get_outbound_selected(&outbound).await {
                return Ok(Json(models::SelectReply {
                    selected: Some(selected),
                }));
            }
        }
        Ok(Json(models::SelectReply { selected: None }))
    }

    #[cfg(feature = "outbound-select")]
    pub async fn select_list(
        Query(opts): Query<models::SelectOptions>,
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<Json<Vec<String>>, Infallible> {
        if let models::SelectOptions {
            outbound: Some(outbound),
            ..
        } = opts
        {
            if let Ok(selects) = rm.get_outbound_selects(&outbound).await {
                return Ok(Json(selects));
            }
        }
        Ok(Json(Vec::new()))
    }

    /// Reloads from the configuration file: 200 once the new one runs;
    /// otherwise the old one runs on, and the error tells why.
    /// The body tells what became of each inbound: `{"path", "inbounds":
    /// [{"tag", "change"}]}`, `change` one of untouched, reloaded, added,
    /// removed, replaced. Only the removed and the replaced had their
    /// connections closed. `path` is `inbounds_only` when nothing but the
    /// inbounds differed from what ran, and nothing else was built again;
    /// `full` otherwise. The request's body, JSON, may be empty, or say
    /// what becomes of the connections open: `{"recheck_open":
    /// "close_rejected"}` rechecks them against the routing the reload
    /// leaves, closes those it rejects, and answers with `"recheck":
    /// {"closed": [{"id", "rule"}], "differ": [{"id", "old", "new"}]}`;
    /// `keep`, the default, leaves them.
    pub async fn runtime_reload(
        State(rm): State<Arc<RuntimeManager>>,
        body: axum::body::Bytes,
    ) -> Response {
        let options = match body.is_empty() {
            true => Default::default(),
            false => match json::ReloadOptions::parse(&body) {
                Ok(options) => options,
                Err(e) => return error(StatusCode::BAD_REQUEST, "invalid", format!("body: {}", e)),
            },
        };
        match rm.reload_rechecking(None, options).await {
            Ok(report) => {
                let inbounds: Vec<_> = report
                    .inbounds
                    .iter()
                    .map(|(tag, change)| serde_json::json!({ "tag": tag, "change": change.name() }))
                    .collect();
                let notes: Vec<_> = report.notes.iter().map(|note| note.to_string()).collect();
                let mut answer = serde_json::json!({
                    "path": report.path.name(),
                    "inbounds": inbounds,
                    "notes": notes,
                });
                if let Some(recheck) = &report.recheck {
                    answer["recheck"] = serde_json::json!(json::Recheck::of(recheck));
                }
                Json(answer).into_response()
            }
            Err(e) => {
                warn!("reload failed, the configuration running is kept: {:#}", e);
                failed(e)
            }
        }
    }

    pub async fn outbound_add(
        State(rm): State<Arc<RuntimeManager>>,
        Json(outbound): Json<crate::config::Outbound>,
    ) -> Response {
        changed(rm.add_outbound(outbound).await)
    }

    pub async fn outbound_remove(
        State(rm): State<Arc<RuntimeManager>>,
        Path(tag): Path<String>,
    ) -> Response {
        changed(rm.remove_outbound(&tag).await)
    }

    pub async fn inbound_add(
        State(rm): State<Arc<RuntimeManager>>,
        Json(inbound): Json<crate::config::Inbound>,
    ) -> Response {
        changed(rm.add_inbound(inbound).await)
    }

    pub async fn inbound_remove(
        State(rm): State<Arc<RuntimeManager>>,
        Path(tag): Path<String>,
    ) -> Response {
        changed(rm.remove_inbound(&tag).await)
    }

    /// A change made, or why it was not.
    fn changed(result: Result<(), crate::Error>) -> Response {
        match result {
            Ok(()) => StatusCode::OK.into_response(),
            Err(e) => failed(e),
        }
    }

    /// Why a change was not made: what the configuration or the request
    /// got wrong, or what failed in sail.
    fn failed(e: crate::Error) -> Response {
        match e {
            crate::Error::Config(e) => {
                error(StatusCode::BAD_REQUEST, "invalid", format!("{:#}", e))
            }
            crate::Error::NoConfigFile => error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported",
                "the instance was started from no file to reload",
            ),
            // Nothing changed: what the configuration asks takes a start.
            e @ crate::Error::NeedsRestart(_) => error(StatusCode::CONFLICT, "needs_restart", e),
            // The inbound it names listens no more.
            e @ crate::Error::InboundLost { .. } => {
                error(StatusCode::INTERNAL_SERVER_ERROR, "inbound_lost", e)
            }
            e @ crate::Error::NoInbound(_) => error(StatusCode::NOT_FOUND, "not_found", e),
            e => error(StatusCode::INTERNAL_SERVER_ERROR, "internal", e),
        }
    }

    /// This build of sail: its release, and the modules compiled in.
    pub async fn capabilities() -> Json<json::Capabilities> {
        Json(json::Capabilities {
            version: crate::embed::BUILD.version,
            commit: crate::embed::BUILD.commit,
            features: crate::control::features(),
        })
    }

    fn no_user(name: &str) -> Response {
        error(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("user [{}]: there is none", name),
        )
    }

    /// Every user there is, by name.
    pub async fn users(State(rm): State<Arc<RuntimeManager>>) -> Response {
        match rm.users() {
            Ok(users) => Json(json::Users {
                users: users.iter().map(json::User::of).collect(),
            })
            .into_response(),
            Err(e) => failed(e),
        }
    }

    pub async fn user(State(rm): State<Arc<RuntimeManager>>, Path(name): Path<String>) -> Response {
        match rm.user(&name) {
            Ok(Some(user)) => Json(json::User::of(&user)).into_response(),
            Ok(None) => no_user(&name),
            Err(e) => failed(e),
        }
    }

    /// `action` done to the user `name`, or 404 when there is none.
    fn on_user<T>(
        rm: &RuntimeManager,
        name: &str,
        action: impl FnOnce() -> Result<T, crate::Error>,
        done: impl FnOnce(T) -> Response,
    ) -> Response {
        match rm.user(name) {
            Ok(Some(_)) => match action() {
                Ok(t) => done(t),
                Err(e) => failed(e),
            },
            Ok(None) => no_user(name),
            Err(e) => failed(e),
        }
    }

    /// Limits the user by the body until the next reload or a DELETE: the
    /// `limits` a GET answers with, so that it goes back as it came, or a
    /// user's in `user_limits`, its time in RFC 3339.
    pub async fn user_limits_set(
        State(rm): State<Arc<RuntimeManager>>,
        Path(name): Path<String>,
        body: axum::body::Bytes,
    ) -> Response {
        let limits = match serde_json::from_slice::<models::Limits>(&body)
            .map_err(|e| format!("body: {}", e))
            .and_then(models::Limits::configured)
        {
            Ok(limits) => limits,
            Err(e) => return error(StatusCode::BAD_REQUEST, "invalid", e),
        };
        if let Err(e) = limits.check(&name) {
            return error(StatusCode::BAD_REQUEST, "invalid", e);
        }
        let limits = crate::user::Limits::from_config(&limits);
        on_user(
            &rm,
            &name,
            || rm.set_user_limits(&name, limits),
            |()| StatusCode::NO_CONTENT.into_response(),
        )
    }

    /// Limits the user by what the configuration sets again.
    pub async fn user_limits_restore(
        State(rm): State<Arc<RuntimeManager>>,
        Path(name): Path<String>,
    ) -> Response {
        on_user(
            &rm,
            &name,
            || rm.restore_user_limits(&name),
            |()| StatusCode::NO_CONTENT.into_response(),
        )
    }

    pub async fn user_quota_reset(
        State(rm): State<Arc<RuntimeManager>>,
        Path(name): Path<String>,
    ) -> Response {
        on_user(
            &rm,
            &name,
            || rm.reset_quota(&name),
            |()| StatusCode::NO_CONTENT.into_response(),
        )
    }

    /// Closes the user's connections; it may connect again.
    pub async fn user_disconnect(
        State(rm): State<Arc<RuntimeManager>>,
        Path(name): Path<String>,
    ) -> Response {
        on_user(
            &rm,
            &name,
            || rm.disconnect_user(&name),
            |closed| Json(serde_json::json!({ "closed": closed })).into_response(),
        )
    }

    /// The traffic of each user, inbound and outbound; with `?clear=true`,
    /// since the last read that cleared it, as ssm-api reads. Quotas do
    /// not count from it.
    pub async fn stats(
        State(rm): State<Arc<RuntimeManager>>,
        uri: axum::http::Uri,
    ) -> Json<json::Stats> {
        let clear = uri
            .query()
            .is_some_and(|q| q.split('&').any(|p| p == "clear=true" || p == "clear=1"));
        Json(json::Stats::of(&rm.read_traffic(clear)))
    }

    /// What the instance sent and received, its connections and memory.
    pub async fn status(State(rm): State<Arc<RuntimeManager>>) -> Json<json::Traffic> {
        Json(json::Traffic::of(&rm.traffic().await))
    }

    pub async fn connections(State(rm): State<Arc<RuntimeManager>>) -> Json<json::Connections> {
        Json(json::Connections {
            connections: rm
                .connections()
                .await
                .iter()
                .map(json::Connection::of)
                .collect(),
        })
    }

    pub async fn connection_close(
        State(rm): State<Arc<RuntimeManager>>,
        Path(id): Path<u64>,
    ) -> Response {
        if rm.close_connection(id).await {
            StatusCode::NO_CONTENT.into_response()
        } else {
            error(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("connection {}: there is none", id),
            )
        }
    }

    /// An interim pass, now: a record of each connection open, idle ones
    /// too, to the subscribers of `connection` events; how many.
    pub async fn connections_report(
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Json<serde_json::Value> {
        Json(serde_json::json!({ "recorded": rm.report_connections().await }))
    }

    pub async fn connections_close(
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Json<serde_json::Value> {
        Json(serde_json::json!({ "closed": rm.close_all_connections().await }))
    }

    /// Why a change to an inbound or its users was not made.
    fn inbound_failed(e: crate::control::InboundError) -> Response {
        use crate::control::InboundError::*;
        match e {
            NoInbound(_) | NoUser(..) => error(StatusCode::NOT_FOUND, "not_found", e),
            NotReloadable(_) => error(StatusCode::UNPROCESSABLE_ENTITY, "unsupported", e),
            UserExists(..) => error(StatusCode::CONFLICT, "exists", e),
            Invalid(_) => error(StatusCode::BAD_REQUEST, "invalid", e),
            Failed(e) => failed(e),
        }
    }

    /// The inbounds, by tag: their type, where they listen, and whether
    /// their users change while they run.
    pub async fn inbounds(State(rm): State<Arc<RuntimeManager>>) -> Response {
        match rm.inbounds() {
            Ok(inbounds) => Json(json::Inbounds {
                inbounds: inbounds.iter().map(json::Inbound::of).collect(),
            })
            .into_response(),
            Err(e) => failed(e),
        }
    }

    /// Replaces the inbound's users and certificate by the body, the whole
    /// inbound as the configuration has it, without its socket rebound.
    pub async fn inbound_update(
        State(rm): State<Arc<RuntimeManager>>,
        Path(tag): Path<String>,
        Json(mut inbound): Json<crate::config::Inbound>,
    ) -> Response {
        if inbound.tag.is_empty() {
            inbound.tag = tag.clone();
        }
        if inbound.tag != tag {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid",
                format!("tag: [{}] is not the inbound [{}]", inbound.tag, tag),
            );
        }
        match rm.inbounds() {
            Ok(inbounds) => match inbounds.iter().find(|i| i.tag == tag) {
                None => return inbound_failed(crate::control::InboundError::NoInbound(tag)),
                Some(i) if !i.reloadable => {
                    return inbound_failed(crate::control::InboundError::NotReloadable(tag))
                }
                Some(_) => {}
            },
            Err(e) => return failed(e),
        }
        match rm.update_inbound_resources(inbound).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => failed(e),
        }
    }

    /// The names of the inbound's users.
    pub async fn inbound_users(
        State(rm): State<Arc<RuntimeManager>>,
        Path(tag): Path<String>,
    ) -> Response {
        match rm.inbound_users(&tag) {
            Ok(Some(users)) => Json(json::InboundUsers { users }).into_response(),
            Ok(None) => inbound_failed(crate::control::InboundError::NoInbound(tag)),
            Err(e) => failed(e),
        }
    }

    /// Adds the body, a user as the inbound's `users` has them, named.
    pub async fn inbound_user_add(
        State(rm): State<Arc<RuntimeManager>>,
        Path(tag): Path<String>,
        Json(user): Json<serde_json::Value>,
    ) -> Response {
        match rm.add_inbound_user(&tag, user).await {
            Ok(()) => StatusCode::CREATED.into_response(),
            Err(e) => inbound_failed(e),
        }
    }

    /// Replaces the user's credentials by the body: its connections go on.
    pub async fn inbound_user_replace(
        State(rm): State<Arc<RuntimeManager>>,
        Path((tag, name)): Path<(String, String)>,
        Json(user): Json<serde_json::Value>,
    ) -> Response {
        match rm.replace_inbound_user(&tag, &name, user).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => inbound_failed(e),
        }
    }

    /// Takes the user out of the inbound, and closes its connections
    /// through it.
    pub async fn inbound_user_remove(
        State(rm): State<Arc<RuntimeManager>>,
        Path((tag, name)): Path<(String, String)>,
    ) -> Response {
        match rm.remove_inbound_user(&tag, &name).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => inbound_failed(e),
        }
    }

    /// What happens from now on, as Server-Sent Events, of the kinds
    /// `?kinds=` names: `user` (the default), what happens to users, each
    /// event named as its `event` field; `connection`, the connections'
    /// records, each named `connection`; `admission`, admission under
    /// memory pressure changing level, named `admission`. The data is the
    /// JSON. One that
    /// falls behind by more than the events kept gets `lagged`, with
    /// `kind` and how many it `missed`, and goes on from the oldest kept.
    pub async fn events(State(rm): State<Arc<RuntimeManager>>, uri: axum::http::Uri) -> Response {
        use axum::response::sse::{Event, KeepAlive, Sse};
        use futures::stream::BoxStream;
        use tokio::sync::broadcast::error::RecvError;
        let (mut users, mut connections, mut admission) = (false, false, false);
        // `?kinds=user,connection`, read here: the API's build has no
        // query extractor of axum's.
        let kinds = uri
            .query()
            .unwrap_or("")
            .split('&')
            .find_map(|pair| pair.strip_prefix("kinds="))
            .map(|kinds| kinds.replace("%2C", ",").replace("%2c", ","));
        for kind in kinds.as_deref().unwrap_or("user").split(',') {
            match kind.trim() {
                "user" => users = true,
                "connection" => connections = true,
                "admission" => admission = true,
                other => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "invalid",
                        format!("no kind of event [{}]: user, connection, admission", other),
                    )
                }
            }
        }
        fn lagged(kind: &str, missed: u64) -> Event {
            Event::default()
                .event("lagged")
                .data(serde_json::json!({ "kind": kind, "missed": missed }).to_string())
        }
        let mut streams: Vec<BoxStream<'static, Result<Event, Infallible>>> = Vec::new();
        if users {
            streams.push(Box::pin(futures::stream::unfold(
                rm.user_events(),
                |mut events| async move {
                    let event = match events.recv().await {
                        Ok(e) => {
                            let e = json::UserEvent::of(&e);
                            Event::default()
                                .event(e.event)
                                .json_data(&e)
                                .unwrap_or_else(|_| Event::default().event("error"))
                        }
                        Err(RecvError::Lagged(missed)) => lagged("user", missed),
                        // The instance stopped.
                        Err(RecvError::Closed) => return None,
                    };
                    Some((Ok(event), events))
                },
            )));
        }
        if connections {
            streams.push(Box::pin(futures::stream::unfold(
                rm.connection_records(),
                |mut records| async move {
                    let event = match records.recv().await {
                        Ok(r) => Event::default()
                            .event("connection")
                            .json_data(json::ConnectionRecord::of(&r))
                            .unwrap_or_else(|_| Event::default().event("error")),
                        Err(RecvError::Lagged(missed)) => lagged("connection", missed),
                        Err(RecvError::Closed) => return None,
                    };
                    Some((Ok(event), records))
                },
            )));
        }
        if admission {
            streams.push(Box::pin(futures::stream::unfold(
                rm.admission_changes(),
                |mut changes| async move {
                    let event = match changes.recv().await {
                        Ok(c) => Event::default()
                            .event("admission")
                            .json_data(json::AdmissionChange::of(&c))
                            .unwrap_or_else(|_| Event::default().event("error")),
                        Err(RecvError::Lagged(missed)) => lagged("admission", missed),
                        Err(RecvError::Closed) => return None,
                    };
                    Some((Ok(event), changes))
                },
            )));
        }
        Sse::new(futures::stream::select_all(streams))
            .keep_alive(KeepAlive::default())
            .into_response()
    }

    /// What admission under memory pressure did since the instance
    /// started; `level` is `off` when it is.
    pub async fn admission(State(rm): State<Arc<RuntimeManager>>) -> Json<json::Admission> {
        Json(json::Admission::of(rm.admission().as_ref()))
    }

    /// The network the host is on, as it told or sail detected it.
    pub async fn network(
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Json<crate::net::network::NetworkState> {
        Json((*rm.network().snapshot()).clone())
    }

    /// The host tells what network it is on; sail's own detection is left
    /// from then on.
    pub async fn network_put(
        State(rm): State<Arc<RuntimeManager>>,
        body: String,
    ) -> Result<StatusCode, (StatusCode, String)> {
        let state = crate::net::network::NetworkState::from_json(&body)
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
        rm.network().push(state);
        Ok(StatusCode::NO_CONTENT)
    }

    /// The assets the configuration reads.
    pub async fn assets(State(rm): State<Arc<RuntimeManager>>) -> Json<Vec<crate::assets::Asset>> {
        Json(rm.assets())
    }

    /// Downloads an asset, puts it in place and reloads. The body, JSON,
    /// may be empty.
    #[cfg(feature = "http-client")]
    pub async fn asset_update(
        State(rm): State<Arc<RuntimeManager>>,
        Path(name): Path<String>,
        body: axum::body::Bytes,
    ) -> Result<Json<crate::assets::Updated>, (StatusCode, String)> {
        use crate::assets::UpdateError;
        let body: models::AssetUpdate = match body.is_empty() {
            true => Default::default(),
            false => serde_json::from_slice(&body)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("body: {}", e)))?,
        };
        crate::assets::update(&rm, &name, body.url.as_deref(), body.detour.as_deref())
            .await
            .map(Json)
            .map_err(|e| {
                let status = match e {
                    UpdateError::Unknown(_) => StatusCode::NOT_FOUND,
                    UpdateError::NoSource(_) => StatusCode::BAD_REQUEST,
                    UpdateError::Failed(_) => StatusCode::BAD_GATEWAY,
                };
                (status, e.to_string())
            })
    }

    pub async fn runtime_shutdown(
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<StatusCode, Infallible> {
        if rm.shutdown().await {
            Ok(StatusCode::OK)
        } else {
            Ok(StatusCode::ACCEPTED)
        }
    }

    /// What the DNS cache holds and how it served.
    pub async fn dns_cache(
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Json<crate::app::dns::CacheStats> {
        Json(rm.dns_cache_stats())
    }

    pub async fn dns_cache_flush(State(rm): State<Arc<RuntimeManager>>) -> StatusCode {
        rm.clear_dns_cache();
        StatusCode::NO_CONTENT
    }

    /// The sessions and streams of every multiplexing protocol on the
    /// session core, and the streams reset for stalling.
    #[cfg(any(
        feature = "mux",
        feature = "inbound-amux",
        feature = "outbound-amux",
        feature = "inbound-anytls",
        feature = "outbound-anytls",
        feature = "quic"
    ))]
    pub async fn stat_mux_json(
    ) -> Json<std::collections::BTreeMap<&'static str, crate::transport::muxcore::stats::Snapshot>>
    {
        Json(crate::transport::muxcore::stats::snapshot())
    }

    pub async fn last_peer_active(
        Path(tag): Path<String>,
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<Json<models::LastPeerActive>, Infallible> {
        let last_peer_active = rm.get_outbound_last_peer_active(&tag).await.ok().flatten();
        Ok(Json(models::LastPeerActive {
            tag,
            last_peer_active,
        }))
    }

    pub async fn since_last_peer_active(
        Path(tag): Path<String>,
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<Json<models::SinceLastPeerActive>, Infallible> {
        let since = rm.stat_manager().since_last_peer_active(&tag);
        Ok(Json(models::SinceLastPeerActive {
            tag,
            since_last_peer_active: since,
        }))
    }

    pub async fn outbound_health(
        Path(tag): Path<String>,
        State(rm): State<Arc<RuntimeManager>>,
    ) -> Result<Json<models::OutboundHealthCheck>, Infallible> {
        let (tcp_res, udp_res) = rm.health_check_outbound(&tag, None).await.unwrap_or((
            Err(anyhow::anyhow!("runtime")),
            Err(anyhow::anyhow!("runtime")),
        ));
        let tcp_ms = tcp_res.ok().map(|d| d.as_millis());
        let udp_ms = udp_res.ok().map(|d| d.as_millis());
        Ok(Json(models::OutboundHealthCheck {
            tag,
            tcp_ms,
            udp_ms,
        }))
    }
}

pub struct ApiServer {
    runtime_manager: Arc<RuntimeManager>,
}

/// The listeners for `api`, and the secret calls carry: bound at start,
/// so that an address in use fails the start rather than the API alone,
/// later. From within the runtime.
pub fn bind(
    api: &crate::config::model::Api,
    env: &crate::runtime::RuntimeEnv,
) -> anyhow::Result<(Vec<Listener>, Option<String>)> {
    let mut listeners = Vec::new();
    #[cfg(not(unix))]
    if api.path.is_none() && api.listen.is_none() {
        bail!("api: unix sockets are not served here; set api.listen and api.secret");
    }
    if let Some(path) = api.socket() {
        let path = std::path::PathBuf::from(env.data_path(&path.to_string_lossy()));
        let len = path.as_os_str().len();
        if len > listen::SOCKET_PATH_MAX {
            bail!(
                "api.path: {} is {} bytes, more than a unix socket's {}",
                path.display(),
                len,
                listen::SOCKET_PATH_MAX
            );
        }
        listeners.push(
            listen::bind(&listen::Address::Unix(path.clone()))
                .map_err(|e| anyhow!("api.path: {}", e))?,
        );
        info!("api server listening on {}", path.display());
    }
    if let Some(addr) = api.listen {
        let listener = crate::net::listen_tcp(&addr)
            .and_then(|l| l.set_nonblocking(true).map(|()| l))
            .and_then(tokio::net::TcpListener::from_std)
            .map_err(|e| anyhow!("api.listen: {}: {}", addr, e))?;
        listeners.push(Listener::Tcp(listener));
        info!("api server listening tcp {}", addr);
    }
    Ok((listeners, api.secret.clone()))
}

/// An error as the API tells it: a stable `code` a client acts on, and
/// what went wrong, with what a URL in it carries left out.
fn error(status: StatusCode, code: &'static str, message: impl std::fmt::Display) -> Response {
    let message = without_url_secrets(&message.to_string());
    (
        status,
        Json(serde_json::json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

/// `text` with each URL in it as [`crate::common::redact::url`] tells it:
/// a subscription's token is in its path or query as often as not.
fn without_url_secrets(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let start = rest[..at]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |i| i + 1);
        let end = rest[at..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '<' | '>'))
            .map_or(rest.len(), |i| at + i);
        out.push_str(&rest[..start]);
        out.push_str(&crate::common::redact::url(&rest[start..end]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Lets a call through only with the secret, as `Authorization: Bearer`.
async fn authorize(State(secret): State<Arc<str>>, request: Request, next: Next) -> Response {
    let given = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match given {
        Some(given) if listen::same_secret(given.as_bytes(), secret.as_bytes()) => {
            next.run(request).await
        }
        _ => {
            let mut response = error(
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "the API's secret is needed, as Authorization: Bearer <secret>",
            );
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
            response
        }
    }
}

/// Serves `app` on what `listener` accepts, a connection at a time on a
/// task of its own, as axum does.
async fn accept(listener: Listener, app: Router) {
    loop {
        let accepted = match &listener {
            #[cfg(unix)]
            Listener::Unix(l) => l.accept().await.map(|(s, _)| connection(s, app.clone())),
            Listener::Tcp(l) => l.accept().await.map(|(s, _)| connection(s, app.clone())),
        };
        if let Err(e) = accepted {
            // Out of descriptors, mostly: a moment for some to free up.
            warn!("api server: accept: {}", e);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

fn connection<S>(stream: S, app: Router)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        server::conn::auto::Builder,
        service::TowerToHyperService,
    };
    crate::runtime::scope::spawn("api connection", async move {
        let _ = Builder::new(TokioExecutor::new())
            .http1_only()
            .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
            .await;
    });
}

impl ApiServer {
    pub fn new(runtime_manager: Arc<RuntimeManager>) -> Self {
        Self { runtime_manager }
    }

    /// Serves on `listeners`, which [`bind`] made; with `secret`, a call
    /// without it is refused.
    pub fn serve(&self, listeners: Vec<Listener>, secret: Option<String>) -> crate::Runner {
        // Under /api/v1 routes and fields are only added, and a client
        // ignores what it does not know; a change that takes one away or
        // changes what it means goes under /api/v2.
        let mut app = Router::new()
            .route("/api/v1/runtime/reload", post(handlers::runtime_reload))
            .route("/api/v1/runtime/shutdown", post(handlers::runtime_shutdown))
            .route("/api/v1/runtime/outbounds", post(handlers::outbound_add))
            .route(
                "/api/v1/runtime/outbounds/:tag",
                delete(handlers::outbound_remove),
            )
            .route("/api/v1/runtime/dns/cache", get(handlers::dns_cache))
            .route(
                "/api/v1/runtime/dns/cache/flush",
                post(handlers::dns_cache_flush),
            )
            .route(
                "/api/v1/runtime/inbounds",
                get(handlers::inbounds).post(handlers::inbound_add),
            )
            .route(
                "/api/v1/runtime/inbounds/:tag",
                put(handlers::inbound_update).delete(handlers::inbound_remove),
            )
            .route(
                "/api/v1/runtime/inbounds/:tag/users",
                get(handlers::inbound_users).post(handlers::inbound_user_add),
            )
            .route(
                "/api/v1/runtime/inbounds/:tag/users/:name",
                put(handlers::inbound_user_replace).delete(handlers::inbound_user_remove),
            )
            .route("/api/v1/runtime/assets", get(handlers::assets))
            .route(
                "/api/v1/runtime/network",
                get(handlers::network).put(handlers::network_put),
            );

        #[cfg(feature = "http-client")]
        {
            app = app.route(
                "/api/v1/runtime/assets/:name/update",
                post(handlers::asset_update),
            );
        }

        #[cfg(feature = "outbound-select")]
        {
            app = app
                .route("/api/v1/app/outbound/select", post(handlers::select_update))
                .route("/api/v1/app/outbound/select", get(handlers::select_get))
                .route("/api/v1/app/outbound/selects", get(handlers::select_list));
        }

        #[cfg(any(
            feature = "mux",
            feature = "inbound-amux",
            feature = "outbound-amux",
            feature = "inbound-anytls",
            feature = "outbound-anytls",
            feature = "quic"
        ))]
        {
            app = app.route("/api/v1/runtime/stat/mux", get(handlers::stat_mux_json));
        }

        app = app
            .route("/api/v1", get(handlers::capabilities))
            .route("/api/v1/runtime/users", get(handlers::users))
            .route("/api/v1/runtime/users/:name", get(handlers::user))
            .route(
                "/api/v1/runtime/users/:name/limits",
                put(handlers::user_limits_set).delete(handlers::user_limits_restore),
            )
            .route(
                "/api/v1/runtime/users/:name/quota/reset",
                post(handlers::user_quota_reset),
            )
            .route(
                "/api/v1/runtime/users/:name/disconnect",
                post(handlers::user_disconnect),
            )
            .route("/api/v1/runtime/events", get(handlers::events))
            .route("/api/v1/runtime/admission", get(handlers::admission))
            .route("/api/v1/runtime/stats", get(handlers::stats))
            .route("/api/v1/runtime/status", get(handlers::status))
            .route(
                "/api/v1/runtime/connections",
                get(handlers::connections).delete(handlers::connections_close),
            )
            .route(
                "/api/v1/runtime/connections/report",
                post(handlers::connections_report),
            )
            .route(
                "/api/v1/runtime/connections/:id",
                delete(handlers::connection_close),
            )
            .route(
                "/api/v1/runtime/outbound/:tag/last_peer_active",
                get(handlers::last_peer_active),
            )
            .route(
                "/api/v1/runtime/outbound/:tag/since_last_peer_active",
                get(handlers::since_last_peer_active),
            )
            .route(
                "/api/v1/runtime/outbound/:tag/health",
                get(handlers::outbound_health),
            );

        let mut app = app.with_state(self.runtime_manager.clone());
        if let Some(secret) = secret {
            app = app.layer(middleware::from_fn_with_state(
                Arc::<str>::from(secret),
                authorize,
            ));
        }
        Box::pin(async move {
            futures::future::join_all(listeners.into_iter().map(|l| accept(l, app.clone()))).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_tells_no_more_of_a_url_than_its_host() {
        assert_eq!(
            without_url_secrets(
                "[p] provider: \"https://user:pw@sub.example:8443/link?token=abc\": 403, \
                 and http://h/x too"
            ),
            "[p] provider: \"https://sub.example:8443/…\": 403, and http://h/… too"
        );
        assert_eq!(
            without_url_secrets("outbounds[0].type: unknown \"nope\""),
            "outbounds[0].type: unknown \"nope\""
        );
    }
}
