//! `/proxies` and `/group`: the outbounds and groups, as Mihomo shows them
//! (type, `now`, `all`, the delays measured), selecting a group's member,
//! and measuring delays. What they tell is the instance's, through
//! [`crate::control`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Map, Value};

use super::{ApiError, Clash};
use crate::app::healthcheck::DEFAULT_URL;
use crate::control::{ControlError, OutboundInfo};

/// A delay as Mihomo gives it: milliseconds, at least 1.
pub(super) fn millis(delay: Duration) -> u64 {
    delay.as_millis().max(1) as u64
}

/// `outbound` as Mihomo shows an outbound or a group.
pub(super) fn proxy(outbound: &OutboundInfo) -> Value {
    let alive = outbound.history.last().is_none_or(|d| d.delay.is_some());
    let mut proxy = Map::new();
    proxy.insert("name".into(), json!(outbound.tag));
    proxy.insert("type".into(), json!(outbound.kind));
    proxy.insert("udp".into(), json!(outbound.udp));
    proxy.insert("xudp".into(), json!(false));
    proxy.insert("tfo".into(), json!(false));
    proxy.insert("alive".into(), json!(alive));
    proxy.insert(
        "history".into(),
        Value::Array(
            outbound
                .history
                .iter()
                .map(|d| {
                    json!({
                        "time": crate::util::rfc3339::millis(d.time),
                        "delay": d.delay.map_or(0, millis),
                    })
                })
                .collect(),
        ),
    );
    proxy.insert("extra".into(), json!({}));
    if let Some(group) = &outbound.group {
        proxy.insert("now".into(), json!(group.selected));
        proxy.insert("all".into(), json!(group.members));
        proxy.insert("hidden".into(), json!(false));
        proxy.insert("icon".into(), json!(""));
        proxy.insert(
            "testUrl".into(),
            json!(group.test_url.as_deref().unwrap_or("")),
        );
        // As Mihomo's groups that test, `*` for any (adapter/outboundgroup/
        // fallback.go, parser.go); "" for one that does not.
        proxy.insert(
            "expectedStatus".into(),
            json!(group.expected_status.as_deref().unwrap_or("")),
        );
        if !group.selectable {
            proxy.insert("fixed".into(), json!(group.fixed.as_deref().unwrap_or("")));
        }
    }
    Value::Object(proxy)
}

/// A delay test's failure, as Mihomo answers it.
pub(super) fn delay_error(e: ControlError) -> ApiError {
    match e {
        ControlError::NotFound(_) => ApiError::not_found(),
        ControlError::Failed(_) => ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred in the delay test".into(),
        ),
        ControlError::Timeout => ApiError(StatusCode::GATEWAY_TIMEOUT, "Timeout".into()),
        e => ApiError::bad_request(e.to_string()),
    }
}

/// The URL and timeout of a delay test, as dashboards give them.
pub(super) fn test_params(
    params: &HashMap<String, String>,
) -> Result<(String, Duration), ApiError> {
    let timeout: u64 = params
        .get("timeout")
        .and_then(|t| t.parse().ok())
        .filter(|t| *t > 0)
        .ok_or_else(|| ApiError::bad_request("Body invalid"))?;
    let url = params
        .get("url")
        .filter(|u| !u.is_empty())
        .cloned()
        .unwrap_or_else(|| DEFAULT_URL.to_string());
    Ok((url, Duration::from_millis(timeout)))
}

pub(super) async fn list(State(clash): State<Arc<Clash>>) -> Json<Value> {
    let outbounds = clash.rm.outbounds().await;
    let mut proxies: Map<String, Value> = outbounds
        .iter()
        .map(|o| (o.tag.clone(), proxy(o)))
        .collect();
    // Mihomo's GLOBAL group, as sing-box shows it, unless an outbound is so
    // tagged (a Clash configuration's is).
    if !proxies.contains_key("GLOBAL") {
        let default = clash.rm.default_outbound().unwrap_or_default();
        let mut all: Vec<&String> = outbounds
            .iter()
            .filter(|o| {
                o.protocol.as_deref().is_some_and(|p| {
                    !matches!(p, "direct" | "drop" | "block" | "reject" | "pass" | "dns")
                })
            })
            .map(|o| &o.tag)
            .collect();
        all.sort();
        if let Some(i) = all.iter().position(|t| **t == default) {
            let d = all.remove(i);
            all.insert(0, d);
        }
        proxies.insert(
            "GLOBAL".into(),
            json!({
                "name": "GLOBAL", "type": "Fallback", "udp": true, "history": [],
                "all": all, "now": default, "hidden": true, "icon": "",
            }),
        );
    }
    Json(json!({ "proxies": proxies }))
}

pub(super) async fn one(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    clash
        .rm
        .outbound(&name)
        .await
        .map(|o| Json(proxy(&o)))
        .ok_or_else(ApiError::not_found)
}

/// Selects `{"name": member}` of the group `name`, which must be a
/// selector: the choice is kept in the cache file, as sing-box keeps it.
pub(super) async fn select(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let body: Map<String, Value> =
        serde_json::from_slice(&body).map_err(|_| ApiError::bad_request("Body invalid"))?;
    let member = body
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad_request("Body invalid"))?;
    match clash.rm.select(&name, member).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(ControlError::Rejected(e)) => Err(ApiError::bad_request(format!(
            "Selector update error: {}",
            e
        ))),
        Err(_) => Err(ApiError::bad_request("Must be a Selector")),
    }
}

/// Unpins a group that selects by itself, as Mihomo does; nothing to undo
/// for one that is not pinned, but for a selector, which is not such.
pub(super) async fn unfix(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    match clash.rm.unfix(&name).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(ControlError::NotFound(_)) => Err(ApiError::not_found()),
        Err(_) => Err(ApiError::bad_request("Must not be a Selector")),
    }
}

pub(super) async fn delay(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (url, timeout) = test_params(&params)?;
    let delay = clash
        .rm
        .url_test(&name, Some(&url), timeout)
        .await
        .map_err(delay_error)?;
    Ok(Json(json!({ "delay": millis(delay) })))
}

/// The groups, as an array, as Mihomo gives them.
pub(super) async fn groups(State(clash): State<Arc<Clash>>) -> Json<Value> {
    let groups: Vec<Value> = clash.rm.groups().await.iter().map(proxy).collect();
    Json(json!({ "proxies": groups }))
}

pub(super) async fn group(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    clash
        .rm
        .outbound(&name)
        .await
        .filter(|o| o.group.is_some())
        .map(|o| Json(proxy(&o)))
        .ok_or_else(ApiError::not_found)
}

/// Measures each member of the group `name`, ten at a time: their delays
/// by name, those that failed left out, as Mihomo answers.
pub(super) async fn group_delay(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (url, timeout) = test_params(&params)?;
    // Mihomo unpins the group it tests (hub/route/groups.go).
    let _ = clash.rm.unfix(&name).await;
    let delays = clash
        .rm
        .url_test_members(&name, Some(&url), timeout)
        .await
        // As sing-box answers: 404 for no such group, 504 with the
        // error's own text for any error of the test.
        .map_err(|e| match e {
            ControlError::NotFound(_) => ApiError::not_found(),
            e => ApiError(StatusCode::GATEWAY_TIMEOUT, e.to_string()),
        })?;
    let map: Map<String, Value> = delays
        .into_iter()
        .filter_map(|(m, d)| d.ok().map(|d| (m, json!(millis(d)))))
        .collect();
    Ok(Json(Value::Object(map)))
}
