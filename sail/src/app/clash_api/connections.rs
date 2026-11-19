//! `/connections` and `/rules`: the connections open now, as Mihomo lists
//! them, closing them, and the routing rules, as Mihomo lists its own:
//! a type, a payload and a proxy (describe.rs).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::StreamExt;
use serde_json::{json, Value};

use super::streams::send;
use super::Clash;
use crate::control::ConnectionInfo;
use crate::RuntimeManager;

/// How often a WebSocket is sent the connections, unless `?interval=`
/// (milliseconds) says otherwise, as in Mihomo.
const INTERVAL: Duration = Duration::from_millis(1000);

/// The shortest interval taken: a dashboard cannot ask for a busy loop.
const INTERVAL_MIN: Duration = Duration::from_millis(100);

/// The connections now, once, or, over a WebSocket, every interval.
pub(super) async fn list(
    State(clash): State<Arc<Clash>>,
    Query(query): Query<HashMap<String, String>>,
    ws: Option<WebSocketUpgrade>,
) -> Response {
    let Some(ws) = ws else {
        return Json(snapshot(&clash.rm).await).into_response();
    };
    let interval = query
        .get("interval")
        .and_then(|ms| ms.parse().ok())
        .map(Duration::from_millis)
        .unwrap_or(INTERVAL)
        .max(INTERVAL_MIN);
    let frames =
        futures::stream::unfold(tokio::time::interval(interval), |mut interval| async move {
            interval.tick().await;
            Some(((), interval))
        })
        .then(move |()| {
            let clash = clash.clone();
            async move { snapshot(&clash.rm).await }
        });
    send(Some(ws), frames)
}

/// Each rule's Mihomo type and payload, by the words a connection it
/// decided carries.
type Told = HashMap<String, (String, String)>;

async fn snapshot(rm: &RuntimeManager) -> Value {
    let traffic = rm.traffic().await;
    let connections = rm.connections().await;
    let router = rm.router();
    let view = rm.clash_view();
    let told: Told = router
        .rules()
        .map(|about| {
            (
                about.matched.to_string(),
                (
                    about.clash_type.to_string(),
                    about.clash_payload.to_string(),
                ),
            )
        })
        .collect();
    json!({
        "downloadTotal": traffic.down_total,
        "uploadTotal": traffic.up_total,
        "connections": connections
            .iter()
            .map(|c| connection(c, &told, &view.inbounds))
            .collect::<Vec<_>>(),
        "memory": crate::control::resident_memory(),
    })
}

/// A connection as Mihomo lists one. Its rule is the one it matched, as
/// Mihomo types it, with its payload; none matched is Mihomo's `Match`;
/// one of a configuration since replaced goes by sail's words for it.
fn connection(c: &ConnectionInfo, told: &Told, inbounds: &HashMap<String, (String, u16)>) -> Value {
    let inbound = inbounds.get(&c.inbound_tag);
    let (rule, payload) = match c.rule.as_deref() {
        None => ("Match", ""),
        Some(matched) => match told.get(matched) {
            Some((kind, payload)) => (kind.as_str(), payload.as_str()),
            None => (matched, ""),
        },
    };
    let start = crate::util::rfc3339::seconds_from_unix(i64::from(c.start))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
    let mut value = json!({
        "id": c.id.to_string(),
        "metadata": {
            "network": c.network.to_string(),
            "type": format!("{}/{}", c.inbound_type, c.inbound_tag),
            "sourceIP": c.source.ip().to_string(),
            "sourcePort": c.source.port().to_string(),
            "destinationIP": c.destination.ip().map(|ip| ip.to_string()).unwrap_or_default(),
            "destinationPort": c.destination.port().to_string(),
            "host": c.host.clone().unwrap_or_default(),
            "sniffHost": c.sniff_host.clone().unwrap_or_default(),
            "dialDomainSource": c.dial_domain_source.unwrap_or_default(),
            "dnsMode": if c.reverse_mapped { "mapping" } else { "normal" },
            "processPath": c.process.clone().unwrap_or_default(),
            // The process's name, its path's last part, as Mihomo's.
            "process": c.process.as_deref().map(process_name).unwrap_or_default(),
            "inboundName": c.inbound_tag,
            "inboundIP": inbound.map(|(ip, _)| ip.as_str()).unwrap_or_default(),
            "inboundPort": inbound.map(|(_, port)| port.to_string()).unwrap_or_default(),
            "inboundUser": c.user.clone().unwrap_or_default(),
            // sail reads no DSCP, and keeps no special proxy or rules.
            "dscp": 0,
            "specialProxy": "",
            "specialRules": "",
            "remoteDestination": "",
        },
        "upload": c.upload,
        "download": c.download,
        "start": start,
        "chains": c.chains,
        "rule": rule,
        "rulePayload": payload,
    });
    // The user the process runs as, where it is known (Android, Linux).
    if let Some(uid) = c.uid {
        value["metadata"]["uid"] = json!(uid);
    }
    value
}

/// A process's name, the last part of its path, Windows' or Unix's.
fn process_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

/// A time in milliseconds since the epoch as Mihomo writes one, RFC 3339;
/// 0, never, as Go's zero time.
fn time_of(millis: u64) -> String {
    match i64::try_from(millis)
        .ok()
        .filter(|m| *m > 0)
        .and_then(crate::util::rfc3339::millis_from_unix)
    {
        Some(at) => at,
        None => "0001-01-01T00:00:00Z".into(),
    }
}

/// Turns rules off and on again, by their index among `/rules`: the body
/// is `{"<index>": true}` to turn one off, `false` on, as Mihomo's. An
/// index of no rule is passed over; what is set lasts until a reload.
pub(super) async fn disable_rules(
    State(clash): State<Arc<Clash>>,
    body: axum::body::Bytes,
) -> Result<StatusCode, super::ApiError> {
    let wanted: HashMap<String, bool> =
        serde_json::from_slice(&body).map_err(|_| super::ApiError::bad_request("Body invalid"))?;
    let router = clash.rm.router();
    for (index, disabled) in wanted {
        let index: usize = index
            .parse()
            .map_err(|_| super::ApiError::bad_request("Body invalid"))?;
        router.set_disabled(index, disabled);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Closes every connection.
pub(super) async fn close_all(State(clash): State<Arc<Clash>>) -> StatusCode {
    clash.rm.close_all_connections().await;
    StatusCode::NO_CONTENT
}

/// Closes one; one there is not is no error, as in Mihomo.
pub(super) async fn close(State(clash): State<Arc<Clash>>, Path(id): Path<String>) -> StatusCode {
    if let Ok(id) = id.parse() {
        clash.rm.close_connection(id).await;
    }
    StatusCode::NO_CONTENT
}

/// The routing rules, in order, as Mihomo lists its own: `size` is the
/// number of rules of the rule-sets a `RuleSet` names, -1 for another.
pub(super) async fn rules(State(clash): State<Arc<Clash>>) -> Json<Value> {
    let router = clash.rm.router();
    let sizes: HashMap<String, usize> = router
        .rule_sets()
        .list()
        .into_iter()
        .map(|set| (set.tag, set.size))
        .collect();
    let rules: Vec<Value> = router
        .rules_with_stats()
        .enumerate()
        .map(|(index, (about, proxy, stats))| {
            let size = if about.clash_type == "RuleSet" {
                about
                    .rule_sets
                    .iter()
                    .map(|tag| sizes.get(tag).copied().unwrap_or(0) as i64)
                    .sum::<i64>()
            } else {
                -1
            };
            json!({
                "index": index,
                "type": about.clash_type,
                "payload": about.clash_payload,
                "proxy": proxy,
                "size": size,
                // Mihomo's, but for the misses, which sail does not count.
                "extra": {
                    "disabled": stats.disabled,
                    "hitCount": stats.hits,
                    "hitAt": time_of(stats.hit_at),
                },
            })
        })
        .collect();
    Json(json!({ "rules": rules }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As Mihomo's: `mapping` where the name came from the DNS answers
    /// given for the address, else `normal`.
    #[test]
    fn the_dns_mode_is_mapping_for_a_reverse_mapped_name() {
        let info = |reverse_mapped: bool| ConnectionInfo {
            id: 1,
            network: crate::session::Network::Tcp,
            inbound_type: "tun".into(),
            inbound_tag: "tun".into(),
            source: "127.0.0.1:1".parse().unwrap(),
            destination: crate::session::SocksAddr::from((
                "192.0.2.1".parse::<std::net::IpAddr>().unwrap(),
                443,
            )),
            host: Some("mapped.test".into()),
            sniff_host: None,
            dial_domain_source: None,
            reverse_mapped,
            process: None,
            user: None,
            uid: None,
            packages: Vec::new(),
            upload: 0,
            download: 0,
            start: 0,
            chains: Vec::new(),
            rule: None,
        };
        let told = Told::new();
        assert_eq!(
            connection(&info(true), &told, &HashMap::new())["metadata"]["dnsMode"],
            "mapping"
        );
        assert_eq!(
            connection(&info(false), &told, &HashMap::new())["metadata"]["dnsMode"],
            "normal"
        );
    }

    /// A connection's rule is the one it matched, as Mihomo types it, with
    /// its payload; none matched is `Match`.
    #[test]
    fn a_connection_s_rule_is_mihomo_s() {
        let mut c = ConnectionInfo {
            id: 1,
            network: crate::session::Network::Tcp,
            inbound_type: "tun".into(),
            inbound_tag: "tun".into(),
            source: "127.0.0.1:1".parse().unwrap(),
            destination: crate::session::SocksAddr::from((
                "192.0.2.1".parse::<std::net::IpAddr>().unwrap(),
                443,
            )),
            host: None,
            sniff_host: None,
            dial_domain_source: None,
            reverse_mapped: false,
            process: None,
            user: None,
            uid: None,
            packages: Vec::new(),
            upload: 0,
            download: 0,
            start: 0,
            chains: Vec::new(),
            rule: None,
        };
        let mut told = Told::new();
        told.insert(
            "domain_suffix=a.com => route(proxy)".into(),
            ("DomainSuffix".into(), "a.com".into()),
        );
        let rule = |c: &ConnectionInfo| {
            let v = connection(c, &told, &HashMap::new());
            (v["rule"].clone(), v["rulePayload"].clone())
        };
        assert_eq!(rule(&c), (json!("Match"), json!("")));
        c.rule = Some("domain_suffix=a.com => route(proxy)".into());
        assert_eq!(rule(&c), (json!("DomainSuffix"), json!("a.com")));
        c.rule = Some("port=1 => route(gone)".into());
        assert_eq!(rule(&c), (json!("port=1 => route(gone)"), json!("")));
    }

    #[test]
    fn a_process_is_named_by_its_path_s_last_part() {
        assert_eq!(process_name("/usr/bin/curl"), "curl");
        assert_eq!(process_name("C:\\Program Files\\a.exe"), "a.exe");
        assert_eq!(process_name("curl"), "curl");
        assert_eq!(time_of(0), "0001-01-01T00:00:00Z");
        assert_eq!(time_of(1_000), "1970-01-01T00:00:01.000Z");
    }
}
