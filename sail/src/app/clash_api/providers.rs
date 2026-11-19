//! `/providers/proxies` and `/providers/rules`: the outbound providers and
//! the rule-sets, as Mihomo shows its proxy and rule providers, updating
//! them, and measuring a provider's members.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Map, Value};

use super::proxies::test_params;
#[cfg(feature = "outbound-provider")]
use super::proxies::{delay_error, millis, proxy};
use super::{ApiError, Clash};

/// How long a provider's health check waits on each member.
#[cfg(feature = "outbound-provider")]
const HEALTH_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A time as Mihomo gives it; Go's zero time for none.
#[cfg(any(feature = "outbound-provider", feature = "rule-set"))]
fn time(at: Option<std::time::SystemTime>) -> String {
    match at {
        Some(at) => crate::util::rfc3339::seconds(at),
        None => "0001-01-01T00:00:00Z".to_string(),
    }
}

#[cfg(any(feature = "outbound-provider", feature = "rule-set"))]
fn update_failed(e: impl std::fmt::Display) -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("{:#}", e))
}

#[cfg(feature = "outbound-provider")]
impl Clash {
    fn provider(&self, name: &str) -> Result<Arc<crate::app::provider::Provider>, ApiError> {
        self.rm
            .outbound_manager()
            .providers()
            .all()
            .iter()
            .find(|p| &*p.tag == name)
            .cloned()
            .ok_or_else(ApiError::not_found)
    }

    /// Measures the member `name` of the provider `provider`.
    async fn probe_member(
        &self,
        provider: &str,
        name: &str,
        url: &str,
        timeout: std::time::Duration,
    ) -> Result<std::time::Duration, ApiError> {
        self.rm
            .url_test_provider_member(provider, name, Some(url), timeout)
            .await
            .map_err(delay_error)
    }

    async fn show_provider(&self, info: &crate::control::ProviderInfo) -> Value {
        use crate::control::SourceKind;
        let proxies: Vec<Value> = self
            .rm
            .provider_members(&info.tag)
            .await
            .unwrap_or_default()
            .iter()
            .map(proxy)
            .collect();
        let mut shown = json!({
            "name": info.tag,
            "type": "Proxy",
            "vehicleType": match info.source {
                SourceKind::Remote => "HTTP",
                SourceKind::Local => "File",
                _ => "Inline",
            },
            "proxies": proxies,
            "testUrl": "",
            "expectedStatus": "*",
            "updatedAt": time(info.updated),
        });
        // As Mihomo gives it: seconds since the epoch, 0 for none.
        if let Some(s) = &info.subscription {
            shown["subscriptionInfo"] = json!({
                "Upload": s.upload,
                "Download": s.download,
                "Total": s.total,
                "Expire": s.expire.map_or(0, |e| e
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())),
            });
        }
        shown
    }
}

/// The outbound providers, by tag.
pub(super) async fn proxy_providers(State(clash): State<Arc<Clash>>) -> Json<Value> {
    #[cfg_attr(not(feature = "outbound-provider"), allow(unused_mut))]
    let mut providers = Map::new();
    #[cfg(feature = "outbound-provider")]
    for info in clash.rm.providers().await {
        providers.insert(info.tag.clone(), clash.show_provider(&info).await);
    }
    #[cfg(not(feature = "outbound-provider"))]
    let _ = clash;
    Json(json!({ "providers": providers }))
}

pub(super) async fn proxy_provider(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    #[cfg(feature = "outbound-provider")]
    {
        let info = clash
            .rm
            .provider(&name)
            .await
            .ok_or_else(ApiError::not_found)?;
        Ok(Json(clash.show_provider(&info).await))
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name);
        Err(ApiError::not_found())
    }
}

/// Downloads the provider, or reads its file, again.
pub(super) async fn update_proxy_provider(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    #[cfg(feature = "outbound-provider")]
    {
        match clash.rm.update_provider(&name).await {
            Ok(()) => Ok(StatusCode::NO_CONTENT),
            Err(crate::control::ControlError::NoProvider(_)) => Err(ApiError::not_found()),
            Err(e) => Err(update_failed(e)),
        }
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name);
        Err(ApiError::not_found())
    }
}

/// Measures every member of the provider, ten at a time, keeping their
/// delays, as Mihomo's health check does.
pub(super) async fn health_check(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    #[cfg(feature = "outbound-provider")]
    {
        use futures::StreamExt;
        let provider = clash.provider(&name)?;
        let names: Vec<String> = provider
            .members()
            .load()
            .members
            .iter()
            .map(|m| m.key.name.to_string())
            .collect();
        futures::stream::iter(names)
            .map(|member| {
                let clash = clash.clone();
                let name = name.clone();
                async move {
                    clash
                        .probe_member(
                            &name,
                            &member,
                            crate::app::healthcheck::DEFAULT_URL,
                            HEALTH_CHECK_TIMEOUT,
                        )
                        .await
                }
            })
            .buffer_unordered(10)
            .collect::<Vec<_>>()
            .await;
        Ok(StatusCode::NO_CONTENT)
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name);
        Err(ApiError::not_found())
    }
}

/// One member of the provider.
pub(super) async fn member(
    State(clash): State<Arc<Clash>>,
    Path((name, proxy)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    #[cfg(feature = "outbound-provider")]
    {
        clash.provider(&name)?;
        clash
            .rm
            .provider_members(&name)
            .await
            .unwrap_or_default()
            .iter()
            .find(|m| m.tag == proxy)
            .map(|m| Json(self::proxy(m)))
            .ok_or_else(ApiError::not_found)
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name, proxy);
        Err(ApiError::not_found())
    }
}

/// Measures one member of the provider, as `/proxies/:name/delay` does.
pub(super) async fn member_delay(
    State(clash): State<Arc<Clash>>,
    Path((name, proxy)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (url, timeout) = test_params(&params)?;
    #[cfg(feature = "outbound-provider")]
    {
        let delay = clash.probe_member(&name, &proxy, &url, timeout).await?;
        Ok(Json(json!({ "delay": millis(delay) })))
    }
    #[cfg(not(feature = "outbound-provider"))]
    {
        let _ = (clash, name, proxy, url, timeout);
        Err(ApiError::not_found())
    }
}

/// The rule-sets, by tag, as Mihomo's rule providers.
pub(super) async fn rule_providers(State(clash): State<Arc<Clash>>) -> Json<Value> {
    #[cfg_attr(not(feature = "rule-set"), allow(unused_mut))]
    let mut providers = Map::new();
    #[cfg(feature = "rule-set")]
    for set in clash.rm.router().rule_sets().list() {
        providers.insert(set.tag.clone(), rule_provider(&set));
    }
    #[cfg(not(feature = "rule-set"))]
    let _ = clash;
    Json(json!({ "providers": providers }))
}

#[cfg(feature = "rule-set")]
fn rule_provider(set: &crate::app::router::rule_set::Listed) -> Value {
    use crate::config::rule_set::{ClashBehavior, RuleSetFormat, RuleSetKind};
    json!({
        "name": set.tag,
        "type": "Rule",
        "vehicleType": match set.kind {
            RuleSetKind::Remote => "HTTP",
            RuleSetKind::Local => "File",
            RuleSetKind::Inline => "Inline",
        },
        // sing-box's rule-sets hold rules of every kind.
        "behavior": match set.behavior {
            Some(ClashBehavior::Domain) => "Domain",
            Some(ClashBehavior::Ipcidr) => "IPCIDR",
            Some(ClashBehavior::Classical) | None => "Classical",
        },
        "format": match set.format {
            Some(RuleSetFormat::ClashYaml) => "YamlRule",
            Some(RuleSetFormat::ClashText) => "TextRule",
            Some(RuleSetFormat::Mrs) => "MrsRule",
            Some(RuleSetFormat::Binary) => "Binary",
            Some(RuleSetFormat::Source) | None => "Source",
            #[allow(unreachable_patterns)]
            Some(_) => "Unknown",
        },
        "ruleCount": set.size,
        "updatedAt": time(set.updated),
    })
}

/// Downloads the rule-set again; one not downloaded is left as it is.
pub(super) async fn update_rule_provider(
    State(clash): State<Arc<Clash>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    #[cfg(feature = "rule-set")]
    {
        match clash.rm.update_rule_set(&name).await {
            Ok(()) => Ok(StatusCode::NO_CONTENT),
            Err(crate::control::ControlError::NoRuleSet(_)) => Err(ApiError::not_found()),
            Err(e) => Err(update_failed(e)),
        }
    }
    #[cfg(not(feature = "rule-set"))]
    {
        let _ = (clash, name);
        Err(ApiError::not_found())
    }
}
