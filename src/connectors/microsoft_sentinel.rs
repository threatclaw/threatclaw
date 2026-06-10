//! Microsoft Sentinel ingestion. Pulls incidents, alerts, entities, and
//! analytic-rule context into the ThreatClaw incident pipeline.
//!
//! Auth: shared with microsoft_graph via crate::connectors::microsoft_auth,
//! scope `https://management.azure.com/.default`.
//!
//! API version: 2024-09-01 across all Microsoft.SecurityInsights endpoints.

use chrono::{DateTime, Utc};
use reqwest::Client;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;

use crate::connectors::microsoft_auth::{AuthMethod, MicrosoftAuthCache};

pub const API_VERSION: &str = "2024-09-01";
pub const ARM_SCOPE: &str = "https://management.azure.com/.default";

#[derive(Debug, Clone)]
pub struct MicrosoftSentinelConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub auth_method: AuthMethod,
    pub credential: SecretString,
    pub subscription_id: String,
    pub resource_group: String,
    pub workspace_name: String,
    pub workspace_id: Uuid,
    pub enable_comment_write: bool,
    /// Test-only override: when Some, redirects BOTH the ARM endpoint
    /// (management.azure.com) AND the OAuth token endpoint
    /// (login.microsoftonline.com/<tenant>/oauth2/v2.0/token) to this base URL,
    /// AND bypasses the shared MicrosoftAuthCache + certificate-flow path in
    /// favor of an inline Secret-flow token request. Production builds MUST
    /// leave this None. See `acquire_arm_token` for the gory details.
    ///
    /// TODO(skill-microsoft-sentinel): a future refactor should plumb a
    /// token-endpoint override through microsoft_auth.rs itself (e.g. a
    /// new `acquire_token_with_token_base` helper) so this field can become
    /// a single-endpoint override and the test branch in acquire_arm_token
    /// can go away.
    pub arm_base_override: Option<String>,
}

impl MicrosoftSentinelConfig {
    pub fn arm_base(&self) -> String {
        self.arm_base_override
            .clone()
            .unwrap_or_else(|| "https://management.azure.com".to_string())
    }

    pub fn workspace_path(&self) -> String {
        format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.OperationalInsights/workspaces/{}/providers/Microsoft.SecurityInsights",
            self.subscription_id, self.resource_group, self.workspace_name
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentinelSyncCursors {
    pub last_incident_modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Default, Serialize)]
pub struct SentinelSyncResult {
    pub incidents_pulled: u32,
    pub incidents_new: u32,
    pub incidents_updated: u32,
    pub alerts_pulled: u32,
    pub entities_pulled: u32,
    pub comments_posted: u32,
    pub dedup_skipped: u32,
    pub errors: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("auth: {0}")]
    Auth(#[from] crate::connectors::microsoft_auth::AuthError),
    #[error("http: {0}")]
    Http(#[from] crate::connectors::microsoft_auth::HttpError),
    #[error("transport: {0}")]
    Transport(String),
    #[error("parse: {0}")]
    Parse(String),
}

// Manual impl rather than #[from] on the Transport variant.
//
// Task 7 of this skill plan previously removed a Transport(#[from] reqwest::Error)
// variant because thiserror's #[from] generation conflicted with the
// existing Http(#[from] HttpError) variant (HttpError itself has
// From<reqwest::Error>, creating two From<reqwest::Error> paths and
// breaking ? propagation).
//
// This manual impl re-introduces a direct reqwest::Error -> SentinelError
// path without triggering that conflict because thiserror does NOT
// generate a transitive From<reqwest::Error> for SentinelError through
// Http(#[from] HttpError) -- it only generates the direct newtype
// conversions. Do NOT replace this with a #[from] annotation on a
// Transport variant: it will reintroduce the Task 7 conflict.
impl From<reqwest::Error> for SentinelError {
    fn from(e: reqwest::Error) -> Self {
        SentinelError::Transport(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatclawStatus {
    Open,
    Investigating,
    Resolved,
    FalsePositive,
}

impl ThreatclawStatus {
    pub fn as_db_value(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Investigating => "investigating",
            Self::Resolved => "resolved",
            Self::FalsePositive => "false_positive",
        }
    }
}

/// Map a Sentinel incident status + classification pair to the equivalent
/// ThreatClaw status. Unknown values fall back to `Open` so we never silently
/// hide an incident on shape changes (Microsoft has added status values
/// over the years; failing open is safer than failing closed).
pub fn map_sentinel_status(status: &str, classification: Option<&str>) -> ThreatclawStatus {
    match (status, classification) {
        ("New", _) => ThreatclawStatus::Open,
        ("Active", _) => ThreatclawStatus::Investigating,
        ("Closed", Some("FalsePositive")) => ThreatclawStatus::FalsePositive,
        ("Closed", _) => ThreatclawStatus::Resolved,
        _ => ThreatclawStatus::Open,
    }
}

/// Normalized representation of a single Sentinel incident extracted from the
/// `GET /incidents` REST response. Only the fields ThreatClaw actually
/// persists or correlates are surfaced; the rest of the Sentinel envelope is
/// intentionally discarded.
#[derive(Debug, Clone)]
pub struct ParsedSentinelIncident {
    pub sentinel_incident_id: Uuid,
    pub incident_number: i32,
    pub etag: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub classification: Option<String>,
    pub classification_reason: Option<String>,
    pub provider_name: String,
    pub provider_incident_id: Option<String>,
    pub provider_incident_url: Option<String>,
    pub related_analytic_rule_ids: Vec<String>,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub last_modified_utc: DateTime<Utc>,
    pub created_utc: DateTime<Utc>,
}

/// Parse the body of `GET /incidents?api-version=...` into a vec of
/// `ParsedSentinelIncident`. The Sentinel envelope shape is `{ "value": [...] }`
/// where each item carries an ARM resource `name` (the incident UUID), an
/// `etag` (used for optimistic concurrency on later updates) and a `properties`
/// bag. `relatedAnalyticRuleIds` arrives as full ARM paths; we keep only the
/// trailing UUID segment so downstream joins use the same key as the
/// alert-rules sync. MITRE `tactics`/`techniques` live under
/// `properties.additionalData` and are optional. Unknown fields are ignored.
pub fn parse_incidents_response(body: &str) -> Result<Vec<ParsedSentinelIncident>, SentinelError> {
    #[derive(Deserialize)]
    struct Wire {
        value: Vec<WireInc>,
    }
    #[derive(Deserialize)]
    struct WireInc {
        name: String,
        etag: String,
        properties: WireProps,
    }
    #[derive(Deserialize)]
    struct WireProps {
        title: String,
        description: Option<String>,
        severity: String,
        status: String,
        classification: Option<String>,
        #[serde(rename = "classificationReason")]
        classification_reason: Option<String>,
        #[serde(rename = "providerName")]
        provider_name: String,
        #[serde(rename = "providerIncidentId")]
        provider_incident_id: Option<String>,
        #[serde(rename = "incidentUrl")]
        incident_url: Option<String>,
        #[serde(rename = "incidentNumber")]
        incident_number: i32,
        #[serde(rename = "relatedAnalyticRuleIds")]
        related_analytic_rule_ids: Option<Vec<String>>,
        #[serde(rename = "additionalData")]
        additional_data: Option<JsonValue>,
        #[serde(rename = "lastModifiedTimeUtc")]
        last_modified_utc: DateTime<Utc>,
        #[serde(rename = "createdTimeUtc")]
        created_utc: DateTime<Utc>,
    }

    let wire: Wire = serde_json::from_str(body).map_err(|e| SentinelError::Parse(e.to_string()))?;
    let mut out = Vec::with_capacity(wire.value.len());
    for w in wire.value {
        let uuid = Uuid::parse_str(&w.name)
            .map_err(|e| SentinelError::Parse(format!("incident.name not uuid: {e}")))?;
        let rule_ids = w
            .properties
            .related_analytic_rule_ids
            .unwrap_or_default()
            .into_iter()
            .filter_map(|full| full.rsplit('/').next().map(|s| s.to_string()))
            .collect();
        let (tactics, techniques) = match w.properties.additional_data.as_ref() {
            Some(JsonValue::Object(map)) => (
                map.get("tactics")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                map.get("techniques")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
            _ => (Vec::new(), Vec::new()),
        };
        out.push(ParsedSentinelIncident {
            sentinel_incident_id: uuid,
            incident_number: w.properties.incident_number,
            etag: w.etag,
            title: w.properties.title,
            description: w.properties.description,
            severity: w.properties.severity,
            status: w.properties.status,
            classification: w.properties.classification,
            classification_reason: w.properties.classification_reason,
            provider_name: w.properties.provider_name,
            provider_incident_id: w.properties.provider_incident_id,
            provider_incident_url: w.properties.incident_url,
            related_analytic_rule_ids: rule_ids,
            tactics,
            techniques,
            last_modified_utc: w.properties.last_modified_utc,
            created_utc: w.properties.created_utc,
        });
    }
    Ok(out)
}

/// Normalized representation of a single Sentinel alert extracted from the
/// `POST /incidents/{id}/alerts` REST response. `providerAlertId` is the
/// dedup key against Defender Graph ingestion (same alert can land via both
/// surfaces); `systemAlertId` is Sentinel's own UUID. MITRE techniques live
/// JSON-string-encoded under `additionalData.MitreTechniques` and are
/// extracted into a flat `Vec<String>`. The raw `additionalData` bag is kept
/// in `additional_data` for downstream consumers that need the full envelope.
#[derive(Debug, Clone)]
pub struct ParsedSentinelAlert {
    pub system_alert_id: Uuid,
    pub provider_alert_id: String,
    pub provider_name: String,
    pub vendor_name: Option<String>,
    pub product_name: Option<String>,
    pub alert_display_name: String,
    pub description: Option<String>,
    pub severity: String,
    pub confidence_level: Option<String>,
    pub status: Option<String>,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub alert_link: Option<String>,
    pub start_time_utc: Option<DateTime<Utc>>,
    pub end_time_utc: Option<DateTime<Utc>>,
    pub time_generated: Option<DateTime<Utc>>,
    pub additional_data: Option<JsonValue>,
}

/// Normalized representation of a single Sentinel entity extracted from the
/// `POST /incidents/{id}/entities` REST response. Sentinel ships many entity
/// kinds (Account, Host, Ip, FileHash, ...) with kind-specific property
/// shapes; we keep `raw_properties` as an opaque JsonValue (persisted as
/// JSONB) and surface `friendlyName` separately because asset resolution
/// hits it first.
#[derive(Debug, Clone)]
pub struct ParsedSentinelEntity {
    pub kind: String,
    pub friendly_name: Option<String>,
    pub raw_properties: JsonValue,
}

/// Parse the body of `POST /incidents/{id}/alerts?api-version=...` into a vec
/// of `ParsedSentinelAlert`. The Sentinel envelope shape is
/// `{ "value": [ { "properties": {...} } ] }`. `provider_name` is sourced
/// from `productName` (Microsoft uses values like "Azure Sentinel" or
/// "Microsoft XDR"). MITRE techniques are stored as a JSON-encoded string
/// inside `additionalData.MitreTechniques` (not a native JSON array); we
/// best-effort-decode that string and fall back to an empty list when the
/// shape diverges. Unknown fields are ignored.
pub fn parse_alerts_response(body: &str) -> Result<Vec<ParsedSentinelAlert>, SentinelError> {
    #[derive(Deserialize)]
    struct Wire {
        value: Vec<WireAlert>,
    }
    #[derive(Deserialize)]
    struct WireAlert {
        properties: WireProps,
    }
    #[derive(Deserialize)]
    struct WireProps {
        #[serde(rename = "systemAlertId")]
        system_alert_id: String,
        #[serde(rename = "providerAlertId")]
        provider_alert_id: String,
        #[serde(rename = "productName")]
        product_name: Option<String>,
        #[serde(rename = "vendorName")]
        vendor_name: Option<String>,
        #[serde(rename = "alertDisplayName")]
        alert_display_name: String,
        description: Option<String>,
        severity: String,
        #[serde(rename = "confidenceLevel")]
        confidence_level: Option<String>,
        status: Option<String>,
        tactics: Option<Vec<String>>,
        #[serde(rename = "alertLink")]
        alert_link: Option<String>,
        #[serde(rename = "startTimeUtc")]
        start_time_utc: Option<DateTime<Utc>>,
        #[serde(rename = "endTimeUtc")]
        end_time_utc: Option<DateTime<Utc>>,
        #[serde(rename = "timeGenerated")]
        time_generated: Option<DateTime<Utc>>,
        #[serde(rename = "additionalData")]
        additional_data: Option<JsonValue>,
    }

    let wire: Wire = serde_json::from_str(body).map_err(|e| SentinelError::Parse(e.to_string()))?;
    let mut out = Vec::with_capacity(wire.value.len());
    for w in wire.value {
        // provider_name comes from productName (e.g., "Microsoft XDR" or "Azure Sentinel")
        let provider_name = w.properties.product_name.clone().unwrap_or_default();
        // techniques are JSON-string-encoded inside additionalData.MitreTechniques
        let techniques = match w.properties.additional_data.as_ref() {
            Some(JsonValue::Object(map)) => map
                .get("MitreTechniques")
                .and_then(|v| v.as_str())
                .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let system_alert_id = Uuid::parse_str(&w.properties.system_alert_id)
            .map_err(|e| SentinelError::Parse(format!("systemAlertId not uuid: {e}")))?;
        out.push(ParsedSentinelAlert {
            system_alert_id,
            provider_alert_id: w.properties.provider_alert_id,
            provider_name,
            vendor_name: w.properties.vendor_name,
            product_name: w.properties.product_name,
            alert_display_name: w.properties.alert_display_name,
            description: w.properties.description,
            severity: w.properties.severity,
            confidence_level: w.properties.confidence_level,
            status: w.properties.status,
            tactics: w.properties.tactics.unwrap_or_default(),
            techniques,
            alert_link: w.properties.alert_link,
            start_time_utc: w.properties.start_time_utc,
            end_time_utc: w.properties.end_time_utc,
            time_generated: w.properties.time_generated,
            additional_data: w.properties.additional_data,
        });
    }
    Ok(out)
}

/// Parse the body of `POST /incidents/{id}/entities?api-version=...` into a
/// vec of `ParsedSentinelEntity`. The envelope shape is
/// `{ "entities": [ { "kind": "...", "properties": {...} } ], "metaData": [...] }`.
/// The `entities` key is optional: an incident with zero related entities
/// returns `{}`, which must parse to an empty Vec rather than error.
/// Per-kind property shapes vary widely, so we keep the raw `properties`
/// object as JsonValue and only pull out `friendlyName` (the human-readable
/// label asset resolution uses as a first-pass key).
pub fn parse_entities_response(body: &str) -> Result<Vec<ParsedSentinelEntity>, SentinelError> {
    #[derive(Deserialize)]
    struct Wire {
        entities: Option<Vec<WireEnt>>,
    }
    #[derive(Deserialize)]
    struct WireEnt {
        kind: String,
        properties: Option<JsonValue>,
    }

    let wire: Wire = serde_json::from_str(body).map_err(|e| SentinelError::Parse(e.to_string()))?;
    let entities = wire.entities.unwrap_or_default();
    let mut out = Vec::with_capacity(entities.len());
    for w in entities {
        let raw = w.properties.unwrap_or(JsonValue::Null);
        let friendly_name = raw
            .get("friendlyName")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.push(ParsedSentinelEntity {
            kind: w.kind,
            friendly_name,
            raw_properties: raw,
        });
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct ParsedAnalyticRule {
    pub rule_id: Uuid,
    pub kind: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub severity: Option<String>,
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub query: Option<String>,
    pub query_frequency: Option<String>,
    pub query_period: Option<String>,
    pub trigger_operator: Option<String>,
    pub trigger_threshold: Option<i32>,
    pub enabled: Option<bool>,
    pub raw: JsonValue,
}

pub fn parse_analytic_rules_list(body: &str) -> Result<Vec<ParsedAnalyticRule>, SentinelError> {
    let wire: JsonValue =
        serde_json::from_str(body).map_err(|e| SentinelError::Parse(e.to_string()))?;
    let mut out = Vec::new();
    if let Some(arr) = wire.get("value").and_then(|v| v.as_array()) {
        for r in arr {
            let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
            // Microsoft sometimes returns non-UUID names like "BuiltInFusion"
            // for built-in rules. Our cache PK requires a UUID. Skip silently.
            let Ok(rule_id) = Uuid::parse_str(name) else {
                continue;
            };
            let p = r.get("properties").cloned().unwrap_or(JsonValue::Null);
            out.push(ParsedAnalyticRule {
                rule_id,
                kind: r.get("kind").and_then(|v| v.as_str()).map(str::to_string),
                display_name: p
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                description: p
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                severity: p
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                tactics: p
                    .get("tactics")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                techniques: p
                    .get("techniques")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                query: p.get("query").and_then(|v| v.as_str()).map(str::to_string),
                query_frequency: p
                    .get("queryFrequency")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                query_period: p
                    .get("queryPeriod")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                trigger_operator: p
                    .get("triggerOperator")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                trigger_threshold: p
                    .get("triggerThreshold")
                    .and_then(|v| v.as_i64())
                    .map(|x| x as i32),
                enabled: p.get("enabled").and_then(|v| v.as_bool()),
                raw: p,
            });
        }
    }
    Ok(out)
}

/// Whether an incident's provider name suggests its analytic rule is reachable
/// via the Sentinel `alertRules/{id}` endpoint. Microsoft Defender / XDR
/// incidents reference rules managed by Defender, which return 404 from
/// Sentinel's API. Skip the fetch for those.
pub fn should_fetch_analytic_rule(provider_name: &str) -> bool {
    !matches!(
        provider_name,
        "Microsoft XDR" | "Microsoft Defender" | "Microsoft Defender XDR"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupDecision {
    /// Insert the alert as a new Sentinel-sourced row in the DB.
    Insert,
    /// Skip the insert: this alert was already ingested via skill-microsoft-graph's
    /// Defender path. Attach the Sentinel incident metadata to the existing row.
    SkipMergeWithGraph,
}

/// Pure decision function for Sentinel-alert dedup.
///
/// Returns `SkipMergeWithGraph` only when BOTH:
/// 1. The alert's provider_name indicates it originated from Microsoft Defender
///    (which Sentinel wraps via the M365 Defender connector); AND
/// 2. The alert's `provider_alert_id` is in the set of `provider_alert_id`s
///    already ingested by skill-microsoft-graph's Defender path.
///
/// Sentinel-native alerts (Fusion, Scheduled, NRT, etc.) always Insert: they
/// never overlap with Graph Defender ingestion.
pub fn decide_dedup(
    alert: &ParsedSentinelAlert,
    known_graph_provider_alert_ids: &std::collections::HashSet<String>,
) -> DedupDecision {
    let is_defender_origin = matches!(
        alert.provider_name.as_str(),
        "Microsoft XDR" | "Microsoft Defender" | "Microsoft Defender XDR"
    );
    if is_defender_origin && known_graph_provider_alert_ids.contains(&alert.provider_alert_id) {
        DedupDecision::SkipMergeWithGraph
    } else {
        DedupDecision::Insert
    }
}

/// Token acquisition with optional ARM/token-endpoint override.
///
/// Production path (`cfg.arm_base_override == None`): delegates to
/// `microsoft_auth::acquire_token`, which uses the shared cache and the
/// configured auth method (cert or secret).
///
/// Test path (`cfg.arm_base_override == Some(uri)`): performs an inline
/// Secret-flow token request against `<uri>/<tenant>/oauth2/v2.0/token`
/// so wiremock can intercept it. This branch bypasses the cache,
/// hard-codes Secret flow (no certificate support in tests yet), and is
/// reachable ONLY when `arm_base_override` is set, which is documented
/// as test-only at the field declaration.
///
/// TODO(skill-microsoft-sentinel): replace this helper entirely with a
/// proper token-endpoint override plumbed through microsoft_auth.rs.
/// The test branch here exists because acquire_token in microsoft_auth.rs
/// hard-codes "https://login.microsoftonline.com" and there is no way to
/// stub that endpoint from a wiremock server short of an HTTP proxy.
async fn acquire_arm_token(
    cfg: &MicrosoftSentinelConfig,
    auth: &MicrosoftAuthCache,
    http: &Client,
) -> Result<String, SentinelError> {
    if let Some(base) = cfg.arm_base_override.as_deref() {
        use secrecy::ExposeSecret;
        let token_endpoint = format!(
            "{}/{}/oauth2/v2.0/token",
            base.trim_end_matches('/'),
            cfg.tenant_id
        );
        let form: Vec<(&str, String)> = vec![
            ("client_id", cfg.client_id.clone()),
            ("scope", ARM_SCOPE.to_string()),
            ("grant_type", "client_credentials".to_string()),
            ("client_secret", cfg.credential.expose_secret().to_string()),
        ];
        let resp = http.post(&token_endpoint).form(&form).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SentinelError::Parse(format!(
                "token endpoint HTTP {}: {}",
                status.as_u16(),
                body
            )));
        }
        #[derive(Deserialize)]
        struct TokenResp {
            access_token: String,
        }
        let parsed: TokenResp = resp
            .json()
            .await
            .map_err(|e| SentinelError::Parse(e.to_string()))?;
        return Ok(parsed.access_token);
    }

    let token = crate::connectors::microsoft_auth::acquire_token(
        auth,
        http,
        &cfg.tenant_id,
        &cfg.client_id,
        cfg.auth_method,
        &cfg.credential,
        ARM_SCOPE,
    )
    .await?;
    Ok(token)
}

/// Poll Sentinel for incidents that have changed since `cursor`. When
/// `cursor` is `None` (cold start) the call omits `$filter` and lets Sentinel
/// return the full incident list. When `cursor` is `Some`, we attach
/// `$filter=properties/lastModifiedTimeUtc gt <cursor>` plus
/// `$orderby=properties/lastModifiedTimeUtc asc` so the next cursor advance is
/// monotonic and so we can stop pagination as soon as an item lands earlier
/// than the cursor (defensive — Sentinel respects the order param).
///
/// The function only issues the first page; pagination over `nextLink` is a
/// follow-up task. Parsing is delegated to `parse_incidents_response`.
pub async fn poll_incidents_delta(
    cfg: &MicrosoftSentinelConfig,
    auth: &MicrosoftAuthCache,
    http: &Client,
    cursor: Option<DateTime<Utc>>,
) -> Result<Vec<ParsedSentinelIncident>, SentinelError> {
    let token = acquire_arm_token(cfg, auth, http).await?;

    let base_url = format!("{}{}/incidents", cfg.arm_base(), cfg.workspace_path());

    let mut query: Vec<(&str, String)> = vec![("api-version", API_VERSION.to_string())];
    if let Some(c) = cursor {
        let f = c.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        query.push((
            "$filter",
            format!("properties/lastModifiedTimeUtc gt {}", f),
        ));
        query.push(("$orderby", "properties/lastModifiedTimeUtc asc".to_string()));
    }

    let req = http
        .get(&base_url)
        .bearer_auth(&token)
        .query(&query)
        .build()?;
    let resp = crate::connectors::microsoft_auth::do_request_with_retry(http, req).await?;
    let body = resp
        .text()
        .await
        .map_err(|e| SentinelError::Parse(e.to_string()))?;
    parse_incidents_response(&body)
}

/// Fetch the alerts attached to a Sentinel incident via
/// `POST /incidents/{id}/alerts?api-version=...`.
///
/// Microsoft API quirk: this is a POST with an empty body, not a GET. The
/// Content-Length: 0 header is set explicitly because reqwest does not emit
/// it on POSTs with no body, and ARM rejects bodyless POSTs that omit it.
/// Parsing is delegated to `parse_alerts_response`.
pub async fn fetch_alerts_for_incident(
    cfg: &MicrosoftSentinelConfig,
    auth: &MicrosoftAuthCache,
    http: &Client,
    incident_id: Uuid,
) -> Result<Vec<ParsedSentinelAlert>, SentinelError> {
    let token = acquire_arm_token(cfg, auth, http).await?;
    let url = format!(
        "{}{}/incidents/{}/alerts?api-version={}",
        cfg.arm_base(),
        cfg.workspace_path(),
        incident_id,
        API_VERSION
    );
    let req = http
        .post(&url)
        .bearer_auth(&token)
        .header("Content-Length", "0")
        .build()?;
    let resp = crate::connectors::microsoft_auth::do_request_with_retry(http, req).await?;
    let body = resp
        .text()
        .await
        .map_err(|e| SentinelError::Parse(e.to_string()))?;
    parse_alerts_response(&body)
}

/// Fetch the entities attached to a Sentinel incident via
/// `POST /incidents/{id}/entities?api-version=...`.
///
/// Microsoft API quirk: this is a POST with an empty body, not a GET. The
/// Content-Length: 0 header is set explicitly because reqwest does not emit
/// it on POSTs with no body, and ARM rejects bodyless POSTs that omit it.
/// Parsing is delegated to `parse_entities_response`.
pub async fn fetch_entities_for_incident(
    cfg: &MicrosoftSentinelConfig,
    auth: &MicrosoftAuthCache,
    http: &Client,
    incident_id: Uuid,
) -> Result<Vec<ParsedSentinelEntity>, SentinelError> {
    let token = acquire_arm_token(cfg, auth, http).await?;
    let url = format!(
        "{}{}/incidents/{}/entities?api-version={}",
        cfg.arm_base(),
        cfg.workspace_path(),
        incident_id,
        API_VERSION
    );
    let req = http
        .post(&url)
        .bearer_auth(&token)
        .header("Content-Length", "0")
        .build()?;
    let resp = crate::connectors::microsoft_auth::do_request_with_retry(http, req).await?;
    let body = resp
        .text()
        .await
        .map_err(|e| SentinelError::Parse(e.to_string()))?;
    parse_entities_response(&body)
}

/// Top-level entry called by sync_scheduler. The MVP skeleton is a no-op that
/// returns an empty SyncResult. Each subsequent task in Phase 4 of the plan
/// fills in one behavior at a time, TDD-driven.
pub async fn sync_microsoft_sentinel(
    _config: &MicrosoftSentinelConfig,
    cursors: SentinelSyncCursors,
    _auth: &MicrosoftAuthCache,
) -> Result<(SentinelSyncResult, SentinelSyncCursors), SentinelError> {
    Ok((SentinelSyncResult::default(), cursors))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use wiremock::matchers::{header, method, path_regex, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn mock_token_endpoint(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path_regex(r"^/[^/]+/oauth2/v2\.0/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token_type": "Bearer", "expires_in": 3599, "access_token": "MOCK"
            })))
            .mount(server)
            .await;
    }

    fn test_cfg() -> MicrosoftSentinelConfig {
        MicrosoftSentinelConfig {
            tenant_id: "t".into(),
            client_id: "c".into(),
            auth_method: AuthMethod::Secret,
            credential: SecretString::from(String::new()),
            subscription_id: "sub".into(),
            resource_group: "rg".into(),
            workspace_name: "ws".into(),
            workspace_id: Uuid::nil(),
            enable_comment_write: false,
            arm_base_override: None,
        }
    }

    #[test]
    fn workspace_path_format() {
        let cfg = test_cfg();
        assert_eq!(
            cfg.workspace_path(),
            "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/providers/Microsoft.SecurityInsights"
        );
    }

    #[test]
    fn arm_base_default_and_override() {
        let mut cfg = test_cfg();
        assert_eq!(cfg.arm_base(), "https://management.azure.com");
        cfg.arm_base_override = Some("http://localhost:9999".into());
        assert_eq!(cfg.arm_base(), "http://localhost:9999");
    }

    #[test]
    fn map_status_new_to_open() {
        assert_eq!(map_sentinel_status("New", None), ThreatclawStatus::Open);
    }

    #[test]
    fn map_status_active_to_investigating() {
        assert_eq!(
            map_sentinel_status("Active", None),
            ThreatclawStatus::Investigating
        );
    }

    #[test]
    fn map_status_closed_true_positive_to_resolved() {
        assert_eq!(
            map_sentinel_status("Closed", Some("TruePositive")),
            ThreatclawStatus::Resolved
        );
    }

    #[test]
    fn map_status_closed_false_positive_to_false_positive() {
        assert_eq!(
            map_sentinel_status("Closed", Some("FalsePositive")),
            ThreatclawStatus::FalsePositive
        );
    }

    #[test]
    fn map_status_closed_benign_positive_to_resolved() {
        assert_eq!(
            map_sentinel_status("Closed", Some("BenignPositive")),
            ThreatclawStatus::Resolved
        );
    }

    #[test]
    fn map_status_closed_undetermined_to_resolved() {
        assert_eq!(
            map_sentinel_status("Closed", Some("Undetermined")),
            ThreatclawStatus::Resolved
        );
    }

    #[test]
    fn map_status_unknown_defaults_to_open() {
        assert_eq!(
            map_sentinel_status("WeirdValue", None),
            ThreatclawStatus::Open
        );
        assert_eq!(
            map_sentinel_status("", Some("Anything")),
            ThreatclawStatus::Open
        );
    }

    const INCIDENTS_LIST_FIXTURE: &str =
        include_str!("../../tests/fixtures/sentinel/incidents_list.json");

    #[test]
    fn parse_incidents_list_extracts_required_fields() {
        let parsed = parse_incidents_response(INCIDENTS_LIST_FIXTURE).expect("parse ok");
        assert!(
            !parsed.is_empty(),
            "fixture must have at least one incident"
        );
        let first = &parsed[0];
        assert!(!first.sentinel_incident_id.is_nil());
        assert!(!first.title.is_empty());
        assert!(first.last_modified_utc.timestamp() > 0);
        assert!(!first.provider_name.is_empty());
    }

    #[test]
    fn parse_incidents_list_handles_empty_value_array() {
        let json = r#"{"value": []}"#;
        let parsed = parse_incidents_response(json).expect("empty list ok");
        assert!(parsed.is_empty());
    }

    #[test]
    fn parse_incidents_list_extracts_related_rule_ids_uuid_only() {
        let parsed = parse_incidents_response(INCIDENTS_LIST_FIXTURE).expect("parse ok");
        for inc in &parsed {
            for r in &inc.related_analytic_rule_ids {
                // Each must be exactly 36 chars (a UUID), not a full ARM resource path.
                assert_eq!(r.len(), 36, "rule id must be a UUID, got '{}'", r);
            }
        }
    }

    #[test]
    fn parse_incidents_list_extracts_mitre_tactics_and_techniques() {
        let parsed = parse_incidents_response(INCIDENTS_LIST_FIXTURE).expect("parse ok");
        // At least one incident in the lab has tactics + techniques in additionalData
        let with_mitre = parsed
            .iter()
            .find(|i| !i.tactics.is_empty() || !i.techniques.is_empty());
        assert!(
            with_mitre.is_some(),
            "fixture should have at least one incident with MITRE annotations"
        );
    }

    const ALERTS_FIXTURE: &str =
        include_str!("../../tests/fixtures/sentinel/alerts_for_incident.json");
    const ENTITIES_FIXTURE: &str =
        include_str!("../../tests/fixtures/sentinel/entities_for_incident.json");

    #[test]
    fn parse_alerts_extracts_provider_alert_id() {
        let parsed = parse_alerts_response(ALERTS_FIXTURE).expect("parse ok");
        assert!(!parsed.is_empty());
        let a = &parsed[0];
        assert!(
            !a.provider_alert_id.is_empty(),
            "providerAlertId is the dedup key, must be present"
        );
        assert!(!a.system_alert_id.is_nil());
    }

    #[test]
    fn parse_alerts_extracts_mitre_techniques_from_additional_data() {
        let parsed = parse_alerts_response(ALERTS_FIXTURE).expect("parse ok");
        // At least one alert should have techniques (extracted from additionalData.MitreTechniques JSON string)
        let any_with_techniques = parsed.iter().any(|a| !a.techniques.is_empty());
        assert!(
            any_with_techniques,
            "expected at least one alert with MITRE techniques"
        );
    }

    #[test]
    fn parse_entities_extracts_account_and_host() {
        let parsed = parse_entities_response(ENTITIES_FIXTURE).expect("parse ok");
        let kinds: Vec<&str> = parsed.iter().map(|e| e.kind.as_str()).collect();
        assert!(
            kinds.contains(&"Account"),
            "expected Account entity in fixture, got {:?}",
            kinds
        );
        assert!(
            kinds.contains(&"Host"),
            "expected Host entity in fixture, got {:?}",
            kinds
        );
    }

    #[test]
    fn parse_entities_handles_missing_entities_array() {
        let json = r#"{}"#;
        let parsed = parse_entities_response(json).expect("missing entities ok");
        assert!(parsed.is_empty());
    }

    #[tokio::test]
    async fn poll_incidents_delta_attaches_filter_and_parses_fixture() {
        let server = MockServer::start().await;
        mock_token_endpoint(&server).await;

        Mock::given(method("GET"))
            .and(path_regex(r"^/subscriptions/.+/incidents"))
            .and(header("authorization", "Bearer MOCK"))
            .and(query_param(
                "$filter",
                "properties/lastModifiedTimeUtc gt 2026-06-01T00:00:00Z",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string(INCIDENTS_LIST_FIXTURE))
            .mount(&server)
            .await;

        let auth = MicrosoftAuthCache::new();
        let http = crate::connectors::microsoft_auth::build_http_client();
        let mut cfg = test_cfg();
        cfg.arm_base_override = Some(server.uri());

        let cursor = Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());
        let parsed = poll_incidents_delta(&cfg, &auth, &http, cursor)
            .await
            .expect("ok");
        assert!(
            !parsed.is_empty(),
            "fixture should yield at least one incident"
        );
    }

    #[tokio::test]
    async fn poll_incidents_delta_omits_filter_when_no_cursor() {
        let server = MockServer::start().await;
        mock_token_endpoint(&server).await;

        // No $filter param expected (cold start). query_param_is_missing
        // enforces the absence; without it wiremock would happily match a
        // request that incorrectly attached $filter.
        Mock::given(method("GET"))
            .and(path_regex(r"^/subscriptions/.+/incidents"))
            .and(query_param_is_missing("$filter"))
            .respond_with(ResponseTemplate::new(200).set_body_string(INCIDENTS_LIST_FIXTURE))
            .mount(&server)
            .await;

        let auth = MicrosoftAuthCache::new();
        let http = crate::connectors::microsoft_auth::build_http_client();
        let mut cfg = test_cfg();
        cfg.arm_base_override = Some(server.uri());

        let parsed = poll_incidents_delta(&cfg, &auth, &http, None)
            .await
            .expect("ok");
        assert!(!parsed.is_empty());
    }

    #[tokio::test]
    async fn fetch_alerts_for_incident_returns_parsed_alerts() {
        let server = MockServer::start().await;
        mock_token_endpoint(&server).await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/subscriptions/.+/incidents/.+/alerts"))
            .and(header("authorization", "Bearer MOCK"))
            .respond_with(ResponseTemplate::new(200).set_body_string(ALERTS_FIXTURE))
            .mount(&server)
            .await;

        let auth = MicrosoftAuthCache::new();
        let http = crate::connectors::microsoft_auth::build_http_client();
        let mut cfg = test_cfg();
        cfg.arm_base_override = Some(server.uri());

        let incident_id = Uuid::new_v4();
        let alerts = fetch_alerts_for_incident(&cfg, &auth, &http, incident_id)
            .await
            .expect("ok");
        assert!(!alerts.is_empty());
        assert!(!alerts[0].provider_alert_id.is_empty());
    }

    const RULES_LIST_FIXTURE: &str =
        include_str!("../../tests/fixtures/sentinel/analytic_rules_list.json");

    #[test]
    fn parse_analytic_rules_list_extracts_native_rules() {
        let parsed = parse_analytic_rules_list(RULES_LIST_FIXTURE).expect("ok");
        assert!(!parsed.is_empty());
        // The fixture has at least one Fusion or Scheduled rule
        let has_known_kind = parsed.iter().any(|r| {
            matches!(
                r.kind.as_deref(),
                Some("Fusion") | Some("Scheduled") | Some("NRT")
            )
        });
        assert!(
            has_known_kind,
            "fixture should contain at least one Fusion/Scheduled/NRT rule"
        );
    }

    #[test]
    fn parse_analytic_rules_list_skips_non_uuid_names() {
        // Some Microsoft rules (e.g., BuiltInFusion) have non-UUID names that would
        // break our cache PK (UUID). The parser must silently skip them.
        let json = r#"{"value":[
            {"name":"BuiltInFusion","kind":"Fusion","properties":{"displayName":"Fusion","severity":"High","tactics":[],"techniques":[]}},
            {"name":"550e8400-e29b-41d4-a716-446655440000","kind":"Scheduled","properties":{"displayName":"S","severity":"Medium","tactics":[],"techniques":[]}}
        ]}"#;
        let parsed = parse_analytic_rules_list(json).expect("ok");
        assert_eq!(parsed.len(), 1, "non-UUID name should be filtered");
        assert_eq!(parsed[0].display_name.as_deref(), Some("S"));
    }

    #[test]
    fn rule_fetch_skipped_for_xdr_provider() {
        assert!(!should_fetch_analytic_rule("Microsoft XDR"));
        assert!(!should_fetch_analytic_rule("Microsoft Defender"));
        assert!(!should_fetch_analytic_rule("Microsoft Defender XDR"));
    }

    #[test]
    fn rule_fetch_attempted_for_sentinel_native() {
        assert!(should_fetch_analytic_rule("Azure Sentinel"));
        assert!(should_fetch_analytic_rule("Microsoft Sentinel"));
    }

    #[tokio::test]
    async fn fetch_entities_for_incident_returns_parsed_entities() {
        let server = MockServer::start().await;
        mock_token_endpoint(&server).await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/subscriptions/.+/incidents/.+/entities"))
            .and(header("authorization", "Bearer MOCK"))
            .respond_with(ResponseTemplate::new(200).set_body_string(ENTITIES_FIXTURE))
            .mount(&server)
            .await;

        let auth = MicrosoftAuthCache::new();
        let http = crate::connectors::microsoft_auth::build_http_client();
        let mut cfg = test_cfg();
        cfg.arm_base_override = Some(server.uri());

        let incident_id = Uuid::new_v4();
        let ents = fetch_entities_for_incident(&cfg, &auth, &http, incident_id)
            .await
            .expect("ok");
        let kinds: Vec<&str> = ents.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"Account"));
    }

    fn make_test_alert(provider_alert_id: &str, provider_name: &str) -> ParsedSentinelAlert {
        ParsedSentinelAlert {
            system_alert_id: Uuid::new_v4(),
            provider_alert_id: provider_alert_id.into(),
            provider_name: provider_name.into(),
            vendor_name: None,
            product_name: Some(provider_name.into()),
            alert_display_name: "Test".into(),
            description: None,
            severity: "Medium".into(),
            confidence_level: None,
            status: None,
            tactics: vec![],
            techniques: vec![],
            alert_link: None,
            start_time_utc: None,
            end_time_utc: None,
            time_generated: None,
            additional_data: None,
        }
    }

    #[test]
    fn dedup_xdr_alert_with_match_returns_skip() {
        let alert = make_test_alert("abc-123", "Microsoft XDR");
        let known: std::collections::HashSet<String> = ["abc-123".into()].into_iter().collect();
        assert_eq!(
            decide_dedup(&alert, &known),
            DedupDecision::SkipMergeWithGraph
        );
    }

    #[test]
    fn dedup_xdr_alert_no_match_returns_insert() {
        let alert = make_test_alert("abc-999", "Microsoft XDR");
        let known = std::collections::HashSet::new();
        assert_eq!(decide_dedup(&alert, &known), DedupDecision::Insert);
    }

    #[test]
    fn dedup_sentinel_native_always_insert() {
        let alert = make_test_alert("would-match-if-checked", "Azure Sentinel");
        let known: std::collections::HashSet<String> =
            ["would-match-if-checked".into()].into_iter().collect();
        assert_eq!(decide_dedup(&alert, &known), DedupDecision::Insert);
    }

    #[test]
    fn dedup_microsoft_defender_xdr_treated_as_defender_origin() {
        let alert = make_test_alert("def-1", "Microsoft Defender XDR");
        let known: std::collections::HashSet<String> = ["def-1".into()].into_iter().collect();
        assert_eq!(
            decide_dedup(&alert, &known),
            DedupDecision::SkipMergeWithGraph
        );
    }

    #[test]
    fn dedup_unknown_vendor_inserts_without_check() {
        let alert = make_test_alert("xyz", "Palo Alto");
        let known: std::collections::HashSet<String> = ["xyz".into()].into_iter().collect();
        // Non-Microsoft vendors are NOT in the Graph Defender ingestion path,
        // so we don't bother checking and always Insert.
        assert_eq!(decide_dedup(&alert, &known), DedupDecision::Insert);
    }
}
