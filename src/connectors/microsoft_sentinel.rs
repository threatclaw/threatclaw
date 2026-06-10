//! Microsoft Sentinel ingestion. Pulls incidents, alerts, entities, and
//! analytic-rule context into the ThreatClaw incident pipeline.
//!
//! Auth: shared with microsoft_graph via crate::connectors::microsoft_auth,
//! scope `https://management.azure.com/.default`.
//!
//! API version: 2024-09-01 across all Microsoft.SecurityInsights endpoints.

use chrono::{DateTime, Utc};
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
    /// Overridable for tests: when Some, points the connector at a wiremock
    /// URL instead of management.azure.com. Production builds always leave None.
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
    #[error("parse: {0}")]
    Parse(String),
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
}
