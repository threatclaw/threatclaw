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
}
