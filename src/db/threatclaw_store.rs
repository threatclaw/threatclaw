//! ThreatClaw-specific database operations for findings, alerts, skill configs, and metrics.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::DatabaseError;

// ── Record types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub id: i64,
    pub skill_id: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub status: String,
    pub category: Option<String>,
    pub asset: Option<String>,
    pub source: Option<String>,
    pub metadata: serde_json::Value,
    pub detected_at: String,
    pub resolved_at: Option<String>,
    pub resolved_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewFinding {
    pub skill_id: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub category: Option<String>,
    pub asset: Option<String>,
    pub source: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: i64,
    pub rule_id: String,
    pub level: String,
    pub title: String,
    pub status: String,
    pub hostname: Option<String>,
    pub source_ip: Option<String>,
    pub username: Option<String>,
    pub matched_at: String,
    pub matched_fields: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillConfigRecord {
    pub skill_id: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricRecord {
    pub metric_name: String,
    pub metric_value: f64,
    pub labels: serde_json::Value,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMetrics {
    pub security_score: f64,
    pub findings_critical: i64,
    pub findings_high: i64,
    pub findings_medium: i64,
    pub findings_low: i64,
    pub alerts_total: i64,
    pub alerts_new: i64,
    pub cloud_score: f64,
    pub darkweb_leaks: i64,
}

// ── Store trait ──

#[async_trait]
pub trait ThreatClawStore: Send + Sync {
    // Findings
    async fn insert_finding(&self, finding: &NewFinding) -> Result<i64, DatabaseError>;
    async fn list_findings(
        &self,
        severity: Option<&str>,
        status: Option<&str>,
        skill_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<FindingRecord>, DatabaseError>;
    async fn get_finding(&self, id: i64) -> Result<Option<FindingRecord>, DatabaseError>;
    async fn update_finding_status(
        &self,
        id: i64,
        status: &str,
        resolved_by: Option<&str>,
    ) -> Result<(), DatabaseError>;
    async fn count_findings_by_severity(&self) -> Result<Vec<(String, i64)>, DatabaseError>;

    // Alerts (sigma_alerts)
    async fn list_alerts(
        &self,
        level: Option<&str>,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<AlertRecord>, DatabaseError>;
    async fn get_alert(&self, id: i64) -> Result<Option<AlertRecord>, DatabaseError>;
    async fn update_alert_status(
        &self,
        id: i64,
        status: &str,
        notes: Option<&str>,
    ) -> Result<(), DatabaseError>;
    async fn count_alerts_by_level(&self) -> Result<Vec<(String, i64)>, DatabaseError>;

    // Skill configs
    async fn get_skill_config(&self, skill_id: &str) -> Result<Vec<SkillConfigRecord>, DatabaseError>;
    async fn set_skill_config(
        &self,
        skill_id: &str,
        key: &str,
        value: &str,
    ) -> Result<(), DatabaseError>;
    async fn delete_skill_config(&self, skill_id: &str, key: &str) -> Result<(), DatabaseError>;

    // Metrics
    async fn record_metric(
        &self,
        name: &str,
        value: f64,
        labels: &serde_json::Value,
    ) -> Result<(), DatabaseError>;
    async fn get_dashboard_metrics(&self) -> Result<DashboardMetrics, DatabaseError>;

    // Anonymizer custom rules
    async fn list_anonymizer_rules(&self) -> Result<Vec<serde_json::Value>, DatabaseError>;
    async fn create_anonymizer_rule(
        &self,
        label: &str,
        pattern: &str,
        token_prefix: &str,
        capture_group: i32,
    ) -> Result<String, DatabaseError>;
    async fn delete_anonymizer_rule(&self, id: &str) -> Result<(), DatabaseError>;
}
