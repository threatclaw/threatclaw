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

/// A raw log record from the logs table (ingested by Fluent Bit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub id: i64,
    pub tag: Option<String>,
    pub time: String,
    pub hostname: Option<String>,
    pub data: serde_json::Value,
}

// ── Asset types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetRecord {
    pub id: String,
    pub name: String,
    pub category: String,
    pub subcategory: Option<String>,
    pub role: Option<String>,
    pub criticality: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub fqdn: Option<String>,
    pub url: Option<String>,
    pub os: Option<String>,
    pub os_confidence: f32,
    pub mac_vendor: Option<String>,
    pub services: serde_json::Value,
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub owner: Option<String>,
    pub location: Option<String>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub classification_method: String,
    pub classification_confidence: f32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAsset {
    pub id: String,
    pub name: String,
    pub category: String,
    pub subcategory: Option<String>,
    pub role: Option<String>,
    pub criticality: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub fqdn: Option<String>,
    pub url: Option<String>,
    pub os: Option<String>,
    pub mac_vendor: Option<String>,
    pub services: serde_json::Value,  // JSON array of {port, proto, service, product, version}
    pub source: String,
    pub owner: Option<String>,
    pub location: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalNetwork {
    pub id: i64,
    pub cidr: String,
    pub label: Option<String>,
    pub zone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyProfile {
    pub company_name: Option<String>,
    pub nace_code: Option<String>,
    pub sector: String,
    pub company_size: String,
    pub employee_count: Option<i32>,
    pub country: String,
    pub business_hours: String,
    pub business_hours_start: String,
    pub business_hours_end: String,
    pub work_days: Vec<String>,
    pub geo_scope: String,
    pub allowed_countries: Vec<String>,
    pub blocked_countries: Vec<String>,
    pub critical_systems: Vec<String>,
    pub compliance_frameworks: Vec<String>,
    pub anomaly_sensitivity: String,
}

impl Default for CompanyProfile {
    fn default() -> Self {
        Self {
            company_name: None, nace_code: None,
            sector: "other".into(), company_size: "small".into(),
            employee_count: None, country: "FR".into(),
            business_hours: "office".into(),
            business_hours_start: "08:00".into(), business_hours_end: "18:00".into(),
            work_days: vec!["mon".into(), "tue".into(), "wed".into(), "thu".into(), "fri".into()],
            geo_scope: "france".into(),
            allowed_countries: vec!["FR".into()],
            blocked_countries: vec![],
            critical_systems: vec![],
            compliance_frameworks: vec![],
            anomaly_sensitivity: "medium".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetCategory {
    pub id: String,
    pub label: String,
    pub label_en: Option<String>,
    pub icon: String,
    pub color: String,
    pub subcategories: Vec<String>,
    pub is_builtin: bool,
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
        offset: i64,
    ) -> Result<Vec<FindingRecord>, DatabaseError>;

    async fn count_findings_filtered(
        &self,
        severity: Option<&str>,
        status: Option<&str>,
        skill_id: Option<&str>,
    ) -> Result<i64, DatabaseError>;
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
        offset: i64,
    ) -> Result<Vec<AlertRecord>, DatabaseError>;

    async fn count_alerts_filtered(
        &self,
        level: Option<&str>,
        status: Option<&str>,
    ) -> Result<i64, DatabaseError>;
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

    // Logs (raw log records from Fluent Bit ingestion)
    async fn query_logs(
        &self,
        minutes_back: i64,
        hostname: Option<&str>,
        tag: Option<&str>,
        limit: i64,
    ) -> Result<Vec<LogRecord>, DatabaseError>;

    async fn count_logs(&self, minutes_back: i64) -> Result<i64, DatabaseError>;

    /// Insert a log record directly (for testing/simulation).
    async fn insert_log(
        &self,
        tag: &str,
        hostname: &str,
        data: &serde_json::Value,
        time: &str,
    ) -> Result<i64, DatabaseError>;

    /// Insert a sigma alert directly (for testing/simulation).
    async fn insert_sigma_alert(
        &self,
        rule_id: &str,
        level: &str,
        title: &str,
        hostname: &str,
        source_ip: Option<&str>,
        username: Option<&str>,
    ) -> Result<i64, DatabaseError>;

    // Graph operations (Apache AGE Cypher queries)
    async fn execute_cypher(&self, cypher: &str) -> Result<Vec<serde_json::Value>, DatabaseError>;

    // LLM training data collection
    async fn log_llm_call(
        &self,
        model: &str,
        prompt_hash: &str,
        prompt_length: i32,
        response_json: Option<&serde_json::Value>,
        raw_response: Option<&str>,
        parsing_ok: bool,
        parsing_method: &str,
        severity: Option<&str>,
        confidence: Option<f64>,
        actions_count: i32,
        escalation: &str,
        cycle_duration_ms: i32,
        observations_count: i32,
    ) -> Result<(), DatabaseError>;

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

    // ── Assets Management ──

    async fn list_assets(
        &self,
        category: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AssetRecord>, DatabaseError>;

    async fn count_assets_filtered(
        &self,
        category: Option<&str>,
        status: Option<&str>,
    ) -> Result<i64, DatabaseError>;

    async fn get_asset(&self, id: &str) -> Result<Option<AssetRecord>, DatabaseError>;

    async fn upsert_asset(&self, asset: &NewAsset) -> Result<String, DatabaseError>;

    async fn delete_asset(&self, id: &str) -> Result<(), DatabaseError>;

    async fn count_assets_by_category(&self) -> Result<Vec<(String, i64)>, DatabaseError>;

    async fn find_asset_by_ip(&self, ip: &str) -> Result<Option<AssetRecord>, DatabaseError>;

    async fn find_asset_by_mac(&self, mac: &str) -> Result<Option<AssetRecord>, DatabaseError>;

    // ── Internal Networks ──

    async fn list_internal_networks(&self) -> Result<Vec<InternalNetwork>, DatabaseError>;

    async fn add_internal_network(&self, cidr: &str, label: Option<&str>, zone: Option<&str>) -> Result<i64, DatabaseError>;

    async fn delete_internal_network(&self, id: i64) -> Result<(), DatabaseError>;

    // ── Company Profile ──

    async fn get_company_profile(&self) -> Result<CompanyProfile, DatabaseError>;

    async fn update_company_profile(&self, profile: &CompanyProfile) -> Result<(), DatabaseError>;

    // ── Asset Categories ──

    async fn list_asset_categories(&self) -> Result<Vec<AssetCategory>, DatabaseError>;

    async fn upsert_asset_category(&self, cat: &AssetCategory) -> Result<(), DatabaseError>;

    // ── Enrichment Cache ──

    async fn get_enrichment_cache(&self, source: &str, key: &str) -> Result<Option<serde_json::Value>, DatabaseError>;

    async fn set_enrichment_cache(&self, source: &str, key: &str, value: &serde_json::Value, ttl_hours: i64) -> Result<(), DatabaseError>;

    // ── ML Scores (dedicated table) ──

    async fn get_ml_score(&self, asset_id: &str) -> Result<Option<(f64, String)>, DatabaseError>;

    async fn set_ml_score(&self, asset_id: &str, score: f64, reason: &str, features: &serde_json::Value) -> Result<(), DatabaseError>;
}
