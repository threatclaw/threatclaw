//! LibSQL stub implementation of ThreatClawStore.
//! ThreatClaw features require PostgreSQL; these methods return errors on libSQL.

use async_trait::async_trait;

use super::libsql::LibSqlBackend;
use super::threatclaw_store::*;
use crate::error::DatabaseError;

fn not_supported() -> DatabaseError {
    DatabaseError::Query("ThreatClaw features require PostgreSQL backend".to_string())
}

#[async_trait]
impl ThreatClawStore for LibSqlBackend {
    async fn insert_finding(&self, _: &NewFinding) -> Result<i64, DatabaseError> { Err(not_supported()) }
    async fn list_findings(&self, _: Option<&str>, _: Option<&str>, _: Option<&str>, _: i64, _: i64) -> Result<Vec<FindingRecord>, DatabaseError> { Err(not_supported()) }
    async fn count_findings_filtered(&self, _: Option<&str>, _: Option<&str>, _: Option<&str>) -> Result<i64, DatabaseError> { Err(not_supported()) }
    async fn get_finding(&self, _: i64) -> Result<Option<FindingRecord>, DatabaseError> { Err(not_supported()) }
    async fn update_finding_status(&self, _: i64, _: &str, _: Option<&str>) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn count_findings_by_severity(&self) -> Result<Vec<(String, i64)>, DatabaseError> { Err(not_supported()) }
    async fn auto_close_stale_findings(&self, _: &str, _: &str) -> Result<i64, DatabaseError> { Err(not_supported()) }
    async fn list_alerts(&self, _: Option<&str>, _: Option<&str>, _: i64, _: i64) -> Result<Vec<AlertRecord>, DatabaseError> { Err(not_supported()) }
    async fn count_alerts_filtered(&self, _: Option<&str>, _: Option<&str>) -> Result<i64, DatabaseError> { Err(not_supported()) }
    async fn get_alert(&self, _: i64) -> Result<Option<AlertRecord>, DatabaseError> { Err(not_supported()) }
    async fn update_alert_status(&self, _: i64, _: &str, _: Option<&str>) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn count_alerts_by_level(&self) -> Result<Vec<(String, i64)>, DatabaseError> { Err(not_supported()) }
    async fn get_skill_config(&self, _: &str) -> Result<Vec<SkillConfigRecord>, DatabaseError> { Err(not_supported()) }
    async fn set_skill_config(&self, _: &str, _: &str, _: &str) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn delete_skill_config(&self, _: &str, _: &str) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn record_metric(&self, _: &str, _: f64, _: &serde_json::Value) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn get_dashboard_metrics(&self) -> Result<DashboardMetrics, DatabaseError> { Err(not_supported()) }
    async fn list_anonymizer_rules(&self) -> Result<Vec<serde_json::Value>, DatabaseError> { Err(not_supported()) }
    async fn create_anonymizer_rule(&self, _: &str, _: &str, _: &str, _: i32) -> Result<String, DatabaseError> { Err(not_supported()) }
    async fn delete_anonymizer_rule(&self, _: &str) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn query_logs(&self, _: i64, _: Option<&str>, _: Option<&str>, _: i64) -> Result<Vec<LogRecord>, DatabaseError> { Err(not_supported()) }
    async fn count_logs(&self, _: i64) -> Result<i64, DatabaseError> { Err(not_supported()) }
    async fn insert_log(&self, _: &str, _: &str, _: &serde_json::Value, _: &str) -> Result<i64, DatabaseError> { Err(not_supported()) }
    async fn insert_sigma_alert(&self, _: &str, _: &str, _: &str, _: &str, _: Option<&str>, _: Option<&str>) -> Result<i64, DatabaseError> { Err(not_supported()) }
    async fn list_sigma_rules_enabled(&self) -> Result<Vec<serde_json::Value>, DatabaseError> { Err(not_supported()) }
    async fn execute_cypher(&self, _: &str) -> Result<Vec<serde_json::Value>, DatabaseError> { Err(not_supported()) }
    async fn log_llm_call(&self, _: &str, _: &str, _: i32, _: Option<&serde_json::Value>, _: Option<&str>, _: bool, _: &str, _: Option<&str>, _: Option<f64>, _: i32, _: &str, _: i32, _: i32) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn list_assets(&self, _: Option<&str>, _: Option<&str>, _: i64, _: i64) -> Result<Vec<AssetRecord>, DatabaseError> { Err(not_supported()) }
    async fn count_assets_filtered(&self, _: Option<&str>, _: Option<&str>) -> Result<i64, DatabaseError> { Err(not_supported()) }
    async fn get_asset(&self, _: &str) -> Result<Option<AssetRecord>, DatabaseError> { Err(not_supported()) }
    async fn upsert_asset(&self, _: &NewAsset) -> Result<String, DatabaseError> { Err(not_supported()) }
    async fn delete_asset(&self, _: &str) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn count_assets_by_category(&self) -> Result<Vec<(String, i64)>, DatabaseError> { Err(not_supported()) }
    async fn find_asset_by_ip(&self, _: &str) -> Result<Option<AssetRecord>, DatabaseError> { Err(not_supported()) }
    async fn find_asset_by_mac(&self, _: &str) -> Result<Option<AssetRecord>, DatabaseError> { Err(not_supported()) }
    async fn list_internal_networks(&self) -> Result<Vec<InternalNetwork>, DatabaseError> { Err(not_supported()) }
    async fn add_internal_network(&self, _: &str, _: Option<&str>, _: Option<&str>) -> Result<i64, DatabaseError> { Err(not_supported()) }
    async fn delete_internal_network(&self, _: i64) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn get_company_profile(&self) -> Result<CompanyProfile, DatabaseError> { Err(not_supported()) }
    async fn update_company_profile(&self, _: &CompanyProfile) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn list_asset_categories(&self) -> Result<Vec<AssetCategory>, DatabaseError> { Err(not_supported()) }
    async fn upsert_asset_category(&self, _: &AssetCategory) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn get_enrichment_cache(&self, _: &str, _: &str) -> Result<Option<serde_json::Value>, DatabaseError> { Err(not_supported()) }
    async fn set_enrichment_cache(&self, _: &str, _: &str, _: &serde_json::Value, _: i64) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn get_ml_score(&self, _: &str) -> Result<Option<(f64, String)>, DatabaseError> { Err(not_supported()) }
    async fn set_ml_score(&self, _: &str, _: f64, _: &str, _: &serde_json::Value) -> Result<(), DatabaseError> { Err(not_supported()) }
}
