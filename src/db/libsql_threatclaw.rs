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
    async fn list_findings(&self, _: Option<&str>, _: Option<&str>, _: Option<&str>, _: i64) -> Result<Vec<FindingRecord>, DatabaseError> { Err(not_supported()) }
    async fn get_finding(&self, _: i64) -> Result<Option<FindingRecord>, DatabaseError> { Err(not_supported()) }
    async fn update_finding_status(&self, _: i64, _: &str, _: Option<&str>) -> Result<(), DatabaseError> { Err(not_supported()) }
    async fn count_findings_by_severity(&self) -> Result<Vec<(String, i64)>, DatabaseError> { Err(not_supported()) }
    async fn list_alerts(&self, _: Option<&str>, _: Option<&str>, _: i64) -> Result<Vec<AlertRecord>, DatabaseError> { Err(not_supported()) }
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
    async fn log_llm_call(&self, _: &str, _: &str, _: i32, _: Option<&serde_json::Value>, _: Option<&str>, _: bool, _: &str, _: Option<&str>, _: Option<f64>, _: i32, _: &str, _: i32, _: i32) -> Result<(), DatabaseError> { Err(not_supported()) }
}
