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
    async fn insert_finding(&self, _: &NewFinding) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn list_findings(
        &self,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        _: i64,
        _: i64,
    ) -> Result<Vec<FindingRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn count_findings_filtered(
        &self,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn get_finding(&self, _: i64) -> Result<Option<FindingRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn update_finding_status(
        &self,
        _: i64,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn count_findings_by_severity(&self) -> Result<Vec<(String, i64)>, DatabaseError> {
        Err(not_supported())
    }
    async fn auto_close_stale_findings(&self, _: &str, _: &str) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn list_alerts(
        &self,
        _: Option<&str>,
        _: Option<&str>,
        _: i64,
        _: i64,
    ) -> Result<Vec<AlertRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn count_alerts_filtered(
        &self,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn get_alert(&self, _: i64) -> Result<Option<AlertRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn update_alert_status(
        &self,
        _: i64,
        _: &str,
        _: Option<&str>,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn count_alerts_by_level(&self) -> Result<Vec<(String, i64)>, DatabaseError> {
        Err(not_supported())
    }
    async fn get_skill_config(&self, _: &str) -> Result<Vec<SkillConfigRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn set_skill_config(&self, _: &str, _: &str, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn delete_skill_config(&self, _: &str, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn record_metric(
        &self,
        _: &str,
        _: f64,
        _: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn get_dashboard_metrics(&self) -> Result<DashboardMetrics, DatabaseError> {
        Err(not_supported())
    }
    async fn list_anonymizer_rules(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn create_anonymizer_rule(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: i32,
    ) -> Result<String, DatabaseError> {
        Err(not_supported())
    }
    async fn delete_anonymizer_rule(&self, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn query_logs(
        &self,
        _: i64,
        _: Option<&str>,
        _: Option<&str>,
        _: i64,
    ) -> Result<Vec<LogRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn count_logs(&self, _: i64) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn insert_log(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
        _: &str,
    ) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn insert_sigma_alert(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn list_sigma_rules_enabled(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn execute_cypher(&self, _: &str) -> Result<Vec<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn log_llm_call(
        &self,
        _: &str,
        _: &str,
        _: i32,
        _: Option<&serde_json::Value>,
        _: Option<&str>,
        _: bool,
        _: &str,
        _: Option<&str>,
        _: Option<f64>,
        _: i32,
        _: &str,
        _: i32,
        _: i32,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn list_assets(
        &self,
        _: Option<&str>,
        _: Option<&str>,
        _: i64,
        _: i64,
    ) -> Result<Vec<AssetRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn count_assets_filtered(
        &self,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn get_asset(&self, _: &str) -> Result<Option<AssetRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn upsert_asset(&self, _: &NewAsset) -> Result<String, DatabaseError> {
        Err(not_supported())
    }
    async fn delete_asset(&self, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn count_assets_by_category(&self) -> Result<Vec<(String, i64)>, DatabaseError> {
        Err(not_supported())
    }
    async fn find_asset_by_ip(&self, _: &str) -> Result<Option<AssetRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn find_asset_by_mac(&self, _: &str) -> Result<Option<AssetRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn find_asset_by_hostname(&self, _: &str) -> Result<Option<AssetRecord>, DatabaseError> {
        Err(not_supported())
    }
    async fn mark_asset_user_modified(&self, _: &str, _: &[&str]) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn update_asset_software(
        &self,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn set_asset_criticality(&self, _: &str, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn set_asset_dedup_confidence(&self, _: &str, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn merge_assets(&self, _: &str, _: &str, _: &str, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn unmerge_asset(&self, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn resolve_canonical_id(&self, id: &str) -> Result<String, DatabaseError> {
        // libsql backend has no merge_aliases table — every id is its own canonical.
        Ok(id.to_string())
    }
    async fn set_asset_excluded(
        &self,
        _: &str,
        _: bool,
        _: &str,
        _: Option<chrono::DateTime<chrono::Utc>>,
        _: &str,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn expire_asset_exclusions(&self) -> Result<u64, DatabaseError> {
        Ok(0)
    }
    async fn list_internal_networks(&self) -> Result<Vec<InternalNetwork>, DatabaseError> {
        Err(not_supported())
    }
    async fn add_internal_network(
        &self,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn delete_internal_network(&self, _: i64) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn get_company_profile(&self) -> Result<CompanyProfile, DatabaseError> {
        Err(not_supported())
    }
    async fn update_company_profile(&self, _: &CompanyProfile) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn list_asset_categories(&self) -> Result<Vec<AssetCategory>, DatabaseError> {
        Err(not_supported())
    }
    async fn upsert_asset_category(&self, _: &AssetCategory) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn get_enrichment_cache(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn set_enrichment_cache(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
        _: i64,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn get_ml_score(&self, _: &str) -> Result<Option<(f64, String)>, DatabaseError> {
        Err(not_supported())
    }
    async fn get_all_ml_scores(
        &self,
    ) -> Result<std::collections::HashMap<String, (f64, String)>, DatabaseError> {
        Err(not_supported())
    }
    async fn set_ml_score(
        &self,
        _: &str,
        _: f64,
        _: &str,
        _: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn create_incident(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &[i32],
        _: &[i32],
        _: i32,
    ) -> Result<i32, DatabaseError> {
        Err(not_supported())
    }
    async fn update_incident_verdict(
        &self,
        _: i32,
        _: &str,
        _: f64,
        _: &str,
        _: &[String],
        _: &serde_json::Value,
        _: &serde_json::Value,
        _: &serde_json::Value,
        _: Option<&str>,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn update_incident_hitl(
        &self,
        _: i32,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn attach_blast_radius_snapshot(
        &self,
        _: i32,
        _: u8,
        _: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn list_suppression_rules(
        &self,
        _: bool,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn get_suppression_rule(
        &self,
        _: uuid::Uuid,
    ) -> Result<Option<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn create_suppression_rule(
        &self,
        _: &str,
        _: &serde_json::Value,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: &str,
        _: &str,
        _: &str,
        _: Option<chrono::DateTime<chrono::Utc>>,
        _: &str,
    ) -> Result<uuid::Uuid, DatabaseError> {
        Err(not_supported())
    }
    async fn disable_suppression_rule(&self, _: uuid::Uuid) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn load_active_suppression_rules(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn bump_suppression_match(&self, _: uuid::Uuid) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn list_incidents_for_preview(
        &self,
        _: i32,
        _: i64,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn record_kev_observation(
        &self,
        _: &str,
        _: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<bool, DatabaseError> {
        Err(not_supported())
    }
    async fn record_kev_first_match(&self, _: &str, _: Option<i32>) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn kev_tta_metrics(&self) -> Result<serde_json::Value, DatabaseError> {
        Err(not_supported())
    }
    async fn monthly_rssi_summary(
        &self,
        _: chrono::NaiveDate,
    ) -> Result<Option<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn top_incidents_by_blast(
        &self,
        _: chrono::NaiveDate,
        _: i32,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn refresh_monthly_rssi_summary(&self) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn update_incident_status(&self, _: i32, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn update_incident_title(&self, _: i32, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn list_incidents(
        &self,
        _: Option<&str>,
        _: i64,
        _: i64,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn get_incident(&self, _: i32) -> Result<Option<serde_json::Value>, DatabaseError> {
        Err(not_supported())
    }
    async fn find_open_incident_for_asset(&self, _: &str) -> Result<Option<i32>, DatabaseError> {
        Err(not_supported())
    }
    async fn touch_incident(&self, _: i32, _: i32, _: Option<&str>) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn phase_g_acceptance_stats(
        &self,
        _: i32,
    ) -> Result<(i64, i64, Vec<i32>), DatabaseError> {
        Err(not_supported())
    }

    async fn billable_breakdown(
        &self,
        _: &[String],
    ) -> Result<crate::agent::billing::BillableCount, DatabaseError> {
        Err(not_supported())
    }

    async fn reclassify_inactive_assets(&self, _: i32) -> Result<u64, DatabaseError> {
        Err(not_supported())
    }

    async fn cleanup_old_sigma_alerts(&self, _: i32) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn count_mitre_techniques(&self) -> Result<i64, DatabaseError> {
        Ok(0)
    }
    async fn archive_resolved_incidents(&self) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn archive_resolved_alerts(&self) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn purge_old_archived(&self, _: i32) -> Result<(i64, i64), DatabaseError> {
        Err(not_supported())
    }
    async fn add_incident_note(&self, _: i32, _: &str, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }

    // ── Phase G1b — task_queue (libsql non supporté, postgres only) ──

    async fn enqueue_task(
        &self,
        _: &crate::agent::task_queue::NewTask,
    ) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn claim_next_task(
        &self,
        _: crate::agent::task_queue::TaskKind,
        _: &str,
    ) -> Result<Option<crate::agent::task_queue::Task>, DatabaseError> {
        Err(not_supported())
    }
    async fn complete_task(&self, _: i64, _: &serde_json::Value) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn fail_task(&self, _: i64, _: &str) -> Result<(), DatabaseError> {
        Err(not_supported())
    }
    async fn recover_stale_tasks(&self, _: i64) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn count_tasks_by_status(
        &self,
    ) -> Result<crate::agent::task_queue::QueueDepths, DatabaseError> {
        Err(not_supported())
    }
    async fn create_graph_execution(
        &self,
        _: &crate::agent::task_queue::NewGraphExecution,
    ) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn finalize_graph_execution(
        &self,
        _: i64,
        _: crate::agent::task_queue::GraphExecutionStatus,
        _: Option<&str>,
        _: Option<i32>,
        _: &serde_json::Value,
        _: Option<&str>,
    ) -> Result<(), DatabaseError> {
        Err(not_supported())
    }

    // ── Phase G2 — attack_paths (postgres only) ──

    async fn insert_attack_paths(
        &self,
        _: &[crate::agent::path_risk::AttackPath],
    ) -> Result<i64, DatabaseError> {
        Err(not_supported())
    }
    async fn latest_attack_paths(
        &self,
        _: i64,
    ) -> Result<Vec<crate::agent::path_risk::AttackPath>, DatabaseError> {
        Err(not_supported())
    }
    async fn latest_choke_points(
        &self,
        _: i64,
    ) -> Result<Vec<crate::db::threatclaw_store::ChokePoint>, DatabaseError> {
        Err(not_supported())
    }
    async fn list_graph_executions(
        &self,
        _: &crate::db::threatclaw_store::GraphExecutionsFilter,
    ) -> Result<Vec<crate::agent::task_queue::GraphExecutionRecord>, DatabaseError> {
        Err(not_supported())
    }
}
