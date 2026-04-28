//! ThreatClaw-specific database operations for findings, alerts, skill configs, and metrics.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

/// Read-only view of an agent_audit_log row (V16 immutable log).
/// Used by exports/audit-trail and the governance dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntryRecord {
    pub id: String,
    pub timestamp: String,
    pub event_type: String,
    pub agent_mode: String,
    pub cmd_id: Option<String>,
    pub approved_by: Option<String>,
    pub success: Option<bool>,
    pub error_message: Option<String>,
    pub skill_id: Option<String>,
    pub row_hash: String,
    pub previous_hash: Option<String>,
}

/// Row of the `ai_systems` governance table (V41).
/// Unified inventory : IA declared by the CISO + IA detected in shadow
/// by `skill-shadow-ai-monitor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSystemRecord {
    pub id: i64,
    pub name: String,
    pub category: String, // llm-commercial | llm-self-hosted | agent | embedding | coding-assistant
    pub provider: Option<String>,
    pub endpoint: Option<String>,
    pub status: String,             // detected | declared | assessed | retired
    pub risk_level: Option<String>, // high | medium | low
    pub assessment_status: Option<String>, // pending | in_progress | completed
    pub declared_by: Option<String>,
    pub declared_at: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub remediation: Option<String>,
    pub metadata: serde_json::Value,
}

/// Input for upsert — on conflict (category, provider, endpoint) the last_seen
/// is refreshed and the status may be promoted (detected → declared).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAiSystem {
    pub name: String,
    pub category: String,
    pub provider: Option<String>,
    pub endpoint: Option<String>,
    pub status: String,
    pub risk_level: Option<String>,
    pub metadata: Option<serde_json::Value>,
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
    pub sources: Vec<String>,
    pub software: serde_json::Value,
    pub user_modified: Vec<String>,
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
    pub services: serde_json::Value, // JSON array of {port, proto, service, product, version}
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
            company_name: None,
            nace_code: None,
            sector: "other".into(),
            company_size: "small".into(),
            employee_count: None,
            country: "FR".into(),
            business_hours: "office".into(),
            business_hours_start: "08:00".into(),
            business_hours_end: "18:00".into(),
            work_days: vec![
                "mon".into(),
                "tue".into(),
                "wed".into(),
                "thu".into(),
                "fri".into(),
            ],
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

// ── Firewall events (V54__firewall_events.sql) ──

/// Per-source-IP aggregate of blocked events over a time window.
/// Used by the firewall detection cycle to surface port scans and
/// brute-force attempts without pulling individual rows into memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallBlockedAggregate {
    pub src_ip: String,
    pub blocked_count: i64,
    pub distinct_dst_ips: i64,
    pub distinct_dst_ports: i64,
    pub hits_ssh: i64,
    pub hits_rdp: i64,
    pub hits_smb: i64,
    pub sample_dst_ips: Vec<String>,
}

/// One pf log entry as ingested from pfSense / OPNsense.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallEventRecord {
    pub id: i64,
    pub timestamp: String,
    pub fw_source: String,
    pub interface: Option<String>,
    pub action: String,
    pub direction: Option<String>,
    pub proto: Option<String>,
    pub src_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i32>,
    pub rule_id: Option<String>,
    pub raw_meta: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct NewFirewallEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub fw_source: String,
    pub interface: Option<String>,
    pub action: String,
    pub direction: Option<String>,
    pub proto: Option<String>,
    pub src_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i32>,
    pub rule_id: Option<String>,
    pub raw_meta: serde_json::Value,
}

// ── Scan schedule records (V52__scan_schedules.sql) ──

/// One row from the `scan_schedules` table — a recurring scan plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSchedule {
    pub id: i64,
    pub scan_type: String,
    pub target: String,
    pub name: Option<String>,
    pub frequency: String, // hourly | daily | weekly | monthly
    pub minute: i32,
    pub hour: Option<i32>,
    pub day_of_week: Option<i32>,
    pub day_of_month: Option<i32>,
    pub enabled: bool,
    pub last_run_at: Option<String>,
    pub next_run_at: String,
    pub created_at: String,
    pub created_by: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NewScanSchedule {
    pub scan_type: String,
    pub target: String,
    pub name: Option<String>,
    pub frequency: String,
    pub minute: i32,
    pub hour: Option<i32>,
    pub day_of_week: Option<i32>,
    pub day_of_month: Option<i32>,
}

// ── Scan queue records ──

/// One row from the `scan_queue` table — represents a queued/running/done
/// scan job (see migrations/V51__scan_queue.sql).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: i64,
    pub target: String,
    pub scan_type: String,
    pub status: String, // queued | running | done | error | skipped
    pub asset_id: Option<String>,
    pub requested_by: String,
    pub requested_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub duration_ms: Option<i32>,
    pub result_json: Option<serde_json::Value>,
    pub error_msg: Option<String>,
    pub ttl_seconds: i32,
    pub worker_id: Option<String>,
}

/// Input for scan_queue::enqueue. Caller doesn't set status/timestamps —
/// those are managed by the queue.
#[derive(Debug, Clone)]
pub struct NewScanRequest {
    pub target: String,
    pub scan_type: String,
    pub asset_id: Option<String>,
    pub requested_by: String,
    pub ttl_seconds: Option<i32>,
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

    /// Count recent independent signals on a given asset across the major
    /// signal tables (sigma_alerts + findings + firewall_events block).
    /// Used by sigma_engine to decide whether a `medium` sigma match has
    /// enough corroboration to be promoted to a finding (and downstream
    /// to escalate as an incident). The default impl returns 0 so non-PG
    /// stores stay safe — only the Postgres impl is expected to wire it.
    async fn count_recent_signals_on_asset(
        &self,
        _asset: &str,
        _minutes: i64,
    ) -> Result<i64, DatabaseError> {
        Ok(0)
    }

    // ── Shift Report queries ──

    /// Count findings created since a given timestamp.
    async fn count_findings_since(
        &self,
        _since: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        Ok(0)
    }
    /// Count sigma alerts since a given timestamp.
    async fn count_alerts_since(
        &self,
        _since: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        Ok(0)
    }
    /// Count incidents since a given timestamp.
    async fn count_incidents_since(
        &self,
        _since: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        Ok(0)
    }
    /// List finding titles by severity since a timestamp.
    async fn list_finding_titles_since(
        &self,
        _since: chrono::DateTime<chrono::Utc>,
        _severity: &str,
        _limit: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        Ok(vec![])
    }
    /// List assets that had findings or alerts since a timestamp.
    async fn list_active_assets_since(
        &self,
        _since: chrono::DateTime<chrono::Utc>,
        _limit: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        Ok(vec![])
    }
    /// List assets with ML anomaly scores above a threshold.
    async fn list_ml_anomalies(
        &self,
        _threshold: f64,
        _limit: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        Ok(vec![])
    }

    /// List entries from the immutable agent_audit_log (V16).
    /// Used by the audit-trail export and the governance dashboard. Default
    /// implementation returns an empty list for backends that don't support
    /// the append-only plpgsql-triggered table (only PostgreSQL does).
    async fn list_audit_entries_between(
        &self,
        _since: Option<chrono::DateTime<chrono::Utc>>,
        _until: Option<chrono::DateTime<chrono::Utc>>,
        _limit: i64,
    ) -> Result<Vec<AuditEntryRecord>, DatabaseError> {
        Ok(vec![])
    }

    // ── AI Systems (governance inventory, V41) ──

    /// List all AI systems (declared + detected). Filter by status if provided.
    async fn list_ai_systems(
        &self,
        _status: Option<&str>,
        _limit: i64,
    ) -> Result<Vec<AiSystemRecord>, DatabaseError> {
        Ok(vec![])
    }

    /// Insert or update an AI system (unique by category + provider + endpoint).
    /// On conflict, refreshes last_seen and metadata, preserves existing status
    /// unless the incoming one is more advanced (detected → declared → assessed).
    async fn upsert_ai_system(&self, _system: &NewAiSystem) -> Result<i64, DatabaseError> {
        Ok(0)
    }

    /// Promote status + optional risk_level + declared_by (CISO action).
    async fn update_ai_system_status(
        &self,
        _id: i64,
        _status: &str,
        _risk_level: Option<&str>,
        _declared_by: Option<&str>,
    ) -> Result<(), DatabaseError> {
        Ok(())
    }

    /// Count of AI systems grouped by status (for Governance card).
    async fn count_ai_systems_by_status(&self) -> Result<Vec<(String, i64)>, DatabaseError> {
        Ok(vec![])
    }

    /// Auto-close findings from a skill that were NOT re-confirmed since `since`.
    /// Called after a re-scan: findings not found again are considered resolved.
    async fn auto_close_stale_findings(
        &self,
        skill_id: &str,
        since: &str, // ISO timestamp — findings with detected_at < since are stale
    ) -> Result<i64, DatabaseError>;

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

    // Demo data management
    async fn count_demo_findings(&self) -> Result<i64, DatabaseError> {
        Ok(0)
    }
    async fn count_demo_alerts(&self) -> Result<i64, DatabaseError> {
        Ok(0)
    }
    async fn delete_demo_findings(&self) -> Result<i64, DatabaseError> {
        Ok(0)
    }
    async fn delete_demo_alerts(&self) -> Result<i64, DatabaseError> {
        Ok(0)
    }
    async fn delete_demo_logs(&self) -> Result<i64, DatabaseError> {
        Ok(0)
    }
    async fn delete_demo_data_older_than(&self, _ttl_minutes: i64) -> Result<i64, DatabaseError> {
        Ok(0)
    }

    // ── Scan queue (V51__scan_queue.sql) ──
    // Default impls are no-ops so the libsql backend doesn't have to
    // implement them — scans run on the postgres-backed prod stack.

    /// Enqueue a scan job. Returns the row id, or `None` if a recent
    /// `done` row exists for the same (target, scan_type) within
    /// `ttl_seconds` (dedup).
    async fn enqueue_scan(&self, _req: &NewScanRequest) -> Result<Option<i64>, DatabaseError> {
        Ok(None)
    }

    /// Worker pool: claim the next queued job. Uses
    /// `SELECT FOR UPDATE SKIP LOCKED` so multiple workers can run in
    /// parallel without trampling each other.
    async fn claim_next_scan(&self, _worker_id: &str) -> Result<Option<ScanJob>, DatabaseError> {
        Ok(None)
    }

    /// Mark a job done with its structured result.
    async fn complete_scan(
        &self,
        _id: i64,
        _result: &serde_json::Value,
        _duration_ms: i32,
    ) -> Result<(), DatabaseError> {
        Ok(())
    }

    /// Mark a job failed. `duration_ms` is best-effort (may be 0 if the
    /// failure happened before any work).
    async fn fail_scan(
        &self,
        _id: i64,
        _error_msg: &str,
        _duration_ms: i32,
    ) -> Result<(), DatabaseError> {
        Ok(())
    }

    /// Recent scans for an asset (newest first, capped at `limit`).
    async fn recent_scans_for_asset(
        &self,
        _asset_id: &str,
        _limit: i64,
    ) -> Result<Vec<ScanJob>, DatabaseError> {
        Ok(vec![])
    }

    /// True if at least one queued or running scan exists for the asset.
    /// Used by the incident card "scan en cours" badge.
    async fn has_running_scan_for_asset(&self, _asset_id: &str) -> Result<bool, DatabaseError> {
        Ok(false)
    }

    /// Paginated listing for the /scans Historique tab.
    async fn list_scans(
        &self,
        _status: Option<&str>,
        _scan_type: Option<&str>,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<ScanJob>, DatabaseError> {
        Ok(vec![])
    }

    /// Total count for paginator on /scans Historique.
    async fn count_scans(
        &self,
        _status: Option<&str>,
        _scan_type: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        Ok(0)
    }

    // ── Scan schedules (V52__scan_schedules.sql) ──

    async fn create_scan_schedule(
        &self,
        _req: &NewScanSchedule,
        _next_run_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        Err(DatabaseError::Query(
            "scan schedules require postgres".into(),
        ))
    }

    async fn list_scan_schedules(&self) -> Result<Vec<ScanSchedule>, DatabaseError> {
        Ok(vec![])
    }

    async fn delete_scan_schedule(&self, _id: i64) -> Result<(), DatabaseError> {
        Ok(())
    }

    async fn toggle_scan_schedule(&self, _id: i64, _enabled: bool) -> Result<(), DatabaseError> {
        Ok(())
    }

    /// Tick worker: rows whose next_run_at <= now AND enabled = true.
    /// Returned in oldest-first order so a backlog drains predictably.
    async fn fetch_due_scan_schedules(&self) -> Result<Vec<ScanSchedule>, DatabaseError> {
        Ok(vec![])
    }

    /// After enqueueing a scan, update last_run_at = now and next_run_at
    /// to the new computed value.
    async fn bump_scan_schedule(
        &self,
        _id: i64,
        _next_run_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DatabaseError> {
        Ok(())
    }

    // ── Firewall events (V54__firewall_events.sql) ──

    /// Bulk insert firewall events (pf log entries). Skips duplicates
    /// based on (timestamp, src_ip, src_port, dst_ip, dst_port, rule_id).
    /// Returns number of rows actually inserted.
    async fn insert_firewall_events(
        &self,
        _events: &[NewFirewallEvent],
    ) -> Result<usize, DatabaseError> {
        Ok(0)
    }

    /// Delete events older than the cutoff. Returns number of rows
    /// deleted. Called at the end of each sync cycle for 24h retention.
    async fn prune_firewall_events(
        &self,
        _cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        Ok(0)
    }

    /// Per-source-IP aggregate of recent BLOCKED events. Powers the
    /// firewall_detection cycle (port scan, brute force).
    async fn firewall_blocked_aggregates(
        &self,
        _since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<FirewallBlockedAggregate>, DatabaseError> {
        Ok(vec![])
    }

    /// Forensic lookup: events involving an IP within a time window.
    async fn firewall_events_for_ip(
        &self,
        _ip: &str,
        _since: chrono::DateTime<chrono::Utc>,
        _limit: i64,
    ) -> Result<Vec<FirewallEventRecord>, DatabaseError> {
        Ok(vec![])
    }

    /// Pattern detection helper: count blocks toward dst_ip in last
    /// N seconds, grouped by src_ip. Returns top sources by hit count.
    async fn firewall_block_counts_by_src(
        &self,
        _dst_ip: &str,
        _since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<(String, i64)>, DatabaseError> {
        Ok(vec![])
    }

    // Skill configs
    async fn get_skill_config(
        &self,
        skill_id: &str,
    ) -> Result<Vec<SkillConfigRecord>, DatabaseError>;
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

    /// List all enabled Sigma rules with their detection_json for the native engine.
    async fn list_sigma_rules_enabled(&self) -> Result<Vec<serde_json::Value>, DatabaseError>;

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

    /// Find an asset by hostname or name (case-insensitive).
    /// Used by the Intelligence Engine to resolve alert hostnames to known assets.
    async fn find_asset_by_hostname(
        &self,
        hostname: &str,
    ) -> Result<Option<AssetRecord>, DatabaseError>;

    /// Mark specific fields as user-modified (protected from auto-discovery overwrite).
    async fn mark_asset_user_modified(
        &self,
        id: &str,
        fields: &[&str],
    ) -> Result<(), DatabaseError>;

    // ── Internal Networks ──

    async fn list_internal_networks(&self) -> Result<Vec<InternalNetwork>, DatabaseError>;

    async fn add_internal_network(
        &self,
        cidr: &str,
        label: Option<&str>,
        zone: Option<&str>,
    ) -> Result<i64, DatabaseError>;

    async fn delete_internal_network(&self, id: i64) -> Result<(), DatabaseError>;

    /// Merge software inventory into an asset (union, not replace). See ADR-044.
    async fn update_asset_software(
        &self,
        id: &str,
        software: &serde_json::Value,
    ) -> Result<(), DatabaseError>;

    /// Sprint 3 #2 — RSSI override of the seed/auto-detected criticality.
    /// Updates the canonical `assets` row; the caller is responsible for
    /// keeping the AGE graph node in sync (via threat_graph::upsert_asset).
    async fn set_asset_criticality(&self, id: &str, criticality: &str)
    -> Result<(), DatabaseError>;

    // ── Company Profile ──

    async fn get_company_profile(&self) -> Result<CompanyProfile, DatabaseError>;

    async fn update_company_profile(&self, profile: &CompanyProfile) -> Result<(), DatabaseError>;

    // ── Asset Categories ──

    async fn list_asset_categories(&self) -> Result<Vec<AssetCategory>, DatabaseError>;

    async fn upsert_asset_category(&self, cat: &AssetCategory) -> Result<(), DatabaseError>;

    // ── Enrichment Cache ──

    async fn get_enrichment_cache(
        &self,
        source: &str,
        key: &str,
    ) -> Result<Option<serde_json::Value>, DatabaseError>;

    async fn set_enrichment_cache(
        &self,
        source: &str,
        key: &str,
        value: &serde_json::Value,
        ttl_hours: i64,
    ) -> Result<(), DatabaseError>;

    // ── ML Scores (dedicated table) ──

    async fn get_ml_score(&self, asset_id: &str) -> Result<Option<(f64, String)>, DatabaseError>;

    /// Batch fetch all ML scores in one query. See ADR-030.
    async fn get_all_ml_scores(&self) -> Result<HashMap<String, (f64, String)>, DatabaseError>;

    async fn set_ml_score(
        &self,
        asset_id: &str,
        score: f64,
        reason: &str,
        features: &serde_json::Value,
    ) -> Result<(), DatabaseError>;

    // ── Incidents (See ADR-043) ──

    async fn create_incident(
        &self,
        asset: &str,
        title: &str,
        severity: &str,
        alert_ids: &[i32],
        finding_ids: &[i32],
        alert_count: i32,
    ) -> Result<i32, DatabaseError>;

    async fn update_incident_verdict(
        &self,
        id: i32,
        verdict: &str,
        confidence: f64,
        summary: &str,
        mitre: &[String],
        proposed_actions: &serde_json::Value,
        investigation_log: &serde_json::Value,
        evidence_citations: &serde_json::Value,
        // 'graph' | 'react' | 'manual'. None preserves the existing value
        // (used by re-investigate paths that update without changing source).
        verdict_source: Option<&str>,
    ) -> Result<(), DatabaseError>;

    async fn update_incident_hitl(
        &self,
        id: i32,
        status: &str,
        responded_by: &str,
        response: &str,
    ) -> Result<(), DatabaseError>;

    /// Attach a pre-computed blast-radius snapshot. See ADR-048.
    async fn attach_blast_radius_snapshot(
        &self,
        id: i32,
        score: u8,
        snapshot: &serde_json::Value,
    ) -> Result<(), DatabaseError>;

    async fn update_incident_status(&self, id: i32, status: &str) -> Result<(), DatabaseError>;

    /// Overwrite the incident title with a short LLM-rewritten label
    /// (≤120 chars). Called when L1/L2 returns a non-empty `incident_title_fr`
    /// that improves on the heuristic title set at incident creation
    /// (see `humanize_incident_title`).
    async fn update_incident_title(&self, id: i32, title: &str) -> Result<(), DatabaseError>;

    // ── Suppression rules (See ADR-047) ──

    async fn list_suppression_rules(
        &self,
        enabled_only: bool,
    ) -> Result<Vec<serde_json::Value>, DatabaseError>;

    async fn get_suppression_rule(
        &self,
        id: uuid::Uuid,
    ) -> Result<Option<serde_json::Value>, DatabaseError>;

    async fn create_suppression_rule(
        &self,
        name: &str,
        predicate: &serde_json::Value,
        predicate_source: &str,
        action: &str,
        severity_cap: Option<&str>,
        scope: &str,
        reason: &str,
        created_by: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        source: &str,
    ) -> Result<uuid::Uuid, DatabaseError>;

    async fn disable_suppression_rule(&self, id: uuid::Uuid) -> Result<(), DatabaseError>;

    /// Returns the raw rows needed to rebuild the in-memory engine.
    /// Only enabled + non-expired rules are returned.
    async fn load_active_suppression_rules(&self) -> Result<Vec<serde_json::Value>, DatabaseError>;

    /// Bump match_count + last_match_at. Cheap atomic update used on
    /// the hot path — tolerant of write contention.
    async fn bump_suppression_match(&self, id: uuid::Uuid) -> Result<(), DatabaseError>;

    /// Preview helper: count + sample incidents created in the last
    /// `lookback_days` days. Expression evaluation is performed by the
    /// caller in Rust — this only returns candidate events.
    async fn list_incidents_for_preview(
        &self,
        lookback_days: i32,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>, DatabaseError>;

    // ── CISA KEV time-to-alert ──

    /// Record a newly-observed KEV entry. Idempotent on `cve_id`.
    /// Returns true when a new row was inserted (first observation).
    async fn record_kev_observation(
        &self,
        cve_id: &str,
        kev_published_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<bool, DatabaseError>;

    /// Mark the moment this KEV entry first matched one of our assets.
    /// No-op if already set (first-match semantics).
    async fn record_kev_first_match(
        &self,
        cve_id: &str,
        incident_id: Option<i32>,
    ) -> Result<(), DatabaseError>;

    /// Dashboard metric — from the kev_tta_metrics_30d materialized view.
    async fn kev_tta_metrics(&self) -> Result<serde_json::Value, DatabaseError>;

    // ── Monthly RSSI summary (See roadmap §3.4) ──

    /// Full row for one month (from the materialized view). `month` must
    /// be the first of the month, UTC.
    async fn monthly_rssi_summary(
        &self,
        month: chrono::NaiveDate,
    ) -> Result<Option<serde_json::Value>, DatabaseError>;

    /// Top N incidents by blast-radius score for the month.
    async fn top_incidents_by_blast(
        &self,
        month: chrono::NaiveDate,
        limit: i32,
    ) -> Result<Vec<serde_json::Value>, DatabaseError>;

    /// Refresh the matview. Uses `CONCURRENTLY` so queries stay fast.
    async fn refresh_monthly_rssi_summary(&self) -> Result<(), DatabaseError>;

    async fn list_incidents(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<serde_json::Value>, DatabaseError>;

    async fn get_incident(&self, id: i32) -> Result<Option<serde_json::Value>, DatabaseError>;

    async fn find_open_incident_for_asset(&self, asset: &str)
    -> Result<Option<i32>, DatabaseError>;

    /// Touch an existing open incident: bump alert_count by delta, refresh updated_at.
    /// Used when a recurring pattern on the same asset would otherwise create a duplicate.
    /// Bump `alert_count` and `updated_at` on an existing incident.
    ///
    /// Sprint 5 #2 — `pattern_key` (sigma rule_id, graph name, or any
    /// string identifying the trigger) gates the count bump: when the
    /// new pattern matches the last one we touched the incident with,
    /// `alert_count_delta` is ignored (no-op on count, only `updated_at`
    /// moves). This stops the count from growing unbounded when the
    /// same rule keeps firing on the same asset. `None` preserves the
    /// legacy behavior (always bump) — used by callers that don't yet
    /// track a pattern key.
    async fn touch_incident(
        &self,
        id: i32,
        alert_count_delta: i32,
        pattern_key: Option<&str>,
    ) -> Result<(), DatabaseError>;

    /// Cleanup: delete acknowledged/resolved sigma alerts older than `days_old` days.
    /// Returns the number of deleted rows.
    async fn cleanup_old_sigma_alerts(&self, days_old: i32) -> Result<i64, DatabaseError>;

    /// Phase G acceptance check — counts incidents created in the last
    /// `lookback_days` days that have an empty `proposed_actions.actions`
    /// array (or null). Returns `(total, missing)` so the caller can
    /// compute the actionable ratio and surface the worst offender ids.
    /// See `PHASE_G_INVESTIGATION_GRAPHS.md` acceptance criteria.
    async fn phase_g_acceptance_stats(
        &self,
        lookback_days: i32,
    ) -> Result<(i64, i64, Vec<i32>), DatabaseError>;

    /// Count rows in the mitre_techniques table (used for self-heal trigger).
    async fn count_mitre_techniques(&self) -> Result<i64, DatabaseError>;

    /// Archive all incidents with a resolved-like status (resolved, closed, false_positive).
    /// Returns the number of rows archived. Reversible — archived rows stay in DB.
    async fn archive_resolved_incidents(&self) -> Result<i64, DatabaseError>;

    /// Archive all sigma alerts with status 'acknowledged' or 'resolved'.
    /// Returns the number of rows archived.
    async fn archive_resolved_alerts(&self) -> Result<i64, DatabaseError>;

    /// Permanently delete archived incidents older than `days_old` days.
    /// Only targets rows with status='archived' — fresh open incidents are safe.
    async fn purge_old_archived(&self, days_old: i32) -> Result<(i64, i64), DatabaseError>;

    /// Append a note to an incident's audit trail. Notes are stored as a
    /// JSONB array of {text, author, at}. Used by the dashboard "commentaire RSSI"
    /// field and by bots when they execute actions (for context).
    async fn add_incident_note(
        &self,
        id: i32,
        text: &str,
        author: &str,
    ) -> Result<(), DatabaseError>;

    // ── Phase G1b — task_queue + graph_executions (V62) ──

    /// Push une nouvelle task dans `task_queue`. Renvoie l'id alloué.
    async fn enqueue_task(
        &self,
        task: &crate::agent::task_queue::NewTask,
    ) -> Result<i64, DatabaseError>;

    /// Pull la prochaine task `queued` du kind donné. Atomique (FOR UPDATE
    /// SKIP LOCKED) — les workers concurrents grab des rows différentes.
    /// Retourne `None` si la queue est vide pour ce kind.
    async fn claim_next_task(
        &self,
        kind: crate::agent::task_queue::TaskKind,
        worker_id: &str,
    ) -> Result<Option<crate::agent::task_queue::Task>, DatabaseError>;

    /// Marque la task `done` avec son résultat.
    async fn complete_task(&self, id: i64, result: &serde_json::Value)
    -> Result<(), DatabaseError>;

    /// Marque la task `error`. Si `attempts < max_attempts`, le caller
    /// peut rééenqueue (logique applicative, pas DB).
    async fn fail_task(&self, id: i64, error: &str) -> Result<(), DatabaseError>;

    /// Recovery au boot : remet en `queued` les tasks `running` plus
    /// vieilles que `older_than_secs` (worker mort sans nettoyage).
    /// Retourne le nombre de rows recovered.
    async fn recover_stale_tasks(&self, older_than_secs: i64) -> Result<i64, DatabaseError>;

    /// Comptage par status — utilisé par le check de backpressure pour
    /// décider si on accepte de nouveaux graphs.
    async fn count_tasks_by_status(
        &self,
    ) -> Result<crate::agent::task_queue::QueueDepths, DatabaseError>;

    /// Crée une row dans `graph_executions` au démarrage d'un graph.
    /// Renvoie l'id alloué (sert de `graph_run_id` aux tasks enfants).
    async fn create_graph_execution(
        &self,
        exec: &crate::agent::task_queue::NewGraphExecution,
    ) -> Result<i64, DatabaseError>;

    /// Update du status final d'un graph (archived/incident/inconclusive/failed).
    /// Persiste la trace JSON et marque finished_at + duration_ms.
    async fn finalize_graph_execution(
        &self,
        id: i64,
        status: crate::agent::task_queue::GraphExecutionStatus,
        archive_reason: Option<&str>,
        incident_id: Option<i32>,
        trace: &serde_json::Value,
        error: Option<&str>,
    ) -> Result<(), DatabaseError>;

    // ── Phase G2 — attack_paths_predicted (V63) ──

    /// Bulk-insert d'un batch de paths d'un même run. Renvoie le nombre
    /// inséré.
    async fn insert_attack_paths(
        &self,
        paths: &[crate::agent::path_risk::AttackPath],
    ) -> Result<i64, DatabaseError>;

    /// Top-N paths du dernier run (par score décroissant). Utilisé par
    /// l'endpoint API + future page UI.
    async fn latest_attack_paths(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::agent::path_risk::AttackPath>, DatabaseError>;

    /// Phase G3 — Top-N choke points : nœuds qui apparaissent dans le
    /// plus grand nombre d'attack_paths du dernier run, pondérés par le
    /// score des paths. Patcher ces nœuds = casser le plus de paths.
    async fn latest_choke_points(&self, limit: i64) -> Result<Vec<ChokePoint>, DatabaseError>;

    /// Phase G4a — list les `graph_executions` filtrables par status,
    /// asset, motif d'archive, période. Pour pages /enquetes et /archives.
    async fn list_graph_executions(
        &self,
        filter: &GraphExecutionsFilter,
    ) -> Result<Vec<crate::agent::task_queue::GraphExecutionRecord>, DatabaseError>;
}

/// Phase G4 — filtre côté list_graph_executions.
#[derive(Debug, Clone, Default)]
pub struct GraphExecutionsFilter {
    /// "running" | "archived" | "incident" | "inconclusive" | "failed"
    pub status: Option<String>,
    pub asset_id: Option<String>,
    pub archive_reason: Option<String>,
    pub since_hours: Option<i64>,
    pub limit: i64,
}

/// Phase G3 — un choke point dans le top-N : asset qui, durci, casse N
/// chemins d'attaque (avec poids = somme des scores).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChokePoint {
    pub asset: String,
    /// Nombre de paths du dernier run qui passent par cet asset.
    pub paths_through: i64,
    /// Somme des scores des paths qui le traversent.
    pub weighted_score: f64,
    /// Top-3 des assets cibles (crown jewels) accessibles via ce choke point.
    pub top_targets: Vec<String>,
}
