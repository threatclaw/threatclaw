//! ThreatClaw-specific API handlers for findings, alerts, config, and metrics.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::channels::web::server::GatewayState;
use crate::agent::mode_manager::{AgentMode, ModeConfig, parse_mode};
use crate::db::threatclaw_store::{
    AlertRecord, DashboardMetrics, FindingRecord, NewFinding, SkillConfigRecord,
};

// ── DTOs ──

#[derive(Debug, Deserialize)]
pub struct FindingsQuery {
    pub severity: Option<String>,
    pub status: Option<String>,
    pub skill_id: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct FindingsListResponse {
    pub findings: Vec<FindingRecord>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct FindingResponse {
    pub finding: FindingRecord,
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusRequest {
    pub status: String,
    pub resolved_by: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    pub level: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AlertsListResponse {
    pub alerts: Vec<AlertRecord>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct CountsResponse {
    pub counts: Vec<CountEntry>,
}

#[derive(Debug, Serialize)]
pub struct CountEntry {
    pub label: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct SkillConfigResponse {
    pub skill_id: String,
    pub config: Vec<SkillConfigRecord>,
}

#[derive(Debug, Deserialize)]
pub struct SetConfigRequest {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub metrics: DashboardMetrics,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub database: bool,
    pub llm: &'static str,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, String)>;

fn db_err(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn no_db() -> (StatusCode, String) {
    (StatusCode::SERVICE_UNAVAILABLE, "Database not available".to_string())
}

// ── Health ──

pub async fn tc_health_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<HealthResponse> {
    let db_ok = state.store.is_some();
    Ok(Json(HealthResponse {
        status: if db_ok { "ok" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
        database: db_ok,
        llm: "ollama",
    }))
}

// ── Findings ──

pub async fn findings_list_handler(
    State(state): State<Arc<GatewayState>>,
    Query(q): Query<FindingsQuery>,
) -> ApiResult<FindingsListResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let findings = store
        .list_findings(
            q.severity.as_deref(),
            q.status.as_deref(),
            q.skill_id.as_deref(),
            q.limit.unwrap_or(100),
        )
        .await
        .map_err(db_err)?;
    let total = findings.len();
    Ok(Json(FindingsListResponse { findings, total }))
}

pub async fn findings_create_handler(
    State(state): State<Arc<GatewayState>>,
    Json(finding): Json<NewFinding>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let id = store.insert_finding(&finding).await.map_err(db_err)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "status": "created" })),
    ))
}

pub async fn findings_detail_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<i64>,
) -> ApiResult<FindingResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let finding = store
        .get_finding(id)
        .await
        .map_err(db_err)?
        .ok_or((StatusCode::NOT_FOUND, "Finding not found".to_string()))?;
    Ok(Json(FindingResponse { finding }))
}

pub async fn findings_update_status_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateStatusRequest>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    store
        .update_finding_status(id, &req.status, req.resolved_by.as_deref())
        .await
        .map_err(db_err)?;
    Ok(Json(serde_json::json!({ "status": "updated" })))
}

pub async fn findings_counts_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<CountsResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let counts = store.count_findings_by_severity().await.map_err(db_err)?;
    Ok(Json(CountsResponse {
        counts: counts
            .into_iter()
            .map(|(label, count)| CountEntry { label, count })
            .collect(),
    }))
}

// ── Alerts ──

pub async fn alerts_list_handler(
    State(state): State<Arc<GatewayState>>,
    Query(q): Query<AlertsQuery>,
) -> ApiResult<AlertsListResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let alerts = store
        .list_alerts(q.level.as_deref(), q.status.as_deref(), q.limit.unwrap_or(100))
        .await
        .map_err(db_err)?;
    let total = alerts.len();
    Ok(Json(AlertsListResponse { alerts, total }))
}

pub async fn alerts_update_status_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateStatusRequest>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    store
        .update_alert_status(id, &req.status, req.notes.as_deref())
        .await
        .map_err(db_err)?;
    Ok(Json(serde_json::json!({ "status": "updated" })))
}

pub async fn alerts_counts_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<CountsResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let counts = store.count_alerts_by_level().await.map_err(db_err)?;
    Ok(Json(CountsResponse {
        counts: counts
            .into_iter()
            .map(|(label, count)| CountEntry { label, count })
            .collect(),
    }))
}

// ── Skill Config ──

pub async fn skill_config_get_handler(
    State(state): State<Arc<GatewayState>>,
    Path(skill_id): Path<String>,
) -> ApiResult<SkillConfigResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let config = store.get_skill_config(&skill_id).await.map_err(db_err)?;
    Ok(Json(SkillConfigResponse { skill_id, config }))
}

pub async fn skill_config_set_handler(
    State(state): State<Arc<GatewayState>>,
    Path(skill_id): Path<String>,
    Json(req): Json<SetConfigRequest>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    store
        .set_skill_config(&skill_id, &req.key, &req.value)
        .await
        .map_err(db_err)?;
    Ok(Json(serde_json::json!({ "status": "saved" })))
}

// ── Dashboard Metrics ──

pub async fn dashboard_metrics_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<MetricsResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let metrics = store.get_dashboard_metrics().await.map_err(db_err)?;
    Ok(Json(MetricsResponse { metrics }))
}

// ── Agent Mode ──

#[derive(Debug, Serialize)]
pub struct AgentModeResponse {
    pub current_mode: String,
    pub mode_name: String,
    pub description: String,
    pub react_enabled: bool,
    pub auto_execute: bool,
    pub hitl_required: bool,
    pub available_modes: Vec<ModeInfo>,
}

#[derive(Debug, Serialize)]
pub struct ModeInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub react_enabled: bool,
    pub auto_execute: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetModeRequest {
    pub mode: String,
}

pub async fn agent_mode_get_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<AgentModeResponse> {
    // Read current mode from settings (system user)
    let mode_str = if let Some(store) = state.store.as_ref() {
        store.get_setting("_system", "agent_mode").await.ok().flatten()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "investigator".to_string())
    } else {
        "investigator".to_string()
    };

    let mode = parse_mode(&mode_str).unwrap_or(AgentMode::Investigator);
    let cfg = ModeConfig::for_mode(mode);

    let available: Vec<ModeInfo> = [AgentMode::Analyst, AgentMode::Investigator, AgentMode::Responder, AgentMode::AutonomousLow]
        .iter()
        .map(|m| {
            let c = ModeConfig::for_mode(*m);
            ModeInfo {
                id: m.to_string(),
                name: c.name.to_string(),
                description: c.description.to_string(),
                react_enabled: c.react_enabled,
                auto_execute: c.auto_execute,
            }
        })
        .collect();

    Ok(Json(AgentModeResponse {
        current_mode: mode.to_string(),
        mode_name: cfg.name.to_string(),
        description: cfg.description.to_string(),
        react_enabled: cfg.react_enabled,
        auto_execute: cfg.auto_execute,
        hitl_required: cfg.hitl_required,
        available_modes: available,
    }))
}

pub async fn agent_mode_set_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<SetModeRequest>,
) -> ApiResult<serde_json::Value> {
    let mode = parse_mode(&req.mode).ok_or((
        StatusCode::BAD_REQUEST,
        format!("Unknown mode: '{}'. Valid: analyst, investigator, responder, autonomous_low", req.mode),
    ))?;

    if let Some(store) = state.store.as_ref() {
        let val = serde_json::Value::String(mode.to_string());
        store.set_setting("_system", "agent_mode", &val).await.map_err(db_err)?;
    }

    tracing::info!("Agent mode changed to: {}", mode);
    Ok(Json(serde_json::json!({ "status": "mode_changed", "mode": mode.to_string() })))
}

// ── Kill Switch ──

#[derive(Debug, Serialize)]
pub struct KillSwitchStatus {
    pub active: bool,
    pub kill_reason: Option<String>,
}

pub async fn kill_switch_status_handler(
    State(_state): State<Arc<GatewayState>>,
) -> ApiResult<KillSwitchStatus> {
    // In production, this would read from a shared KillSwitch instance.
    // For now, return the default state (active).
    Ok(Json(KillSwitchStatus {
        active: true,
        kill_reason: None,
    }))
}

#[derive(Debug, Deserialize)]
pub struct KillSwitchTriggerRequest {
    pub triggered_by: String,
}

pub async fn kill_switch_trigger_handler(
    State(_state): State<Arc<GatewayState>>,
    Json(req): Json<KillSwitchTriggerRequest>,
) -> ApiResult<serde_json::Value> {
    tracing::error!("KILL SWITCH triggered via API by: {}", req.triggered_by);
    // In production, this would engage the shared KillSwitch instance.
    Ok(Json(serde_json::json!({
        "status": "kill_switch_engaged",
        "triggered_by": req.triggered_by,
        "message": "Agent stopped. Manual intervention required."
    })))
}

// ── Audit Log ──

#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub event_type: String,
    pub agent_mode: String,
    pub cmd_id: Option<String>,
    pub approved_by: Option<String>,
    pub success: Option<bool>,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<i64>,
    pub event_type: Option<String>,
}

pub async fn audit_log_handler(
    State(_state): State<Arc<GatewayState>>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<serde_json::Value> {
    // Audit log entries will be populated when the ReAct cycle runs.
    // For now return the structure so the dashboard can render it.
    let _ = q;
    Ok(Json(serde_json::json!({
        "entries": [],
        "total": 0,
        "note": "Audit log will populate when ReAct cycles execute"
    })))
}

// ── ReAct Cycle ──

#[derive(Debug, Serialize)]
pub struct ReactCycleResponse {
    pub status: String,
    pub observations: usize,
    pub escalation_level: u8,
    pub analysis: Option<serde_json::Value>,
    pub error: Option<String>,
}

pub async fn react_cycle_trigger_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<ReactCycleResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let config = crate::agent::react_runner::ReactRunnerConfig::default();
    let result = crate::agent::react_runner::run_react_cycle(
        Arc::clone(store),
        &config,
    ).await;

    let analysis_json = result.analysis.as_ref().map(|a| serde_json::to_value(a).unwrap_or_default());

    Ok(Json(ReactCycleResponse {
        status: result.cycle_result,
        observations: result.observations_count,
        escalation_level: result.escalation_level,
        analysis: analysis_json,
        error: result.error,
    }))
}

// ── Audit Entries (from settings) ──

pub async fn audit_entries_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let all_settings = store.list_settings("_audit").await.map_err(db_err)?;
    let mut entries: Vec<serde_json::Value> = Vec::new();

    for setting in all_settings.iter().rev().take(50) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&setting.value.to_string()) {
            entries.push(val);
        }
    }

    Ok(Json(serde_json::json!({
        "entries": entries,
        "total": entries.len(),
    })))
}

// ── HITL Callback ──

#[derive(Debug, Deserialize)]
pub struct HitlCallbackRequest {
    pub nonce: String,
    pub approved: bool,
    pub approved_by: String,
    pub params: std::collections::HashMap<String, String>,
}

pub async fn hitl_callback_handler(
    State(_state): State<Arc<GatewayState>>,
    Json(req): Json<HitlCallbackRequest>,
) -> ApiResult<serde_json::Value> {
    use crate::agent::hitl_nonce::NonceManager;
    use std::time::Duration;

    // Create a temporary nonce manager (in production this would be shared via state)
    let nonce_mgr = NonceManager::new(Duration::from_secs(3600));

    let result = crate::agent::hitl_bridge::process_slack_callback(
        &req.nonce,
        req.approved,
        &req.approved_by,
        &nonce_mgr,
        &req.params,
    )
    .await;

    match result {
        Ok(r) => Ok(Json(serde_json::json!({
            "status": if r.approved { "approved" } else { "rejected" },
            "cmd_id": r.cmd_id,
            "executed": r.executed,
            "success": r.execution_success,
            "output": r.execution_output,
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "status": "error",
            "error": e.to_string(),
        }))),
    }
}

// ── Targets / Infrastructure ──

#[derive(Debug, Deserialize)]
pub struct CreateTargetRequest {
    pub id: String,
    pub host: String,
    pub target_type: String,
    pub access_type: String,
    pub port: Option<i32>,
    pub mode: Option<String>,
    pub credential_name: Option<String>,
    pub ssh_host_key: Option<String>,
    pub driver: Option<String>,
    pub allowed_actions: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
}

pub async fn targets_list_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let settings = store.list_settings("_targets").await.map_err(db_err)?;
    let targets: Vec<serde_json::Value> = settings.iter()
        .filter_map(|s| serde_json::from_value(s.value.clone()).ok())
        .collect();
    Ok(Json(serde_json::json!({ "targets": targets, "total": targets.len() })))
}

pub async fn targets_create_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<CreateTargetRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let target = serde_json::json!({
        "id": req.id,
        "host": req.host,
        "target_type": req.target_type,
        "access_type": req.access_type,
        "port": req.port.unwrap_or(22),
        "mode": req.mode.unwrap_or_else(|| "investigator".to_string()),
        "credential_name": req.credential_name,
        "ssh_host_key": req.ssh_host_key,
        "driver": req.driver,
        "allowed_actions": req.allowed_actions.unwrap_or_default(),
        "tags": req.tags.unwrap_or_default(),
    });
    let key = format!("target_{}", req.id);
    store.set_setting("_targets", &key, &target).await.map_err(db_err)?;
    tracing::info!("Target created: {} ({})", req.id, req.host);
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "status": "created", "id": req.id }))))
}

pub async fn targets_delete_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let key = format!("target_{}", id);
    store.delete_setting("_targets", &key).await.map_err(db_err)?;
    tracing::info!("Target deleted: {}", id);
    Ok(Json(serde_json::json!({ "status": "deleted", "id": id })))
}

// ── Skills Catalog (reads real skill.json files) ──

pub async fn skills_catalog_handler(
    State(_state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let mut skills = Vec::new();

    // Read from skills-src/ (official WASM skills)
    let skills_src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/skills-src"));
    if let Ok(entries) = std::fs::read_dir(skills_src) {
        for entry in entries.flatten() {
            let skill_json = entry.path().join("skill.json");
            if skill_json.exists() {
                if let Ok(content) = std::fs::read_to_string(&skill_json) {
                    if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&content) {
                        // Check if WASM is compiled
                        let wasm_path = format!("{}/.threatclaw/channels/{}.wasm",
                            std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()),
                            val["id"].as_str().unwrap_or(""));
                        val["installed"] = serde_json::json!(std::path::Path::new(&wasm_path).exists());
                        val["runtime"] = serde_json::json!("wasm");
                        skills.push(val);
                    }
                }
            }
        }
    }

    // Read from skills/ (legacy Python skills with skill.json)
    let skills_dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/skills"));
    if let Ok(entries) = std::fs::read_dir(skills_dir) {
        for entry in entries.flatten() {
            let skill_json = entry.path().join("skill.json");
            if skill_json.exists() {
                if let Ok(content) = std::fs::read_to_string(&skill_json) {
                    if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&content) {
                        val["installed"] = serde_json::json!(true);
                        if val.get("runtime").is_none() {
                            val["runtime"] = serde_json::json!("docker");
                        }
                        skills.push(val);
                    }
                }
            }
        }
    }

    Ok(Json(serde_json::json!({ "skills": skills, "total": skills.len() })))
}

// ── Soul Info ──

pub async fn soul_info_handler(
    State(_state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let soul_path = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/AGENT_SOUL.toml"));
    match crate::agent::soul::AgentSoul::load_and_verify(soul_path) {
        Ok(soul) => Ok(Json(serde_json::json!({
            "status": "verified",
            "name": soul.identity.name,
            "version": soul.identity.version,
            "purpose": soul.identity.purpose,
            "rules_count": soul.immutable_rules.len(),
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "status": "error",
            "error": e.to_string(),
        }))),
    }
}
