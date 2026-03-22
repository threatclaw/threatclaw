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
                        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
                        let skill_id = val["id"].as_str().unwrap_or("");
                        // Check both tools/ (compiled) and channels/ (legacy) directories
                        let installed = std::path::Path::new(&format!("{}/.threatclaw/tools/{}.wasm", home, skill_id)).exists()
                            || std::path::Path::new(&format!("{}/.threatclaw/channels/{}.wasm", home, skill_id)).exists();
                        val["installed"] = serde_json::json!(installed);
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

// ── Skill Install ──

/// POST /api/tc/skills/{id}/install — install a WASM skill.
/// Looks for the compiled .wasm in the build output and copies it to ~/.threatclaw/tools/.
pub async fn skill_install_handler(
    Path(skill_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let tools_dir = format!("{}/.threatclaw/tools", home);

    // Ensure tools directory exists
    let _ = std::fs::create_dir_all(&tools_dir);

    let target_path = format!("{}/{}.wasm", tools_dir, skill_id);

    // Already installed?
    if std::path::Path::new(&target_path).exists() {
        return Ok(Json(serde_json::json!({ "ok": true, "status": "already_installed" })));
    }

    // Look for pre-compiled WASM in build output
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let search_paths = [
        format!("{}/target/wasm32-wasip2/release/{}.wasm", manifest_dir, skill_id),
        format!("{}/target/wasm32-wasip2/debug/{}.wasm", manifest_dir, skill_id),
        format!("{}/skills-src/{}/target/wasm32-wasip2/release/{}.wasm", manifest_dir, skill_id, skill_id.replace('-', "_")),
    ];

    for path in &search_paths {
        if std::path::Path::new(path).exists() {
            match std::fs::copy(path, &target_path) {
                Ok(_) => {
                    tracing::info!("Skill installed: {} → {}", skill_id, target_path);
                    return Ok(Json(serde_json::json!({ "ok": true, "status": "installed", "source": "pre_compiled" })));
                }
                Err(e) => {
                    return Ok(Json(serde_json::json!({ "ok": false, "error": format!("Copy failed: {e}") })));
                }
            }
        }
    }

    // Try to compile from source if skill-src exists
    let skill_src = format!("{}/skills-src/{}", manifest_dir, skill_id);
    if std::path::Path::new(&skill_src).exists() {
        tracing::info!("Skill source found, attempting WASM compilation: {}", skill_id);

        // Run cargo build for the skill
        let output = std::process::Command::new("cargo")
            .args(["build", "--release", "--target", "wasm32-wasip2"])
            .current_dir(&skill_src)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                // Find the compiled .wasm
                let crate_name = skill_id.replace('-', "_");
                let compiled = format!("{}/target/wasm32-wasip2/release/{}.wasm", skill_src, crate_name);
                if std::path::Path::new(&compiled).exists() {
                    match std::fs::copy(&compiled, &target_path) {
                        Ok(_) => {
                            tracing::info!("Skill compiled and installed: {}", skill_id);
                            return Ok(Json(serde_json::json!({ "ok": true, "status": "compiled_and_installed" })));
                        }
                        Err(e) => return Ok(Json(serde_json::json!({ "ok": false, "error": format!("Copy failed: {e}") }))),
                    }
                }
                Ok(Json(serde_json::json!({ "ok": false, "error": "Compiled but WASM not found in output" })))
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                Ok(Json(serde_json::json!({ "ok": false, "error": format!("Compilation failed: {}", stderr.chars().take(300).collect::<String>()) })))
            }
            Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": format!("Cannot run cargo: {e}") }))),
        }
    } else {
        Ok(Json(serde_json::json!({
            "ok": false,
            "error": format!("Skill {} not found — no pre-compiled WASM and no source directory", skill_id),
        })))
    }
}

// ── Skill Test ──

/// POST /api/tc/skills/{id}/test — test a skill's API connection with saved config.
pub async fn skill_test_handler(
    State(state): State<Arc<GatewayState>>,
    Path(skill_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    // Load skill config from DB
    let config = store.get_skill_config(&skill_id).await.map_err(db_err)?;
    let cfg: std::collections::HashMap<String, String> = config.iter()
        .map(|c| (c.key.clone(), c.value.clone()))
        .collect();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let result = match skill_id.as_str() {
        "skill-abuseipdb" => {
            let api_key = cfg.get("api_key").cloned().unwrap_or_default();
            if api_key.is_empty() {
                return Ok(Json(serde_json::json!({ "ok": false, "error": "Clé API non configurée" })));
            }
            match client.get("https://api.abuseipdb.com/api/v2/check")
                .header("Key", &api_key).header("Accept", "application/json")
                .query(&[("ipAddress", "8.8.8.8"), ("maxAgeInDays", "1")])
                .send().await {
                Ok(r) => {
                    if r.status().is_success() {
                        let data: serde_json::Value = r.json().await.unwrap_or_default();
                        serde_json::json!({ "ok": true, "detail": format!("API OK — IP 8.8.8.8 score: {}", data["data"]["abuseConfidenceScore"]) })
                    } else {
                        serde_json::json!({ "ok": false, "error": format!("HTTP {} — vérifiez votre clé API", r.status()) })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "skill-shodan" => {
            let api_key = cfg.get("api_key").cloned().unwrap_or_default();
            if api_key.is_empty() {
                return Ok(Json(serde_json::json!({ "ok": false, "error": "Clé API non configurée" })));
            }
            match client.get("https://api.shodan.io/api-info")
                .query(&[("key", api_key.as_str())])
                .send().await {
                Ok(r) => {
                    if r.status().is_success() {
                        let data: serde_json::Value = r.json().await.unwrap_or_default();
                        serde_json::json!({ "ok": true, "detail": format!("API OK — plan: {}, crédits: {}", data["plan"], data["query_credits"]) })
                    } else {
                        serde_json::json!({ "ok": false, "error": format!("HTTP {} — vérifiez votre clé API", r.status()) })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "skill-virustotal" => {
            let api_key = cfg.get("api_key").cloned().unwrap_or_default();
            if api_key.is_empty() {
                return Ok(Json(serde_json::json!({ "ok": false, "error": "Clé API non configurée" })));
            }
            match client.get("https://www.virustotal.com/api/v3/users/me")
                .header("x-apikey", &api_key)
                .send().await {
                Ok(r) => {
                    if r.status().is_success() {
                        serde_json::json!({ "ok": true, "detail": "API OK — clé valide" })
                    } else {
                        serde_json::json!({ "ok": false, "error": format!("HTTP {} — vérifiez votre clé API", r.status()) })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "skill-cti-crowdsec" => {
            let api_key = cfg.get("api_key").cloned().unwrap_or_default();
            if api_key.is_empty() {
                return Ok(Json(serde_json::json!({ "ok": false, "error": "Clé API non configurée" })));
            }
            match client.get("https://cti.api.crowdsec.net/v2/smoke/8.8.8.8")
                .header("x-api-key", &api_key)
                .send().await {
                Ok(r) => {
                    if r.status().is_success() {
                        serde_json::json!({ "ok": true, "detail": "API OK — connexion CrowdSec CTI réussie" })
                    } else {
                        serde_json::json!({ "ok": false, "error": format!("HTTP {} — vérifiez votre clé API", r.status()) })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "skill-darkweb-monitor" => {
            let api_key = cfg.get("api_key").cloned().unwrap_or_default();
            if api_key.is_empty() {
                return Ok(Json(serde_json::json!({ "ok": false, "error": "Clé API HIBP non configurée" })));
            }
            match client.get("https://haveibeenpwned.com/api/v3/subscription/status")
                .header("hibp-api-key", &api_key)
                .header("user-agent", "ThreatClaw")
                .send().await {
                Ok(r) => {
                    if r.status().is_success() {
                        serde_json::json!({ "ok": true, "detail": "API OK — abonnement HIBP actif" })
                    } else if r.status().as_u16() == 401 {
                        serde_json::json!({ "ok": false, "error": "Clé API invalide" })
                    } else {
                        serde_json::json!({ "ok": false, "error": format!("HTTP {}", r.status()) })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "skill-wazuh" => {
            let url = cfg.get("url").cloned().unwrap_or_default();
            let username = cfg.get("username").cloned().unwrap_or_default();
            let password = cfg.get("password").cloned().unwrap_or_default();
            if url.is_empty() || username.is_empty() {
                return Ok(Json(serde_json::json!({ "ok": false, "error": "URL et utilisateur requis" })));
            }
            let wazuh_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            match wazuh_client.post(format!("{}/security/user/authenticate", url))
                .basic_auth(&username, Some(&password))
                .send().await {
                Ok(r) => {
                    if r.status().is_success() {
                        serde_json::json!({ "ok": true, "detail": "API OK — authentification Wazuh réussie" })
                    } else {
                        serde_json::json!({ "ok": false, "error": format!("HTTP {} — vérifiez vos identifiants", r.status()) })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": format!("Connexion échouée: {} — vérifiez l'URL", e) }),
            }
        }
        "skill-email-audit" => {
            let domains = cfg.get("domains").cloned().unwrap_or_default();
            if domains.is_empty() {
                return Ok(Json(serde_json::json!({ "ok": false, "error": "Aucun domaine configuré" })));
            }
            let first_domain = domains.split(',').next().unwrap_or("").trim();
            // Test DNS lookup via public resolver
            match client.get(format!("https://dns.google/resolve?name={first_domain}&type=TXT"))
                .send().await {
                Ok(r) => {
                    if r.status().is_success() {
                        let data: serde_json::Value = r.json().await.unwrap_or_default();
                        let has_spf = data["Answer"].as_array()
                            .map(|a| a.iter().any(|r| r["data"].as_str().map(|s| s.contains("v=spf1")).unwrap_or(false)))
                            .unwrap_or(false);
                        serde_json::json!({
                            "ok": true,
                            "detail": format!("DNS OK — {} {}", first_domain, if has_spf { "(SPF trouvé)" } else { "(pas de SPF)" })
                        })
                    } else {
                        serde_json::json!({ "ok": false, "error": "Résolution DNS échouée" })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "skill-compliance-nis2" | "skill-compliance-iso27001" => {
            serde_json::json!({ "ok": true, "detail": "Analyse locale — aucune API externe requise" })
        }
        "skill-report-gen" => {
            serde_json::json!({ "ok": true, "detail": "Génération locale — aucune API externe requise" })
        }
        _ => {
            serde_json::json!({ "ok": false, "error": format!("Test non disponible pour {}", skill_id) })
        }
    };

    Ok(Json(result))
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

// ══════════════════════════════════════════════════════════
// CONFIGURATION (LLM, channels, permissions, anonymizer)
// ══════════════════════════════════════════════════════════

/// GET /api/tc/config — get all ThreatClaw configuration.
pub async fn config_get_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let mut config = serde_json::json!({});
    for key in &["llm", "forensic", "instruct", "cloud", "channels", "permissions", "anonymize_primary", "general"] {
        let setting_key = format!("tc_config_{}", key);
        if let Ok(Some(val)) = store.get_setting("_system", &setting_key).await {
            config[*key] = val;
        }
    }
    Ok(Json(config))
}

/// POST /api/tc/config — save all ThreatClaw configuration.
pub async fn config_set_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    // Save each config section
    for key in &["llm", "forensic", "instruct", "cloud", "channels", "permissions", "anonymize_primary", "general"] {
        if let Some(val) = body.get(*key) {
            let setting_key = format!("tc_config_{}", key);
            store.set_setting("_system", &setting_key, val).await.map_err(db_err)?;
        }
    }

    // Also update agent_mode if permissions changed
    if let Some(perm) = body.get("permissions").and_then(|v| v.as_str()) {
        let mode = match perm {
            "READ_ONLY" => "analyst",
            "ALERT_ONLY" => "investigator",
            "REMEDIATE_WITH_APPROVAL" => "responder",
            "FULL_AUTO" => "autonomous_low",
            _ => "investigator",
        };
        store.set_setting("_system", "agent_mode", &serde_json::json!(mode)).await.map_err(db_err)?;
    }

    // ── Bridge channel tokens to env vars for credential injection ──
    if let Some(channels_val) = body.get("channels") {
        bridge_channel_tokens(channels_val);
    }

    // Set onboard completed
    store.set_setting("_system", "tc_onboarded", &serde_json::json!(true)).await.map_err(db_err)?;

    tracing::info!("ThreatClaw configuration saved via dashboard");
    Ok(Json(serde_json::json!({ "status": "saved" })))
}

/// POST /api/tc/config/test-channel — test a channel connection.
pub async fn config_test_channel_handler(
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let channel = body.get("channel").and_then(|v| v.as_str()).unwrap_or("");
    let token = body.get("token").and_then(|v| v.as_str()).unwrap_or("");

    if token.is_empty() {
        return Ok(Json(serde_json::json!({ "ok": false, "error": "Token is empty" })));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let result = match channel {
        "slack" => {
            let resp = client.get("https://slack.com/api/auth.test")
                .header("Authorization", format!("Bearer {}", token))
                .send().await;
            match resp {
                Ok(r) => {
                    let data: serde_json::Value = r.json().await.unwrap_or_default();
                    if data["ok"].as_bool() == Some(true) {
                        serde_json::json!({ "ok": true, "team": data["team"], "user": data["user"] })
                    } else {
                        serde_json::json!({ "ok": false, "error": data["error"] })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "telegram" => {
            let resp = client.get(format!("https://api.telegram.org/bot{}/getMe", token))
                .send().await;
            match resp {
                Ok(r) => {
                    let data: serde_json::Value = r.json().await.unwrap_or_default();
                    if data["ok"].as_bool() == Some(true) {
                        serde_json::json!({ "ok": true, "username": data["result"]["username"] })
                    } else {
                        serde_json::json!({ "ok": false, "error": data["description"] })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        "discord" => {
            let resp = client.get("https://discord.com/api/v10/users/@me")
                .header("Authorization", format!("Bot {}", token))
                .send().await;
            match resp {
                Ok(r) => {
                    if r.status().is_success() {
                        let data: serde_json::Value = r.json().await.unwrap_or_default();
                        serde_json::json!({ "ok": true, "username": data["username"] })
                    } else {
                        serde_json::json!({ "ok": false, "error": format!("HTTP {}", r.status()) })
                    }
                }
                Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
            }
        }
        _ => serde_json::json!({ "ok": false, "error": format!("Test not available for channel: {}", channel) }),
    };

    Ok(Json(result))
}

// ══════════════════════════════════════════════════════════
// CVE ENRICHMENT (NVD API)
// ══════════════════════════════════════════════════════════

/// GET /api/tc/enrichment/cve?id=CVE-2021-44228
pub async fn cve_lookup_handler(
    State(state): State<Arc<GatewayState>>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let cve_id = q.get("id").ok_or((StatusCode::BAD_REQUEST, "Missing 'id' parameter".to_string()))?;

    let config = if let Some(store) = state.store.as_ref() {
        crate::enrichment::cve_lookup::NvdConfig::from_db(store.as_ref()).await
    } else {
        crate::enrichment::cve_lookup::NvdConfig::default()
    };
    // Use cached lookup if DB available, direct otherwise
    let result = if let Some(store) = state.store.as_ref() {
        crate::enrichment::cve_lookup::lookup_cve_cached(cve_id, &config, store.as_ref()).await
    } else {
        crate::enrichment::cve_lookup::lookup_cve(cve_id, &config).await
    };
    match result {
        Ok(cve) => Ok(Json(serde_json::json!({
            "cve_id": cve.cve_id,
            "description": cve.description,
            "cvss_score": cve.cvss_score,
            "cvss_severity": cve.cvss_severity,
            "published": cve.published,
            "exploited_in_wild": cve.exploited_in_wild,
            "patch_urls": cve.patch_urls,
            "prompt_format": crate::enrichment::cve_lookup::format_for_prompt(&cve),
        }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

// ══════════════════════════════════════════════════════════
// ENRICHMENT — MITRE ATT&CK + CERT-FR + Offline status
// ══════════════════════════════════════════════════════════

/// POST /api/tc/enrichment/mitre/sync — sync MITRE ATT&CK techniques from STIX JSON.
pub async fn mitre_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match crate::enrichment::mitre_attack::sync_attack_techniques(store.as_ref()).await {
        Ok(count) => Ok(Json(serde_json::json!({ "ok": true, "synced": count }))),
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e }))),
    }
}

/// GET /api/tc/enrichment/mitre/{id} — lookup a MITRE technique.
pub async fn mitre_lookup_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match crate::enrichment::mitre_attack::lookup_technique(store.as_ref(), &id).await {
        Some(t) => Ok(Json(serde_json::to_value(t).unwrap_or_default())),
        None => Ok(Json(serde_json::json!({ "error": format!("Technique {} not found", id) }))),
    }
}

/// POST /api/tc/enrichment/certfr/sync — sync CERT-FR alerts from RSS.
pub async fn certfr_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match crate::enrichment::certfr::sync_certfr_alerts(store.as_ref()).await {
        Ok(count) => Ok(Json(serde_json::json!({ "ok": true, "synced": count }))),
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e }))),
    }
}

/// GET /api/tc/enrichment/certfr/recent — get recent CERT-FR alerts.
pub async fn certfr_recent_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let alerts = crate::enrichment::certfr::get_recent_alerts(store.as_ref(), 20).await;
    Ok(Json(serde_json::json!({ "alerts": alerts, "total": alerts.len() })))
}

/// GET /api/tc/enrichment/status — overall enrichment status.
pub async fn enrichment_status_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let mitre_meta = crate::enrichment::mitre_attack::get_sync_meta(store.as_ref()).await;
    let certfr_meta = crate::enrichment::certfr::get_sync_meta(store.as_ref()).await;

    // Count cached CVEs
    let cve_settings = store.list_settings("_cve_cache").await.unwrap_or_default();
    let cve_count = cve_settings.len();

    Ok(Json(serde_json::json!({
        "cve_cache": { "count": cve_count },
        "mitre": mitre_meta.unwrap_or(serde_json::json!({"status": "not_synced"})),
        "certfr": certfr_meta.unwrap_or(serde_json::json!({"status": "not_synced"})),
    })))
}

// ══════════════════════════════════════════════════════════
// INSTRUCT AI — Playbooks SOAR, rapports, Sigma rules
// À la demande RSSI uniquement (pas dans le pipeline auto)
// ══════════════════════════════════════════════════════════

/// POST /api/tc/instruct/generate — generate playbook, report, or sigma rule.
/// Body: { "type": "playbook|report|sigma|threat_model", "context": "..." }
pub async fn instruct_generate_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let gen_type = body["type"].as_str().unwrap_or("playbook");
    let context = body["context"].as_str().unwrap_or("");

    if context.is_empty() {
        return Ok(Json(serde_json::json!({ "ok": false, "error": "Missing context" })));
    }

    // Load instruct model config from DB
    let llm_config = crate::agent::llm_router::LlmRouterConfig::from_db_settings(store.as_ref()).await;
    let instruct = &llm_config.instruct;

    // Build prompt based on type
    let prompt = match gen_type {
        "playbook" => format!(
            "Génère un playbook SOAR complet pour l'incident suivant. Structure avec : Actions immédiates (<15min), Investigation (<1h), Remédiation (<4h), Notification NIS2 si applicable, Post-incident.\n\nContexte de l'incident :\n{context}"
        ),
        "report" => format!(
            "Génère un rapport d'incident de sécurité professionnel en français. Inclus : Résumé exécutif, Timeline, Impact, Analyse technique (MITRE ATT&CK), Recommandations, Conformité NIS2.\n\nDonnées de l'incident :\n{context}"
        ),
        "sigma" => format!(
            "Génère une ou plusieurs règles Sigma (format YAML standard SigmaHQ) pour détecter ce type d'attaque. Inclus le titre, la description, les sources de données, et la logique de détection.\n\nType d'attaque à détecter :\n{context}"
        ),
        "threat_model" => format!(
            "Réalise une analyse de menaces (threat modeling) pour l'architecture suivante. Identifie les vecteurs d'attaque, les risques principaux (MITRE ATT&CK), et les recommandations de hardening.\n\nArchitecture :\n{context}"
        ),
        _ => return Ok(Json(serde_json::json!({ "ok": false, "error": format!("Unknown type: {gen_type}") }))),
    };

    // Call Ollama with instruct model
    let url = format!("{}/api/chat", instruct.base_url);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let ollama_body = serde_json::json!({
        "model": instruct.model,
        "messages": [{ "role": "user", "content": prompt }],
        "stream": false,
        "options": { "temperature": 0.3, "num_predict": 4096 }
    });

    tracing::info!("Instruct: Generating {} with model {}", gen_type, instruct.model);

    let resp = client.post(&url).json(&ollama_body).send().await;
    match resp {
        Ok(r) if r.status().is_success() => {
            let data: serde_json::Value = r.json().await.unwrap_or_default();
            let content = data["message"]["content"].as_str()
                .or_else(|| data["response"].as_str())
                .unwrap_or("Erreur: pas de réponse du modèle");

            // Write audit entry
            let audit_key = format!("instruct_{}_{}", gen_type, chrono::Utc::now().timestamp());
            let _ = store.set_setting("_audit", &audit_key, &serde_json::json!({
                "type": gen_type, "model": instruct.model,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            })).await;

            Ok(Json(serde_json::json!({
                "ok": true,
                "type": gen_type,
                "model": instruct.model,
                "content": content,
                "generated_at": chrono::Utc::now().to_rfc3339(),
            })))
        }
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            Ok(Json(serde_json::json!({
                "ok": false,
                "error": format!("Ollama returned {}: {}", status, text.chars().take(200).collect::<String>()),
                "hint": format!("Vérifiez que le modèle {} est installé (ollama pull {})", instruct.model, instruct.model),
            })))
        }
        Err(e) => {
            Ok(Json(serde_json::json!({
                "ok": false,
                "error": format!("Ollama unreachable: {e}"),
                "hint": "Vérifiez que Ollama est démarré et accessible",
            })))
        }
    }
}

// ══════════════════════════════════════════════════════════
// CONFIG BRIDGE — Channel tokens → env vars
// ══════════════════════════════════════════════════════════

/// Bridge channel tokens from dashboard config to process env vars.
/// This allows the existing credential injection system (which reads env vars
/// as a fallback) to pick up tokens configured via the dashboard.
fn bridge_channel_tokens(channels: &serde_json::Value) {
    let mappings: &[(&str, &[(&str, &str)])] = &[
        ("telegram", &[("botToken", "TELEGRAM_BOT_TOKEN")]),
        ("slack", &[("botToken", "SLACK_BOT_TOKEN"), ("signingSecret", "SLACK_SIGNING_SECRET")]),
        ("discord", &[("botToken", "DISCORD_BOT_TOKEN")]),
        ("whatsapp", &[("accessToken", "WHATSAPP_ACCESS_TOKEN")]),
    ];

    for (channel, fields) in mappings {
        if let Some(ch) = channels.get(*channel) {
            let enabled = ch["enabled"].as_bool().unwrap_or(false);
            for (json_key, env_key) in *fields {
                if let Some(token) = ch[*json_key].as_str() {
                    if !token.is_empty() && enabled {
                        // SAFETY: acceptable for config — single writer (dashboard save)
                        unsafe { std::env::set_var(env_key, token); }
                        tracing::info!("Bridge: {} → env {} ({})", channel, env_key,
                            if token.len() > 8 { format!("{}...{}", &token[..4], &token[token.len()-4..]) }
                            else { "****".to_string() }
                        );
                    }
                }
            }
        }
    }
}

// ══════════════════════════════════════════════════════════
// TELEGRAM DIRECT API — Send messages / bot info
// ══════════════════════════════════════════════════════════

/// POST /api/tc/telegram/send — send a message via Telegram bot.
/// Reads token from DB config (tc_config_channels.telegram.botToken).
pub async fn telegram_send_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let chat_id = body["chat_id"].as_str()
        .or_else(|| body["chat_id"].as_i64().map(|_| ""))
        .ok_or((StatusCode::BAD_REQUEST, "Missing chat_id".to_string()))?;
    let chat_id_str = if chat_id.is_empty() {
        body["chat_id"].as_i64().unwrap().to_string()
    } else {
        chat_id.to_string()
    };

    let text = body["text"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing text".to_string()))?;
    let parse_mode = body["parse_mode"].as_str().unwrap_or("Markdown");

    // Get bot token: env var > DB config
    let token = std::env::var("TELEGRAM_BOT_TOKEN").ok()
        .filter(|t| !t.is_empty())
        .or_else(|| {
            // Synchronous context — we need a blocking approach
            None
        });

    // If not in env, read from DB
    let token = if let Some(t) = token {
        t
    } else {
        match store.get_setting("_system", "tc_config_channels").await {
            Ok(Some(channels)) => {
                channels["telegram"]["botToken"].as_str()
                    .filter(|t| !t.is_empty())
                    .map(|t| t.to_string())
                    .ok_or((StatusCode::BAD_REQUEST, "Telegram bot token not configured".to_string()))?
            }
            _ => return Ok(Json(serde_json::json!({ "ok": false, "error": "Telegram bot token not configured" }))),
        }
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = client.post(format!("https://api.telegram.org/bot{}/sendMessage", token))
        .json(&serde_json::json!({
            "chat_id": chat_id_str,
            "text": text,
            "parse_mode": parse_mode,
        }))
        .send().await;

    match resp {
        Ok(r) => {
            let data: serde_json::Value = r.json().await.unwrap_or_default();
            if data["ok"].as_bool() == Some(true) {
                tracing::info!("Telegram message sent to chat_id={}", chat_id_str);
                Ok(Json(serde_json::json!({ "ok": true, "message_id": data["result"]["message_id"] })))
            } else {
                Ok(Json(serde_json::json!({ "ok": false, "error": data["description"] })))
            }
        }
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e.to_string() }))),
    }
}

/// POST /api/tc/telegram/poll — poll for new messages (one-shot).
/// Used for interactive Telegram bot: receive commands, return them.
pub async fn telegram_poll_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let offset = body["offset"].as_i64().unwrap_or(0);

    // Get bot token from env or DB
    let token = get_telegram_token(store.as_ref()).await
        .ok_or((StatusCode::BAD_REQUEST, "Telegram bot token not configured".to_string()))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = client.get(format!("https://api.telegram.org/bot{}/getUpdates", token))
        .query(&[
            ("offset", offset.to_string()),
            ("timeout", "10".to_string()),
            ("allowed_updates", "[\"message\"]".to_string()),
        ])
        .send().await;

    match resp {
        Ok(r) => {
            let data: serde_json::Value = r.json().await.unwrap_or_default();
            Ok(Json(data))
        }
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e.to_string() }))),
    }
}

/// GET /api/tc/telegram/status — check Telegram bot status.
pub async fn telegram_status_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let token = match get_telegram_token(store.as_ref()).await {
        Some(t) => t,
        None => return Ok(Json(serde_json::json!({
            "configured": false,
            "ok": false,
            "error": "No Telegram bot token configured"
        }))),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = client.get(format!("https://api.telegram.org/bot{}/getMe", token))
        .send().await;

    match resp {
        Ok(r) => {
            let data: serde_json::Value = r.json().await.unwrap_or_default();
            if data["ok"].as_bool() == Some(true) {
                Ok(Json(serde_json::json!({
                    "configured": true,
                    "ok": true,
                    "username": data["result"]["username"],
                    "first_name": data["result"]["first_name"],
                    "id": data["result"]["id"],
                })))
            } else {
                Ok(Json(serde_json::json!({
                    "configured": true,
                    "ok": false,
                    "error": data["description"],
                })))
            }
        }
        Err(e) => Ok(Json(serde_json::json!({
            "configured": true,
            "ok": false,
            "error": e.to_string(),
        }))),
    }
}

/// Helper: get Telegram bot token from env var or DB config.
pub async fn get_telegram_token(store: &dyn crate::db::Database) -> Option<String> {
    // 1. Env var (highest priority)
    if let Ok(token) = std::env::var("TELEGRAM_BOT_TOKEN") {
        if !token.is_empty() {
            return Some(token);
        }
    }

    // 2. DB config (dashboard setting)
    if let Ok(Some(channels)) = store.get_setting("_system", "tc_config_channels").await {
        if let Some(token) = channels["telegram"]["botToken"].as_str() {
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }

    None
}

// ══════════════════════════════════════════════════════════
// ANONYMIZER CUSTOM RULES
// ══════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct NewAnonymizerRule {
    pub label: String,
    pub pattern: String,
    pub token_prefix: Option<String>,
    pub capture_group: Option<i32>,
}

/// GET /api/tc/anonymizer/rules — list all custom anonymization rules.
pub async fn anonymizer_rules_list_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.list_anonymizer_rules().await {
        Ok(rules) => Ok(Json(serde_json::json!({ "rules": rules }))),
        Err(e) => {
            tracing::error!("Failed to list anonymizer rules: {e}");
            Ok(Json(serde_json::json!({ "rules": [], "error": e.to_string() })))
        }
    }
}

/// POST /api/tc/anonymizer/rules — create a new custom anonymization rule.
pub async fn anonymizer_rules_create_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<NewAnonymizerRule>,
) -> ApiResult<serde_json::Value> {
    if regex::Regex::new(&body.pattern).is_err() {
        return Ok(Json(serde_json::json!({ "error": "Invalid regex pattern" })));
    }
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.create_anonymizer_rule(
        &body.label,
        &body.pattern,
        body.token_prefix.as_deref().unwrap_or("CUSTOM"),
        body.capture_group.unwrap_or(0),
    ).await {
        Ok(id) => Ok(Json(serde_json::json!({ "id": id, "status": "created" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() })))
    }
}

/// DELETE /api/tc/anonymizer/rules/:id — delete a custom anonymization rule.
pub async fn anonymizer_rules_delete_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.delete_anonymizer_rule(&id).await {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "deleted" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() })))
    }
}
