//! ThreatClaw-specific API handlers for findings, alerts, config, and metrics.
//!
//! ## File organization (search for ══ or ── to jump to sections)
//!
//! 1. DTOs + shared types
//! 2. Health + Auto-start services
//! 3. Findings CRUD
//! 4. Alerts CRUD
//! 5. Skill Config
//! 6. Dashboard Metrics + Agent Mode + Kill Switch
//! 7. Audit Log + ReAct Cycle
//! 8. Targets / Infrastructure + Skills Catalog
//! 9. Configuration (LLM, channels, permissions, anonymizer)
//! 10. CVE Enrichment (NVD API)
//! 11. MITRE ATT&CK + CERT-FR enrichment
//! 12. Instruct AI (Playbooks, reports, Sigma rules)
//! 13. Config Bridge + Telegram Direct API
//! 14. SSH Remote Execution
//! 15. Graph Intelligence (Apache AGE) + Graph Phase 3-5
//! 16. Enrichment (Shodan, VirusTotal, HIBP)
//! 17. Cloud Intent + License
//! 18. Unified Skill Catalog + Connectors (AD, pfSense)
//! 19. Remediation Actions (HITL)
//! 20. Asset Resolution + Behavioral Analysis
//! 21. Skill Scheduler + Test Scenarios
//! 22. Enrichment Sources (CISA KEV, GreyNoise, ThreatFox)
//! 23. Intelligence Engine + Notification Routing
//! 24. HITL Callback + Conversational Bot
//! 25. Anonymizer Custom Rules + Webhook Ingest
//! 26. Enrichment Web Security (Tier 1) — SafeBrowsing, SSL Labs, etc.
//! 27. Connectors Web Security (Tier 2) — Cloudflare
//! 28. Assets Management (v1.6)
//! 29. Internal Networks + Company Profile
//! 30. v1.7+ Connectors (Pi-hole, UniFi, DHCP, MAC OUI)
//! 31. v1.8 Zeek + Suricata + v1.9 NACE Threat Profiles

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{StatusCode, HeaderMap},
    response::{IntoResponse, Response},
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
    pub page: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedFindingsResponse {
    pub findings: Vec<FindingRecord>,
    pub total: i64,
    pub page: i64,
    pub pages: i64,
    pub has_more: bool,
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
    pub page: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedAlertsResponse {
    pub alerts: Vec<AlertRecord>,
    pub total: i64,
    pub page: i64,
    pub pages: i64,
    pub has_more: bool,
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
    pub disk_free: Option<String>,
    pub ml: Option<serde_json::Value>,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, String)>;

fn db_err(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn no_db() -> (StatusCode, String) {
    (StatusCode::SERVICE_UNAVAILABLE, "Database not available".to_string())
}

// ── Health + Auto-start services ──

static SERVICES_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub async fn tc_health_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<HealthResponse> {
    let db_ok = state.store.is_some();

    // Auto-start Intelligence Engine + Bot on first health check
    // This runs once after the gateway is fully ready.
    if db_ok && !SERVICES_STARTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        if let Some(store) = state.store.as_ref() {
            let store_clone = store.clone();
            let nonce_mgr = Arc::clone(&state.hitl_nonce_manager);
            tokio::spawn(async move {
                // Wait a bit for all channels to initialize
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                // Start Intelligence Engine (cycle every 5 min)
                if !INTELLIGENCE_RUNNING.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    crate::agent::intelligence_engine::spawn_intelligence_ticker(
                        store_clone.clone(),
                        std::time::Duration::from_secs(300),
                        Some(nonce_mgr.clone()),
                    );
                    tracing::info!("AUTO-START: Intelligence Engine started (cycle every 5min)");
                }

                // Start Connector Sync Scheduler
                static SCHEDULER_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                if !SCHEDULER_RUNNING.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    crate::connectors::sync_scheduler::spawn_sync_scheduler(store_clone.clone());
                    tracing::info!("AUTO-START: Connector Sync Scheduler started");
                }

                // Start Telegram Bot (if configured)
                if !BOT_RUNNING.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    // Check if Telegram is configured
                    if let Ok(Some(channels)) = store_clone.get_setting("_system", "tc_config_channels").await {
                        if channels["telegram"]["enabled"].as_bool() == Some(true)
                            && channels["telegram"]["botToken"].as_str().map(|t| !t.is_empty()) == Some(true)
                        {
                            crate::agent::conversational_bot::spawn_telegram_bot(
                                store_clone.clone(),
                                std::time::Duration::from_secs(1),
                            );
                            tracing::info!("AUTO-START: Telegram bot started (poll every 3s)");
                        } else {
                            BOT_RUNNING.store(false, std::sync::atomic::Ordering::Relaxed);
                            tracing::debug!("AUTO-START: Telegram bot skipped (not configured)");
                        }
                    }
                }
            });
        }
    }

    // Get ML engine status from heartbeat
    let ml = if db_ok {
        if let Some(store) = state.store.as_ref() {
            store.get_setting("_system", "ml_heartbeat").await.ok().flatten()
        } else { None }
    } else { None };

    // Get real disk space
    let disk_free = {
        let output = std::process::Command::new("df")
            .args(["-h", "--output=avail", "/srv"])
            .output();
        match output {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout);
                s.lines().nth(1).map(|l| format!("{} libre", l.trim()))
            }
            Err(_) => None,
        }
    };

    Ok(Json(HealthResponse {
        status: if db_ok { "ok" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
        database: db_ok,
        llm: "ollama",
        disk_free,
        ml,
    }))
}

// ── Findings ──

pub async fn findings_list_handler(
    State(state): State<Arc<GatewayState>>,
    Query(q): Query<FindingsQuery>,
) -> ApiResult<PaginatedFindingsResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let limit = q.limit.unwrap_or(50);
    let page = q.page.unwrap_or(1).max(1);
    let offset = (page - 1) * limit;
    let total = store
        .count_findings_filtered(q.severity.as_deref(), q.status.as_deref(), q.skill_id.as_deref())
        .await
        .map_err(db_err)?;
    let findings = store
        .list_findings(
            q.severity.as_deref(),
            q.status.as_deref(),
            q.skill_id.as_deref(),
            limit,
            offset,
        )
        .await
        .map_err(db_err)?;
    let pages = (total + limit - 1) / limit;
    Ok(Json(PaginatedFindingsResponse {
        findings,
        total,
        page,
        pages,
        has_more: page < pages,
    }))
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
) -> ApiResult<PaginatedAlertsResponse> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let limit = q.limit.unwrap_or(50);
    let page = q.page.unwrap_or(1).max(1);
    let offset = (page - 1) * limit;
    let total = store
        .count_alerts_filtered(q.level.as_deref(), q.status.as_deref())
        .await
        .map_err(db_err)?;
    let alerts = store
        .list_alerts(q.level.as_deref(), q.status.as_deref(), limit, offset)
        .await
        .map_err(db_err)?;
    let pages = (total + limit - 1) / limit;
    Ok(Json(PaginatedAlertsResponse {
        alerts,
        total,
        page,
        pages,
        has_more: page < pages,
    }))
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
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let paused = store.get_setting("_system", "tc_paused").await
        .ok().flatten()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Ok(Json(serde_json::json!({
        "paused": paused,
        "active": !paused,
    })))
}

/// POST /api/tc/pause — toggle pause/resume all services.
pub async fn pause_toggle_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let currently_paused = store.get_setting("_system", "tc_paused").await
        .ok().flatten()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let new_state = !currently_paused;
    store.set_setting("_system", "tc_paused", &serde_json::json!(new_state)).await.map_err(db_err)?;

    if new_state {
        tracing::warn!("PAUSE: All services paused by dashboard user");
        // Stop the Telegram bot
        BOT_RUNNING.store(false, std::sync::atomic::Ordering::Relaxed);
    } else {
        tracing::info!("RESUME: All services resumed by dashboard user");
        // Restart the Telegram bot
        if !BOT_RUNNING.swap(true, std::sync::atomic::Ordering::Relaxed) {
            if let Ok(Some(channels)) = store.get_setting("_system", "tc_config_channels").await {
                if channels["telegram"]["enabled"].as_bool() == Some(true)
                    && channels["telegram"]["botToken"].as_str().map(|t| !t.is_empty()) == Some(true)
                {
                    crate::agent::conversational_bot::spawn_telegram_bot(
                        store.clone(),
                        std::time::Duration::from_secs(1),
                    );
                    tracing::info!("RESUME: Telegram bot restarted");
                } else {
                    BOT_RUNNING.store(false, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    Ok(Json(serde_json::json!({
        "paused": new_state,
        "message": if new_state { "Services en pause" } else { "Services repris" },
    })))
}

#[derive(Debug, Deserialize)]
pub struct KillSwitchTriggerRequest {
    pub triggered_by: String,
}

pub async fn kill_switch_trigger_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<KillSwitchTriggerRequest>,
) -> ApiResult<serde_json::Value> {
    tracing::error!("KILL SWITCH triggered via API by: {}", req.triggered_by);
    let store = state.store.as_ref().ok_or_else(no_db)?;
    store.set_setting("_system", "tc_paused", &serde_json::json!(true)).await.map_err(db_err)?;
    BOT_RUNNING.store(false, std::sync::atomic::Ordering::Relaxed);
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
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<HitlCallbackRequest>,
) -> ApiResult<serde_json::Value> {
    // Use the shared NonceManager from GatewayState
    let nonce_mgr = &state.hitl_nonce_manager;

    let result = crate::agent::hitl_bridge::process_slack_callback(
        &req.nonce,
        req.approved,
        &req.approved_by,
        nonce_mgr,
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
    for key in &["llm", "forensic", "instruct", "cloud", "conversational", "channels", "permissions", "anonymize_primary", "general", "enrichment_enabled", "enrichment_keys"] {
        let setting_key = format!("tc_config_{}", key);
        if let Ok(Some(val)) = store.get_setting("_system", &setting_key).await {
            config[*key] = val;
        }
    }

    // Add model catalog and RAM estimates for the dashboard
    let catalog = crate::agent::llm_router::model_catalog();
    let mut catalog_json = serde_json::json!({});
    for (level, models) in &catalog {
        catalog_json[*level] = serde_json::json!(models);
    }
    config["model_catalog"] = catalog_json;

    Ok(Json(config))
}

/// POST /api/tc/config — save all ThreatClaw configuration.
pub async fn config_set_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    // ADR-044: Save remediation / HITL config
    for rkey in &["tc_protected_assets", "tc_hitl_approvers", "tc_hitl_approvers_config", "tc_hitl_limits"] {
        if let Some(val) = body.get(*rkey) {
            store.set_setting("_system", rkey, val).await.map_err(db_err)?;
        }
    }

    // Save each config section
    for key in &["llm", "forensic", "instruct", "cloud", "conversational", "channels", "permissions", "anonymize_primary", "general", "enrichment_enabled", "enrichment_keys"] {
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
        "mattermost" => {
            // Test Mattermost webhook by sending a test message
            let webhook = body.get("webhookUrl").and_then(|v| v.as_str()).unwrap_or(token);
            match crate::integrations::mattermost_hitl::test_connection(webhook).await {
                Ok(msg) => serde_json::json!({ "ok": true, "detail": msg }),
                Err(e) => serde_json::json!({ "ok": false, "error": e }),
            }
        }
        "ntfy" => {
            let server = body.get("server").and_then(|v| v.as_str()).unwrap_or("https://ntfy.sh");
            let topic = body.get("topic").and_then(|v| v.as_str()).unwrap_or(token);
            let auth = body.get("authToken").and_then(|v| v.as_str());
            match crate::integrations::ntfy_hitl::test_connection(server, topic, auth).await {
                Ok(msg) => serde_json::json!({ "ok": true, "detail": msg }),
                Err(e) => serde_json::json!({ "ok": false, "error": e }),
            }
        }
        "gotify" => {
            let url = body.get("url").and_then(|v| v.as_str()).unwrap_or("");
            match crate::integrations::gotify_notify::test_connection(url, token).await {
                Ok(msg) => serde_json::json!({ "ok": true, "detail": msg }),
                Err(e) => serde_json::json!({ "ok": false, "error": e }),
            }
        }
        "olvid" => {
            let daemon_url = body.get("daemonUrl").and_then(|v| v.as_str()).unwrap_or("http://localhost:50051");
            let client_key = body.get("clientKey").and_then(|v| v.as_str()).unwrap_or(token);
            match crate::connectors::olvid::test_connection(daemon_url, client_key).await {
                Ok(detail) => serde_json::json!({ "ok": true, "detail": detail }),
                Err(e) => serde_json::json!({ "ok": false, "error": e }),
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

    // KEV
    let kev_meta = store.get_setting("_system", "kev_sync_meta").await.ok().flatten();
    // OpenPhish
    let openphish_meta = store.get_setting("_enrichment", "openphish_urls").await.ok().flatten();

    Ok(Json(serde_json::json!({
        "nvd": { "cache_count": cve_count, "status": "active" },
        "cisa_kev": kev_meta.map(|m| serde_json::json!({"status": "synced", "meta": m})).unwrap_or(serde_json::json!({"status": "not_synced"})),
        "mitre": mitre_meta.map(|m| serde_json::json!({"status": "synced", "meta": m})).unwrap_or(serde_json::json!({"status": "not_synced"})),
        "certfr": certfr_meta.map(|m| serde_json::json!({"status": "synced", "meta": m})).unwrap_or(serde_json::json!({"status": "not_synced"})),
        "openphish": openphish_meta.map(|m| serde_json::json!({"status": "synced", "count": m["count"], "synced_at": m["synced_at"]})).unwrap_or(serde_json::json!({"status": "not_synced"})),
        "greynoise": { "status": "active", "type": "on_demand" },
        "threatfox": { "status": "active", "type": "on_demand" },
        "malware_bazaar": { "status": "active", "type": "on_demand" },
        "urlhaus": { "status": "active", "type": "on_demand" },
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
        ("olvid", &[("clientKey", "OLVID_CLIENT_KEY"), ("daemonUrl", "OLVID_DAEMON_URL")]),
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
// OLVID (ANSSI-certified messenger) — See ADR-044
// ══════════════════════════════════════════════════════════

pub async fn olvid_send_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let text = body["text"].as_str().unwrap_or("").to_string();
    if text.is_empty() {
        return Ok(Json(serde_json::json!({ "ok": false, "error": "Missing text" })));
    }

    let channels = store.get_setting("_system", "tc_config_channels").await
        .ok().flatten().unwrap_or_default();
    let daemon_url = channels["olvid"]["daemonUrl"].as_str().unwrap_or("http://localhost:50051");
    let client_key = channels["olvid"]["clientKey"].as_str().unwrap_or("");
    let discussion_id = body["discussion_id"].as_str()
        .or_else(|| channels["olvid"]["discussionId"].as_str())
        .unwrap_or("");

    if client_key.is_empty() || discussion_id.is_empty() {
        return Ok(Json(serde_json::json!({ "ok": false, "error": "Olvid not configured (clientKey or discussionId missing)" })));
    }

    match crate::connectors::olvid::send_message(daemon_url, client_key, discussion_id, &text).await {
        Ok(()) => Ok(Json(serde_json::json!({ "ok": true }))),
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e }))),
    }
}

pub async fn olvid_status_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let channels = store.get_setting("_system", "tc_config_channels").await
        .ok().flatten().unwrap_or_default();
    let daemon_url = channels["olvid"]["daemonUrl"].as_str().unwrap_or("");
    let client_key = channels["olvid"]["clientKey"].as_str().unwrap_or("");

    if daemon_url.is_empty() || client_key.is_empty() {
        return Ok(Json(serde_json::json!({ "configured": false, "ok": false, "error": "Olvid not configured" })));
    }

    match crate::connectors::olvid::test_connection(daemon_url, client_key).await {
        Ok(detail) => Ok(Json(serde_json::json!({ "configured": true, "ok": true, "detail": detail }))),
        Err(e) => Ok(Json(serde_json::json!({ "configured": true, "ok": false, "error": e }))),
    }
}

pub async fn olvid_discussions_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let channels = store.get_setting("_system", "tc_config_channels").await
        .ok().flatten().unwrap_or_default();
    let daemon_url = channels["olvid"]["daemonUrl"].as_str().unwrap_or("");
    let client_key = channels["olvid"]["clientKey"].as_str().unwrap_or("");

    if daemon_url.is_empty() || client_key.is_empty() {
        return Ok(Json(serde_json::json!({ "ok": false, "error": "Olvid not configured" })));
    }

    match crate::connectors::olvid::list_discussions(daemon_url, client_key).await {
        Ok(discussions) => {
            let list: Vec<serde_json::Value> = discussions.iter()
                .map(|(id, title)| serde_json::json!({ "id": id, "title": title }))
                .collect();
            Ok(Json(serde_json::json!({ "ok": true, "discussions": list })))
        }
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e }))),
    }
}

// ══════════════════════════════════════════════════════════
// SSH REMOTE EXECUTION + TARGET LOOKUP + BINARY VERIFY
// ══════════════════════════════════════════════════════════

/// POST /api/tc/ssh/execute — execute a whitelisted command on a remote target via SSH.
pub async fn ssh_execute_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let target_ref = body["target"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing target".to_string()))?;
    let cmd_id = body["cmd_id"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing cmd_id".to_string()))?;

    let params: std::collections::HashMap<String, String> = body["params"]
        .as_object()
        .map(|obj| obj.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
        .unwrap_or_default();

    // Validate command via whitelist
    let validated = match crate::agent::remediation_whitelist::validate_remediation(cmd_id, &params) {
        Ok(v) => v,
        Err(e) => return Ok(Json(serde_json::json!({ "ok": false, "error": format!("Validation failed: {e}") }))),
    };

    // Resolve target and execute
    match crate::agent::executor_ssh::execute_on_target(store.as_ref(), target_ref, &validated).await {
        Ok(result) => {
            // Audit log
            let audit_key = format!("ssh_exec_{}_{}", cmd_id, chrono::Utc::now().timestamp());
            let _ = store.set_setting("_audit", &audit_key, &serde_json::json!({
                "target": target_ref, "cmd_id": cmd_id, "success": result.success,
                "exit_code": result.exit_code, "timestamp": chrono::Utc::now().to_rfc3339(),
            })).await;

            Ok(Json(serde_json::json!({
                "ok": true,
                "success": result.success,
                "exit_code": result.exit_code,
                "stdout": result.stdout.chars().take(2000).collect::<String>(),
                "stderr": result.stderr.chars().take(500).collect::<String>(),
                "rendered_cmd": result.rendered_cmd,
            })))
        }
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e.to_string() }))),
    }
}

/// GET /api/tc/targets/resolve/{ref} — resolve a target by ID or hostname.
pub async fn target_resolve_handler(
    State(state): State<Arc<GatewayState>>,
    Path(target_ref): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    match crate::agent::executor_ssh::resolve_target(store.as_ref(), &target_ref).await {
        Ok(target) => Ok(Json(serde_json::json!({
            "ok": true,
            "target_id": target.target_id,
            "host": target.host,
            "port": target.port,
            "username": target.username,
        }))),
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e.to_string() }))),
    }
}

/// GET /api/tc/security/verify-binary — verify binary integrity.
pub async fn binary_verify_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let result = crate::agent::binary_verify::verify_binary(store.as_ref()).await;
    Ok(Json(serde_json::to_value(result).unwrap_or_default()))
}

// ══════════════════════════════════════════════════════════
// GRAPH INTELLIGENCE (Apache AGE)
// ══════════════════════════════════════════════════════════

/// POST /api/tc/graph/query — execute a Cypher query on the threat graph.
pub async fn graph_query_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let cypher = body["cypher"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing cypher query".to_string()))?;

    let results = crate::graph::threat_graph::query(store.as_ref(), cypher).await;
    Ok(Json(serde_json::json!({ "results": results, "count": results.len() })))
}

/// GET /api/tc/graph/context/{asset_id} — get full investigation context for an asset.
pub async fn graph_context_handler(
    State(state): State<Arc<GatewayState>>,
    Path(asset_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let context = crate::graph::threat_graph::build_investigation_context(store.as_ref(), &asset_id).await;
    Ok(Json(context))
}

/// GET /api/tc/graph/attackers/{asset_id} — find all IPs attacking an asset.
pub async fn graph_attackers_handler(
    State(state): State<Arc<GatewayState>>,
    Path(asset_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let attackers = crate::graph::threat_graph::find_attackers(store.as_ref(), &asset_id).await;
    Ok(Json(serde_json::json!({ "attackers": attackers })))
}

/// GET /api/tc/graph/investigations — list all investigation graph templates.
pub async fn graph_investigations_handler() -> ApiResult<serde_json::Value> {
    let graphs = crate::graph::investigation::get_investigation_graphs();
    Ok(Json(serde_json::json!({ "investigations": graphs, "count": graphs.len() })))
}

// ══════════════════════════════════════════════════════════
// GRAPH PHASE 3 — Confidence, Lateral Movement, Notes
// ══════════════════════════════════════════════════════════

/// GET /api/tc/graph/confidence/{ip} — compute confidence score for an IP.
pub async fn graph_confidence_ip_handler(
    State(state): State<Arc<GatewayState>>,
    Path(ip): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let asset = params.get("asset").map(|s| s.as_str());
    let hour = params.get("hour").and_then(|h| h.parse::<u32>().ok());
    let score = crate::graph::confidence::compute_ip_confidence(store.as_ref(), &ip, asset, hour).await;
    Ok(Json(serde_json::json!(score)))
}

/// GET /api/tc/graph/confidence/cve/{cve_id} — compute confidence for a CVE.
pub async fn graph_confidence_cve_handler(
    State(state): State<Arc<GatewayState>>,
    Path(cve_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let asset = params.get("asset").map(|s| s.as_str());
    let score = crate::graph::confidence::compute_cve_confidence(store.as_ref(), &cve_id, asset).await;
    Ok(Json(serde_json::json!(score)))
}

/// GET /api/tc/graph/lateral — run lateral movement detection.
pub async fn graph_lateral_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let analysis = crate::graph::lateral::detect_lateral_movement(store.as_ref()).await;
    Ok(Json(serde_json::json!(analysis)))
}

/// POST /api/tc/graph/notes — create a note on graph objects.
pub async fn graph_notes_create_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let content = body["content"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing content".to_string()))?;
    let object_refs: Vec<&str> = body["object_refs"].as_array()
        .ok_or((StatusCode::BAD_REQUEST, "Missing object_refs array".to_string()))?
        .iter().filter_map(|v| v.as_str()).collect();
    let author = body["author"].as_str();
    let confidence = body["confidence"].as_u64().map(|c| c.min(100) as u8);

    let note = crate::graph::notes::create_note(store.as_ref(), content, &object_refs, author, confidence).await;
    Ok(Json(serde_json::json!(note)))
}

/// GET /api/tc/graph/notes — list all notes.
pub async fn graph_notes_list_handler(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let limit = params.get("limit").and_then(|l| l.parse::<u64>().ok()).unwrap_or(50);
    let notes = crate::graph::notes::list_notes(store.as_ref(), limit).await;
    Ok(Json(serde_json::json!({ "notes": notes, "count": notes.len() })))
}

/// GET /api/tc/graph/notes/ip/{ip} — notes for a specific IP.
pub async fn graph_notes_ip_handler(
    State(state): State<Arc<GatewayState>>,
    Path(ip): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let notes = crate::graph::notes::find_notes_for_ip(store.as_ref(), &ip).await;
    Ok(Json(serde_json::json!({ "notes": notes })))
}

/// GET /api/tc/graph/notes/asset/{asset_id} — notes for a specific asset.
pub async fn graph_notes_asset_handler(
    State(state): State<Arc<GatewayState>>,
    Path(asset_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let notes = crate::graph::notes::find_notes_for_asset(store.as_ref(), &asset_id).await;
    Ok(Json(serde_json::json!({ "notes": notes })))
}

/// DELETE /api/tc/graph/notes/{note_id} — delete a note.
pub async fn graph_notes_delete_handler(
    State(state): State<Arc<GatewayState>>,
    Path(note_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let deleted = crate::graph::notes::delete_note(store.as_ref(), &note_id).await;
    Ok(Json(serde_json::json!({ "deleted": deleted, "note_id": note_id })))
}

// ══════════════════════════════════════════════════════════
// GRAPH PHASE 4-5 — Campaign, Identity, Blast Radius, Attack Path, Supply Chain, Threat Actor
// ══════════════════════════════════════════════════════════

/// GET /api/tc/graph/campaigns — detect coordinated attack campaigns.
pub async fn graph_campaigns_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let analysis = crate::graph::campaign::detect_campaigns(store.as_ref()).await;
    Ok(Json(serde_json::json!(analysis)))
}

/// GET /api/tc/graph/identity — detect identity anomalies (UBA).
pub async fn graph_identity_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let analysis = crate::graph::identity_graph::detect_identity_anomalies(store.as_ref()).await;
    Ok(Json(serde_json::json!(analysis)))
}

/// GET /api/tc/graph/blast-radius/{asset_id} — compute blast radius.
pub async fn graph_blast_radius_handler(
    State(state): State<Arc<GatewayState>>,
    Path(asset_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let br = crate::graph::blast_radius::compute_blast_radius(store.as_ref(), &asset_id).await;
    Ok(Json(serde_json::json!(br)))
}

/// GET /api/tc/graph/attack-paths — predict attack paths.
pub async fn graph_attack_paths_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let analysis = crate::graph::attack_path::predict_attack_paths(store.as_ref()).await;
    Ok(Json(serde_json::json!(analysis)))
}

/// GET /api/tc/graph/supply-chain — analyze supply chain risk.
pub async fn graph_supply_chain_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let analysis = crate::graph::supply_chain::analyze_supply_chain(store.as_ref()).await;
    Ok(Json(serde_json::json!(analysis)))
}

/// GET /api/tc/graph/supply-chain/nis2 — NIS2 Article 21 supply chain report.
pub async fn graph_nis2_report_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let report = crate::graph::supply_chain::generate_nis2_report(store.as_ref()).await;
    Ok(Json(report))
}

/// GET /api/tc/graph/threat-actors — profile threat actors.
pub async fn graph_threat_actors_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let analysis = crate::graph::threat_actor::profile_threat_actors(store.as_ref()).await;
    Ok(Json(serde_json::json!(analysis)))
}

/// POST /api/tc/graph/coa/seed — seed default MITRE mitigations as CoA nodes.
pub async fn graph_coa_seed_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    crate::graph::course_of_action::seed_default_mitigations(store.as_ref()).await;
    Ok(Json(serde_json::json!({ "seeded": true })))
}

/// GET /api/tc/graph/coa/cve/{cve_id} — find CoAs for a CVE.
pub async fn graph_coa_cve_handler(
    State(state): State<Arc<GatewayState>>,
    Path(cve_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let coas = crate::graph::course_of_action::find_coa_for_cve(store.as_ref(), &cve_id).await;
    Ok(Json(serde_json::json!({ "courses_of_action": coas })))
}

/// GET /api/tc/graph/coa/asset/{asset_id} — find CoAs for an asset.
pub async fn graph_coa_asset_handler(
    State(state): State<Arc<GatewayState>>,
    Path(asset_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let coas = crate::graph::course_of_action::find_coa_for_asset(store.as_ref(), &asset_id).await;
    Ok(Json(serde_json::json!({ "courses_of_action": coas })))
}

// ══════════════════════════════════════════════════════════
// ENRICHMENT — Shodan, VirusTotal, HIBP
// ══════════════════════════════════════════════════════════

/// GET /api/tc/enrichment/shodan/{ip} — Shodan IP lookup.
pub async fn enrichment_shodan_handler(
    State(state): State<Arc<GatewayState>>,
    Path(ip): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok())
        .or_else(|| params.get("api_key").map(|s| s.as_str()))
        .unwrap_or("");
    match crate::enrichment::shodan_lookup::lookup_ip(&ip, api_key).await {
        Ok(result) => Ok(Json(serde_json::json!(result))),
        Err(e) => Ok(Json(serde_json::json!({"error": e}))),
    }
}

/// GET /api/tc/enrichment/virustotal/ip/{ip} — VirusTotal IP lookup.
pub async fn enrichment_vt_ip_handler(
    State(state): State<Arc<GatewayState>>,
    Path(ip): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok())
        .or_else(|| params.get("api_key").map(|s| s.as_str()))
        .unwrap_or("");
    match crate::enrichment::virustotal_lookup::lookup_ip(&ip, api_key).await {
        Ok(result) => Ok(Json(serde_json::json!(result))),
        Err(e) => Ok(Json(serde_json::json!({"error": e}))),
    }
}

/// GET /api/tc/enrichment/virustotal/hash/{hash} — VirusTotal file hash lookup.
pub async fn enrichment_vt_hash_handler(
    State(state): State<Arc<GatewayState>>,
    Path(hash): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok())
        .or_else(|| params.get("api_key").map(|s| s.as_str()))
        .unwrap_or("");
    match crate::enrichment::virustotal_lookup::lookup_hash(&hash, api_key).await {
        Ok(result) => Ok(Json(serde_json::json!(result))),
        Err(e) => Ok(Json(serde_json::json!({"error": e}))),
    }
}

/// GET /api/tc/enrichment/hibp/{email} — Have I Been Pwned email check.
pub async fn enrichment_hibp_handler(
    State(state): State<Arc<GatewayState>>,
    Path(email): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok())
        .or_else(|| params.get("api_key").map(|s| s.as_str()))
        .unwrap_or("");
    match crate::enrichment::hibp_lookup::check_email(&email, api_key).await {
        Ok(result) => Ok(Json(serde_json::json!(result))),
        Err(e) => Ok(Json(serde_json::json!({"error": e}))),
    }
}

// ══════════════════════════════════════════════════════════
// CLOUD INTENT (natural language command)
// ══════════════════════════════════════════════════════════

/// POST /api/tc/command/intent — parse and execute a natural language command.
pub async fn command_intent_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let message = body["message"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing message".to_string()))?;

    // Get conversation mode from request or DB
    let mode = match body["mode"].as_str() {
        Some("cloud_assisted") => crate::agent::conversation_mode::ConversationMode::CloudAssisted,
        Some("cloud_direct") => crate::agent::conversation_mode::ConversationMode::CloudDirect,
        Some("local") => crate::agent::conversation_mode::ConversationMode::Local,
        _ => crate::agent::conversation_mode::get_mode(store.as_ref()).await,
    };

    let intent = crate::agent::cloud_intent::parse_intent(message, &mode.to_string()).await;
    let result = crate::agent::conversation_mode::process_message(store.as_ref(), message, mode).await;

    Ok(Json(serde_json::json!({
        "intent": intent,
        "result": result,
        "mode": mode.to_string(),
    })))
}

/// GET /api/tc/conversation/mode — get current conversation mode.
pub async fn conversation_mode_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let mode = crate::agent::conversation_mode::get_mode(store.as_ref()).await;
    Ok(Json(serde_json::json!({ "mode": mode.to_string() })))
}

// ══════════════════════════════════════════════════════════
// INSTANCE IDENTITY
// ══════════════════════════════════════════════════════════

/// GET /api/tc/license — get instance identity + asset count (no limits).
pub async fn license_status_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let license = crate::config::license::load_license(store.as_ref()).await;

    // Count assets
    let asset_stats = crate::graph::asset_resolution::asset_stats(store.as_ref()).await;
    let asset_count = asset_stats["total_assets"].as_i64().unwrap_or(0) as usize;

    Ok(Json(serde_json::json!({
        "instance_id": license.instance_id,
        "tier": license.tier,
        "max_assets": null,  // Unlimited
        "asset_count": asset_count,
        "over_limit": false, // Never limited
        "client_name": license.client_name,
        "status_message": license.status_message(asset_count),
    })))
}

// ══════════════════════════════════════════════════════════
// UNIFIED SKILL CATALOG
// ══════════════════════════════════════════════════════════

/// GET /api/tc/skills/catalog — unified skill catalog (tools + connectors + enrichment).
pub async fn tc_skills_catalog_handler(
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let catalog = crate::skills::tc_catalog::load_tc_catalog();
    let filter_type = params.get("type").map(|s| s.as_str());

    let filtered: Vec<_> = if let Some(t) = filter_type {
        catalog.skills.iter().filter(|s| s.skill_type == t).collect()
    } else {
        catalog.skills.iter().collect()
    };

    Ok(Json(serde_json::json!({
        "skills": filtered,
        "total": catalog.total,
        "tools": catalog.tools,
        "connectors": catalog.connectors,
        "enrichment": catalog.enrichment,
        "filter": filter_type,
    })))
}

// ══════════════════════════════════════════════════════════
// CONNECTORS — AD, pfSense
// ══════════════════════════════════════════════════════════

/// POST /api/tc/connectors/ad/sync — sync Active Directory into graph.
pub async fn connector_ad_sync_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let config = serde_json::from_value::<crate::connectors::active_directory::AdConfig>(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid AD config: {e}")))?;
    let result = crate::connectors::active_directory::sync_ad(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

/// POST /api/tc/skills/run/{skill_id} — run a tool skill via Docker executor.
pub async fn skill_run_handler(
    State(state): State<Arc<GatewayState>>,
    Path(skill_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let target = body["target"].as_str().unwrap_or(".");
    // Optional: RSSI can name what this scan is about (e.g. "API Intranet", "SRV-WEB-01")
    let asset_label = body["asset_name"].as_str().or(body["project"].as_str());

    use crate::connectors::docker_executor::*;
    let (mut config, parser): (DockerSkillConfig, fn(&str) -> Vec<ParsedFinding>) = match skill_id.as_str() {
        "skill-semgrep" => (semgrep_config(target), parse_semgrep),
        "skill-checkov" => (checkov_config(target), parse_checkov),
        "skill-trufflehog" => (trufflehog_config(target), parse_trufflehog),
        "skill-grype" => (grype_config(target), parse_grype),
        "skill-syft" => (syft_config(target), parse_syft),
        "skill-lynis" => (lynis_config(target), parse_lynis),
        "skill-docker-bench" => (docker_bench_config(), parse_docker_bench),
        "skill-nuclei" => (nuclei_config(target), parse_nuclei),
        "skill-trivy" => (trivy_image_config(target), parse_trivy),
        "skill-zap" => {
            let config = DockerSkillConfig {
                image: "zaproxy/zap-stable:latest".into(),
                command: vec!["zap-baseline.py".into(), "-t".into(), target.into(), "-I".into()],
                mount_path: Some("/tmp/zap-work".into()), mount_target: "/zap/wrk".into(),
                network: "host".into(), memory_limit: "1g".into(),
                timeout_seconds: 600, skill_id: "skill-zap".into(), skill_name: "OWASP ZAP".into(), asset_label: None,
            };
            // ZAP baseline outputs text with WARN/FAIL lines — parse those
            fn parse_zap_text(stdout: &str) -> Vec<ParsedFinding> {
                let mut findings = vec![];
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("WARN-NEW:") || trimmed.starts_with("FAIL-NEW:") {
                        let is_fail = trimmed.starts_with("FAIL");
                        let msg = trimmed.split(':').skip(1).collect::<Vec<_>>().join(":").trim().to_string();
                        if msg.len() > 5 {
                            findings.push(ParsedFinding {
                                title: msg.chars().take(100).collect(),
                                description: msg.clone(),
                                severity: if is_fail { "HIGH".into() } else { "MEDIUM".into() },
                                category: "dast".into(),
                                asset: None,
                                metadata: serde_json::json!({"tool": "zap", "type": if is_fail { "fail" } else { "warn" }}),
                            });
                        }
                    }
                }
                findings
            }
            (config, parse_zap_text as fn(&str) -> Vec<ParsedFinding>)
        }
        "skill-subfinder" => {
            let config = DockerSkillConfig {
                image: "projectdiscovery/subfinder:latest".into(),
                command: vec!["-d".into(), target.into(), "-silent".into(), "-json".into()],
                mount_path: None, mount_target: "/workspace".into(),
                network: "host".into(), memory_limit: "256m".into(),
                timeout_seconds: 300, skill_id: "skill-subfinder".into(), skill_name: "Subfinder".into(), asset_label: None,
            };
            fn parse_subfinder(stdout: &str) -> Vec<ParsedFinding> {
                stdout.lines().filter_map(|line| {
                    let v: serde_json::Value = serde_json::from_str(line).ok()?;
                    let host = v["host"].as_str()?;
                    Some(ParsedFinding {
                        title: format!("Subdomain: {}", host),
                        description: format!("Source: {}", v["source"].as_str().unwrap_or("?")),
                        severity: "LOW".into(), category: "recon".into(),
                        asset: Some(host.to_string()),
                        metadata: serde_json::json!({"host": host, "tool": "subfinder"}),
                    })
                }).collect()
            }
            (config, parse_subfinder as fn(&str) -> Vec<ParsedFinding>)
        }
        "skill-httpx" => {
            let config = DockerSkillConfig {
                image: "projectdiscovery/httpx:latest".into(),
                command: vec!["-u".into(), target.into(), "-json".into(), "-silent".into()],
                mount_path: None, mount_target: "/workspace".into(),
                network: "host".into(), memory_limit: "256m".into(),
                timeout_seconds: 300, skill_id: "skill-httpx".into(), skill_name: "httpx Probe".into(), asset_label: None,
            };
            fn parse_httpx(stdout: &str) -> Vec<ParsedFinding> {
                stdout.lines().filter_map(|line| {
                    let v: serde_json::Value = serde_json::from_str(line).ok()?;
                    let url = v["url"].as_str()?;
                    let status = v["status_code"].as_i64().unwrap_or(0);
                    let title = v["title"].as_str().unwrap_or("");
                    let tech: Vec<String> = v["tech"].as_array()
                        .map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    Some(ParsedFinding {
                        title: format!("{} [{}] {}", url, status, title),
                        description: format!("Technologies: {}", if tech.is_empty() { "none".into() } else { tech.join(", ") }),
                        severity: "LOW".into(), category: "recon".into(),
                        asset: Some(url.to_string()),
                        metadata: serde_json::json!({"url": url, "status": status, "title": title, "tech": tech, "tool": "httpx"}),
                    })
                }).collect()
            }
            (config, parse_httpx as fn(&str) -> Vec<ParsedFinding>)
        }
        _ => return Err((StatusCode::BAD_REQUEST, format!("Unknown skill: {}", skill_id))),
    };

    // Inject asset label if provided by the RSSI
    if let Some(label) = asset_label {
        config.asset_label = Some(label.to_string());
    }

    let result = execute_skill(store.as_ref(), &config, parser).await;
    Ok(Json(serde_json::json!(result)))
}

/// POST /api/tc/connectors/nmap/scan — run nmap discovery and feed into graph.
pub async fn connector_nmap_scan_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let config = serde_json::from_value::<crate::connectors::nmap_discovery::NmapConfig>(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid nmap config: {e}")))?;

    // Run in background (scans can take 5+ minutes for /24)
    let store_clone = store.clone();
    tokio::spawn(async move {
        let result = crate::connectors::nmap_discovery::run_discovery(store_clone.as_ref(), &config).await;
        tracing::info!("NMAP COMPLETE: {:?}", result);
    });

    Ok(Json(serde_json::json!({
        "ok": true,
        "status": "running",
        "message": "Scan Nmap lancé en arrière-plan. Les assets découverts apparaîtront dans la page Assets."
    })))
}

/// POST /api/tc/connectors/proxmox/sync — sync Proxmox VMs into graph.
pub async fn connector_proxmox_sync_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let config = serde_json::from_value::<crate::connectors::proxmox::ProxmoxConfig>(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid proxmox config: {e}")))?;
    let result = crate::connectors::proxmox::sync_proxmox(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

/// POST /api/tc/connectors/wazuh/sync — import alerts from Wazuh SIEM.
pub async fn connector_wazuh_sync_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let config = serde_json::from_value::<crate::connectors::wazuh::WazuhConfig>(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid wazuh config: {e}")))?;
    let result = crate::connectors::wazuh::sync_wazuh(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

/// POST /api/tc/connectors/glpi/sync — import assets from GLPI CMDB.
pub async fn connector_glpi_sync_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let config = serde_json::from_value::<crate::connectors::glpi::GlpiConfig>(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid GLPI config: {e}")))?;
    let result = crate::connectors::glpi::sync_glpi(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

/// POST /api/tc/connectors/glpi/ticket — create a GLPI ticket from a finding.
/// Body: { "finding_id": 123 } or { "title": "...", "description": "...", "urgency": 3 }
pub async fn connector_glpi_ticket_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    // Load GLPI config from skill_configs
    let url = get_skill_config_field(store.as_ref(), "skill-glpi", "glpi_url").await;
    let app_token = get_skill_config_field(store.as_ref(), "skill-glpi", "glpi_app_token").await;
    let user_token = get_skill_config_field(store.as_ref(), "skill-glpi", "glpi_user_token").await;

    if url.is_empty() || app_token.is_empty() {
        return Ok(Json(serde_json::json!({"error": "GLPI not configured. Set glpi_url and glpi_app_token in skill config."})));
    }

    let config = crate::connectors::glpi::GlpiConfig {
        url, app_token, user_token, no_tls_verify: true,
    };

    // If finding_id provided, build ticket from the finding
    let (title, description, urgency) = if let Some(finding_id) = body["finding_id"].as_i64() {
        match store.get_finding(finding_id).await {
            Ok(Some(f)) => {
                let urg = match f.severity.to_uppercase().as_str() {
                    "CRITICAL" => 5,
                    "HIGH" => 4,
                    "MEDIUM" => 3,
                    "LOW" => 2,
                    _ => 1,
                };
                (
                    format!("[ThreatClaw] {}", f.title),
                    format!("{}\n\nAsset: {}\nSource: {}\nDétecté: {}\nSévérité: {}",
                        f.description.unwrap_or_default(), f.asset.unwrap_or("—".into()),
                        f.source.unwrap_or("—".into()), f.detected_at, f.severity),
                    urg,
                )
            }
            _ => return Ok(Json(serde_json::json!({"error": format!("Finding #{} not found", finding_id)}))),
        }
    } else {
        (
            body["title"].as_str().unwrap_or("ThreatClaw Alert").to_string(),
            body["description"].as_str().unwrap_or("").to_string(),
            body["urgency"].as_u64().unwrap_or(3) as u8,
        )
    };

    match crate::connectors::glpi::create_ticket(&config, &title, &description, urgency).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => Ok(Json(serde_json::json!({"error": e}))),
    }
}

/// POST /api/tc/connectors/fortinet/sync — sync FortiGate into graph.
pub async fn connector_fortinet_sync_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let config = serde_json::from_value::<crate::connectors::fortinet::FortinetConfig>(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid fortinet config: {e}")))?;
    let result = crate::connectors::fortinet::sync_fortinet(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

/// POST /api/tc/connectors/defectdojo/export — export findings to DefectDojo.
pub async fn connector_defectdojo_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let config = serde_json::from_value::<crate::connectors::defectdojo::DefectDojoConfig>(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid defectdojo config: {e}")))?;
    let result = crate::connectors::defectdojo::export_findings(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

/// POST /api/tc/connectors/firewall/sync — sync pfSense/OPNsense into graph.
pub async fn connector_firewall_sync_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let config = serde_json::from_value::<crate::connectors::pfsense::FirewallConfig>(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid firewall config: {e}")))?;
    let result = crate::connectors::pfsense::sync_firewall(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

// ══════════════════════════════════════════════════════════
// REMEDIATION ACTIONS (HITL required)
// ══════════════════════════════════════════════════════════

/// POST /api/tc/remediation/block-ip — block IP on firewall (pfSense/OPNsense).
pub async fn remediation_block_ip_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let ip = body["ip"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing ip".to_string()))?;
    let fw_url = body["fw_url"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing fw_url".to_string()))?;
    let fw_type = body["fw_type"].as_str().unwrap_or("pfsense");
    let auth_user = body["auth_user"].as_str().unwrap_or("");
    let auth_secret = body["auth_secret"].as_str().unwrap_or("");
    let no_tls = body["no_tls_verify"].as_bool().unwrap_or(true);

    let result = if fw_type == "opnsense" {
        crate::connectors::remediation::opnsense_block_ip(fw_url, auth_user, auth_secret, ip, no_tls).await
    } else {
        crate::connectors::remediation::pfsense_block_ip(fw_url, auth_user, auth_secret, ip, no_tls).await
    };

    Ok(Json(serde_json::json!(result)))
}

/// POST /api/tc/remediation/disable-account — disable AD account.
pub async fn remediation_disable_account_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let username = body["username"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing username".to_string()))?;
    let host = body["host"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing host".to_string()))?;
    let port = body["port"].as_u64().unwrap_or(636) as u16;
    let bind_dn = body["bind_dn"].as_str().unwrap_or("");
    let bind_pw = body["bind_password"].as_str().unwrap_or("");
    let base_dn = body["base_dn"].as_str().unwrap_or("");
    let no_tls = body["no_tls_verify"].as_bool().unwrap_or(false);

    let result = crate::connectors::remediation::ad_disable_account(
        host, port, bind_dn, bind_pw, base_dn, username, no_tls
    ).await;

    Ok(Json(serde_json::json!(result)))
}

// ══════════════════════════════════════════════════════════
// ASSET RESOLUTION + BEHAVIORAL ANALYSIS
// ══════════════════════════════════════════════════════════

/// POST /api/tc/graph/assets/resolve — resolve a discovered asset (merge or create).
pub async fn graph_asset_resolve_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let discovered = serde_json::from_value::<crate::graph::asset_resolution::DiscoveredAsset>(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid asset data: {e}")))?;
    let result = crate::graph::asset_resolution::resolve_asset(store.as_ref(), &discovered).await;
    Ok(Json(serde_json::json!(result)))
}

/// GET /api/tc/graph/assets — list all resolved assets.
pub async fn graph_assets_list_handler(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let limit = params.get("limit").and_then(|l| l.parse::<u64>().ok()).unwrap_or(100);
    let assets = crate::graph::asset_resolution::list_assets(store.as_ref(), limit).await;
    Ok(Json(serde_json::json!({ "assets": assets, "count": assets.len() })))
}

/// GET /api/tc/graph/assets/stats — asset discovery statistics.
pub async fn graph_assets_stats_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let stats = crate::graph::asset_resolution::asset_stats(store.as_ref()).await;
    Ok(Json(stats))
}

/// GET /api/tc/graph/assets/incomplete — assets needing more discovery sources.
pub async fn graph_assets_incomplete_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let incomplete = crate::graph::asset_resolution::find_incomplete_assets(store.as_ref()).await;
    Ok(Json(serde_json::json!({ "incomplete_assets": incomplete, "count": incomplete.len() })))
}

/// GET /api/tc/graph/behavior/{username} — get behavioral profile for a user.
pub async fn graph_behavior_handler(
    State(state): State<Arc<GatewayState>>,
    Path(username): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let baseline = crate::graph::behavior::compute_baseline(store.as_ref(), &username).await;
    Ok(Json(serde_json::json!(baseline)))
}

/// POST /api/tc/graph/behavior/score — score a login event against baseline.
pub async fn graph_behavior_score_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let username = body["username"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing username".to_string()))?;
    let source_ip = body["source_ip"].as_str().unwrap_or("unknown");
    let target_asset = body["target_asset"].as_str().unwrap_or("unknown");
    let success = body["success"].as_bool().unwrap_or(true);
    let score = crate::graph::behavior::score_login(store.as_ref(), username, source_ip, target_asset, success).await;
    Ok(Json(serde_json::json!(score)))
}

/// POST /api/tc/graph/behavior/refresh — refresh baselines for all users.
pub async fn graph_behavior_refresh_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    crate::graph::behavior::refresh_all_baselines(store.as_ref()).await;
    Ok(Json(serde_json::json!({ "refreshed": true })))
}

// ══════════════════════════════════════════════════════════
// SKILL SCHEDULER
// ══════════════════════════════════════════════════════════

/// GET /api/tc/scheduler — list skill schedules.
pub async fn scheduler_list_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let schedules = crate::agent::skill_scheduler::load_schedules(store.as_ref()).await;
    Ok(Json(serde_json::json!({ "schedules": schedules })))
}

/// POST /api/tc/scheduler — save skill schedules.
pub async fn scheduler_save_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let schedules: Vec<crate::agent::skill_scheduler::SkillSchedule> = serde_json::from_value(
        body["schedules"].clone()
    ).map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid schedules: {e}")))?;
    crate::agent::skill_scheduler::save_schedules(store.as_ref(), &schedules).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(serde_json::json!({ "status": "saved", "count": schedules.len() })))
}

// ══════════════════════════════════════════════════════════
// TEST SCENARIOS — Demo & E2E testing
// ══════════════════════════════════════════════════════════

/// GET /api/tc/test/scenarios — list available test scenarios.
pub async fn test_scenarios_list_handler() -> ApiResult<serde_json::Value> {
    let scenarios = crate::agent::test_scenarios::list_scenarios();
    Ok(Json(serde_json::json!({ "scenarios": scenarios })))
}

/// POST /api/tc/test/run/{id} — run a test scenario.
/// Query param: ?notify=true to trigger notifications.
pub async fn test_scenario_run_handler(
    State(state): State<Arc<GatewayState>>,
    Path(scenario_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let trigger = params.get("notify").map(|v| v == "true").unwrap_or(true);

    tracing::info!("TEST: Running scenario '{}' (notify={})", scenario_id, trigger);

    // Run in background (scenarios can take time with enrichment)
    let store_clone = store.clone();
    let scenario_id_clone = scenario_id.clone();
    tokio::spawn(async move {
        let result = crate::agent::test_scenarios::run_scenario(
            store_clone, &scenario_id_clone, trigger,
        ).await;
        tracing::info!(
            "TEST: Scenario '{}' complete — {} logs, {} findings, {} alerts, score={:?}, level={:?}",
            result.scenario_id, result.logs_injected, result.findings_created,
            result.alerts_created, result.intelligence_score, result.notification_level
        );
    });

    Ok(Json(serde_json::json!({
        "ok": true,
        "scenario": scenario_id,
        "status": "running",
        "message": "Scénario lancé en arrière-plan. Les logs, findings et alertes sont injectés dans le vrai pipeline. Vérifiez Telegram et le dashboard.",
    })))
}

// ══════════════════════════════════════════════════════════
// ENRICHMENT SOURCES — CISA KEV, GreyNoise, ThreatFox, etc.
// ══════════════════════════════════════════════════════════

/// POST /api/tc/enrichment/kev/sync — sync CISA KEV catalog.
pub async fn kev_sync_handler(State(state): State<Arc<GatewayState>>) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match crate::enrichment::cisa_kev::sync_kev(store.as_ref()).await {
        Ok(count) => Ok(Json(serde_json::json!({ "ok": true, "synced": count }))),
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e }))),
    }
}

/// GET /api/tc/enrichment/kev/{cve_id} — check if CVE is in KEV.
pub async fn kev_check_handler(State(state): State<Arc<GatewayState>>, Path(cve_id): Path<String>) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match crate::enrichment::cisa_kev::is_exploited(store.as_ref(), &cve_id).await {
        Some(entry) => Ok(Json(serde_json::json!({ "exploited": true, "entry": serde_json::to_value(entry).unwrap_or_default() }))),
        None => Ok(Json(serde_json::json!({ "exploited": false }))),
    }
}

/// GET /api/tc/enrichment/greynoise/{ip} — GreyNoise IP lookup.
pub async fn greynoise_handler(Path(ip): Path<String>) -> ApiResult<serde_json::Value> {
    match crate::enrichment::greynoise::lookup_ip(&ip, None).await {
        Ok(r) => Ok(Json(serde_json::to_value(r).unwrap_or_default())),
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/tc/enrichment/threatfox/{ioc} — ThreatFox IoC lookup.
pub async fn threatfox_handler(Path(ioc): Path<String>) -> ApiResult<serde_json::Value> {
    match crate::enrichment::threatfox::lookup_ioc(&ioc, None).await {
        Ok(results) => Ok(Json(serde_json::json!({ "results": results, "count": results.len() }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/tc/enrichment/malware/{hash} — MalwareBazaar hash lookup.
pub async fn malware_handler(Path(hash): Path<String>) -> ApiResult<serde_json::Value> {
    match crate::enrichment::malware_bazaar::lookup_hash(&hash, None).await {
        Ok(Some(info)) => Ok(Json(serde_json::json!({ "found": true, "info": serde_json::to_value(info).unwrap_or_default() }))),
        Ok(None) => Ok(Json(serde_json::json!({ "found": false }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/tc/enrichment/openphish/sync — sync OpenPhish feed.
pub async fn openphish_sync_handler(State(state): State<Arc<GatewayState>>) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match crate::enrichment::openphish::sync_feed(store.as_ref()).await {
        Ok(count) => Ok(Json(serde_json::json!({ "ok": true, "synced": count }))),
        Err(e) => Ok(Json(serde_json::json!({ "ok": false, "error": e }))),
    }
}

/// POST /api/tc/enrichment/sync-all — sync all enrichment sources.
pub async fn enrichment_sync_all_handler(State(state): State<Arc<GatewayState>>) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let mut results = serde_json::json!({});

    // KEV
    results["kev"] = match crate::enrichment::cisa_kev::sync_kev(store.as_ref()).await {
        Ok(n) => serde_json::json!({ "ok": true, "count": n }),
        Err(e) => serde_json::json!({ "ok": false, "error": e }),
    };
    // MITRE
    results["mitre"] = match crate::enrichment::mitre_attack::sync_attack_techniques(store.as_ref()).await {
        Ok(n) => serde_json::json!({ "ok": true, "count": n }),
        Err(e) => serde_json::json!({ "ok": false, "error": e }),
    };
    // CERT-FR
    results["certfr"] = match crate::enrichment::certfr::sync_certfr_alerts(store.as_ref()).await {
        Ok(n) => serde_json::json!({ "ok": true, "count": n }),
        Err(e) => serde_json::json!({ "ok": false, "error": e }),
    };
    // OpenPhish
    results["openphish"] = match crate::enrichment::openphish::sync_feed(store.as_ref()).await {
        Ok(n) => serde_json::json!({ "ok": true, "count": n }),
        Err(e) => serde_json::json!({ "ok": false, "error": e }),
    };

    Ok(Json(results))
}

/// GET /api/tc/enrichment/epss/{cve_id} — EPSS score lookup.
pub async fn epss_handler(Path(cve_id): Path<String>) -> ApiResult<serde_json::Value> {
    match crate::enrichment::epss::lookup_epss(&cve_id).await {
        Ok(Some(score)) => Ok(Json(serde_json::to_value(score).unwrap_or_default())),
        Ok(None) => Ok(Json(serde_json::json!({ "error": "CVE not found in EPSS" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/tc/enrichment/ipinfo/{ip} — IP geolocation + ASN.
pub async fn ipinfo_handler(Path(ip): Path<String>) -> ApiResult<serde_json::Value> {
    match crate::enrichment::ipinfo::lookup_ip(&ip).await {
        Ok(info) => Ok(Json(serde_json::to_value(info).unwrap_or_default())),
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

/// POST /api/tc/enrichment/priority — compute ThreatClaw priority score.
/// Body: { "cvss": 7.5, "cve_id": "CVE-2023-44487" }
pub async fn priority_score_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let cvss = body["cvss"].as_f64().unwrap_or(0.0);
    let cve_id = body["cve_id"].as_str().unwrap_or("");

    // Enrich from all sources
    let in_kev = if !cve_id.is_empty() {
        crate::enrichment::cisa_kev::is_exploited(store.as_ref(), cve_id).await.is_some()
    } else { false };

    let epss = if !cve_id.is_empty() {
        crate::enrichment::epss::lookup_epss(cve_id).await.ok().flatten().map(|s| s.epss).unwrap_or(0.0)
    } else { 0.0 };

    let ip = body["ip"].as_str().unwrap_or("");
    let (gn_noise, gn_malicious) = if !ip.is_empty() {
        match crate::enrichment::greynoise::lookup_ip(ip, None).await {
            Ok(r) => (r.noise, r.classification == "malicious"),
            Err(_) => (false, false),
        }
    } else { (false, false) };

    let tf_hits = if !ip.is_empty() {
        crate::enrichment::threatfox::lookup_ioc(ip, None).await.map(|r| r.len()).unwrap_or(0)
    } else { 0 };

    let input = crate::enrichment::priority_score::PriorityInput {
        cvss_score: cvss, in_kev, epss_score: epss,
        greynoise_noise: gn_noise, greynoise_malicious: gn_malicious,
        threatfox_hits: tf_hits,
    };
    let result = crate::enrichment::priority_score::compute_priority(&input);

    Ok(Json(serde_json::json!({
        "priority": result.priority,
        "score": result.score,
        "reason": result.reason,
        "adjustments": result.adjustments,
        "input": { "cvss": cvss, "kev": in_kev, "epss": epss, "greynoise_noise": gn_noise, "greynoise_malicious": gn_malicious, "threatfox_hits": tf_hits },
    })))
}

// ══════════════════════════════════════════════════════════
// INTELLIGENCE ENGINE + NOTIFICATION ROUTING
// ══════════════════════════════════════════════════════════

/// Shared intelligence engine running flag.
static INTELLIGENCE_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// GET /api/tc/intelligence/situation — get current security situation.
pub async fn intelligence_situation_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.get_setting("_system", "security_situation").await {
        Ok(Some(val)) => Ok(Json(val)),
        _ => Ok(Json(serde_json::json!({ "global_score": 100.0, "notification_level": "silence", "status": "not_computed" }))),
    }
}

/// POST /api/tc/intelligence/cycle — run one intelligence cycle manually.
/// Spawns the cycle in background (enrichment can take 30s+) and returns immediately.
pub async fn intelligence_cycle_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    // Spawn in background — enrichment calls external APIs (EPSS, GreyNoise, IPinfo)
    let store_clone = store.clone();
    tokio::spawn(async move {
        let situation = crate::agent::intelligence_engine::run_intelligence_cycle(store_clone.clone()).await;

        // Route notification if level >= Alert
        if situation.notification_level >= crate::agent::intelligence_engine::NotificationLevel::Alert {
            if let Some(ref alert_msg) = situation.alert_message {
                let results = crate::agent::notification_router::route_notification(
                    store_clone.as_ref(), situation.notification_level, alert_msg, &situation.digest_message,
                ).await;
                for (ch, r) in &results {
                    if r.is_ok() {
                        tracing::info!("INTELLIGENCE: Notification sent to {} (level={:?})", ch, situation.notification_level);
                    }
                }
            }
        }
    });

    Ok(Json(serde_json::json!({
        "ok": true,
        "status": "cycle_started",
        "message": "Intelligence cycle running in background. Check /api/tc/intelligence/situation for results.",
    })))
}

/// POST /api/tc/intelligence/start — start the background intelligence ticker.
pub async fn intelligence_start_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    if INTELLIGENCE_RUNNING.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(Json(serde_json::json!({ "ok": true, "status": "already_running" })));
    }

    INTELLIGENCE_RUNNING.store(true, std::sync::atomic::Ordering::Relaxed);
    crate::agent::intelligence_engine::spawn_intelligence_ticker(
        store.clone(),
        std::time::Duration::from_secs(300), // 5 min
        Some(Arc::clone(&state.hitl_nonce_manager)),
    );

    tracing::info!("INTELLIGENCE: Engine started via API (cycle every 5min)");
    Ok(Json(serde_json::json!({ "ok": true, "status": "started", "interval": "5min" })))
}

/// GET /api/tc/notifications/routing — get notification routing config.
pub async fn notification_routing_get_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let routing = crate::agent::notification_router::load_routing(store.as_ref()).await;
    Ok(Json(serde_json::to_value(routing).unwrap_or_default()))
}

/// POST /api/tc/notifications/routing — save notification routing config.
pub async fn notification_routing_set_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let routing: crate::agent::notification_router::NotificationRouting = serde_json::from_value(body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid routing config: {e}")))?;
    crate::agent::notification_router::save_routing(store.as_ref(), &routing).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(serde_json::json!({ "status": "saved" })))
}

/// POST /api/tc/notifications/test — send a test notification through the router.
pub async fn notification_test_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let level = match body["level"].as_str().unwrap_or("alert") {
        "digest" => crate::agent::intelligence_engine::NotificationLevel::Digest,
        "critical" => crate::agent::intelligence_engine::NotificationLevel::Critical,
        _ => crate::agent::intelligence_engine::NotificationLevel::Alert,
    };
    let message = body["message"].as_str().unwrap_or("ThreatClaw — Test de notification");
    let results = crate::agent::notification_router::route_notification(
        store.as_ref(), level, message, message,
    ).await;
    let summary: Vec<serde_json::Value> = results.iter().map(|(ch, r)| {
        serde_json::json!({ "channel": ch, "ok": r.is_ok(), "error": r.as_ref().err().map(String::as_str) })
    }).collect();
    Ok(Json(serde_json::json!({ "results": summary })))
}

// ══════════════════════════════════════════════════════════
// HITL CALLBACK (for Mattermost/Ntfy button actions)
// ══════════════════════════════════════════════════════════

/// GET/POST /api/tc/hitl/callback — universal callback for HITL buttons.
/// Called when user clicks Approve/Reject in Mattermost or Ntfy.
/// Query params or JSON body: action=approve|reject, nonce=xxx
pub async fn hitl_button_callback_handler(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    let action = params.get("action").map(String::as_str).unwrap_or("");
    let nonce = params.get("nonce").map(String::as_str).unwrap_or("");

    if nonce.is_empty() {
        return Ok(Json(serde_json::json!({ "ok": false, "error": "Missing nonce" })));
    }

    let approved = action == "approve";

    // Log the callback
    let audit_key = format!("hitl_callback_{}_{}", if approved { "approve" } else { "reject" }, chrono::Utc::now().timestamp());
    let _ = store.set_setting("_audit", &audit_key, &serde_json::json!({
        "action": action, "nonce": nonce,
        "source": "button_callback",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })).await;

    tracing::info!("HITL: Callback received — action={}, nonce={}", action, &nonce[..8.min(nonce.len())]);

    // Use the shared NonceManager and process_slack_callback (works for all channels)
    let nonce_mgr = &state.hitl_nonce_manager;

    let result = crate::agent::hitl_bridge::process_slack_callback(
        nonce,
        approved,
        "button_callback",
        nonce_mgr,
        &params,
    ).await;

    match result {
        Ok(r) => {
            tracing::info!("HITL: {} — cmd_id={}, executed={}, success={:?}",
                if r.approved { "APPROVED" } else { "REJECTED" }, r.cmd_id, r.executed, r.execution_success);
            Ok(Json(serde_json::json!({
                "ok": true,
                "action": if r.approved { "approved" } else { "rejected" },
                "cmd_id": r.cmd_id,
                "executed": r.executed,
                "success": r.execution_success,
                "output": r.execution_output,
                "message": if r.approved { "Action approuvée et exécutée" } else { "Action rejetée" },
            })))
        }
        Err(e) => {
            tracing::warn!("HITL: Callback error: {}", e);
            Ok(Json(serde_json::json!({
                "ok": false,
                "error": format!("{}", e),
            })))
        }
    }
}

// ══════════════════════════════════════════════════════════
// CONVERSATIONAL BOT + COMMAND INTERPRETER
// ══════════════════════════════════════════════════════════

/// Shared bot handle — stores the JoinHandle of the polling bot.
static BOT_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// POST /api/tc/bot/start — start the Telegram polling bot.
pub async fn bot_start_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    if BOT_RUNNING.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(Json(serde_json::json!({ "ok": true, "status": "already_running" })));
    }

    BOT_RUNNING.store(true, std::sync::atomic::Ordering::Relaxed);
    crate::agent::conversational_bot::spawn_telegram_bot(
        store.clone(),
        std::time::Duration::from_secs(1),
    );

    tracing::info!("CONV_BOT: Started via API");
    Ok(Json(serde_json::json!({ "ok": true, "status": "started" })))
}

/// GET /api/tc/bot/status — check if bot is running.
pub async fn bot_status_handler() -> ApiResult<serde_json::Value> {
    Ok(Json(serde_json::json!({
        "running": BOT_RUNNING.load(std::sync::atomic::Ordering::Relaxed),
    })))
}

/// POST /api/tc/command — execute a natural language command (channel-agnostic).
/// Body: { "message": "scan de port sur 192.168.1.50", "channel": "api" }
pub async fn command_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let message = body["message"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "Missing message".to_string()))?;

    let llm_config = crate::agent::llm_router::LlmRouterConfig::from_db_settings(store.as_ref()).await;

    // Parse
    let cmd = crate::agent::command_interpreter::parse_command(message, &llm_config).await;

    // Execute (for API, no confirmation needed — RSSI is already authenticated)
    let result = crate::agent::command_interpreter::execute_command(&cmd, store.as_ref(), &llm_config).await;

    Ok(Json(serde_json::json!({
        "parsed": {
            "action": cmd.action,
            "target": cmd.target,
            "confidence": cmd.confidence,
            "summary": cmd.summary,
        },
        "result": {
            "success": result.success,
            "message": result.message,
            "data": result.data,
        },
    })))
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

// ════════════════════════════════════════════════════════════════
// WEBHOOK INGEST
// ════════════════════════════════════════════════════════════════

pub async fn webhook_ingest_handler(
    State(state): State<Arc<GatewayState>>,
    Path(source): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: axum::body::Bytes,
) -> StatusCode {
    let store = match state.store.as_ref() {
        Some(s) => s.as_ref(),
        None => return StatusCode::OK, // Silent drop
    };
    // See ADR-040: prefer header over query param (query params are logged by proxies)
    let token = headers.get("x-webhook-token").and_then(|v| v.to_str().ok())
        .or_else(|| params.get("token").map(|s| s.as_str()))
        .unwrap_or("");
    let count = crate::connectors::webhook_ingest::process_webhook(store, &source, token, &body).await;
    if count > 0 {
        tracing::info!("WEBHOOK: {} events from source {}", count, source);
    }
    StatusCode::OK // Always 200
}

pub async fn webhook_generate_token_handler(
    State(state): State<Arc<GatewayState>>,
    Path(source): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match crate::connectors::webhook_ingest::generate_token(store.as_ref(), &source).await {
        Ok(token) => Ok(Json(serde_json::json!({
            "source": source,
            "token": token,
            "endpoint": format!("/api/tc/webhook/ingest/{}", source),
            "header": "X-Webhook-Token",
            "endpoint_legacy": format!("/api/tc/webhook/ingest/{}?token={}", source, token)
        }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

// ════════════════════════════════════════════════════════════════
// ENRICHMENT — WEB SECURITY (Tier 1)
// ════════════════════════════════════════════════════════════════

pub async fn enrichment_safebrowsing_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let url = body["url"].as_str().unwrap_or("");
    // Cache check
    if let Ok(Some(cached)) = store.get_enrichment_cache("safebrowsing", url).await {
        return Ok(Json(cached));
    }
    let api_key = get_skill_config_field(store.as_ref(), "skill-enrichment-safebrowsing", "GOOGLE_SAFEBROWSING_KEY").await;
    match crate::enrichment::google_safebrowsing::check_url(url, &api_key).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("safebrowsing", url, &result, 24).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

pub async fn enrichment_ssllabs_handler(
    State(state): State<Arc<GatewayState>>,
    Path(host): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    // Cache check
    if let Ok(Some(cached)) = store.get_enrichment_cache("ssllabs", &host).await {
        return Ok(Json(cached));
    }
    match crate::enrichment::ssl_labs::analyze(&host).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("ssllabs", &host, &result, 168).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

pub async fn enrichment_observatory_handler(
    State(state): State<Arc<GatewayState>>,
    Path(host): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    // Cache check
    if let Ok(Some(cached)) = store.get_enrichment_cache("observatory", &host).await {
        return Ok(Json(cached));
    }
    match crate::enrichment::mozilla_observatory::scan(&host).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("observatory", &host, &result, 168).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

pub async fn enrichment_crtsh_handler(
    State(state): State<Arc<GatewayState>>,
    Path(domain): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    // Cache check
    if let Ok(Some(cached)) = store.get_enrichment_cache("crtsh", &domain).await {
        return Ok(Json(cached));
    }
    match crate::enrichment::crt_sh::lookup_domain(&domain).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("crtsh", &domain, &result, 24).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

pub async fn enrichment_wpscan_handler(
    State(state): State<Arc<GatewayState>>,
    Path(slug): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    // Cache check
    if let Ok(Some(cached)) = store.get_enrichment_cache("wpscan", &slug).await {
        return Ok(Json(cached));
    }
    let api_token = get_skill_config_field(store.as_ref(), "skill-enrichment-wpscan", "WPSCAN_API_TOKEN").await;
    match crate::enrichment::wpscan::lookup_plugin(&slug, &api_token).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("wpscan", &slug, &result, 24).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

pub async fn enrichment_phishtank_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let url = body["url"].as_str().unwrap_or("");
    let store = state.store.as_ref().ok_or_else(no_db)?;
    // Cache check
    if let Ok(Some(cached)) = store.get_enrichment_cache("phishtank", url).await {
        return Ok(Json(cached));
    }
    let app_key = get_skill_config_field(store.as_ref(), "skill-enrichment-phishtank", "PHISHTANK_APP_KEY").await;
    let key_opt = if app_key.is_empty() { None } else { Some(app_key.as_str()) };
    match crate::enrichment::phishtank::check_url(url, key_opt).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("phishtank", url, &result, 24).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

pub async fn enrichment_spamhaus_handler(
    State(state): State<Arc<GatewayState>>,
    Path(ip): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    // Cache check
    if let Ok(Some(cached)) = store.get_enrichment_cache("spamhaus", &ip).await {
        return Ok(Json(cached));
    }
    match crate::enrichment::spamhaus::check_ip(&ip).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("spamhaus", &ip, &result, 24).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/tc/enrichment/vulnlookup/{cve_id} — Vulnerability-Lookup (CIRCL) multi-source CVE + sightings.
pub async fn enrichment_vulnlookup_handler(
    State(state): State<Arc<GatewayState>>,
    Path(cve_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    // Cache check (24h TTL)
    if let Ok(Some(cached)) = store.get_enrichment_cache("vulnlookup", &cve_id).await {
        return Ok(Json(cached));
    }
    match crate::enrichment::vuln_lookup::lookup_cve(&cve_id).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("vulnlookup", &cve_id, &result, 24).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/tc/enrichment/vulnlookup/{cve_id}/sightings — Exploit sightings for a CVE.
pub async fn enrichment_vulnlookup_sightings_handler(
    Path(cve_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    match crate::enrichment::vuln_lookup::fetch_sightings(&cve_id).await {
        Ok(r) => Ok(Json(serde_json::json!(r))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

/// GET /api/tc/enrichment/vulnlookup/{cve_id}/rules — Detection rules (Sigma/YARA) for a CVE.
pub async fn enrichment_vulnlookup_rules_handler(
    Path(cve_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    match crate::enrichment::vuln_lookup::fetch_detection_rules(&cve_id).await {
        Ok(r) => Ok(Json(serde_json::json!(r))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

pub async fn enrichment_securitytrails_handler(
    State(state): State<Arc<GatewayState>>,
    Path(domain): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    if let Ok(Some(cached)) = store.get_enrichment_cache("securitytrails", &domain).await {
        return Ok(Json(cached));
    }
    let api_key = get_skill_config_field(store.as_ref(), "skill-enrichment-securitytrails", "SECURITYTRAILS_API_KEY").await;
    match crate::enrichment::securitytrails::lookup_domain(&domain, &api_key).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("securitytrails", &domain, &result, 24).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

pub async fn enrichment_urlscan_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let url = body["url"].as_str().unwrap_or("");
    if url.is_empty() {
        return Ok(Json(serde_json::json!({ "error": "Missing url field" })));
    }
    if let Ok(Some(cached)) = store.get_enrichment_cache("urlscan", url).await {
        return Ok(Json(cached));
    }
    let api_key = get_skill_config_field(store.as_ref(), "skill-enrichment-urlscan", "URLSCAN_API_KEY").await;
    match crate::enrichment::urlscan::scan_url(url, &api_key).await {
        Ok(r) => {
            let result = serde_json::json!(r);
            let _ = store.set_enrichment_cache("urlscan", url, &result, 24).await;
            Ok(Json(result))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e }))),
    }
}

pub async fn enrichment_wordfence_handler() -> ApiResult<serde_json::Value> {
    // Sync the Wordfence feed if needed, then return stats
    if crate::enrichment::wordfence_intel::needs_sync() {
        match crate::enrichment::wordfence_intel::sync_feed().await {
            Ok(count) => {
                return Ok(Json(serde_json::json!({
                    "status": "synced",
                    "vulnerabilities_loaded": count,
                    "known_slugs": crate::enrichment::wordfence_intel::known_slugs_count(),
                })));
            }
            Err(e) => return Ok(Json(serde_json::json!({ "error": e }))),
        }
    }
    Ok(Json(serde_json::json!({
        "status": "cached",
        "known_slugs": crate::enrichment::wordfence_intel::known_slugs_count(),
    })))
}

pub async fn enrichment_wordfence_lookup_handler(
    Path(slug): Path<String>,
) -> ApiResult<serde_json::Value> {
    let vulns = crate::enrichment::wordfence_intel::lookup_slug(&slug);
    Ok(Json(serde_json::json!({ "slug": slug, "vulnerabilities": vulns, "count": vulns.len() })))
}

// ════════════════════════════════════════════════════════════════
// CONNECTORS — WEB SECURITY (Tier 2)
// ════════════════════════════════════════════════════════════════

pub async fn connector_cloudflare_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let token = get_skill_config_field(store.as_ref(), "skill-cloudflare", "CF_API_TOKEN").await;
    let zone_id = get_skill_config_field(store.as_ref(), "skill-cloudflare", "CF_ZONE_ID").await;
    let config = crate::connectors::cloudflare::CloudflareConfig {
        api_token: token, zone_id, max_events: 100,
    };
    let result = crate::connectors::cloudflare::sync_cloudflare(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

pub async fn connector_crowdsec_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let url = get_skill_config_field(store.as_ref(), "skill-crowdsec-connector", "CROWDSEC_URL").await;
    let key = get_skill_config_field(store.as_ref(), "skill-crowdsec-connector", "CROWDSEC_BOUNCER_KEY").await;
    let config = crate::connectors::crowdsec::CrowdSecConfig {
        url, bouncer_key: key,
    };
    let result = crate::connectors::crowdsec::sync_crowdsec(store.as_ref(), &config, false).await;
    Ok(Json(serde_json::json!(result)))
}

pub async fn connector_uptimerobot_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let api_key = get_skill_config_field(store.as_ref(), "skill-uptimerobot", "UPTIMEROBOT_API_KEY").await;
    let config = crate::connectors::uptimerobot::UptimeRobotConfig {
        api_key, latency_threshold_ms: 2000, cert_warn_days: 14,
    };
    let result = crate::connectors::uptimerobot::sync_uptimerobot(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

/// Helper: get a config field for a skill.
async fn get_skill_config_field(store: &dyn crate::db::Database, skill_id: &str, field: &str) -> String {
    match store.get_skill_config(skill_id).await {
        Ok(configs) => configs.iter()
            .find(|c| c.key == field)
            .map(|c| c.value.clone())
            .unwrap_or_default(),
        Err(_) => String::new(),
    }
}

// ════════════════════════════════════════════════════════════════
// ASSETS MANAGEMENT (v1.6)
// ════════════════════════════════════════════════════════════════

pub async fn assets_list_handler(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let category = params.get("category").map(|s| s.as_str());
    let status = params.get("status").map(|s| s.as_str());
    let limit: i64 = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    let page: i64 = params.get("page").and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    let offset = (page - 1) * limit;
    let total = store.count_assets_filtered(category, status).await.unwrap_or(0);
    match store.list_assets(category, status, limit, offset).await {
        Ok(assets) => {
            let pages = (total + limit - 1) / limit;
            Ok(Json(serde_json::json!({
                "assets": assets,
                "total": total,
                "page": page,
                "pages": pages,
                "has_more": page < pages,
            })))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

pub async fn assets_get_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.get_asset(&id).await {
        Ok(Some(asset)) => Ok(Json(serde_json::json!(asset))),
        Ok(None) => Ok(Json(serde_json::json!({ "error": "Asset not found" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

pub async fn assets_upsert_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    use crate::db::threatclaw_store::NewAsset;

    let id = body["id"].as_str()
        .unwrap_or(&uuid::Uuid::new_v4().to_string())
        .to_string();

    let asset = NewAsset {
        id: id.clone(),
        name: body["name"].as_str().unwrap_or(&id).to_string(),
        category: body["category"].as_str().unwrap_or("unknown").to_string(),
        subcategory: body["subcategory"].as_str().map(String::from),
        role: body["role"].as_str().map(String::from),
        criticality: body["criticality"].as_str().unwrap_or("medium").to_string(),
        ip_addresses: body["ip_addresses"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .or_else(|| body["ip"].as_str().map(|ip| vec![ip.to_string()]))
            .unwrap_or_default(),
        mac_address: body["mac_address"].as_str().map(String::from),
        hostname: body["hostname"].as_str().map(String::from),
        fqdn: body["fqdn"].as_str().map(String::from),
        url: body["url"].as_str().map(String::from),
        os: body["os"].as_str().map(String::from),
        mac_vendor: body["mac_vendor"].as_str().map(String::from),
            services: serde_json::json!([]),
        source: body["source"].as_str().unwrap_or("manual").to_string(),
        owner: body["owner"].as_str().map(String::from),
        location: body["location"].as_str().map(String::from),
        tags: body["tags"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
    };

    match store.upsert_asset(&asset).await {
        Ok(ref aid) => {
            // Track which fields the user manually changed (protects from auto-discovery overwrite)
            let mut modified_fields: Vec<&str> = vec![];
            if body.get("name").is_some() { modified_fields.push("name"); }
            if body.get("hostname").is_some() { modified_fields.push("hostname"); }
            if body.get("category").is_some() { modified_fields.push("category"); }
            if body.get("criticality").is_some() { modified_fields.push("criticality"); }
            if body.get("owner").is_some() { modified_fields.push("owner"); }
            if body.get("location").is_some() { modified_fields.push("location"); }
            if body.get("tags").is_some() { modified_fields.push("tags"); }
            if !modified_fields.is_empty() {
                let _ = store.mark_asset_user_modified(aid, &modified_fields).await;
            }
            Ok(Json(serde_json::json!({ "status": "ok", "id": aid })))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

pub async fn assets_delete_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.delete_asset(&id).await {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "deleted" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

pub async fn assets_counts_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.count_assets_by_category().await {
        Ok(counts) => {
            let total: i64 = counts.iter().map(|(_, c)| c).sum();
            Ok(Json(serde_json::json!({ "counts": counts.iter().map(|(k, v)| serde_json::json!({"category": k, "count": v})).collect::<Vec<_>>(), "total": total })))
        }
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

pub async fn assets_categories_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.list_asset_categories().await {
        Ok(cats) => Ok(Json(serde_json::json!({ "categories": cats }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

pub async fn assets_category_upsert_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    use crate::db::threatclaw_store::AssetCategory;
    let cat = AssetCategory {
        id: body["id"].as_str().unwrap_or("custom").to_string(),
        label: body["label"].as_str().unwrap_or("Custom").to_string(),
        label_en: body["label_en"].as_str().map(String::from),
        icon: body["icon"].as_str().unwrap_or("box").to_string(),
        color: body["color"].as_str().unwrap_or("var(--tc-blue)").to_string(),
        subcategories: body["subcategories"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        is_builtin: false,
    };
    match store.upsert_asset_category(&cat).await {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "ok" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

// ════════════════════════════════════════════════════════════════
// INTERNAL NETWORKS
// ════════════════════════════════════════════════════════════════

pub async fn networks_list_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.list_internal_networks().await {
        Ok(nets) => Ok(Json(serde_json::json!({ "networks": nets }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

pub async fn networks_add_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let cidr = body["cidr"].as_str().unwrap_or("");
    let label = body["label"].as_str();
    let zone = body["zone"].as_str();
    match store.add_internal_network(cidr, label, zone).await {
        Ok(id) => Ok(Json(serde_json::json!({ "status": "ok", "id": id }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

pub async fn networks_delete_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let net_id: i64 = id.parse().unwrap_or(0);
    match store.delete_internal_network(net_id).await {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "deleted" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

// ════════════════════════════════════════════════════════════════
// COMPANY PROFILE
// ════════════════════════════════════════════════════════════════

pub async fn company_get_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.get_company_profile().await {
        Ok(profile) => Ok(Json(serde_json::json!(profile))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

// ════════════════════════════════════════════════════════════════
// DB HEALTH MONITORING
// ════════════════════════════════════════════════════════════════

pub async fn db_health_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    // Use execute_cypher for raw SQL (it handles connection pooling)
    // But we need a simpler approach — use get_dashboard_metrics + counts
    let metrics = store.get_dashboard_metrics().await.unwrap_or(crate::db::threatclaw_store::DashboardMetrics {
        security_score: 0.0, findings_critical: 0, findings_high: 0, findings_medium: 0, findings_low: 0,
        alerts_total: 0, alerts_new: 0, cloud_score: 0.0, darkweb_leaks: 0,
    });
    let assets = store.count_assets_by_category().await.unwrap_or_default();
    let total_assets: i64 = assets.iter().map(|(_, c)| c).sum();
    let log_count = store.count_logs(60 * 24).await.unwrap_or(0); // last 24h

    Ok(Json(serde_json::json!({
        "total_logs_24h": log_count,
        "total_alerts": metrics.alerts_total,
        "total_findings": metrics.findings_critical + metrics.findings_high + metrics.findings_medium + metrics.findings_low,
        "active_assets": total_assets,
        "security_score": metrics.security_score,
    })))
}

// ════════════════════════════════════════════════════════════════
// BACKUP / RESTORE
// ════════════════════════════════════════════════════════════════

pub async fn backup_export_handler(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let full = params.get("mode").map(|m| m == "full").unwrap_or(false);

    let mut backup = serde_json::json!({
        "version": "2.0.0",
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "mode": if full { "full" } else { "light" },
    });

    // Always export config
    let company = store.get_company_profile().await.unwrap_or_default();
    backup["company_profile"] = serde_json::json!(company);

    let networks = store.list_internal_networks().await.unwrap_or_default();
    backup["internal_networks"] = serde_json::json!(networks);

    let categories = store.list_asset_categories().await.unwrap_or_default();
    backup["asset_categories"] = serde_json::json!(categories);

    let assets = store.list_assets(None, None, 10000, 0).await.unwrap_or_default();
    backup["assets"] = serde_json::json!(assets);

    // Settings (config keys) — serialize manually since SettingRow may not impl Serialize
    let all_settings = store.list_settings("_system").await.unwrap_or_default();
    let settings_json: Vec<serde_json::Value> = all_settings.iter()
        .map(|s| serde_json::json!({"key": s.key, "value": s.value}))
        .collect();
    backup["settings"] = serde_json::json!(settings_json);

    // Full mode: include alerts + findings + logs
    if full {
        let alerts = store.list_alerts(None, None, 5000, 0).await.unwrap_or_default();
        backup["alerts"] = serde_json::json!(alerts);

        let findings = store.list_findings(None, None, None, 5000, 0).await.unwrap_or_default();
        backup["findings"] = serde_json::json!(findings);

        let logs = store.query_logs(60 * 24 * 30, None, None, 100000).await.unwrap_or_default(); // last 30 days
        backup["logs_count"] = serde_json::json!(logs.len());
        // Don't include raw logs in JSON (too big) — just the count
    }

    Ok(Json(backup))
}

pub async fn backup_import_handler(
    State(state): State<Arc<GatewayState>>,
    Json(backup): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let mut imported = vec![];

    // Import company profile
    if let Some(cp) = backup.get("company_profile") {
        if let Ok(profile) = serde_json::from_value::<crate::db::threatclaw_store::CompanyProfile>(cp.clone()) {
            let _ = store.update_company_profile(&profile).await;
            imported.push("company_profile");
        }
    }

    // Import internal networks
    if let Some(nets) = backup["internal_networks"].as_array() {
        for n in nets {
            let cidr = n["cidr"].as_str().unwrap_or("");
            let label = n["label"].as_str();
            let zone = n["zone"].as_str();
            if !cidr.is_empty() {
                let _ = store.add_internal_network(cidr, label, zone).await;
            }
        }
        imported.push("internal_networks");
    }

    // Import assets
    if let Some(assets) = backup["assets"].as_array() {
        for a in assets {
            if let Ok(asset) = serde_json::from_value::<crate::db::threatclaw_store::NewAsset>(a.clone()) {
                let _ = store.upsert_asset(&asset).await;
            }
        }
        imported.push("assets");
    }

    // Import custom categories
    if let Some(cats) = backup["asset_categories"].as_array() {
        for c in cats {
            if let Ok(cat) = serde_json::from_value::<crate::db::threatclaw_store::AssetCategory>(c.clone()) {
                if !cat.is_builtin {
                    let _ = store.upsert_asset_category(&cat).await;
                }
            }
        }
        imported.push("asset_categories");
    }

    Ok(Json(serde_json::json!({
        "status": "imported",
        "sections": imported,
        "mode": backup["mode"].as_str().unwrap_or("light"),
    })))
}

// ════════════════════════════════════════════════════════════════
// VERSION CHECK
// ════════════════════════════════════════════════════════════════

pub async fn version_check_handler(
    State(_state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let current = "2.0.0-beta";

    // Check GitHub for latest release
    let latest = match reqwest::Client::new()
        .get("https://api.github.com/repos/threatclaw/threatclaw/releases/latest")
        .header("User-Agent", "ThreatClaw")
        .timeout(std::time::Duration::from_secs(5))
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            body["tag_name"].as_str().unwrap_or(current).to_string()
        }
        _ => current.to_string(),
    };

    let update_available = latest != current && !latest.is_empty();

    Ok(Json(serde_json::json!({
        "current": current,
        "latest": latest,
        "update_available": update_available,
    })))
}

pub async fn company_update_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    use crate::db::threatclaw_store::CompanyProfile;
    let profile = CompanyProfile {
        company_name: body["company_name"].as_str().map(String::from),
        nace_code: body["nace_code"].as_str().map(String::from),
        sector: body["sector"].as_str().unwrap_or("other").to_string(),
        company_size: body["company_size"].as_str().unwrap_or("small").to_string(),
        employee_count: body["employee_count"].as_i64().map(|n| n as i32),
        country: body["country"].as_str().unwrap_or("FR").to_string(),
        business_hours: body["business_hours"].as_str().unwrap_or("office").to_string(),
        business_hours_start: body["business_hours_start"].as_str().unwrap_or("08:00").to_string(),
        business_hours_end: body["business_hours_end"].as_str().unwrap_or("18:00").to_string(),
        work_days: body["work_days"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["mon".into(),"tue".into(),"wed".into(),"thu".into(),"fri".into()]),
        geo_scope: body["geo_scope"].as_str().unwrap_or("france").to_string(),
        allowed_countries: body["allowed_countries"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| vec!["FR".into()]),
        blocked_countries: body["blocked_countries"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        critical_systems: body["critical_systems"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        compliance_frameworks: body["compliance_frameworks"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        anomaly_sensitivity: body["anomaly_sensitivity"].as_str().unwrap_or("medium").to_string(),
    };
    match store.update_company_profile(&profile).await {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "saved" }))),
        Err(e) => Ok(Json(serde_json::json!({ "error": e.to_string() }))),
    }
}

// ════════════════════════════════════════════════════════════════
// v1.7 CONNECTORS — Network (Pi-hole, UniFi, DHCP, MAC OUI)
// ════════════════════════════════════════════════════════════════

pub async fn connector_pihole_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let url = get_skill_config_field(store.as_ref(), "skill-pihole", "pihole_url").await;
    let password = get_skill_config_field(store.as_ref(), "skill-pihole", "pihole_password").await;
    let config = crate::connectors::pihole::PiholeConfig { url, password };
    let result = crate::connectors::pihole::sync_pihole(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

pub async fn connector_unifi_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let url = get_skill_config_field(store.as_ref(), "skill-unifi", "unifi_url").await;
    let username = get_skill_config_field(store.as_ref(), "skill-unifi", "unifi_username").await;
    let password = get_skill_config_field(store.as_ref(), "skill-unifi", "unifi_password").await;
    let site = get_skill_config_field(store.as_ref(), "skill-unifi", "unifi_site").await;
    let config = crate::connectors::unifi::UnifiConfig {
        url, username, password,
        site: if site.is_empty() { "default".into() } else { site },
        no_tls_verify: true,
    };
    let result = crate::connectors::unifi::sync_unifi(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

pub async fn connector_dhcp_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let result = crate::connectors::dhcp_parser::process_dhcp_logs(store.as_ref()).await;
    Ok(Json(serde_json::json!(result)))
}

// ── Freebox Connector ──

pub async fn connector_freebox_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let url = get_skill_config_field(store.as_ref(), "skill-freebox", "freebox_url").await;
    // Token may be stored as JSON string "token" or raw — handle both
    let app_token = {
        let raw = get_skill_config_field(store.as_ref(), "skill-freebox", "freebox_app_token").await;
        let trimmed = raw.trim().trim_matches('"').to_string();
        trimmed
    };
    tracing::debug!("FREEBOX SYNC: url={}, token_len={}", url, app_token.len());
    if app_token.is_empty() {
        return Ok(Json(serde_json::json!({"error": "Freebox app_token not configured. Run pairing first."})));
    }
    let config = crate::connectors::freebox::FreeboxConfig {
        url: if url.is_empty() { "http://mafreebox.freebox.fr".into() } else { url },
        app_token,
    };
    let result = crate::connectors::freebox::sync_freebox(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

pub async fn connector_freebox_pair_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let url = body["url"].as_str().unwrap_or("http://mafreebox.freebox.fr");

    match crate::connectors::freebox::request_pairing(url).await {
        Ok((token, track_id)) => {
            let _ = store.set_setting("_system", "freebox_pending_token", &serde_json::json!({
                "app_token": token,
                "track_id": track_id,
                "url": url,
            })).await;
            Ok(Json(serde_json::json!({
                "status": "pending",
                "track_id": track_id,
                "message": "Appuyez sur le bouton de votre Freebox pour autoriser ThreatClaw.",
            })))
        }
        Err(e) => Ok(Json(serde_json::json!({"error": e}))),
    }
}

pub async fn connector_freebox_pair_status_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    // Check if already paired (token exists and is non-empty)
    let existing_token = get_skill_config_field(store.as_ref(), "skill-freebox", "freebox_app_token").await;
    let existing_trimmed = existing_token.trim().trim_matches('"');
    if !existing_trimmed.is_empty() {
        return Ok(Json(serde_json::json!({"status": "granted", "message": "Freebox appairée"})));
    }

    let pending = store.get_setting("_system", "freebox_pending_token").await.ok().flatten();
    if pending.is_none() || pending.as_ref().map(|v| v.is_null()).unwrap_or(true) {
        return Ok(Json(serde_json::json!({"status": "no_pending"})));
    }
    let pending = pending.unwrap();
    let url = pending["url"].as_str().unwrap_or("http://mafreebox.freebox.fr");
    let track_id = pending["track_id"].as_i64().unwrap_or(0);
    let app_token = pending["app_token"].as_str().unwrap_or("");

    match crate::connectors::freebox::check_pairing_status(url, track_id).await {
        Ok(status) => {
            if status == "granted" {
                tracing::info!("FREEBOX PAIR: Granted! Token length: {}", app_token.len());
                let _ = store.set_setting("skill-freebox", "freebox_app_token", &serde_json::Value::String(app_token.to_string())).await;
                let _ = store.set_setting("skill-freebox", "freebox_url", &serde_json::Value::String(url.to_string())).await;
                let _ = store.set_setting("_system", "freebox_pending_token", &serde_json::json!(null)).await;
                Ok(Json(serde_json::json!({"status": "granted", "message": "Freebox appairée !"})))
            } else {
                Ok(Json(serde_json::json!({"status": status})))
            }
        }
        Err(e) => Ok(Json(serde_json::json!({"status": "error", "error": e}))),
    }
}

pub async fn enrichment_mac_handler(
    State(_state): State<Arc<GatewayState>>,
    Path(mac): Path<String>,
) -> ApiResult<serde_json::Value> {
    let result = crate::enrichment::mac_oui_lookup::lookup(&mac);
    Ok(Json(serde_json::json!(result)))
}

// ════════════════════════════════════════════════════════════════
// v1.8 — Zeek + Suricata Connectors
// ════════════════════════════════════════════════════════════════

pub async fn connector_zeek_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let log_dir = get_skill_config_field(store.as_ref(), "skill-zeek", "zeek_log_dir").await;
    let dir = if log_dir.is_empty() { "/opt/zeek/logs/current".to_string() } else { log_dir };
    let config = crate::connectors::zeek::ZeekConfig { log_dir: dir, sync_interval_minutes: 5 };
    let result = crate::connectors::zeek::sync_zeek(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

pub async fn connector_suricata_sync_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let eve_path = get_skill_config_field(store.as_ref(), "skill-suricata", "eve_json_path").await;
    let path = if eve_path.is_empty() { "/var/log/suricata/eve.json".to_string() } else { eve_path };
    let config = crate::connectors::suricata::SuricataConfig { eve_json_path: path };
    let result = crate::connectors::suricata::sync_suricata(store.as_ref(), &config).await;
    Ok(Json(serde_json::json!(result)))
}

// ════════════════════════════════════════════════════════════════
// v1.9 — NACE Threat Profiles
// ════════════════════════════════════════════════════════════════

pub async fn threat_profiles_list_handler(
    State(_state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let profiles = crate::agent::nace_profiles::list_profiles();
    Ok(Json(serde_json::json!({ "profiles": profiles })))
}

pub async fn threat_profile_handler(
    State(_state): State<Arc<GatewayState>>,
    Path(sector): Path<String>,
) -> ApiResult<serde_json::Value> {
    let profile = crate::agent::nace_profiles::get_profile(&sector);
    Ok(Json(serde_json::json!(profile)))
}

// ════════════════════════════════════════════════════════════════
// EXPORTS — Rapports & Data
// ════════════════════════════════════════════════════════════════

/// Generic data export (assets, alerts, findings, IOCs, audit trail)
pub async fn export_data_handler(
    State(state): State<Arc<GatewayState>>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let path = uri.path();
    let company = store.get_company_profile().await.unwrap_or_default();

    if path.contains("assets") {
        let assets = store.list_assets(None, None, 10000, 0).await.unwrap_or_default();
        return Ok(Json(serde_json::json!({
            "type": "assets", "company_name": company.company_name,
            "exported_at": chrono::Utc::now().to_rfc3339(), "count": assets.len(),
            "data": assets,
        })));
    }

    if path.contains("alerts") {
        let alerts = store.list_alerts(None, None, 5000, 0).await.unwrap_or_default();
        return Ok(Json(serde_json::json!({
            "type": "alerts", "company_name": company.company_name,
            "exported_at": chrono::Utc::now().to_rfc3339(), "count": alerts.len(),
            "data": alerts,
        })));
    }

    if path.contains("findings") {
        let findings = store.list_findings(None, None, None, 5000, 0).await.unwrap_or_default();
        return Ok(Json(serde_json::json!({
            "type": "findings", "company_name": company.company_name,
            "exported_at": chrono::Utc::now().to_rfc3339(), "count": findings.len(),
            "data": findings,
        })));
    }

    if path.contains("iocs") {
        // Extract IOCs from alerts (source IPs) + findings (CVEs)
        let alerts = store.list_alerts(None, None, 10000, 0).await.unwrap_or_default();
        let mut ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for a in &alerts {
            if let Some(ref ip) = a.source_ip {
                let clean = ip.split('/').next().unwrap_or("").trim().to_string();
                if !clean.is_empty() && !crate::agent::ip_classifier::is_non_routable(&clean) {
                    ips.insert(clean);
                }
            }
        }
        return Ok(Json(serde_json::json!({
            "type": "iocs", "company_name": company.company_name,
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "malicious_ips": ips.iter().collect::<Vec<_>>(),
            "total_ips": ips.len(),
        })));
    }

    if path.contains("audit") {
        // Return audit log entries
        return Ok(Json(serde_json::json!({
            "type": "audit-trail", "company_name": company.company_name,
            "exported_at": chrono::Utc::now().to_rfc3339(),
            "note": "Audit trail export — actions de l'agent ThreatClaw",
        })));
    }

    Ok(Json(serde_json::json!({"error": "Unknown export type"})))
}

/// STIX 2.1 Bundle / MISP Event export
pub async fn export_stix2_handler(
    State(state): State<Arc<GatewayState>>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let company = store.get_company_profile().await.unwrap_or_default();
    let is_misp = uri.path().contains("misp");

    // Fetch graph data
    let alerts = store.list_alerts(None, None, 1000, 0).await.unwrap_or_default();
    let findings = store.list_findings(None, None, None, 1000, 0).await.unwrap_or_default();
    let assets = store.list_assets(None, None, 1000, 0).await.unwrap_or_default();

    if is_misp {
        // MISP Event format
        let event = serde_json::json!({
            "Event": {
                "info": format!("ThreatClaw Export — {}", company.company_name.as_deref().unwrap_or("Unknown")),
                "date": chrono::Utc::now().format("%Y-%m-%d").to_string(),
                "threat_level_id": "2",
                "analysis": "2",
                "published": false,
                "Attribute": alerts.iter().take(100).filter_map(|a| {
                    a.source_ip.as_ref().map(|ip| serde_json::json!({
                        "type": "ip-src", "value": ip.split('/').next().unwrap_or(""),
                        "category": "Network activity", "to_ids": true,
                        "comment": a.title,
                    }))
                }).collect::<Vec<_>>(),
            }
        });
        return Ok(Json(event));
    }

    // STIX 2.1 Bundle
    let mut objects = vec![
        serde_json::json!({
            "type": "identity", "spec_version": "2.1",
            "id": format!("identity--{}", uuid::Uuid::new_v4()),
            "name": company.company_name.as_deref().unwrap_or("ThreatClaw Instance"),
            "identity_class": "organization",
            "created": chrono::Utc::now().to_rfc3339(),
        }),
    ];

    // Add indicators from alerts
    for a in alerts.iter().take(50) {
        if let Some(ref ip) = a.source_ip {
            let clean = ip.split('/').next().unwrap_or("").trim();
            if !clean.is_empty() && !clean.starts_with("192.168.") {
                objects.push(serde_json::json!({
                    "type": "indicator", "spec_version": "2.1",
                    "id": format!("indicator--{}", uuid::Uuid::new_v4()),
                    "name": format!("Malicious IP: {}", clean),
                    "pattern": format!("[ipv4-addr:value = '{}']", clean),
                    "pattern_type": "stix",
                    "valid_from": a.matched_at,
                    "description": a.title,
                }));
            }
        }
    }

    let bundle = serde_json::json!({
        "type": "bundle", "id": format!("bundle--{}", uuid::Uuid::new_v4()),
        "spec_version": "2.1",
        "objects": objects,
    });

    Ok(Json(bundle))
}

/// Compile a Typst template to PDF. Writes data.json to a temp dir, copies template + common.typ, runs typst compile.
fn compile_typst_pdf(template_name: &str, data: &serde_json::Value) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let tmp = std::env::temp_dir().join(format!("tc-report-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| format!("mkdir: {e}"))?;

    // Write data.json
    let data_path = tmp.join("data.json");
    let mut f = std::fs::File::create(&data_path).map_err(|e| format!("data.json: {e}"))?;
    f.write_all(serde_json::to_string_pretty(data).unwrap().as_bytes()).map_err(|e| format!("write: {e}"))?;

    // Copy template + common.typ
    let tpl_dir = std::path::Path::new("templates");
    let common_src = tpl_dir.join("common.typ");
    let tpl_src = tpl_dir.join(format!("{template_name}.typ"));

    if !tpl_src.exists() {
        return Err(format!("Template not found: {}", tpl_src.display()));
    }

    std::fs::copy(&common_src, tmp.join("common.typ")).map_err(|e| format!("copy common: {e}"))?;
    std::fs::copy(&tpl_src, tmp.join(format!("{template_name}.typ"))).map_err(|e| format!("copy tpl: {e}"))?;

    // Copy label files for multilingual templates
    let labels_dir = tpl_dir.join("labels");
    if labels_dir.exists() {
        let tmp_labels = tmp.join("labels");
        std::fs::create_dir_all(&tmp_labels).map_err(|e| format!("mkdir labels: {e}"))?;
        if let Ok(entries) = std::fs::read_dir(&labels_dir) {
            for entry in entries.flatten() {
                if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                    let _ = std::fs::copy(entry.path(), tmp_labels.join(entry.file_name()));
                }
            }
        }
    }

    let output_pdf = tmp.join("output.pdf");

    // Run typst compile
    let result = std::process::Command::new("typst")
        .arg("compile")
        .arg(format!("{template_name}.typ"))
        .arg("output.pdf")
        .current_dir(&tmp)
        .output()
        .map_err(|e| format!("typst exec: {e}"))?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(format!("typst compile failed: {stderr}"));
    }

    let pdf_bytes = std::fs::read(&output_pdf).map_err(|e| format!("read pdf: {e}"))?;

    // Cleanup temp dir
    let _ = std::fs::remove_dir_all(&tmp);

    Ok(pdf_bytes)
}

/// Report generation (NIS2, executive, technical) — JSON or PDF via Typst
pub async fn export_report_handler(
    State(state): State<Arc<GatewayState>>,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let format = body.get("format").and_then(|f| f.as_str()).unwrap_or("json");
    let report_locale = body.get("locale").and_then(|l| l.as_str()).unwrap_or("fr");
    let store = match state.store.as_ref() {
        Some(s) => s,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "Database not available").into_response(),
    };
    let company = store.get_company_profile().await.unwrap_or_default();
    let path = uri.path();
    let now = chrono::Utc::now();

    let alerts = store.list_alerts(None, None, 1000, 0).await.unwrap_or_default();
    let findings = store.list_findings(None, None, None, 1000, 0).await.unwrap_or_default();
    let assets = store.list_assets(None, None, 1000, 0).await.unwrap_or_default();

    let situation = store.get_setting("_system", "security_situation").await.ok().flatten();
    let score = situation.as_ref().and_then(|s| s["global_score"].as_f64()).unwrap_or(100.0);

    let company_name = company.company_name.as_deref().unwrap_or("Organisation");
    let sector = company.sector.as_str();

    // ── Graph AGE: extract MITRE ATT&CK TTPs ──
    let mitre_ttps: Vec<String> = {
        let cypher = "MATCH (t:Technique) RETURN t.mitre_id, t.name, t.tactic LIMIT 20";
        let results = crate::graph::threat_graph::query(store.as_ref(), cypher).await;
        results.iter().filter_map(|r| {
            let id = r.get("t.mitre_id").and_then(|v| v.as_str());
            let name = r.get("t.name").and_then(|v| v.as_str());
            match (id, name) {
                (Some(i), Some(n)) => Some(format!("{i} — {n}")),
                (Some(i), None) => Some(i.to_string()),
                _ => None,
            }
        }).collect()
    };

    // ── ML scores: get anomaly scores for affected assets ──
    let ml_anomalies: Vec<serde_json::Value> = {
        let mut anomalies = Vec::new();
        for asset in assets.iter().take(50) {
            if let Ok(Some((ml_score, reason))) = store.get_ml_score(&asset.id).await {
                if ml_score > 0.5 { // anomaly threshold (0=normal, 1=anomalous)
                    anomalies.push(serde_json::json!({
                        "asset": asset.name,
                        "asset_id": asset.id,
                        "ml_score": format!("{:.2}", ml_score),
                        "reason": reason,
                        "category": asset.category,
                    }));
                }
            }
        }
        anomalies
    };

    // Common asset mapping for NIS2 reports
    let asset_json = |a: &crate::db::threatclaw_store::AssetRecord| serde_json::json!({
        "name": a.name, "category": a.category, "criticality": a.criticality,
        "ip": a.ip_addresses.first().unwrap_or(&"—".to_string()),
    });

    let notification_id = format!("TC-{}-{:03}", now.format("%Y-%m%d"), 1);
    let incident_id = format!("TC-INC-{}-001", now.format("%Y%m%d"));
    let generated_display = now.format("%d/%m/%Y %H:%M").to_string();
    let critical_alerts: Vec<_> = alerts.iter().filter(|a| a.level == "critical").collect();

    // Determine incident type from most frequent alert pattern
    let incident_type = if alerts.iter().any(|a| a.title.to_lowercase().contains("ransomware") || a.title.to_lowercase().contains("chiffr")) {
        "ransomware"
    } else if alerts.iter().any(|a| a.title.to_lowercase().contains("brute") || a.title.to_lowercase().contains("ssh") || a.title.to_lowercase().contains("intrusion")) {
        "intrusion"
    } else if alerts.iter().any(|a| a.title.to_lowercase().contains("ddos") || a.title.to_lowercase().contains("flood")) {
        "ddos"
    } else if alerts.iter().any(|a| a.title.to_lowercase().contains("fuite") || a.title.to_lowercase().contains("leak") || a.title.to_lowercase().contains("exfiltration")) {
        "data_leak"
    } else if alerts.iter().any(|a| a.title.to_lowercase().contains("malware") || a.title.to_lowercase().contains("trojan") || a.title.to_lowercase().contains("virus")) {
        "malware"
    } else if alerts.iter().any(|a| a.title.to_lowercase().contains("phishing") || a.title.to_lowercase().contains("hameçon")) {
        "phishing"
    } else {
        "other"
    };

    let incident_type_label = match incident_type {
        "ransomware" => "Ransomware / Chiffrement",
        "intrusion" => "Accès non autorisé / Intrusion",
        "ddos" => "DDoS / Déni de service",
        "data_leak" => "Fuite de données",
        "malware" => "Malware / Code malveillant",
        "phishing" => "Hameçonnage ciblé",
        _ => "Autre",
    };

    let incident_status = if score < 50.0 { "ongoing" } else if score < 80.0 { "contained" } else { "resolved" };
    let incident_status_label = match incident_status {
        "ongoing" => "En cours",
        "contained" => "Contenu",
        _ => "Résolu",
    };

    let severity = if score < 30.0 { "critical" } else if score < 50.0 { "high" } else if score < 70.0 { "medium" } else { "low" };

    // ── RGPD Art.33 auto-detection ──
    // Determine if personal data is likely involved → triggers CNIL notification
    let gdpr_required = {
        // Criterion 1: incident type is data leak
        let is_data_leak = incident_type == "data_leak";
        // Criterion 2: database assets are affected
        let db_assets_affected = assets.iter().any(|a| {
            let cat = a.category.to_lowercase();
            cat.contains("base de donn") || cat.contains("database") || cat.contains("bdd")
                || cat.contains("sql") || cat.contains("storage")
        });
        // Criterion 3: findings mention PII / personal data
        let pii_findings = findings.iter().any(|f| {
            let t = f.title.to_lowercase();
            let d = f.description.as_deref().unwrap_or("").to_lowercase();
            t.contains("pii") || t.contains("données personnelles") || t.contains("personal data")
                || t.contains("rgpd") || t.contains("gdpr") || t.contains("fuite")
                || t.contains("leak") || t.contains("exfiltration")
                || d.contains("pii") || d.contains("données personnelles") || d.contains("personal data")
        });
        // Criterion 4: alerts mention data exfiltration
        let exfil_alerts = alerts.iter().any(|a| {
            let t = a.title.to_lowercase();
            t.contains("exfiltration") || t.contains("data leak") || t.contains("fuite")
                || t.contains("données personnelles") || t.contains("pii")
        });

        if is_data_leak || pii_findings || exfil_alerts {
            "yes"
        } else if db_assets_affected && (severity == "critical" || severity == "high") {
            "likely"
        } else {
            "no"
        }
    };

    // Build the report data JSON + determine template name
    let (template_name, report_data_raw) = if path.contains("nis2-early") {
        let deadline_72h = (now + chrono::Duration::hours(72)).format("%d/%m/%Y %H:%M").to_string();
        ("nis2-early-warning", serde_json::json!({
            "org_name": company_name,
            "sector": sector,
            "sub_sector": company.nace_code.as_deref().unwrap_or("—"),
            "nis2_status": "Entité Essentielle / Importante",
            "security_contact": "RSSI",
            "contact_email": "—",
            "contact_phone": "—",
            "notification_id": notification_id,
            "generated_at_display": generated_display,
            "incident_id": incident_id,
            "detected_at": now.format("%d/%m/%Y %H:%M").to_string(),
            "notified_at": generated_display,
            "delay_hours": "0",
            "incident_type": incident_type,
            "incident_type_detail": if !critical_alerts.is_empty() { &critical_alerts[0].title } else { "Anomalie détectée" },
            "incident_description": format!("{} alertes détectées par ThreatClaw Engine, dont {} critiques. Score sécurité : {:.0}/100.", alerts.len(), critical_alerts.len(), score),
            "suspected_malicious": if critical_alerts.is_empty() { "unknown" } else { "yes" },
            "affected_assets": assets.iter().take(20).map(&asset_json).collect::<Vec<_>>(),
            "cross_border_impact": "unknown",
            "incident_status": incident_status,
            "deadline_72h": deadline_72h,
        }))
    } else if path.contains("nis2-intermediate") {
        let deadline_final = (now + chrono::Duration::days(30)).format("%d/%m/%Y").to_string();
        ("nis2-intermediate", serde_json::json!({
            "org_name": company_name,
            "sector": sector,
            "notification_id": notification_id,
            "early_warning_ref": format!("TC-{}-001", now.format("%Y-%m%d")),
            "generated_at_display": generated_display,
            "incident_id": incident_id,
            "detected_at": now.format("%d/%m/%Y %H:%M").to_string(),
            "incident_type_label": incident_type_label,
            "incident_status_label": incident_status_label,
            "alerts_count": alerts.len().to_string(),
            "findings_count": findings.len().to_string(),
            "assets_count": assets.len().to_string(),
            "score": format!("{:.0}", score),
            "severity": severity,
            "impact_scope": format!("{} assets dans le périmètre impacté, {} alertes de sécurité détectées.", assets.len(), alerts.len()),
            "affected_services": "En cours d'identification par ThreatClaw Engine.",
            "probable_cause": "Analyse en cours par ThreatClaw Engine. Corrélation multi-source et détection comportementale activées.",
            "attack_vector": "En cours d'identification",
            "iocs": alerts.iter().filter_map(|a| a.source_ip.as_ref()).take(10).map(|ip| serde_json::json!({
                "type": "IPv4", "value": ip, "source": "ThreatClaw Engine", "confidence": "Medium",
            })).collect::<Vec<_>>(),
            "affected_assets": assets.iter().take(20).map(&asset_json).collect::<Vec<_>>(),
            "cross_border_impact": "unknown",
            "deadline_final": deadline_final,
        }))
    } else if path.contains("nis2-final") {
        ("nis2-final", serde_json::json!({
            "org_name": company_name,
            "sector": sector,
            "notification_id": notification_id,
            "early_warning_ref": format!("TC-{}-001", now.format("%Y-%m%d")),
            "generated_at_display": generated_display,
            "incident_id": incident_id,
            "incident_type_label": incident_type_label,
            "detected_at": now.format("%d/%m/%Y %H:%M").to_string(),
            "closure_date": now.format("%d/%m/%Y").to_string(),
            "incident_duration": "En cours d'évaluation",
            "final_severity": severity,
            "score": format!("{:.0}", score),
            "alerts_count": alerts.len().to_string(),
            "findings_count": findings.len().to_string(),
            "assets_count": assets.len().to_string(),
            "full_description": format!("L'incident a été détecté par ThreatClaw Engine. {} alertes ont été générées, dont {} critiques. {} vulnérabilités ont été identifiées sur {} assets.", alerts.len(), critical_alerts.len(), findings.len(), assets.len()),
            "root_cause": "Analyse des causes racines consolidée par ThreatClaw Engine à partir des corrélations multi-sources et du graph d'attaque.",
            "attack_vector": "En cours d'identification",
            "operational_impact": if score < 50.0 { "Impact significatif détecté" } else { "Impact limité grâce à la détection précoce" },
            "financial_impact": "En cours d'évaluation",
            "data_exposed": "Aucune donnée personnelle identifiée comme exposée",
            "affected_users": "—",
            "affected_assets": assets.iter().take(30).map(&asset_json).collect::<Vec<_>>(),
            "notified_authority": "ANSSI / CSIRT-FR",
            "gdpr_notification_required": gdpr_required,
            "timeline": [],
            "mitre_ttps": mitre_ttps,
        }))
    } else if path.contains("article21") {
        let measures = vec![
            serde_json::json!({"title": "Politiques de sécurité des SI", "status": "partial", "score": "60", "covered_by": "ThreatClaw Engine + Config"}),
            serde_json::json!({"title": "Gestion des incidents", "status": "covered", "score": "90", "covered_by": "Intelligence Engine + Alertes + Rapports NIS2"}),
            serde_json::json!({"title": "Continuité d'activité", "status": "partial", "score": "40", "covered_by": "Monitoring uptime"}),
            serde_json::json!({"title": "Sécurité chaîne d'approvisionnement", "status": "covered", "score": "70", "covered_by": "Supply Chain Graph Analysis"}),
            serde_json::json!({"title": "Sécurité acquisition/développement", "status": "partial", "score": "50", "covered_by": "Trivy + Semgrep scans"}),
            serde_json::json!({"title": "Évaluation efficacité mesures", "status": "covered", "score": "85", "covered_by": "Score sécurité + ML baselines"}),
            serde_json::json!({"title": "Pratiques d'hygiène cyber", "status": "covered", "score": "75", "covered_by": "Lynis + Docker Bench audits"}),
            serde_json::json!({"title": "Cryptographie", "status": "covered", "score": "80", "covered_by": "SSL Labs + Observatory checks"}),
            serde_json::json!({"title": "Ressources humaines", "status": "not_covered", "score": "0", "covered_by": "Hors périmètre ThreatClaw"}),
            serde_json::json!({"title": "Contrôle d'accès + authentification", "status": "covered", "score": "70", "covered_by": "AD Audit + HIBP + Identity Graph"}),
        ];
        ("nis2-article21", serde_json::json!({
            "company_name": company_name,
            "global_score": "62",
            "measures": measures,
        }))
    } else if path.contains("executive") {
        ("executive-report", serde_json::json!({
            "company_name": company_name,
            "period": format!("{}", now.format("%B %Y")),
            "score": format!("{:.0}", score),
            "alerts_count": alerts.len().to_string(),
            "critical_count": alerts.iter().filter(|a| a.level == "critical").count().to_string(),
            "assets_count": assets.len().to_string(),
            "alerts": alerts.iter().filter(|a| a.level == "critical").take(10).map(|a| serde_json::json!({
                "date": a.matched_at.chars().take(10).collect::<String>(),
                "title": a.title,
                "source": a.source_ip.as_deref().unwrap_or("—"),
            })).collect::<Vec<_>>(),
        }))
    } else if path.contains("technical") {
        ("technical-report", serde_json::json!({
            "company_name": company_name,
            "period": format!("{}", now.format("%B %Y")),
            "score": format!("{:.0}", score),
            "alerts_count": alerts.len().to_string(),
            "findings_count": findings.len().to_string(),
            "critical_count": alerts.iter().filter(|a| a.level == "critical").count().to_string(),
            "assets_count": assets.len().to_string(),
            "alerts": alerts.iter().take(50).map(|a| serde_json::json!({
                "level": a.level, "title": a.title, "date": a.matched_at.chars().take(10).collect::<String>(),
                "source_ip": a.source_ip.as_deref().unwrap_or("—"),
            })).collect::<Vec<_>>(),
            "findings": findings.iter().take(50).map(|f| serde_json::json!({
                "title": f.title, "severity": f.severity,
                "asset": f.asset.as_deref().unwrap_or("—"),
                "source": f.source.as_deref().unwrap_or("—"),
            })).collect::<Vec<_>>(),
            "assets": assets.iter().take(50).map(|a| serde_json::json!({
                "name": a.name, "category": a.category, "criticality": a.criticality,
                "ip": a.ip_addresses.first().unwrap_or(&"—".to_string()),
            })).collect::<Vec<_>>(),
            "ml_anomalies": ml_anomalies,
            "mitre_ttps": mitre_ttps,
        }))
    } else if path.contains("audit-trail") {
        ("audit-trail", serde_json::json!({
            "company_name": company_name,
            "period": format!("{}", now.format("%B %Y")),
            "period_start": now.format("%d/%m/%Y").to_string(),
            "period_end": now.format("%d/%m/%Y").to_string(),
            "entries": [],
            "journal_hash": "sha256:pending",
        }))
    } else if path.contains("gdpr") {
        let risk_level = if incident_type == "data_leak" { "high" } else if gdpr_required == "yes" { "high" } else if gdpr_required == "likely" { "medium" } else { "low" };
        ("gdpr-article33", serde_json::json!({
            "org_name": company_name,
            "sector": sector,
            "notification_id": format!("TC-RGPD-{}-001", now.format("%Y%m%d")),
            "generated_at_display": generated_display,
            "security_contact": "RSSI",
            "contact_email": "—",
            "contact_phone": "—",
            "dpo_contact": "DPO",
            "dpo_email": "—",
            "incident_type_label": incident_type_label,
            "incident_description": format!("{} alertes détectées, score sécurité {:.0}/100.", alerts.len(), score),
            "data_subject_categories": "En cours d'évaluation",
            "affected_persons_count": "En cours d'évaluation",
            "data_categories": "En cours d'évaluation",
            "affected_records_count": "En cours d'évaluation",
            "probable_consequences": "Évaluation en cours par ThreatClaw Engine.",
            "risk_level": risk_level,
            "affected_assets": assets.iter().take(20).map(&asset_json).collect::<Vec<_>>(),
            "nis2_notification_sent": "yes",
        }))
    } else if path.contains("nist") {
        ("nist-incident", serde_json::json!({
            "org_name": company_name,
            "sector": sector,
            "generated_at_display": generated_display,
            "incident_id": incident_id,
            "security_contact": "RSSI",
            "contact_email": "—",
            "contact_phone": "—",
            "alerts_count": alerts.len().to_string(),
            "findings_count": findings.len().to_string(),
            "assets_count": assets.len().to_string(),
            "score": format!("{:.0}", score),
            "detected_at": now.format("%d/%m/%Y %H:%M").to_string(),
            "notified_at": generated_display,
            "incident_status_label": incident_status_label,
            "incident_type_label": incident_type_label,
            "severity": severity,
            "attack_vector": "Under investigation",
            "incident_description": format!("{} alerts detected, {} critical. Security score: {:.0}/100.", alerts.len(), critical_alerts.len(), score),
            "affected_assets": assets.iter().take(30).map(&asset_json).collect::<Vec<_>>(),
            "iocs": alerts.iter().filter_map(|a| a.source_ip.as_ref()).take(10).map(|ip| serde_json::json!({
                "type": "IPv4", "value": ip, "source": "ThreatClaw Engine", "confidence": "Medium",
            })).collect::<Vec<_>>(),
            "root_cause": "Under investigation by ThreatClaw Engine.",
            "operational_impact": if score < 50.0 { "Significant impact detected" } else { "Limited impact" },
            "data_exposed": "No data exposure identified",
            "financial_impact": "Under evaluation",
            "recoverability": if score >= 70.0 { "Recoverable" } else { "Supplemented" },
            "mitre_ttps": mitre_ttps,
        }))
    } else if path.contains("iso27001") {
        ("iso27001-incident", serde_json::json!({
            "org_name": company_name,
            "sector": sector,
            "generated_at_display": generated_display,
            "incident_id": incident_id,
            "incident_type_label": incident_type_label,
            "severity": severity,
            "detected_at": now.format("%d/%m/%Y %H:%M").to_string(),
            "incident_status_label": incident_status_label,
            "incident_description": format!("{} alertes détectées, score sécurité {:.0}/100.", alerts.len(), score),
            "alerts_count": alerts.len().to_string(),
            "findings_count": findings.len().to_string(),
            "assets_count": assets.len().to_string(),
            "score": format!("{:.0}", score),
            "affected_assets": assets.iter().take(30).map(&asset_json).collect::<Vec<_>>(),
            "iocs": alerts.iter().filter_map(|a| a.source_ip.as_ref()).take(10).map(|ip| serde_json::json!({
                "type": "IPv4", "value": ip, "source": "ThreatClaw Engine", "confidence": "Medium",
            })).collect::<Vec<_>>(),
            "root_cause": "Analyse en cours par ThreatClaw Engine.",
            "attack_vector": "En cours d'identification",
            "notified_authority": "À évaluer",
            "nis2_notification_sent": "no",
            "gdpr_notification_required": gdpr_required,
            "mitre_ttps": mitre_ttps,
        }))
    } else {
        return (StatusCode::BAD_REQUEST, "Unknown report type").into_response();
    };

    // Inject locale into report data for multilingual templates
    let mut report_data = report_data_raw;
    if let Some(obj) = report_data.as_object_mut() {
        obj.insert("locale".into(), serde_json::json!(report_locale));
    }

    // JSON format → return data as JSON
    if format != "pdf" {
        return Json(report_data).into_response();
    }

    // PDF format → compile via Typst
    match compile_typst_pdf(template_name, &report_data) {
        Ok(pdf_bytes) => {
            let filename = format!("threatclaw_{}_{}_{}.pdf",
                template_name,
                company_name.replace(' ', "_"),
                now.format("%Y%m%d"),
            );
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/pdf")
                .header("Content-Disposition", format!("attachment; filename=\"{filename}\""))
                .header("Content-Length", pdf_bytes.len().to_string())
                .body(axum::body::Body::from(pdf_bytes))
                .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Response build error").into_response())
        }
        Err(e) => {
            tracing::error!("Typst PDF compilation failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("PDF generation failed: {e}")).into_response()
        }
    }
}

// ══════════════════════════════════════════════════════════
// LOG SOURCES STATS
// ══════════════════════════════════════════════════════════

/// GET /api/tc/logs/stats — log reception statistics for the Sources page.
pub async fn log_stats_handler(
    State(state): State<Arc<GatewayState>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;

    // Count logs (using existing count_logs method with minutes_back)
    let today_count = match store.count_logs(1440).await {
        Ok(c) => c,
        Err(e) => { tracing::error!("LOG_STATS: count_logs failed: {e}"); 0 }
    };
    let total_count = match store.count_logs(43200).await {
        Ok(c) => c,
        Err(e) => { tracing::error!("LOG_STATS: count_logs 30d failed: {e}"); 0 }
    };

    // Get last log to find time + count distinct sources
    let recent_logs = match store.query_logs(60, None, None, 1).await {
        Ok(l) => l,
        Err(e) => { tracing::error!("LOG_STATS: query_logs failed: {e}"); vec![] }
    };
    let last_received = recent_logs.first().map(|l| l.time.clone());

    // Count distinct hostnames from recent logs
    let all_recent = store.query_logs(1440, None, None, 1000).await.unwrap_or_default();
    let sources: std::collections::HashSet<&str> = all_recent.iter()
        .filter_map(|l| l.hostname.as_deref())
        .collect();

    Ok(Json(serde_json::json!({
        "today": today_count,
        "total_30d": total_count,
        "last_received": last_received,
        "sources_count": sources.len(),
        "syslog_port": 514,
    })))
}

// ══════════════════════════════════════════════════════════
// SYSTEM LOGS
// ══════════════════════════════════════════════════════════

/// GET /api/tc/system-logs — get recent system events (audit, auth, notifications, intelligence).
pub async fn system_logs_handler(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let limit = params.get("limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(50);

    let mut events: Vec<serde_json::Value> = Vec::new();

    // Collect audit events (conv_bot actions)
    if let Ok(all) = store.get_all_settings("_audit").await {
        for (key, val) in &all {
            events.push(serde_json::json!({
                "type": "audit",
                "key": key,
                "action": val.get("action").and_then(|v| v.as_str()).unwrap_or("?"),
                "target": val.get("target"),
                "success": val.get("success"),
                "timestamp": val.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""),
                "channel": val.get("channel").and_then(|v| v.as_str()).unwrap_or(""),
            }));
        }
    }

    // Collect auth events
    if let Ok(all) = store.get_all_settings("_auth_log").await {
        for (key, val) in &all {
            events.push(serde_json::json!({
                "type": "auth",
                "key": key,
                "event": val.get("event").and_then(|v| v.as_str()).unwrap_or("?"),
                "email": val.get("email").and_then(|v| v.as_str()).unwrap_or(""),
                "ip": val.get("ip").and_then(|v| v.as_str()).unwrap_or(""),
                "timestamp": val.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""),
            }));
        }
    }

    // Collect notification events
    if let Ok(all) = store.get_all_settings("_notifications").await {
        for (key, val) in &all {
            events.push(serde_json::json!({
                "type": "notification",
                "key": key,
                "level": val.get("level").and_then(|v| v.as_str()).unwrap_or("?"),
                "channel": val.get("channel").and_then(|v| v.as_str()).unwrap_or(""),
                "timestamp": val.get("timestamp").and_then(|v| v.as_str()).unwrap_or(""),
            }));
        }
    }

    // Sort by timestamp desc
    events.sort_by(|a, b| {
        let ta = a["timestamp"].as_str().unwrap_or("");
        let tb = b["timestamp"].as_str().unwrap_or("");
        tb.cmp(ta)
    });
    events.truncate(limit);

    // Get system info
    let paused = store.get_setting("_system", "tc_paused").await
        .ok().flatten().and_then(|v| v.as_bool()).unwrap_or(false);

    Ok(Json(serde_json::json!({
        "events": events,
        "total": events.len(),
        "paused": paused,
    })))
}

// ══════════════════════════════════════════════════════════
// DASHBOARD AUTHENTICATION
// ══════════════════════════════════════════════════════════

/// GET /api/auth/status — check if auth is configured (any user exists).
pub async fn auth_status_handler(
    State(state): State<Arc<GatewayState>>,
) -> impl IntoResponse {
    let store = match state.store.as_ref() {
        Some(s) => s,
        None => return Json(serde_json::json!({ "configured": false, "error": "no_db" })).into_response(),
    };

    let has_user = crate::channels::web::dashboard_auth::has_any_user(store).await;
    Json(serde_json::json!({
        "configured": has_user,
        "requires_setup": !has_user,
    })).into_response()
}

/// POST /api/auth/setup — create first admin user (first-run only).
pub async fn auth_setup_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let store = match state.store.as_ref() {
        Some(s) => s,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "DB unavailable" }))).into_response(),
    };

    let email = body["email"].as_str().unwrap_or("");
    let password = body["password"].as_str().unwrap_or("");
    let display_name = body["displayName"].as_str().unwrap_or(email);

    match crate::channels::web::dashboard_auth::create_admin(store, email, password, display_name).await {
        Ok(user) => {
            tracing::info!("AUTH SETUP: Admin created — {}", user.email);
            Json(serde_json::json!({
                "ok": true,
                "user": user,
            })).into_response()
        }
        Err(e) => {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": e }))).into_response()
        }
    }
}

/// POST /api/auth/login — authenticate and create session.
pub async fn auth_login_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let store = match state.store.as_ref() {
        Some(s) => s,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "DB unavailable" }))).into_response(),
    };

    let email = body["email"].as_str().unwrap_or("");
    let password = body["password"].as_str().unwrap_or("");
    let ip = headers.get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let user_agent = headers.get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    match crate::channels::web::dashboard_auth::authenticate(store, email, password, ip, user_agent).await {
        Ok((user, token)) => {
            let cookie = crate::channels::web::dashboard_auth::build_session_cookie(
                &token, crate::channels::web::dashboard_auth::SESSION_DURATION_SECS
            );
            let mut response = Json(serde_json::json!({
                "ok": true,
                "user": user,
            })).into_response();
            response.headers_mut().insert(
                axum::http::header::SET_COOKIE,
                axum::http::HeaderValue::from_str(&cookie).unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
            );
            response
        }
        Err(e) => {
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": e }))).into_response()
        }
    }
}

/// POST /api/auth/logout — destroy session.
pub async fn auth_logout_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Some(store) = state.store.as_ref() {
        if let Some(cookie) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
            if let Some(token) = crate::channels::web::dashboard_auth::extract_session_cookie(cookie) {
                crate::channels::web::dashboard_auth::delete_session(store, &token).await;
            }
        }
    }
    let mut response = Json(serde_json::json!({ "ok": true })).into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&crate::channels::web::dashboard_auth::clear_session_cookie()).unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
    );
    response
}

/// POST /api/auth/password — change password (requires current session).
pub async fn auth_change_password_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let store = match state.store.as_ref() {
        Some(s) => s,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "DB unavailable" }))).into_response(),
    };

    // Validate session
    let cookie = headers.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = match crate::channels::web::dashboard_auth::extract_session_cookie(cookie) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Non authentifié" }))).into_response(),
    };
    let user = match crate::channels::web::dashboard_auth::validate_session(store, &token).await {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "Session invalide" }))).into_response(),
    };

    let current_password = body["currentPassword"].as_str().unwrap_or("");
    let new_password = body["newPassword"].as_str().unwrap_or("");

    if new_password.len() < 8 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": "Le nouveau mot de passe doit faire au moins 8 caractères" }))).into_response();
    }

    // Verify current password by re-authenticating
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("unknown");
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("unknown");
    match crate::channels::web::dashboard_auth::authenticate(store, &user.email, current_password, ip, ua).await {
        Ok(_) => {}
        Err(_) => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "ok": false, "error": "Mot de passe actuel incorrect" }))).into_response(),
    }

    // Update password
    match crate::channels::web::dashboard_auth::change_password(store, &user.email, new_password).await {
        Ok(_) => {
            tracing::info!("AUTH: Password changed for {}", user.email);
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "ok": false, "error": e }))).into_response(),
    }
}

/// GET /api/auth/me — get current user info from session.
pub async fn auth_me_handler(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    let store = match state.store.as_ref() {
        Some(s) => s,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "not_authenticated" }))).into_response(),
    };

    // Try session cookie
    if let Some(cookie) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        if let Some(token) = crate::channels::web::dashboard_auth::extract_session_cookie(cookie) {
            if let Some(user) = crate::channels::web::dashboard_auth::validate_session(store, &token).await {
                return Json(serde_json::json!({
                    "authenticated": true,
                    "user": user,
                })).into_response();
            }
        }
    }

    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({
        "authenticated": false,
    }))).into_response()
}

// ══════════════════════════════════════════════════════════
// INCIDENTS — See ADR-043
// ══════════════════════════════════════════════════════════

/// GET /api/tc/incidents — list incidents
pub async fn incidents_list_handler(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let status = params.get("status").map(|s| s.as_str());
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50i64);
    let offset = params.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0i64);
    let incidents = store.list_incidents(status, limit, offset).await.map_err(db_err)?;
    Ok(Json(serde_json::json!({ "incidents": incidents, "total": incidents.len() })))
}

/// GET /api/tc/incidents/:id — get incident detail
pub async fn incident_detail_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<i32>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.get_incident(id).await.map_err(db_err)? {
        Some(incident) => Ok(Json(incident)),
        None => Err((StatusCode::NOT_FOUND, "Incident not found".into())),
    }
}

/// POST /api/tc/incidents/:id/hitl — HITL response (approve/reject) — See ADR-044
pub async fn incident_hitl_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<i32>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let response = body["response"].as_str().unwrap_or("reject");
    let responded_by = body["responded_by"].as_str().unwrap_or("dashboard");

    store.update_incident_hitl(id, "responded", responded_by, response).await.map_err(db_err)?;

    if response.starts_with("approve") || response == "execute" {
        // ADR-044: Execute real remediation through the guard
        let (success, msg) = crate::agent::remediation_engine::execute_incident_remediation(
            store.clone(), id, response
        ).await;
        tracing::info!("INCIDENT #{}: HITL {} via {} — success={} msg={}", id, response, responded_by, success, msg);
        if success {
            store.update_incident_status(id, "resolved").await.map_err(db_err)?;
        }
        return Ok(Json(serde_json::json!({ "status": "ok", "incident_id": id, "response": response, "remediation": { "success": success, "message": msg } })));
    } else if response == "false_positive" {
        store.update_incident_status(id, "closed").await.map_err(db_err)?;
    }

    Ok(Json(serde_json::json!({ "status": "ok", "incident_id": id, "response": response })))
}

/// POST /api/tc/incidents/:id/status — update incident status
pub async fn incident_status_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<i32>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    let status = body["status"].as_str().unwrap_or("open");
    store.update_incident_status(id, status).await.map_err(db_err)?;
    Ok(Json(serde_json::json!({ "status": "ok", "incident_id": id, "new_status": status })))
}

/// GET /api/tc/settings/{user_id}/{key} — read a setting value
pub async fn settings_read_handler(
    State(state): State<Arc<GatewayState>>,
    Path((user_id, key)): Path<(String, String)>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.as_ref().ok_or_else(no_db)?;
    match store.get_setting(&user_id, &key).await {
        Ok(Some(val)) => Ok(Json(serde_json::json!({ "user_id": user_id, "key": key, "value": val }))),
        Ok(None) => Ok(Json(serde_json::json!({ "user_id": user_id, "key": key, "value": null }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e))),
    }
}
