//! Shift Report (Quart de Veille) — periodic L2 forensic situation analysis.
//!
//! Runs every N hours (configurable, default 4h). Collects all findings, alerts,
//! and ML scores since the last shift, then asks L2 to produce a structured
//! situation briefing. Only notifies the RSSI if the situation score exceeds
//! a configurable threshold.
//!
//! Design: if nothing happened → no L2 call, no notification. If activity but
//! below threshold → log only. If above threshold or daily summary hour → notify.

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::db::Database;

// ── Configuration ──

/// Configuration for the Shift Report feature, loaded from DB settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShiftReportConfig {
    /// Whether the shift report feature is enabled (opt-in).
    pub enabled: bool,
    /// Interval between shifts in minutes (default: 240 = 4 hours).
    pub interval_minutes: u64,
    /// Minimum situation score (0-100) to trigger a notification.
    pub notify_threshold: u32,
    /// Always send a summary at this hour (0-23). Set to 255 to disable.
    pub daily_summary_hour: u8,
}

impl Default for ShiftReportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: 240,
            notify_threshold: 20,
            daily_summary_hour: 8,
        }
    }
}

impl ShiftReportConfig {
    pub async fn from_db(store: &dyn Database) -> Self {
        match store.get_setting("_system", "tc_config_shift_report").await {
            Ok(Some(v)) => serde_json::from_value(v).unwrap_or_default(),
            _ => Self::default(),
        }
    }
}

// ── Data structures ──

/// Data collected for a single shift period.
#[derive(Debug, Clone, Serialize)]
pub struct ShiftData {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub new_findings_count: i64,
    pub new_alerts_count: i64,
    pub new_incidents_count: i64,
    pub critical_findings: Vec<String>,
    pub high_findings: Vec<String>,
    pub active_assets: Vec<String>,
    pub ml_anomalies: Vec<String>,
    pub global_score: f64,
}

/// Structured shift report produced by L2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShiftReport {
    pub situation: String,
    pub score: u32,
    pub summary: String,
    pub correlations: Vec<String>,
    pub recommendations: Vec<String>,
    pub generated_at: DateTime<Utc>,
    pub llm_model: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
}

// ── Data collection ──

async fn collect_shift_data(store: &dyn Database, since: DateTime<Utc>) -> ShiftData {
    let now = Utc::now();

    let new_findings_count = store.count_findings_since(since).await.unwrap_or(0);
    let new_alerts_count = store.count_alerts_since(since).await.unwrap_or(0);
    let new_incidents_count = store.count_incidents_since(since).await.unwrap_or(0);

    let critical_findings = store.list_finding_titles_since(since, "CRITICAL", 10).await.unwrap_or_default();
    let high_findings = store.list_finding_titles_since(since, "HIGH", 10).await.unwrap_or_default();
    let active_assets = store.list_active_assets_since(since, 20).await.unwrap_or_default();
    let ml_anomalies = store.list_ml_anomalies(0.7, 10).await.unwrap_or_default();

    let global_score = match store.get_setting("_system", "ie_last_score").await {
        Ok(Some(v)) => v.as_f64().unwrap_or(0.0),
        _ => 0.0,
    };

    ShiftData {
        period_start: since,
        period_end: now,
        new_findings_count,
        new_alerts_count,
        new_incidents_count,
        critical_findings,
        high_findings,
        active_assets,
        ml_anomalies,
        global_score,
    }
}

// ── L2 analysis ──

async fn analyze_shift(store: &dyn Database, data: &ShiftData) -> Result<ShiftReport, String> {
    let llm_config = crate::agent::llm_router::LlmRouterConfig::from_db_settings(store).await;

    let prompt = format!(
        "Tu es un analyste SOC senior rédigeant un rapport de quart de veille pour un RSSI.\n\n\
         PÉRIODE : {} → {}\n\n\
         STATISTIQUES :\n\
         - Nouveaux findings : {}\n\
         - Nouvelles alertes Sigma : {}\n\
         - Nouveaux incidents : {}\n\
         - Score de situation global : {:.0}/100\n\n\
         FINDINGS CRITIQUES :\n{}\n\n\
         FINDINGS HIGH :\n{}\n\n\
         ASSETS ACTIFS :\n{}\n\n\
         ANOMALIES ML (score > 0.7) :\n{}\n\n\
         Réponds en JSON avec EXACTEMENT ces clés :\n\
         {{\n\
           \"situation\": \"calme|activite|suspect|attaque\",\n\
           \"score\": 0,\n\
           \"summary\": \"2-3 phrases résumant la situation de sécurité\",\n\
           \"correlations\": [\"corrélation observée entre X et Y\"],\n\
           \"recommendations\": [\"action recommandée 1\"]\n\
         }}\n\
         Si aucune activité suspecte, indique situation=calme et score bas. Sois factuel.",
        data.period_start.format("%H:%M"),
        data.period_end.format("%H:%M"),
        data.new_findings_count,
        data.new_alerts_count,
        data.new_incidents_count,
        data.global_score,
        format_list(&data.critical_findings),
        format_list(&data.high_findings),
        format_list(&data.active_assets),
        format_list(&data.ml_anomalies),
    );

    let l2_base_url = if llm_config.forensic.base_url.contains("127.0.0.1")
        || llm_config.forensic.base_url.contains("localhost")
    {
        llm_config.primary.base_url.clone()
    } else {
        llm_config.forensic.base_url.clone()
    };

    let raw = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        crate::agent::react_runner::call_ollama(&l2_base_url, &llm_config.forensic.model, &prompt),
    )
    .await
    .map_err(|_| "L2 shift analysis timeout (300s)".to_string())?
    .map_err(|e| format!("L2 shift analysis failed: {e}"))?;

    let cleaned = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let v: serde_json::Value =
        serde_json::from_str(cleaned).map_err(|e| format!("L2 shift JSON parse error: {e}"))?;

    Ok(ShiftReport {
        situation: v.get("situation").and_then(|v| v.as_str()).unwrap_or("calme").to_string(),
        score: v.get("score").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        summary: v
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("Aucune analyse disponible.")
            .to_string(),
        correlations: extract_string_array(&v, "correlations"),
        recommendations: extract_string_array(&v, "recommendations"),
        generated_at: Utc::now(),
        llm_model: llm_config.forensic.model.clone(),
        period_start: data.period_start,
        period_end: data.period_end,
    })
}

// ── Notification ──

async fn notify_shift_report(store: &dyn Database, report: &ShiftReport, data: &ShiftData) {
    let situation_icon = match report.situation.as_str() {
        "attaque" => "\u{1f534}",
        "suspect" => "\u{1f7e0}",
        "activite" => "\u{1f7e1}",
        _ => "\u{1f7e2}",
    };

    let mut msg = format!(
        "{icon} QUART DE VEILLE — {situation}\n\
         \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\
         Période : {} \u{2192} {}\n\
         Score : {}/100\n\
         \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\n\
         {}\n",
        report.period_start.format("%H:%M"),
        report.period_end.format("%H:%M"),
        report.score,
        report.summary,
        icon = situation_icon,
        situation = report.situation.to_uppercase(),
    );

    msg.push_str(&format!(
        "\n\u{1f4ca} {} findings \u{00b7} {} alertes \u{00b7} {} incidents\n",
        data.new_findings_count, data.new_alerts_count, data.new_incidents_count,
    ));

    if !report.correlations.is_empty() {
        msg.push_str("\n\u{1f517} Corrélations :\n");
        for c in &report.correlations {
            msg.push_str(&format!("  \u{00b7} {c}\n"));
        }
    }

    if !report.recommendations.is_empty() {
        msg.push_str("\n\u{25b6} Recommandations :\n");
        for (i, r) in report.recommendations.iter().enumerate() {
            msg.push_str(&format!("  {}. {r}\n", i + 1));
        }
    }

    msg.push_str(&format!("\n\u{1f916} Analysé par {}", report.llm_model));

    let level = if report.score >= 80 {
        crate::agent::intelligence_engine::NotificationLevel::Critical
    } else if report.score >= 50 {
        crate::agent::intelligence_engine::NotificationLevel::Alert
    } else {
        crate::agent::intelligence_engine::NotificationLevel::Digest
    };

    crate::agent::notification_router::route_notification(store, level, &msg, &msg).await;
}

// ── Main loop ──

/// Run the shift report loop. Spawned once from the IE startup.
pub async fn run_shift_loop(store: Arc<dyn Database>) {
    // Wait for boot to complete before starting
    tokio::time::sleep(std::time::Duration::from_secs(120)).await;

    let mut last_shift = Utc::now();
    let mut last_daily_summary: Option<DateTime<Utc>> = None;

    loop {
        let config = ShiftReportConfig::from_db(&*store).await;

        if !config.enabled {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            continue;
        }

        let now = Utc::now();
        let elapsed_minutes = (now - last_shift).num_minutes() as u64;

        let is_daily_summary_time = config.daily_summary_hour < 24
            && now.hour() == config.daily_summary_hour as u32
            && last_daily_summary.map_or(true, |t| (now - t).num_hours() >= 20);

        if elapsed_minutes < config.interval_minutes && !is_daily_summary_time {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            continue;
        }

        tracing::info!(
            "SHIFT_REPORT: Starting shift analysis ({}min since last)",
            elapsed_minutes
        );

        let data = collect_shift_data(&*store, last_shift).await;

        // Skip L2 call if nothing happened and not daily summary time
        let has_activity = data.new_findings_count > 0
            || data.new_alerts_count > 0
            || data.new_incidents_count > 0
            || data.global_score > 20.0;

        if !has_activity && !is_daily_summary_time {
            tracing::info!("SHIFT_REPORT: No activity since last shift, skipping");
            last_shift = now;
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            continue;
        }

        // Acquire investigation semaphore — don't compete with real-time investigations
        let _permit = super::intelligence_engine::INVESTIGATION_SEMAPHORE.acquire().await.ok();

        match analyze_shift(&*store, &data).await {
            Ok(report) => {
                tracing::info!(
                    "SHIFT_REPORT: {} score={} findings={} alerts={}",
                    report.situation,
                    report.score,
                    data.new_findings_count,
                    data.new_alerts_count
                );

                let _ = store
                    .set_setting(
                        "_system",
                        "last_shift_report",
                        &serde_json::to_value(&report).unwrap_or_default(),
                    )
                    .await;

                if report.score >= config.notify_threshold || is_daily_summary_time {
                    notify_shift_report(&*store, &report, &data).await;
                    if is_daily_summary_time {
                        last_daily_summary = Some(now);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("SHIFT_REPORT: L2 analysis failed: {e}");
            }
        }

        last_shift = now;
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

// ── Helpers ──

fn format_list(items: &[String]) -> String {
    if items.is_empty() {
        "Aucun".to_string()
    } else {
        items.iter().map(|f| format!("- {f}")).collect::<Vec<_>>().join("\n")
    }
}

fn extract_string_array(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|i| i.as_str().map(String::from)).collect())
        .unwrap_or_default()
}
