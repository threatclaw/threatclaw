//! Intelligence Engine — the brain of ThreatClaw.
//!
//! Runs every 5 minutes, collects all new events (findings, alerts, enrichment),
//! deduplicates, correlates by asset, computes a global security score,
//! and decides what level of notification the RSSI needs.
//!
//! KEY PRINCIPLE: The RSSI should NOT be drowned in notifications.
//! Silence = everything is fine. Only escalate when there's real signal.
//!
//! Flow:
//!   Events (findings, sigma alerts) → Buffer → Deduplicate → Correlate → Score → Decide → Notify
//!
//! Scale: This module does NOT call LLM for every event.
//! It uses simple rules for 95% of decisions, and only calls L1 when
//! the score crosses a threshold (suspected incident).

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// Notification level decided by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationLevel {
    /// Nothing new, nothing to report. Silence is golden.
    Silence,
    /// Normal activity, some low/medium findings. Batched into daily digest.
    Digest,
    /// Something suspicious — new High, correlation detected. Immediate alert.
    Alert,
    /// Confirmed incident — Critical finding, kill chain, active exploit. HITL required.
    Critical,
}

/// A correlated security situation for one asset.
#[derive(Debug, Clone, Serialize)]
pub struct AssetSituation {
    pub asset: String,
    pub score: f64,
    pub findings_critical: usize,
    pub findings_high: usize,
    pub findings_medium: usize,
    pub findings_low: usize,
    pub active_alerts: usize,
    /// Correlation flags
    pub has_kill_chain: bool,       // finding + alert on same asset
    pub has_known_exploit: bool,    // CVE exploited in wild
    pub has_active_attack: bool,    // sigma alert + recent finding
    pub summary: String,
}

/// Global security situation computed by the engine.
#[derive(Debug, Clone, Serialize)]
pub struct SecuritySituation {
    pub global_score: f64,
    pub notification_level: NotificationLevel,
    pub assets: Vec<AssetSituation>,
    pub new_findings_count: usize,
    pub new_alerts_count: usize,
    pub total_open_findings: usize,
    pub total_active_alerts: usize,
    pub digest_message: String,
    pub alert_message: Option<String>,
    pub computed_at: String,
}

/// Run the intelligence engine cycle.
/// Returns the current security situation and recommended notification level.
pub async fn run_intelligence_cycle(
    store: Arc<dyn Database>,
) -> SecuritySituation {
    let now = chrono::Utc::now();

    // ── 1. Collect all open findings ──
    let findings = store.list_findings(None, Some("open"), None, 500).await.unwrap_or_default();
    let alerts = store.list_alerts(None, Some("new"), 200).await.unwrap_or_default();

    // ── 2. Group by asset ──
    let mut asset_map: HashMap<String, AssetSituation> = HashMap::new();

    for f in &findings {
        let asset = f.asset.as_deref().unwrap_or("unknown").to_string();
        let entry = asset_map.entry(asset.clone()).or_insert_with(|| AssetSituation {
            asset: asset.clone(), score: 0.0,
            findings_critical: 0, findings_high: 0, findings_medium: 0, findings_low: 0,
            active_alerts: 0, has_kill_chain: false, has_known_exploit: false,
            has_active_attack: false, summary: String::new(),
        });

        match f.severity.to_lowercase().as_str() {
            "critical" => entry.findings_critical += 1,
            "high" => entry.findings_high += 1,
            "medium" => entry.findings_medium += 1,
            _ => entry.findings_low += 1,
        }

        // Check for known exploited CVEs
        if let Some(meta) = f.metadata.as_object() {
            if meta.get("exploited_in_wild").and_then(|v| v.as_bool()) == Some(true) {
                entry.has_known_exploit = true;
            }
        }
    }

    // ── 3. Overlay alerts on assets ──
    for a in &alerts {
        let asset = a.hostname.as_deref().unwrap_or("unknown").to_string();
        let entry = asset_map.entry(asset.clone()).or_insert_with(|| AssetSituation {
            asset: asset.clone(), score: 0.0,
            findings_critical: 0, findings_high: 0, findings_medium: 0, findings_low: 0,
            active_alerts: 0, has_kill_chain: false, has_known_exploit: false,
            has_active_attack: false, summary: String::new(),
        });

        entry.active_alerts += 1;

        // Kill chain: finding + alert on same asset = active exploitation attempt
        if entry.findings_critical > 0 || entry.findings_high > 0 {
            entry.has_kill_chain = true;
        }

        // Active attack: sigma alert on asset with findings
        if entry.findings_critical + entry.findings_high + entry.findings_medium > 0 {
            entry.has_active_attack = true;
        }
    }

    // ── 4. Score each asset ──
    for entry in asset_map.values_mut() {
        entry.score = compute_asset_score(entry);
        entry.summary = build_asset_summary(entry);
    }

    // ── 5. Compute global score ──
    let global_score = if asset_map.is_empty() {
        100.0 // Perfect score if nothing to report
    } else {
        let worst_asset = asset_map.values().map(|a| a.score).fold(0.0f64, f64::max);
        let avg_score = asset_map.values().map(|a| a.score).sum::<f64>() / asset_map.len() as f64;
        // Global = weighted average (worst asset counts more)
        (100.0 - (worst_asset * 0.6 + avg_score * 0.4)).max(0.0)
    };

    // ── 6. ENRICHMENT — enrich critical findings + alert IPs ──
    // All enrichment is wrapped in catch_unwind-style error handling.
    // External API failures must NEVER crash the engine.
    let mut enrichment_lines: Vec<String> = vec![];

    // Enrich CVEs from critical findings with EPSS + KEV
    for f in &findings {
        if f.severity.to_lowercase() != "critical" { continue; }
        if let Some(cve) = f.metadata.as_object().and_then(|m| m.get("cve")).and_then(|v| v.as_str()) {
            // EPSS — wrapped in timeout
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                crate::enrichment::epss::lookup_epss(cve)
            ).await {
                Ok(Ok(Some(epss))) => {
                    let pct = epss.epss * 100.0;
                    if pct > 50.0 {
                        enrichment_lines.push(format!("EPSS {}: {:.0}% probabilité exploitation 30j", cve, pct));
                    }
                    let asset_name = f.asset.as_deref().unwrap_or("unknown");
                    if let Some(entry) = asset_map.get_mut(asset_name) {
                        if epss.epss > 0.9 { entry.score = (entry.score + 20.0).min(100.0); }
                    }
                }
                Ok(Err(e)) => tracing::debug!("ENRICHMENT: EPSS failed for {cve}: {e}"),
                _ => tracing::debug!("ENRICHMENT: EPSS timeout for {cve}"),
            }

            // KEV check (local DB only — no external call, fast)
            if let Some(kev) = crate::enrichment::cisa_kev::is_exploited(store.as_ref(), cve).await {
                enrichment_lines.push(format!("CISA KEV: {} activement exploitée — action requise avant {}", cve, kev.due_date));
                let asset_name = f.asset.as_deref().unwrap_or("unknown");
                if let Some(entry) = asset_map.get_mut(asset_name) {
                    entry.has_known_exploit = true;
                    entry.score = (entry.score + 25.0).min(100.0);
                }
            }
        }
    }

    // Enrich alert source IPs with GreyNoise + IPinfo
    for a in &alerts {
        if let Some(ref raw_ip) = a.source_ip {
            // Clean IP (remove /32 CIDR suffix, trim whitespace)
            let ip_str = raw_ip.split('/').next().unwrap_or("").trim();
            if ip_str.is_empty() || ip_str.starts_with("10.") || ip_str.starts_with("192.168.") || ip_str.starts_with("127.") {
                continue;
            }

            // GreyNoise — with timeout
            match tokio::time::timeout(
                std::time::Duration::from_secs(8),
                crate::enrichment::greynoise::lookup_ip(ip_str, None)
            ).await {
                Ok(Ok(gn)) => {
                    let label = if gn.classification == "malicious" { "attaque ciblée" }
                        else if gn.noise { "scanner de masse" }
                        else { "inconnu" };
                    enrichment_lines.push(format!("GreyNoise {}: {} ({})", ip_str, gn.classification, label));
                }
                Ok(Err(e)) => tracing::debug!("ENRICHMENT: GreyNoise failed for {ip_str}: {e}"),
                Err(_) => tracing::debug!("ENRICHMENT: GreyNoise timeout for {ip_str}"),
            }

            // IPinfo — with timeout
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                crate::enrichment::ipinfo::lookup_ip(ip_str)
            ).await {
                Ok(Ok(geo)) => {
                    let ctx = crate::enrichment::ipinfo::format_for_context(&geo);
                    enrichment_lines.push(format!("Origine: {}", ctx));
                }
                Ok(Err(e)) => tracing::debug!("ENRICHMENT: IPinfo failed for {ip_str}: {e}"),
                Err(_) => tracing::debug!("ENRICHMENT: IPinfo timeout for {ip_str}"),
            }
        }
    }

    tracing::info!("ENRICHMENT: {} enrichment lines collected", enrichment_lines.len());

    // ── 7. Decide notification level (after enrichment may have changed scores) ──
    // Recompute summaries after enrichment
    for entry in asset_map.values_mut() {
        entry.summary = build_asset_summary(entry);
    }
    let notification_level = decide_notification_level(&asset_map, global_score);

    // ── 8. Build messages (enriched) ──
    let mut assets: Vec<AssetSituation> = asset_map.into_values().collect();
    assets.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    let digest_message = build_digest_message(&assets, global_score, findings.len(), alerts.len());
    let alert_message = if notification_level >= NotificationLevel::Alert {
        Some(build_enriched_alert_message(&assets, &alerts, &enrichment_lines))
    } else {
        None
    };

    // ── 8. Store situation in DB ──
    let situation = SecuritySituation {
        global_score,
        notification_level,
        assets,
        new_findings_count: findings.len(),
        new_alerts_count: alerts.len(),
        total_open_findings: findings.len(),
        total_active_alerts: alerts.len(),
        digest_message,
        alert_message,
        computed_at: now.to_rfc3339(),
    };

    // Persist for dashboard
    let _ = store.set_setting("_system", "security_situation", &json!({
        "global_score": situation.global_score,
        "notification_level": situation.notification_level,
        "open_findings": situation.total_open_findings,
        "active_alerts": situation.total_active_alerts,
        "assets_at_risk": situation.assets.iter().filter(|a| a.score > 30.0).count(),
        "computed_at": situation.computed_at,
    })).await;
    let _ = store.record_metric("security_score", global_score, &json!({})).await;

    tracing::info!(
        "INTELLIGENCE: Score={:.0} Level={:?} Findings={} Alerts={} Assets={}",
        global_score, notification_level, findings.len(), alerts.len(), situation.assets.len()
    );

    situation
}

/// Compute risk score for an asset (0-100, higher = more risk).
fn compute_asset_score(asset: &AssetSituation) -> f64 {
    let mut score = 0.0;

    // Severity-based scoring
    score += asset.findings_critical as f64 * 30.0;
    score += asset.findings_high as f64 * 15.0;
    score += asset.findings_medium as f64 * 5.0;
    score += asset.findings_low as f64 * 1.0;

    // Alert multiplier
    score += asset.active_alerts as f64 * 20.0;

    // Correlation bonuses (these are the real signal)
    if asset.has_kill_chain { score += 25.0; }
    if asset.has_known_exploit { score += 20.0; }
    if asset.has_active_attack { score += 15.0; }

    score.min(100.0)
}

/// Decide notification level from global situation.
fn decide_notification_level(
    assets: &HashMap<String, AssetSituation>,
    global_score: f64,
) -> NotificationLevel {
    // Any kill chain or known exploit → Critical
    if assets.values().any(|a| a.has_kill_chain && a.has_known_exploit) {
        return NotificationLevel::Critical;
    }

    // Any Critical finding with active alert → Critical
    if assets.values().any(|a| a.findings_critical > 0 && a.active_alerts > 0) {
        return NotificationLevel::Critical;
    }

    // Any Critical finding alone → Alert
    if assets.values().any(|a| a.findings_critical > 0) {
        return NotificationLevel::Alert;
    }

    // Multiple High on same asset → Alert
    if assets.values().any(|a| a.findings_high >= 3) {
        return NotificationLevel::Alert;
    }

    // Kill chain without critical → Alert
    if assets.values().any(|a| a.has_kill_chain) {
        return NotificationLevel::Alert;
    }

    // Active attack → Alert
    if assets.values().any(|a| a.has_active_attack) {
        return NotificationLevel::Alert;
    }

    // Low global score → Digest
    if global_score < 80.0 {
        return NotificationLevel::Digest;
    }

    // Nothing notable → Silence
    NotificationLevel::Silence
}

/// Build the daily digest message.
fn build_digest_message(
    assets: &[AssetSituation],
    global_score: f64,
    findings_count: usize,
    alerts_count: usize,
) -> String {
    let date = chrono::Utc::now().format("%d/%m/%Y").to_string();
    let mut msg = format!(
        "*ThreatClaw — Digest {}*\n\nScore sécurité : *{:.0}/100*\n",
        date, global_score
    );

    if !assets.is_empty() {
        msg.push_str("\n*Assets à risque :*\n");
        for asset in assets.iter().take(5) {
            let level = if asset.score >= 60.0 { "CRITIQUE" }
                else if asset.score >= 30.0 { "ATTENTION" }
                else { "OK" };
            msg.push_str(&format!(
                "  {} [{}] — {} findings, {} alertes\n",
                asset.asset, level,
                asset.findings_critical + asset.findings_high + asset.findings_medium + asset.findings_low,
                asset.active_alerts,
            ));
        }
    }

    msg.push_str(&format!(
        "\nFindings ouverts : {}\nAlertes actives : {}\n",
        findings_count, alerts_count
    ));

    if global_score >= 80.0 {
        msg.push_str("\n_Aucune action requise._");
    } else if global_score >= 50.0 {
        msg.push_str("\n_Quelques points d'attention — voir le dashboard pour les détails._");
    } else {
        msg.push_str("\n_Situation dégradée — action recommandée._");
    }

    msg
}

/// Build an immediate alert message (basic, without enrichment).
fn build_alert_message(
    assets: &[AssetSituation],
    alerts: &[crate::db::threatclaw_store::AlertRecord],
) -> String {
    build_enriched_alert_message(assets, alerts, &[])
}

/// Build an enriched alert message with all intelligence data.
fn build_enriched_alert_message(
    assets: &[AssetSituation],
    alerts: &[crate::db::threatclaw_store::AlertRecord],
    enrichment: &[String],
) -> String {
    let critical_assets: Vec<&AssetSituation> = assets.iter()
        .filter(|a| a.score >= 30.0)
        .collect();

    let is_critical = critical_assets.iter().any(|a| a.has_kill_chain || a.has_known_exploit || a.findings_critical > 0);
    let header = if is_critical {
        "*ThreatClaw — ALERTE CRITIQUE*"
    } else {
        "*ThreatClaw — Alerte sécurité*"
    };

    let mut msg = format!("{}\n\n", header);

    // Assets at risk
    for asset in critical_assets.iter().take(3) {
        let flags = [
            if asset.has_kill_chain { Some("kill chain") } else { None },
            if asset.has_known_exploit { Some("exploit connu") } else { None },
            if asset.has_active_attack { Some("attaque active") } else { None },
        ].into_iter().flatten().collect::<Vec<_>>().join(", ");

        msg.push_str(&format!("*{}* — score {:.0}/100\n", asset.asset, asset.score));
        msg.push_str(&format!("{}\n", asset.summary));
        if !flags.is_empty() {
            msg.push_str(&format!("Indicateurs: {}\n", flags));
        }
        msg.push('\n');
    }

    // Sigma alerts
    if !alerts.is_empty() {
        msg.push_str("*Alertes actives :*\n");
        for a in alerts.iter().take(3) {
            let src = a.source_ip.as_deref().map(|ip| format!(" depuis {}", ip)).unwrap_or_default();
            msg.push_str(&format!("[{}] {}{}\n", a.level.to_uppercase(), a.title, src));
        }
        msg.push('\n');
    }

    // Enrichment intelligence
    if !enrichment.is_empty() {
        msg.push_str("*Enrichissement :*\n");
        for line in enrichment.iter().take(6) {
            msg.push_str(&format!("  {}\n", line));
        }
        msg.push('\n');
    }

    msg.push_str("_Intelligence Engine — cycle automatique_");
    msg
}

/// Build a human-readable summary for an asset.
fn build_asset_summary(asset: &AssetSituation) -> String {
    let mut parts = vec![];

    if asset.findings_critical > 0 {
        parts.push(format!("{} CRITICAL", asset.findings_critical));
    }
    if asset.findings_high > 0 {
        parts.push(format!("{} HIGH", asset.findings_high));
    }
    if asset.active_alerts > 0 {
        parts.push(format!("{} alerte(s) active(s)", asset.active_alerts));
    }
    if asset.has_kill_chain {
        parts.push("kill chain détectée".into());
    }
    if asset.has_known_exploit {
        parts.push("CVE exploitée en production".into());
    }

    if parts.is_empty() {
        "RAS".into()
    } else {
        parts.join(", ")
    }
}

/// Spawn the intelligence engine as a background ticker.
pub fn spawn_intelligence_ticker(
    store: Arc<dyn Database>,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("INTELLIGENCE: Engine started — cycle every {}s", interval.as_secs());
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip first immediate tick

        loop {
            ticker.tick().await;
            let situation = run_intelligence_cycle(store.clone()).await;

            // Route notifications based on level
            if situation.notification_level >= NotificationLevel::Alert {
                if let Some(ref alert_msg) = situation.alert_message {
                    // Send via notification router
                    let _ = crate::agent::notification_router::route_notification(
                        store.as_ref(),
                        situation.notification_level,
                        alert_msg,
                        &situation.digest_message,
                    ).await;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_score() {
        let mut asset = AssetSituation {
            asset: "test".into(), score: 0.0,
            findings_critical: 1, findings_high: 2, findings_medium: 0, findings_low: 0,
            active_alerts: 1, has_kill_chain: false, has_known_exploit: false,
            has_active_attack: false, summary: String::new(),
        };
        let score = compute_asset_score(&asset);
        assert!(score > 60.0); // 30 + 30 + 20 = 80

        asset.has_kill_chain = true;
        let score2 = compute_asset_score(&asset);
        assert!(score2 > score); // Kill chain adds 25
    }

    #[test]
    fn test_notification_levels() {
        let mut assets = HashMap::new();

        // Empty → Silence
        assert_eq!(decide_notification_level(&assets, 100.0), NotificationLevel::Silence);

        // Low findings → Digest
        assets.insert("srv".into(), AssetSituation {
            asset: "srv".into(), score: 5.0,
            findings_critical: 0, findings_high: 0, findings_medium: 2, findings_low: 3,
            active_alerts: 0, has_kill_chain: false, has_known_exploit: false,
            has_active_attack: false, summary: String::new(),
        });
        assert_eq!(decide_notification_level(&assets, 70.0), NotificationLevel::Digest);

        // Critical finding → Alert
        assets.get_mut("srv").unwrap().findings_critical = 1;
        assert_eq!(decide_notification_level(&assets, 40.0), NotificationLevel::Alert);

        // Critical + active alert → Critical
        assets.get_mut("srv").unwrap().active_alerts = 1;
        assert_eq!(decide_notification_level(&assets, 20.0), NotificationLevel::Critical);
    }
}
