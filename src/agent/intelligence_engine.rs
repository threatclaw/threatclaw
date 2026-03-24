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

use chrono::Timelike;
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

    // ── 0. Sync the threat graph from DB ──
    crate::graph::threat_graph::sync_graph_from_db(store.as_ref()).await;

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

    // ── 5b. RUN INVESTIGATION GRAPHS for each alert ──
    // Match alerts to investigation graphs and run deterministic investigation.
    let all_graphs = crate::graph::investigation::get_investigation_graphs();
    for a in alerts.iter().take(3) {
        if let Some(graph_id) = crate::graph::investigation::match_investigation_graph(&a.title) {
            if let Some(graph) = all_graphs.iter().find(|g| g.id == graph_id) {
                let ip = a.source_ip.as_deref().map(|s| s.split('/').next().unwrap_or(s));
                let host = a.hostname.as_deref();
                let result = crate::graph::executor::run_investigation(
                    store.clone(), graph, &a.title, ip, host,
                ).await;
                tracing::info!(
                    "INVESTIGATION: '{}' → {} steps, {} ms",
                    graph_id, result.steps_completed.len(), result.total_duration_ms
                );
            }
        }
    }

    // ── 5c. CONFIDENCE SCORING — compute graph-based confidence for top alerts ──
    for a in alerts.iter().take(5) {
        if let Some(ref ip) = a.source_ip {
            let clean_ip = ip.split('/').next().unwrap_or(ip).trim();
            if !clean_ip.is_empty() && !clean_ip.starts_with("10.") && !clean_ip.starts_with("192.168.") {
                let hour = chrono::Utc::now().hour();
                let host = a.hostname.as_deref();
                let score = crate::graph::confidence::compute_ip_confidence(
                    store.as_ref(), clean_ip, host, Some(hour),
                ).await;
                tracing::info!(
                    "CONFIDENCE: {} → {}/100 ({}) — {} sources",
                    clean_ip, score.score, score.level, score.source_count
                );
            }
        }
    }

    // ── 5d. LATERAL MOVEMENT DETECTION — graph traversal ──
    let lateral = crate::graph::lateral::detect_lateral_movement(store.as_ref()).await;
    if lateral.total_detections > 0 {
        tracing::warn!("LATERAL: {} detections — {}", lateral.total_detections, lateral.summary);
        // TODO: auto-create CRITICAL finding for lateral movement
    }

    // ── 5e. CAMPAIGN DETECTION — correlate coordinated attacks ──
    let campaigns = crate::graph::campaign::detect_campaigns(store.as_ref()).await;
    if campaigns.total_campaigns > 0 {
        tracing::warn!("CAMPAIGN: {}", campaigns.summary);
    }

    // ── 5f. IDENTITY ANOMALY DETECTION — UBA via graph ──
    let identity = crate::graph::identity_graph::detect_identity_anomalies(store.as_ref()).await;
    if !identity.anomalies.is_empty() {
        tracing::warn!("IDENTITY: {}", identity.summary);
    }

    // ── 5g. THREAT ACTOR PROFILING — attribution from graph patterns ──
    let actors = crate::graph::threat_actor::profile_threat_actors(store.as_ref()).await;
    if actors.total_actors > 0 {
        tracing::info!("THREAT_ACTOR: {}", actors.summary);
    }

    // ── 5h. SCAN RECENT LOGS for IoCs (URLs, IPs, hashes) ──
    // This is where the engine becomes a true SOC brain — it reads raw logs,
    // extracts indicators, and cross-references with enrichment sources.
    let log_scan_results = scan_logs_for_threats(store.clone()).await;
    for threat in &log_scan_results {
        // Auto-create finding for each threat detected in logs
        let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
            skill_id: "intelligence-engine".into(),
            title: threat.title.clone(),
            description: Some(threat.description.clone()),
            severity: threat.severity.clone(),
            category: Some("log-analysis".into()),
            asset: threat.asset.clone(),
            source: Some(threat.source.clone()),
            metadata: Some(threat.metadata.clone()),
        }).await;
    }
    if !log_scan_results.is_empty() {
        tracing::info!("INTELLIGENCE: {} threat(s) detected from log scan", log_scan_results.len());
        // Re-fetch findings after inserting new ones
        let findings = store.list_findings(None, Some("open"), None, 500).await.unwrap_or_default();
        // Rebuild asset map with new findings
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
        }
    }

    // ── 6. ENRICHMENT — enrich critical findings + alert IPs ──
    // All enrichment is wrapped in timeout + rate limiting.
    // External API failures must NEVER crash the engine.
    let mut enrichment_lines: Vec<String> = vec![];
    let mut rate_limiter = crate::agent::production_safeguards::CycleRateLimiter::new(15); // Max 15 external lookups per cycle

    // Enrich CVEs from critical findings with EPSS + KEV
    for f in &findings {
        if f.severity.to_lowercase() != "critical" { continue; }
        if !rate_limiter.can_lookup() { break; }
        if let Some(cve) = f.metadata.as_object().and_then(|m| m.get("cve")).and_then(|v| v.as_str()) {
            // EPSS — check cache first, then API with timeout
            let epss_cached = crate::agent::production_safeguards::get_cached_ioc(store.as_ref(), "epss", cve).await;
            let epss_result = if let Some(cached) = epss_cached {
                cached["epss"].as_f64()
            } else {
                rate_limiter.record_lookup();
                match tokio::time::timeout(std::time::Duration::from_secs(10), crate::enrichment::epss::lookup_epss(cve)).await {
                    Ok(Ok(Some(ref epss))) => {
                        crate::agent::production_safeguards::cache_ioc(store.as_ref(), "epss", cve, &json!({"epss": epss.epss})).await;
                        Some(epss.epss)
                    }
                    _ => None,
                }
            };

            if let Some(epss_val) = epss_result {
                let pct = epss_val * 100.0;
                if pct > 50.0 {
                    enrichment_lines.push(format!("EPSS {}: {:.0}% probabilité exploitation 30j", cve, pct));
                }
                let asset_name = f.asset.as_deref().unwrap_or("unknown");
                if let Some(entry) = asset_map.get_mut(asset_name) {
                    if epss_val > 0.9 { entry.score = (entry.score + 20.0).min(100.0); }
                }
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

    // Enrich alert source IPs with GreyNoise + IPinfo (with rate limiting + caching)
    for a in &alerts {
        if !rate_limiter.can_lookup() { break; }
        if let Some(ref raw_ip) = a.source_ip {
            let ip_str = raw_ip.split('/').next().unwrap_or("").trim();
            if ip_str.is_empty() || ip_str.starts_with("10.") || ip_str.starts_with("192.168.") || ip_str.starts_with("127.") {
                continue;
            }
            // Skip if already looked up this cycle
            if rate_limiter.ip_already_seen(ip_str) { continue; }

            // GreyNoise — cache first
            let gn_cached = crate::agent::production_safeguards::get_cached_ioc(store.as_ref(), "greynoise", ip_str).await;
            if let Some(cached) = gn_cached {
                let classification = cached["classification"].as_str().unwrap_or("?");
                let label = if classification == "malicious" { "attaque ciblée" } else if cached["noise"].as_bool() == Some(true) { "scanner de masse" } else { "inconnu" };
                enrichment_lines.push(format!("GreyNoise {}: {} ({})", ip_str, classification, label));
            } else {
                rate_limiter.record_lookup();
                match tokio::time::timeout(std::time::Duration::from_secs(8), crate::enrichment::greynoise::lookup_ip(ip_str, None)).await {
                    Ok(Ok(gn)) => {
                        crate::agent::production_safeguards::cache_ioc(store.as_ref(), "greynoise", ip_str, &json!({"classification": gn.classification, "noise": gn.noise, "riot": gn.riot})).await;
                        let label = if gn.classification == "malicious" { "attaque ciblée" } else if gn.noise { "scanner de masse" } else { "inconnu" };
                        enrichment_lines.push(format!("GreyNoise {}: {} ({})", ip_str, gn.classification, label));
                    }
                    Ok(Err(e)) => tracing::debug!("ENRICHMENT: GreyNoise failed for {ip_str}: {e}"),
                    Err(_) => tracing::debug!("ENRICHMENT: GreyNoise timeout for {ip_str}"),
                }
            }

            // IPinfo — cache first
            if !rate_limiter.can_lookup() { continue; }
            let geo_cached = crate::agent::production_safeguards::get_cached_ioc(store.as_ref(), "ipinfo", ip_str).await;
            if let Some(cached) = geo_cached {
                let country = cached["country"].as_str().unwrap_or("?");
                let org = cached["org"].as_str().unwrap_or("?");
                enrichment_lines.push(format!("Origine: {} · {} · {}", ip_str, country, org));
            } else {
                rate_limiter.record_lookup();
                match tokio::time::timeout(std::time::Duration::from_secs(5), crate::enrichment::ipinfo::lookup_ip(ip_str)).await {
                    Ok(Ok(geo)) => {
                        crate::agent::production_safeguards::cache_ioc(store.as_ref(), "ipinfo", ip_str, &json!({"country": geo.country, "org": geo.org})).await;
                        enrichment_lines.push(format!("Origine: {}", crate::enrichment::ipinfo::format_for_context(&geo)));
                    }
                    Ok(Err(e)) => tracing::debug!("ENRICHMENT: IPinfo failed for {ip_str}: {e}"),
                    Err(_) => tracing::debug!("ENRICHMENT: IPinfo timeout for {ip_str}"),
                }
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
        Some(build_enriched_alert_message(&assets, &alerts, &enrichment_lines, &findings))
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
    findings: &[crate::db::threatclaw_store::FindingRecord],
) -> String {
    build_enriched_alert_message(assets, alerts, &[], findings)
}

/// Build an enriched alert message with all intelligence data.
fn build_enriched_alert_message(
    assets: &[AssetSituation],
    alerts: &[crate::db::threatclaw_store::AlertRecord],
    enrichment: &[String],
    findings: &[crate::db::threatclaw_store::FindingRecord],
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

    // ── LLM Analysis (from the most recent AI-generated finding) ──
    let ai_finding = findings.iter().rev()
        .find(|f| f.source.as_deref() == Some("threatclaw-l1") || f.source.as_deref() == Some("threatclaw-l2"));
    if let Some(f) = ai_finding {
        if let Some(ref desc) = f.description {
            // Extract just the analysis text (before "Corrélations :")
            let analysis = desc.split("Corrélations :").next().unwrap_or(desc)
                .replace("Analyse automatique par ThreatClaw AI :\n", "")
                .trim().to_string();
            if !analysis.is_empty() {
                msg.push_str(&format!("*Analyse IA ({} — {})*\n{}\n\n",
                    f.source.as_deref().unwrap_or("L1"),
                    f.title.split(" — ").last().unwrap_or(""),
                    analysis));
            }
            // Add correlations if present
            if let Some(corr_part) = desc.split("Corrélations : ").nth(1) {
                let corr = corr_part.split("Actions proposées").next().unwrap_or(corr_part).trim();
                if !corr.is_empty() {
                    msg.push_str(&format!("*Corrélations :* {}\n\n", corr));
                }
            }
        }
    }

    // ── Assets at risk ──
    for asset in critical_assets.iter().take(3) {
        let flags = [
            if asset.has_kill_chain { Some("kill chain") } else { None },
            if asset.has_known_exploit { Some("exploit connu") } else { None },
            if asset.has_active_attack { Some("attaque active") } else { None },
        ].into_iter().flatten().collect::<Vec<_>>().join(", ");

        msg.push_str(&format!("*{}* — score {:.0}/100\n", asset.asset, asset.score));
        if !flags.is_empty() {
            msg.push_str(&format!("{}\n", flags));
        }
    }
    if !critical_assets.is_empty() { msg.push('\n'); }

    // ── Sigma alerts (top 4) ──
    if !alerts.is_empty() {
        msg.push_str(&format!("*{} alertes Sigma :*\n", alerts.len()));
        for a in alerts.iter().take(4) {
            let src = a.source_ip.as_deref().map(|ip| format!(" ({})", ip.split('/').next().unwrap_or(ip))).unwrap_or_default();
            msg.push_str(&format!("  [{}] {}{}\n", a.level.to_uppercase(), a.title, src));
        }
        if alerts.len() > 4 {
            msg.push_str(&format!("  ... et {} autres\n", alerts.len() - 4));
        }
        msg.push('\n');
    }

    // ── Enrichment (deduplicated) ──
    if !enrichment.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let deduped: Vec<&String> = enrichment.iter()
            .filter(|line| seen.insert(line.as_str()))
            .collect();
        if !deduped.is_empty() {
            msg.push_str("*Enrichissement :*\n");
            for line in deduped.iter().take(4) {
                msg.push_str(&format!("  {}\n", line));
            }
            msg.push('\n');
        }
    }

    msg.push_str("_ThreatClaw Intelligence Engine_");

    // Telegram limit is 4096 chars
    if msg.len() > 4000 {
        msg.truncate(3950);
        msg.push_str("...\n_[tronqué — voir dashboard]_");
    }

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

        // ── Initial sync of enrichment sources at startup ──
        tracing::info!("INTELLIGENCE: Initial enrichment sync...");
        if let Err(e) = crate::enrichment::cisa_kev::sync_kev(store.as_ref()).await {
            tracing::warn!("INTELLIGENCE: KEV sync failed: {e}");
        }
        // MITRE and CERT-FR are bigger — sync in background
        let store_sync = store.clone();
        tokio::spawn(async move {
            let _ = crate::enrichment::mitre_attack::sync_attack_techniques(store_sync.as_ref()).await;
            let _ = crate::enrichment::certfr::sync_certfr_alerts(store_sync.as_ref()).await;
            let _ = crate::enrichment::openphish::sync_feed(store_sync.as_ref()).await;
            tracing::info!("INTELLIGENCE: Background enrichment sync complete");
        });

        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip first immediate tick

        // ── Daily re-sync counter (every 288 cycles at 5min = 24h) ──
        let mut cycle_count: u64 = 0;

        loop {
            ticker.tick().await;
            cycle_count += 1;

            // Daily re-sync (every 288 cycles × 5min = 24h)
            if cycle_count % 288 == 0 {
                tracing::info!("INTELLIGENCE: Daily enrichment re-sync");
                let store_resync = store.clone();
                tokio::spawn(async move {
                    let _ = crate::enrichment::cisa_kev::sync_kev(store_resync.as_ref()).await;
                    let _ = crate::enrichment::certfr::sync_certfr_alerts(store_resync.as_ref()).await;
                    let _ = crate::enrichment::openphish::sync_feed(store_resync.as_ref()).await;
                });
            }

            let situation = run_intelligence_cycle(store.clone()).await;

            // Route notifications based on level (with cooldown)
            if situation.notification_level >= NotificationLevel::Alert {
                let level_str = format!("{:?}", situation.notification_level);
                if crate::agent::production_safeguards::should_notify(store.as_ref(), &level_str).await {
                    if let Some(ref alert_msg) = situation.alert_message {
                        let results = crate::agent::notification_router::route_notification(
                            store.as_ref(),
                            situation.notification_level,
                            alert_msg,
                            &situation.digest_message,
                        ).await;
                        if results.iter().any(|(_, r)| r.is_ok()) {
                            crate::agent::production_safeguards::record_notification_sent(
                                store.as_ref(), &level_str, situation.global_score
                            ).await;
                        }
                    }
                } else {
                    tracing::debug!("INTELLIGENCE: Notification suppressed (cooldown active)");
                }
            }
        }
    })
}

// ══════════════════════════════════════════════════════════
// LOG SCANNING — extract IoCs from raw logs and cross-reference
// with ALL enrichment sources to auto-detect threats.
// ══════════════════════════════════════════════════════════

/// A threat detected from log analysis.
#[derive(Debug, Clone)]
struct DetectedThreat {
    title: String,
    description: String,
    severity: String,
    asset: Option<String>,
    source: String,
    metadata: serde_json::Value,
}

/// Scan recent logs for IoCs and cross-reference with enrichment sources.
/// Creates findings for any threats detected.
async fn scan_logs_for_threats(store: Arc<dyn Database>) -> Vec<DetectedThreat> {
    use crate::db::threatclaw_store::ThreatClawStore;
    use crate::enrichment::ioc_extractor;

    let mut threats = vec![];

    // Query logs from last 10 minutes
    let logs = match store.query_logs(10, None, None, 500).await {
        Ok(l) => l,
        Err(e) => {
            tracing::debug!("INTELLIGENCE: Log scan skipped — {e}");
            return threats;
        }
    };

    if logs.is_empty() {
        return threats;
    }

    tracing::debug!("INTELLIGENCE: Scanning {} recent logs for IoCs", logs.len());

    // Extract IoCs from logs
    let iocs = ioc_extractor::extract_from_logs(&logs);

    tracing::debug!(
        "INTELLIGENCE: Extracted {} IPs, {} URLs, {} hashes, {} domains",
        iocs.ips.len(), iocs.urls.len(), iocs.hashes.len(), iocs.domains.len()
    );

    // Cross-reference URLs with OpenPhish
    for url in iocs.urls.iter().take(20) {
        if crate::enrichment::openphish::is_phishing(store.as_ref(), url).await {
            threats.push(DetectedThreat {
                title: format!("URL de phishing détectée dans les logs : {}", truncate_str(url, 80)),
                description: format!("L'URL {} a été trouvée dans les logs et correspond à une URL de phishing connue (OpenPhish).", url),
                severity: "HIGH".into(),
                asset: None,
                source: "openphish".into(),
                metadata: json!({ "url": url, "source": "openphish" }),
            });
        }
    }

    // Cross-reference IPs with ThreatFox (C2 servers)
    for ip in iocs.ips.iter().take(10) {
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::enrichment::threatfox::lookup_ioc(ip, None),
        ).await {
            Ok(Ok(results)) if !results.is_empty() => {
                let r = &results[0];
                threats.push(DetectedThreat {
                    title: format!("IP malveillante (C2) détectée dans les logs : {}", ip),
                    description: format!("L'IP {} est un IoC connu dans ThreatFox : {} ({}). {} hit(s).",
                        ip, r.threat_type, r.malware.as_deref().unwrap_or("?"), results.len()),
                    severity: "CRITICAL".into(),
                    asset: None,
                    source: "threatfox".into(),
                    metadata: json!({ "ip": ip, "threat_type": r.threat_type, "malware": r.malware, "hits": results.len() }),
                });
            }
            _ => {}
        }
    }

    // Cross-reference hashes with MalwareBazaar
    for hash in iocs.hashes.iter().take(5) {
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::enrichment::malware_bazaar::lookup_hash(hash, None),
        ).await {
            Ok(Ok(Some(info))) => {
                threats.push(DetectedThreat {
                    title: format!("Hash de malware détecté dans les logs : {}", &hash[..16]),
                    description: format!("Le hash {} correspond au malware {} ({}). Tags: {}.",
                        hash, info.signature.as_deref().unwrap_or("?"),
                        info.file_type.as_deref().unwrap_or("?"),
                        info.tags.join(", ")),
                    severity: "CRITICAL".into(),
                    asset: None,
                    source: "malware_bazaar".into(),
                    metadata: json!({ "hash": hash, "signature": info.signature, "tags": info.tags }),
                });
            }
            _ => {}
        }
    }

    // Cross-reference URLs with URLhaus
    for url in iocs.urls.iter().take(10) {
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::enrichment::urlhaus::lookup_url(url, None),
        ).await {
            Ok(Ok(Some(result))) if result.url_status == "online" => {
                threats.push(DetectedThreat {
                    title: format!("URL malveillante (malware) dans les logs : {}", truncate_str(url, 80)),
                    description: format!("L'URL {} distribue du malware ({}) selon URLhaus. Status: {}.",
                        url, result.threat.as_deref().unwrap_or("?"), result.url_status),
                    severity: "HIGH".into(),
                    asset: None,
                    source: "urlhaus".into(),
                    metadata: json!({ "url": url, "threat": result.threat, "status": result.url_status }),
                });
            }
            _ => {}
        }
    }

    threats
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}...", &s[..max]) }
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
