//! Intelligence Engine — threat correlation and scoring. See ADR-012, ADR-024.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::Timelike;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

// See ADR-030: investigation dedup (24h window)
static INVESTIGATION_BLOOM: std::sync::LazyLock<Arc<tokio::sync::RwLock<InvestigationDedup>>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::RwLock::new(InvestigationDedup::new())));

// Serialize LLM investigations — Ollama on CPU can handle only 1 concurrent inference effectively.
pub(crate) static INVESTIGATION_SEMAPHORE: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));

struct InvestigationDedup {
    /// asset → (verdict_type, investigated_at)
    seen: HashMap<String, (String, chrono::DateTime<chrono::Utc>)>,
}

impl InvestigationDedup {
    fn new() -> Self {
        Self { seen: HashMap::new() }
    }

    /// Check if an asset is still in cooldown from a previous investigation.
    /// Cooldown depends on verdict: confirmed/FP = 4h, inconclusive = 1h, other = 30min.
    fn is_in_cooldown(&self, asset: &str) -> bool {
        if let Some((verdict, when)) = self.seen.get(asset) {
            let cooldown_hours = match verdict.as_str() {
                "confirmed" | "false_positive" => 4.0,
                "inconclusive" => 1.0,
                _ => 0.5,
            };
            let elapsed = (chrono::Utc::now() - *when).num_seconds() as f64;
            elapsed < cooldown_hours * 3600.0
        } else {
            false
        }
    }

    fn record(&mut self, asset: String, verdict: String) {
        // Clean entries older than 24h
        let now = chrono::Utc::now();
        self.seen.retain(|_, (_, when)| (now - *when).num_hours() < 24);
        self.seen.insert(asset, (verdict, now));
    }
}

fn investigation_key(asset: &str, _situation: &AssetSituation) -> String {
    asset.to_string()
}

/// Clean L2 forensic LLM output: strip think blocks, extract text from JSON if needed, trim.
fn clean_l2_output(raw: &str) -> String {
    let mut text = raw.to_string();

    // 1. Strip <think>...</think> blocks (qwen3 reasoning traces)
    // Handle both paired <think>...</think> and orphan </think> (common when Ollama strips opening tag)
    while let Some(start) = text.find("<think>") {
        if let Some(end) = text.find("</think>") {
            text = format!("{}{}", &text[..start], &text[end + 8..]);
        } else {
            text = text[..start].to_string();
            break;
        }
    }
    // Handle orphan </think> without <think> — everything before it is think output, take what's after
    if let Some(end) = text.find("</think>") {
        text = text[end + 8..].to_string();
    }

    // 2. Strip markdown code fences
    let text = text
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    // 3. If it looks like JSON, extract human-readable fields
    if text.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
            return extract_text_from_l2_json(&v);
        }
    }

    // 4. Return cleaned text as-is (already plain text)
    text.to_string()
}

/// Extract human-readable text from structured L2 JSON output.
/// Handles multiple L2 output formats (nested analyse_forensique or flat summary/mitre/ioc/actions).
fn extract_text_from_l2_json(v: &serde_json::Value) -> String {
    // Unwrap nested wrappers: the LLM may produce various nesting levels like
    // {"analyse_forensique": {...}} or {"incident": {"analyse_forensique": {...}}}
    let unwrapped = v.get("incident").unwrap_or(v);
    let root = unwrapped.get("analyse_forensique")
        .or(unwrapped.get("forensic_analysis"))
        .or(unwrapped.get("analysis"))
        .unwrap_or(unwrapped);

    let mut parts: Vec<String> = Vec::new();

    // RÉSUMÉ — try multiple key names
    for key in &["summary", "resume_attaque", "1_resume_attaque", "resume", "résumé"] {
        if let Some(s) = root.get(key).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                parts.push(format!("RÉSUMÉ : {}", s));
                break;
            }
        }
    }

    // MITRE ATT&CK — try multiple key names
    for key in &["mitre_attck", "mitre_attck_techniques", "2_mitre_attck_techniques", "techniques"] {
        if let Some(techs) = root.get(key).and_then(|v| v.as_array()) {
            let tech_strs: Vec<String> = techs.iter().filter_map(|t| {
                if let Some(s) = t.as_str() { return Some(s.to_string()); }
                let id = t.get("technique_id").and_then(|v| v.as_str()).unwrap_or("?");
                let nom = t.get("technique_nom").or(t.get("name")).and_then(|v| v.as_str()).unwrap_or("");
                Some(format!("{} ({})", id, nom))
            }).collect();
            if !tech_strs.is_empty() {
                parts.push(format!("TECHNIQUES : {}", tech_strs.join(", ")));
                break;
            }
        }
    }

    // IOC — try multiple key names and formats
    for key in &["ioc", "3_ioc", "indicateurs_compromission"] {
        if let Some(ioc) = root.get(key) {
            if let Some(arr) = ioc.as_array() {
                let strs: Vec<String> = arr.iter().filter_map(|i| {
                    if let Some(s) = i.as_str() { return Some(s.to_string()); }
                    let typ = i.get("ioc_type").or(i.get("type")).and_then(|v| v.as_str()).unwrap_or("?");
                    let val = i.get("ioc_valeur").or(i.get("value")).and_then(|v| v.as_str()).unwrap_or("?");
                    Some(format!("{}: {}", typ, val))
                }).collect();
                if !strs.is_empty() { parts.push(format!("IOC : {}", strs.join(", "))); break; }
            } else if let Some(obj) = ioc.as_object() {
                let mut ioc_parts = Vec::new();
                for (k, val) in obj {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() && s != "null" { ioc_parts.push(format!("{}: {}", k, s)); }
                    } else if let Some(arr) = val.as_array() {
                        let vals: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                        if !vals.is_empty() { ioc_parts.push(format!("{}: {}", k, vals.join(", "))); }
                    } else if let Some(b) = val.as_bool() {
                        if b { ioc_parts.push(k.clone()); }
                    }
                }
                if !ioc_parts.is_empty() { parts.push(format!("IOC : {}", ioc_parts.join(", "))); break; }
            }
        }
    }

    // ACTIONS — try multiple key names
    for key in &["actions", "actions_prioritaires", "4_actions_recommandees_prioritaires", "actions_recommandees"] {
        if let Some(actions) = root.get(key).and_then(|v| v.as_array()) {
            let strs: Vec<String> = actions.iter().filter_map(|a| {
                if let Some(s) = a.as_str() { return Some(format!("- {}", s)); }
                a.get("action").and_then(|v| v.as_str()).map(|s| format!("- {}", s))
            }).collect();
            if !strs.is_empty() {
                parts.push(format!("ACTIONS :\n{}", strs.join("\n")));
                break;
            }
        }
    }

    if parts.is_empty() {
        // Fallback: extract string values from unknown JSON keys instead of dumping raw JSON.
        // Handles models that use unexpected key names (e.g. "root_cause" instead of "summary").
        let mut text_parts: Vec<String> = Vec::new();
        if let Some(obj) = v.as_object() {
            for (key, val) in obj {
                if let Some(s) = val.as_str() {
                    if !s.is_empty() && s.len() > 10 {
                        let label = key.replace('_', " ").to_uppercase();
                        text_parts.push(format!("{} : {}", label, s));
                    }
                } else if let Some(arr) = val.as_array() {
                    let strs: Vec<&str> = arr.iter().filter_map(|item| item.as_str()).collect();
                    if !strs.is_empty() {
                        let label = key.replace('_', " ").to_uppercase();
                        text_parts.push(format!("{} : {}", label, strs.join(", ")));
                    }
                }
            }
        }
        if text_parts.is_empty() {
            "Analyse disponible dans le dashboard.".to_string()
        } else {
            let combined = text_parts.join("\n\n");
            if combined.len() > 1500 {
                let mut end = 1500;
                while end > 0 && !combined.is_char_boundary(end) { end -= 1; }
                format!("{}...", &combined[..end])
            } else {
                combined
            }
        }
    } else {
        parts.join("\n\n")
    }
}

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
    /// Graph intelligence results (for notification enrichment)
    pub graph_intel: Option<GraphIntelSummary>,
}

/// Summary of graph intelligence results for the current cycle.
#[derive(Debug, Clone, Serialize)]
pub struct GraphIntelSummary {
    pub lateral_detections: usize,
    pub lateral_summary: String,
    pub campaigns_count: usize,
    pub campaigns_summary: String,
    pub actors_count: usize,
    pub actors_summary: String,
    pub identity_anomalies: usize,
    pub identity_summary: String,
    pub confidence_scores: Vec<(String, u8, String)>, // (ip, score, level)
}

/// Build an IncidentDossier from a SecuritySituation and its worst asset.
/// Re-fetches findings from DB for that specific asset.
async fn build_dossier_from_situation(
    store: &dyn Database,
    worst_asset: &AssetSituation,
    situation: &SecuritySituation,
) -> crate::agent::incident_dossier::IncidentDossier {
    use crate::agent::incident_dossier::*;

    // Re-fetch open findings for this specific asset
    let all_findings = store.list_findings(None, Some("open"), None, 500, 0).await.unwrap_or_default();
    // Collect findings for this asset, sorted by severity (CRITICAL first), limited to 10
    let severity_order = |s: &str| match s.to_uppercase().as_str() {
        "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, _ => 3,
    };
    // Exclude inventory/scan categories from investigation — these are not incidents
    const INVENTORY_CATEGORIES: &[&str] = &[
        "container-vuln", "sbom", "sast", "iac", "secrets", "hardening",
        "docker-cis", "recon", "vuln-scan", "dast",
    ];

    let mut asset_findings: Vec<DossierFinding> = all_findings.iter()
        .filter(|f| f.asset.as_deref() == Some(&worst_asset.asset))
        .filter(|f| {
            let cat = f.category.as_deref().unwrap_or("");
            !INVENTORY_CATEGORIES.contains(&cat)
        })
        .map(|f| {
            DossierFinding {
                id: f.id,
                title: f.title.clone(),
                description: f.description.clone(),
                severity: f.severity.clone(),
                asset: f.asset.clone(),
                source: f.source.clone(),
                metadata: f.metadata.clone(),
                detected_at: chrono::DateTime::parse_from_rfc3339(&f.detected_at)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
            }
        })
        .collect();
    asset_findings.sort_by(|a, b| severity_order(&a.severity).cmp(&severity_order(&b.severity)));
    asset_findings.truncate(10); // Top 10 most severe — keeps prompt manageable for local LLM

    // Extract kill chain steps from MITRE metadata
    let kill_chain_steps: Vec<MitreStep> = asset_findings.iter()
        .flat_map(|f| {
            let mitre = match f.metadata.get("mitre") {
                Some(m) => m.clone(),
                None => return vec![],
            };
            let ids: Vec<String> = if let Some(arr) = mitre.as_array() {
                arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
            } else if let Some(s) = mitre.as_str() {
                vec![s.to_string()]
            } else {
                return vec![];
            };
            ids.into_iter().map(|id| MitreStep {
                technique_id: id,
                technique_name: String::new(),
                tactic: String::new(),
                finding_id: f.id,
            }).collect::<Vec<_>>()
        })
        .collect();

    IncidentDossier {
        id: uuid::Uuid::new_v4(),
        created_at: chrono::Utc::now(),
        primary_asset: worst_asset.asset.clone(),
        findings: asset_findings,
        sigma_alerts: vec![],
        enrichment: EnrichmentBundle {
            ip_reputations: vec![],
            cve_details: vec![],
            threat_intel: vec![],
            enrichment_lines: vec![],
        },
        correlations: CorrelationBundle {
            kill_chain_detected: worst_asset.has_kill_chain,
            kill_chain_steps,
            active_attack: worst_asset.has_active_attack,
            known_exploits: vec![],
            related_assets: vec![],
            campaign_id: None,
        },
        graph_intel: situation.graph_intel.clone(),
        ml_scores: MlBundle {
            anomaly_score: 0.5, // Neutral default — will be enriched by ML if available
            dga_domains: vec![],
            behavioral_cluster: None,
        },
        asset_score: worst_asset.score,
        global_score: situation.global_score,
        notification_level: situation.notification_level,
    }
}

/// Run the intelligence engine cycle.
/// Returns the current security situation and recommended notification level.
pub async fn run_intelligence_cycle(
    store: Arc<dyn Database>,
) -> SecuritySituation {
    // Check if paused
    if let Ok(Some(paused)) = store.get_setting("_system", "tc_paused").await {
        if paused.as_bool() == Some(true) {
            tracing::debug!("INTELLIGENCE: Cycle skipped — system paused");
            return SecuritySituation {
                global_score: 100.0,
                notification_level: NotificationLevel::Silence,
                assets: vec![],
                new_findings_count: 0,
                new_alerts_count: 0,
                total_open_findings: 0,
                total_active_alerts: 0,
                digest_message: "System paused".into(),
                alert_message: None,
                computed_at: chrono::Utc::now().to_rfc3339(),
                graph_intel: None,
            };
        }
    }

    let now = chrono::Utc::now();

    // See ADR-030: per-cycle caches
    let mut asset_cache: HashMap<String, String> = HashMap::new();

    // ── 0. Sync the threat graph from DB ──
    crate::graph::threat_graph::sync_graph_from_db(store.as_ref()).await;

    // ── 1. Collect all open findings ──
    let findings = store.list_findings(None, Some("open"), None, 500, 0).await.unwrap_or_default();
    let alerts = store.list_alerts(None, Some("new"), 200, 0).await.unwrap_or_default();

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

    // ── 3. Overlay alerts on assets (resolve hostnames/IPs to asset names) ──
    // Resolution cascade: IP → hostname/name → source_ip → raw fallback
    // Uses per-cycle cache to avoid repeated DB queries for the same hostname
    for a in &alerts {
        let raw_host = a.hostname.as_deref().unwrap_or("unknown");

        // Check per-cycle cache first (~0ns vs ~2ms DB query)
        let asset_name = if let Some(cached) = asset_cache.get(raw_host) {
            cached.clone()
        } else {
            // Cache miss → resolve via DB cascade
            let resolved = if let Ok(Some(found)) = store.find_asset_by_ip(raw_host).await {
                found.name.clone()
            } else if let Ok(Some(found)) = store.find_asset_by_hostname(raw_host).await {
                found.name.clone()
            } else if let Some(ref src_ip) = a.source_ip {
                let clean_ip = src_ip.split('/').next().unwrap_or("").trim();
                if !clean_ip.is_empty() {
                    if let Ok(Some(found)) = store.find_asset_by_ip(clean_ip).await {
                        found.name.clone()
                    } else {
                        raw_host.to_string()
                    }
                } else {
                    raw_host.to_string()
                }
            } else {
                raw_host.to_string()
            };
            // Store in cache for this cycle
            asset_cache.insert(raw_host.to_string(), resolved.clone());
            resolved
        };

        let entry = asset_map.entry(asset_name.clone()).or_insert_with(|| AssetSituation {
            asset: asset_name.clone(), score: 0.0,
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

    // ── 4. Score each asset (with ML adjustment) ──
    // See ADR-030: batch fetch all ML scores in one query instead of N queries
    let ml_scores = store.get_all_ml_scores().await.unwrap_or_default();
    for entry in asset_map.values_mut() {
        entry.score = compute_asset_score(entry);

        if let Some((ml_score, ml_reason)) = ml_scores.get(&entry.asset) {
            let ml_score = *ml_score;
            let ml_reason = ml_reason.clone();
            if ml_score < 0.3 && entry.score < 50.0 {
                // ML says this is normal behavior → downgrade
                entry.score = (entry.score * 0.5).max(0.0);
                entry.summary = format!("{} [ML: normal behavior, score reduced]", entry.summary);
            } else if ml_score > 0.7 {
                // ML says this is anomalous → boost score
                let boost = ml_score * 30.0;
                entry.score = (entry.score + boost).min(100.0);
                entry.summary = format!("{} [ML anomaly {:.0}%: {}]", entry.summary, ml_score * 100.0, ml_reason);
            }
        }

        entry.summary = if entry.summary.is_empty() { build_asset_summary(entry) } else { entry.summary.clone() };
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
    let mut confidence_scores: Vec<(String, u8, String)> = vec![];
    for a in alerts.iter().take(5) {
        if let Some(ref ip) = a.source_ip {
            let clean_ip = ip.split('/').next().unwrap_or(ip).trim();
            if !clean_ip.is_empty() && !crate::agent::ip_classifier::is_non_routable(clean_ip) {
                let hour = chrono::Utc::now().hour();
                let host = a.hostname.as_deref();
                let score = crate::graph::confidence::compute_ip_confidence(
                    store.as_ref(), clean_ip, host, Some(hour),
                ).await;
                confidence_scores.push((clean_ip.to_string(), score.score, score.level.to_string()));
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

    // ── 5h. BEHAVIORAL SCORING — score recent logins against baselines ──
    for a in alerts.iter().take(5) {
        if let (Some(ip), Some(host)) = (&a.source_ip, &a.hostname) {
            let clean_ip = ip.split('/').next().unwrap_or(ip).trim();
            // Extract username from alert if available
            let username = a.title.split("for ").nth(1)
                .or(a.title.split("user ").nth(1))
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("");
            if !username.is_empty() && !clean_ip.is_empty() {
                let score = crate::graph::behavior::score_login(
                    store.as_ref(), username, clean_ip, host, true,
                ).await;
                if score.total_score >= 50 {
                    tracing::warn!("BEHAVIOR: {} score {}/100 ({})", username, score.total_score, score.level);
                }
            }
        }
    }

    // See ADR-030: single log fetch shared between scan_logs, Bloom check, and NDR skills
    let mut finding_dedup: HashSet<String> = HashSet::new();
    let recent_logs = store.query_logs(10, None, None, 2000).await.unwrap_or_default();

    // ── 5i. SCAN RECENT LOGS for IoCs (URLs, IPs, hashes) ──
    let log_scan_results = scan_logs_for_threats(store.clone(), &recent_logs).await;
    for threat in &log_scan_results {
        let dedup_key = format!("{}|{}|{}", threat.title, threat.asset.as_deref().unwrap_or(""), threat.source);
        if !finding_dedup.insert(dedup_key) { continue; }
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
        let findings = store.list_findings(None, Some("open"), None, 500, 0).await.unwrap_or_default();
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

    // ── 5j. BLOOM FILTER — uses shared recent_logs (See ADR-030)
    {
        let mut bloom_hits = 0u32;
        for log in &recent_logs {
            let detected = crate::agent::ioc_bloom::check_log(&log.data, log.hostname.as_deref(), store.as_ref()).await;
            for ioc in &detected {
                let dedup_key = format!("bloom|{}|{}", ioc.ioc_type, ioc.ioc_value);
                if !finding_dedup.insert(dedup_key) { continue; }
                let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
                    skill_id: "bloom-ioc".into(),
                    title: format!("{} malveillant détecté: {}", ioc.ioc_type.to_uppercase(), ioc.ioc_value),
                    description: Some(format!("IoC de type {} identifié par Bloom filter, confirmé par {}", ioc.ioc_type, ioc.source)),
                    severity: ioc.severity.clone(),
                    category: Some("ioc-detection".into()),
                    asset: ioc.hostname.clone(),
                    source: Some(ioc.source.clone()),
                    metadata: Some(serde_json::json!({
                        "ioc_type": ioc.ioc_type,
                        "ioc_value": ioc.ioc_value,
                        "detection": "bloom-filter"
                    })),
                }).await;
                bloom_hits += 1;
            }
        }
        if bloom_hits > 0 {
            tracing::info!("BLOOM: {} IoC confirmed from {} logs", bloom_hits, recent_logs.len());
        }
    }

    // ── 5k. SIGMA ENGINE — native rule matching on recent logs ──
    crate::agent::sigma_engine::run_sigma_cycle(store.clone(), 5).await;

    // ── 5l. NDR — JA3 fingerprinting, beacon detection, TLS scoring, DNS tunneling, SNI ──
    // NDR analysis — See ADR-005, ADR-007, SESSION_2026-04-06.md
    let ja3_result = crate::agent::ndr_ja3::scan_ja3(store.clone(), 5).await;
    let beacon_result = crate::agent::ndr_beacon::scan_beacons(store.clone(), 60).await; // 1h window for timing analysis
    let tls_result = crate::agent::ndr_tls::scan_tls(store.clone(), 5).await;
    let dns_tunnel_result = crate::agent::ndr_dns_tunnel::scan_dns_tunnels(store.clone(), 60).await; // 1h window for volume analysis
    let sni_result = crate::agent::ndr_sni::scan_sni(store.clone(), 5).await;
    let ransomware_result = crate::agent::ndr_ransomware::scan_ransomware(store.clone(), 15).await; // 15min window for file ops
    let ndr_total = ja3_result.matches_found + beacon_result.beacons_detected
        + tls_result.anomalies_found + dns_tunnel_result.tunnels_detected
        + sni_result.suspects_found + ransomware_result.suspects_found;
    if ndr_total > 0 {
        tracing::info!(
            "NDR: JA3={} beacons={} TLS={} DNS-tunnel={} SNI={} ransomware={}",
            ja3_result.matches_found, beacon_result.beacons_detected,
            tls_result.anomalies_found, dns_tunnel_result.tunnels_detected,
            sni_result.suspects_found, ransomware_result.suspects_found
        );
    }

    // ── 5m. RETROACT — nocturnal re-scan of suspect findings (03:00-03:05 window) ──
    {
        let hour = chrono::Utc::now().hour();
        let minute = chrono::Utc::now().minute();
        if hour == 3 && minute < 5 {
            let retroact_result = crate::agent::retroact::run_retroact_cycle(store.clone()).await;
            if retroact_result.candidates_checked > 0 {
                tracing::info!(
                    "RETROACT: {} checked, {} upgraded, {} cleared",
                    retroact_result.candidates_checked, retroact_result.upgraded, retroact_result.cleared
                );
            }
        }
    }

    // ── 5n. CTI FEED SYNC — unified threat intel (every 6 hours) ──
    {
        let hour = chrono::Utc::now().hour();
        let minute = chrono::Utc::now().minute();
        // Run at 00:00, 06:00, 12:00, 18:00 (±5 min)
        if hour % 6 == 0 && minute < 5 {
            let cti_result = crate::enrichment::cti_feed::sync_all_feeds(store.as_ref()).await;
            tracing::info!(
                "CTI-FEED: {} sources synced, {} new IoCs, {} errors",
                cti_result.sources_synced, cti_result.iocs_new, cti_result.errors.len()
            );
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
            if ip_str.is_empty() || crate::agent::ip_classifier::is_non_routable(ip_str) {
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
    let lang = crate::agent::prompt_builder::get_language(store.as_ref()).await;
    let mut assets: Vec<AssetSituation> = asset_map.into_values().collect();
    assets.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    let digest_message = build_digest_message(&assets, global_score, findings.len(), alerts.len(), &lang);
    // Build graph intel summary
    let graph_intel = GraphIntelSummary {
        lateral_detections: lateral.total_detections,
        lateral_summary: lateral.summary.clone(),
        campaigns_count: campaigns.total_campaigns,
        campaigns_summary: campaigns.summary.clone(),
        actors_count: actors.total_actors,
        actors_summary: actors.summary.clone(),
        identity_anomalies: identity.anomalies.len(),
        identity_summary: identity.summary.clone(),
        confidence_scores: confidence_scores.clone(),
    };

    let alert_message = if notification_level >= NotificationLevel::Alert {
        Some(build_enriched_alert_message(&assets, &alerts, &enrichment_lines, &findings, &graph_intel, &lang))
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
        graph_intel: Some(graph_intel),
    };

    // Persist for dashboard (full situation including assets)
    let _ = store.set_setting("_system", "security_situation", &json!({
        "global_score": situation.global_score,
        "notification_level": situation.notification_level,
        "new_findings_count": situation.new_findings_count,
        "total_open_findings": situation.total_open_findings,
        "total_active_alerts": situation.total_active_alerts,
        "assets_at_risk": situation.assets.iter().filter(|a| a.score > 30.0).count(),
        "assets": situation.assets,
        "computed_at": situation.computed_at,
        "digest_message": situation.digest_message,
    })).await;
    let _ = store.record_metric("security_score", global_score, &json!({})).await;

    tracing::info!(
        "INTELLIGENCE: Score={:.0} Level={:?} Findings={} Alerts={} Assets={}",
        global_score, notification_level, findings.len(), alerts.len(), situation.assets.len()
    );

    // ── Remind if unresolved — check stale open incidents that nobody responded to ──
    check_unresolved_reminders(store.as_ref()).await;

    // ── Daily digest — send once per day at configured time ──
    check_daily_digest(store.as_ref(), &situation).await;

    // ── Daily backup — fire once per day at the configured time ──
    crate::agent::backup_manager::check_daily_backup(store.as_ref()).await;

    // ── Daily cleanup — purge old sigma alerts past retention ──
    check_daily_cleanup(store.as_ref()).await;

    // ── Self-heal: re-trigger MITRE sync if table is empty ──
    self_heal_mitre(store.as_ref()).await;

    situation
}

/// Self-heal MITRE: if the techniques table is empty and the last retry is old enough,
/// trigger a background sync. Avoids hammering the GitHub raw URL on persistent failures.
async fn self_heal_mitre(store: &dyn Database) {
    // Only check once per cycle group (the cycle itself runs every ~45s)
    let count = store.count_mitre_techniques().await.unwrap_or(0);
    if count > 0 { return; }

    // 6h cooldown between retries
    if let Ok(Some(last)) = store.get_setting("_system", "last_mitre_retry").await {
        if let Some(ts) = last.as_str() {
            if let Ok(last_dt) = chrono::DateTime::parse_from_rfc3339(ts) {
                let elapsed = (chrono::Utc::now() - last_dt.with_timezone(&chrono::Utc)).num_seconds();
                if elapsed < 6 * 3600 { return; }
            }
        }
    }

    tracing::warn!("SELF_HEAL: mitre_techniques is empty — retrying sync");
    let _ = store.set_setting("_system", "last_mitre_retry",
        &serde_json::json!(chrono::Utc::now().to_rfc3339())).await;
    match crate::enrichment::mitre_attack::sync_attack_techniques(store).await {
        Ok(n) => tracing::info!("SELF_HEAL: MITRE sync OK ({} techniques)", n),
        Err(e) => tracing::warn!("SELF_HEAL: MITRE sync failed: {}", e),
    }
}

/// Run cleanup tasks once per day: purge old acknowledged/resolved sigma alerts,
/// VACUUM logs to reclaim bloat. Default retention: 30 days.
async fn check_daily_cleanup(store: &dyn Database) {
    let now = chrono::Utc::now();
    // Run only once per day, just after midnight
    let cur_h = now.format("%H").to_string().parse::<u32>().unwrap_or(0);
    if cur_h != 3 { return; } // Run between 03:00 and 03:10 UTC

    let today = now.format("%Y-%m-%d").to_string();
    if let Ok(Some(last)) = store.get_setting("_system", "last_daily_cleanup").await {
        if last.as_str() == Some(today.as_str()) { return; }
    }

    tracing::info!("CLEANUP: Running daily cleanup (sigma alerts retention + archived purge)");
    match store.cleanup_old_sigma_alerts(30).await {
        Ok(deleted) => tracing::info!("CLEANUP: Purged {} old sigma alerts", deleted),
        Err(e) => tracing::warn!("CLEANUP: Failed to purge sigma alerts: {}", e),
    }
    // Permanently delete archived incidents/alerts older than 60 days.
    // Gives the RSSI a 2-month window to recover from an accidental archive
    // before data is gone for good.
    match store.purge_old_archived(60).await {
        Ok((inc, al)) => tracing::info!("CLEANUP: Purged {} archived incidents, {} archived alerts", inc, al),
        Err(e) => tracing::warn!("CLEANUP: Failed to purge archived: {}", e),
    }
    let _ = store.set_setting("_system", "last_daily_cleanup", &serde_json::json!(today)).await;
}

/// Re-notify for unresolved incidents past the reminder threshold.
async fn check_unresolved_reminders(store: &dyn Database) {
    let settings = crate::agent::notification_router::load_notification_settings(store).await;

    // Only process CRITICAL and HIGH reminders (if configured)
    let thresholds: Vec<(&str, i64)> = vec![
        ("CRITICAL", settings.remind_unresolved_critical_secs),
        ("HIGH", settings.remind_unresolved_high_secs),
    ];

    for (severity, remind_secs) in thresholds {
        if remind_secs <= 0 { continue; }

        // Find open incidents of this severity that have been stale for > remind_secs
        let incidents = store.list_incidents(Some("open"), 50, 0).await.unwrap_or_default();
        for inc in &incidents {
            let inc_severity = inc["severity"].as_str().unwrap_or("");
            if inc_severity != severity { continue; }

            let inc_id = inc["id"].as_i64().unwrap_or(0) as i32;
            let asset = inc["asset"].as_str().unwrap_or("");
            let hitl_status = inc["hitl_status"].as_str().unwrap_or("");

            // Skip if already responded
            if hitl_status == "responded" || hitl_status == "approved" { continue; }

            // Check if we already sent a reminder recently (use a separate cooldown key)
            let remind_key = format!("last_remind:{}:{}", asset, inc_id);
            let should_remind = match store.get_setting("_system", &remind_key).await {
                Ok(Some(prev)) => {
                    if let Some(ts) = prev.as_str() {
                        if let Ok(last) = chrono::DateTime::parse_from_rfc3339(ts) {
                            (chrono::Utc::now() - last.with_timezone(&chrono::Utc)).num_seconds() > remind_secs
                        } else { true }
                    } else { true }
                }
                _ => {
                    // No remind key — check incident age
                    if let Some(created_str) = inc["created_at"].as_str() {
                        if let Ok(created) = chrono::DateTime::parse_from_rfc3339(created_str) {
                            (chrono::Utc::now() - created.with_timezone(&chrono::Utc)).num_seconds() > remind_secs
                        } else { false }
                    } else { false }
                }
            };

            if should_remind {
                tracing::info!("REMIND: Incident #{} ({} {}) unresolved after {}h — re-notifying",
                    inc_id, asset, severity, remind_secs / 3600);
                let summary = inc["summary"].as_str().unwrap_or("Incident non résolu");
                let remind_text = format!("⏰ RAPPEL — Incident #{} ({}) non traité depuis {}h",
                    inc_id, asset, remind_secs / 3600);
                crate::agent::notification_router::route_incident_notification(
                    store, inc_id, asset, &remind_text, summary, severity, 0
                ).await;
                let _ = store.set_setting("_system", &remind_key,
                    &serde_json::json!(chrono::Utc::now().to_rfc3339())).await;
            }
        }
    }
}

/// Daily digest: sends a summary once per day at the configured time.
async fn check_daily_digest(store: &dyn Database, situation: &SecuritySituation) {
    let settings = crate::agent::notification_router::load_notification_settings(store).await;
    if !settings.daily_digest_enabled { return; }

    // Parse target time
    let parts: Vec<&str> = settings.daily_digest_time.split(':').collect();
    let target_h = parts.first().and_then(|h| h.parse::<u32>().ok()).unwrap_or(8);
    let target_m = parts.get(1).and_then(|m| m.parse::<u32>().ok()).unwrap_or(0);

    // Approximate local time (same logic as quiet hours)
    let now = chrono::Utc::now();
    let tz_offset = if let Ok(Some(profile)) = store.get_setting("_system", "company_profile").await {
        let tz = profile["business_hours"]["timezone"].as_str().unwrap_or("Europe/Paris");
        if tz.contains("Paris") || tz.contains("Berlin") || tz.contains("CET") { 2i64 } else { 0 }
    } else { 2 }; // Default to Europe/Paris
    let local_h = ((now.format("%H").to_string().parse::<i64>().unwrap_or(12) + tz_offset) % 24) as u32;
    let local_m = now.format("%M").to_string().parse::<u32>().unwrap_or(0);

    // Only fire within a 10-min window of the target time
    let target_min = target_h * 60 + target_m;
    let local_min = local_h * 60 + local_m;
    if local_min < target_min || local_min > target_min + 10 { return; }

    // Check if already sent today
    let today = now.format("%Y-%m-%d").to_string();
    let digest_key = "last_daily_digest";
    if let Ok(Some(last)) = store.get_setting("_system", digest_key).await {
        if last.as_str() == Some(today.as_str()) { return; }
    }

    // Build digest
    let open_incidents = store.list_incidents(Some("open"), 10, 0).await.unwrap_or_default();
    let open_count = open_incidents.len();
    let critical_count = open_incidents.iter().filter(|i| i["severity"].as_str() == Some("CRITICAL")).count();

    let digest = format!(
        "📊 DIGEST QUOTIDIEN — {}\n\
         ━━━━━━━━━━━━━━━━━━━━━━\n\
         Score sécurité : {:.0}/100\n\
         Incidents ouverts : {} (dont {} CRITICAL)\n\
         Alertes actives : {}\n\
         Vulnérabilités : {}\n\
         ━━━━━━━━━━━━━━━━━━━━━━\n\n\
         {}",
        today,
        situation.global_score,
        open_count,
        critical_count,
        situation.total_active_alerts,
        situation.total_open_findings,
        if open_count == 0 { "Aucun incident en cours. Bonne journée ! 👍".into() }
        else {
            let top: Vec<String> = open_incidents.iter().take(3).map(|i| {
                format!("  • #{} {} — {} ({})",
                    i["id"].as_i64().unwrap_or(0),
                    i["asset"].as_str().unwrap_or("?"),
                    i["severity"].as_str().unwrap_or("?"),
                    i["verdict"].as_str().unwrap_or("pending"))
            }).collect();
            format!("Top incidents :\n{}", top.join("\n"))
        }
    );

    crate::agent::notification_router::route_notification(
        store,
        NotificationLevel::Digest,
        &digest,
        &digest,
    ).await;

    let _ = store.set_setting("_system", digest_key, &serde_json::json!(today)).await;
    tracing::info!("DIGEST: Daily digest sent for {}", today);
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
    lang: &str,
) -> String {
    let date = chrono::Utc::now().format("%d/%m/%Y").to_string();
    let en = lang == "en";
    let mut msg = if en {
        format!("*ThreatClaw — Digest {}*\n\nSecurity score: *{:.0}/100*\n", date, global_score)
    } else {
        format!("*ThreatClaw — Digest {}*\n\nScore sécurité : *{:.0}/100*\n", date, global_score)
    };

    if !assets.is_empty() {
        msg.push_str(if en { "\n*At-risk assets:*\n" } else { "\n*Assets à risque :*\n" });
        for asset in assets.iter().take(5) {
            let level = if asset.score >= 60.0 {
                if en { "CRITICAL" } else { "CRITIQUE" }
            } else if asset.score >= 30.0 {
                if en { "WARNING" } else { "ATTENTION" }
            } else { "OK" };
            msg.push_str(&format!(
                "  {} [{}] — {} findings, {} {}\n",
                asset.asset, level,
                asset.findings_critical + asset.findings_high + asset.findings_medium + asset.findings_low,
                asset.active_alerts,
                if en { "alerts" } else { "alertes" },
            ));
        }
    }

    if en {
        msg.push_str(&format!("\nOpen findings: {}\nActive alerts: {}\n", findings_count, alerts_count));
    } else {
        msg.push_str(&format!("\nFindings ouverts : {}\nAlertes actives : {}\n", findings_count, alerts_count));
    }

    if global_score >= 80.0 {
        msg.push_str(if en { "\n_No action required._" } else { "\n_Aucune action requise._" });
    } else if global_score >= 50.0 {
        msg.push_str(if en {
            "\n_Some items need attention — check the dashboard for details._"
        } else {
            "\n_Quelques points d'attention — voir le dashboard pour les détails._"
        });
    } else {
        msg.push_str(if en {
            "\n_Degraded situation — action recommended._"
        } else {
            "\n_Situation dégradée — action recommandée._"
        });
    }

    msg
}

/// Build an immediate alert message (basic, without enrichment).
fn build_alert_message(
    assets: &[AssetSituation],
    alerts: &[crate::db::threatclaw_store::AlertRecord],
    findings: &[crate::db::threatclaw_store::FindingRecord],
    lang: &str,
) -> String {
    let empty_intel = GraphIntelSummary {
        lateral_detections: 0, lateral_summary: String::new(),
        campaigns_count: 0, campaigns_summary: String::new(),
        actors_count: 0, actors_summary: String::new(),
        identity_anomalies: 0, identity_summary: String::new(),
        confidence_scores: vec![],
    };
    build_enriched_alert_message(assets, alerts, &[], findings, &empty_intel, lang)
}

/// Build an enriched alert message with all intelligence data.
fn build_enriched_alert_message(
    assets: &[AssetSituation],
    alerts: &[crate::db::threatclaw_store::AlertRecord],
    enrichment: &[String],
    findings: &[crate::db::threatclaw_store::FindingRecord],
    graph_intel: &GraphIntelSummary,
    lang: &str,
) -> String {
    let en = lang == "en";
    let critical_assets: Vec<&AssetSituation> = assets.iter()
        .filter(|a| a.score >= 30.0)
        .collect();

    let is_critical = critical_assets.iter().any(|a| a.has_kill_chain || a.has_known_exploit || a.findings_critical > 0);

    let mut msg = String::new();

    // ── Header with emoji severity ──
    if is_critical {
        msg.push_str(if en { "*CRITICAL ALERT*\n" } else { "*ALERTE CRITIQUE*\n" });
    } else {
        msg.push_str(if en { "*Security alert*\n" } else { "*Alerte securite*\n" });
    }
    msg.push_str("━━━━━━━━━━━━━━━━━━━━━\n\n");

    // ── LLM Analysis ──
    let ai_finding = findings.iter().rev()
        .find(|f| f.source.as_deref() == Some("threatclaw-l1") || f.source.as_deref() == Some("threatclaw-l2"));
    if let Some(f) = ai_finding {
        if let Some(ref desc) = f.description {
            let analysis = desc.split("Corrélations :").next().unwrap_or(desc)
                .replace("Analyse automatique par ThreatClaw AI :\n", "")
                .trim().to_string();
            let source = if f.source.as_deref() == Some("threatclaw-l2") { "L2 Forensique" } else { "L1 Triage" };
            if !analysis.is_empty() {
                msg.push_str(&format!("*Analyse {}*\n{}\n\n", source, analysis));
            }
        }
    }

    // ── Assets impactes (clean format) ──
    if !critical_assets.is_empty() {
        msg.push_str(if en { "*Impacted assets*\n" } else { "*Assets impactes*\n" });
        for asset in critical_assets.iter().take(3) {
            let mut flags = vec![];
            if asset.has_kill_chain { flags.push("kill chain"); }
            if asset.has_known_exploit { flags.push(if en { "active exploit" } else { "exploit actif" }); }
            if asset.has_active_attack { flags.push(if en { "ongoing attack" } else { "attaque en cours" }); }
            if asset.findings_critical > 0 { flags.push(if en { "critical vuln" } else { "vuln critique" }); }
            let flag_str = if flags.is_empty() { String::new() } else { format!(" ({})", flags.join(", ")) };
            msg.push_str(&format!("  {} — {:.0}/100{}\n", asset.asset, asset.score, flag_str));
        }
        msg.push('\n');
    }

    // ── Graph Intelligence (NEW — the key addition) ──
    let mut intel_lines = vec![];

    // Confidence scores
    for (ip, score, level) in &graph_intel.confidence_scores {
        let label = if en { "Confidence" } else { "Confiance" };
        intel_lines.push(format!("{} {} : {}/100 ({})", label, ip, score, level));
    }

    // Lateral movement
    if graph_intel.lateral_detections > 0 {
        let label = if en { "Lateral movement" } else { "Mouvement lateral" };
        intel_lines.push(format!("{} : {}", label, graph_intel.lateral_summary.lines().next().unwrap_or("")));
    }

    // Campaigns
    if graph_intel.campaigns_count > 0 {
        let label = if en { "Campaign" } else { "Campagne" };
        intel_lines.push(format!("{} : {}", label, graph_intel.campaigns_summary.lines().next().unwrap_or("")));
    }

    // Threat actors
    if graph_intel.actors_count > 0 {
        let label = if en { "Actors" } else { "Acteurs" };
        intel_lines.push(format!("{} : {}", label, graph_intel.actors_summary));
    }

    // Identity anomalies
    if graph_intel.identity_anomalies > 0 {
        let label = if en { "Identity" } else { "Identite" };
        intel_lines.push(format!("{} : {}", label, graph_intel.identity_summary));
    }

    if !intel_lines.is_empty() {
        msg.push_str(if en { "*Graph Intelligence*\n" } else { "*Graph Intelligence*\n" });
        for line in intel_lines.iter().take(5) {
            msg.push_str(&format!("  {}\n", line));
        }
        msg.push('\n');
    }

    // ── Top alerts (max 3, clean format) ──
    if !alerts.is_empty() {
        msg.push_str(&format!("*{} ({} total)*\n", if en { "Alerts" } else { "Alertes" }, alerts.len()));
        for a in alerts.iter().take(3) {
            let src = a.source_ip.as_deref()
                .map(|ip| format!(" — {}", ip.split('/').next().unwrap_or(ip)))
                .unwrap_or_default();
            msg.push_str(&format!("  [{}] {}{}\n", a.level.to_uppercase(), a.title, src));
        }
        if alerts.len() > 3 {
            msg.push_str(&format!("  +{} {}\n", alerts.len() - 3, if en { "more" } else { "autres" }));
        }
        msg.push('\n');
    }

    // ── Enrichment (max 3 lines) ──
    if !enrichment.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let deduped: Vec<&String> = enrichment.iter()
            .filter(|line| seen.insert(line.as_str()))
            .collect();
        if !deduped.is_empty() {
            msg.push_str(if en { "*Enrichment*\n" } else { "*Enrichissement*\n" });
            for line in deduped.iter().take(3) {
                msg.push_str(&format!("  {}\n", line));
            }
            msg.push('\n');
        }
    }

    // ── Footer ──
    msg.push_str("━━━━━━━━━━━━━━━━━━━━━\n");
    msg.push_str(&crate::branding::notification_footer());
    msg.push_str(if en { "\n_Dashboard: /intelligence_" } else { "\n_Dashboard : /intelligence_" });

    // Telegram limit is 4096 chars
    if msg.len() > 4000 {
        msg.truncate(3900);
        msg.push_str(if en { "\n...\n_[see dashboard /intelligence]_" } else { "\n...\n_[voir dashboard /intelligence]_" });
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
    nonce_manager: Option<Arc<crate::agent::hitl_nonce::NonceManager>>,
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
            let _ = crate::enrichment::misp_circl::sync_feed(store_sync.as_ref()).await;
            tracing::info!("INTELLIGENCE: Background enrichment sync complete");
            // Build Bloom filter from cached feeds (includes MISP)
            crate::agent::ioc_bloom::init(store_sync.as_ref()).await;
            crate::agent::sigma_engine::init(store_sync.as_ref()).await;
        });

        // Spawn Shift Report loop (Quart de Veille) — periodic L2 situation analysis
        let store_shift = store.clone();
        tokio::spawn(async move {
            crate::agent::shift_report::run_shift_loop(store_shift).await;
        });

        // See ADR-041: dynamic cycle interval based on situation score
        let mut next_interval = interval;
        let mut last_misp_sync = chrono::Utc::now();
        let mut last_daily_sync = chrono::Utc::now();

        // Skip first tick to let boot complete
        tokio::time::sleep(interval).await;

        loop {
            let now = chrono::Utc::now();

            // 6-hour MISP sync (timestamp-based, works with any cycle interval)
            if (now - last_misp_sync).num_hours() >= 6 {
                last_misp_sync = now;
                let store_misp = store.clone();
                tokio::spawn(async move {
                    match crate::enrichment::misp_circl::sync_feed(store_misp.as_ref()).await {
                        Ok(count) => tracing::info!("MISP: Synced {} IoC from CIRCL OSINT", count),
                        Err(e) => tracing::warn!("MISP: Sync failed: {e}"),
                    }
                    crate::agent::ioc_bloom::refresh(store_misp.as_ref()).await;
                });
            }

            // Daily re-sync (timestamp-based)
            if (now - last_daily_sync).num_hours() >= 24 {
                last_daily_sync = now;
                tracing::info!("INTELLIGENCE: Daily enrichment re-sync");
                let store_resync = store.clone();
                tokio::spawn(async move {
                    let _ = crate::enrichment::cisa_kev::sync_kev(store_resync.as_ref()).await;
                    let _ = crate::enrichment::certfr::sync_certfr_alerts(store_resync.as_ref()).await;
                    let _ = crate::enrichment::openphish::sync_feed(store_resync.as_ref()).await;
                    crate::agent::ioc_bloom::refresh(store_resync.as_ref()).await;
                    crate::agent::sigma_engine::reload(store_resync.as_ref()).await;
                    // Daily software vulnerability scan across all assets
                    crate::enrichment::software_vuln::scan_all_assets(store_resync).await;
                });
            }

            let situation = run_intelligence_cycle(store.clone()).await;

            // Dynamic interval: adapt speed to threat level
            let has_kill_chain = situation.assets.iter().any(|a| a.has_kill_chain || a.has_active_attack);
            next_interval = if has_kill_chain {
                std::time::Duration::from_secs(30)
            } else if situation.global_score < 50.0 {
                std::time::Duration::from_secs(60)
            } else if situation.global_score < 80.0 {
                std::time::Duration::from_secs(120)
            } else {
                interval // default (5 min)
            };

            tracing::debug!("INTELLIGENCE: Next cycle in {}s (score={:.0})", next_interval.as_secs(), situation.global_score);

            // ── V3: Escalate to ReAct investigation instead of notifying directly ──
            if situation.notification_level >= NotificationLevel::Alert {
                // Find the worst asset
                if let Some(worst_asset) = situation.assets.iter()
                    .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
                {
                    let registry = crate::agent::investigation::get_registry();
                    let inv_key = investigation_key(&worst_asset.asset, worst_asset);

                    // Skip if same asset still in cooldown from previous investigation
                    let already_investigated = {
                        let dedup = INVESTIGATION_BLOOM.read().await;
                        dedup.is_in_cooldown(&inv_key)
                    };

                    if already_investigated {
                        tracing::debug!("INTELLIGENCE: Skipping investigation for {} — same pattern already investigated", worst_asset.asset);
                    } else if !registry.is_investigating(&worst_asset.asset).await {
                        // Build dossier from the worst asset's data
                        let dossier = build_dossier_from_situation(
                            store.as_ref(),
                            worst_asset,
                            &situation,
                        ).await;

                        tracing::info!("INTELLIGENCE: Escalating to investigation — {}", dossier.summary());

                        // See ADR-043: create incident in DB before investigation
                        let alert_ids: Vec<i32> = vec![];
                        let finding_ids: Vec<i32> = dossier.findings.iter().map(|f| f.id as i32).collect();

                        // Derive security severity from worst finding, or fallback to notification level
                        let incident_severity = dossier.findings.iter()
                            .map(|f| f.severity.to_uppercase())
                            .max_by_key(|s| match s.as_str() {
                                "CRITICAL" => 4, "HIGH" => 3, "MEDIUM" => 2, "LOW" => 1, _ => 0,
                            })
                            .unwrap_or_else(|| match situation.notification_level {
                                NotificationLevel::Alert => "HIGH".to_string(),
                                _ => format!("{:?}", situation.notification_level).to_uppercase(),
                            });

                        // Deduplicate: if an open incident exists for this asset within the last 4h,
                        // touch it (update alert_count + updated_at) instead of creating a duplicate.
                        // Prevents Telegram spam when a recurring pattern keeps firing.
                        let incident_id = match store.find_open_incident_for_asset(&worst_asset.asset).await {
                            Ok(Some(existing_id)) => {
                                tracing::info!(
                                    "INTELLIGENCE: Reusing existing incident #{} for {} (within 4h dedup window)",
                                    existing_id, worst_asset.asset
                                );
                                let _ = store.touch_incident(existing_id, worst_asset.active_alerts as i32).await;
                                existing_id
                            }
                            _ => {
                                let new_id = store.create_incident(
                                    &worst_asset.asset,
                                    &dossier.summary(),
                                    &incident_severity,
                                    &alert_ids,
                                    &finding_ids,
                                    worst_asset.active_alerts as i32,
                                ).await.unwrap_or(-1);
                                if new_id > 0 {
                                    tracing::info!("INTELLIGENCE: Incident #{} created for {}", new_id, worst_asset.asset);
                                }
                                new_id
                            }
                        };

                        let dossier_id = dossier.id;
                        if registry.try_register(&worst_asset.asset, dossier_id).await {
                            let store_inv = store.clone();
                            let asset_name = worst_asset.asset.clone();
                            let registry_ref = crate::agent::investigation::get_registry();
                            let nm_ref = nonce_manager.clone();
                            let inv_key_owned = inv_key.clone();

                            tokio::spawn(async move {
                                // Serialize: only 1 LLM investigation at a time (CPU-bound Ollama).
                                let _permit = INVESTIGATION_SEMAPHORE.acquire().await.ok();
                                let llm_config = crate::agent::llm_router::LlmRouterConfig::from_db_settings(store_inv.as_ref()).await;
                                let inv_config = crate::agent::investigation::InvestigationConfig::default();

                                let result = crate::agent::investigation::run_investigation(
                                    dossier.clone(), store_inv.clone(), &llm_config, &inv_config
                                ).await;

                                // Record in dedup cache with verdict-based cooldown.
                                // Skip recording on error so we retry next cycle.
                                if result.verdict.verdict_type() != "error" {
                                    INVESTIGATION_BLOOM.write().await.record(
                                        inv_key_owned,
                                        result.verdict.verdict_type().to_string(),
                                    );
                                }

                                tracing::info!(
                                    "INVESTIGATION: Completed for {} — {}={:.0}% duration={}s",
                                    asset_name, result.verdict.verdict_type(), result.verdict.confidence() * 100.0, result.duration_secs
                                );

                                // L2 enrichment: on confirmed/inconclusive, ask Foundation-Sec-Reasoning for a deeper forensic analysis.
                                let mut final_analysis = result.verdict.analysis_text();
                                // Structured output from L2 — populated if the JSON parses.
                                let mut parsed_mitre: Vec<String> = vec![];
                                let mut parsed_iocs: Vec<String> = vec![];
                                let mut parsed_actions: Vec<serde_json::Value> = vec![];
                                if result.verdict.should_notify() {
                                    tracing::info!("INVESTIGATION: Enriching verdict with L2 (forensic) for {}", asset_name);
                                    let l2_prompt = format!(
                                        "Tu es un analyste SOC senior. Analyse cet incident et produis un rapport JSON structuré pour un RSSI.\n\n\
                                         CONTEXTE :\n\
                                         Asset : {asset}\n\
                                         Dossier : {dossier}\n\
                                         Analyse initiale : {l1}\n\n\
                                         Réponds en JSON avec EXACTEMENT ces clés :\n\
                                         {{\n\
                                           \"summary\": \"1-2 phrases décrivant ce qui s'est passé\",\n\
                                           \"mitre_attck\": [\"T1110 Brute Force\", \"T1078 Valid Accounts\"],\n\
                                           \"ioc\": [\"IP: 1.2.3.4\", \"hash: abc123\"],\n\
                                           \"actions\": [\"Bloquer l'IP source\", \"Réinitialiser les mots de passe\", \"Vérifier les logs\"]\n\
                                         }}\n\
                                         Maximum 4 clés. Sois factuel, concis, maximum 15 lignes au total.",
                                        asset = asset_name, dossier = dossier.summary(), l1 = result.verdict.analysis_text()
                                    );
                                    // Use primary base_url (L1/L2 share same Ollama instance)
                                    let l2_base_url = if llm_config.forensic.base_url.contains("127.0.0.1")
                                        || llm_config.forensic.base_url.contains("localhost") {
                                        llm_config.primary.base_url.clone()
                                    } else {
                                        llm_config.forensic.base_url.clone()
                                    };
                                    match tokio::time::timeout(
                                        std::time::Duration::from_secs(900),
                                        crate::agent::react_runner::call_ollama(
                                            &l2_base_url,
                                            &llm_config.forensic.model,
                                            &l2_prompt,
                                        ),
                                    ).await {
                                        Ok(Ok(l2_raw)) => {
                                            let l2_clean = clean_l2_output(&l2_raw);
                                            tracing::info!("INVESTIGATION: L2 enrichment OK for {} ({} chars → {} clean)", asset_name, l2_raw.len(), l2_clean.len());
                                            // Try to parse the structured JSON output first. L2 is prompted to
                                            // return {"summary","mitre_attck","ioc","actions"} — if the JSON is
                                            // valid we extract the structured fields; otherwise we fall back to
                                            // the plain text cleanup for the summary.
                                            let parsed = serde_json::from_str::<serde_json::Value>(&l2_clean)
                                                .ok()
                                                .or_else(|| {
                                                    // Try to extract JSON from between the first { and last }
                                                    let start = l2_clean.find('{')?;
                                                    let end = l2_clean.rfind('}')?;
                                                    serde_json::from_str::<serde_json::Value>(&l2_clean[start..=end]).ok()
                                                });

                                            if let Some(obj) = parsed {
                                                // Extract summary
                                                if let Some(s) = obj.get("summary").and_then(|v| v.as_str()) {
                                                    final_analysis = s.to_string();
                                                }
                                                // Extract MITRE techniques (array of strings)
                                                if let Some(arr) = obj.get("mitre_attck").and_then(|v| v.as_array())
                                                    .or_else(|| obj.get("mitre").and_then(|v| v.as_array()))
                                                {
                                                    parsed_mitre = arr.iter()
                                                        .filter_map(|v| v.as_str().map(String::from))
                                                        .filter(|s| !s.is_empty())
                                                        .collect();
                                                }
                                                // Extract IOCs (array of strings)
                                                if let Some(arr) = obj.get("ioc").and_then(|v| v.as_array())
                                                    .or_else(|| obj.get("iocs").and_then(|v| v.as_array()))
                                                {
                                                    parsed_iocs = arr.iter()
                                                        .filter_map(|v| v.as_str().map(String::from))
                                                        .filter(|s| !s.is_empty())
                                                        .collect();
                                                }
                                                // Extract proposed actions — convert each string to a
                                                // structured object with a kind guess (block_ip, create_ticket,
                                                // disable_account, …) so the dashboard can render Execute buttons.
                                                if let Some(arr) = obj.get("actions").and_then(|v| v.as_array()) {
                                                    parsed_actions = arr.iter()
                                                        .filter_map(|v| v.as_str())
                                                        .filter(|s| !s.is_empty())
                                                        .map(|desc| {
                                                            let lower = desc.to_lowercase();
                                                            let kind = if lower.contains("bloqu") || lower.contains("block") || lower.contains("firewall") || lower.contains("pfsense") || lower.contains("opnsense") {
                                                                "block_ip"
                                                            } else if lower.contains("ticket") || lower.contains("glpi") {
                                                                "create_ticket"
                                                            } else if lower.contains("désactiv") || lower.contains("disable") || lower.contains("réinitialis") || lower.contains("reset") || lower.contains("compte") || lower.contains("account") {
                                                                "disable_account"
                                                            } else {
                                                                "manual"
                                                            };
                                                            serde_json::json!({
                                                                "kind": kind,
                                                                "description": desc,
                                                            })
                                                        })
                                                        .collect();
                                                }
                                                tracing::info!(
                                                    "INVESTIGATION: L2 parsed — {} MITRE, {} IOCs, {} actions",
                                                    parsed_mitre.len(), parsed_iocs.len(), parsed_actions.len()
                                                );
                                            } else {
                                                // JSON parse failed — fall back to old quality-gate + plain text
                                                let is_garbage = l2_clean.len() > 3000
                                                    || l2_clean.matches("analyse_forensique").count() > 1
                                                    || l2_clean.contains("[L1]")
                                                    || l2_clean.contains("Analyse initiale");
                                                if is_garbage {
                                                    tracing::warn!("INVESTIGATION: L2 output is low quality ({} chars, repeated blocks), using L1 only", l2_clean.len());
                                                } else {
                                                    final_analysis = l2_clean;
                                                }
                                            }
                                        }
                                        Ok(Err(e)) => tracing::warn!("INVESTIGATION: L2 enrichment failed for {}: {}", asset_name, e),
                                        Err(_) => tracing::warn!("INVESTIGATION: L2 enrichment timeout for {}", asset_name),
                                    }
                                }

                                // See ADR-043: update incident with verdict
                                if incident_id > 0 {
                                    // Use the structured data parsed from L2 (fallback to empty if unavailable).
                                    let proposed = serde_json::json!({
                                        "actions": parsed_actions,
                                        "iocs": parsed_iocs,
                                    });
                                    let inv_log = serde_json::json!({
                                        "duration_secs": result.duration_secs,
                                        "iterations": result.iterations,
                                        "skill_calls": result.skill_calls,
                                    });
                                    let _ = store_inv.update_incident_verdict(
                                        incident_id,
                                        result.verdict.verdict_type(),
                                        result.verdict.confidence() as f64,
                                        &final_analysis,
                                        &parsed_mitre,
                                        &proposed,
                                        &inv_log,
                                    ).await;
                                    tracing::info!("INCIDENT #{}: verdict={} confidence={:.0}%", incident_id, result.verdict.verdict_type(), result.verdict.confidence() * 100.0);

                                    // Send incident notification (gated by NotificationSettings: severity threshold,
                                    // per-severity cooldown, quiet hours, escalation bypass).
                                    let verdict_type_str = result.verdict.verdict_type().to_string();
                                    if result.verdict.should_notify()
                                        && crate::agent::production_safeguards::should_notify_incident(
                                            store_inv.as_ref(), &asset_name, &verdict_type_str, &incident_severity
                                        ).await
                                    {
                                        let summary = final_analysis.clone();
                                        crate::agent::notification_router::route_incident_notification(
                                            store_inv.as_ref(),
                                            incident_id,
                                            &asset_name,
                                            &format!("{} — {}", asset_name, verdict_type_str),
                                            &summary,
                                            &incident_severity,
                                            dossier.findings.len() as i32,
                                        ).await;
                                        crate::agent::production_safeguards::record_incident_notified(
                                            store_inv.as_ref(), &asset_name, &verdict_type_str
                                        ).await;
                                    }
                                }

                                // Notify only if verdict warrants it + delta check
                                if result.verdict.should_notify() {
                                    if crate::agent::production_safeguards::should_renotify_verdict(
                                        store_inv.as_ref(), &asset_name, &result.verdict
                                    ).await {
                                        let notif_results = crate::agent::notification_router::route_verdict_notification(
                                            store_inv.as_ref(), &result, &dossier, incident_id
                                        ).await;

                                        if notif_results.iter().any(|(_, r)| r.is_ok()) {
                                            crate::agent::production_safeguards::record_verdict_sent(
                                                store_inv.as_ref(), &asset_name, &result.verdict
                                            ).await;
                                        }

                                        // HITL for confirmed CRITICAL incidents
                                        if let crate::agent::verdict::InvestigationVerdict::Confirmed { ref severity, .. } = result.verdict {
                                            if severity == "CRITICAL" {
                                                if let Some(ref nm) = nm_ref {
                                                    // Reconstruct a minimal SecuritySituation for HITL
                                                    let situation_for_hitl = SecuritySituation {
                                                        global_score: dossier.global_score,
                                                        notification_level: NotificationLevel::Critical,
                                                        assets: vec![],
                                                        new_findings_count: dossier.findings.len(),
                                                        new_alerts_count: 0,
                                                        total_open_findings: dossier.findings.len(),
                                                        total_active_alerts: 0,
                                                        digest_message: String::new(),
                                                        alert_message: None,
                                                        computed_at: chrono::Utc::now().to_rfc3339(),
                                                        graph_intel: dossier.graph_intel.clone(),
                                                    };
                                                    propose_hitl_actions(store_inv.as_ref(), &situation_for_hitl, nm.as_ref()).await;
                                                }
                                            }
                                        }
                                    } else {
                                        tracing::debug!("INVESTIGATION: Re-notification suppressed (no delta) for {}", asset_name);
                                    }
                                }

                                // Auto-close findings if false positive
                                if let crate::agent::verdict::InvestigationVerdict::FalsePositive { ref reason, .. } = result.verdict {
                                    tracing::info!("INVESTIGATION: False positive for {} — {}", asset_name, reason);
                                    // TODO: auto-close findings for this asset
                                }

                                // Unregister investigation
                                registry_ref.unregister(&asset_name).await;
                            });
                        }
                    } else {
                        tracing::debug!("INTELLIGENCE: Investigation already in progress for {}", worst_asset.asset);
                    }
                }
            }

            // See ADR-041: wait dynamic interval before next cycle
            tokio::time::sleep(next_interval).await;
        }
    })
}

/// Propose HITL remediation actions for Critical situations.
/// Extracts attacker IPs and affected assets, proposes concrete actions.
async fn propose_hitl_actions(
    store: &dyn Database,
    situation: &SecuritySituation,
    nonce_manager: &crate::agent::hitl_nonce::NonceManager,
) {
    use crate::agent::hitl_bridge;

    let mut proposed_actions: Vec<(String, String, String)> = vec![]; // (action, target, description)

    for asset in &situation.assets {
        // Extract attacker IPs from the asset's alert summaries
        if asset.score > 50.0 && asset.active_alerts > 0 {
            // Propose scanning the at-risk asset
            proposed_actions.push((
                "scan".into(),
                asset.asset.clone(),
                format!("Scanner {} — score {:.0}, {} alertes actives", asset.asset, asset.score, asset.active_alerts),
            ));
        }

        if asset.has_known_exploit {
            proposed_actions.push((
                "scan".into(),
                asset.asset.clone(),
                format!("Scanner en urgence {} — exploit connu détecté", asset.asset),
            ));
        }
    }

    // Get recent critical alerts to find attacker IPs
    if let Ok(alerts) = store.list_alerts(Some("critical"), Some("new"), 10, 0).await {
        for alert in &alerts {
            if let Some(ref ip) = alert.source_ip {
                let clean = ip.trim();
                if !clean.is_empty() {
                    proposed_actions.push((
                        "block_ip".into(),
                        clean.into(),
                        format!("Bloquer {} — {}", clean, alert.title),
                    ));
                }
            }
        }
    }

    if proposed_actions.is_empty() {
        tracing::debug!("INTELLIGENCE HITL: No actions to propose");
        return;
    }

    // Deduplicate by target
    proposed_actions.sort_by(|a, b| a.1.cmp(&b.1));
    proposed_actions.dedup_by(|a, b| a.1 == b.1 && a.0 == b.0);

    tracing::info!("INTELLIGENCE HITL: Proposing {} actions", proposed_actions.len());

    // Build HITL message with proposed actions
    let mut hitl_text = format!(
        "*ALERTE CRITIQUE — Actions recommandées*\n\nScore sécurité : {:.0}/100\n\n",
        situation.global_score
    );
    for (i, (action, target, desc)) in proposed_actions.iter().enumerate() {
        hitl_text.push_str(&format!("{}. *{}* `{}` — {}\n", i + 1, action, target, desc));
    }
    hitl_text.push_str("\nRépondez avec la commande pour exécuter (ex: `bloque 185.220.101.34`) ou ignorez pour ne rien faire.");

    // Send via all configured notification channels
    let _ = crate::agent::notification_router::route_notification(
        store,
        NotificationLevel::Critical,
        &hitl_text,
        &hitl_text,
    ).await;

    // Also send HITL to Telegram with the proposed actions
    let _ = hitl_bridge::send_hitl_to_telegram_text(store, &hitl_text).await;
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
// See ADR-030: accepts pre-fetched logs to avoid duplicate query_logs call
async fn scan_logs_for_threats(store: Arc<dyn Database>, prefetched_logs: &[crate::db::threatclaw_store::LogRecord]) -> Vec<DetectedThreat> {
    use crate::enrichment::ioc_extractor;

    let mut threats = vec![];

    if prefetched_logs.is_empty() {
        return threats;
    }

    let logs = prefetched_logs;

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
