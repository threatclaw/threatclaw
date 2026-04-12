//! Retroact: retrospective re-scanning of suspect findings.
//!
//! Inspired by Gatewatcher Retroact — re-analyzes inconclusive or borderline
//! findings 48h later with updated threat intelligence (new GreyNoise data,
//! CISA KEV additions, EPSS score changes, ThreatFox entries).
//!
//! "ThreatClaw ne lâche jamais un suspect."
//!
//! Runs as a nocturnal cycle (03:00) after ML retraining.
//! Uses the settings table to track rescan candidates (no new trait methods needed).

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// Namespace for rescan tracking in settings table.
const RESCAN_NS: &str = "_retroact";

/// Result of a retroact scan cycle.
#[derive(Debug)]
pub struct RetroactResult {
    pub candidates_checked: usize,
    pub upgraded: usize,
    pub cleared: usize,
    pub still_suspect: usize,
}

/// Mark a finding for future re-scan (called when verdict is inconclusive
/// or ML score is borderline 0.4-0.7).
pub async fn mark_for_rescan(store: &dyn Database, finding_id: i64, reason: &str) {
    let rescan_at = chrono::Utc::now() + chrono::Duration::hours(48);
    let key = format!("finding_{}", finding_id);
    let _ = store.set_setting(RESCAN_NS, &key, &serde_json::json!({
        "finding_id": finding_id,
        "reason": reason,
        "rescan_at": rescan_at.to_rfc3339(),
        "marked_at": chrono::Utc::now().to_rfc3339(),
    })).await;
    tracing::debug!("RETROACT: finding #{} marked for rescan at {}", finding_id, rescan_at);
}

/// Run the nocturnal retroact cycle.
/// Re-checks findings that were marked for rescan and whose rescan_at has passed.
/// For each candidate:
/// - Re-fetch enrichment (GreyNoise, EPSS, ThreatFox, CISA KEV)
/// - If threat status changed (IP now in KEV, EPSS jumped, etc.) → upgrade severity
/// - If still inconclusive after 2 rescans → keep as-is (stop re-scanning)
pub async fn run_retroact_cycle(
    store: std::sync::Arc<dyn Database>,
) -> RetroactResult {
    let mut result = RetroactResult {
        candidates_checked: 0, upgraded: 0, cleared: 0, still_suspect: 0,
    };

    // Load all rescan candidates
    let candidates = load_rescan_candidates(store.as_ref()).await;
    if candidates.is_empty() { return result; }

    let now = chrono::Utc::now();

    for candidate in &candidates {
        // Only process if rescan_at has passed
        if let Some(rescan_at) = &candidate.rescan_at {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(rescan_at) {
                if ts > now { continue; }
            }
        }

        result.candidates_checked += 1;

        // Fetch the original finding
        let finding = match store.get_finding(candidate.finding_id).await {
            Ok(Some(f)) => f,
            _ => {
                // Finding deleted or not found — clean up rescan marker
                let key = format!("finding_{}", candidate.finding_id);
                let _ = store.delete_setting(RESCAN_NS, &key).await;
                continue;
            }
        };

        // Skip already resolved/false_positive
        if finding.status == "resolved" || finding.status == "false_positive" {
            let key = format!("finding_{}", candidate.finding_id);
            let _ = store.delete_setting(RESCAN_NS, &key).await;
            result.cleared += 1;
            continue;
        }

        // Re-enrich: check if any external source now flags this finding's IoCs
        let mut escalation_reasons: Vec<String> = Vec::new();

        // Extract IPs and CVEs from finding metadata
        let meta = &finding.metadata;
        let src_ip = meta["src_ip"].as_str().unwrap_or("");
        let dst_ip = meta["dst_ip"].as_str().unwrap_or("");
        let cve = meta["cve"].as_str().unwrap_or("");
        let hash = meta["hash"].as_str().unwrap_or("");

        // 1. Check CISA KEV for CVEs
        if !cve.is_empty() {
            if let Some(kev) = crate::enrichment::cisa_kev::is_exploited(store.as_ref(), cve).await {
                escalation_reasons.push(format!(
                    "CVE {} ajoutée au CISA KEV — action requise avant {}",
                    cve, kev.due_date
                ));
            }
        }

        // 2. Check EPSS for CVEs (score may have increased)
        if !cve.is_empty() {
            if let Ok(Ok(Some(epss))) = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                crate::enrichment::epss::lookup_epss(cve),
            ).await {
                if epss.epss > 0.7 {
                    escalation_reasons.push(format!(
                        "EPSS {} : {:.0}% probabilité exploitation 30j (précédemment plus bas)",
                        cve, epss.epss * 100.0
                    ));
                }
            }
        }

        // 3. Check GreyNoise for IPs
        for ip in [src_ip, dst_ip] {
            if ip.is_empty() || crate::agent::ip_classifier::is_non_routable(ip) { continue; }
            // Check cache first
            let cached = crate::agent::production_safeguards::get_cached_ioc(
                store.as_ref(), "greynoise", ip,
            ).await;
            if let Some(cached) = cached {
                if cached["classification"].as_str() == Some("malicious") {
                    escalation_reasons.push(format!(
                        "IP {} classifiée 'malicious' par GreyNoise (attaque ciblée)",
                        ip
                    ));
                }
            }
        }

        // 4. Check Bloom filter for hashes (new IoCs may have been synced)
        if !hash.is_empty() {
            let bloom = crate::agent::ioc_bloom::IOC_BLOOM.read().await;
            if bloom.maybe_contains(hash) {
                escalation_reasons.push(format!(
                    "Hash {} maintenant présent dans les feeds IoC (ThreatFox/MalwareBazaar)",
                    &hash[..std::cmp::min(16, hash.len())]
                ));
            }
        }

        let key = format!("finding_{}", candidate.finding_id);

        if !escalation_reasons.is_empty() {
            // UPGRADE: threat confirmed by new intelligence
            tracing::warn!(
                "RETROACT: finding #{} UPGRADED — {}",
                candidate.finding_id, escalation_reasons.join("; ")
            );

            // Create a new finding with escalated info (dedup will merge with existing)
            let new_severity = if finding.severity.to_lowercase() == "medium" { "HIGH" }
                else if finding.severity.to_lowercase() == "high" { "CRITICAL" }
                else { &finding.severity };

            let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
                skill_id: finding.skill_id.clone(),
                title: format!("[RETROACT] {}", finding.title),
                description: Some(format!(
                    "Re-analyse rétrospective — nouvelles informations:\n- {}\n\n{}",
                    escalation_reasons.join("\n- "),
                    finding.description.as_deref().unwrap_or("")
                )),
                severity: new_severity.into(),
                category: finding.category.clone(),
                asset: finding.asset.clone(),
                source: Some("Retroact re-scan".into()),
                metadata: Some(serde_json::json!({
                    "retroact": true,
                    "original_finding_id": candidate.finding_id,
                    "escalation_reasons": escalation_reasons,
                    "original_severity": finding.severity,
                    "detection": "retroact-rescan",
                })),
            }).await;

            // Clean up rescan marker
            let _ = store.delete_setting(RESCAN_NS, &key).await;
            result.upgraded += 1;
        } else {
            // Check rescan count — stop after 2 rescans
            let rescan_count = candidate.rescan_count + 1;
            if rescan_count >= 2 {
                // Give up — remove marker, finding stays as-is
                let _ = store.delete_setting(RESCAN_NS, &key).await;
                result.still_suspect += 1;
                tracing::debug!(
                    "RETROACT: finding #{} still inconclusive after {} rescans — closing retroact",
                    candidate.finding_id, rescan_count
                );
            } else {
                // Schedule another rescan in 48h
                let next = chrono::Utc::now() + chrono::Duration::hours(48);
                let _ = store.set_setting(RESCAN_NS, &key, &serde_json::json!({
                    "finding_id": candidate.finding_id,
                    "reason": candidate.reason,
                    "rescan_at": next.to_rfc3339(),
                    "rescan_count": rescan_count,
                    "marked_at": candidate.marked_at,
                })).await;
                result.still_suspect += 1;
            }
        }
    }

    if result.candidates_checked > 0 {
        tracing::info!(
            "RETROACT: {} checked, {} upgraded, {} cleared, {} still suspect",
            result.candidates_checked, result.upgraded, result.cleared, result.still_suspect
        );
    }

    result
}

// ── Internal helpers ──

struct RescanCandidate {
    finding_id: i64,
    rescan_at: Option<String>,
    rescan_count: u32,
    reason: String,
    marked_at: String,
}

/// Load all pending rescan candidates from the settings table.
async fn load_rescan_candidates(store: &dyn Database) -> Vec<RescanCandidate> {
    let mut candidates = Vec::new();

    // List all settings in the _retroact namespace
    // We use a scan pattern — iterate finding_1, finding_2, etc.
    // Since there's no list_settings_by_namespace, we rely on known IDs.
    // Load up to 200 candidate IDs from a tracking list.
    let tracking = store.get_setting(RESCAN_NS, "_tracking_ids").await;
    let ids: Vec<i64> = match tracking {
        Ok(Some(val)) => {
            val["ids"].as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect())
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };

    for id in ids {
        let key = format!("finding_{}", id);
        if let Ok(Some(val)) = store.get_setting(RESCAN_NS, &key).await {
            candidates.push(RescanCandidate {
                finding_id: id,
                rescan_at: val["rescan_at"].as_str().map(String::from),
                rescan_count: val["rescan_count"].as_u64().unwrap_or(0) as u32,
                reason: val["reason"].as_str().unwrap_or("").to_string(),
                marked_at: val["marked_at"].as_str().unwrap_or("").to_string(),
            });
        }
    }

    candidates
}

/// Add a finding ID to the retroact tracking list.
pub async fn track_finding(store: &dyn Database, finding_id: i64) {
    let mut ids: Vec<i64> = match store.get_setting(RESCAN_NS, "_tracking_ids").await {
        Ok(Some(val)) => {
            val["ids"].as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_i64()).collect())
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };

    if !ids.contains(&finding_id) {
        ids.push(finding_id);
        // Keep list bounded (max 500 tracked findings)
        if ids.len() > 500 { ids.drain(0..ids.len() - 500); }
        let _ = store.set_setting(RESCAN_NS, "_tracking_ids", &serde_json::json!({"ids": ids})).await;
    }
}

/// Combined: mark + track a finding for retroact re-scan.
pub async fn schedule_rescan(store: &dyn Database, finding_id: i64, reason: &str) {
    mark_for_rescan(store, finding_id, reason).await;
    track_finding(store, finding_id).await;
}
