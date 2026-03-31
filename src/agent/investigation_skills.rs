//! Investigation Skills — read-only tools the ReAct investigation can call.
//!
//! During an investigation, the LLM can request additional lookups to confirm
//! or deny its hypothesis. All skills here are read-only — no remediation,
//! no write actions. Remediation goes through HITL at stage 3.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// Skill request from the LLM during investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillRequest {
    pub skill_name: String,
    pub params: Value,
}

/// Result of executing an investigation skill
#[derive(Debug, Clone, Serialize)]
pub struct SkillResult {
    pub skill_name: String,
    pub success: bool,
    pub data: Value,
    pub duration_ms: u64,
}

/// Schema of available investigation skills (injected into the LLM prompt)
pub fn investigation_skills_description() -> Vec<(&'static str, &'static str)> {
    vec![
        ("ip_reputation", "Lookup IP reputation via GreyNoise. Returns malicious/benign/noise classification."),
        ("cve_lookup", "Lookup CVE details from NVD cache. Returns CVSS score, description, exploited_in_wild."),
        ("threat_intel", "Cross-reference an IoC (IP, URL, hash) with ThreatFox. Returns threat type, malware family."),
        ("mitre_context", "Get MITRE ATT&CK technique details: name, tactic, description, detection."),
        ("log_search", "Search recent logs by hostname. Returns matching log entries."),
        ("asset_context", "Get asset details: category, OS, IPs, criticality."),
    ]
}

/// Execute an investigation skill (read-only only)
pub async fn execute_investigation_skill(
    request: &SkillRequest,
    store: &Arc<dyn Database>,
) -> SkillResult {
    let start = std::time::Instant::now();

    let (success, data) = match request.skill_name.as_str() {
        "ip_reputation" => execute_ip_reputation(&request.params, store).await,
        "cve_lookup" => execute_cve_lookup(&request.params, store).await,
        "threat_intel" => execute_threat_intel(&request.params).await,
        "mitre_context" => execute_mitre_context(&request.params, store).await,
        "log_search" => execute_log_search(&request.params, store).await,
        "asset_context" => execute_asset_context(&request.params, store).await,
        _ => (false, json!({"error": format!("Unknown skill: {}", request.skill_name)})),
    };

    SkillResult {
        skill_name: request.skill_name.clone(),
        success,
        data,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

// ── Skill implementations ──

async fn execute_ip_reputation(params: &Value, store: &Arc<dyn Database>) -> (bool, Value) {
    let ip = match params.get("ip").and_then(|v| v.as_str()) {
        Some(ip) => ip,
        None => return (false, json!({"error": "Missing 'ip' parameter"})),
    };

    // Check enrichment cache first
    let cache_key = format!("ip:{ip}");
    if let Ok(Some(cached)) = store.get_setting("_enrichment_cache", &cache_key).await {
        return (true, cached);
    }

    // Call GreyNoise (no API key needed for community)
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::enrichment::greynoise::lookup_ip(ip, None),
    )
    .await
    {
        Ok(Ok(result)) => {
            let data = json!({
                "ip": ip,
                "classification": result.classification,
                "noise": result.noise,
                "riot": result.riot,
                "name": result.name,
                "source": "greynoise",
            });
            let _ = store
                .set_setting("_enrichment_cache", &cache_key, &data)
                .await;
            (true, data)
        }
        Ok(Err(e)) => (false, json!({"error": format!("GreyNoise: {e}"), "ip": ip})),
        Err(_) => (false, json!({"error": "GreyNoise timeout (10s)", "ip": ip})),
    }
}

async fn execute_cve_lookup(params: &Value, store: &Arc<dyn Database>) -> (bool, Value) {
    let cve_id = match params.get("cve_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return (false, json!({"error": "Missing 'cve_id' parameter"})),
    };

    // Build NVD config from DB settings (same as IE does)
    let nvd_config = crate::enrichment::cve_lookup::NvdConfig::from_db(store.as_ref()).await;

    match crate::enrichment::cve_lookup::lookup_cve_cached(cve_id, &nvd_config, store.as_ref())
        .await
    {
        Ok(cve) => (
            true,
            json!({
                "cve_id": cve.cve_id,
                "description": cve.description,
                "cvss_score": cve.cvss_score,
                "cvss_severity": cve.cvss_severity,
                "exploited_in_wild": cve.exploited_in_wild,
                "published": cve.published,
                "patch_urls": cve.patch_urls,
            }),
        ),
        Err(e) => (false, json!({"error": format!("CVE lookup: {e}"), "cve_id": cve_id})),
    }
}

async fn execute_threat_intel(params: &Value) -> (bool, Value) {
    let indicator = match params.get("indicator").and_then(|v| v.as_str()) {
        Some(i) => i,
        None => return (false, json!({"error": "Missing 'indicator' parameter"})),
    };

    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::enrichment::threatfox::lookup_ioc(indicator, None),
    )
    .await
    {
        Ok(Ok(results)) if !results.is_empty() => {
            let hits: Vec<Value> = results
                .iter()
                .take(5)
                .map(|r| {
                    json!({
                        "threat_type": r.threat_type,
                        "malware": r.malware,
                        "confidence": r.confidence_level,
                        "first_seen": r.first_seen,
                        "tags": r.tags,
                    })
                })
                .collect();
            (
                true,
                json!({"indicator": indicator, "source": "threatfox", "hits": hits.len(), "results": hits}),
            )
        }
        Ok(Ok(_)) => (
            true,
            json!({"indicator": indicator, "source": "threatfox", "hits": 0}),
        ),
        Ok(Err(e)) => (false, json!({"error": format!("ThreatFox: {e}")})),
        Err(_) => (false, json!({"error": "ThreatFox timeout (10s)"})),
    }
}

async fn execute_mitre_context(params: &Value, store: &Arc<dyn Database>) -> (bool, Value) {
    let tid = match params.get("technique_id").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return (false, json!({"error": "Missing 'technique_id' parameter"})),
    };

    match crate::enrichment::mitre_attack::lookup_technique(store.as_ref(), tid).await {
        Some(tech) => (
            true,
            json!({
                "technique_id": tech.technique_id,
                "name": tech.name,
                "tactic": tech.tactic,
                "description": tech.description.chars().take(500).collect::<String>(),
                "platform": tech.platform,
                "detection": tech.detection.chars().take(300).collect::<String>(),
                "url": tech.url,
            }),
        ),
        None => (true, json!({"technique_id": tid, "found": false})),
    }
}

async fn execute_log_search(params: &Value, store: &Arc<dyn Database>) -> (bool, Value) {
    let hostname = params
        .get("hostname")
        .and_then(|v| v.as_str());
    let minutes = params
        .get("hours")
        .and_then(|v| v.as_i64())
        .unwrap_or(24)
        * 60;
    let limit = params.get("limit").and_then(|v| v.as_i64()).unwrap_or(20);

    match store
        .query_logs(minutes, hostname, None, limit)
        .await
    {
        Ok(logs) => {
            let entries: Vec<Value> = logs
                .iter()
                .map(|l| {
                    json!({
                        "time": l.time,
                        "tag": l.tag,
                        "hostname": l.hostname,
                        "data_preview": l.data.to_string().chars().take(200).collect::<String>(),
                    })
                })
                .collect();
            (
                true,
                json!({"matches": entries.len(), "entries": entries}),
            )
        }
        Err(e) => (false, json!({"error": format!("Log search: {e}")})),
    }
}

async fn execute_asset_context(params: &Value, store: &Arc<dyn Database>) -> (bool, Value) {
    let asset_id = match params.get("asset").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => return (false, json!({"error": "Missing 'asset' parameter"})),
    };

    match store.get_asset(asset_id).await {
        Ok(Some(a)) => (
            true,
            json!({
                "id": a.id,
                "name": a.name,
                "category": a.category,
                "criticality": a.criticality,
                "ip_addresses": a.ip_addresses,
                "hostname": a.hostname,
                "os": a.os,
                "os_confidence": a.os_confidence,
                "services": a.services,
            }),
        ),
        Ok(None) => (true, json!({"asset": asset_id, "found": false})),
        Err(e) => (false, json!({"error": format!("Asset lookup: {e}")})),
    }
}
