//! Investigation helpers: IP enrichment (GreyNoise + Spamhaus) + L1 analysis runner.
//!
//! Called by:
//!   - POST /api/tc/incidents/:id/investigate  (on-demand L1 from RSSI)
//!   - task_queue/workers.rs                   (post-graph conditional trigger)
//!   - intelligence_engine.rs                  (15-min continuous monitoring)

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::db::Database;
use crate::db::threatclaw_store::{NewAiAnalysis, ThreatClawStore};

// ── Public types ──────────────────────────────────────────────────────────────

/// Merged result from GreyNoise + Spamhaus enrichment for a single IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpEnrichmentResult {
    pub ip: String,
    pub is_malicious: bool,
    /// "malicious" | "benign" | "unknown"
    pub classification: String,
    pub noise: bool,
    pub riot: bool,
    pub greynoise_name: Option<String>,
    pub spamhaus_listed: bool,
    pub spamhaus_lists: Vec<String>,
    pub country: Option<String>,
    pub asn: Option<String>,
}

// ── IP Enrichment ─────────────────────────────────────────────────────────────

/// Fetch IP reputation from GreyNoise + Spamhaus with enrichment_cache (TTL 1h).
/// Fails gracefully: partial results are still returned if one source is down.
pub async fn fetch_ip_enrichment(ip: &str, store: &Arc<dyn Database>) -> IpEnrichmentResult {
    // Cache hit
    if let Ok(Some(cached)) = store.get_enrichment_cache("investigation_ip", ip).await {
        if let Ok(r) = serde_json::from_value::<IpEnrichmentResult>(cached) {
            return r;
        }
    }

    // GreyNoise (community API — no key needed)
    let gn = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::enrichment::greynoise::lookup_ip(ip, None),
    )
    .await
    {
        Ok(Ok(r)) => Some(r),
        Ok(Err(e)) => {
            warn!("IP_ENRICH: GreyNoise error for {ip}: {e}");
            None
        }
        Err(_) => {
            warn!("IP_ENRICH: GreyNoise timeout for {ip}");
            None
        }
    };

    // Spamhaus ZEN (DNS lookup — no key needed)
    let sp = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::enrichment::spamhaus::check_ip(ip),
    )
    .await
    {
        Ok(Ok(r)) => Some(r),
        Ok(Err(e)) => {
            warn!("IP_ENRICH: Spamhaus error for {ip}: {e}");
            None
        }
        Err(_) => {
            warn!("IP_ENRICH: Spamhaus timeout for {ip}");
            None
        }
    };

    let classification = gn
        .as_ref()
        .map(|g| g.classification.clone())
        .unwrap_or_else(|| "unknown".into());

    let spamhaus_listed = sp.as_ref().map(|s| s.is_listed).unwrap_or(false);
    let spamhaus_lists: Vec<String> = sp
        .as_ref()
        .map(|s| s.listings.iter().map(|l| l.list.clone()).collect())
        .unwrap_or_default();

    let is_malicious = classification == "malicious" || spamhaus_listed;

    let result = IpEnrichmentResult {
        ip: ip.to_string(),
        is_malicious,
        classification: if spamhaus_listed && classification == "unknown" {
            "malicious".into()
        } else {
            classification
        },
        noise: gn.as_ref().map(|g| g.noise).unwrap_or(false),
        riot: gn.as_ref().map(|g| g.riot).unwrap_or(false),
        greynoise_name: gn.as_ref().and_then(|g| g.name.clone()),
        spamhaus_listed,
        spamhaus_lists,
        // GreyNoise community API doesn't return geo — future: ipinfo enrichment
        country: None,
        asn: None,
    };

    // Cache for 1 hour
    if let Ok(v) = serde_json::to_value(&result) {
        let _ = store.set_enrichment_cache("investigation_ip", ip, &v, 1).await;
    }

    result
}

// ── IP extraction ─────────────────────────────────────────────────────────────

/// Find the first plausible external (non-RFC1918) IPv4 in the incident JSON.
/// Checks evidence_citations first, then scans investigation_log text.
pub fn extract_external_ip_from_incident(incident: &Value) -> Option<String> {
    // evidence_citations: [{ioc: "..."}, ...]
    if let Some(citations) = incident.get("evidence_citations").and_then(|v| v.as_array()) {
        for c in citations {
            if let Some(ioc) = c.get("ioc").and_then(|v| v.as_str()) {
                if is_external_ipv4(ioc) {
                    return Some(ioc.to_string());
                }
            }
        }
    }
    // investigation_log: ["text...", ...] or [{content: "..."}, ...]
    if let Some(log) = incident.get("investigation_log").and_then(|v| v.as_array()) {
        for entry in log {
            let text = entry
                .as_str()
                .or_else(|| entry.get("content").and_then(|v| v.as_str()))
                .unwrap_or("");
            if let Some(ip) = first_ipv4_in_text(text) {
                if is_external_ipv4(&ip) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

pub fn is_external_ipv4(s: &str) -> bool {
    let Ok(ip) = s.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_broadcast()
}

fn first_ipv4_in_text(text: &str) -> Option<String> {
    for word in text.split_ascii_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        if clean.parse::<std::net::Ipv4Addr>().is_ok() {
            return Some(clean.to_string());
        }
    }
    None
}

// ── L1 prompt ────────────────────────────────────────────────────────────────

/// Build L1 triage prompt. Pure function — easy to test.
pub fn build_l1_prompt(
    asset: &str,
    title: &str,
    graph_verdict: &str,
    severity: &str,
    mitre_techniques: &[String],
    enrichment_summary: &str,
) -> String {
    let mitre_str = if mitre_techniques.is_empty() {
        "aucune technique identifiée".into()
    } else {
        mitre_techniques.join(", ")
    };
    format!(
        "Tu es un analyste SOC L1. Fournis une analyse rapide de cet incident.\n\n\
         Asset : {asset}\n\
         Incident : {title}\n\
         Severity : {severity}\n\
         Verdict graph : {graph_verdict}\n\
         Techniques MITRE : {mitre_str}\n\
         Contexte enrichissement :\n{enrichment_summary}\n\n\
         Réponds en JSON avec EXACTEMENT ces clés :\n\
         {{\n\
           \"summary\": \"2-3 phrases : ce qui s'est passé et pourquoi c'est réel/faux\",\n\
           \"confidence\": 0.85,\n\
           \"verdict\": \"confirmed\",\n\
           \"skills_used\": [\"greynoise\"],\n\
           \"mitre_added\": [\"T1110.001\"]\n\
         }}\n\
         Sois factuel. Maximum 10 lignes."
    )
}

/// Extract JSON from raw LLM output (handles fences + leading text).
pub fn parse_l1_output(raw: &str) -> Value {
    // Strip ``` fences if present
    let cleaned = if let Some(start) = raw.find("```json") {
        let s = &raw[start + 7..];
        s.find("```").map(|e| &s[..e]).unwrap_or(s)
    } else if let Some(start) = raw.find("```") {
        let s = &raw[start + 3..];
        s.find("```").map(|e| &s[..e]).unwrap_or(s)
    } else {
        raw
    };

    // Find first { ... }
    if let (Some(s), Some(e)) = (cleaned.find('{'), cleaned.rfind('}')) {
        if let Ok(v) = serde_json::from_str::<Value>(&cleaned[s..=e]) {
            return v;
        }
    }
    json!({"summary": raw.chars().take(500).collect::<String>(), "confidence": 0.5})
}

pub fn parse_confidence(v: &Value) -> f32 {
    v.get("confidence")
        .and_then(|x| x.as_f64())
        .unwrap_or(0.5)
        .clamp(0.0, 1.0) as f32
}

// ── L1 runner ─────────────────────────────────────────────────────────────────

/// Run L1 triage analysis for a specific incident.
///
/// 1. Load incident + check if already analyzed recently (dedup 5 min)
/// 2. Fetch IP enrichment if an external IP is in the evidence
/// 3. Call LLM L1 model with structured prompt
/// 4. Store result in incident_ai_analyses (source = "react_l1")
///
/// Returns the id of the inserted analysis row.
pub async fn run_l1_analysis(
    incident_id: i32,
    store: Arc<dyn Database>,
) -> Result<i32, String> {
    // 1. Load incident
    let incident = store
        .get_incident(incident_id)
        .await
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or("incident not found")?;

    // Dedup: skip if L1 ran in the last 5 minutes
    let recent_analyses = store
        .get_ai_analyses(incident_id)
        .await
        .unwrap_or_default();
    if let Some(last) = recent_analyses.iter().filter(|a| a.source == "react_l1").max_by_key(|a| a.created_at) {
        let age_secs = (chrono::Utc::now() - last.created_at).num_seconds();
        if age_secs < 300 {
            info!("L1_ANALYSIS: incident #{incident_id} — skipping, last L1 was {age_secs}s ago");
            return Ok(last.id);
        }
    }

    let asset = incident["asset"].as_str().unwrap_or("").to_string();
    let title = incident["title"].as_str().unwrap_or("").to_string();
    let graph_verdict = incident["verdict"].as_str().unwrap_or("inconclusive");
    let severity = incident["severity"].as_str().unwrap_or("MEDIUM");
    let mitre_techniques: Vec<String> = incident["mitre_techniques"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // 2. Build enrichment summary
    let mut skills_used: Vec<String> = Vec::new();
    let mut enrichment_lines: Vec<String> = Vec::new();

    let external_ip = extract_external_ip_from_incident(&incident);
    if let Some(ref ip) = external_ip {
        let enrich = fetch_ip_enrichment(ip, &store).await;
        skills_used.push("greynoise".into());
        if enrich.spamhaus_listed {
            skills_used.push("spamhaus".into());
        }
        let sp_str = if enrich.spamhaus_listed {
            format!("Listed ({})", enrich.spamhaus_lists.join(", "))
        } else {
            "Clean".into()
        };
        enrichment_lines.push(format!(
            "IP {ip} — GreyNoise: {} (noise={}, riot={}) | Spamhaus: {sp_str}",
            enrich.classification, enrich.noise, enrich.riot,
        ));
    }

    let enrichment_summary = if enrichment_lines.is_empty() {
        "Aucun enrichissement externe disponible".into()
    } else {
        enrichment_lines.join("\n")
    };

    // 3. Call LLM L1
    let llm_config =
        crate::agent::llm_router::LlmRouterConfig::from_db_settings(store.as_ref()).await;
    let prompt = build_l1_prompt(
        &asset,
        &title,
        graph_verdict,
        severity,
        &mitre_techniques,
        &enrichment_summary,
    );

    info!("L1_ANALYSIS: incident #{incident_id} ({asset}) — calling L1 model");

    let raw = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        crate::agent::react_runner::call_ollama(
            &llm_config.primary.base_url,
            &llm_config.primary.model,
            &prompt,
        ),
    )
    .await
    .map_err(|_| "L1 timeout (120s)")?
    .map_err(|e| format!("L1 LLM call failed: {e}"))?;

    // 4. Parse + store
    let parsed = parse_l1_output(&raw);
    let confidence = parse_confidence(&parsed);
    let summary = parsed
        .get("summary")
        .and_then(|v| v.as_str())
        .unwrap_or("Aucun résumé produit")
        .to_string();
    let mitre_added: Vec<String> = parsed
        .get("mitre_added")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let analysis = NewAiAnalysis {
        incident_id,
        source: "react_l1".into(),
        confidence: Some(confidence),
        summary,
        skills_used,
        mitre_added,
        raw_output: Some(json!({"raw": raw, "parsed": parsed})),
    };

    let id = store
        .insert_ai_analysis(&analysis)
        .await
        .map_err(|e| format!("DB insert failed: {e}"))?;

    info!(
        "L1_ANALYSIS: incident #{incident_id} — stored analysis #{id} (confidence={:.2})",
        confidence
    );
    Ok(id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_enrichment_result_serializes_roundtrip() {
        let r = IpEnrichmentResult {
            ip: "119.147.84.53".into(),
            is_malicious: true,
            classification: "malicious".into(),
            noise: false,
            riot: false,
            greynoise_name: Some("ScannerBot".into()),
            spamhaus_listed: true,
            spamhaus_lists: vec!["XBL".into()],
            country: None,
            asn: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: IpEnrichmentResult = serde_json::from_str(&s).unwrap();
        assert_eq!(back.ip, "119.147.84.53");
        assert!(back.is_malicious);
        assert_eq!(back.spamhaus_lists, ["XBL"]);
    }

    #[test]
    fn external_ip_detection() {
        assert!(is_external_ipv4("119.147.84.53"));
        assert!(is_external_ipv4("8.8.8.8"));
        assert!(!is_external_ipv4("192.168.1.1"));
        assert!(!is_external_ipv4("10.0.0.1"));
        assert!(!is_external_ipv4("172.16.0.1"));
        assert!(!is_external_ipv4("127.0.0.1"));
        assert!(!is_external_ipv4("not-an-ip"));
    }

    #[test]
    fn first_ipv4_in_text_finds_ip() {
        assert_eq!(
            first_ipv4_in_text("Source: 119.147.84.53 attacked"),
            Some("119.147.84.53".into())
        );
        assert_eq!(first_ipv4_in_text("no ip here at all"), None);
        assert_eq!(
            first_ipv4_in_text("IP=10.0.0.1 is internal, attacker=5.6.7.8"),
            Some("10.0.0.1".into())
        );
    }

    #[test]
    fn parse_confidence_clamps() {
        assert!((parse_confidence(&json!({"confidence": 0.87})) - 0.87_f32).abs() < 0.001);
        assert_eq!(parse_confidence(&json!({})), 0.5_f32);
        assert_eq!(parse_confidence(&json!({"confidence": 1.5})), 1.0_f32);
        assert_eq!(parse_confidence(&json!({"confidence": -0.1})), 0.0_f32);
    }

    #[test]
    fn l1_prompt_includes_all_context() {
        let prompt = build_l1_prompt(
            "srv-web-01",
            "SSH brute force",
            "confirmed",
            "HIGH",
            &["T1110".into(), "T1078".into()],
            "IP 119.147.84.53 — GreyNoise: malicious",
        );
        assert!(prompt.contains("srv-web-01"));
        assert!(prompt.contains("T1110"));
        assert!(prompt.contains("GreyNoise"));
        assert!(prompt.contains("\"confidence\""));
        assert!(prompt.contains("\"summary\""));
    }

    #[test]
    fn parse_l1_output_extracts_clean_json() {
        let raw = r#"Voici mon analyse :
{"summary": "Brute force SSH confirmé", "confidence": 0.92, "verdict": "confirmed", "skills_used": ["greynoise"], "mitre_added": ["T1110.001"]}"#;
        let v = parse_l1_output(raw);
        assert_eq!(v["verdict"].as_str(), Some("confirmed"));
        assert!((v["confidence"].as_f64().unwrap() - 0.92).abs() < 0.001);
    }

    #[test]
    fn parse_l1_output_handles_fenced_json() {
        let raw = "```json\n{\"summary\": \"test\", \"confidence\": 0.7, \"verdict\": \"inconclusive\", \"skills_used\": [], \"mitre_added\": []}\n```";
        let v = parse_l1_output(raw);
        assert_eq!(v["verdict"].as_str(), Some("inconclusive"));
    }

    #[test]
    fn extract_external_ip_from_evidence_citations() {
        let incident = json!({
            "evidence_citations": [
                {"ioc": "192.168.1.1"},
                {"ioc": "119.147.84.53"}
            ],
            "investigation_log": []
        });
        assert_eq!(
            extract_external_ip_from_incident(&incident),
            Some("119.147.84.53".into())
        );
    }

    #[test]
    fn extract_external_ip_from_log_fallback() {
        let incident = json!({
            "evidence_citations": [],
            "investigation_log": ["Connexion depuis 8.8.8.8 vers srv-web-01"]
        });
        assert_eq!(
            extract_external_ip_from_incident(&incident),
            Some("8.8.8.8".into())
        );
    }
}
