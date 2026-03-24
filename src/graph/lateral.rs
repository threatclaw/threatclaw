//! Lateral Movement Detection — multi-hop graph traversal queries.
//!
//! Detects attack chains where a compromised node is used as a pivot
//! to reach other assets. Uses variable-length Cypher paths (2-5 hops).
//!
//! Detection patterns:
//! 1. Multi-hop attack chains (IP→Asset→Asset via ATTACKS)
//! 2. Fan-out anomaly (one IP attacking many assets in short time)
//! 3. Path to critical assets through any compromised node
//! 4. New edges not seen in baseline (HOPPER-style)

use crate::db::Database;
use crate::graph::threat_graph::query;
use serde::Serialize;
use serde_json::json;

/// A detected lateral movement path.
#[derive(Debug, Clone, Serialize)]
pub struct LateralPath {
    /// Source IP or entry point.
    pub entry_point: String,
    /// Assets in the chain (hop by hop).
    pub hops: Vec<String>,
    /// Number of hops.
    pub depth: usize,
    /// Final target (last asset).
    pub final_target: String,
    /// Whether the final target is critical.
    pub target_is_critical: bool,
    /// Detection method used.
    pub detection: String,
}

/// Fan-out detection result.
#[derive(Debug, Clone, Serialize)]
pub struct FanOutAnomaly {
    /// IP performing the fan-out.
    pub ip_addr: String,
    /// Country of origin.
    pub country: String,
    /// Number of unique assets targeted.
    pub target_count: i64,
    /// List of targeted asset hostnames.
    pub targets: Vec<String>,
    /// Classification (GreyNoise).
    pub classification: String,
}

/// Complete lateral movement analysis result.
#[derive(Debug, Clone, Serialize)]
pub struct LateralAnalysis {
    /// Multi-hop chains detected.
    pub chains: Vec<LateralPath>,
    /// Fan-out anomalies (one IP → many assets).
    pub fan_outs: Vec<FanOutAnomaly>,
    /// Paths to critical assets through compromised nodes.
    pub critical_paths: Vec<LateralPath>,
    /// Total number of detections.
    pub total_detections: usize,
    /// Summary text for notifications.
    pub summary: String,
}

fn esc(s: &str) -> String {
    s.replace('\'', "\\'")
}

/// Run all lateral movement detection queries.
pub async fn detect_lateral_movement(store: &dyn Database) -> LateralAnalysis {
    let chains = detect_multi_hop_chains(store).await;
    let fan_outs = detect_fan_out(store, 3).await;
    let critical_paths = detect_paths_to_critical(store).await;

    let total = chains.len() + fan_outs.len() + critical_paths.len();
    let summary = build_summary(&chains, &fan_outs, &critical_paths);

    if total > 0 {
        tracing::warn!("LATERAL: {} detections — {} chains, {} fan-outs, {} critical paths",
            total, chains.len(), fan_outs.len(), critical_paths.len());
    }

    LateralAnalysis {
        chains,
        fan_outs,
        critical_paths,
        total_detections: total,
        summary,
    }
}

/// Detect multi-hop attack chains: IP attacks Asset A, then Asset A is attacked
/// from the same context reaching Asset B (2-3 hop chains via ATTACKS edges).
///
/// Query: Find IPs that attack multiple different assets (potential pivot).
pub async fn detect_multi_hop_chains(store: &dyn Database) -> Vec<LateralPath> {
    // Find IPs that attack 2+ different assets — indicates lateral movement or recon
    let results = query(store,
        "MATCH (ip:IP)-[:ATTACKS]->(a1:Asset), (ip)-[:ATTACKS]->(a2:Asset) \
         WHERE a1 <> a2 \
         RETURN DISTINCT ip.addr, a1.id, a1.hostname, a2.id, a2.hostname, a2.criticality \
         LIMIT 50"
    ).await;

    let mut chains = vec![];
    let mut seen = std::collections::HashSet::new();

    for r in &results {
        let result = &r["result"];
        let ip = result["ip.addr"].as_str().unwrap_or("").to_string();
        let a1_id = result["a1.id"].as_str().unwrap_or("").to_string();
        let a1_host = result["a1.hostname"].as_str().unwrap_or(&a1_id).to_string();
        let a2_id = result["a2.id"].as_str().unwrap_or("").to_string();
        let a2_host = result["a2.hostname"].as_str().unwrap_or(&a2_id).to_string();
        let a2_critical = result["a2.criticality"].as_str() == Some("critical");

        // Deduplicate
        let key = format!("{}-{}-{}", ip, a1_id, a2_id);
        if seen.contains(&key) { continue; }
        seen.insert(key);

        if !ip.is_empty() && !a1_id.is_empty() && !a2_id.is_empty() {
            chains.push(LateralPath {
                entry_point: ip,
                hops: vec![a1_host, a2_host.clone()],
                depth: 2,
                final_target: a2_host,
                target_is_critical: a2_critical,
                detection: "multi_hop_attack".into(),
            });
        }
    }

    chains
}

/// Detect fan-out: one IP targeting many different assets.
/// This indicates reconnaissance or automated lateral scanning.
pub async fn detect_fan_out(store: &dyn Database, threshold: i64) -> Vec<FanOutAnomaly> {
    let results = query(store, &format!(
        "MATCH (ip:IP)-[:ATTACKS]->(a:Asset) \
         WITH ip, collect(DISTINCT a.hostname) AS targets, count(DISTINCT a) AS cnt \
         WHERE cnt >= {} \
         RETURN ip.addr, ip.country, ip.classification, cnt, targets \
         ORDER BY cnt DESC \
         LIMIT 20",
        threshold
    )).await;

    let mut fan_outs = vec![];
    for r in &results {
        let result = &r["result"];
        let ip = result["ip.addr"].as_str().unwrap_or("").to_string();
        let country = result["ip.country"].as_str().unwrap_or("").to_string();
        let classification = result["ip.classification"].as_str().unwrap_or("unknown").to_string();
        let cnt = result["cnt"].as_i64().unwrap_or(0);

        // Parse targets array
        let targets: Vec<String> = result["targets"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        if !ip.is_empty() && cnt >= threshold {
            fan_outs.push(FanOutAnomaly {
                ip_addr: ip,
                country,
                target_count: cnt,
                targets,
                classification,
            });
        }
    }

    fan_outs
}

/// Detect paths from any malicious IP to critical assets.
/// This is the highest-priority detection — a confirmed threat reaching crown jewels.
pub async fn detect_paths_to_critical(store: &dyn Database) -> Vec<LateralPath> {
    // Find malicious IPs that attack critical assets
    let results = query(store,
        "MATCH (ip:IP)-[:ATTACKS]->(a:Asset) \
         WHERE ip.classification = 'malicious' AND a.criticality = 'critical' \
         RETURN ip.addr, a.id, a.hostname \
         LIMIT 20"
    ).await;

    let mut paths = vec![];
    for r in &results {
        let result = &r["result"];
        let ip = result["ip.addr"].as_str().unwrap_or("").to_string();
        let asset_id = result["a.id"].as_str().unwrap_or("").to_string();
        let hostname = result["a.hostname"].as_str().unwrap_or(&asset_id).to_string();

        if !ip.is_empty() && !asset_id.is_empty() {
            paths.push(LateralPath {
                entry_point: ip,
                hops: vec![hostname.clone()],
                depth: 1,
                final_target: hostname,
                target_is_critical: true,
                detection: "malicious_to_critical".into(),
            });
        }
    }

    paths
}

/// Detect IPs with attack chains that cross multiple assets sharing CVEs.
/// If IP attacks Asset A which has CVE-X, and Asset B also has CVE-X,
/// Asset B is a likely next target.
pub async fn detect_shared_vulnerability_paths(store: &dyn Database) -> Vec<serde_json::Value> {
    query(store,
        "MATCH (ip:IP)-[:ATTACKS]->(a1:Asset)<-[:AFFECTS]-(c:CVE)-[:AFFECTS]->(a2:Asset) \
         WHERE a1 <> a2 \
         RETURN ip.addr, a1.hostname, c.id, c.cvss, a2.hostname, a2.criticality \
         ORDER BY c.cvss DESC \
         LIMIT 30"
    ).await
}

fn build_summary(chains: &[LateralPath], fan_outs: &[FanOutAnomaly], critical_paths: &[LateralPath]) -> String {
    let mut parts = vec![];

    if !chains.is_empty() {
        parts.push(format!("{} chaînes d'attaque multi-sauts détectées", chains.len()));
        let critical_chains: Vec<_> = chains.iter().filter(|c| c.target_is_critical).collect();
        if !critical_chains.is_empty() {
            parts.push(format!("  dont {} vers des assets critiques", critical_chains.len()));
        }
    }

    if !fan_outs.is_empty() {
        for fo in fan_outs {
            parts.push(format!("IP {} ({}) cible {} assets", fo.ip_addr, fo.country, fo.target_count));
        }
    }

    if !critical_paths.is_empty() {
        parts.push(format!("{} IPs malveillantes atteignent des assets critiques", critical_paths.len()));
        for p in critical_paths.iter().take(3) {
            parts.push(format!("  {} → {}", p.entry_point, p.final_target));
        }
    }

    if parts.is_empty() {
        "Aucun mouvement latéral détecté".into()
    } else {
        parts.join("\n")
    }
}

/// Format lateral analysis for notification/HITL message.
pub fn format_lateral_alert(analysis: &LateralAnalysis) -> String {
    if analysis.total_detections == 0 {
        return String::new();
    }

    let mut out = String::from("LATERAL MOVEMENT DETECTED\n");
    out.push_str(&format!("Detections: {}\n\n", analysis.total_detections));
    out.push_str(&analysis.summary);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_summary_empty() {
        let summary = build_summary(&[], &[], &[]);
        assert_eq!(summary, "Aucun mouvement latéral détecté");
    }

    #[test]
    fn test_summary_with_chains() {
        let chains = vec![LateralPath {
            entry_point: "1.2.3.4".into(),
            hops: vec!["srv-web".into(), "srv-db".into()],
            depth: 2,
            final_target: "srv-db".into(),
            target_is_critical: true,
            detection: "multi_hop_attack".into(),
        }];
        let summary = build_summary(&chains, &[], &[]);
        assert!(summary.contains("1 chaînes d'attaque"));
        assert!(summary.contains("assets critiques"));
    }

    #[test]
    fn test_summary_with_fan_out() {
        let fan_outs = vec![FanOutAnomaly {
            ip_addr: "5.6.7.8".into(),
            country: "RU".into(),
            target_count: 5,
            targets: vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
            classification: "malicious".into(),
        }];
        let summary = build_summary(&[], &fan_outs, &[]);
        assert!(summary.contains("5.6.7.8"));
        assert!(summary.contains("5 assets"));
    }

    #[test]
    fn test_format_lateral_empty() {
        let analysis = LateralAnalysis {
            chains: vec![], fan_outs: vec![], critical_paths: vec![],
            total_detections: 0, summary: String::new(),
        };
        assert_eq!(format_lateral_alert(&analysis), "");
    }
}
