//! Attack Path Prediction — passive pentest via graph simulation.
//!
//! Calculates the most likely attack paths an attacker would take
//! to reach critical assets, based on current vulnerabilities,
//! exposed services, and network topology in the graph.

use crate::db::Database;
use crate::graph::threat_graph::query;
use serde::Serialize;
use serde_json::json;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// A predicted attack path.
#[derive(Debug, Clone, Serialize)]
pub struct AttackPath {
    /// Entry point (exposed IP or service).
    pub entry_point: String,
    /// Chain of assets in the path.
    pub path: Vec<PathNode>,
    /// Final target (critical asset).
    pub target: String,
    /// Exploitability score (0-100).
    pub exploitability: f64,
    /// CVEs involved in the path.
    pub cves_involved: Vec<String>,
    /// MITRE techniques applicable.
    pub mitre_techniques: Vec<String>,
    /// Risk level.
    pub risk: String,
}

/// A node in an attack path.
#[derive(Debug, Clone, Serialize)]
pub struct PathNode {
    pub asset: String,
    pub hostname: String,
    pub role: String, // "entry", "pivot", "target"
    pub cvss_max: f64,
    pub has_kev: bool,
}

/// Complete attack path analysis.
#[derive(Debug, Clone, Serialize)]
pub struct AttackPathAnalysis {
    pub paths: Vec<AttackPath>,
    pub total_paths: usize,
    pub critical_paths: usize,
    pub summary: String,
    pub top_recommendations: Vec<String>,
}

/// Compute all attack paths to critical assets.
pub async fn predict_attack_paths(store: &dyn Database) -> AttackPathAnalysis {
    let mut paths = vec![];

    // Path type 1: External IP → Vulnerable Asset → Critical Asset
    let external_paths = find_external_to_critical(store).await;
    paths.extend(external_paths);

    // Path type 2: CVE chain — asset with high CVSS/KEV that connects to critical
    let cve_paths = find_cve_chain_paths(store).await;
    paths.extend(cve_paths);

    // Path type 3: Direct exposure — critical assets attacked directly
    let direct_paths = find_direct_critical_exposure(store).await;
    paths.extend(direct_paths);

    // Sort by exploitability (highest risk first)
    paths.sort_by(|a, b| b.exploitability.partial_cmp(&a.exploitability).unwrap_or(std::cmp::Ordering::Equal));
    paths.truncate(20);

    let total = paths.len();
    let critical = paths.iter().filter(|p| p.risk == "critical").count();

    let top_recs = generate_recommendations(&paths);

    let summary = if total == 0 {
        "Aucun chemin d'attaque prédit vers les assets critiques".into()
    } else {
        format!("{} chemins d'attaque prédits ({} critiques). Top menace : {}",
            total, critical, paths.first().map(|p| p.entry_point.as_str()).unwrap_or("?"))
    };

    if total > 0 {
        tracing::info!("ATTACK_PATH: {} paths predicted ({} critical)", total, critical);
    }

    AttackPathAnalysis {
        paths,
        total_paths: total,
        critical_paths: critical,
        summary,
        top_recommendations: top_recs,
    }
}

/// External malicious IPs → intermediate asset → critical asset.
async fn find_external_to_critical(store: &dyn Database) -> Vec<AttackPath> {
    let results = query(store,
        "MATCH (ip:IP)-[:ATTACKS]->(pivot:Asset), \
         (ip2:IP)-[:ATTACKS]->(target:Asset {criticality: 'critical'}) \
         WHERE ip.classification = 'malicious' AND pivot <> target \
         RETURN DISTINCT ip.addr, pivot.id, pivot.hostname, target.id, target.hostname \
         LIMIT 20"
    ).await;

    results.iter().filter_map(|r| {
        let result = r;
        let ip = result["ip.addr"].as_str()?;
        let pivot_id = result["pivot.id"].as_str()?;
        let pivot_host = result["pivot.hostname"].as_str().unwrap_or(pivot_id);
        let target_id = result["target.id"].as_str()?;
        let target_host = result["target.hostname"].as_str().unwrap_or(target_id);

        Some(AttackPath {
            entry_point: ip.to_string(),
            path: vec![
                PathNode { asset: pivot_id.into(), hostname: pivot_host.into(), role: "pivot".into(), cvss_max: 0.0, has_kev: false },
                PathNode { asset: target_id.into(), hostname: target_host.into(), role: "target".into(), cvss_max: 0.0, has_kev: false },
            ],
            target: target_host.to_string(),
            exploitability: 70.0,
            cves_involved: vec![],
            mitre_techniques: vec!["T1021".into()], // Remote Services
            risk: "high".into(),
        })
    }).collect()
}

/// Assets with high CVSS CVEs that are connected to critical assets.
async fn find_cve_chain_paths(store: &dyn Database) -> Vec<AttackPath> {
    let results = query(store,
        "MATCH (c:CVE)-[:AFFECTS]->(entry:Asset), \
         (ip:IP)-[:ATTACKS]->(entry), \
         (c2:CVE)-[:AFFECTS]->(target:Asset {criticality: 'critical'}) \
         WHERE c.cvss >= 7.0 AND entry <> target \
         RETURN DISTINCT ip.addr, entry.id, entry.hostname, c.id AS entry_cve, c.cvss, c.in_kev, \
         target.id, target.hostname, c2.id AS target_cve \
         ORDER BY c.cvss DESC LIMIT 15"
    ).await;

    results.iter().filter_map(|r| {
        let result = r;
        let ip = result["ip.addr"].as_str().unwrap_or("unknown");
        let entry_id = result["entry.id"].as_str()?;
        let entry_host = result["entry.hostname"].as_str().unwrap_or(entry_id);
        let entry_cve = result["entry_cve"].as_str().unwrap_or("");
        let cvss = result["c.cvss"].as_f64().unwrap_or(0.0);
        let has_kev = result["c.in_kev"].as_bool().unwrap_or(false);
        let target_id = result["target.id"].as_str()?;
        let target_host = result["target.hostname"].as_str().unwrap_or(target_id);
        let target_cve = result["target_cve"].as_str().unwrap_or("");

        let exploitability = cvss * 10.0 + if has_kev { 15.0 } else { 0.0 };

        Some(AttackPath {
            entry_point: ip.to_string(),
            path: vec![
                PathNode { asset: entry_id.into(), hostname: entry_host.into(), role: "entry".into(), cvss_max: cvss, has_kev },
                PathNode { asset: target_id.into(), hostname: target_host.into(), role: "target".into(), cvss_max: 0.0, has_kev: false },
            ],
            target: target_host.to_string(),
            exploitability: exploitability.min(100.0),
            cves_involved: vec![entry_cve.into(), target_cve.into()].into_iter().filter(|s: &String| !s.is_empty()).collect(),
            mitre_techniques: vec!["T1190".into()], // Exploit Public-Facing
            risk: if has_kev || cvss >= 9.0 { "critical".into() } else { "high".into() },
        })
    }).collect()
}

/// Critical assets directly attacked from external IPs.
async fn find_direct_critical_exposure(store: &dyn Database) -> Vec<AttackPath> {
    let results = query(store,
        "MATCH (ip:IP)-[:ATTACKS]->(target:Asset {criticality: 'critical'}) \
         WHERE ip.classification = 'malicious' \
         RETURN ip.addr, target.id, target.hostname \
         LIMIT 10"
    ).await;

    results.iter().filter_map(|r| {
        let result = r;
        let ip = result["ip.addr"].as_str()?;
        let target_id = result["target.id"].as_str()?;
        let target_host = result["target.hostname"].as_str().unwrap_or(target_id);

        Some(AttackPath {
            entry_point: ip.to_string(),
            path: vec![PathNode {
                asset: target_id.into(), hostname: target_host.into(),
                role: "target".into(), cvss_max: 0.0, has_kev: false,
            }],
            target: target_host.to_string(),
            exploitability: 90.0,
            cves_involved: vec![],
            mitre_techniques: vec![],
            risk: "critical".into(),
        })
    }).collect()
}

fn generate_recommendations(paths: &[AttackPath]) -> Vec<String> {
    let mut recs = vec![];

    // Collect all KEV CVEs
    let kev_nodes: Vec<_> = paths.iter()
        .flat_map(|p| &p.path)
        .filter(|n| n.has_kev)
        .collect();
    if !kev_nodes.is_empty() {
        recs.push(format!("URGENT : Patcher les CVEs CISA KEV sur {}",
            kev_nodes.iter().map(|n| n.hostname.as_str()).collect::<Vec<_>>().join(", ")));
    }

    // High CVSS paths
    let high_cvss: Vec<_> = paths.iter()
        .flat_map(|p| &p.path)
        .filter(|n| n.cvss_max >= 9.0)
        .collect();
    if !high_cvss.is_empty() {
        recs.push("Patcher les vulnérabilités CVSS >= 9.0 en priorité".into());
    }

    // Direct critical exposure
    let direct: Vec<_> = paths.iter().filter(|p| p.path.len() == 1 && p.risk == "critical").collect();
    if !direct.is_empty() {
        recs.push(format!("Isoler les assets critiques attaqués directement : {}",
            direct.iter().map(|p| p.target.as_str()).collect::<Vec<_>>().join(", ")));
    }

    if recs.is_empty() {
        recs.push("Aucune action urgente — surveiller les évolutions".into());
    }

    recs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_recommendations_empty() {
        let recs = generate_recommendations(&[]);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].contains("Aucune action"));
    }
}
