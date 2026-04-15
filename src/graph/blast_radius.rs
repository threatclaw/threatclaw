//! Blast Radius — if an asset is compromised, what's the impact?
//!
//! Traverses the graph to find all assets reachable from a compromised node
//! at 1, 2, and 3 hops. Computes a criticality-weighted impact score.

use crate::db::Database;
use crate::graph::threat_graph::query;
use serde::Serialize;
use serde_json::json;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Impact at a specific hop distance.
#[derive(Debug, Clone, Serialize)]
pub struct HopImpact {
    pub hop: u8,
    pub assets: Vec<AssetImpact>,
    pub count: usize,
}

/// A single impacted asset.
#[derive(Debug, Clone, Serialize)]
pub struct AssetImpact {
    pub id: String,
    pub hostname: String,
    pub criticality: String,
    pub cve_count: usize,
    pub has_kev: bool,
}

/// Complete blast radius analysis for an asset.
#[derive(Debug, Clone, Serialize)]
pub struct BlastRadius {
    pub source_asset: String,
    pub total_impacted: usize,
    pub critical_impacted: usize,
    pub hops: Vec<HopImpact>,
    pub impact_score: f64,
    pub summary: String,
    pub recommendation: String,
}

/// Compute the blast radius if the given asset is compromised.
pub async fn compute_blast_radius(store: &dyn Database, asset_id: &str) -> BlastRadius {
    let mut all_assets: Vec<AssetImpact> = vec![];
    let mut hops = vec![];

    // Hop 1: Assets directly connected (same attacker IPs)
    let hop1 = find_connected_assets(store, asset_id, 1).await;
    hops.push(HopImpact {
        hop: 1,
        count: hop1.len(),
        assets: hop1.clone(),
    });
    all_assets.extend(hop1);

    // Hop 2: Assets connected through shared IPs or CVEs
    let hop2 = find_shared_vulnerability_assets(store, asset_id).await;
    let hop2_new: Vec<_> = hop2
        .into_iter()
        .filter(|a| !all_assets.iter().any(|x| x.id == a.id) && a.id != asset_id)
        .collect();
    hops.push(HopImpact {
        hop: 2,
        count: hop2_new.len(),
        assets: hop2_new.clone(),
    });
    all_assets.extend(hop2_new);

    // Hop 3: Assets connected through User identity (same user logged into both)
    let hop3 = find_user_connected_assets(store, asset_id).await;
    let hop3_new: Vec<_> = hop3
        .into_iter()
        .filter(|a| !all_assets.iter().any(|x| x.id == a.id) && a.id != asset_id)
        .collect();
    hops.push(HopImpact {
        hop: 3,
        count: hop3_new.len(),
        assets: hop3_new.clone(),
    });
    all_assets.extend(hop3_new);

    let total = all_assets.len();
    let critical = all_assets
        .iter()
        .filter(|a| a.criticality == "critical")
        .count();
    let impact_score = compute_impact_score(&all_assets);

    let summary = format!(
        "Si {} est compromis : {} assets impactés ({} critiques)",
        asset_id, total, critical
    );

    let recommendation = if critical > 0 {
        "Isolation réseau immédiate recommandée — assets critiques exposés".into()
    } else if total > 5 {
        "Surveillance renforcée — large blast radius".into()
    } else if total > 0 {
        "Monitoring standard — impact limité".into()
    } else {
        "Asset isolé — pas d'impact collatéral détecté".into()
    };

    if total > 0 {
        tracing::info!(
            "BLAST_RADIUS: {} → {} assets impactés ({} critiques), score {:.1}",
            asset_id,
            total,
            critical,
            impact_score
        );
    }

    BlastRadius {
        source_asset: asset_id.to_string(),
        total_impacted: total,
        critical_impacted: critical,
        hops,
        impact_score,
        summary,
        recommendation,
    }
}

/// Find assets attacked by the same IPs as the source asset (hop 1).
async fn find_connected_assets(store: &dyn Database, asset_id: &str, _hop: u8) -> Vec<AssetImpact> {
    let results = query(
        store,
        &format!(
            "MATCH (ip:IP)-[:ATTACKS]->(src:Asset {{id: '{}'}}), \
         (ip)-[:ATTACKS]->(other:Asset) \
         WHERE other.id <> '{}' \
         RETURN DISTINCT other.id, other.hostname, other.criticality",
            esc(asset_id),
            esc(asset_id)
        ),
    )
    .await;

    parse_asset_results(&results)
}

/// Find assets sharing the same CVEs as the source asset (hop 2).
async fn find_shared_vulnerability_assets(
    store: &dyn Database,
    asset_id: &str,
) -> Vec<AssetImpact> {
    let results = query(
        store,
        &format!(
            "MATCH (c:CVE)-[:AFFECTS]->(src:Asset {{id: '{}'}}), \
         (c)-[:AFFECTS]->(other:Asset) \
         WHERE other.id <> '{}' \
         RETURN DISTINCT other.id, other.hostname, other.criticality, c.in_kev",
            esc(asset_id),
            esc(asset_id)
        ),
    )
    .await;

    results
        .iter()
        .filter_map(|r| {
            let result = r;
            let id = result["other.id"].as_str()?.to_string();
            let hostname = result["other.hostname"].as_str().unwrap_or(&id).to_string();
            let criticality = result["other.criticality"]
                .as_str()
                .unwrap_or("medium")
                .to_string();
            let has_kev = result["c.in_kev"].as_bool().unwrap_or(false);
            Some(AssetImpact {
                id,
                hostname,
                criticality,
                cve_count: 1,
                has_kev,
            })
        })
        .collect()
}

/// Find assets connected through User logins (hop 3).
async fn find_user_connected_assets(store: &dyn Database, asset_id: &str) -> Vec<AssetImpact> {
    let results = query(
        store,
        &format!(
            "MATCH (u:User)-[:LOGGED_IN]->(src:Asset {{id: '{}'}}), \
         (u)-[:LOGGED_IN]->(other:Asset) \
         WHERE other.id <> '{}' \
         RETURN DISTINCT other.id, other.hostname, other.criticality",
            esc(asset_id),
            esc(asset_id)
        ),
    )
    .await;

    parse_asset_results(&results)
}

fn parse_asset_results(results: &[serde_json::Value]) -> Vec<AssetImpact> {
    results
        .iter()
        .filter_map(|r| {
            let result = r;
            let id = result["other.id"].as_str()?.to_string();
            let hostname = result["other.hostname"].as_str().unwrap_or(&id).to_string();
            let criticality = result["other.criticality"]
                .as_str()
                .unwrap_or("medium")
                .to_string();
            Some(AssetImpact {
                id,
                hostname,
                criticality,
                cve_count: 0,
                has_kev: false,
            })
        })
        .collect()
}

fn compute_impact_score(assets: &[AssetImpact]) -> f64 {
    assets
        .iter()
        .map(|a| {
            let base = match a.criticality.as_str() {
                "critical" => 10.0,
                "high" => 7.0,
                "medium" => 4.0,
                "low" => 1.0,
                _ => 4.0,
            };
            let kev_boost = if a.has_kev { 3.0 } else { 0.0 };
            base + kev_boost
        })
        .sum::<f64>()
        .min(100.0)
}

/// Format blast radius for notification.
pub fn format_blast_radius(br: &BlastRadius) -> String {
    if br.total_impacted == 0 {
        return String::new();
    }

    let mut out = format!("BLAST RADIUS — {}\n", br.summary);
    for hop in &br.hops {
        if hop.count > 0 {
            let names: Vec<_> = hop.assets.iter().map(|a| a.hostname.as_str()).collect();
            out.push_str(&format!(
                "  Hop {} : {} assets ({})\n",
                hop.hop,
                hop.count,
                names.join(", ")
            ));
        }
    }
    out.push_str(&format!("Score impact : {:.1}/100\n", br.impact_score));
    out.push_str(&format!("Recommandation : {}\n", br.recommendation));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impact_score() {
        let assets = vec![
            AssetImpact {
                id: "a".into(),
                hostname: "srv-db".into(),
                criticality: "critical".into(),
                cve_count: 0,
                has_kev: true,
            },
            AssetImpact {
                id: "b".into(),
                hostname: "srv-web".into(),
                criticality: "medium".into(),
                cve_count: 0,
                has_kev: false,
            },
        ];
        let score = compute_impact_score(&assets);
        assert!(score > 15.0); // critical(10)+kev(3) + medium(4) = 17
    }

    #[test]
    fn test_format_empty() {
        let br = BlastRadius {
            source_asset: "test".into(),
            total_impacted: 0,
            critical_impacted: 0,
            hops: vec![],
            impact_score: 0.0,
            summary: String::new(),
            recommendation: String::new(),
        };
        assert_eq!(format_blast_radius(&br), "");
    }
}
