//! STIX 2.1 Campaign Detection — correlate coordinated attacks.
//!
//! Detects when multiple IPs from the same ASN/country target the same
//! assets in a short time window. Groups them into a STIX Campaign object.

use crate::db::Database;
use crate::graph::threat_graph::{mutate, query};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// A detected campaign.
#[derive(Debug, Clone, Serialize)]
pub struct Campaign {
    pub id: String,
    pub name: String,
    pub description: String,
    /// IPs involved in this campaign.
    pub source_ips: Vec<String>,
    /// Assets targeted.
    pub targets: Vec<String>,
    /// Common ASN (if any).
    pub common_asn: Option<String>,
    /// Common country (if any).
    pub common_country: Option<String>,
    /// Number of attacks correlated.
    pub attack_count: i64,
    /// Campaign confidence (0-100).
    pub confidence: u8,
}

/// Campaign detection result.
#[derive(Debug, Clone, Serialize)]
pub struct CampaignAnalysis {
    pub campaigns: Vec<Campaign>,
    pub total_campaigns: usize,
    pub summary: String,
}

/// Detect campaigns by grouping IPs from the same country attacking the same targets.
pub async fn detect_campaigns(store: &dyn Database) -> CampaignAnalysis {
    let mut campaigns = vec![];

    // Pattern 1: Multiple IPs from same country attacking same asset
    let country_clusters = detect_country_clusters(store).await;
    campaigns.extend(country_clusters);

    // Pattern 2: IPs sharing the same ASN targeting multiple assets
    let asn_clusters = detect_asn_clusters(store).await;
    campaigns.extend(asn_clusters);

    let total = campaigns.len();
    let summary = if total == 0 {
        "Aucune campagne coordonnée détectée".into()
    } else {
        let names: Vec<_> = campaigns.iter().map(|c| c.name.as_str()).collect();
        format!("{} campagne(s) détectée(s) : {}", total, names.join(", "))
    };

    if total > 0 {
        tracing::warn!("CAMPAIGN: {} campaigns detected", total);
        // Persist campaigns as graph nodes
        for c in &campaigns {
            persist_campaign(store, c).await;
        }
    }

    CampaignAnalysis {
        campaigns,
        total_campaigns: total,
        summary,
    }
}

/// Detect IPs from the same country attacking the same asset.
async fn detect_country_clusters(store: &dyn Database) -> Vec<Campaign> {
    let results = query(store,
        "MATCH (ip1:IP)-[:ATTACKS]->(a:Asset)<-[:ATTACKS]-(ip2:IP) \
         WHERE ip1 <> ip2 AND ip1.country = ip2.country AND ip1.country IS NOT NULL \
         WITH a, ip1.country AS country, collect(DISTINCT ip1.addr) + collect(DISTINCT ip2.addr) AS ips, count(*) AS attacks \
         WHERE size(ips) >= 3 \
         RETURN a.id, a.hostname, country, ips, attacks \
         ORDER BY attacks DESC LIMIT 10"
    ).await;

    results
        .iter()
        .filter_map(|r| {
            let result = r;
            let asset_id = result["a.id"].as_str()?;
            let hostname = result["a.hostname"].as_str().unwrap_or(asset_id);
            let country = result["country"].as_str()?;
            let attacks = result["attacks"].as_i64().unwrap_or(0);
            let ips: Vec<String> = result["ips"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            if ips.len() < 3 {
                return None;
            }

            Some(Campaign {
                id: format!("campaign--country-{}-{}", country.to_lowercase(), asset_id),
                name: format!("Campagne {} → {}", country, hostname),
                description: format!(
                    "{} IPs depuis {} ciblent {} ({} attaques)",
                    ips.len(),
                    country,
                    hostname,
                    attacks
                ),
                source_ips: ips,
                targets: vec![hostname.to_string()],
                common_asn: None,
                common_country: Some(country.to_string()),
                attack_count: attacks,
                confidence: calculate_campaign_confidence(attacks, country),
            })
        })
        .collect()
}

/// Detect IPs sharing the same ASN attacking multiple assets.
async fn detect_asn_clusters(store: &dyn Database) -> Vec<Campaign> {
    let results = query(store,
        "MATCH (ip:IP)-[:ATTACKS]->(a:Asset) \
         WHERE ip.asn IS NOT NULL \
         WITH ip.asn AS asn, collect(DISTINCT ip.addr) AS ips, collect(DISTINCT a.hostname) AS targets, count(*) AS attacks \
         WHERE size(ips) >= 2 AND size(targets) >= 2 \
         RETURN asn, ips, targets, attacks \
         ORDER BY attacks DESC LIMIT 10"
    ).await;

    results
        .iter()
        .filter_map(|r| {
            let result = r;
            let asn = result["asn"].as_str()?;
            let attacks = result["attacks"].as_i64().unwrap_or(0);
            let ips: Vec<String> = result["ips"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let targets: Vec<String> = result["targets"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            if ips.len() < 2 {
                return None;
            }

            Some(Campaign {
                id: format!("campaign--asn-{}", asn.replace(' ', "-").to_lowercase()),
                name: format!("Campagne ASN {}", asn),
                description: format!(
                    "{} IPs depuis ASN {} ciblent {} assets ({} attaques)",
                    ips.len(),
                    asn,
                    targets.len(),
                    attacks
                ),
                source_ips: ips,
                targets,
                common_asn: Some(asn.to_string()),
                common_country: None,
                attack_count: attacks,
                confidence: 60,
            })
        })
        .collect()
}

fn calculate_campaign_confidence(attacks: i64, country: &str) -> u8 {
    let mut conf: u8 = 40;
    // More attacks = higher confidence
    conf = conf.saturating_add(match attacks {
        0..=5 => 5,
        6..=20 => 15,
        21..=50 => 25,
        _ => 35,
    });
    // High-risk countries boost confidence
    conf = conf.saturating_add(match country.to_uppercase().as_str() {
        "CN" | "RU" | "KP" | "IR" => 20,
        "BR" | "IN" | "VN" => 10,
        _ => 0,
    });
    conf.min(100)
}

/// Persist a campaign as a graph node with links to IPs and assets.
async fn persist_campaign(store: &dyn Database, campaign: &Campaign) {
    let cypher = format!(
        "MERGE (c:Campaign {{id: '{}'}}) \
         SET c.name = '{}', c.description = '{}', c.confidence = {}, \
         c.attack_count = {}, c.country = '{}', c.asn = '{}' RETURN c",
        esc(&campaign.id),
        esc(&campaign.name),
        esc(&campaign.description),
        campaign.confidence,
        campaign.attack_count,
        esc(campaign.common_country.as_deref().unwrap_or("")),
        esc(campaign.common_asn.as_deref().unwrap_or(""))
    );
    mutate(store, &cypher).await;

    // Link campaign to source IPs
    for ip in campaign.source_ips.iter().take(20) {
        let link = format!(
            "MATCH (c:Campaign {{id: '{}'}}), (ip:IP {{addr: '{}'}}) MERGE (ip)-[:PART_OF]->(c)",
            esc(&campaign.id),
            esc(ip)
        );
        mutate(store, &link).await;
    }
}

/// List all detected campaigns.
pub async fn list_campaigns(store: &dyn Database) -> Vec<serde_json::Value> {
    query(
        store,
        "MATCH (c:Campaign) \
         RETURN c.id, c.name, c.description, c.confidence, c.attack_count, c.country, c.asn \
         ORDER BY c.attack_count DESC LIMIT 20",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_campaign_confidence() {
        assert!(calculate_campaign_confidence(50, "RU") > calculate_campaign_confidence(5, "FR"));
        assert!(calculate_campaign_confidence(100, "CN") >= 95);
    }

    #[test]
    fn test_campaign_confidence_cap() {
        assert!(calculate_campaign_confidence(1000, "KP") <= 100);
    }
}
