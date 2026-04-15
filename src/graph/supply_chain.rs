//! Supply Chain Risk — NIS2 Article 21 compliance.
//!
//! Models Vendor → Software → Asset → CVE relationships.
//! Generates supply chain risk reports for ANSSI audits.

use crate::db::Database;
use crate::graph::threat_graph::{mutate, query};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// A software vendor in the supply chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vendor {
    pub id: String,
    pub name: String,
    pub products: Vec<String>,
    pub risk_score: f64,
    pub kev_count: usize,
    pub cve_count: usize,
}

/// A software product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Software {
    pub id: String,
    pub name: String,
    pub version: String,
    pub vendor: String,
}

/// Supply chain risk analysis.
#[derive(Debug, Clone, Serialize)]
pub struct SupplyChainAnalysis {
    pub vendors: Vec<VendorRisk>,
    pub total_vendors: usize,
    pub total_software: usize,
    pub total_cves: usize,
    pub kev_exposures: usize,
    pub summary: String,
}

/// Risk assessment for a single vendor.
#[derive(Debug, Clone, Serialize)]
pub struct VendorRisk {
    pub vendor_name: String,
    pub software_count: usize,
    pub cve_count: usize,
    pub kev_count: usize,
    pub max_cvss: f64,
    pub affected_assets: Vec<String>,
    pub risk_level: String,
}

/// Upsert a Vendor node.
pub async fn upsert_vendor(store: &dyn Database, vendor_id: &str, name: &str) {
    let cypher = format!(
        "MERGE (v:Vendor {{id: '{}'}}) SET v.name = '{}' RETURN v",
        esc(vendor_id),
        esc(name)
    );
    mutate(store, &cypher).await;
}

/// Upsert a Software node.
pub async fn upsert_software(
    store: &dyn Database,
    software_id: &str,
    name: &str,
    version: &str,
    vendor_id: &str,
) {
    let cypher = format!(
        "MERGE (s:Software {{id: '{}'}}) SET s.name = '{}', s.version = '{}' RETURN s",
        esc(software_id),
        esc(name),
        esc(version)
    );
    mutate(store, &cypher).await;

    // Link to vendor
    let link = format!(
        "MATCH (v:Vendor {{id: '{}'}}), (s:Software {{id: '{}'}}) MERGE (v)-[:PROVIDES]->(s)",
        esc(vendor_id),
        esc(software_id)
    );
    mutate(store, &link).await;
}

/// Link software to an asset: Software -[:INSTALLED_ON]-> Asset
pub async fn link_software_to_asset(store: &dyn Database, software_id: &str, asset_id: &str) {
    let cypher = format!(
        "MATCH (s:Software {{id: '{}'}}), (a:Asset {{id: '{}'}}) MERGE (s)-[:INSTALLED_ON]->(a)",
        esc(software_id),
        esc(asset_id)
    );
    mutate(store, &cypher).await;
}

/// Link a CVE to software: CVE -[:AFFECTS_SOFTWARE]-> Software
pub async fn link_cve_to_software(store: &dyn Database, cve_id: &str, software_id: &str) {
    let cypher = format!(
        "MATCH (c:CVE {{id: '{}'}}), (s:Software {{id: '{}'}}) MERGE (c)-[:AFFECTS_SOFTWARE]->(s)",
        esc(cve_id),
        esc(software_id)
    );
    mutate(store, &cypher).await;
}

/// Analyze supply chain risk across all vendors.
pub async fn analyze_supply_chain(store: &dyn Database) -> SupplyChainAnalysis {
    // Query: Vendor → Software → Asset with CVE stats
    let results = query(
        store,
        "MATCH (v:Vendor)-[:PROVIDES]->(s:Software)-[:INSTALLED_ON]->(a:Asset) \
         OPTIONAL MATCH (c:CVE)-[:AFFECTS_SOFTWARE]->(s) \
         WITH v.name AS vendor, collect(DISTINCT s.name) AS software, \
         collect(DISTINCT a.hostname) AS assets, \
         collect(DISTINCT c.id) AS cves, \
         MAX(c.cvss) AS max_cvss, \
         SUM(CASE WHEN c.in_kev = true THEN 1 ELSE 0 END) AS kev_count \
         RETURN vendor, software, assets, cves, max_cvss, kev_count \
         ORDER BY kev_count DESC, max_cvss DESC",
    )
    .await;

    let mut vendors = vec![];
    let mut total_cves = 0;
    let mut total_kev = 0;
    let mut total_software = 0;

    for r in &results {
        let result = r;
        let vendor_name = result["vendor"].as_str().unwrap_or("Unknown").to_string();
        let software: Vec<String> = result["software"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let assets: Vec<String> = result["assets"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let cves: Vec<String> = result["cves"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let max_cvss = result["max_cvss"].as_f64().unwrap_or(0.0);
        let kev_count = result["kev_count"].as_i64().unwrap_or(0) as usize;

        total_cves += cves.len();
        total_kev += kev_count;
        total_software += software.len();

        let risk_level = if kev_count > 0 {
            "critical".into()
        } else if max_cvss >= 9.0 {
            "high".into()
        } else if max_cvss >= 7.0 {
            "medium".into()
        } else {
            "low".into()
        };

        vendors.push(VendorRisk {
            vendor_name,
            software_count: software.len(),
            cve_count: cves.len(),
            kev_count,
            max_cvss,
            affected_assets: assets,
            risk_level,
        });
    }

    let summary = format!(
        "Supply chain : {} fournisseurs, {} logiciels, {} CVEs, {} KEV",
        vendors.len(),
        total_software,
        total_cves,
        total_kev
    );

    SupplyChainAnalysis {
        vendors,
        total_vendors: results.len(),
        total_software,
        total_cves,
        kev_exposures: total_kev,
        summary,
    }
}

/// Generate NIS2 Article 21 supply chain report (JSON).
pub async fn generate_nis2_report(store: &dyn Database) -> serde_json::Value {
    let analysis = analyze_supply_chain(store).await;

    json!({
        "report_type": "NIS2 Article 21 — Supply Chain Risk",
        "spec_version": "2.1",
        "created_by_ref": crate::branding::STIX_IDENTITY,
        "generated_by": crate::branding::version_string(),
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "summary": analysis.summary,
        "vendors": analysis.vendors,
        "metrics": {
            "total_vendors": analysis.total_vendors,
            "total_software": analysis.total_software,
            "total_cves": analysis.total_cves,
            "kev_exposures": analysis.kev_exposures,
        },
        "compliance_status": if analysis.kev_exposures == 0 { "compliant" } else { "action_required" },
        "footer": crate::branding::report_footer(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vendor_struct() {
        let v = VendorRisk {
            vendor_name: "Fortinet".into(),
            software_count: 1,
            cve_count: 3,
            kev_count: 1,
            max_cvss: 9.8,
            affected_assets: vec!["fw-01".into()],
            risk_level: "critical".into(),
        };
        assert_eq!(v.risk_level, "critical");
    }
}
