//! CISA KEV — Known Exploited Vulnerabilities catalog.
//!
//! The most impactful enrichment source: if a CVE is in the KEV,
//! it's actively exploited in the wild and should be treated as CRITICAL
//! regardless of its CVSS score.
//!
//! Sync: daily from https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//! Storage: settings DB under "_kev" namespace
//! No API key required.

use serde::{Deserialize, Serialize};

const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub date_added: String,
    pub due_date: String,
    pub required_action: String,
}

/// Sync KEV catalog from CISA. Returns number of entries synced.
pub async fn sync_kev(store: &dyn crate::db::Database) -> Result<usize, String> {
    tracing::info!("CISA KEV: Starting sync...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build().map_err(|e| format!("HTTP: {e}"))?;

    let resp = client.get(KEV_URL).send().await.map_err(|e| format!("KEV download: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("KEV returned {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("KEV JSON: {e}"))?;
    let vulns = data["vulnerabilities"].as_array().ok_or("No vulnerabilities array")?;

    let mut count = 0;
    for vuln in vulns {
        let cve_id = vuln["cveID"].as_str().unwrap_or("").to_string();
        if cve_id.is_empty() { continue; }

        let entry = serde_json::json!({
            "cve_id": cve_id,
            "vendor": vuln["vendorProject"].as_str().unwrap_or(""),
            "product": vuln["product"].as_str().unwrap_or(""),
            "name": vuln["vulnerabilityName"].as_str().unwrap_or(""),
            "date_added": vuln["dateAdded"].as_str().unwrap_or(""),
            "due_date": vuln["dueDate"].as_str().unwrap_or(""),
            "required_action": vuln["requiredAction"].as_str().unwrap_or(""),
        });

        let _ = store.set_setting("_kev", &cve_id, &entry).await;
        count += 1;
    }

    let _ = store.set_setting("_system", "kev_sync_meta", &serde_json::json!({
        "last_sync": chrono::Utc::now().to_rfc3339(),
        "count": count,
    })).await;

    tracing::info!("CISA KEV: Synced {count} entries");
    Ok(count)
}

/// Check if a CVE is in the KEV (actively exploited).
pub async fn is_exploited(store: &dyn crate::db::Database, cve_id: &str) -> Option<KevEntry> {
    let val = store.get_setting("_kev", cve_id).await.ok()??;
    serde_json::from_value(val).ok()
}
