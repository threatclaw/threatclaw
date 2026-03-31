//! EPSS (Exploit Prediction Scoring System) — FIRST.org
//!
//! Predicts the probability a CVE will be exploited in the next 30 days.
//! Free API, no key required. Updated daily.
//! https://api.first.org/data/v1/epss

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://api.first.org/data/v1/epss";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssScore {
    pub cve_id: String,
    pub epss: f64,          // 0.0 - 1.0 probability of exploitation in 30 days
    pub percentile: f64,    // 0.0 - 1.0 rank among all CVEs
    pub date: String,
}

/// Lookup EPSS score for a CVE. Free, no API key.
pub async fn lookup_epss(cve_id: &str) -> Result<Option<EpssScore>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| format!("HTTP: {e}"))?;

    let resp = client.get(API_URL)
        .query(&[("cve", cve_id)])
        .send().await.map_err(|e| format!("EPSS: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("EPSS HTTP {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    let entry = data["data"].as_array().and_then(|a| a.first());
    match entry {
        Some(e) => Ok(Some(EpssScore {
            cve_id: e["cve"].as_str().unwrap_or(cve_id).into(),
            epss: e["epss"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0),
            percentile: e["percentile"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0),
            date: e["date"].as_str().unwrap_or("").into(),
        })),
        None => Ok(None),
    }
}

/// Lookup EPSS with cache in DB (refresh daily).
pub async fn lookup_epss_cached(
    cve_id: &str,
    store: &dyn crate::db::Database,
) -> Result<Option<EpssScore>, String> {
    // Check cache
    if let Ok(Some(cached)) = store.get_setting("_epss", cve_id).await {
        if let Some(date) = cached["date"].as_str() {
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            if date == today {
                return Ok(serde_json::from_value(cached).ok());
            }
        }
    }

    // Fetch fresh
    let result = lookup_epss(cve_id).await?;

    // Cache
    if let Some(ref score) = result {
        let _ = store.set_setting("_epss", cve_id,
            &serde_json::to_value(score).unwrap_or_default()).await;
    }

    Ok(result)
}
