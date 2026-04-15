//! ThreatFox (abuse.ch) — IoC lookup (C2 servers, malicious domains, IPs).
//! No API key required.

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFoxIoc {
    pub ioc_type: String,
    pub ioc_value: String,
    pub threat_type: String,
    pub malware: Option<String>,
    pub confidence_level: Option<u8>,
    pub first_seen: Option<String>,
    pub tags: Vec<String>,
}

/// Search ThreatFox for an IoC (IP, domain, URL, hash).
/// Requires free API key from https://threatfox.abuse.ch/account/
pub async fn lookup_ioc(ioc: &str, api_key: Option<&str>) -> Result<Vec<ThreatFoxIoc>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let mut req = client
        .post(API_URL)
        .json(&serde_json::json!({ "query": "search_ioc", "search_term": ioc }));
    if let Some(key) = api_key {
        req = req.header("Auth-Key", key);
    }
    let resp = req.send().await.map_err(|e| format!("ThreatFox: {e}"))?;

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    if data["query_status"].as_str() != Some("ok") {
        return Ok(vec![]);
    }

    let results: Vec<ThreatFoxIoc> = data["data"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    Some(ThreatFoxIoc {
                        ioc_type: entry["ioc_type"].as_str()?.into(),
                        ioc_value: entry["ioc"].as_str()?.into(),
                        threat_type: entry["threat_type"].as_str().unwrap_or("").into(),
                        malware: entry["malware_printable"].as_str().map(String::from),
                        confidence_level: entry["confidence_level"].as_u64().map(|v| v as u8),
                        first_seen: entry["first_seen_utc"].as_str().map(String::from),
                        tags: entry["tags"]
                            .as_array()
                            .map(|t| {
                                t.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(results)
}
