//! AlienVault OTX — community threat intelligence.
//! Free API key required (account on otx.alienvault.com).

use serde::{Deserialize, Serialize};

const API_BASE: &str = "https://otx.alienvault.com/api/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtxResult {
    pub indicator: String,
    pub pulse_count: u32,
    pub reputation: Option<i32>,
    pub country: Option<String>,
    pub malware_families: Vec<String>,
}

/// Lookup an IP in OTX.
pub async fn lookup_ip(ip: &str, api_key: &str) -> Result<OtxResult, String> {
    if api_key.is_empty() {
        return Err("OTX API key not configured".into());
    }

    let url = format!("{}/indicators/IPv4/{}/general", API_BASE, ip);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let resp = client
        .get(&url)
        .header("X-OTX-API-KEY", api_key)
        .send()
        .await
        .map_err(|e| format!("OTX: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("OTX HTTP {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    Ok(OtxResult {
        indicator: data["indicator"].as_str().unwrap_or(ip).into(),
        pulse_count: data["pulse_info"]["count"].as_u64().unwrap_or(0) as u32,
        reputation: data["reputation"].as_i64().map(|v| v as i32),
        country: data["country_name"].as_str().map(String::from),
        malware_families: data["pulse_info"]["pulses"]
            .as_array()
            .map(|p| {
                p.iter()
                    .filter_map(|pulse| {
                        pulse["malware_families"].as_array().map(|f| {
                            f.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<Vec<_>>()
                        })
                    })
                    .flatten()
                    .collect()
            })
            .unwrap_or_default(),
    })
}
