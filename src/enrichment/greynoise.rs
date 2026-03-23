//! GreyNoise — distinguish targeted attacks from internet noise.
//! Community API: free, no key required. Full API: key optional.
//! Crucial for reducing false positives in SOC triage.

use serde::{Deserialize, Serialize};

const COMMUNITY_URL: &str = "https://api.greynoise.io/v3/community/";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreyNoiseResult {
    pub ip: String,
    pub noise: bool,        // true = mass scanner (benign noise)
    pub riot: bool,         // true = known benign service (CDN, DNS, etc.)
    pub classification: String, // "benign", "malicious", "unknown"
    pub name: Option<String>,
    pub message: Option<String>,
}

/// Lookup an IP in GreyNoise Community API.
/// Returns: noise=true → mass scanner, deprioritize.
///          riot=true → known good service (Google, Cloudflare).
///          classification="malicious" → targeted attack, escalate.
pub async fn lookup_ip(ip: &str, api_key: Option<&str>) -> Result<GreyNoiseResult, String> {
    let url = format!("{}{}", COMMUNITY_URL, ip);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| format!("HTTP: {e}"))?;

    let mut req = client.get(&url);
    if let Some(key) = api_key {
        req = req.header("key", key);
    }

    let resp = req.send().await.map_err(|e| format!("GreyNoise: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("GreyNoise HTTP {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    Ok(GreyNoiseResult {
        ip: data["ip"].as_str().unwrap_or(ip).into(),
        noise: data["noise"].as_bool().unwrap_or(false),
        riot: data["riot"].as_bool().unwrap_or(false),
        classification: data["classification"].as_str().unwrap_or("unknown").into(),
        name: data["name"].as_str().map(String::from),
        message: data["message"].as_str().map(String::from),
    })
}

/// Interpret GreyNoise result for severity adjustment.
/// Returns: negative = deprioritize, positive = escalate, 0 = no change.
pub fn severity_adjustment(result: &GreyNoiseResult) -> i8 {
    if result.riot {
        return -2; // Known benign (Google, Cloudflare) → strongly deprioritize
    }
    if result.noise {
        return -1; // Mass scanner → deprioritize
    }
    if result.classification == "malicious" {
        return 1; // Targeted attack → escalate
    }
    0 // Unknown → no change
}
