//! VirusTotal Enrichment — check files, URLs, IPs, domains.
//!
//! API v3: GET https://www.virustotal.com/api/v3/{type}/{resource}
//! Header: x-apikey: {API_KEY}
//! Free tier: 4 requests/min, 500/day

use serde::{Deserialize, Serialize};

const VT_API: &str = "https://www.virustotal.com/api/v3";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtIpResult {
    pub ip: String,
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub country: Option<String>,
    pub as_owner: Option<String>,
    pub reputation: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtHashResult {
    pub hash: String,
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub type_description: Option<String>,
    pub popular_threat_name: Option<String>,
    pub reputation: i64,
}

/// Lookup an IP address on VirusTotal.
pub async fn lookup_ip(ip: &str, api_key: &str) -> Result<VtIpResult, String> {
    if api_key.is_empty() { return Err("VirusTotal API key required".into()); }

    let url = format!("{}/ip_addresses/{}", VT_API, ip);
    let resp = reqwest::Client::new()
        .get(&url)
        .header("x-apikey", api_key)
        .timeout(std::time::Duration::from_secs(15))
        .send().await
        .map_err(|e| format!("VT request: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("VT HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("VT parse: {}", e))?;
    let attrs = &body["data"]["attributes"];
    let stats = &attrs["last_analysis_stats"];

    Ok(VtIpResult {
        ip: ip.to_string(),
        malicious: stats["malicious"].as_u64().unwrap_or(0) as u32,
        suspicious: stats["suspicious"].as_u64().unwrap_or(0) as u32,
        harmless: stats["harmless"].as_u64().unwrap_or(0) as u32,
        undetected: stats["undetected"].as_u64().unwrap_or(0) as u32,
        country: attrs["country"].as_str().map(String::from),
        as_owner: attrs["as_owner"].as_str().map(String::from),
        reputation: attrs["reputation"].as_i64().unwrap_or(0),
    })
}

/// Lookup a file hash on VirusTotal.
pub async fn lookup_hash(hash: &str, api_key: &str) -> Result<VtHashResult, String> {
    if api_key.is_empty() { return Err("VirusTotal API key required".into()); }

    let url = format!("{}/files/{}", VT_API, hash);
    let resp = reqwest::Client::new()
        .get(&url)
        .header("x-apikey", api_key)
        .timeout(std::time::Duration::from_secs(15))
        .send().await
        .map_err(|e| format!("VT request: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("VT HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("VT parse: {}", e))?;
    let attrs = &body["data"]["attributes"];
    let stats = &attrs["last_analysis_stats"];

    Ok(VtHashResult {
        hash: hash.to_string(),
        malicious: stats["malicious"].as_u64().unwrap_or(0) as u32,
        suspicious: stats["suspicious"].as_u64().unwrap_or(0) as u32,
        harmless: stats["harmless"].as_u64().unwrap_or(0) as u32,
        undetected: stats["undetected"].as_u64().unwrap_or(0) as u32,
        type_description: attrs["type_description"].as_str().map(String::from),
        popular_threat_name: attrs["popular_threat_classification"]["suggested_threat_label"].as_str().map(String::from),
        reputation: attrs["reputation"].as_i64().unwrap_or(0),
    })
}
