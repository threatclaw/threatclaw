//! Shodan Enrichment — check internet exposure of an IP.
//!
//! API: GET https://api.shodan.io/shodan/host/{ip}?key={API_KEY}
//! Returns: open ports, services, vulns, OS, ISP, country

use serde::{Deserialize, Serialize};

const SHODAN_API: &str = "https://api.shodan.io";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanResult {
    pub ip: String,
    pub ports: Vec<u16>,
    pub vulns: Vec<String>,
    pub os: Option<String>,
    pub isp: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub hostnames: Vec<String>,
    pub last_update: Option<String>,
}

/// Lookup an IP on Shodan.
pub async fn lookup_ip(ip: &str, api_key: &str) -> Result<ShodanResult, String> {
    if api_key.is_empty() {
        return Err("Shodan API key required".into());
    }

    let url = format!("{}/shodan/host/{}?key={}", SHODAN_API, ip, api_key);

    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Shodan request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Shodan HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("Shodan parse: {}", e))?;

    let ports: Vec<u16> = body["ports"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect())
        .unwrap_or_default();

    let vulns: Vec<String> = body["vulns"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let hostnames: Vec<String> = body["hostnames"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    Ok(ShodanResult {
        ip: ip.to_string(),
        ports,
        vulns,
        os: body["os"].as_str().map(String::from),
        isp: body["isp"].as_str().map(String::from),
        country: body["country_name"].as_str().map(String::from),
        city: body["city"].as_str().map(String::from),
        hostnames,
        last_update: body["last_update"].as_str().map(String::from),
    })
}
