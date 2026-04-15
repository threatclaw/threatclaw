//! IPinfo Lite — IP geolocation + ASN lookup.
//! Free, no API key required for basic lookups.
//! https://ipinfo.io/{ip}/json

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpGeoInfo {
    pub ip: String,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub org: Option<String>, // ASN + Organization name
    pub timezone: Option<String>,
}

/// Lookup IP geolocation and ASN info. Free, no key.
pub async fn lookup_ip(ip: &str) -> Result<IpGeoInfo, String> {
    let url = format!("https://ipinfo.io/{}/json", ip);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("IPinfo: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("IPinfo HTTP {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    Ok(IpGeoInfo {
        ip: data["ip"].as_str().unwrap_or(ip).into(),
        country: data["country"].as_str().map(String::from),
        region: data["region"].as_str().map(String::from),
        city: data["city"].as_str().map(String::from),
        org: data["org"].as_str().map(String::from),
        timezone: data["timezone"].as_str().map(String::from),
    })
}

/// Format IP info for LLM context injection.
pub fn format_for_context(info: &IpGeoInfo) -> String {
    let country = info.country.as_deref().unwrap_or("?");
    let org = info.org.as_deref().unwrap_or("?");
    format!("{} · {} · {}", info.ip, country, org)
}
