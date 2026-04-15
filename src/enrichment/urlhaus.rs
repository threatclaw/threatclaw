//! URLhaus (abuse.ch) — malicious URL lookup.
//! No API key required.

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://urlhaus-api.abuse.ch/v1/url/";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlhausResult {
    pub url: String,
    pub url_status: String,
    pub threat: Option<String>,
    pub tags: Vec<String>,
    pub date_added: Option<String>,
    pub reporter: Option<String>,
}

/// Check if a URL is known malicious in URLhaus.
/// Requires free API key from https://urlhaus.abuse.ch/account/
pub async fn lookup_url(url: &str, api_key: Option<&str>) -> Result<Option<UrlhausResult>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let mut req = client.post(API_URL).form(&[("url", url)]);
    if let Some(key) = api_key {
        req = req.header("Auth-Key", key);
    }
    let resp = req.send().await.map_err(|e| format!("URLhaus: {e}"))?;

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    if data["query_status"].as_str() != Some("ok") {
        return Ok(None);
    }

    Ok(Some(UrlhausResult {
        url: data["url"].as_str().unwrap_or("").into(),
        url_status: data["url_status"].as_str().unwrap_or("").into(),
        threat: data["threat"].as_str().map(String::from),
        tags: data["tags"]
            .as_array()
            .map(|t| {
                t.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        date_added: data["date_added"].as_str().map(String::from),
        reporter: data["reporter"].as_str().map(String::from),
    }))
}
