//! URLScan.io — sandbox URL analysis (screenshot, scripts, redirections, malware).
//!
//! Submit: POST https://urlscan.io/api/v1/scan/
//! Result: GET https://urlscan.io/api/v1/result/{uuid}/
//! Auth: API-Key header. Free tier: ~50-100 scans/day.
//! Scan takes 10-30s; poll result endpoint until HTTP 200.

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://urlscan.io/api/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlScanResult {
    pub url: String,
    pub uuid: String,
    pub is_malicious: bool,
    pub score: i32,
    pub domain: Option<String>,
    pub ip: Option<String>,
    pub status_code: Option<i32>,
    pub total_requests: i32,
    pub malicious_requests: i32,
    pub result_url: String,
}

/// Submit a URL for scanning and wait for result (max 60s).
pub async fn scan_url(url: &str, api_key: &str) -> Result<UrlScanResult, String> {
    if api_key.is_empty() {
        return Err("URLScan.io API key required".into());
    }
    if url.is_empty() {
        return Err("URL required".into());
    }

    let client = reqwest::Client::new();

    // Submit scan
    let submit_resp = client
        .post(&format!("{}/scan/", API_URL))
        .header("API-Key", api_key)
        .json(&serde_json::json!({
            "url": url,
            "visibility": "unlisted"
        }))
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("URLScan submit: {}", e))?;

    if submit_resp.status().as_u16() == 429 {
        return Err("URLScan.io rate limited".into());
    }
    if !submit_resp.status().is_success() {
        let status = submit_resp.status();
        let body = submit_resp.text().await.unwrap_or_default();
        return Err(format!("URLScan submit HTTP {} — {}", status, body));
    }

    let submit_body: serde_json::Value = submit_resp.json().await
        .map_err(|e| format!("URLScan submit parse: {}", e))?;

    let uuid = submit_body["uuid"].as_str()
        .ok_or("URLScan: no UUID in response")?
        .to_string();

    let result_api = format!("{}/result/{}/", API_URL, uuid);

    // Poll for result (returns 404 while scanning)
    for _ in 0..12 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let poll_resp = client
            .get(&result_api)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| format!("URLScan poll: {}", e))?;

        if poll_resp.status().as_u16() == 404 {
            continue; // Still scanning
        }

        if !poll_resp.status().is_success() {
            continue;
        }

        let body: serde_json::Value = poll_resp.json().await
            .map_err(|e| format!("URLScan result parse: {}", e))?;

        let verdicts = &body["verdicts"]["overall"];
        let page = &body["page"];
        let stats = &body["stats"];

        return Ok(UrlScanResult {
            url: url.to_string(),
            uuid: uuid.clone(),
            is_malicious: verdicts["malicious"].as_bool().unwrap_or(false),
            score: verdicts["score"].as_i64().unwrap_or(0) as i32,
            domain: page["domain"].as_str().map(String::from),
            ip: page["ip"].as_str().map(String::from),
            status_code: page["status"].as_str()
                .and_then(|s| s.parse::<i32>().ok()),
            total_requests: stats["resourceStats"].as_array()
                .map(|a| a.len() as i32)
                .unwrap_or(0),
            malicious_requests: stats["malicious"].as_i64().unwrap_or(0) as i32,
            result_url: format!("https://urlscan.io/result/{}/", uuid),
        });
    }

    Err("URLScan scan timed out after 60 seconds".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_api_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scan_url("https://example.com", ""));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("API key required"));
    }

    #[test]
    fn test_empty_url() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scan_url("", "some_key"));
        assert!(result.is_err());
    }
}
