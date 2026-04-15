//! Mozilla Observatory — HTTP security headers assessment.
//!
//! API v2: POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host={domain}
//! Free, no API key. Returns grade (A+ to F) and score (/100+).
//! NOTE: v1 was shut down October 2024. v2 only.

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://observatory-api.mdn.mozilla.net/api/v2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservatoryResult {
    pub host: String,
    pub grade: String,
    pub score: i32,
    pub tests_passed: i32,
    pub tests_failed: i32,
    pub tests_quantity: i32,
    pub status_code: Option<i32>,
}

/// Scan a host with Mozilla Observatory.
pub async fn scan(host: &str) -> Result<ObservatoryResult, String> {
    if host.is_empty() {
        return Err("Host required".into());
    }

    let url = format!("{}/scan?host={}", API_URL, host);

    let resp = reqwest::Client::new()
        .post(&url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Observatory request: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Observatory HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Observatory parse: {}", e))?;

    if let Some(err) = body["error"].as_str() {
        return Err(format!("Observatory error: {}", err));
    }

    Ok(ObservatoryResult {
        host: host.to_string(),
        grade: body["grade"].as_str().unwrap_or("?").to_string(),
        score: body["score"].as_i64().unwrap_or(0) as i32,
        tests_passed: body["tests_passed"].as_i64().unwrap_or(0) as i32,
        tests_failed: body["tests_failed"].as_i64().unwrap_or(0) as i32,
        tests_quantity: body["tests_quantity"].as_i64().unwrap_or(0) as i32,
        status_code: body["status_code"].as_i64().map(|v| v as i32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_host() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(scan(""));
        assert!(result.is_err());
    }
}
