//! SSL Labs — audit SSL/TLS configuration with grade (A+ to F).
//!
//! API v3: GET https://api.ssllabs.com/api/v3/analyze?host={domain}
//! Free, no API key for v3. Async: submit then poll until READY.
//! Note: v4 requires email registration. We use v3 for simplicity.

use serde::{Deserialize, Serialize};

const API_BASE: &str = "https://api.ssllabs.com/api/v3";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslLabsResult {
    pub host: String,
    pub grade: String,
    pub has_warnings: bool,
    pub cert_expiry: Option<String>,
    pub protocols: Vec<String>,
    pub status: String,
}

/// Start a new SSL Labs scan and poll until ready (max 5 min).
pub async fn analyze(host: &str) -> Result<SslLabsResult, String> {
    if host.is_empty() {
        return Err("Host required".into());
    }

    let client = reqwest::Client::new();

    // Start new scan
    let url = format!("{}/analyze?host={}&startNew=on&all=done", API_BASE, host);
    let resp = client.get(&url)
        .timeout(std::time::Duration::from_secs(15))
        .send().await
        .map_err(|e| format!("SSL Labs request: {}", e))?;

    if resp.status().as_u16() == 429 {
        return Err("SSL Labs rate limited — too many concurrent assessments".into());
    }
    if resp.status().as_u16() == 529 {
        return Err("SSL Labs service overloaded — retry in 15+ min".into());
    }
    if !resp.status().is_success() {
        return Err(format!("SSL Labs HTTP {}", resp.status()));
    }

    let mut body: serde_json::Value = resp.json().await
        .map_err(|e| format!("SSL Labs parse: {}", e))?;

    // Poll until READY or ERROR (max 60 polls × 5s = 5 min)
    let poll_url = format!("{}/analyze?host={}&all=done", API_BASE, host);
    for _ in 0..60 {
        let status = body["status"].as_str().unwrap_or("");
        match status {
            "READY" => break,
            "ERROR" => {
                let msg = body["statusMessage"].as_str().unwrap_or("Unknown error");
                return Err(format!("SSL Labs error: {}", msg));
            }
            "DNS" | "IN_PROGRESS" => {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let resp = client.get(&poll_url)
                    .timeout(std::time::Duration::from_secs(15))
                    .send().await
                    .map_err(|e| format!("SSL Labs poll: {}", e))?;
                if !resp.status().is_success() {
                    return Err(format!("SSL Labs poll HTTP {}", resp.status()));
                }
                body = resp.json().await
                    .map_err(|e| format!("SSL Labs poll parse: {}", e))?;
            }
            _ => {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let resp = client.get(&poll_url)
                    .timeout(std::time::Duration::from_secs(15))
                    .send().await
                    .map_err(|e| format!("SSL Labs poll: {}", e))?;
                body = resp.json().await.unwrap_or_default();
            }
        }
    }

    if body["status"].as_str() != Some("READY") {
        return Err("SSL Labs scan timed out after 5 minutes".into());
    }

    // Parse endpoints
    let endpoints = body["endpoints"].as_array();
    let first = endpoints.and_then(|a| a.first());

    let grade = first
        .and_then(|e| e["grade"].as_str())
        .unwrap_or("?")
        .to_string();

    let has_warnings = first
        .and_then(|e| e["hasWarnings"].as_bool())
        .unwrap_or(false);

    // Parse protocols from details
    let protocols: Vec<String> = first
        .and_then(|e| e["details"]["protocols"].as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let name = p["name"].as_str()?;
                    let version = p["version"].as_str()?;
                    Some(format!("{} {}", name, version))
                })
                .collect()
        })
        .unwrap_or_default();

    // Parse cert expiry
    let cert_expiry = body["certs"].as_array()
        .and_then(|certs| certs.first())
        .and_then(|c| c["notAfter"].as_i64())
        .map(|ts| {
            chrono::DateTime::from_timestamp(ts / 1000, 0)
                .map(|dt| dt.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| ts.to_string())
        });

    Ok(SslLabsResult {
        host: host.to_string(),
        grade,
        has_warnings,
        cert_expiry,
        protocols,
        status: "READY".into(),
    })
}

/// Quick check: just get the cached grade if available (no new scan).
pub async fn get_cached_grade(host: &str) -> Result<Option<String>, String> {
    let url = format!("{}/analyze?host={}&fromCache=on&all=done", API_BASE, host);

    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send().await
        .map_err(|e| format!("SSL Labs cache check: {}", e))?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("SSL Labs parse: {}", e))?;

    if body["status"].as_str() != Some("READY") {
        return Ok(None);
    }

    let grade = body["endpoints"].as_array()
        .and_then(|a| a.first())
        .and_then(|e| e["grade"].as_str())
        .map(String::from);

    Ok(grade)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_host() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(analyze(""));
        assert!(result.is_err());
    }
}
