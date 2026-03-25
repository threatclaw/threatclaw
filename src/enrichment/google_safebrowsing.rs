//! Google Safe Browsing — check if a URL is blacklisted (malware, phishing, social engineering).
//!
//! API v4: POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}
//! Free with Google Cloud API key. Max 500 URLs per request.

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeBrowsingResult {
    pub url: String,
    pub is_threat: bool,
    pub threat_types: Vec<String>,
}

/// Check a URL against Google Safe Browsing.
pub async fn check_url(url: &str, api_key: &str) -> Result<SafeBrowsingResult, String> {
    if api_key.is_empty() {
        return Err("Google Safe Browsing API key required".into());
    }

    let endpoint = format!("{}?key={}", API_URL, api_key);

    let body = serde_json::json!({
        "client": {"clientId": "threatclaw", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    });

    let resp = reqwest::Client::new()
        .post(&endpoint)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Safe Browsing request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Safe Browsing HTTP {}", resp.status()));
    }

    let result: serde_json::Value = resp.json().await
        .map_err(|e| format!("Safe Browsing parse: {}", e))?;

    let matches = result["matches"].as_array();

    let threat_types: Vec<String> = matches
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m["threatType"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(SafeBrowsingResult {
        url: url.to_string(),
        is_threat: !threat_types.is_empty(),
        threat_types,
    })
}

/// Check multiple URLs in a single request (max 500).
pub async fn check_urls(urls: &[&str], api_key: &str) -> Result<Vec<SafeBrowsingResult>, String> {
    if api_key.is_empty() {
        return Err("Google Safe Browsing API key required".into());
    }
    if urls.is_empty() {
        return Ok(vec![]);
    }

    let entries: Vec<serde_json::Value> = urls.iter()
        .take(500)
        .map(|u| serde_json::json!({"url": u}))
        .collect();

    let endpoint = format!("{}?key={}", API_URL, api_key);

    let body = serde_json::json!({
        "client": {"clientId": "threatclaw", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": entries
        }
    });

    let resp = reqwest::Client::new()
        .post(&endpoint)
        .json(&body)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("Safe Browsing request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Safe Browsing HTTP {}", resp.status()));
    }

    let result: serde_json::Value = resp.json().await
        .map_err(|e| format!("Safe Browsing parse: {}", e))?;

    let matches = result["matches"].as_array();

    // Build a map of threat URLs
    let mut threat_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    if let Some(arr) = matches {
        for m in arr {
            if let (Some(url), Some(tt)) = (
                m["threat"]["url"].as_str(),
                m["threatType"].as_str(),
            ) {
                threat_map.entry(url.to_string()).or_default().push(tt.to_string());
            }
        }
    }

    Ok(urls.iter().map(|u| {
        let types = threat_map.get(*u).cloned().unwrap_or_default();
        SafeBrowsingResult {
            url: u.to_string(),
            is_threat: !types.is_empty(),
            threat_types: types,
        }
    }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_api_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(check_url("https://example.com", ""));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("API key required"));
    }
}
