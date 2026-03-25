//! PhishTank — check if a URL is known phishing.
//!
//! API: POST https://checkurl.phishtank.com/checkurl/
//! Content-Type: application/x-www-form-urlencoded (NOT JSON!)
//! Auth: Optional app_key for higher rate limits.
//! MUST set User-Agent: phishtank/threatclaw

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://checkurl.phishtank.com/checkurl/";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishTankResult {
    pub url: String,
    pub in_database: bool,
    pub is_phish: bool,
    pub verified: bool,
    pub phish_id: Option<String>,
    pub detail_url: Option<String>,
}

/// Check a URL against PhishTank database.
pub async fn check_url(url: &str, app_key: Option<&str>) -> Result<PhishTankResult, String> {
    if url.is_empty() {
        return Err("URL required".into());
    }

    let mut params = vec![
        ("url", url.to_string()),
        ("format", "json".to_string()),
    ];
    if let Some(key) = app_key {
        if !key.is_empty() {
            params.push(("app_key", key.to_string()));
        }
    }

    let resp = reqwest::Client::new()
        .post(API_URL)
        .header("User-Agent", "phishtank/threatclaw")
        .form(&params)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("PhishTank request: {}", e))?;

    if resp.status().as_u16() == 509 {
        return Err("PhishTank rate limited".into());
    }

    if !resp.status().is_success() {
        return Err(format!("PhishTank HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("PhishTank parse: {}", e))?;

    let results = &body["results"];

    let in_database = results["in_database"].as_bool()
        .or_else(|| results["in_database"].as_str().map(|s| s == "true"))
        .unwrap_or(false);

    let verified = results["verified"].as_bool()
        .or_else(|| results["verified"].as_str().map(|s| s == "true"))
        .unwrap_or(false);

    let valid = results["valid"].as_bool()
        .or_else(|| results["valid"].as_str().map(|s| s == "true"))
        .unwrap_or(false);

    Ok(PhishTankResult {
        url: url.to_string(),
        in_database,
        is_phish: in_database && verified && valid,
        verified,
        phish_id: results["phish_id"].as_str().map(String::from)
            .or_else(|| results["phish_id"].as_u64().map(|n| n.to_string())),
        detail_url: results["phish_detail_page"].as_str().map(String::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_url() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(check_url("", None));
        assert!(result.is_err());
    }
}
