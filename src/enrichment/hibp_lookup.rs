//! Have I Been Pwned — check if an email has been in data breaches.
//!
//! API v3: GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
//! Header: hibp-api-key: {API_KEY}
//! Rate limit: 10 requests/min (with key)

use serde::{Deserialize, Serialize};

const HIBP_API: &str = "https://haveibeenpwned.com/api/v3";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HibpResult {
    pub email: String,
    pub breached: bool,
    pub breach_count: usize,
    pub breaches: Vec<HibpBreach>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HibpBreach {
    pub name: String,
    pub domain: String,
    pub breach_date: String,
    pub data_classes: Vec<String>,
    pub is_verified: bool,
}

/// Check if an email appears in known data breaches.
pub async fn check_email(email: &str, api_key: &str) -> Result<HibpResult, String> {
    if api_key.is_empty() { return Err("HIBP API key required".into()); }

    let url = format!("{}/breachedaccount/{}?truncateResponse=false", HIBP_API, email);
    let resp = reqwest::Client::new()
        .get(&url)
        .header("hibp-api-key", api_key)
        .header("user-agent", "ThreatClaw-SecurityAgent")
        .timeout(std::time::Duration::from_secs(10))
        .send().await
        .map_err(|e| format!("HIBP request: {}", e))?;

    // 404 = not breached (good!)
    if resp.status().as_u16() == 404 {
        return Ok(HibpResult {
            email: email.to_string(),
            breached: false,
            breach_count: 0,
            breaches: vec![],
        });
    }

    if !resp.status().is_success() {
        return Err(format!("HIBP HTTP {}", resp.status()));
    }

    let breaches_raw: Vec<serde_json::Value> = resp.json().await
        .map_err(|e| format!("HIBP parse: {}", e))?;

    let breaches: Vec<HibpBreach> = breaches_raw.iter().map(|b| {
        HibpBreach {
            name: b["Name"].as_str().unwrap_or("").to_string(),
            domain: b["Domain"].as_str().unwrap_or("").to_string(),
            breach_date: b["BreachDate"].as_str().unwrap_or("").to_string(),
            data_classes: b["DataClasses"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            is_verified: b["IsVerified"].as_bool().unwrap_or(false),
        }
    }).collect();

    Ok(HibpResult {
        email: email.to_string(),
        breached: !breaches.is_empty(),
        breach_count: breaches.len(),
        breaches,
    })
}
