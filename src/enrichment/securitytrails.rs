//! SecurityTrails — DNS intelligence, subdomains, and WHOIS history.
//!
//! API: GET https://api.securitytrails.com/v1/domain/{hostname}/subdomains
//! Auth: APIKEY header (all caps, no hyphen — unusual but confirmed)
//! Free tier: 50 requests/month. Cache aggressively.

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://api.securitytrails.com/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTrailsResult {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub a_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub ns_records: Vec<String>,
}

/// Lookup domain info and subdomains.
pub async fn lookup_domain(domain: &str, api_key: &str) -> Result<SecurityTrailsResult, String> {
    if api_key.is_empty() {
        return Err("SecurityTrails API key required".into());
    }
    if domain.is_empty() {
        return Err("Domain required".into());
    }

    let client = reqwest::Client::new();

    // Get domain details
    let domain_url = format!("{}/domain/{}", API_URL, domain);
    let domain_resp = client
        .get(&domain_url)
        .header("APIKEY", api_key)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("SecurityTrails request: {}", e))?;

    if domain_resp.status().as_u16() == 429 {
        return Err("SecurityTrails rate limited (50 req/month free tier)".into());
    }
    if !domain_resp.status().is_success() {
        return Err(format!("SecurityTrails HTTP {}", domain_resp.status()));
    }

    let domain_body: serde_json::Value = domain_resp
        .json()
        .await
        .map_err(|e| format!("SecurityTrails parse: {}", e))?;

    let dns = &domain_body["current_dns"];

    let a_records: Vec<String> = dns["a"]["values"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v["ip"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let mx_records: Vec<String> = dns["mx"]["values"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v["hostname"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let ns_records: Vec<String> = dns["ns"]["values"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v["nameserver"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Get subdomains (separate request)
    let sub_url = format!("{}/domain/{}/subdomains", API_URL, domain);
    let sub_resp = client
        .get(&sub_url)
        .header("APIKEY", api_key)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("SecurityTrails subdomains: {}", e))?;

    let subdomains: Vec<String> = if sub_resp.status().is_success() {
        let sub_body: serde_json::Value = sub_resp
            .json()
            .await
            .map_err(|e| format!("SecurityTrails subdomains parse: {}", e))?;
        sub_body["subdomains"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| format!("{}.{}", s, domain)))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    };

    Ok(SecurityTrailsResult {
        domain: domain.to_string(),
        subdomains,
        a_records,
        mx_records,
        ns_records,
    })
}

/// Lookup DNS history for a domain (A records changes).
pub async fn dns_history(
    domain: &str,
    api_key: &str,
    record_type: &str,
) -> Result<Vec<DnsHistoryEntry>, String> {
    if api_key.is_empty() {
        return Err("SecurityTrails API key required".into());
    }

    let url = format!("{}/history/{}/dns/{}", API_URL, domain, record_type);
    let resp = reqwest::Client::new()
        .get(&url)
        .header("APIKEY", api_key)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("SecurityTrails history: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("SecurityTrails history HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("SecurityTrails history parse: {}", e))?;

    let entries = body["records"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|r| {
                    let values: Vec<String> = r["values"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v["ip"].as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    DnsHistoryEntry {
                        first_seen: r["first_seen"].as_str().unwrap_or("").to_string(),
                        last_seen: r["last_seen"].as_str().unwrap_or("").to_string(),
                        values,
                        organizations: r["organizations"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(entries)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHistoryEntry {
    pub first_seen: String,
    pub last_seen: String,
    pub values: Vec<String>,
    pub organizations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(lookup_domain("example.com", ""));
        assert!(result.is_err());
    }
}
