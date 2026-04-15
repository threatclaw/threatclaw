//! crt.sh — Certificate Transparency log monitoring.
//!
//! API: GET https://crt.sh/?q={domain}&output=json
//! Free, no API key, no auth. Undocumented but stable.
//! Discovers certificates issued for a domain + subdomains.

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://crt.sh";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrtShEntry {
    pub id: i64,
    pub issuer_name: String,
    pub common_name: String,
    pub name_values: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub entry_timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrtShResult {
    pub domain: String,
    pub certificates: Vec<CrtShEntry>,
    pub subdomains: Vec<String>,
}

/// Lookup all certificates for a domain (including wildcard subdomains).
pub async fn lookup_domain(domain: &str) -> Result<CrtShResult, String> {
    if domain.is_empty() {
        return Err("Domain required".into());
    }

    // %25 is URL-encoded % for wildcard subdomain matching
    let url = format!("{}/?q=%25.{}&output=json&deduplicate=Y", API_URL, domain);

    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(30)) // Can be slow for popular domains
        .send()
        .await
        .map_err(|e| format!("crt.sh request: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("crt.sh HTTP {}", resp.status()));
    }

    let text = resp
        .text()
        .await
        .map_err(|e| format!("crt.sh read body: {}", e))?;

    // crt.sh returns empty body or "[]" if no results
    if text.is_empty() || text.trim() == "[]" {
        return Ok(CrtShResult {
            domain: domain.to_string(),
            certificates: vec![],
            subdomains: vec![],
        });
    }

    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&text).map_err(|e| format!("crt.sh parse: {}", e))?;

    let mut subdomains = std::collections::HashSet::new();
    let mut certs = Vec::new();

    for entry in &entries {
        let name_value = entry["name_value"].as_str().unwrap_or("");
        // name_value contains SANs separated by newlines
        let names: Vec<String> = name_value
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|n| !n.is_empty() && !n.starts_with('*'))
            .collect();

        for name in &names {
            // Extract subdomain part
            if name.ends_with(domain) && name != domain {
                subdomains.insert(name.clone());
            }
        }

        certs.push(CrtShEntry {
            id: entry["id"].as_i64().unwrap_or(0),
            issuer_name: entry["issuer_name"].as_str().unwrap_or("").to_string(),
            common_name: entry["common_name"].as_str().unwrap_or("").to_string(),
            name_values: names,
            not_before: entry["not_before"].as_str().unwrap_or("").to_string(),
            not_after: entry["not_after"].as_str().unwrap_or("").to_string(),
            entry_timestamp: entry["entry_timestamp"].as_str().unwrap_or("").to_string(),
        });
    }

    let mut subdomain_list: Vec<String> = subdomains.into_iter().collect();
    subdomain_list.sort();

    Ok(CrtShResult {
        domain: domain.to_string(),
        certificates: certs,
        subdomains: subdomain_list,
    })
}

/// Check for recently issued certificates (last N days).
pub async fn recent_certs(domain: &str, days: i64) -> Result<Vec<CrtShEntry>, String> {
    let result = lookup_domain(domain).await?;
    let cutoff = chrono::Utc::now() - chrono::Duration::days(days);
    let cutoff_str = cutoff.format("%Y-%m-%d").to_string();

    Ok(result
        .certificates
        .into_iter()
        .filter(|c| c.not_before >= cutoff_str)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_domain() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(lookup_domain(""));
        assert!(result.is_err());
    }
}
