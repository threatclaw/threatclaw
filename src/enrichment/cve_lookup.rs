//! CVE Enrichment via NVD API v2.
//!
//! Lookup CVE details on demand — no massive sync.
//! Cache in PostgreSQL, refresh after 7 days.
//! Rate limited: 5 req/30s without key, 50 req/30s with key.

use serde::{Deserialize, Serialize};

/// CVE enrichment data from NVD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: Option<f64>,
    pub cvss_severity: Option<String>,
    pub published: Option<String>,
    pub exploited_in_wild: bool,
    pub patch_urls: Vec<String>,
}

/// NVD API configuration.
#[derive(Debug, Clone)]
pub struct NvdConfig {
    pub api_key: Option<String>,
    pub cache_days: u64,
}

impl Default for NvdConfig {
    fn default() -> Self {
        Self {
            api_key: std::env::var("NVD_API_KEY").ok().filter(|k| !k.is_empty()),
            cache_days: 7,
        }
    }
}

impl NvdConfig {
    /// Rate limit in milliseconds between requests.
    pub fn rate_limit_ms(&self) -> u64 {
        if self.api_key.is_some() { 600 } else { 6000 }
    }

    /// Charge la config NVD depuis la base de données (settings du dashboard).
    /// Priorité : env var NVD_API_KEY > DB setting tc_config_general.nvdApiKey > None.
    pub async fn from_db(store: &dyn crate::db::Database) -> Self {
        let mut config = Self::default();

        // Si déjà défini par env var, ne pas écraser
        if config.api_key.is_some() {
            return config;
        }

        // Lire depuis tc_config_general
        if let Ok(Some(general)) = store.get_setting("_system", "tc_config_general").await {
            if let Some(key) = general["nvdApiKey"].as_str() {
                if !key.is_empty() {
                    config.api_key = Some(key.to_string());
                    tracing::debug!("NVD API key loaded from dashboard config");
                }
            }
        }

        config
    }
}

/// Lookup a CVE from NVD API v2.
/// Returns enrichment data for injection into the LLM prompt.
pub async fn lookup_cve(cve_id: &str, config: &NvdConfig) -> Result<CveInfo, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let mut req = client.get("https://services.nvd.nist.gov/rest/json/cves/2.0")
        .query(&[("cveId", cve_id)]);

    if let Some(ref key) = config.api_key {
        req = req.header("apiKey", key);
    }

    let resp = req.send().await
        .map_err(|e| format!("NVD API request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("NVD API returned {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await
        .map_err(|e| format!("NVD JSON parse error: {e}"))?;

    let vuln = data["vulnerabilities"]
        .as_array()
        .and_then(|v| v.first())
        .ok_or_else(|| format!("CVE {} not found in NVD", cve_id))?;

    let cve = &vuln["cve"];

    // Extract description (English preferred)
    let description = cve["descriptions"]
        .as_array()
        .and_then(|descs| {
            descs.iter()
                .find(|d| d["lang"].as_str() == Some("en"))
                .or(descs.first())
        })
        .and_then(|d| d["value"].as_str())
        .unwrap_or("")
        .to_string();

    // Extract CVSS score (try v3.1 first, then v3.0, then v2)
    let (cvss_score, cvss_severity) = extract_cvss(cve);

    // Extract published date
    let published = cve["published"].as_str().map(|s| s.to_string());

    // Check if exploited in wild (CISA KEV)
    let exploited_in_wild = cve["cisaExploitAdd"].as_str().is_some();

    // Extract patch/reference URLs
    let patch_urls: Vec<String> = cve["references"]
        .as_array()
        .map(|refs| {
            refs.iter()
                .filter(|r| {
                    r["tags"].as_array()
                        .map(|t| t.iter().any(|tag| {
                            let s = tag.as_str().unwrap_or("");
                            s == "Patch" || s == "Vendor Advisory"
                        }))
                        .unwrap_or(false)
                })
                .filter_map(|r| r["url"].as_str().map(|s| s.to_string()))
                .take(3)
                .collect()
        })
        .unwrap_or_default();

    Ok(CveInfo {
        cve_id: cve_id.to_string(),
        description: truncate(&description, 300),
        cvss_score,
        cvss_severity,
        published,
        exploited_in_wild,
        patch_urls,
    })
}

/// Extract CVSS score from NVD CVE data.
fn extract_cvss(cve: &serde_json::Value) -> (Option<f64>, Option<String>) {
    let metrics = &cve["metrics"];

    // Try CVSS v3.1
    if let Some(v31) = metrics["cvssMetricV31"].as_array().and_then(|a| a.first()) {
        let score = v31["cvssData"]["baseScore"].as_f64();
        let severity = v31["cvssData"]["baseSeverity"].as_str().map(|s| s.to_string());
        if score.is_some() { return (score, severity); }
    }

    // Try CVSS v3.0
    if let Some(v30) = metrics["cvssMetricV30"].as_array().and_then(|a| a.first()) {
        let score = v30["cvssData"]["baseScore"].as_f64();
        let severity = v30["cvssData"]["baseSeverity"].as_str().map(|s| s.to_string());
        if score.is_some() { return (score, severity); }
    }

    // Try CVSS v2
    if let Some(v2) = metrics["cvssMetricV2"].as_array().and_then(|a| a.first()) {
        let score = v2["cvssData"]["baseScore"].as_f64();
        let severity = v2["baseSeverity"].as_str().map(|s| s.to_string());
        if score.is_some() { return (score, severity); }
    }

    (None, None)
}

/// Format CVE info for LLM prompt injection (compact).
pub fn format_for_prompt(cve: &CveInfo) -> String {
    let score = cve.cvss_score.map(|s| format!("CVSS {s}")).unwrap_or_else(|| "CVSS ?".to_string());
    let kev = if cve.exploited_in_wild { " [EXPLOITED IN WILD]" } else { "" };
    format!("{} ({}{}): {}", cve.cve_id, score, kev, truncate(&cve.description, 150))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else {
        let end = s.char_indices().take_while(|(i, _)| *i < max).last().map(|(i, c)| i + c.len_utf8()).unwrap_or(0);
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lookup_log4shell() {
        let config = NvdConfig::default();
        match lookup_cve("CVE-2021-44228", &config).await {
            Ok(cve) => {
                assert_eq!(cve.cve_id, "CVE-2021-44228");
                assert!(cve.cvss_score.unwrap_or(0.0) >= 9.0);
                assert!(cve.description.contains("Log4j") || cve.description.contains("Apache"));
                println!("Log4Shell: {}", format_for_prompt(&cve));
            }
            Err(e) => {
                // NVD might rate limit in CI
                eprintln!("NVD lookup failed (rate limited?): {e}");
            }
        }
    }
}
