//! WPScan — WordPress vulnerability lookup for plugins, themes, and core.
//!
//! API v3: GET https://wpscan.com/api/v3/plugins/{slug}
//! Auth: Authorization: Token token=YOUR_API_TOKEN
//! Free tier: 25 requests/day.

use serde::{Deserialize, Serialize};

const API_URL: &str = "https://wpscan.com/api/v3";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpVulnerability {
    pub id: String,
    pub title: String,
    pub fixed_in: Option<String>,
    pub cve_ids: Vec<String>,
    pub vuln_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WpPluginResult {
    pub slug: String,
    pub friendly_name: Option<String>,
    pub latest_version: Option<String>,
    pub vulnerabilities: Vec<WpVulnerability>,
}

/// Lookup vulnerabilities for a WordPress plugin by slug.
pub async fn lookup_plugin(slug: &str, api_token: &str) -> Result<WpPluginResult, String> {
    lookup_component("plugins", slug, api_token).await
}

/// Lookup vulnerabilities for a WordPress theme by slug.
pub async fn lookup_theme(slug: &str, api_token: &str) -> Result<WpPluginResult, String> {
    lookup_component("themes", slug, api_token).await
}

/// Lookup vulnerabilities for a WordPress core version.
/// Version format: "663" for 6.6.3 (no dots).
pub async fn lookup_core(version: &str, api_token: &str) -> Result<WpPluginResult, String> {
    let version_nodots = version.replace('.', "");
    lookup_component("wordpresses", &version_nodots, api_token).await
}

async fn lookup_component(
    component_type: &str,
    slug: &str,
    api_token: &str,
) -> Result<WpPluginResult, String> {
    if api_token.is_empty() {
        return Err("WPScan API token required".into());
    }
    if slug.is_empty() {
        return Err("Slug required".into());
    }

    let url = format!("{}/{}/{}", API_URL, component_type, slug);

    let resp = reqwest::Client::new()
        .get(&url)
        .header("Authorization", format!("Token token={}", api_token))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("WPScan request: {}", e))?;

    if resp.status().as_u16() == 404 {
        return Ok(WpPluginResult {
            slug: slug.to_string(),
            friendly_name: None,
            latest_version: None,
            vulnerabilities: vec![],
        });
    }

    if resp.status().as_u16() == 429 {
        return Err("WPScan rate limited (25 requests/day)".into());
    }

    if !resp.status().is_success() {
        return Err(format!("WPScan HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("WPScan parse: {}", e))?;

    // Response is keyed by the slug
    let data = body
        .get(slug)
        .or_else(|| body.as_object().and_then(|o| o.values().next()))
        .ok_or("WPScan: unexpected response format")?;

    let vulns: Vec<WpVulnerability> = data["vulnerabilities"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|v| {
                    let cve_ids: Vec<String> = v["references"]["cve"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|c| c.as_str().map(|s| format!("CVE-{}", s)))
                                .collect()
                        })
                        .unwrap_or_default();
                    WpVulnerability {
                        id: v["id"].as_str().unwrap_or("").to_string(),
                        title: v["title"].as_str().unwrap_or("").to_string(),
                        fixed_in: v["fixed_in"].as_str().map(String::from),
                        cve_ids,
                        vuln_type: v["vuln_type"].as_str().map(String::from),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(WpPluginResult {
        slug: slug.to_string(),
        friendly_name: data["friendly_name"].as_str().map(String::from),
        latest_version: data["latest_version"].as_str().map(String::from),
        vulnerabilities: vulns,
    })
}

/// Check if a specific plugin version is vulnerable.
/// Returns only vulns that affect the given version (fixed_in > version).
pub fn filter_for_version<'a>(
    result: &'a WpPluginResult,
    installed_version: &str,
) -> Vec<&'a WpVulnerability> {
    result
        .vulnerabilities
        .iter()
        .filter(|v| {
            match &v.fixed_in {
                Some(fixed) => version_lt(installed_version, fixed),
                None => true, // No fix available = still vulnerable
            }
        })
        .collect()
}

/// Simple version comparison: "5.2.1" < "5.3.2"
fn version_lt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
    let va = parse(a);
    let vb = parse(b);
    va < vb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_lt() {
        assert!(version_lt("5.2.1", "5.3.0"));
        assert!(version_lt("1.0.0", "2.0.0"));
        assert!(!version_lt("5.3.0", "5.2.1"));
        assert!(!version_lt("5.3.0", "5.3.0"));
    }

    #[test]
    fn test_filter_for_version() {
        let result = WpPluginResult {
            slug: "test".into(),
            friendly_name: None,
            latest_version: Some("5.9.0".into()),
            vulnerabilities: vec![
                WpVulnerability {
                    id: "1".into(),
                    title: "Old vuln".into(),
                    fixed_in: Some("4.0.0".into()),
                    cve_ids: vec![],
                    vuln_type: None,
                },
                WpVulnerability {
                    id: "2".into(),
                    title: "Current vuln".into(),
                    fixed_in: Some("6.0.0".into()),
                    cve_ids: vec![],
                    vuln_type: None,
                },
                WpVulnerability {
                    id: "3".into(),
                    title: "Unfixed".into(),
                    fixed_in: None,
                    cve_ids: vec![],
                    vuln_type: None,
                },
            ],
        };
        let affected = filter_for_version(&result, "5.5.0");
        assert_eq!(affected.len(), 2); // "Current vuln" + "Unfixed"
        assert_eq!(affected[0].id, "2");
        assert_eq!(affected[1].id, "3");
    }

    #[test]
    fn test_empty_token() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(lookup_plugin("test", ""));
        assert!(result.is_err());
    }
}
