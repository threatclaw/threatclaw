//! Wordfence Intelligence — WordPress vulnerability feed (free, no API key).
//!
//! API v2: GET https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production
//! Completely free since December 2022. No authentication required.
//! Returns the ENTIRE vulnerability database in one response (several MB).
//! Must be cached locally and resynced at most once per day.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

const PRODUCTION_FEED: &str =
    "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WfVulnerability {
    pub id: String,
    pub title: String,
    pub slug: String,
    pub software_type: String, // "plugin", "theme", "core"
    pub affected_to: Option<String>,
    pub cve_ids: Vec<String>,
    pub cwe_id: Option<u32>,
    pub cwe_name: Option<String>,
    pub published: Option<String>,
}

/// Local cache for the Wordfence feed.
static CACHE: std::sync::LazyLock<Mutex<Option<WfCache>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

struct WfCache {
    fetched_at: chrono::DateTime<chrono::Utc>,
    by_slug: HashMap<String, Vec<WfVulnerability>>,
}

/// Sync the Wordfence Intelligence feed (downloads the entire DB).
/// Returns the number of vulnerabilities loaded.
pub async fn sync_feed() -> Result<usize, String> {
    let resp = reqwest::Client::new()
        .get(PRODUCTION_FEED)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| format!("Wordfence feed request: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Wordfence feed HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Wordfence feed parse: {}", e))?;

    let obj = body
        .as_object()
        .ok_or("Wordfence feed: expected JSON object")?;

    let mut by_slug: HashMap<String, Vec<WfVulnerability>> = HashMap::new();
    let mut count = 0;

    for (_uuid, vuln_data) in obj {
        let title = vuln_data["title"].as_str().unwrap_or("").to_string();

        // Parse software entries
        let software = vuln_data["software"].as_array();
        if let Some(sw_list) = software {
            for sw in sw_list {
                let sw_type = sw["type"].as_str().unwrap_or("plugin").to_string();
                let slug = sw["slug"].as_str().unwrap_or("").to_string();
                if slug.is_empty() {
                    continue;
                }

                // Get the highest affected_to version
                let affected_to = sw["affected_versions"].as_object().and_then(|versions| {
                    versions
                        .values()
                        .filter_map(|v| v["to_version"].as_str().map(String::from))
                        .max()
                });

                let cve_ids: Vec<String> = vuln_data["references"]["cve"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|c| c.as_str().map(|s| format!("CVE-{}", s)))
                            .collect()
                    })
                    .unwrap_or_default();

                let entry = WfVulnerability {
                    id: vuln_data["id"].as_str().unwrap_or("").to_string(),
                    title: title.clone(),
                    slug: slug.clone(),
                    software_type: sw_type,
                    affected_to,
                    cve_ids,
                    cwe_id: vuln_data["cwe"]["id"].as_u64().map(|n| n as u32),
                    cwe_name: vuln_data["cwe"]["name"].as_str().map(String::from),
                    published: vuln_data["published"].as_str().map(String::from),
                };

                by_slug.entry(slug).or_default().push(entry);
                count += 1;
            }
        }
    }

    let cache = WfCache {
        fetched_at: chrono::Utc::now(),
        by_slug,
    };

    *CACHE.lock().unwrap() = Some(cache);

    tracing::info!(
        "Wordfence Intelligence: loaded {} vulnerability entries",
        count
    );
    Ok(count)
}

/// Check if the feed needs a resync (older than 24h or not loaded).
pub fn needs_sync() -> bool {
    let guard = CACHE.lock().unwrap();
    match &*guard {
        None => true,
        Some(cache) => {
            let age = chrono::Utc::now() - cache.fetched_at;
            age.num_hours() >= 24
        }
    }
}

/// Lookup vulnerabilities for a WordPress plugin/theme slug.
pub fn lookup_slug(slug: &str) -> Vec<WfVulnerability> {
    let guard = CACHE.lock().unwrap();
    match &*guard {
        None => vec![],
        Some(cache) => cache.by_slug.get(slug).cloned().unwrap_or_default(),
    }
}

/// Lookup vulnerabilities for a slug that affect a specific version.
pub fn lookup_slug_version(slug: &str, installed_version: &str) -> Vec<WfVulnerability> {
    lookup_slug(slug)
        .into_iter()
        .filter(|v| match &v.affected_to {
            Some(to) => version_lte(installed_version, to),
            None => true,
        })
        .collect()
}

/// Get all slugs in the feed (for debugging/stats).
pub fn known_slugs_count() -> usize {
    let guard = CACHE.lock().unwrap();
    match &*guard {
        None => 0,
        Some(cache) => cache.by_slug.len(),
    }
}

fn version_lte(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
    parse(a) <= parse(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_lte() {
        assert!(version_lte("1.0.0", "2.0.0"));
        assert!(version_lte("1.0.0", "1.0.0"));
        assert!(!version_lte("2.0.0", "1.0.0"));
    }

    #[test]
    fn test_needs_sync_initially() {
        assert!(needs_sync());
    }

    #[test]
    fn test_lookup_empty_cache() {
        let result = lookup_slug("some-plugin");
        assert!(result.is_empty());
    }
}
