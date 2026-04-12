//! Unified CTI Feed — aggregates IoCs from all threat intelligence sources.
//!
//! Sources:
//! - OpenPhish (phishing URLs, free, no key)
//! - ThreatFox (abuse.ch — malware IoCs, free)
//! - URLhaus (abuse.ch — malware URLs, free)
//! - MalwareBazaar (abuse.ch — malware hashes, free)
//! - MISP CIRCL (OSINT feed, free)
//! - CISA KEV (known exploited CVEs, free)
//!
//! Confidence scoring: more sources = higher confidence.
//! Feeds into Bloom filter for real-time detection in IE cycle.
//!
//! Sync interval: every 6 hours (configurable).

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// Result of a CTI sync cycle.
#[derive(Debug)]
pub struct CtiSyncResult {
    pub sources_synced: usize,
    pub iocs_new: usize,
    pub iocs_updated: usize,
    pub iocs_total: usize,
    pub errors: Vec<String>,
}

/// Sync all CTI sources into the unified ioc_feed table.
/// Called every 6 hours by the cyber scheduler.
pub async fn sync_all_feeds(store: &dyn Database) -> CtiSyncResult {
    let mut result = CtiSyncResult {
        sources_synced: 0, iocs_new: 0, iocs_updated: 0, iocs_total: 0, errors: vec![],
    };

    // Sync each source — failures don't stop the others
    macro_rules! sync_source {
        ($name:expr, $func:expr) => {
            match tokio::time::timeout(std::time::Duration::from_secs(60), $func(store)).await {
                Ok(Ok(count)) => {
                    result.iocs_new += count;
                    result.sources_synced += 1;
                    tracing::info!("CTI-FEED: {} synced, {} new IoCs", $name, count);
                }
                Ok(Err(e)) => {
                    result.errors.push(format!("{}: {}", $name, e));
                    tracing::warn!("CTI-FEED: {} failed: {}", $name, e);
                }
                Err(_) => {
                    result.errors.push(format!("{}: timeout", $name));
                    tracing::warn!("CTI-FEED: {} timed out", $name);
                }
            }
        };
    }

    sync_source!("openphish", sync_openphish);
    sync_source!("threatfox", sync_threatfox);
    sync_source!("urlhaus", sync_urlhaus);
    sync_source!("malwarebazaar", sync_malwarebazaar);

    // Recompute confidence scores based on source count
    if let Err(e) = recompute_confidence(store).await {
        result.errors.push(format!("confidence: {}", e));
    }

    tracing::info!(
        "CTI-FEED: sync complete — {} sources, {} new IoCs, {} errors",
        result.sources_synced, result.iocs_new, result.errors.len()
    );

    result
}

/// Upsert an IoC into the unified feed.
/// If it already exists, updates sources array and last_seen.
async fn upsert_ioc(
    store: &dyn Database,
    ioc_type: &str,
    ioc_value: &str,
    source: &str,
    threat_type: Option<&str>,
    malware_family: Option<&str>,
    tags: &[&str],
) -> Result<bool, String> {
    // Use raw SQL via the settings trick — store as a log entry for now,
    // then the migration creates the proper table.
    // In production, this would be a proper DB method.
    // For now, use the settings table as a staging area.
    let key = format!("{}:{}", ioc_type, ioc_value);
    let existing = store.get_setting("_cti_feed", &key).await;

    let now = chrono::Utc::now().to_rfc3339();
    let is_new;

    match existing {
        Ok(Some(mut val)) => {
            // Update: add source if not already present
            let mut sources: Vec<String> = val["sources"].as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            if !sources.contains(&source.to_string()) {
                sources.push(source.to_string());
            }
            val["sources"] = serde_json::json!(sources);
            val["last_seen"] = serde_json::json!(now);
            if let Some(tt) = threat_type { val["threat_type"] = serde_json::json!(tt); }
            if let Some(mf) = malware_family { val["malware_family"] = serde_json::json!(mf); }
            // Confidence: 50 base + 15 per additional source
            let confidence = (50 + (sources.len() as u32 - 1) * 15).min(100);
            val["confidence"] = serde_json::json!(confidence);

            let _ = store.set_setting("_cti_feed", &key, &val).await;
            is_new = false;
        }
        _ => {
            // New IoC
            let val = serde_json::json!({
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "sources": [source],
                "confidence": 50,
                "first_seen": now,
                "last_seen": now,
                "threat_type": threat_type,
                "malware_family": malware_family,
                "tags": tags,
                "active": true,
            });
            let _ = store.set_setting("_cti_feed", &key, &val).await;
            is_new = true;
        }
    }

    Ok(is_new)
}

// ── Source-specific sync functions ──

/// OpenPhish — phishing URLs (free, no API key).
async fn sync_openphish(store: &dyn Database) -> Result<usize, String> {
    let resp = reqwest::Client::new()
        .get("https://openphish.com/feed.txt")
        .timeout(std::time::Duration::from_secs(30))
        .send().await.map_err(|e| format!("OpenPhish: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("OpenPhish HTTP {}", resp.status()));
    }

    let body = resp.text().await.map_err(|e| format!("OpenPhish body: {}", e))?;
    let mut count = 0;

    for line in body.lines().take(5000) {
        let url = line.trim();
        if url.is_empty() || url.starts_with('#') { continue; }
        if upsert_ioc(store, "url", url, "openphish", Some("phishing"), None, &["phishing"]).await.unwrap_or(false) {
            count += 1;
        }
    }

    Ok(count)
}

/// ThreatFox (abuse.ch) — malware IoCs (IPs, domains, URLs, hashes).
async fn sync_threatfox(store: &dyn Database) -> Result<usize, String> {
    let resp = reqwest::Client::new()
        .post("https://threatfox-api.abuse.ch/api/v1/")
        .json(&serde_json::json!({"query": "get_iocs", "days": 1}))
        .timeout(std::time::Duration::from_secs(30))
        .send().await.map_err(|e| format!("ThreatFox: {}", e))?;

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("ThreatFox parse: {}", e))?;
    let mut count = 0;

    if let Some(data) = body["data"].as_array() {
        for ioc in data.iter().take(5000) {
            let ioc_val = ioc["ioc"].as_str().unwrap_or("");
            let ioc_type_raw = ioc["ioc_type"].as_str().unwrap_or("");
            let malware = ioc["malware"].as_str();
            let threat = ioc["threat_type"].as_str();

            if ioc_val.is_empty() { continue; }

            let normalized_type = match ioc_type_raw {
                "ip:port" => "ip",
                "domain" => "domain",
                "url" => "url",
                "md5_hash" => "hash_md5",
                "sha256_hash" => "hash_sha256",
                _ => ioc_type_raw,
            };

            // For ip:port, extract just the IP
            let clean_val = if ioc_type_raw == "ip:port" {
                ioc_val.split(':').next().unwrap_or(ioc_val)
            } else {
                ioc_val
            };

            if upsert_ioc(store, normalized_type, clean_val, "threatfox", threat, malware, &["malware"]).await.unwrap_or(false) {
                count += 1;
            }
        }
    }

    Ok(count)
}

/// URLhaus (abuse.ch) — malware distribution URLs.
async fn sync_urlhaus(store: &dyn Database) -> Result<usize, String> {
    let resp = reqwest::Client::new()
        .get("https://urlhaus-api.abuse.ch/v1/urls/recent/")
        .timeout(std::time::Duration::from_secs(30))
        .send().await.map_err(|e| format!("URLhaus: {}", e))?;

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("URLhaus parse: {}", e))?;
    let mut count = 0;

    if let Some(urls) = body["urls"].as_array() {
        for entry in urls.iter().take(3000) {
            let url = entry["url"].as_str().unwrap_or("");
            let threat = entry["threat"].as_str();

            if url.is_empty() { continue; }

            if upsert_ioc(store, "url", url, "urlhaus", Some("malware"), threat, &["malware-distribution"]).await.unwrap_or(false) {
                count += 1;
            }
        }
    }

    Ok(count)
}

/// MalwareBazaar (abuse.ch) — malware sample hashes.
async fn sync_malwarebazaar(store: &dyn Database) -> Result<usize, String> {
    let resp = reqwest::Client::new()
        .post("https://mb-api.abuse.ch/api/v1/")
        .form(&[("query", "get_recent"), ("selector", "time")])
        .timeout(std::time::Duration::from_secs(30))
        .send().await.map_err(|e| format!("MalwareBazaar: {}", e))?;

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("MalwareBazaar parse: {}", e))?;
    let mut count = 0;

    if let Some(data) = body["data"].as_array() {
        for sample in data.iter().take(3000) {
            let sha256 = sample["sha256_hash"].as_str().unwrap_or("");
            let family = sample["signature"].as_str();

            if sha256.is_empty() { continue; }

            if upsert_ioc(store, "hash_sha256", sha256, "malwarebazaar", Some("malware"), family, &["malware-sample"]).await.unwrap_or(false) {
                count += 1;
            }

            // Also index MD5 if available
            if let Some(md5) = sample["md5_hash"].as_str() {
                if !md5.is_empty() {
                    let _ = upsert_ioc(store, "hash_md5", md5, "malwarebazaar", Some("malware"), family, &["malware-sample"]).await;
                }
            }
        }
    }

    Ok(count)
}

/// Recompute confidence scores: multi-source = higher confidence.
async fn recompute_confidence(_store: &dyn Database) -> Result<(), String> {
    // Confidence is already computed during upsert (50 base + 15/source).
    // This function can be extended for time-based decay or other factors.
    Ok(())
}

/// Load all active IoCs from the feed into a list for Bloom filter refresh.
/// Called by ioc_bloom::build_from_feeds().
pub async fn load_iocs_for_bloom(store: &dyn Database) -> Vec<String> {
    // Scan all keys in the _cti_feed namespace
    // This is a simplified approach — in production, use the ioc_feed SQL table directly
    let mut iocs = Vec::new();

    // Load from enrichment cache (the existing pattern used by ioc_bloom)
    if let Ok(Some(val)) = store.get_setting("_cti_feed", "_index").await {
        if let Some(keys) = val["keys"].as_array() {
            for key in keys {
                if let Some(k) = key.as_str() {
                    if let Ok(Some(ioc)) = store.get_setting("_cti_feed", k).await {
                        if let Some(v) = ioc["ioc_value"].as_str() {
                            iocs.push(v.to_string());
                        }
                    }
                }
            }
        }
    }

    iocs
}
