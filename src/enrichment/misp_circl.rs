//! MISP CIRCL OSINT Feed — public threat intelligence.
//! No authentication required. Synced every 6 hours.
//! Feed: https://www.circl.lu/doc/misp/feed-osint/
//!
//! Provides IoC with campaign/actor context — what ThreatFox/OpenPhish don't give.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MANIFEST_URL: &str = "https://www.circl.lu/doc/misp/feed-osint/manifest.json";
const FEED_BASE: &str = "https://www.circl.lu/doc/misp/feed-osint";
const MAX_EVENTS_PER_SYNC: usize = 50;
const DAYS_BACK: i64 = 7;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispIoc {
    pub ioc_type: String,
    pub ioc_value: String,
    pub event_info: String,
    pub threat_level: u8,
    pub tags: Vec<String>,
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("ThreatClaw/2.2")
        .build()
        .map_err(|e| format!("HTTP: {e}"))
}

/// Sync CIRCL OSINT feed. Downloads manifest, fetches recent events,
/// extracts IoC attributes, stores in settings.
pub async fn sync_feed(store: &dyn crate::db::Database) -> Result<usize, String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    let c = client()?;

    // 1. Fetch manifest
    let manifest: serde_json::Value = c
        .get(MANIFEST_URL)
        .send()
        .await
        .map_err(|e| format!("MISP manifest: {e}"))?
        .json()
        .await
        .map_err(|e| format!("MISP manifest JSON: {e}"))?;

    let now = chrono::Utc::now().timestamp();
    let cutoff = now - (DAYS_BACK * 86400);

    // 2. Filter recent events
    let mut recent_uuids: Vec<String> = Vec::new();
    if let Some(obj) = manifest.as_object() {
        for (uuid, meta) in obj {
            let ts = meta["timestamp"]
                .as_str()
                .and_then(|s| s.parse::<i64>().ok())
                .or_else(|| meta["timestamp"].as_i64())
                .unwrap_or(0);
            if ts >= cutoff {
                recent_uuids.push(uuid.clone());
            }
        }
    }

    recent_uuids.truncate(MAX_EVENTS_PER_SYNC);
    tracing::info!(
        "MISP: {} recent events (last {}d) to fetch",
        recent_uuids.len(),
        DAYS_BACK
    );

    // 3. Fetch events and extract IoC
    let mut all_ips = HashSet::new();
    let mut all_domains = HashSet::new();
    let mut all_urls = HashSet::new();
    let mut all_hashes = HashSet::new();
    let mut events_processed = 0u32;

    let ioc_types: HashSet<&str> = [
        "ip-dst",
        "ip-src",
        "domain",
        "hostname",
        "url",
        "sha256",
        "sha1",
        "md5",
        "filename|sha256",
        "filename|md5",
    ]
    .into_iter()
    .collect();

    for uuid in &recent_uuids {
        if tokio::time::Instant::now() > deadline {
            tracing::warn!(
                "MISP: Deadline reached, stopping after {} events",
                events_processed
            );
            break;
        }

        let url = format!("{}/{}.json", FEED_BASE, uuid);
        let resp = match c.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::debug!("MISP: Event {} returned {}", uuid, r.status());
                continue;
            }
            Err(e) => {
                tracing::debug!("MISP: Event {} fetch failed: {}", uuid, e);
                continue;
            }
        };

        let event_json: serde_json::Value = match resp.json().await {
            Ok(j) => j,
            Err(_) => continue,
        };

        let event = &event_json["Event"];
        let attributes = match event["Attribute"].as_array() {
            Some(a) => a,
            None => continue,
        };

        for attr in attributes {
            let attr_type = attr["type"].as_str().unwrap_or("");
            if !ioc_types.contains(attr_type) {
                continue;
            }

            let value = match attr["value"].as_str() {
                Some(v) if !v.is_empty() => v.to_lowercase(),
                _ => continue,
            };

            // Handle composite types like "filename|sha256"
            let clean_value = if value.contains('|') {
                value.split('|').last().unwrap_or(&value).to_string()
            } else {
                value
            };

            match attr_type {
                "ip-dst" | "ip-src" => {
                    all_ips.insert(clean_value);
                }
                "domain" | "hostname" => {
                    all_domains.insert(clean_value);
                }
                "url" => {
                    all_urls.insert(clean_value);
                }
                "sha256" | "sha1" | "md5" | "filename|sha256" | "filename|md5" => {
                    all_hashes.insert(clean_value);
                }
                _ => {}
            }
        }

        events_processed += 1;
        // Polite delay
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    // 4. Store in settings
    let total = all_ips.len() + all_domains.len() + all_urls.len() + all_hashes.len();
    let data = serde_json::json!({
        "ips": all_ips.into_iter().collect::<Vec<_>>(),
        "domains": all_domains.into_iter().collect::<Vec<_>>(),
        "urls": all_urls.into_iter().collect::<Vec<_>>(),
        "hashes": all_hashes.into_iter().collect::<Vec<_>>(),
        "count": total,
        "events_processed": events_processed,
        "synced_at": chrono::Utc::now().to_rfc3339(),
    });

    store
        .set_setting("_enrichment", "misp_iocs", &data)
        .await
        .map_err(|e| format!("MISP store: {e}"))?;

    tracing::info!(
        "MISP: Synced {} IoC from {} events",
        total,
        events_processed
    );
    Ok(total)
}

/// Load MISP IoC into a Bloom filter.
pub async fn load_into_bloom(
    store: &dyn crate::db::Database,
    filter: &mut crate::agent::ioc_bloom::BloomFilter,
) {
    if let Ok(Some(data)) = store.get_setting("_enrichment", "misp_iocs").await {
        let mut count = 0usize;
        for key in &["ips", "domains", "urls", "hashes"] {
            if let Some(arr) = data[key].as_array() {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        filter.insert(s);
                        count += 1;
                    }
                }
            }
        }
        if count > 0 {
            tracing::debug!("BLOOM: loaded {} MISP CIRCL IoC", count);
        }
    }
}

/// Check if an IoC is known in the MISP feed cache.
pub async fn is_known_ioc(store: &dyn crate::db::Database, ioc: &str) -> Option<MispIoc> {
    let data = store.get_setting("_enrichment", "misp_iocs").await.ok()??;
    let ioc_lower = ioc.to_lowercase();

    for key in &["ips", "domains", "urls", "hashes"] {
        if let Some(arr) = data[key].as_array() {
            if arr.iter().any(|v| v.as_str() == Some(&ioc_lower)) {
                return Some(MispIoc {
                    ioc_type: key.trim_end_matches('s').to_string(),
                    ioc_value: ioc_lower,
                    event_info: "CIRCL OSINT".into(),
                    threat_level: 2,
                    tags: vec!["misp".into(), "circl-osint".into()],
                });
            }
        }
    }
    None
}
