//! JA3 fingerprint threat detection.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use super::ioc_bloom::IOC_BLOOM;

/// Known-bad JA3 hashes from public threat intel feeds.
/// Source: abuse.ch ja3 fingerprint list, Salesforce JA3 repo, SSLBL.
const KNOWN_BAD_JA3: &[(&str, &str)] = &[
    // Cobalt Strike default
    ("72a589da586844d7f0818ce684948eea", "Cobalt Strike"),
    ("a0e9f5d64349fb13191bc781f81f42e1", "Cobalt Strike"),
    // Metasploit Meterpreter
    ("5d65ea3fb1d4aa7d499be5aee94bab18", "Meterpreter"),
    // Trickbot
    ("6734f37431670b3ab4292b8f60f29984", "Trickbot"),
    ("e7d705a3286e19ea42f587b344ee6865", "Trickbot"),
    // IcedID
    ("c12f54a3f91dc7bafd92c258f2ae4263", "IcedID"),
    // Emotet
    ("4d7a28d6f2263ed61de88ca66eb2e914", "Emotet"),
    // AsyncRAT
    ("fc54e0d16d9764783542f0146a98b300", "AsyncRAT"),
    // Sliver C2
    ("cd62b7694e27dc8a7ee20cfbdf5e8c80", "Sliver C2"),
    // Brute Ratel
    ("2bab4e0c372e3ef0a8572b2c94890b70", "Brute Ratel"),
    // Havoc C2
    ("1d095e012eb43fc25cdb4bfbab282f6a", "Havoc C2"),
    // Generic suspicious (empty cipher suite / unusual)
    ("e7071aba632a5b5bfb59bbfa1f5d21e2", "Empty TLS Client"),
];

/// Result of a JA3 scan cycle.
#[derive(Debug)]
pub struct Ja3ScanResult {
    pub logs_checked: usize,
    pub matches_found: usize,
    pub findings_created: usize,
}

/// Load known-bad JA3 hashes into the global Bloom filter.
/// Called during `build_from_feeds()` and on manual refresh.
pub async fn load_ja3_into_bloom(store: &dyn Database, bloom: &mut super::ioc_bloom::BloomFilter) {
    let mut count = 0usize;

    // 1. Built-in known-bad JA3 hashes
    for (hash, _label) in KNOWN_BAD_JA3 {
        bloom.insert(hash);
        count += 1;
    }

    // 2. User-configured JA3 hashes from DB (RSSI can add custom ones)
    if let Ok(Some(data)) = store.get_setting("_enrichment", "ja3_blacklist").await {
        if let Some(hashes) = data["hashes"].as_array() {
            for h in hashes {
                if let Some(s) = h.as_str() { bloom.insert(s); count += 1; }
            }
        }
    }

    // 3. abuse.ch SSLBL JA3 feed (if synced)
    if let Ok(Some(data)) = store.get_setting("_enrichment", "sslbl_ja3").await {
        if let Some(entries) = data["entries"].as_array() {
            for entry in entries {
                if let Some(hash) = entry["ja3_digest"].as_str() {
                    bloom.insert(hash);
                    count += 1;
                }
            }
        }
    }

    if count > 0 {
        tracing::debug!("BLOOM: loaded {} JA3 fingerprints", count);
    }
}

/// Scan recent Zeek ssl.log entries for malicious JA3 fingerprints.
/// Runs every IE cycle (5 min). Checks the Bloom filter first (fast),
/// then verifies matches against the known-bad list (eliminates FP).
pub async fn scan_ja3(
    store: std::sync::Arc<dyn Database>,
    minutes_back: i64,
) -> Ja3ScanResult {
    let mut result = Ja3ScanResult { logs_checked: 0, matches_found: 0, findings_created: 0 };

    // Query recent Zeek SSL logs
    let logs = store.query_logs(minutes_back, None, Some("zeek.ssl"), 2000).await.unwrap_or_default();
    result.logs_checked = logs.len();

    if logs.is_empty() { return result; }

    let bloom = IOC_BLOOM.read().await;

    for log in &logs {
        // Zeek ssl.log stores JA3 in the "ja3" field
        let ja3 = log.data["ja3"].as_str().unwrap_or("");
        if ja3.is_empty() || ja3.len() != 32 { continue; } // JA3 is always 32 hex chars (MD5)

        let ja3_lower = ja3.to_lowercase();

        // Fast Bloom filter check (~200ns)
        if !bloom.maybe_contains(&ja3_lower) { continue; }

        // Bloom says maybe — verify against known-bad list (eliminates false positives)
        let label = match identify_ja3(&ja3_lower, store.as_ref()).await {
            Some(l) => l,
            None => continue, // False positive from Bloom filter
        };

        result.matches_found += 1;

        let src_ip = log.data["id.orig_h"].as_str().unwrap_or("unknown");
        let dst_ip = log.data["id.resp_h"].as_str().unwrap_or("unknown");
        let dst_port = log.data["id.resp_p"].as_u64().unwrap_or(0);
        let server_name = log.data["server_name"].as_str().unwrap_or("unknown");
        let hostname = log.hostname.as_deref().unwrap_or("unknown");

        let title = format!("JA3 malveillant détecté: {} ({})", label, ja3_lower);
        let description = format!(
            "Fingerprint TLS client JA3 associé à {} détecté.\n\
             Source: {} → {}:{} (SNI: {})\n\
             JA3: {}\n\
             Ce fingerprint est connu pour être utilisé par des outils d'attaque.",
            label, src_ip, dst_ip, dst_port, server_name, ja3_lower
        );

        let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
            skill_id: "ndr-ja3".into(),
            title,
            description: Some(description),
            severity: "CRITICAL".into(),
            category: Some("c2-detection".into()),
            asset: Some(hostname.to_string()),
            source: Some("JA3 Bloom filter".into()),
            metadata: Some(serde_json::json!({
                "ja3": ja3_lower,
                "malware_family": label,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "server_name": server_name,
                "detection": "ja3-bloom-filter",
                "mitre": ["T1071.001"]  // Application Layer Protocol: Web
            })),
        }).await;
        result.findings_created += 1;

        tracing::warn!(
            "NDR-JA3: {} detected! {} → {}:{} (JA3: {})",
            label, src_ip, dst_ip, dst_port, &ja3_lower[..12]
        );
    }

    if result.matches_found > 0 {
        tracing::info!(
            "NDR-JA3: {} logs checked, {} JA3 matches, {} findings",
            result.logs_checked, result.matches_found, result.findings_created
        );
    }

    result
}

/// Identify a JA3 hash — check built-in list, then DB custom list.
async fn identify_ja3(ja3: &str, store: &dyn Database) -> Option<String> {
    // Check built-in list first (no DB call)
    for (hash, label) in KNOWN_BAD_JA3 {
        if *hash == ja3 { return Some(label.to_string()); }
    }

    // Check user-configured blacklist
    if let Ok(Some(data)) = store.get_setting("_enrichment", "ja3_blacklist").await {
        if let Some(hashes) = data["hashes"].as_array() {
            if hashes.iter().any(|h| h.as_str() == Some(ja3)) {
                return Some("Custom JA3 blacklist".into());
            }
        }
    }

    // Check SSLBL feed
    if let Ok(Some(data)) = store.get_setting("_enrichment", "sslbl_ja3").await {
        if let Some(entries) = data["entries"].as_array() {
            for entry in entries {
                if entry["ja3_digest"].as_str() == Some(ja3) {
                    let label = entry["listing_reason"].as_str().unwrap_or("SSLBL match");
                    return Some(label.to_string());
                }
            }
        }
    }

    None
}
