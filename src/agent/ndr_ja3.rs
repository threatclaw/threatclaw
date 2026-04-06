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

/// Known-bad HASSH fingerprints — SSH clients used by attack tools.
/// Source: Salesforce HASSH project, threat intel research.
const KNOWN_BAD_HASSH: &[(&str, &str)] = &[
    // Paramiko (Python) — automated SSH attacks, lateral movement
    ("b5752e36ba6c5979a575e43178908adf", "Paramiko"),
    // PowerShell Renci.SshNet — Empire, PowerShell-based lateral movement
    ("de30354b88bae4c2810426614e1b6976", "PowerShell SSH (Renci.SshNet)"),
    // Ruby Net::SSH — Metasploit SSH modules
    ("fafc45381bfde997b6305c4e1600f1bf", "Ruby Net::SSH (Metasploit)"),
    // Dropbear — IoT botnets (Mirai variants), embedded attack tools
    ("16f898dd8ed8279e1055350b4e20666c", "Dropbear SSH"),
    // libssh — automated scanners, some C2 frameworks
    ("ec7378c1a92f5a8dde7e8b7a1ddf33d1", "libssh"),
    // Go x/crypto/ssh — custom Go-based attack tools (Sliver, custom C2)
    ("2307c2e5e3a66a482f4ab3d4d154f6b8", "Go SSH client"),
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

    // 4. User-configured JA4 hashes from DB
    if let Ok(Some(data)) = store.get_setting("_enrichment", "ja4_blacklist").await {
        if let Some(entries) = data["entries"].as_array() {
            for entry in entries {
                if let Some(ja4) = entry["ja4"].as_str() { bloom.insert(ja4); count += 1; }
            }
        }
    }

    if count > 0 {
        tracing::debug!("BLOOM: loaded {} JA3 fingerprints", count);
    }
}

/// Load known-bad HASSH fingerprints into the global Bloom filter.
/// Called during `build_from_feeds()`.
pub async fn load_hassh_into_bloom(store: &dyn Database, bloom: &mut super::ioc_bloom::BloomFilter) {
    let mut count = 0usize;

    // 1. Built-in known-bad HASSH hashes
    for (hash, _label) in KNOWN_BAD_HASSH {
        bloom.insert(hash);
        count += 1;
    }

    // 2. User-configured HASSH hashes from DB
    if let Ok(Some(data)) = store.get_setting("_enrichment", "hassh_blacklist").await {
        if let Some(hashes) = data["hashes"].as_array() {
            for h in hashes {
                if let Some(s) = h.as_str() { bloom.insert(s); count += 1; }
            }
        }
    }

    if count > 0 {
        tracing::debug!("BLOOM: loaded {} HASSH fingerprints", count);
    }
}

/// Scan recent Zeek logs for malicious TLS (JA3/JA4) and SSH (HASSH) fingerprints.
/// Runs every IE cycle (5 min). Checks the Bloom filter first (fast),
/// then verifies matches against the known-bad list (eliminates FP).
pub async fn scan_ja3(
    store: std::sync::Arc<dyn Database>,
    minutes_back: i64,
) -> Ja3ScanResult {
    let mut result = Ja3ScanResult { logs_checked: 0, matches_found: 0, findings_created: 0 };

    let bloom = IOC_BLOOM.read().await;

    // ── 1. Scan JA3 + JA4 in Zeek SSL logs ──
    let ssl_logs = store.query_logs(minutes_back, None, Some("zeek.ssl"), 2000).await.unwrap_or_default();
    result.logs_checked += ssl_logs.len();

    for log in &ssl_logs {
        let hostname = log.hostname.as_deref().unwrap_or("unknown");
        let src_ip = log.data["id.orig_h"].as_str().unwrap_or("unknown");
        let dst_ip = log.data["id.resp_h"].as_str().unwrap_or("unknown");
        let dst_port = log.data["id.resp_p"].as_u64().unwrap_or(0);
        let server_name = log.data["server_name"].as_str().unwrap_or("unknown");

        // Check JA3 (32 hex chars = MD5)
        let ja3 = log.data["ja3"].as_str().unwrap_or("");
        if ja3.len() == 32 {
            let ja3_lower = ja3.to_lowercase();
            if bloom.maybe_contains(&ja3_lower) {
                if let Some(label) = identify_ja3(&ja3_lower, store.as_ref()).await {
                    result.matches_found += 1;
                    let title = format!("JA3 malveillant détecté: {} ({})", label, ja3_lower);
                    let description = format!(
                        "Fingerprint TLS client JA3 associé à {} détecté.\n\
                         Source: {} → {}:{} (SNI: {})\nJA3: {}",
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
                            "ja3": ja3_lower, "malware_family": label,
                            "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
                            "server_name": server_name,
                            "detection": "ja3-bloom-filter",
                            "mitre": ["T1071.001"]
                        })),
                    }).await;
                    result.findings_created += 1;
                    tracing::warn!(
                        "NDR-JA3: {} detected! {} → {}:{}",
                        label, src_ip, dst_ip, dst_port
                    );
                }
            }
        }

        // Check JA4 (format: t13d1516h2_xxxxxxxxxxxx_xxxxxxxxxxxx)
        let ja4 = log.data["ja4"].as_str().unwrap_or("");
        if !ja4.is_empty() && ja4.contains('_') {
            let ja4_lower = ja4.to_lowercase();
            if bloom.maybe_contains(&ja4_lower) {
                if let Some(label) = identify_ja4(&ja4_lower, store.as_ref()).await {
                    result.matches_found += 1;
                    let title = format!("JA4 malveillant détecté: {} ({})", label, &ja4_lower);
                    let description = format!(
                        "Fingerprint TLS client JA4 associé à {} détecté.\n\
                         Source: {} → {}:{} (SNI: {})\nJA4: {}",
                        label, src_ip, dst_ip, dst_port, server_name, ja4_lower
                    );
                    let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
                        skill_id: "ndr-ja4".into(),
                        title,
                        description: Some(description),
                        severity: "CRITICAL".into(),
                        category: Some("c2-detection".into()),
                        asset: Some(hostname.to_string()),
                        source: Some("JA4 Bloom filter".into()),
                        metadata: Some(serde_json::json!({
                            "ja4": ja4_lower, "malware_family": label,
                            "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
                            "server_name": server_name,
                            "detection": "ja4-bloom-filter",
                            "mitre": ["T1071.001"]
                        })),
                    }).await;
                    result.findings_created += 1;
                    tracing::warn!(
                        "NDR-JA4: {} detected! {} → {}:{}",
                        label, src_ip, dst_ip, dst_port
                    );
                }
            }
        }
    }

    // ── 2. Scan HASSH in Zeek SSH logs ──
    let ssh_logs = store.query_logs(minutes_back, None, Some("zeek.ssh"), 2000).await.unwrap_or_default();
    result.logs_checked += ssh_logs.len();

    for log in &ssh_logs {
        let hassh = log.data["hassh"].as_str().unwrap_or("");
        if hassh.len() != 32 { continue; } // HASSH is MD5 = 32 hex chars

        let hassh_lower = hassh.to_lowercase();
        if !bloom.maybe_contains(&hassh_lower) { continue; }

        if let Some(label) = identify_hassh(&hassh_lower, store.as_ref()).await {
            result.matches_found += 1;
            let hostname = log.hostname.as_deref().unwrap_or("unknown");
            let src_ip = log.data["id.orig_h"].as_str().unwrap_or("unknown");
            let dst_ip = log.data["id.resp_h"].as_str().unwrap_or("unknown");
            let dst_port = log.data["id.resp_p"].as_u64().unwrap_or(22);

            let title = format!("HASSH malveillant détecté: {} ({})", label, &hassh_lower[..12]);
            let description = format!(
                "Client SSH utilisant {} détecté via fingerprint HASSH.\n\
                 Source: {} → {}:{}\nHASSH: {}\n\
                 Ce client SSH est associé à des outils d'attaque.",
                label, src_ip, dst_ip, dst_port, hassh_lower
            );
            let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
                skill_id: "ndr-hassh".into(),
                title,
                description: Some(description),
                severity: "HIGH".into(),
                category: Some("c2-detection".into()),
                asset: Some(hostname.to_string()),
                source: Some("HASSH Bloom filter".into()),
                metadata: Some(serde_json::json!({
                    "hassh": hassh_lower, "tool": label,
                    "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
                    "detection": "hassh-bloom-filter",
                    "mitre": ["T1021.004"]
                })),
            }).await;
            result.findings_created += 1;
            tracing::warn!(
                "NDR-HASSH: {} detected! {} → {}:{}",
                label, src_ip, dst_ip, dst_port
            );
        }
    }

    if result.matches_found > 0 {
        tracing::info!(
            "NDR-FINGERPRINT: {} logs checked, {} matches, {} findings",
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

/// Identify a JA4 hash — check user-configured blacklist.
async fn identify_ja4(ja4: &str, store: &dyn Database) -> Option<String> {
    if let Ok(Some(data)) = store.get_setting("_enrichment", "ja4_blacklist").await {
        if let Some(entries) = data["entries"].as_array() {
            for entry in entries {
                if entry["ja4"].as_str() == Some(ja4) {
                    return Some(entry["label"].as_str().unwrap_or("Custom JA4 blacklist").to_string());
                }
            }
        }
    }
    None
}

/// Identify a HASSH hash — check built-in list, then DB custom list.
async fn identify_hassh(hassh: &str, store: &dyn Database) -> Option<String> {
    // Check built-in list first
    for (hash, label) in KNOWN_BAD_HASSH {
        if *hash == hassh { return Some(label.to_string()); }
    }

    // Check user-configured blacklist
    if let Ok(Some(data)) = store.get_setting("_enrichment", "hassh_blacklist").await {
        if let Some(hashes) = data["hashes"].as_array() {
            if hashes.iter().any(|h| h.as_str() == Some(hassh)) {
                return Some("Custom HASSH blacklist".into());
            }
        }
    }

    None
}
