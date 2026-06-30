//! Real-time IoC detection in logs. See ADR-001.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, LazyLock};
use tokio::sync::RwLock;

use crate::enrichment::ioc_extractor;

// ── Global Bloom filter (shared across async tasks) ──

pub static IOC_BLOOM: LazyLock<Arc<RwLock<BloomFilter>>> =
    LazyLock::new(|| Arc::new(RwLock::new(BloomFilter::empty())));

// ── Bloom filter implementation ──

pub struct BloomFilter {
    bits: Vec<u64>,    // packed bits for memory efficiency
    bit_count: usize,  // total number of bits
    hash_count: usize, // number of hash functions
    ioc_count: usize,  // how many IoC were inserted
}

impl BloomFilter {
    /// Create an empty filter (placeholder before init)
    pub fn empty() -> Self {
        Self {
            bits: vec![0; 1],
            bit_count: 64,
            hash_count: 1,
            ioc_count: 0,
        }
    }

    /// Create a filter sized for `expected` items at `fp_rate` false positive rate.
    /// Example: new(500_000, 0.01) → ~585 KB RAM, 7 hash functions
    pub fn new(expected: usize, fp_rate: f64) -> Self {
        let expected = expected.max(100);
        // m = -(n * ln(p)) / (ln(2)^2)
        let m = (-(expected as f64) * fp_rate.ln() / (2.0_f64.ln().powi(2))).ceil() as usize;
        // k = (m/n) * ln(2)
        let k = ((m as f64 / expected as f64) * 2.0_f64.ln()).ceil() as usize;
        let k = k.max(1).min(16); // clamp to reasonable range

        let words = (m + 63) / 64; // pack into u64 words
        Self {
            bits: vec![0u64; words],
            bit_count: words * 64,
            hash_count: k,
            ioc_count: 0,
        }
    }

    /// Compute K bit positions for a value using double hashing
    fn positions(&self, value: &str) -> Vec<usize> {
        // Double hashing: h(i) = (h1 + i * h2) % m
        let mut h1 = DefaultHasher::new();
        value.hash(&mut h1);
        let hash1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        b"bloom_salt".hash(&mut h2);
        value.hash(&mut h2);
        let hash2 = h2.finish();

        (0..self.hash_count)
            .map(|i| (hash1.wrapping_add((i as u64).wrapping_mul(hash2)) as usize) % self.bit_count)
            .collect()
    }

    #[inline]
    fn set_bit(&mut self, pos: usize) {
        self.bits[pos / 64] |= 1u64 << (pos % 64);
    }

    #[inline]
    fn get_bit(&self, pos: usize) -> bool {
        (self.bits[pos / 64] >> (pos % 64)) & 1 == 1
    }

    /// Insert an IoC into the filter
    pub fn insert(&mut self, ioc: &str) {
        let normalized = ioc.trim().to_lowercase();
        if normalized.is_empty() {
            return;
        }
        for pos in self.positions(&normalized) {
            self.set_bit(pos);
        }
        self.ioc_count += 1;
    }

    /// Check if an IoC is PROBABLY in the filter.
    /// false = DEFINITELY NOT in the filter (guaranteed)
    /// true = PROBABLY in the filter (~1% false positive, verify in DB)
    pub fn maybe_contains(&self, ioc: &str) -> bool {
        let normalized = ioc.trim().to_lowercase();
        if normalized.is_empty() {
            return false;
        }
        self.positions(&normalized)
            .iter()
            .all(|&pos| self.get_bit(pos))
    }

    pub fn ioc_count(&self) -> usize {
        self.ioc_count
    }
    pub fn memory_kb(&self) -> usize {
        self.bits.len() * 8 / 1024
    }
}

// ── Feed loading ──

/// Build the Bloom filter from all cached feeds in PostgreSQL.
/// Called at boot and every 6 hours after feed sync.
/// Capacity the IoC Bloom filter is sized for. Combined MISP/ThreatFox/URLhaus/
/// MalwareBazaar/KEV feeds can exceed the old 500k; oversizing keeps the false
/// positive rate near the configured 1% and we warn before saturation (below).
pub const BLOOM_CAPACITY: usize = 2_000_000;

pub async fn build_from_feeds(store: &dyn crate::db::Database) -> BloomFilter {
    let mut filter = BloomFilter::new(BLOOM_CAPACITY, 0.01);

    // OpenPhish URLs
    if let Ok(Some(data)) = store.get_setting("_enrichment", "openphish_urls").await {
        if let Some(urls) = data["urls"].as_array() {
            for u in urls {
                if let Some(s) = u.as_str() {
                    filter.insert(s);
                }
            }
            tracing::debug!("BLOOM: loaded {} OpenPhish URLs", urls.len());
        }
    }

    // ThreatFox IoC (via enrichment cache)
    if let Ok(entries) = store.list_settings("_enrichment_threatfox").await {
        for row in &entries {
            if let Some(ioc) = row.value["ioc_value"].as_str() {
                filter.insert(ioc);
            }
        }
        if !entries.is_empty() {
            tracing::debug!("BLOOM: loaded {} ThreatFox IoC", entries.len());
        }
    }

    // URLhaus
    if let Ok(Some(data)) = store.get_setting("_enrichment", "urlhaus_urls").await {
        if let Some(urls) = data["urls"].as_array() {
            for u in urls {
                if let Some(s) = u.as_str() {
                    filter.insert(s);
                }
            }
            tracing::debug!("BLOOM: loaded {} URLhaus URLs", urls.len());
        }
    }

    // MalwareBazaar hashes
    if let Ok(Some(data)) = store
        .get_setting("_enrichment", "malwarebazaar_hashes")
        .await
    {
        if let Some(hashes) = data["hashes"].as_array() {
            for h in hashes {
                if let Some(s) = h.as_str() {
                    filter.insert(s);
                }
            }
            tracing::debug!("BLOOM: loaded {} MalwareBazaar hashes", hashes.len());
        }
    }

    // MISP CIRCL OSINT
    crate::enrichment::misp_circl::load_into_bloom(store, &mut filter).await;

    // CISA KEV CVE IDs (for cross-reference)
    if let Ok(entries) = store.list_settings("_kev").await {
        for row in &entries {
            if row.key.starts_with("CVE-") {
                filter.insert(&row.key);
            }
        }
        if !entries.is_empty() {
            tracing::debug!("BLOOM: loaded {} KEV CVEs", entries.len());
        }
    }

    // JA3 fingerprints (malicious TLS client identification)
    super::ndr_ja3::load_ja3_into_bloom(store, &mut filter).await;
    // HASSH fingerprints (malicious SSH client identification)
    super::ndr_ja3::load_hassh_into_bloom(store, &mut filter).await;

    // Hub-R2 `ioc` pack — consolidated indicators (abuse.ch/MISP/…) mirrored in
    // the dedicated ioc_indicators table (V103). A Bloom hit is confirmed O(1)
    // via `store.ioc_exists` in verify_in_cache, so this needs no scattered
    // settings keys. Capped at the filter capacity.
    if let Ok(values) = store.ioc_values(BLOOM_CAPACITY as i64).await {
        for v in &values {
            filter.insert(v);
        }
        if !values.is_empty() {
            tracing::debug!("BLOOM: loaded {} pack IoC", values.len());
        }
    }

    tracing::info!(
        "BLOOM: Filter ready — {} IoC, {} KB RAM, ~1% FP rate",
        filter.ioc_count(),
        filter.memory_kb()
    );

    // Warn before the filter saturates — past capacity the false-positive rate
    // climbs and every log line starts triggering a verify_in_cache DB lookup.
    if filter.ioc_count() as f64 > 0.9 * BLOOM_CAPACITY as f64 {
        tracing::warn!(
            "BLOOM: near capacity ({}/{} IoC) — false-positive rate degrading, raise BLOOM_CAPACITY",
            filter.ioc_count(),
            BLOOM_CAPACITY
        );
    }

    filter
}

/// Initialize the global Bloom filter (call at boot)
pub async fn init(store: &dyn crate::db::Database) {
    let filter = build_from_feeds(store).await;
    *IOC_BLOOM.write().await = filter;
}

/// Refresh the global Bloom filter (call after feed sync)
pub async fn refresh(store: &dyn crate::db::Database) {
    let filter = build_from_feeds(store).await;
    let old_count = IOC_BLOOM.read().await.ioc_count();
    *IOC_BLOOM.write().await = filter;
    let new_count = IOC_BLOOM.read().await.ioc_count();
    tracing::info!("BLOOM: Refreshed — {} → {} IoC", old_count, new_count);
}

/// Parse an `ioc` R2 pack (NDJSON, optionally gzipped) into normalized rows.
/// Each line: `{"type":"ip|domain|url|hash","value":"...","source":"..."}`.
/// Values are trimmed + lowercased to match `verify_in_cache`. Pure — no writes.
pub fn parse_ioc_pack(
    bytes: &[u8],
) -> Result<Vec<crate::db::threatclaw_store::IocRow>, String> {
    let raw = maybe_gunzip(bytes)?;
    let text = String::from_utf8_lossy(&raw);
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let (Some(ty), Some(val)) = (v["type"].as_str(), v["value"].as_str()) else {
            continue;
        };
        let value = val.trim().to_lowercase();
        let ioc_type = ty.trim().to_lowercase();
        if value.is_empty() || !matches!(ioc_type.as_str(), "ip" | "domain" | "url" | "hash") {
            continue;
        }
        rows.push(crate::db::threatclaw_store::IocRow {
            value,
            ioc_type,
            source: v["source"].as_str().map(|s| s.to_string()),
        });
    }
    if rows.is_empty() {
        return Err("IOC pack: no rows parsed".to_string());
    }
    Ok(rows)
}

/// Load an `ioc` R2 pack into the dedicated mirror (`ioc_indicators`) and rebuild
/// the Bloom filter so the new indicators match in real time. Returns row count.
pub async fn load_ioc_from_pack(
    store: &dyn crate::db::Database,
    bytes: &[u8],
) -> Result<usize, String> {
    let rows = parse_ioc_pack(bytes)?;
    let n = store
        .bulk_upsert_iocs(&rows)
        .await
        .map_err(|e| format!("IOC bulk upsert: {e}"))?;
    refresh(store).await;
    Ok(n as usize)
}

/// Gunzip `bytes` when they carry the gzip magic (`1f 8b`); otherwise return
/// them as-is. Lets a pack be served compressed or raw.
fn maybe_gunzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        use std::io::Read;
        let mut dec = flate2::read::GzDecoder::new(bytes);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .map_err(|e| format!("IOC pack gunzip: {e}"))?;
        Ok(out)
    } else {
        Ok(bytes.to_vec())
    }
}

// ── Real-time log checking ──

/// Check a log's JSONB data for IoC matches via Bloom filter.
/// Returns detected threats (confirmed after DB verification).
pub async fn check_log(
    log_data: &serde_json::Value,
    hostname: Option<&str>,
    store: &dyn crate::db::Database,
) -> Vec<DetectedIoc> {
    let iocs = ioc_extractor::extract_from_json(log_data);

    let filter = IOC_BLOOM.read().await;
    let mut detected = Vec::new();

    // Check all extracted IoC against Bloom filter
    for ip in &iocs.ips {
        if filter.maybe_contains(ip) {
            if verify_in_cache(store, ip, "ip").await {
                detected.push(DetectedIoc {
                    ioc_type: "ip".into(),
                    ioc_value: ip.clone(),
                    source: "threatfox".into(),
                    severity: "HIGH".into(),
                    hostname: hostname.map(String::from),
                });
            }
        }
    }

    for url in &iocs.urls {
        if filter.maybe_contains(url) {
            if verify_in_cache(store, url, "url").await {
                detected.push(DetectedIoc {
                    ioc_type: "url".into(),
                    ioc_value: url.clone(),
                    source: "openphish/urlhaus".into(),
                    severity: "HIGH".into(),
                    hostname: hostname.map(String::from),
                });
            }
        }
    }

    for hash in &iocs.hashes {
        if filter.maybe_contains(hash) {
            if verify_in_cache(store, hash, "hash").await {
                detected.push(DetectedIoc {
                    ioc_type: "hash".into(),
                    ioc_value: hash.clone(),
                    source: "malwarebazaar".into(),
                    severity: "CRITICAL".into(),
                    hostname: hostname.map(String::from),
                });
            }
        }
    }

    for domain in &iocs.domains {
        if filter.maybe_contains(domain) {
            if verify_in_cache(store, domain, "domain").await {
                detected.push(DetectedIoc {
                    ioc_type: "domain".into(),
                    ioc_value: domain.clone(),
                    source: "threatfox".into(),
                    severity: "HIGH".into(),
                    hostname: hostname.map(String::from),
                });
            }
        }
    }

    detected
}

/// Verify a Bloom match against the actual cached data in PostgreSQL.
/// Eliminates false positives.
async fn verify_in_cache(store: &dyn crate::db::Database, ioc: &str, ioc_type: &str) -> bool {
    let ioc_lower = ioc.to_lowercase();

    // Hub-R2 `ioc` pack mirror (V103) — O(1) PK lookup, confirms a Bloom hit for
    // any indicator type before falling through to the per-feed caches.
    if store.ioc_exists(&ioc_lower).await.unwrap_or(false) {
        return true;
    }

    match ioc_type {
        "ip" => {
            // Check ThreatFox cache
            if let Ok(Some(cached)) = store.get_enrichment_cache("threatfox", &ioc_lower).await {
                return cached.get("threat_type").is_some();
            }
            // Check enrichment settings
            if let Ok(Some(data)) = store.get_setting("_enrichment_threatfox", &ioc_lower).await {
                return data.get("ioc_value").is_some();
            }
        }
        "url" => {
            // Check OpenPhish
            if let Ok(Some(data)) = store.get_setting("_enrichment", "openphish_urls").await {
                if let Some(urls) = data["urls"].as_array() {
                    if urls.iter().any(|u| u.as_str() == Some(&ioc_lower)) {
                        return true;
                    }
                }
            }
            // Check URLhaus cache
            if let Ok(Some(_)) = store.get_enrichment_cache("urlhaus", &ioc_lower).await {
                return true;
            }
        }
        "hash" => {
            // Check MalwareBazaar
            if let Ok(Some(data)) = store
                .get_setting("_enrichment", "malwarebazaar_hashes")
                .await
            {
                if let Some(hashes) = data["hashes"].as_array() {
                    if hashes.iter().any(|h| h.as_str() == Some(&ioc_lower)) {
                        return true;
                    }
                }
            }
        }
        "domain" => {
            // Check OpenPhish (domains extracted from URLs)
            if let Ok(Some(data)) = store.get_setting("_enrichment", "openphish_urls").await {
                if let Some(urls) = data["urls"].as_array() {
                    if urls
                        .iter()
                        .any(|u| u.as_str().map(|s| s.contains(&ioc_lower)).unwrap_or(false))
                    {
                        return true;
                    }
                }
            }
        }
        _ => {}
    }

    false
}

// ── Types ──

#[derive(Debug, Clone)]
pub struct DetectedIoc {
    pub ioc_type: String,
    pub ioc_value: String,
    pub source: String,
    pub severity: String,
    pub hostname: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "{\"type\":\"ip\",\"value\":\"1.2.3.4\",\"source\":\"feodo\"}\n\
        {\"type\":\"URL\",\"value\":\"HTTP://Bad.Example/x\",\"source\":\"urlhaus\"}\n\
        {\"type\":\"hash\",\"value\":\"abc123\"}\n\
        {\"type\":\"bogus\",\"value\":\"skip-me\"}\n\
        not-json\n";

    #[test]
    fn parse_ioc_pack_normalizes_and_filters() {
        let rows = parse_ioc_pack(SAMPLE.as_bytes()).unwrap();
        // bogus type + non-json dropped → 3 valid rows
        assert_eq!(rows.len(), 3);
        // lowercased value + type
        assert_eq!(rows[1].ioc_type, "url");
        assert_eq!(rows[1].value, "http://bad.example/x");
        assert_eq!(rows[0].source.as_deref(), Some("feodo"));
        assert_eq!(rows[2].source, None);
    }

    #[test]
    fn parse_ioc_pack_handles_gzip_and_empty() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(SAMPLE.as_bytes()).unwrap();
        let gz = e.finish().unwrap();
        assert_eq!(parse_ioc_pack(&gz).unwrap().len(), 3);
        assert!(parse_ioc_pack(b"not-json\n").is_err());
    }
}
