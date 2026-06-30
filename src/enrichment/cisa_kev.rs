//! CISA KEV — Known Exploited Vulnerabilities catalog.
//!
//! The most impactful enrichment source: if a CVE is in the KEV,
//! it's actively exploited in the wild and should be treated as CRITICAL
//! regardless of its CVSS score.
//!
//! Sync: daily from https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//! Storage: settings DB under "_kev" namespace
//! No API key required.

use serde::{Deserialize, Serialize};

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub date_added: String,
    pub due_date: String,
    pub required_action: String,
}

/// Sync KEV catalog from CISA. Returns number of entries synced.
pub async fn sync_kev(store: &dyn crate::db::Database) -> Result<usize, String> {
    tracing::info!("CISA KEV: Starting sync...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let resp = client
        .get(KEV_URL)
        .send()
        .await
        .map_err(|e| format!("KEV download: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("KEV returned {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("KEV JSON: {e}"))?;
    let vulns = data["vulnerabilities"]
        .as_array()
        .ok_or("No vulnerabilities array")?;

    let count = load_kev_vulnerabilities(store, vulns).await?;
    tracing::info!("CISA KEV: Synced {count} entries");
    Ok(count)
}

/// Write a list of CISA KEV `vulnerabilities` entries into the store: the
/// per-CVE settings cache (`_kev`), the first-observation metric
/// (`record_kev_observation`), and the sync meta. Shared by the live
/// [`sync_kev`] and the R2 `kev` pack installer ([`load_kev_from_pack`]) so both
/// paths land identical data. Returns the number of entries written.
pub async fn load_kev_vulnerabilities(
    store: &dyn crate::db::Database,
    vulns: &[serde_json::Value],
) -> Result<usize, String> {
    let mut count = 0;
    for vuln in vulns {
        let cve_id = vuln["cveID"].as_str().unwrap_or("").to_string();
        if cve_id.is_empty() {
            continue;
        }

        let date_added_str = vuln["dateAdded"].as_str().unwrap_or("");
        let entry = serde_json::json!({
            "cve_id": cve_id,
            "vendor": vuln["vendorProject"].as_str().unwrap_or(""),
            "product": vuln["product"].as_str().unwrap_or(""),
            "name": vuln["vulnerabilityName"].as_str().unwrap_or(""),
            "date_added": date_added_str,
            "due_date": vuln["dueDate"].as_str().unwrap_or(""),
            "required_action": vuln["requiredAction"].as_str().unwrap_or(""),
        });

        let _ = store.set_setting("_kev", &cve_id, &entry).await;

        // See ADR (roadmap §3.5): first-time observations only.
        let kev_published_at = parse_kev_date(date_added_str);
        if let Ok(true) = store
            .record_kev_observation(&cve_id, kev_published_at)
            .await
        {
            tracing::debug!("CISA KEV: new observation {cve_id}");
        }
        count += 1;
    }

    let _ = store
        .set_setting(
            "_system",
            "kev_sync_meta",
            &serde_json::json!({
                "last_sync": chrono::Utc::now().to_rfc3339(),
                "count": count,
            }),
        )
        .await;

    Ok(count)
}

/// Parse a `kev` R2 pack into the CISA `vulnerabilities` entries. The pack is the
/// CISA `known_exploited_vulnerabilities.json`, optionally gzip-compressed (the
/// builder gzips it; raw JSON is also accepted). Pure — no store writes.
pub fn parse_kev_pack(bytes: &[u8]) -> Result<Vec<serde_json::Value>, String> {
    let json_bytes = maybe_gunzip(bytes)?;
    let data: serde_json::Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("KEV pack JSON: {e}"))?;
    let vulns = data["vulnerabilities"]
        .as_array()
        .ok_or("KEV pack: no vulnerabilities array")?;
    Ok(vulns.clone())
}

/// Load a `kev` R2 pack into the same store destinations as a live sync — used by
/// the multi-pack updater so a premium agent gets KEV from R2 instead of CISA.
pub async fn load_kev_from_pack(
    store: &dyn crate::db::Database,
    bytes: &[u8],
) -> Result<usize, String> {
    let vulns = parse_kev_pack(bytes)?;
    load_kev_vulnerabilities(store, &vulns).await
}

/// Gunzip `bytes` when they carry the gzip magic (`1f 8b`); otherwise return
/// them as-is. Lets a pack be served compressed or raw.
fn maybe_gunzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        use std::io::Read;
        let mut dec = flate2::read::GzDecoder::new(bytes);
        let mut out = Vec::new();
        dec.read_to_end(&mut out).map_err(|e| format!("KEV pack gunzip: {e}"))?;
        Ok(out)
    } else {
        Ok(bytes.to_vec())
    }
}

/// Check if a CVE is in the KEV (actively exploited).
pub async fn is_exploited(store: &dyn crate::db::Database, cve_id: &str) -> Option<KevEntry> {
    let val = store.get_setting("_kev", cve_id).await.ok()??;
    serde_json::from_value(val).ok()
}

/// Parse a CISA KEV `dateAdded` field (YYYY-MM-DD) into a UTC timestamp
/// anchored at 00:00:00 for metric math.
fn parse_kev_date(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let naive = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    let dt = naive.and_hms_opt(0, 0, 0)?;
    Some(chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
        dt,
        chrono::Utc,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kev_date_valid() {
        let d = parse_kev_date("2025-03-14").unwrap();
        assert_eq!(d.format("%Y-%m-%d").to_string(), "2025-03-14");
    }

    #[test]
    fn parse_kev_date_invalid() {
        assert!(parse_kev_date("2025/03/14").is_none());
        assert!(parse_kev_date("").is_none());
        assert!(parse_kev_date("bad").is_none());
    }

    const SAMPLE: &str = r#"{"title":"CISA KEV","vulnerabilities":[
        {"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j",
         "vulnerabilityName":"Log4Shell","dateAdded":"2021-12-10","dueDate":"2021-12-24",
         "requiredAction":"Patch"},
        {"cveID":"CVE-2023-0001","vendorProject":"X","product":"Y",
         "vulnerabilityName":"Z","dateAdded":"2023-01-01","dueDate":"2023-01-15",
         "requiredAction":"Update"}
    ]}"#;

    fn gzip(s: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(s).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn parse_kev_pack_reads_raw_json() {
        let vulns = parse_kev_pack(SAMPLE.as_bytes()).unwrap();
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0]["cveID"], "CVE-2021-44228");
    }

    #[test]
    fn parse_kev_pack_reads_gzipped_json() {
        // The builder gzips the CISA feed; the installer must transparently gunzip.
        let gz = gzip(SAMPLE.as_bytes());
        assert_eq!(&gz[0..2], &[0x1f, 0x8b], "fixture must carry gzip magic");
        let vulns = parse_kev_pack(&gz).unwrap();
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[1]["cveID"], "CVE-2023-0001");
    }

    #[test]
    fn parse_kev_pack_rejects_garbage_and_missing_array() {
        assert!(parse_kev_pack(b"not json").is_err());
        assert!(parse_kev_pack(br#"{"title":"x"}"#).is_err());
    }
}
