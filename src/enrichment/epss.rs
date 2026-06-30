//! EPSS (Exploit Prediction Scoring System) — FIRST.org
//!
//! Predicts the probability a CVE will be exploited in the next 30 days.
//! Free API, no key required. Updated daily.
//! https://api.first.org/data/v1/epss

use crate::db::threatclaw_store::EpssRow;
use serde::{Deserialize, Serialize};

const API_URL: &str = "https://api.first.org/data/v1/epss";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssScore {
    pub cve_id: String,
    pub epss: f64,       // 0.0 - 1.0 probability of exploitation in 30 days
    pub percentile: f64, // 0.0 - 1.0 rank among all CVEs
    pub date: String,
}

/// Lookup EPSS score for a CVE. Free, no API key.
pub async fn lookup_epss(cve_id: &str) -> Result<Option<EpssScore>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let resp = client
        .get(API_URL)
        .query(&[("cve", cve_id)])
        .send()
        .await
        .map_err(|e| format!("EPSS: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("EPSS HTTP {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON: {e}"))?;

    let entry = data["data"].as_array().and_then(|a| a.first());
    match entry {
        Some(e) => Ok(Some(EpssScore {
            cve_id: e["cve"].as_str().unwrap_or(cve_id).into(),
            epss: e["epss"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0),
            percentile: e["percentile"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0),
            date: e["date"].as_str().unwrap_or("").into(),
        })),
        None => Ok(None),
    }
}

/// Lookup EPSS for a CVE. Reads, in order: the local bulk mirror (V102
/// `epss_scores`, kept fresh by the hub-R2 `epss` pack — no network), then the
/// per-CVE settings cache (today's value), then the live FIRST API as a fallback
/// for a brand-new CVE not yet in the dump.
pub async fn lookup_epss_cached(
    cve_id: &str,
    store: &dyn crate::db::Database,
) -> Result<Option<EpssScore>, String> {
    // 1. Local bulk mirror — present for the ~280k CVEs in the FIRST dump.
    if let Ok(Some((epss, percentile, date))) = store.get_epss(cve_id).await {
        return Ok(Some(EpssScore {
            cve_id: cve_id.to_string(),
            epss,
            percentile,
            date,
        }));
    }

    // 2. Per-CVE settings cache (today's value).
    if let Ok(Some(cached)) = store.get_setting("_epss", cve_id).await {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        if cached["date"].as_str() == Some(today.as_str()) {
            return Ok(serde_json::from_value(cached).ok());
        }
    }

    // 3. Live FIRST API fallback (brand-new CVE not yet in the dump).
    let result = lookup_epss(cve_id).await?;

    // Cache
    if let Some(ref score) = result {
        let _ = store
            .set_setting(
                "_epss",
                cve_id,
                &serde_json::to_value(score).unwrap_or_default(),
            )
            .await;
    }

    Ok(result)
}

/// Parse an `epss` R2 pack into `(score_date, rows)`. The pack is FIRST's daily
/// `epss_scores-<date>.csv` (optionally gzipped): a `#...,score_date:<ts>,...`
/// comment line, a `cve,epss,percentile` header, then data rows. Pure.
pub fn parse_epss_pack(bytes: &[u8]) -> Result<(String, Vec<EpssRow>), String> {
    let raw = maybe_gunzip(bytes)?;
    let text = String::from_utf8_lossy(&raw);
    let mut date = String::new();
    let mut rows = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(meta) = line.strip_prefix('#') {
            // e.g. "model_version:v2026.03.01,score_date:2026-06-30T00:00:00+0000"
            if let Some(d) = meta
                .split(',')
                .find_map(|kv| kv.trim().strip_prefix("score_date:"))
            {
                date = d.split('T').next().unwrap_or(d).trim().to_string();
            }
            continue;
        }
        if line.starts_with("cve,") {
            continue; // column header
        }
        let mut cols = line.split(',');
        let (Some(cve), Some(epss), Some(pct)) = (cols.next(), cols.next(), cols.next()) else {
            continue;
        };
        let cve = cve.trim();
        if !cve.starts_with("CVE-") {
            continue;
        }
        let (Ok(epss), Ok(percentile)) =
            (epss.trim().parse::<f64>(), pct.trim().parse::<f64>())
        else {
            continue;
        };
        rows.push(EpssRow {
            cve: cve.to_string(),
            epss,
            percentile,
            score_date: String::new(), // filled below once the date is known
        });
    }

    if date.is_empty() {
        date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    }
    for r in &mut rows {
        r.score_date = date.clone();
    }
    if rows.is_empty() {
        return Err("EPSS pack: no rows parsed".to_string());
    }
    Ok((date, rows))
}

/// Load an `epss` R2 pack into the local bulk mirror (`epss_scores`) so EPSS
/// lookups are offline-safe. Returns the number of rows written.
pub async fn load_epss_from_pack(
    store: &dyn crate::db::Database,
    bytes: &[u8],
) -> Result<usize, String> {
    let (_date, rows) = parse_epss_pack(bytes)?;
    let n = store
        .bulk_upsert_epss(&rows)
        .await
        .map_err(|e| format!("EPSS bulk upsert: {e}"))?;
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
            .map_err(|e| format!("EPSS pack gunzip: {e}"))?;
        Ok(out)
    } else {
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "#model_version:v2026.03.01,score_date:2026-06-30T00:00:00+0000\n\
        cve,epss,percentile\n\
        CVE-2021-44228,0.94567,0.99000\n\
        CVE-2023-0001,0.00123,0.41000\n\
        garbage-line\n";

    #[test]
    fn parse_epss_pack_reads_date_and_rows() {
        let (date, rows) = parse_epss_pack(SAMPLE.as_bytes()).unwrap();
        assert_eq!(date, "2026-06-30");
        assert_eq!(rows.len(), 2, "header/comment/garbage dropped");
        assert_eq!(rows[0].cve, "CVE-2021-44228");
        assert!((rows[0].epss - 0.94567).abs() < 1e-6);
        assert_eq!(rows[0].score_date, "2026-06-30");
    }

    #[test]
    fn parse_epss_pack_handles_gzip() {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(SAMPLE.as_bytes()).unwrap();
        let gz = e.finish().unwrap();
        assert_eq!(&gz[0..2], &[0x1f, 0x8b]);
        let (_d, rows) = parse_epss_pack(&gz).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn parse_epss_pack_errors_on_empty() {
        assert!(parse_epss_pack(b"#score_date:2026-06-30\ncve,epss,percentile\n").is_err());
    }
}
