//! MITRE ATT&CK enrichment — sync techniques from STIX JSON.
//!
//! Downloads the Enterprise ATT&CK STIX bundle from GitHub (monthly sync).
//! Stores techniques in PostgreSQL for fast lookup during ReAct analysis.

use serde::{Deserialize, Serialize};

const ATTACK_STIX_URL: &str =
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

/// A MITRE ATT&CK technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub technique_id: String,
    pub name: String,
    pub description: String,
    pub tactic: String,
    pub platform: Vec<String>,
    pub detection: String,
    pub url: String,
}

/// Sync MITRE ATT&CK techniques from STIX JSON to the database.
/// Returns the number of techniques synced.
pub async fn sync_attack_techniques(store: &dyn crate::db::Database) -> Result<usize, String> {
    tracing::info!("MITRE ATT&CK: Starting sync from STIX bundle...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client
        .get(ATTACK_STIX_URL)
        .send()
        .await
        .map_err(|e| format!("MITRE download failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("MITRE download returned {}", resp.status()));
    }

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("MITRE JSON parse error: {e}"))?;

    let objects = data["objects"]
        .as_array()
        .ok_or("No objects array in STIX bundle")?;
    load_attack_techniques(store, objects).await
}

/// Load MITRE ATT&CK `attack-pattern` objects from a STIX bundle into the store
/// (settings `_mitre` namespace, keyed by technique id) plus the sync meta.
/// Shared by the live [`sync_attack_techniques`] and the R2 `mitre` pack
/// installer ([`load_mitre_from_pack`]) so both land identical data.
pub async fn load_attack_techniques(
    store: &dyn crate::db::Database,
    objects: &[serde_json::Value],
) -> Result<usize, String> {
    let mut count = 0;

    for obj in objects {
        if obj["type"].as_str() != Some("attack-pattern") {
            continue;
        }
        if obj["revoked"].as_bool() == Some(true)
            || obj["x_mitre_deprecated"].as_bool() == Some(true)
        {
            continue;
        }

        // Extract technique ID (e.g., T1059.001)
        let technique_id = obj["external_references"]
            .as_array()
            .and_then(|refs| {
                refs.iter()
                    .find(|r| r["source_name"].as_str() == Some("mitre-attack"))
            })
            .and_then(|r| r["external_id"].as_str())
            .unwrap_or("")
            .to_string();

        if technique_id.is_empty() || !technique_id.starts_with('T') {
            continue;
        }

        let name = obj["name"].as_str().unwrap_or("").to_string();
        let description = obj["description"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(500)
            .collect::<String>();

        // Extract tactic from kill_chain_phases
        let tactic = obj["kill_chain_phases"]
            .as_array()
            .and_then(|phases| phases.first())
            .and_then(|p| p["phase_name"].as_str())
            .unwrap_or("")
            .to_string();

        let platform: Vec<String> = obj["x_mitre_platforms"]
            .as_array()
            .map(|p| {
                p.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let detection = obj["x_mitre_detection"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(300)
            .collect::<String>();

        let url = obj["external_references"]
            .as_array()
            .and_then(|refs| {
                refs.iter()
                    .find(|r| r["source_name"].as_str() == Some("mitre-attack"))
            })
            .and_then(|r| r["url"].as_str())
            .unwrap_or("")
            .to_string();

        // Store in DB via settings (simple key-value)
        let technique = serde_json::json!({
            "technique_id": technique_id,
            "name": name,
            "description": description,
            "tactic": tactic,
            "platform": platform,
            "detection": detection,
            "url": url,
            "synced_at": chrono::Utc::now().to_rfc3339(),
        });

        if let Err(e) = store.set_setting("_mitre", &technique_id, &technique).await {
            tracing::warn!("Failed to store MITRE technique {technique_id}: {e}");
            continue;
        }
        count += 1;
    }

    // Store sync metadata
    let meta = serde_json::json!({
        "last_sync": chrono::Utc::now().to_rfc3339(),
        "technique_count": count,
    });
    let _ = store.set_setting("_system", "mitre_sync_meta", &meta).await;

    tracing::info!("MITRE ATT&CK: Synced {count} techniques");
    Ok(count)
}

/// Parse a `mitre` R2 pack into the STIX `objects` array. The pack is the
/// Enterprise ATT&CK STIX bundle JSON, optionally gzip-compressed (the builder
/// gzips it; raw JSON is also accepted). Pure — no store writes.
pub fn parse_mitre_pack(bytes: &[u8]) -> Result<Vec<serde_json::Value>, String> {
    let json_bytes = maybe_gunzip(bytes)?;
    let data: serde_json::Value =
        serde_json::from_slice(&json_bytes).map_err(|e| format!("MITRE pack JSON: {e}"))?;
    let objects = data["objects"]
        .as_array()
        .ok_or("MITRE pack: no objects array")?;
    Ok(objects.clone())
}

/// Load a `mitre` R2 pack into the same store destination as a live sync — used
/// by the multi-pack updater so a premium agent gets ATT&CK from R2 (the fresh
/// `mitre-attack/attack-stix-data` source) instead of the deprecated `mitre/cti`.
pub async fn load_mitre_from_pack(
    store: &dyn crate::db::Database,
    bytes: &[u8],
) -> Result<usize, String> {
    let objects = parse_mitre_pack(bytes)?;
    load_attack_techniques(store, &objects).await
}

/// Gunzip `bytes` when they carry the gzip magic (`1f 8b`); otherwise return
/// them as-is. Lets a pack be served compressed or raw.
fn maybe_gunzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        use std::io::Read;
        let mut dec = flate2::read::GzDecoder::new(bytes);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .map_err(|e| format!("MITRE pack gunzip: {e}"))?;
        Ok(out)
    } else {
        Ok(bytes.to_vec())
    }
}

/// Lookup a technique by ID (e.g., "T1059.001").
pub async fn lookup_technique(
    store: &dyn crate::db::Database,
    technique_id: &str,
) -> Option<MitreTechnique> {
    let val = store.get_setting("_mitre", technique_id).await.ok()??;
    serde_json::from_value(val).ok()
}

/// Get last sync metadata.
pub async fn get_sync_meta(store: &dyn crate::db::Database) -> Option<serde_json::Value> {
    store.get_setting("_system", "mitre_sync_meta").await.ok()?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technique_id_format() {
        assert!("T1059".starts_with('T'));
        assert!("T1059.001".starts_with('T'));
    }

    const SAMPLE: &str = r#"{"type":"bundle","objects":[
        {"type":"attack-pattern","name":"Command and Scripting Interpreter",
         "external_references":[{"source_name":"mitre-attack","external_id":"T1059","url":"https://attack.mitre.org/techniques/T1059"}]},
        {"type":"identity","name":"not a technique"}
    ]}"#;

    fn gzip(s: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(s).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn parse_mitre_pack_reads_raw_and_gzipped() {
        let raw = parse_mitre_pack(SAMPLE.as_bytes()).unwrap();
        assert_eq!(raw.len(), 2, "all objects returned; filtering happens in load");
        let gz = gzip(SAMPLE.as_bytes());
        assert_eq!(&gz[0..2], &[0x1f, 0x8b]);
        let from_gz = parse_mitre_pack(&gz).unwrap();
        assert_eq!(from_gz.len(), 2);
        assert_eq!(from_gz[0]["type"], "attack-pattern");
    }

    #[test]
    fn parse_mitre_pack_rejects_garbage_and_missing_objects() {
        assert!(parse_mitre_pack(b"not json").is_err());
        assert!(parse_mitre_pack(br#"{"type":"bundle"}"#).is_err());
    }
}
