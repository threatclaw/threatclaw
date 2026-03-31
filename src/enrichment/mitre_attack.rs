//! MITRE ATT&CK enrichment — sync techniques from STIX JSON.
//!
//! Downloads the Enterprise ATT&CK STIX bundle from GitHub (monthly sync).
//! Stores techniques in PostgreSQL for fast lookup during ReAct analysis.

use serde::{Deserialize, Serialize};

const ATTACK_STIX_URL: &str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";

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
pub async fn sync_attack_techniques(
    store: &dyn crate::db::Database,
) -> Result<usize, String> {
    tracing::info!("MITRE ATT&CK: Starting sync from STIX bundle...");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client.get(ATTACK_STIX_URL).send().await
        .map_err(|e| format!("MITRE download failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("MITRE download returned {}", resp.status()));
    }

    let data: serde_json::Value = resp.json().await
        .map_err(|e| format!("MITRE JSON parse error: {e}"))?;

    let objects = data["objects"].as_array()
        .ok_or("No objects array in STIX bundle")?;

    let mut count = 0;

    for obj in objects {
        if obj["type"].as_str() != Some("attack-pattern") {
            continue;
        }
        if obj["revoked"].as_bool() == Some(true) || obj["x_mitre_deprecated"].as_bool() == Some(true) {
            continue;
        }

        // Extract technique ID (e.g., T1059.001)
        let technique_id = obj["external_references"]
            .as_array()
            .and_then(|refs| refs.iter().find(|r| r["source_name"].as_str() == Some("mitre-attack")))
            .and_then(|r| r["external_id"].as_str())
            .unwrap_or("")
            .to_string();

        if technique_id.is_empty() || !technique_id.starts_with('T') {
            continue;
        }

        let name = obj["name"].as_str().unwrap_or("").to_string();
        let description = obj["description"].as_str().unwrap_or("").chars().take(500).collect::<String>();

        // Extract tactic from kill_chain_phases
        let tactic = obj["kill_chain_phases"]
            .as_array()
            .and_then(|phases| phases.first())
            .and_then(|p| p["phase_name"].as_str())
            .unwrap_or("")
            .to_string();

        let platform: Vec<String> = obj["x_mitre_platforms"]
            .as_array()
            .map(|p| p.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let detection = obj["x_mitre_detection"].as_str().unwrap_or("").chars().take(300).collect::<String>();

        let url = obj["external_references"]
            .as_array()
            .and_then(|refs| refs.iter().find(|r| r["source_name"].as_str() == Some("mitre-attack")))
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
}
