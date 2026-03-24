//! DefectDojo Connector — export ThreatClaw findings to DefectDojo.
//!
//! Auth: API v2 token (Authorization: Token {api_key})
//! POST https://{host}/api/v2/findings/
//! POST https://{host}/api/v2/import-scan/ (for bulk import)

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefectDojoConfig {
    pub url: String,
    pub api_key: String,
    /// Product ID in DefectDojo (created manually first)
    pub product_id: u32,
    /// Engagement ID (auto-create if 0)
    pub engagement_id: u32,
    #[serde(default)]
    pub no_tls_verify: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefectDojoSyncResult {
    pub findings_exported: usize,
    pub errors: Vec<String>,
}

/// Export open findings from ThreatClaw to DefectDojo.
pub async fn export_findings(store: &dyn Database, config: &DefectDojoConfig) -> DefectDojoSyncResult {
    let mut result = DefectDojoSyncResult {
        findings_exported: 0, errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("HTTP: {}", e)); return result; }
    };

    // Fetch open findings from ThreatClaw
    let findings = store.list_findings(None, Some("open"), None, 200).await.unwrap_or_default();

    if findings.is_empty() {
        tracing::info!("DEFECTDOJO: No open findings to export");
        return result;
    }

    tracing::info!("DEFECTDOJO: Exporting {} findings to {}", findings.len(), config.url);

    for f in &findings {
        let severity_map = match f.severity.to_uppercase().as_str() {
            "CRITICAL" => "Critical",
            "HIGH" => "High",
            "MEDIUM" => "Medium",
            "LOW" => "Low",
            _ => "Info",
        };

        let dd_finding = serde_json::json!({
            "title": f.title,
            "description": f.description.as_deref().unwrap_or(""),
            "severity": severity_map,
            "numerical_severity": match severity_map {
                "Critical" => "S0",
                "High" => "S1",
                "Medium" => "S2",
                "Low" => "S3",
                _ => "S4",
            },
            "active": true,
            "verified": false,
            "duplicate": false,
            "test": config.engagement_id,
            "found_by": [1], // Automated tool
            "static_finding": false,
            "dynamic_finding": true,
        });

        let url = format!("{}/api/v2/findings/", config.url);
        match client.post(&url)
            .header("Authorization", format!("Token {}", config.api_key))
            .json(&dd_finding)
            .send().await
        {
            Ok(resp) if resp.status().is_success() || resp.status().as_u16() == 201 => {
                result.findings_exported += 1;
            }
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                result.errors.push(format!("Finding '{}': {}", f.title, body.chars().take(200).collect::<String>()));
            }
            Err(e) => {
                result.errors.push(format!("Finding '{}': {}", f.title, e));
            }
        }
    }

    tracing::info!("DEFECTDOJO: {} findings exported, {} errors",
        result.findings_exported, result.errors.len());

    result
}
