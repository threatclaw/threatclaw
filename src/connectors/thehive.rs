//! TheHive 5 Connector — import alerts and observables via REST API.
//!
//! Auth: Bearer API key
//! Alerts: POST /api/v1/query with listAlert
//! Port: 9000 (HTTP by default)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TheHiveConfig {
    pub url: String,
    pub api_key: String,
    #[serde(default)]
    pub org: Option<String>,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
    #[serde(default = "default_limit")]
    pub max_alerts: u32,
}

fn default_true() -> bool {
    true
}
fn default_limit() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize)]
pub struct TheHiveSyncResult {
    pub alerts_imported: usize,
    pub observables_imported: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_thehive(store: &dyn Database, config: &TheHiveConfig) -> TheHiveSyncResult {
    let mut result = TheHiveSyncResult {
        alerts_imported: 0,
        observables_imported: 0,
        findings_created: 0,
        errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("HTTP client: {}", e));
            return result;
        }
    };

    let url = config.url.trim_end_matches('/');
    tracing::info!("THEHIVE: Connecting to {}", url);

    // Fetch alerts
    let query_body = serde_json::json!({
        "query": [{"_name": "listAlert"}],
        "from": 0,
        "to": config.max_alerts
    });

    let resp = match client
        .post(format!("{}/api/v1/query", url))
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&query_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("Alerts request: {}", e));
            return result;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        result.errors.push(format!(
            "Alerts HTTP {}: {}",
            status,
            &text[..text.len().min(200)]
        ));
        return result;
    }

    let alerts: Vec<serde_json::Value> = match resp.json().await {
        Ok(a) => a,
        Err(e) => {
            result.errors.push(format!("Parse alerts: {}", e));
            return result;
        }
    };

    tracing::info!("THEHIVE: {} alerts found", alerts.len());

    for alert in &alerts {
        let title = alert["title"].as_str().unwrap_or("TheHive alert");
        let description = alert["description"].as_str().unwrap_or("");
        let severity = alert["severity"].as_u64().unwrap_or(1);
        let source = alert["source"].as_str().unwrap_or("");
        let source_ref = alert["sourceRef"].as_str().unwrap_or("");
        let tags: Vec<&str> = alert["tags"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let tc_severity = match severity {
            4 => "CRITICAL",
            3 => "HIGH",
            2 => "MEDIUM",
            _ => "LOW",
        };

        // Insert as sigma alert
        let _ = store
            .insert_sigma_alert(source_ref, tc_severity, title, "", None, None)
            .await;
        result.alerts_imported += 1;

        // Create finding for severity >= 2
        if severity >= 2 {
            let _ = store
                .insert_finding(&NewFinding {
                    skill_id: "skill-thehive".into(),
                    title: format!("[TheHive] {}", title),
                    description: Some(description.to_string()),
                    severity: tc_severity.into(),
                    category: Some("soar".into()),
                    asset: None,
                    source: Some(format!("TheHive ({})", source)),
                    metadata: Some(serde_json::json!({
                        "source_ref": source_ref,
                        "tags": tags,
                        "thehive_severity": severity,
                    })),
                })
                .await;
            result.findings_created += 1;
        }
    }

    // Fetch observables (IOCs)
    let obs_body = serde_json::json!({
        "query": [{"_name": "listObservable"}],
        "from": 0,
        "to": 200
    });

    match client
        .post(format!("{}/api/v1/query", url))
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&obs_body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(observables) = resp.json::<Vec<serde_json::Value>>().await {
                tracing::info!("THEHIVE: {} observables found", observables.len());
                for obs in &observables {
                    let data_type = obs["dataType"].as_str().unwrap_or("unknown");
                    let data = obs["data"].as_str().unwrap_or("");
                    let is_ioc = obs["ioc"].as_bool().unwrap_or(false);

                    if is_ioc && !data.is_empty() {
                        let _ = store
                            .insert_finding(&NewFinding {
                                skill_id: "skill-thehive".into(),
                                title: format!("[TheHive IOC] {} = {}", data_type, data),
                                description: obs["message"].as_str().map(|s| s.to_string()),
                                severity: "MEDIUM".into(),
                                category: Some("ioc".into()),
                                asset: None,
                                source: Some("TheHive Observable".into()),
                                metadata: Some(serde_json::json!({
                                    "data_type": data_type,
                                    "data": data,
                                    "tags": obs["tags"],
                                })),
                            })
                            .await;
                        result.observables_imported += 1;
                    }
                }
            }
        }
        Ok(resp) => {
            tracing::warn!("THEHIVE: Observables HTTP {}", resp.status());
        }
        Err(e) => {
            tracing::warn!("THEHIVE: Observables request: {}", e);
        }
    }

    tracing::info!(
        "THEHIVE: Sync done — {} alerts, {} observables, {} findings",
        result.alerts_imported,
        result.observables_imported,
        result.findings_created
    );
    result
}
