//! CrowdSec LAPI Connector — import IP ban decisions from CrowdSec.
//!
//! Auth: X-Api-Key header with bouncer API key
//! Endpoint: GET http://{host}:8080/v1/decisions/stream
//! Returns new and deleted decisions in delta mode.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdSecConfig {
    pub url: String,          // e.g. "http://192.168.1.10:8080"
    pub bouncer_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrowdSecSyncResult {
    pub new_decisions: usize,
    pub deleted_decisions: usize,
    pub alerts_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_crowdsec(store: &dyn Database, config: &CrowdSecConfig, startup: bool) -> CrowdSecSyncResult {
    let mut result = CrowdSecSyncResult {
        new_decisions: 0, deleted_decisions: 0, alerts_created: 0, errors: vec![],
    };

    if config.bouncer_key.is_empty() {
        result.errors.push("CrowdSec bouncer API key required".into());
        return result;
    }

    let client = reqwest::Client::new();

    let url = if startup {
        format!("{}/v1/decisions/stream?startup=true", config.url.trim_end_matches('/'))
    } else {
        format!("{}/v1/decisions/stream", config.url.trim_end_matches('/'))
    };

    let resp = match client.get(&url)
        .header("X-Api-Key", &config.bouncer_key)
        .timeout(Duration::from_secs(15))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("CrowdSec request: {}", e)); return result; }
    };

    if resp.status().as_u16() == 403 {
        result.errors.push("CrowdSec: invalid bouncer key".into());
        return result;
    }
    if !resp.status().is_success() {
        result.errors.push(format!("CrowdSec HTTP {}", resp.status()));
        return result;
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => { result.errors.push(format!("CrowdSec parse: {}", e)); return result; }
    };

    // Process new decisions
    if let Some(new_arr) = body["new"].as_array() {
        for decision in new_arr {
            let dtype = decision["type"].as_str().unwrap_or("");
            let scope = decision["scope"].as_str().unwrap_or("ip");
            let value = decision["value"].as_str().unwrap_or("");
            let scenario = decision["scenario"].as_str().unwrap_or("unknown");
            let duration = decision["duration"].as_str().unwrap_or("");

            if value.is_empty() { continue; }

            result.new_decisions += 1;

            let level = match dtype {
                "ban" => "high",
                "captcha" => "medium",
                _ => "low",
            };

            let title = format!("CrowdSec {}: {} {} ({})", dtype, scope, value, scenario);
            let description = format!(
                "Scenario: {}\nDuration: {}\nScope: {}\nValue: {}",
                scenario, duration, scope, value
            );

            if let Err(e) = store.insert_sigma_alert(
                scenario, level, &title, "", Some(value), None,
            ).await {
                result.errors.push(format!("Create alert: {}", e));
            } else {
                result.alerts_created += 1;
            }
        }
    }

    // Process deleted decisions (resolved)
    if let Some(del_arr) = body["deleted"].as_array() {
        result.deleted_decisions = del_arr.len();
        // In a full implementation, we'd resolve matching alerts here
    }

    tracing::info!(
        "CROWDSEC: {} new decisions, {} deleted, {} alerts created",
        result.new_decisions, result.deleted_decisions, result.alerts_created
    );

    result
}

/// Check if a specific IP has active decisions.
pub async fn check_ip(config: &CrowdSecConfig, ip: &str) -> Result<Vec<String>, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/v1/decisions?ip={}", config.url.trim_end_matches('/'), ip);

    let resp = client.get(&url)
        .header("X-Api-Key", &config.bouncer_key)
        .timeout(Duration::from_secs(10))
        .send().await
        .map_err(|e| format!("CrowdSec check: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("CrowdSec HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("CrowdSec parse: {}", e))?;

    // null = no decisions (clean)
    if body.is_null() {
        return Ok(vec![]);
    }

    let decisions: Vec<String> = body.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|d| {
                    let scenario = d["scenario"].as_str()?;
                    let dtype = d["type"].as_str()?;
                    Some(format!("{} ({})", scenario, dtype))
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(decisions)
}
