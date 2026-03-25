#![allow(unused_imports)]
//! UptimeRobot Connector — import monitor status (uptime, downtime, SSL, latency).
//!
//! Auth: api_key in POST body (NOT a header)
//! Endpoint: POST https://api.uptimerobot.com/v2/getMonitors
//! Content-Type: application/x-www-form-urlencoded
//! IMPORTANT: All UptimeRobot API calls use POST, even reads.

use crate::db::Database;
use crate::db::threatclaw_store::{ThreatClawStore, NewFinding};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const API_URL: &str = "https://api.uptimerobot.com/v2/getMonitors";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UptimeRobotConfig {
    pub api_key: String,
    #[serde(default = "default_latency_threshold")]
    pub latency_threshold_ms: u32,
    #[serde(default = "default_cert_warn_days")]
    pub cert_warn_days: i64,
}

fn default_latency_threshold() -> u32 { 2000 }
fn default_cert_warn_days() -> i64 { 14 }

#[derive(Debug, Clone, Serialize)]
pub struct UptimeRobotSyncResult {
    pub monitors_checked: usize,
    pub monitors_down: usize,
    pub alerts_created: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_uptimerobot(store: &dyn Database, config: &UptimeRobotConfig) -> UptimeRobotSyncResult {
    let mut result = UptimeRobotSyncResult {
        monitors_checked: 0, monitors_down: 0, alerts_created: 0, findings_created: 0, errors: vec![],
    };

    if config.api_key.is_empty() {
        result.errors.push("UptimeRobot API key required".into());
        return result;
    }

    let client = reqwest::Client::new();

    // UptimeRobot uses POST with form-encoded body for everything
    let resp = match client.post(API_URL)
        .form(&[("api_key", &config.api_key), ("format", &"json".to_string())])
        .timeout(Duration::from_secs(15))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("UptimeRobot request: {}", e)); return result; }
    };

    if !resp.status().is_success() {
        result.errors.push(format!("UptimeRobot HTTP {}", resp.status()));
        return result;
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => { result.errors.push(format!("UptimeRobot parse: {}", e)); return result; }
    };

    if body["stat"].as_str() != Some("ok") {
        let msg = body["error"]["message"].as_str().unwrap_or("Unknown error");
        result.errors.push(format!("UptimeRobot API error: {}", msg));
        return result;
    }

    let monitors = match body["monitors"].as_array() {
        Some(m) => m,
        None => { return result; }
    };

    let now = chrono::Utc::now();

    for monitor in monitors {
        result.monitors_checked += 1;

        let name = monitor["friendly_name"].as_str().unwrap_or("unknown");
        let url = monitor["url"].as_str().unwrap_or("");
        let status = monitor["status"].as_i64().unwrap_or(0);
        let avg_response = monitor["average_response_time"].as_i64().unwrap_or(0);

        // Status: 0=paused, 1=not checked, 2=up, 8=seems down, 9=down
        match status {
            8 | 9 => {
                result.monitors_down += 1;
                let level = if status == 9 { "high" } else { "medium" };
                let status_label = if status == 9 { "DOWN" } else { "seems DOWN" };
                let title = format!("{} {} ({})", name, status_label, url);

                if let Err(e) = store.insert_sigma_alert(
                    "uptimerobot-down", level, &title, "", None, None,
                ).await {
                    result.errors.push(format!("Insert alert: {}", e));
                } else {
                    result.alerts_created += 1;
                }
            }
            _ => {}
        }

        // Check SSL certificate expiry
        if let Some(ssl_expiry) = monitor["ssl"].as_object()
            .and_then(|ssl| ssl["expires"].as_i64())
        {
            if let Some(expiry_date) = chrono::DateTime::from_timestamp(ssl_expiry, 0) {
                let days_left = (expiry_date - now).num_days();
                if days_left < config.cert_warn_days {
                    let severity = if days_left <= 0 { "critical" } else if days_left <= 7 { "high" } else { "medium" };
                    let title = format!("SSL certificate expires in {} days: {} ({})", days_left, name, url);

                    if let Err(e) = store.insert_finding(&NewFinding {
                        skill_id: "skill-uptimerobot".into(),
                        title: title.clone(),
                        description: Some(format!("URL: {}\nExpiry: {}", url, expiry_date.format("%Y-%m-%d"))),
                        severity: severity.to_uppercase(),
                        category: Some("ssl-expiry".into()),
                        asset: Some(url.to_string()),
                        source: Some("UptimeRobot".into()),
                        metadata: None,
                    }).await {
                        result.errors.push(format!("Insert finding: {}", e));
                    } else {
                        result.findings_created += 1;
                    }
                }
            }
        }

        // Check high latency
        if status == 2 && avg_response > config.latency_threshold_ms as i64 {
            let title = format!("High latency: {} ({}ms avg) — {}", name, avg_response, url);

            if let Err(e) = store.insert_finding(&NewFinding {
                skill_id: "skill-uptimerobot".into(),
                title: title.clone(),
                description: Some(format!("URL: {}\nAvg response: {}ms", url, avg_response)),
                severity: "LOW".into(),
                category: Some("latency".into()),
                asset: Some(url.to_string()),
                source: Some("UptimeRobot".into()),
                metadata: None,
            }).await {
                result.errors.push(format!("Insert finding: {}", e));
            } else {
                result.findings_created += 1;
            }
        }
    }

    tracing::info!(
        "UPTIMEROBOT: {} monitors checked, {} down, {} alerts, {} findings",
        result.monitors_checked, result.monitors_down, result.alerts_created, result.findings_created
    );

    result
}
