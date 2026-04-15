//! Gotify notification integration — push notifications only (no HITL buttons).
//!
//! Gotify is receive-only: it can display notifications but cannot
//! handle interactive buttons or callbacks. Use it for alerts,
//! not for HITL approvals.

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Gotify notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GotifyConfig {
    pub enabled: bool,
    pub server_url: String,
    pub app_token: String,
}

/// Gotify priority (1-10).
fn severity_to_priority(severity: &str) -> u8 {
    match severity {
        "Critical" | "critical" => 10,
        "High" | "high" => 7,
        "Medium" | "medium" => 5,
        "Low" | "low" => 2,
        _ => 1,
    }
}

/// Send a notification to Gotify.
pub async fn send_notification(
    config: &GotifyConfig,
    title: &str,
    message: &str,
    severity: &str,
) -> Result<(), String> {
    if !config.enabled || config.server_url.is_empty() || config.app_token.is_empty() {
        return Err("Gotify not configured".into());
    }

    let url = format!(
        "{}/message?token={}",
        config.server_url.trim_end_matches('/'),
        config.app_token
    );

    let payload = json!({
        "title": title,
        "message": message,
        "priority": severity_to_priority(severity),
        "extras": {
            "client::display": { "contentType": "text/markdown" }
        }
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Gotify: {e}"))?;

    if resp.status().is_success() {
        tracing::info!("Gotify notification sent: {}", title);
        Ok(())
    } else {
        Err(format!("Gotify HTTP {}", resp.status()))
    }
}

/// Test Gotify connectivity.
pub async fn test_connection(server_url: &str, app_token: &str) -> Result<String, String> {
    let url = format!(
        "{}/message?token={}",
        server_url.trim_end_matches('/'),
        app_token
    );

    let payload = json!({
        "title": "ThreatClaw — Test",
        "message": "Connexion Gotify réussie",
        "priority": 1,
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Gotify: {e}"))?;

    if resp.status().is_success() {
        Ok("Gotify connecté".into())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}
