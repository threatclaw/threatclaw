//! Graylog SIEM Connector — import alert events via REST API.
//!
//! Auth: Basic auth or API token (X-Requested-By header required)
//! Events: POST /api/events/search
//! Port: 9000 (HTTP) or 443 (HTTPS)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraylogConfig {
    pub url: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
    #[serde(default = "default_limit")]
    pub max_events: u32,
}

fn default_true() -> bool { true }
fn default_limit() -> u32 { 100 }

#[derive(Debug, Clone, Serialize)]
pub struct GraylogSyncResult {
    pub events_imported: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_graylog(store: &dyn Database, config: &GraylogConfig) -> GraylogSyncResult {
    let mut result = GraylogSyncResult {
        events_imported: 0, findings_created: 0, errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("HTTP client: {}", e)); return result; }
    };

    let url = config.url.trim_end_matches('/');
    tracing::info!("GRAYLOG: Connecting to {}", url);

    // Build request with auth
    let mut req = client.post(format!("{}/api/events/search", url))
        .header("X-Requested-By", "threatclaw")
        .header("Content-Type", "application/json");

    if let Some(token) = &config.token {
        // Graylog API tokens use token:token as basic auth
        req = req.basic_auth(token, Some("token"));
    } else if let (Some(user), Some(pass)) = (&config.username, &config.password) {
        req = req.basic_auth(user, Some(pass));
    } else {
        result.errors.push("No auth configured: set token or username+password".into());
        return result;
    }

    // Search for events from last 24h
    let body = serde_json::json!({
        "query": "",
        "timerange": { "type": "relative", "range": 86400 },
        "page": 1,
        "per_page": config.max_events,
        "sort_by": "timestamp",
        "sort_direction": "desc"
    });

    let resp = match req.json(&body).send().await {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Request failed: {}", e)); return result; }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        result.errors.push(format!("HTTP {}: {}", status, &text[..text.len().min(200)]));
        return result;
    }

    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(e) => { result.errors.push(format!("Parse response: {}", e)); return result; }
    };

    let events = match data["events"].as_array() {
        Some(e) => e,
        None => {
            tracing::info!("GRAYLOG: No events found");
            return result;
        }
    };

    tracing::info!("GRAYLOG: {} events found", events.len());

    for event_wrapper in events {
        let event = &event_wrapper["event"];
        let title = event["message"].as_str()
            .or_else(|| event["event_definition_id"].as_str())
            .unwrap_or("Graylog event");
        let priority = event["priority"].as_u64().unwrap_or(1);
        let source = event["source"].as_str().unwrap_or("");
        let timestamp = event["timestamp"].as_str().unwrap_or("");

        let tc_severity = match priority {
            3 => "HIGH",
            2 => "MEDIUM",
            _ => "LOW",
        };

        // Extract fields for context
        let fields = &event["fields"];
        let source_ip = fields["source_ip"].as_str()
            .or_else(|| fields["src_ip"].as_str());
        let hostname = fields["hostname"].as_str()
            .or_else(|| fields["source"].as_str());
        let username = fields["username"].as_str()
            .or_else(|| fields["user"].as_str());

        let rule_id = event["event_definition_id"].as_str().unwrap_or("graylog-event");

        // Insert as sigma alert
        let _ = store.insert_sigma_alert(
            rule_id,
            tc_severity,
            title,
            hostname.unwrap_or(""),
            source_ip,
            username,
        ).await;
        result.events_imported += 1;

        // Create finding for priority >= 2
        if priority >= 2 {
            let _ = store.insert_finding(&NewFinding {
                skill_id: "skill-graylog".into(),
                title: format!("[Graylog] {}", title),
                description: Some(format!("Source: {}, Time: {}", source, timestamp)),
                severity: tc_severity.into(),
                category: Some("siem".into()),
                asset: hostname.map(|s| s.to_string()),
                source: Some("Graylog SIEM".into()),
                metadata: Some(serde_json::json!({
                    "event_definition_id": rule_id,
                    "priority": priority,
                    "source_ip": source_ip,
                    "fields": fields,
                })),
            }).await;
            result.findings_created += 1;
        }
    }

    tracing::info!("GRAYLOG: Sync done — {} events, {} findings", result.events_imported, result.findings_created);
    result
}
