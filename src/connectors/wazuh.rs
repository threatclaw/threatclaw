//! Wazuh SIEM Connector — import alerts via REST API.
//!
//! Auth: POST /security/user/authenticate → JWT (900s TTL)
//! Alerts: GET /alerts with pagination
//! Port: 55000 (HTTPS, self-signed cert by default)

use crate::db::Database;
use crate::db::threatclaw_store::{ThreatClawStore, NewFinding};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WazuhConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
    #[serde(default = "default_limit")]
    pub max_alerts: u32,
}

fn default_true() -> bool { true }
fn default_limit() -> u32 { 100 }

#[derive(Debug, Clone, Serialize)]
pub struct WazuhSyncResult {
    pub alerts_imported: usize,
    pub findings_created: usize,
    pub highest_level: u8,
    pub errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WazuhAuthResponse {
    data: Option<WazuhAuthData>,
    error: i32,
}

#[derive(Debug, Deserialize)]
struct WazuhAuthData {
    token: String,
}

#[derive(Debug, Deserialize)]
struct WazuhAlertResponse {
    data: Option<WazuhAlertData>,
    error: i32,
}

#[derive(Debug, Deserialize)]
struct WazuhAlertData {
    affected_items: Vec<serde_json::Value>,
    total_affected_items: u64,
}

pub async fn sync_wazuh(store: &dyn Database, config: &WazuhConfig) -> WazuhSyncResult {
    let mut result = WazuhSyncResult {
        alerts_imported: 0, findings_created: 0, highest_level: 0, errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("HTTP client: {}", e)); return result; }
    };

    tracing::info!("WAZUH: Connecting to {}", config.url);

    // Authenticate
    let auth_url = format!("{}/security/user/authenticate", config.url);
    let auth_resp = match client.post(&auth_url)
        .basic_auth(&config.username, Some(&config.password))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Auth failed: {}", e)); return result; }
    };

    if !auth_resp.status().is_success() {
        result.errors.push(format!("Auth HTTP {}", auth_resp.status()));
        return result;
    }

    let auth: WazuhAuthResponse = match auth_resp.json().await {
        Ok(a) => a,
        Err(e) => { result.errors.push(format!("Auth parse: {}", e)); return result; }
    };

    if auth.error != 0 || auth.data.is_none() {
        result.errors.push("Auth error: no token".into());
        return result;
    }

    let token = auth.data.unwrap().token;
    tracing::info!("WAZUH: Authenticated, fetching alerts");

    // Fetch alerts
    let alerts_url = format!("{}/alerts?limit={}&sort=-timestamp", config.url, config.max_alerts);
    let alerts_resp = match client.get(&alerts_url)
        .header("Authorization", format!("Bearer {}", token))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Alerts fetch: {}", e)); return result; }
    };

    if !alerts_resp.status().is_success() {
        result.errors.push(format!("Alerts HTTP {}", alerts_resp.status()));
        return result;
    }

    let alerts_data: WazuhAlertResponse = match alerts_resp.json().await {
        Ok(a) => a,
        Err(e) => { result.errors.push(format!("Alerts parse: {}", e)); return result; }
    };

    if alerts_data.error != 0 || alerts_data.data.is_none() {
        result.errors.push("Alerts API error".into());
        return result;
    }

    let items = alerts_data.data.unwrap().affected_items;
    result.alerts_imported = items.len();

    // Convert to findings
    for alert in &items {
        let rule_level = alert["rule"]["level"].as_u64().unwrap_or(0) as u8;
        let rule_desc = alert["rule"]["description"].as_str().unwrap_or("");
        let rule_id = alert["rule"]["id"].as_str().unwrap_or("");
        let agent_name = alert["agent"]["name"].as_str().unwrap_or("");
        let agent_ip = alert["agent"]["ip"].as_str().unwrap_or("");
        let src_ip = alert["data"]["srcip"].as_str();
        let timestamp = alert["timestamp"].as_str().unwrap_or("");

        if rule_level > result.highest_level { result.highest_level = rule_level; }

        // Only import level >= 7 (skip noise)
        if rule_level < 7 { continue; }

        let severity = match rule_level {
            0..=5 => "LOW",
            6..=9 => "MEDIUM",
            10..=12 => "HIGH",
            _ => "CRITICAL",
        };

        let mitre_ids: Vec<String> = alert["rule"]["mitre"]["id"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();

        let _ = store.insert_finding(&NewFinding {
            skill_id: "skill-wazuh".into(),
            title: format!("[Wazuh {}] {}", rule_id, rule_desc),
            description: Some(format!(
                "Agent: {} ({})\nSource: {}\nTimestamp: {}\nMITRE: {}",
                agent_name, agent_ip, src_ip.unwrap_or("N/A"),
                timestamp, mitre_ids.join(", ")
            )),
            severity: severity.into(),
            category: Some("wazuh-alert".into()),
            asset: Some(agent_name.into()),
            source: Some("Wazuh SIEM".into()),
            metadata: Some(serde_json::json!({
                "wazuh_rule_id": rule_id,
                "rule_level": rule_level,
                "agent_ip": agent_ip,
                "src_ip": src_ip,
                "mitre": mitre_ids,
            })),
        }).await;

        result.findings_created += 1;
    }

    tracing::info!("WAZUH SYNC: {} alerts imported, {} findings created (max level {})",
        result.alerts_imported, result.findings_created, result.highest_level);

    result
}
