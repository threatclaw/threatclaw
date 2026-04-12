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
    /// OpenSearch/Elasticsearch indexer URL (e.g. "https://192.168.1.1:9200")
    /// If set, alerts are fetched from the indexer when /alerts API is unavailable (Wazuh 4.x)
    #[serde(default)]
    pub indexer_url: Option<String>,
    #[serde(default)]
    pub indexer_username: Option<String>,
    #[serde(default)]
    pub indexer_password: Option<String>,
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
    tracing::info!("WAZUH: Authenticated, fetching agents + alerts");

    // Fetch agents (always available in Wazuh API)
    let agents_url = format!("{}/agents?limit=500&select=id,name,ip,os.name,os.version,status,lastKeepAlive", config.url);
    match client.get(&agents_url)
        .header("Authorization", format!("Bearer {}", token))
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(agents) = data["data"]["affected_items"].as_array() {
                    tracing::info!("WAZUH: {} agents found", agents.len());
                    for agent in agents {
                        let name = agent["name"].as_str().unwrap_or("unknown");
                        let ip = agent["ip"].as_str().unwrap_or("");
                        let os = format!("{} {}", agent["os"]["name"].as_str().unwrap_or(""), agent["os"]["version"].as_str().unwrap_or("")).trim().to_string();
                        let status = agent["status"].as_str().unwrap_or("unknown");

                        // Import agent as asset via resolution pipeline (dedup with other sources)
                        if !ip.is_empty() && ip != "any" {
                            let discovered = crate::graph::asset_resolution::DiscoveredAsset {
                                mac: None,
                                hostname: Some(name.to_string()),
                                fqdn: None,
                                ip: Some(ip.to_string()),
                                os: if os.is_empty() { None } else { Some(os.clone()) },
                                ports: None,
                                services: serde_json::json!([]),
                                ou: None,
                                vlan: None,
                                vm_id: None,
                                criticality: Some("medium".into()),
                                source: "wazuh".into(),
                            };
                            let res = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
                            tracing::debug!("WAZUH ASSET: {} → {:?} ({})", name, res.action, res.asset_id);
                            result.alerts_imported += 1;
                        }

                        // Create finding if agent is disconnected
                        if status == "disconnected" || status == "never_connected" {
                            let _ = store.insert_finding(&NewFinding {
                                skill_id: "skill-wazuh".into(),
                                title: format!("Wazuh agent {} is {}", name, status),
                                description: Some(format!("Agent {} (IP: {}) status: {}. Last keepalive: {}", name, ip, status, agent["lastKeepAlive"].as_str().unwrap_or("?"))),
                                severity: "MEDIUM".into(),
                                category: Some("monitoring".into()),
                                asset: Some(ip.to_string()),
                                source: Some("Wazuh SIEM".into()),
                                metadata: Some(serde_json::json!({"agent_id": agent["id"], "status": status})),
                            }).await;
                            result.findings_created += 1;
                        }
                    }
                }
            }
        }
        Ok(resp) => { result.errors.push(format!("Agents HTTP {}", resp.status())); }
        Err(e) => { result.errors.push(format!("Agents fetch: {}", e)); }
    }

    // Fetch alerts (Wazuh 4.x: /alerts endpoint may not exist — try it, fallback gracefully)
    let alerts_url = format!("{}/alerts?limit={}&sort=-timestamp", config.url, config.max_alerts);
    let alerts_resp = match client.get(&alerts_url)
        .header("Authorization", format!("Bearer {}", token))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Alerts fetch: {}", e)); return result; }
    };

    let alerts: Vec<serde_json::Value> = if alerts_resp.status().is_success() {
        // Wazuh 5.x+ or patched: /alerts endpoint works
        match alerts_resp.json::<WazuhAlertResponse>().await {
            Ok(data) if data.error == 0 && data.data.is_some() => {
                data.data.unwrap().affected_items
            }
            Ok(_) => { result.errors.push("Alerts API error".into()); vec![] }
            Err(e) => { result.errors.push(format!("Alerts parse: {}", e)); vec![] }
        }
    } else if let Some(indexer_url) = &config.indexer_url {
        // Wazuh 4.x fallback: fetch alerts from OpenSearch/Elasticsearch indexer
        tracing::info!("WAZUH: /alerts not available, falling back to indexer at {}", indexer_url);
        match fetch_alerts_from_indexer(&client, config, indexer_url).await {
            Ok(items) => items,
            Err(e) => { result.errors.push(format!("Indexer: {}", e)); vec![] }
        }
    } else {
        tracing::info!("WAZUH: /alerts not available (Wazuh 4.x) and no indexer_url configured. Only agents imported.");
        vec![]
    };

    result.alerts_imported = alerts.len();

    // Convert alerts to findings
    for alert in &alerts {
        import_wazuh_alert(store, alert, &mut result).await;
    }

    tracing::info!("WAZUH SYNC: {} alerts imported, {} findings created (max level {})",
        result.alerts_imported, result.findings_created, result.highest_level);

    result
}

/// Import a single Wazuh alert — routes to sigma_alerts (events) or findings (vulns)
async fn import_wazuh_alert(store: &dyn Database, alert: &serde_json::Value, result: &mut WazuhSyncResult) {
    let rule_level = alert["rule"]["level"].as_u64().unwrap_or(0) as u8;
    let rule_desc = alert["rule"]["description"].as_str().unwrap_or("");
    let rule_id = alert["rule"]["id"].as_str().unwrap_or("");
    let agent_name = alert["agent"]["name"].as_str().unwrap_or("");
    let agent_ip = alert["agent"]["ip"].as_str().unwrap_or("");
    let src_ip = alert["data"]["srcip"].as_str();
    let username = alert["data"]["dstuser"].as_str()
        .or_else(|| alert["data"]["srcuser"].as_str());
    let timestamp = alert["timestamp"].as_str().unwrap_or("");

    if rule_level > result.highest_level { result.highest_level = rule_level; }

    if rule_level < 5 { return; }

    let severity = match rule_level {
        0..=5 => "low",
        6..=9 => "medium",
        10..=12 => "high",
        _ => "critical",
    };

    // Filter noisy audit rules (80700-80799 = Linux audit events)
    // These are inventory/system events, not security alerts. Excluded to avoid score pollution.
    let rule_num: u32 = rule_id.parse().unwrap_or(0);
    if (80700..80800).contains(&rule_num) { return; }

    // Store raw alert in logs table for Sigma engine matching.
    // This enables PowerShell obfuscation rules, Kerberoasting detection, and
    // any future Sigma rule to match against Wazuh event data.
    // Tag: "wazuh.alert" for all events, enables logsource filtering.
    let now = chrono::Utc::now().to_rfc3339();
    let _ = store.insert_log("wazuh.alert", agent_name, alert, &now).await;

    // Wazuh vulnerability rules (5500-5599) → findings (dedup OK)
    // Everything else (auth, intrusion, file integrity) → sigma_alerts (each event counts)
    let is_vuln_rule = (5500..5600).contains(&rule_num);

    if is_vuln_rule {
        // Vulnerability → finding (deduplicated)
        let _ = store.insert_finding(&NewFinding {
            skill_id: "skill-wazuh".into(),
            title: format!("[Wazuh {}] {}", rule_id, rule_desc),
            description: Some(format!("Agent: {} ({})\nSource: {}\nTimestamp: {}",
                agent_name, agent_ip, src_ip.unwrap_or("N/A"), timestamp)),
            severity: severity.to_uppercase(),
            category: Some("wazuh-vuln".into()),
            asset: Some(agent_name.into()),
            source: Some("Wazuh SIEM".into()),
            metadata: Some(serde_json::json!({
                "wazuh_rule_id": rule_id, "rule_level": rule_level,
            })),
        }).await;
        result.findings_created += 1;
    } else {
        // Security event → sigma_alert (each occurrence counts for scoring)
        let sigma_rule_id = format!("wazuh-{}", rule_id);
        let title = format!("[Wazuh {}] {}", rule_id, rule_desc);
        let _ = store.insert_sigma_alert(
            &sigma_rule_id,
            severity,
            &title,
            agent_name,
            src_ip,
            username,
        ).await;
        result.alerts_imported += 1;

        // HIGH/CRITICAL security events also create a finding (deduplicated by rule+asset)
        // This ensures the Intelligence Engine sees them and can escalate to investigation.
        if rule_level >= 10 {
            let finding_title = format!("[Wazuh {}] {}", rule_id, rule_desc);
            let _ = store.insert_finding(&NewFinding {
                skill_id: "skill-wazuh".into(),
                title: finding_title,
                description: Some(format!("Agent: {} ({})\nSource IP: {}\nUser: {}\nTimestamp: {}",
                    agent_name, agent_ip, src_ip.unwrap_or("N/A"), username.unwrap_or("N/A"), timestamp)),
                severity: severity.to_uppercase(),
                category: Some("wazuh-security".into()),
                asset: Some(agent_name.into()),
                source: Some("Wazuh SIEM".into()),
                metadata: Some(serde_json::json!({
                    "wazuh_rule_id": rule_id, "rule_level": rule_level,
                    "source_ip": src_ip, "username": username,
                })),
            }).await;
            result.findings_created += 1;
        }
    }
}

/// Fetch Wazuh alerts from OpenSearch/Elasticsearch indexer.
/// Makes two queries: first HIGH+ (level >= 10), then the rest (level 7-9),
/// to ensure critical alerts are never lost due to pagination.
async fn fetch_alerts_from_indexer(
    client: &Client,
    config: &WazuhConfig,
    indexer_url: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let base = indexer_url.trim_end_matches('/');
    let search_url = format!("{}/wazuh-alerts-*/_search", base);
    let indexer_user = config.indexer_username.as_deref().unwrap_or("admin");
    let indexer_pass = config.indexer_password.as_deref().unwrap_or("admin");

    let mut all_alerts = Vec::new();

    // Query 1: HIGH/CRITICAL alerts (level >= 10) — never miss these
    let query_high = serde_json::json!({
        "size": 100,
        "sort": [{ "timestamp": { "order": "desc" } }],
        "query": { "bool": { "filter": [
            { "range": { "rule.level": { "gte": 10 } } },
            { "range": { "timestamp": { "gte": "now-24h" } } }
        ]}}
    });

    if let Ok(resp) = client.post(&search_url)
        .basic_auth(indexer_user, Some(indexer_pass))
        .header("Content-Type", "application/json")
        .json(&query_high)
        .timeout(Duration::from_secs(15))
        .send().await
    {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(hits) = body["hits"]["hits"].as_array() {
                    for hit in hits {
                        if let Some(src) = hit["_source"].as_object() {
                            all_alerts.push(serde_json::Value::Object(src.clone()));
                        }
                    }
                    if !all_alerts.is_empty() {
                        tracing::info!("WAZUH INDEXER: {} HIGH+ alerts (level >= 10)", all_alerts.len());
                    }
                }
            }
        }
    }

    // Query 2: Medium alerts (level 7-9) — bulk of the alerts
    let remaining = config.max_alerts.saturating_sub(all_alerts.len() as u32);
    let query_medium = serde_json::json!({
        "size": remaining,
        "sort": [{ "timestamp": { "order": "desc" } }],
        "query": { "bool": { "filter": [
            { "range": { "rule.level": { "gte": 7, "lt": 10 } } },
            { "range": { "timestamp": { "gte": "now-24h" } } }
        ]}}
    });

    let resp = client.post(&search_url)
        .basic_auth(indexer_user, Some(indexer_pass))
        .header("Content-Type", "application/json")
        .json(&query_medium)
        .timeout(Duration::from_secs(30))
        .send().await
        .map_err(|e| format!("Indexer request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Indexer HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("Indexer parse: {}", e))?;

    if let Some(hits) = body["hits"]["hits"].as_array() {
        for hit in hits {
            if let Some(src) = hit["_source"].as_object() {
                all_alerts.push(serde_json::Value::Object(src.clone()));
            }
        }
    }

    tracing::info!("WAZUH INDEXER: {} alerts fetched (level >= 7, last 24h)", all_alerts.len());
    Ok(all_alerts)
}
