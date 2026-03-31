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

                        // Import agent as asset
                        if !ip.is_empty() && ip != "any" {
                            use crate::db::threatclaw_store::NewAsset;
                            let asset = NewAsset {
                                id: format!("wazuh-{}", agent["id"].as_str().or(agent["id"].as_u64().map(|_| "")).unwrap_or(&name.replace(' ', "-"))),
                                name: name.to_string(),
                                category: "server".into(),
                                subcategory: None,
                                role: Some("Wazuh agent".into()),
                                criticality: "medium".into(),
                                ip_addresses: vec![ip.to_string()],
                                mac_address: None,
                                hostname: Some(name.to_string()),
                                fqdn: None,
                                url: None,
                                os: if os.is_empty() { None } else { Some(os.clone()) },
                                mac_vendor: None,
                                services: serde_json::json!([]),
                                source: "wazuh".into(),
                                owner: None,
                                location: None,
                                tags: vec!["wazuh-agent".into()],
                            };
                            let _ = store.upsert_asset(&asset).await;
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

/// Import a single Wazuh alert as a ThreatClaw finding
async fn import_wazuh_alert(store: &dyn Database, alert: &serde_json::Value, result: &mut WazuhSyncResult) {
    let rule_level = alert["rule"]["level"].as_u64().unwrap_or(0) as u8;
    let rule_desc = alert["rule"]["description"].as_str().unwrap_or("");
    let rule_id = alert["rule"]["id"].as_str().unwrap_or("");
    let agent_name = alert["agent"]["name"].as_str().unwrap_or("");
    let agent_ip = alert["agent"]["ip"].as_str().unwrap_or("");
    let src_ip = alert["data"]["srcip"].as_str();
    let timestamp = alert["timestamp"].as_str().unwrap_or("");

    if rule_level > result.highest_level { result.highest_level = rule_level; }

    // Only import level >= 7 (skip noise)
    if rule_level < 7 { return; }

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

/// Fetch Wazuh alerts from OpenSearch/Elasticsearch indexer
async fn fetch_alerts_from_indexer(
    client: &Client,
    config: &WazuhConfig,
    indexer_url: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let base = indexer_url.trim_end_matches('/');
    let search_url = format!("{}/wazuh-alerts-*/_search", base);

    let query = serde_json::json!({
        "size": config.max_alerts,
        "sort": [{ "timestamp": { "order": "desc" } }],
        "query": {
            "bool": {
                "filter": [
                    { "range": { "rule.level": { "gte": 7 } } },
                    { "range": { "timestamp": { "gte": "now-24h" } } }
                ]
            }
        }
    });

    let indexer_user = config.indexer_username.as_deref().unwrap_or("admin");
    let indexer_pass = config.indexer_password.as_deref().unwrap_or("admin");

    let resp = client.post(&search_url)
        .basic_auth(indexer_user, Some(indexer_pass))
        .header("Content-Type", "application/json")
        .json(&query)
        .timeout(Duration::from_secs(30))
        .send().await
        .map_err(|e| format!("Indexer request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Indexer HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("Indexer parse: {}", e))?;

    let hits = body["hits"]["hits"].as_array()
        .ok_or_else(|| "No hits in indexer response".to_string())?;

    let alerts: Vec<serde_json::Value> = hits.iter()
        .filter_map(|hit| hit["_source"].as_object().map(|o| serde_json::Value::Object(o.clone())))
        .collect();

    tracing::info!("WAZUH INDEXER: {} alerts fetched (level >= 7, last 24h)", alerts.len());
    Ok(alerts)
}
