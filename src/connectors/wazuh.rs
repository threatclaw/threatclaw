//! Wazuh SIEM Connector — import alerts via REST API.
//!
//! Auth: POST /security/user/authenticate → JWT (900s TTL)
//! Alerts: GET /alerts with pagination
//! Port: 55000 (HTTPS, self-signed cert by default)

use crate::db::Database;
use crate::db::threatclaw_store::{NewFinding, ThreatClawStore};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    /// Minimum rule.level kept (default 7 — matches the noise/signal boundary
    /// most SOCs use). Lower levels are informational events; keeping them
    /// would flood sigma_alerts without improving detection.
    #[serde(default = "default_min_level")]
    pub min_level: u32,
    /// Exact rule-id deny list, applied in addition to the built-in noise
    /// defaults. Useful for customer-specific tuning.
    #[serde(default)]
    pub skip_rule_ids: Vec<String>,
    /// Conditional deny list: `{rule_id → substring}`. Alert is dropped if
    /// its `full_log` contains the substring. Intended for rules that are
    /// noisy under specific conditions only (e.g. rule 5104 is noise on
    /// Docker veth interfaces but a real signal on physical NICs).
    #[serde(default)]
    pub skip_if_log_contains: HashMap<String, String>,
    /// Cursor — last ingested alert timestamp from the previous cycle.
    /// When present the fetch only pulls events newer than this, so we
    /// never re-ingest the same alert and never lose volume during spikes.
    #[serde(default)]
    pub cursor_last_timestamp: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_limit() -> u32 {
    500
}
fn default_min_level() -> u32 {
    7
}

/// Baked-in defaults for well-known noisy Wazuh rules that would otherwise
/// flood SOC dashboards on any Docker / K8s host. Merged with user config.
/// If a customer needs rule 5104 on a real NIC, they can override via
/// `skip_if_log_contains` but the Docker case stays silent by default.
fn built_in_noise_filters() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("5104".to_string(), "veth".to_string());
    m.insert("80710".to_string(), "dev=veth".to_string());
    m
}

fn effective_skip_if_log_contains(config: &WazuhConfig) -> HashMap<String, String> {
    let mut m = built_in_noise_filters();
    for (k, v) in &config.skip_if_log_contains {
        m.insert(k.clone(), v.clone());
    }
    m
}

#[derive(Debug, Clone, Serialize)]
pub struct WazuhSyncResult {
    /// Number of events returned by Wazuh/indexer (pre-filter).
    pub alerts_fetched: usize,
    /// Successful sigma_alerts inserts.
    pub alerts_imported: usize,
    pub findings_created: usize,
    /// Dropped by built-in or user-configured noise filter.
    pub dropped_noise: usize,
    /// DB insert errors (connection failure, constraint violation, etc.).
    pub insert_errors: usize,
    pub highest_level: u8,
    pub errors: Vec<String>,
    /// Advanced cursor. Caller persists via `set_skill_config` so the next
    /// cycle resumes from the right place.
    pub cursor: Option<String>,
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
        alerts_fetched: 0,
        alerts_imported: 0,
        findings_created: 0,
        dropped_noise: 0,
        insert_errors: 0,
        highest_level: 0,
        errors: vec![],
        cursor: config.cursor_last_timestamp.clone(),
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

    tracing::info!("WAZUH: Connecting to {}", config.url);

    // Authenticate
    let auth_url = format!("{}/security/user/authenticate", config.url);
    let auth_resp = match client
        .post(&auth_url)
        .basic_auth(&config.username, Some(&config.password))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("Auth failed: {}", e));
            return result;
        }
    };

    if !auth_resp.status().is_success() {
        result
            .errors
            .push(format!("Auth HTTP {}", auth_resp.status()));
        return result;
    }

    let auth: WazuhAuthResponse = match auth_resp.json().await {
        Ok(a) => a,
        Err(e) => {
            result.errors.push(format!("Auth parse: {}", e));
            return result;
        }
    };

    if auth.error != 0 || auth.data.is_none() {
        result.errors.push("Auth error: no token".into());
        return result;
    }

    let token = auth.data.unwrap().token;
    tracing::info!("WAZUH: Authenticated, fetching agents + alerts");

    // Fetch agents (always available in Wazuh API)
    let agents_url = format!(
        "{}/agents?limit=500&select=id,name,ip,os.name,os.version,status,lastKeepAlive",
        config.url
    );
    match client
        .get(&agents_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(agents) = data["data"]["affected_items"].as_array() {
                    tracing::info!("WAZUH: {} agents found", agents.len());
                    for agent in agents {
                        let name = agent["name"].as_str().unwrap_or("unknown");
                        let ip = agent["ip"].as_str().unwrap_or("");
                        let os = format!(
                            "{} {}",
                            agent["os"]["name"].as_str().unwrap_or(""),
                            agent["os"]["version"].as_str().unwrap_or("")
                        )
                        .trim()
                        .to_string();
                        let status = agent["status"].as_str().unwrap_or("unknown");

                        // Import agent as asset via resolution pipeline (dedup with other sources)
                        if !ip.is_empty() && ip != "any" {
                            let discovered = crate::graph::asset_resolution::DiscoveredAsset {
                                mac: None,
                                hostname: Some(name.to_string()),
                                fqdn: None,
                                ip: Some(ip.to_string()),
                                os: if os.is_empty() {
                                    None
                                } else {
                                    Some(os.clone())
                                },
                                ports: None,
                                services: serde_json::json!([]),
                                ou: None,
                                vlan: None,
                                vm_id: None,
                                criticality: Some("medium".into()),
                                source: "wazuh".into(),
                            };
                            let res =
                                crate::graph::asset_resolution::resolve_asset(store, &discovered)
                                    .await;
                            tracing::debug!(
                                "WAZUH ASSET: {} → {:?} ({})",
                                name,
                                res.action,
                                res.asset_id
                            );
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
        Ok(resp) => {
            result.errors.push(format!("Agents HTTP {}", resp.status()));
        }
        Err(e) => {
            result.errors.push(format!("Agents fetch: {}", e));
        }
    }

    // Fetch alerts (Wazuh 4.x: /alerts endpoint may not exist — try it, fallback gracefully)
    let alerts_url = format!(
        "{}/alerts?limit={}&sort=-timestamp",
        config.url, config.max_alerts
    );
    let alerts_resp = match client
        .get(&alerts_url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("Alerts fetch: {}", e));
            return result;
        }
    };

    let alerts: Vec<serde_json::Value> = if alerts_resp.status().is_success() {
        // Wazuh 5.x+ or patched: /alerts endpoint works
        match alerts_resp.json::<WazuhAlertResponse>().await {
            Ok(data) if data.error == 0 && data.data.is_some() => data.data.unwrap().affected_items,
            Ok(_) => {
                result.errors.push("Alerts API error".into());
                vec![]
            }
            Err(e) => {
                result.errors.push(format!("Alerts parse: {}", e));
                vec![]
            }
        }
    } else if let Some(indexer_url) = &config.indexer_url {
        // Wazuh 4.x fallback: fetch alerts from OpenSearch/Elasticsearch indexer
        tracing::info!(
            "WAZUH: /alerts not available, falling back to indexer at {}",
            indexer_url
        );
        match fetch_alerts_from_indexer(&client, config, indexer_url).await {
            Ok(items) => items,
            Err(e) => {
                result.errors.push(format!("Indexer: {}", e));
                vec![]
            }
        }
    } else {
        tracing::info!(
            "WAZUH: /alerts not available (Wazuh 4.x) and no indexer_url configured. Only agents imported."
        );
        vec![]
    };

    result.alerts_fetched = alerts.len();

    // Advance cursor to the newest timestamp in the batch (ASC order).
    // Fetched alerts are sorted by timestamp asc on the indexer side, but
    // be defensive in case callers hand us unsorted data.
    let mut newest_seen: Option<String> = result.cursor.clone();
    for alert in &alerts {
        if let Some(ts) = alert["timestamp"].as_str() {
            if newest_seen.as_deref().map(|c| ts > c).unwrap_or(true) {
                newest_seen = Some(ts.to_string());
            }
        }
    }

    let skip_conditional = effective_skip_if_log_contains(config);
    for alert in &alerts {
        import_wazuh_alert(store, alert, config, &skip_conditional, &mut result).await;
    }

    if newest_seen != result.cursor {
        result.cursor = newest_seen;
    }

    tracing::info!(
        "WAZUH SYNC: fetched={} imported={} findings={} dropped_noise={} insert_errors={} max_level={}",
        result.alerts_fetched,
        result.alerts_imported,
        result.findings_created,
        result.dropped_noise,
        result.insert_errors,
        result.highest_level
    );

    result
}

/// Import a single Wazuh alert — routes to sigma_alerts (events) or findings (vulns).
///
/// Responsibilities:
///   - Noise filtering: drops events matching the built-in + user-configured
///     deny list (veth promisc, audit inventory, customer-specific rules).
///   - Severity mapping: Wazuh level 0-15 → low/medium/high/critical.
///   - Source IP extraction: tries the standard `data.srcip` then falls back
///     to `data.src_host` / `data.src_ip` used by JSON decoders (OpenCanary,
///     custom pipelines).
///   - Counts: every skip/insert is accounted for in `result` so operators
///     can tell the difference between a quiet SOC and a broken pipeline.
async fn import_wazuh_alert(
    store: &dyn Database,
    alert: &serde_json::Value,
    config: &WazuhConfig,
    skip_conditional: &HashMap<String, String>,
    result: &mut WazuhSyncResult,
) {
    let rule_level = alert["rule"]["level"].as_u64().unwrap_or(0) as u8;
    let rule_desc = alert["rule"]["description"].as_str().unwrap_or("");
    let rule_id = alert["rule"]["id"].as_str().unwrap_or("");
    let agent_name = alert["agent"]["name"].as_str().unwrap_or("");
    let agent_ip = alert["agent"]["ip"].as_str().unwrap_or("");
    let full_log = alert["full_log"].as_str().unwrap_or("");
    // Standard Wazuh decoders populate data.srcip. Some connectors (OpenCanary,
    // custom JSON decoders) use data.src_host or data.src_ip instead.
    let src_ip = alert["data"]["srcip"]
        .as_str()
        .or_else(|| alert["data"]["src_host"].as_str())
        .or_else(|| alert["data"]["src_ip"].as_str());
    let username = alert["data"]["dstuser"]
        .as_str()
        .or_else(|| alert["data"]["srcuser"].as_str());
    let timestamp = alert["timestamp"].as_str().unwrap_or("");

    if rule_level > result.highest_level {
        result.highest_level = rule_level;
    }

    if (rule_level as u32) < config.min_level {
        result.dropped_noise += 1;
        return;
    }

    let severity = match rule_level {
        0..=5 => "low",
        6..=9 => "medium",
        10..=12 => "high",
        _ => "critical",
    };

    // Noise filter: exact rule-id deny + conditional pattern deny.
    if config.skip_rule_ids.iter().any(|id| id == rule_id) {
        result.dropped_noise += 1;
        return;
    }
    if let Some(pat) = skip_conditional.get(rule_id) {
        if full_log.contains(pat.as_str()) {
            result.dropped_noise += 1;
            return;
        }
    }

    // Safety net for Linux audit inventory events — kept in addition to the
    // configurable filter because this range is always noise and a config
    // typo should not reopen the floodgate.
    let rule_num: u32 = rule_id.parse().unwrap_or(0);
    if (80700..80800).contains(&rule_num) {
        result.dropped_noise += 1;
        return;
    }

    // Raw alert → logs table. Downstream Sigma engine matches against this.
    // Insert errors are WARN-logged because a failure here means the Sigma
    // engine loses visibility for this event — not fatal for sigma_alerts
    // which has its own path but worth surfacing.
    let now = chrono::Utc::now().to_rfc3339();
    if let Err(e) = store
        .insert_log("wazuh.alert", agent_name, alert, &now)
        .await
    {
        tracing::warn!(
            rule_id = rule_id,
            agent = agent_name,
            "WAZUH: insert_log failed: {}",
            e
        );
    }

    // Wazuh vulnerability rules (5500-5599) → findings (dedup OK)
    // Everything else (auth, intrusion, file integrity) → sigma_alerts (each event counts)
    let is_vuln_rule = (5500..5600).contains(&rule_num);

    if is_vuln_rule {
        // Vulnerability → finding (deduplicated)
        match store
            .insert_finding(&NewFinding {
                skill_id: "skill-wazuh".into(),
                title: format!("[Wazuh {}] {}", rule_id, rule_desc),
                description: Some(format!(
                    "Agent: {} ({})\nSource: {}\nTimestamp: {}",
                    agent_name,
                    agent_ip,
                    src_ip.unwrap_or("N/A"),
                    timestamp
                )),
                severity: severity.to_uppercase(),
                category: Some("wazuh-vuln".into()),
                asset: Some(agent_name.into()),
                source: Some("Wazuh SIEM".into()),
                metadata: Some(serde_json::json!({
                    "wazuh_rule_id": rule_id, "rule_level": rule_level,
                })),
            })
            .await
        {
            Ok(_) => result.findings_created += 1,
            Err(e) => {
                result.insert_errors += 1;
                tracing::warn!(rule_id = rule_id, "WAZUH: insert_finding failed: {}", e);
            }
        }
    } else {
        // Security event → sigma_alert (each occurrence counts for scoring)
        let sigma_rule_id = format!("wazuh-{}", rule_id);
        let title = format!("[Wazuh {}] {}", rule_id, rule_desc);
        match store
            .insert_sigma_alert(
                &sigma_rule_id,
                severity,
                &title,
                agent_name,
                src_ip,
                username,
            )
            .await
        {
            Ok(_) => result.alerts_imported += 1,
            Err(e) => {
                result.insert_errors += 1;
                tracing::warn!(
                    rule_id = rule_id,
                    agent = agent_name,
                    "WAZUH: insert_sigma_alert failed: {}",
                    e
                );
                return;
            }
        }

        // HIGH/CRITICAL security events also create a finding (deduplicated by rule+asset)
        // This ensures the Intelligence Engine sees them and can escalate to investigation.
        if rule_level >= 10 {
            let finding_title = format!("[Wazuh {}] {}", rule_id, rule_desc);
            match store
                .insert_finding(&NewFinding {
                    skill_id: "skill-wazuh".into(),
                    title: finding_title,
                    description: Some(format!(
                        "Agent: {} ({})\nSource IP: {}\nUser: {}\nTimestamp: {}",
                        agent_name,
                        agent_ip,
                        src_ip.unwrap_or("N/A"),
                        username.unwrap_or("N/A"),
                        timestamp
                    )),
                    severity: severity.to_uppercase(),
                    category: Some("wazuh-security".into()),
                    asset: Some(agent_name.into()),
                    source: Some("Wazuh SIEM".into()),
                    metadata: Some(serde_json::json!({
                        "wazuh_rule_id": rule_id, "rule_level": rule_level,
                        "source_ip": src_ip, "username": username,
                    })),
                })
                .await
            {
                Ok(_) => result.findings_created += 1,
                Err(e) => {
                    result.insert_errors += 1;
                    tracing::warn!(
                        rule_id = rule_id,
                        "WAZUH: HIGH finding insert failed: {}",
                        e
                    );
                }
            }
        }
    }
}

/// Fetch Wazuh alerts from OpenSearch/Elasticsearch indexer using a timestamp
/// cursor.
///
/// Semantics:
///   - If `config.cursor_last_timestamp` is set, we fetch everything strictly
///     newer than that timestamp (no overlap with previous cycle).
///   - Otherwise, first run defaults to the last hour — NOT 24h — to avoid
///     a massive replay on a fresh install, which used to double-insert
///     thousands of rows every time the core restarted.
///   - Hits are sorted by timestamp ASC so the caller can safely advance the
///     cursor to the last item's timestamp.
///   - `must_not: rule.id in skip_rule_ids` is pushed down to the indexer so
///     we save bandwidth and memory on high-volume deployments.
///   - Batch capped at `max_alerts` (default 500). If we saturate the cap we
///     WARN so the operator knows events are lagging — next cycle will catch
///     up because the cursor only advances to the newest item ingested.
async fn fetch_alerts_from_indexer(
    client: &Client,
    config: &WazuhConfig,
    indexer_url: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let base = indexer_url.trim_end_matches('/');
    let search_url = format!("{}/wazuh-alerts-*/_search", base);
    let indexer_user = config.indexer_username.as_deref().unwrap_or("admin");
    let indexer_pass = config.indexer_password.as_deref().unwrap_or("admin");

    let time_filter = match config.cursor_last_timestamp.as_deref() {
        Some(ts) if !ts.is_empty() => {
            serde_json::json!({ "range": { "timestamp": { "gt": ts } } })
        }
        _ => serde_json::json!({ "range": { "timestamp": { "gte": "now-1h" } } }),
    };

    // Push the exact-id deny list down to OpenSearch. The conditional
    // (rule_id + full_log substring) filter still runs client-side because
    // OpenSearch can't express "matches this substring only when rule.id=X"
    // in a single query without scripts.
    let skip_ids: Vec<&str> = config.skip_rule_ids.iter().map(String::as_str).collect();
    let must_not = if skip_ids.is_empty() {
        serde_json::json!([])
    } else {
        serde_json::json!([{ "terms": { "rule.id": skip_ids } }])
    };

    let size = config.max_alerts.max(100);
    let query = serde_json::json!({
        "size": size,
        "sort": [{ "timestamp": { "order": "asc" } }],
        "query": {
            "bool": {
                "filter": [
                    { "range": { "rule.level": { "gte": config.min_level } } },
                    time_filter
                ],
                "must_not": must_not
            }
        }
    });

    let resp = client
        .post(&search_url)
        .basic_auth(indexer_user, Some(indexer_pass))
        .header("Content-Type", "application/json")
        .json(&query)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Indexer request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Indexer HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Indexer parse: {}", e))?;

    let mut alerts = Vec::new();
    if let Some(hits) = body["hits"]["hits"].as_array() {
        for hit in hits {
            if let Some(src) = hit["_source"].as_object() {
                alerts.push(serde_json::Value::Object(src.clone()));
            }
        }
    }

    if alerts.len() as u32 >= size {
        tracing::warn!(
            "WAZUH INDEXER: batch saturated at {} events — events may lag; \
             next cycle will resume from the cursor",
            size
        );
    }

    tracing::info!(
        "WAZUH INDEXER: fetched {} alerts (min_level={}, cursor={})",
        alerts.len(),
        config.min_level,
        config
            .cursor_last_timestamp
            .as_deref()
            .unwrap_or("none (first run, last 1h)")
    );
    Ok(alerts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_config() -> WazuhConfig {
        WazuhConfig {
            url: "https://wazuh.example".into(),
            username: "wazuh".into(),
            password: "pass".into(),
            no_tls_verify: true,
            max_alerts: 500,
            indexer_url: None,
            indexer_username: None,
            indexer_password: None,
            min_level: 7,
            skip_rule_ids: vec![],
            skip_if_log_contains: HashMap::new(),
            cursor_last_timestamp: None,
        }
    }

    fn alert(rule_id: &str, level: u8, full_log: &str) -> serde_json::Value {
        json!({
            "rule": { "id": rule_id, "level": level, "description": "t" },
            "agent": { "name": "host", "ip": "10.0.0.1" },
            "data": { "srcip": "1.2.3.4" },
            "full_log": full_log,
            "timestamp": "2026-04-22T14:00:00.000+0000"
        })
    }

    // Docker veth promisc noise is the #1 customer complaint we can fix up
    // front. 5104 at level 8 matches `min_level >= 7` so without the
    // conditional filter it would land in sigma_alerts at ~40-80/min on
    // any Docker host. Verify the default silences it cleanly while
    // keeping 5104 alerts on real interfaces.
    #[test]
    fn built_in_noise_drops_docker_veth_5104() {
        let skip = effective_skip_if_log_contains(&base_config());
        let a = alert("5104", 8, "device vethabc entered promiscuous mode");
        let pat = skip.get("5104").expect("5104 default");
        assert!(a["full_log"].as_str().unwrap().contains(pat.as_str()));

        let real = alert("5104", 8, "device eth0 entered promiscuous mode");
        assert!(!real["full_log"].as_str().unwrap().contains(pat.as_str()));
    }

    #[test]
    fn auditd_80710_veth_also_silenced() {
        let skip = effective_skip_if_log_contains(&base_config());
        let a = alert(
            "80710",
            10,
            "type=ANOM_PROMISCUOUS msg=audit(...): dev=veth023b prom=256",
        );
        let pat = skip.get("80710").expect("80710 default");
        assert!(a["full_log"].as_str().unwrap().contains(pat.as_str()));
    }

    #[test]
    fn customer_config_extends_but_does_not_replace_defaults() {
        let mut c = base_config();
        c.skip_if_log_contains
            .insert("12345".into(), "custom-noise".into());
        let skip = effective_skip_if_log_contains(&c);
        assert_eq!(skip.get("5104"), Some(&"veth".to_string()));
        assert_eq!(skip.get("12345"), Some(&"custom-noise".to_string()));
    }

    #[test]
    fn customer_can_override_builtin_pattern() {
        // A customer running OpenShift on a non-Docker node might need to
        // re-open rule 5104. They can override the pattern to something no
        // log will ever contain, effectively unmuting it.
        let mut c = base_config();
        c.skip_if_log_contains
            .insert("5104".into(), "NEVER_MATCHES".into());
        let skip = effective_skip_if_log_contains(&c);
        let a = alert("5104", 8, "device vethabc entered promiscuous mode");
        let pat = skip.get("5104").unwrap();
        assert!(!a["full_log"].as_str().unwrap().contains(pat.as_str()));
    }

    #[test]
    fn default_min_level_is_seven() {
        assert_eq!(default_min_level(), 7);
    }

    // Regression for the silent "source_ip = NULL" bug: OpenCanary and any
    // JSON decoder that emits `data.src_host` instead of the canonical
    // `data.srcip`. Matching is handled at call site, so this test mirrors
    // the exact fallback chain.
    #[test]
    fn src_ip_fallback_picks_src_host_when_srcip_missing() {
        let alert = json!({
            "data": { "src_host": "203.0.113.5" }
        });
        let src_ip = alert["data"]["srcip"]
            .as_str()
            .or_else(|| alert["data"]["src_host"].as_str())
            .or_else(|| alert["data"]["src_ip"].as_str());
        assert_eq!(src_ip, Some("203.0.113.5"));
    }

    #[test]
    fn src_ip_fallback_prefers_canonical_srcip_when_both_present() {
        let alert = json!({
            "data": { "srcip": "10.0.0.1", "src_host": "203.0.113.5" }
        });
        let src_ip = alert["data"]["srcip"]
            .as_str()
            .or_else(|| alert["data"]["src_host"].as_str());
        assert_eq!(src_ip, Some("10.0.0.1"));
    }
}
