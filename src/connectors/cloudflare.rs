//! Cloudflare WAF Connector — import WAF events via GraphQL Analytics API.
//!
//! Auth: Bearer token with Analytics:Read permission
//! Endpoint: POST https://api.cloudflare.com/client/v4/graphql
//! WAF events via firewallEventsAdaptive dataset (GraphQL only, no REST).

use crate::db::Database;
use crate::db::threatclaw_store::{ThreatClawStore, NewFinding};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const GRAPHQL_URL: &str = "https://api.cloudflare.com/client/v4/graphql";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    pub api_token: String,
    pub zone_id: String,
    #[serde(default = "default_limit")]
    pub max_events: u32,
}

fn default_limit() -> u32 { 100 }

#[derive(Debug, Clone, Serialize)]
pub struct CloudflareSyncResult {
    pub events_imported: usize,
    pub alerts_created: usize,
    pub top_blocked_ips: Vec<String>,
    pub errors: Vec<String>,
}

pub async fn sync_cloudflare(store: &dyn Database, config: &CloudflareConfig) -> CloudflareSyncResult {
    let mut result = CloudflareSyncResult {
        events_imported: 0, alerts_created: 0, top_blocked_ips: vec![], errors: vec![],
    };

    if config.api_token.is_empty() || config.zone_id.is_empty() {
        result.errors.push("Cloudflare API token and Zone ID required".into());
        return result;
    }

    let client = reqwest::Client::new();

    // Get events from last sync (default: last 15 min)
    let since = chrono::Utc::now() - chrono::Duration::minutes(15);
    let since_str = since.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let query = format!(
        r#"{{ viewer {{ zones(filter: {{zoneTag: "{}"}}) {{ firewallEventsAdaptive(filter: {{datetime_geq: "{}"}}, limit: {}, orderBy: [datetime_DESC]) {{ action clientIP clientCountryName clientRequestPath clientRequestQuery source userAgent datetime ruleId }} }} }} }}"#,
        config.zone_id, since_str, config.max_events
    );

    let resp = match client.post(GRAPHQL_URL)
        .header("Authorization", format!("Bearer {}", config.api_token))
        .json(&serde_json::json!({"query": query}))
        .timeout(Duration::from_secs(30))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Cloudflare request: {}", e)); return result; }
    };

    if !resp.status().is_success() {
        result.errors.push(format!("Cloudflare HTTP {}", resp.status()));
        return result;
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => { result.errors.push(format!("Cloudflare parse: {}", e)); return result; }
    };

    // Check for GraphQL errors
    if let Some(errors) = body["errors"].as_array() {
        if !errors.is_empty() {
            let msg = errors.iter()
                .filter_map(|e| e["message"].as_str())
                .collect::<Vec<_>>()
                .join("; ");
            result.errors.push(format!("Cloudflare GraphQL: {}", msg));
            return result;
        }
    }

    let events = match body["data"]["viewer"]["zones"].as_array()
        .and_then(|zones| zones.first())
        .and_then(|zone| zone["firewallEventsAdaptive"].as_array())
    {
        Some(e) => e,
        None => { return result; }
    };

    let mut ip_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    for event in events {
        let action = event["action"].as_str().unwrap_or("");
        let client_ip = event["clientIP"].as_str().unwrap_or("unknown");
        let path = event["clientRequestPath"].as_str().unwrap_or("");
        let country = event["clientCountryName"].as_str().unwrap_or("");
        let source = event["source"].as_str().unwrap_or("");
        let datetime = event["datetime"].as_str().unwrap_or("");
        let user_agent = event["userAgent"].as_str().unwrap_or("");

        result.events_imported += 1;

        // Count blocked IPs for aggregation
        if action == "block" || action == "challenge" || action == "jschallenge" {
            *ip_counts.entry(client_ip.to_string()).or_insert(0) += 1;
        }

        // Create alert for block/challenge actions
        if action == "block" || action == "drop" {
            let level = if path.contains("wp-login") || path.contains("xmlrpc") || path.contains("/admin") {
                "high"
            } else {
                "medium"
            };

            let title = format!("Cloudflare WAF: {} {} from {} ({})", action, path, client_ip, country);
            let description = format!(
                "Source: {}\nPath: {}\nUser-Agent: {}\nTime: {}",
                source, path, user_agent, datetime
            );

            if let Err(e) = store.insert_sigma_alert(
                &format!("cf-{}", action), level, &title, "", Some(client_ip), None,
            ).await {
                result.errors.push(format!("Insert alert: {}", e));
            } else {
                result.alerts_created += 1;
            }
        }
    }

    // Top blocked IPs
    let mut sorted_ips: Vec<(String, u32)> = ip_counts.into_iter().collect();
    sorted_ips.sort_by(|a, b| b.1.cmp(&a.1));
    result.top_blocked_ips = sorted_ips.iter().take(5)
        .map(|(ip, count)| format!("{} ({}x)", ip, count))
        .collect();

    // If a single IP has > 50 blocks in 15 min, create a high-severity alert
    for (ip, count) in &sorted_ips {
        if *count >= 50 {
            let title = format!("Brute force detected via Cloudflare: {} ({} blocks in 15 min)", ip, count);
            let _ = store.insert_sigma_alert("cf-brute-force", "high", &title, "", Some(ip.as_str()), None).await;
        }
    }

    tracing::info!(
        "CLOUDFLARE: {} events imported, {} alerts created, top IPs: {:?}",
        result.events_imported, result.alerts_created, result.top_blocked_ips
    );

    result
}
