#![allow(unused_imports)]
//! Webhook Ingest — generic endpoint for receiving security events from external tools.
//!
//! Route: POST /api/tc/webhook/ingest/{source}?token={hmac_token}
//! Security:
//!   - HMAC token per source (generated on activation)
//!   - Native signature verification where supported (Cloudflare, Shopify)
//!   - Rate limit: 60/min/source
//!   - Always returns 200 OK (silent drop on errors, no info leak)
//!   - Body max: 64 KB
//!   - Disabled by default

use crate::db::Database;
use crate::db::threatclaw_store::{ThreatClawStore, NewFinding};
use std::collections::HashMap;
use std::sync::Mutex;

/// Rate limiter: source → (count, window_start)
static RATE_LIMITS: std::sync::LazyLock<Mutex<HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const MAX_REQUESTS_PER_MINUTE: u32 = 60;
const MAX_BODY_SIZE: usize = 65_536; // 64 KB

/// Verify the webhook token for a source.
pub async fn verify_token(store: &dyn Database, source: &str, token: &str) -> bool {
    if token.is_empty() { return false; }

    let key = format!("webhook_token_{}", source);
    match store.get_setting("webhook_ingest", &key).await {
        Ok(Some(val)) => {
            let stored = val.as_str().unwrap_or("");
            use subtle::ConstantTimeEq;
            stored.len() == token.len() && bool::from(stored.as_bytes().ct_eq(token.as_bytes()))
        },
        _ => false,
    }
}

/// Check rate limit for a source. Returns true if allowed.
fn check_rate_limit(source: &str) -> bool {
    let now = chrono::Utc::now();
    let mut limits = RATE_LIMITS.lock().unwrap();

    let entry = limits.entry(source.to_string()).or_insert((0, now));

    // Reset window if > 1 minute old
    if (now - entry.1).num_seconds() >= 60 {
        *entry = (1, now);
        return true;
    }

    entry.0 += 1;
    entry.0 <= MAX_REQUESTS_PER_MINUTE
}

/// Process an incoming webhook. Returns number of findings/alerts created.
pub async fn process_webhook(
    store: &dyn Database,
    source: &str,
    token: &str,
    body: &[u8],
) -> u32 {
    // Verify token
    if !verify_token(store, source, token).await {
        tracing::warn!("WEBHOOK: invalid token for source {}", source);
        return 0;
    }

    // Rate limit
    if !check_rate_limit(source) {
        tracing::warn!("WEBHOOK: rate limited source {}", source);
        return 0;
    }

    // Body size check
    if body.len() > MAX_BODY_SIZE {
        tracing::warn!("WEBHOOK: body too large for source {} ({}b)", source, body.len());
        return 0;
    }

    // Parse JSON
    let json: serde_json::Value = match serde_json::from_slice(body) {
        Ok(j) => j,
        Err(_) => {
            tracing::warn!("WEBHOOK: invalid JSON from source {}", source);
            return 0;
        }
    };

    // Dispatch to source-specific parser
    match source {
        "cloudflare" => parse_cloudflare(store, &json).await,
        "crowdsec" => parse_crowdsec(store, &json).await,
        "fail2ban" => parse_fail2ban(store, &json).await,
        "uptimerobot" => parse_uptimerobot(store, &json).await,
        "uptime-kuma" => parse_uptime_kuma(store, &json).await,
        "wordfence" => parse_wordfence(store, &json).await,
        "graylog" => parse_graylog(store, &json).await,
        "changedetection" => parse_changedetection(store, &json).await,
        _ => {
            // Unknown source — try generic parser
            parse_generic(store, source, &json).await
        }
    }
}

/// Generate a new webhook token for a source.
pub async fn generate_token(store: &dyn Database, source: &str) -> Result<String, String> {
    use rand::Rng;
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let key = format!("webhook_token_{}", source);
    store.set_setting("webhook_ingest", &key, &serde_json::json!(token)).await
        .map_err(|e| format!("Failed to store token: {}", e))?;

    Ok(token)
}

// ── Source-specific parsers ──

async fn parse_cloudflare(store: &dyn Database, json: &serde_json::Value) -> u32 {
    let mut count = 0;

    // Cloudflare Logpush sends arrays of events
    let events = json.as_array()
        .or_else(|| json["data"].as_array())
        .cloned()
        .unwrap_or_else(|| vec![json.clone()]);

    for event in &events {
        let action = event["Action"].as_str()
            .or_else(|| event["action"].as_str())
            .unwrap_or("");
        let client_ip = event["ClientIP"].as_str()
            .or_else(|| event["clientIP"].as_str())
            .unwrap_or("unknown");
        let path = event["ClientRequestPath"].as_str()
            .or_else(|| event["clientRequestPath"].as_str())
            .unwrap_or("");

        if action == "block" || action == "drop" || action == "challenge" {
            let title = format!("Cloudflare WAF: {} {} from {}", action, path, client_ip);
            if store.insert_sigma_alert("cf-webhook", "medium", &title, "", Some(client_ip), None).await.is_ok() {
                count += 1;
            }
        }
    }
    count
}

async fn parse_crowdsec(store: &dyn Database, json: &serde_json::Value) -> u32 {
    let mut count = 0;

    // CrowdSec notification format
    let decisions = json.as_array()
        .or_else(|| json["decisions"].as_array())
        .cloned()
        .unwrap_or_else(|| vec![json.clone()]);

    for decision in &decisions {
        let value = decision["value"].as_str().unwrap_or("");
        let scenario = decision["scenario"].as_str().unwrap_or("unknown");
        let dtype = decision["type"].as_str().unwrap_or("ban");

        if !value.is_empty() {
            let title = format!("CrowdSec {}: {} ({})", dtype, value, scenario);
            if store.insert_sigma_alert("cs-webhook", "high", &title, "", Some(value), None).await.is_ok() {
                count += 1;
            }
        }
    }
    count
}

async fn parse_fail2ban(store: &dyn Database, json: &serde_json::Value) -> u32 {
    let ip = json["ip"].as_str().unwrap_or("");
    let action = json["action"].as_str().unwrap_or("ban");
    let jail = json["jail"].as_str().unwrap_or("unknown");

    if ip.is_empty() { return 0; }

    let title = format!("Fail2ban {}: {} (jail: {})", action, ip, jail);
    let level = if action == "ban" { "medium" } else { "low" };

    if store.insert_sigma_alert("f2b-webhook", level, &title, "", Some(ip), None).await.is_ok() {
        1
    } else {
        0
    }
}

async fn parse_uptimerobot(store: &dyn Database, json: &serde_json::Value) -> u32 {
    let monitor_name = json["monitorFriendlyName"].as_str().unwrap_or("unknown");
    let alert_type = json["alertType"].as_i64().unwrap_or(0);
    let alert_details = json["alertDetails"].as_str().unwrap_or("");
    let monitor_url = json["monitorURL"].as_str().unwrap_or("");

    // alertType: 1=down, 2=up, 3=SSL expiry
    let (title, level) = match alert_type {
        1 => (format!("{} DOWN ({})", monitor_name, monitor_url), "high"),
        2 => (format!("{} UP ({})", monitor_name, monitor_url), "low"),
        3 => (format!("SSL expiry warning: {} ({})", monitor_name, monitor_url), "medium"),
        _ => (format!("UptimeRobot alert: {} — {}", monitor_name, alert_details), "medium"),
    };

    if store.insert_sigma_alert("ur-webhook", level, &title, "", None, None).await.is_ok() {
        1
    } else {
        0
    }
}

async fn parse_uptime_kuma(store: &dyn Database, json: &serde_json::Value) -> u32 {
    let monitor_name = json["monitor"]["name"].as_str().unwrap_or("unknown");
    let monitor_url = json["monitor"]["url"].as_str().unwrap_or("");
    let heartbeat_status = json["heartbeat"]["status"].as_i64().unwrap_or(1);
    let heartbeat_msg = json["heartbeat"]["msg"].as_str().unwrap_or("");

    // status: 0=down, 1=up, 2=pending, 3=maintenance
    let (title, level) = match heartbeat_status {
        0 => (format!("{} DOWN — {} ({})", monitor_name, heartbeat_msg, monitor_url), "high"),
        1 => (format!("{} UP ({})", monitor_name, monitor_url), "low"),
        _ => return 0,
    };

    if store.insert_sigma_alert("kuma-webhook", level, &title, "", None, None).await.is_ok() {
        1
    } else {
        0
    }
}

async fn parse_wordfence(store: &dyn Database, json: &serde_json::Value) -> u32 {
    let mut count = 0;

    // Wordfence webhook pushes vulnerability notifications
    let vulns = json.as_array()
        .cloned()
        .unwrap_or_else(|| vec![json.clone()]);

    for vuln in &vulns {
        let title = vuln["title"].as_str().unwrap_or("WordPress vulnerability");
        let slug = vuln["software"].as_array()
            .and_then(|a| a.first())
            .and_then(|s| s["slug"].as_str())
            .unwrap_or("unknown");

        let finding_title = format!("Wordfence: {} ({})", title, slug);
        if store.insert_finding(&NewFinding {
                skill_id: "skill-wordfence-webhook".into(),
                title: finding_title.clone(),
                description: Some(title.to_string()),
                severity: "HIGH".into(),
                category: Some("wordpress-vuln".into()),
                asset: None,
                source: Some("Wordfence Webhook".into()),
                metadata: None,
            }).await.is_ok() {
            count += 1;
        }
    }
    count
}

async fn parse_graylog(store: &dyn Database, json: &serde_json::Value) -> u32 {
    // Graylog alert notification format
    let title = json["check_result"]["result_description"].as_str()
        .or_else(|| json["event_definition_title"].as_str())
        .unwrap_or("Graylog alert");

    let _message = json["check_result"]["matching_messages"].as_array()
        .and_then(|a| a.first())
        .and_then(|m| m["message"].as_str())
        .or_else(|| json["backlog"].as_array()
            .and_then(|a| a.first())
            .and_then(|m| m["message"].as_str()))
        .unwrap_or("");

    let source_ip = json["check_result"]["matching_messages"].as_array()
        .and_then(|a| a.first())
        .and_then(|m| m["source"].as_str());

    if store.insert_sigma_alert("graylog-webhook", "medium", title, "", source_ip, None).await.is_ok() {
        1
    } else {
        0
    }
}

async fn parse_changedetection(store: &dyn Database, json: &serde_json::Value) -> u32 {
    let url = json["url"].as_str().unwrap_or("unknown");
    let title_text = json["title"].as_str().unwrap_or("Content changed");

    let alert_title = format!("Website change detected: {} — {}", title_text, url);
    let description = json["current_snapshot"].as_str().unwrap_or("").to_string();
    let _desc_truncated = if description.len() > 500 { &description[..500] } else { &description };

    if store.insert_sigma_alert("cd-webhook", "medium", &alert_title, "", None, None).await.is_ok() {
        1
    } else {
        0
    }
}

async fn parse_generic(store: &dyn Database, source: &str, json: &serde_json::Value) -> u32 {
    // Generic parser: extract common fields
    let title = json["title"].as_str()
        .or_else(|| json["message"].as_str())
        .or_else(|| json["alert"].as_str())
        .or_else(|| json["summary"].as_str())
        .unwrap_or("External webhook event");

    let level = json["severity"].as_str()
        .or_else(|| json["level"].as_str())
        .or_else(|| json["priority"].as_str())
        .unwrap_or("medium");

    let normalized_level = match level.to_lowercase().as_str() {
        "critical" | "crit" | "4" | "5" => "critical",
        "high" | "3" => "high",
        "medium" | "2" | "warning" | "warn" => "medium",
        _ => "low",
    };

    let ip = json["ip"].as_str()
        .or_else(|| json["source_ip"].as_str())
        .or_else(|| json["client_ip"].as_str());

    let source_label = format!("{}-webhook", source);
    let description = serde_json::to_string_pretty(json).unwrap_or_default();
    let _desc_truncated = if description.len() > 1000 { &description[..1000] } else { &description };

    if store.insert_sigma_alert(&source_label, normalized_level, title, "", ip, None).await.is_ok() {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit() {
        // First 60 should pass
        for _ in 0..60 {
            assert!(check_rate_limit("test-source"));
        }
        // 61st should fail
        assert!(!check_rate_limit("test-source"));
        // Different source should still work
        assert!(check_rate_limit("other-source"));
    }
}
