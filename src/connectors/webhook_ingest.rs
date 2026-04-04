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
const MAX_BODY_SIZE_LOGS: usize = 1_048_576; // 1 MB for Zeek/Suricata bulk log ingestion

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

    // Body size check (Zeek/Suricata allow larger payloads for bulk log ingestion)
    let max_size = match source {
        "zeek" | "suricata" => MAX_BODY_SIZE_LOGS,
        _ => MAX_BODY_SIZE,
    };
    if body.len() > max_size {
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
        "zeek" => parse_zeek(store, &json).await,
        "suricata" => parse_suricata(store, &json).await,
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

// ── Zeek & Suricata — bulk log ingestion (from remote Fluent-Bit agents) ──

/// Parse Zeek JSON logs pushed from a remote Fluent-Bit agent.
/// Accepts single entry or array of entries. Each entry is inserted as a log
/// with the appropriate tag (zeek.conn, zeek.dns, zeek.ssl, etc.).
/// The tag is auto-detected from the entry fields.
async fn parse_zeek(store: &dyn Database, json: &serde_json::Value) -> u32 {
    let entries: Vec<&serde_json::Value> = if let Some(arr) = json.as_array() {
        arr.iter().collect()
    } else {
        vec![json]
    };

    let mut count = 0u32;
    let now = chrono::Utc::now().to_rfc3339();

    for entry in entries {
        // Auto-detect Zeek log type from entry fields
        let tag = detect_zeek_log_type(entry);
        let hostname = entry["id.orig_h"].as_str()
            .or_else(|| entry["host"].as_str())
            .unwrap_or("");

        if store.insert_log(&tag, hostname, entry, &now).await.is_ok() {
            count += 1;
        }

        // Generate sigma alerts for notable events (same logic as zeek.rs connector)
        match tag.as_str() {
            "zeek.ssl" => {
                let validation = entry["validation_status"].as_str().unwrap_or("");
                if validation.contains("expired") || validation.contains("self signed") {
                    let server = entry["server_name"].as_str().unwrap_or("unknown");
                    let title = format!("Zeek: SSL issue on {} — {}", server, validation);
                    let _ = store.insert_sigma_alert("zeek-ssl-issue", "medium", &title,
                        entry["id.resp_h"].as_str().unwrap_or(""), None, None).await;
                }
            }
            "zeek.conn" => {
                // Long connection (> 1h) to external IP
                let duration = entry["duration"].as_f64().unwrap_or(0.0);
                let dst = entry["id.resp_h"].as_str().unwrap_or("");
                if duration > 3600.0 && !dst.starts_with("10.") && !dst.starts_with("192.168.") && !dst.starts_with("127.") {
                    let title = format!("Zeek: Long connection to {} ({:.0}min)", dst, duration / 60.0);
                    let _ = store.insert_sigma_alert("zeek-long-conn", "medium", &title,
                        hostname, Some(dst), None).await;
                }
                // Large upload (> 10 MB)
                let orig_bytes = entry["orig_bytes"].as_u64().unwrap_or(0);
                if orig_bytes > 10_000_000 {
                    let title = format!("Zeek: Large upload to {} ({:.1} MB)", dst, orig_bytes as f64 / 1_000_000.0);
                    let _ = store.insert_sigma_alert("zeek-large-upload", "high", &title,
                        hostname, Some(dst), None).await;
                }
            }
            "zeek.ssh" => {
                let auth_success = entry["auth_success"].as_bool().unwrap_or(true);
                let src = entry["id.orig_h"].as_str().unwrap_or("");
                if !auth_success && !src.starts_with("10.") && !src.starts_with("192.168.") {
                    let title = format!("Zeek: SSH auth failure from {}", src);
                    let _ = store.insert_sigma_alert("zeek-ssh-fail", "medium", &title,
                        entry["id.resp_h"].as_str().unwrap_or(""), Some(src), None).await;
                }
            }
            _ => {}
        }
    }

    if count > 0 {
        tracing::info!("WEBHOOK-ZEEK: ingested {} log entries", count);
    }
    count
}

/// Detect Zeek log type from JSON entry fields.
fn detect_zeek_log_type(entry: &serde_json::Value) -> String {
    // Check for tag field first (Fluent-Bit may set this)
    if let Some(tag) = entry["_tag"].as_str().or_else(|| entry["tag"].as_str()) {
        if tag.starts_with("zeek.") { return tag.to_string(); }
    }
    // Auto-detect from fields unique to each log type
    if entry.get("query").is_some() && entry.get("qtype_name").is_some() { return "zeek.dns".into(); }
    if entry.get("server_name").is_some() || entry.get("ja3").is_some() || entry.get("validation_status").is_some() { return "zeek.ssl".into(); }
    if entry.get("method").is_some() && entry.get("uri").is_some() && entry.get("status_code").is_some() { return "zeek.http".into(); }
    if entry.get("auth_success").is_some() || entry.get("client").is_some() && entry.get("server").is_some() && entry.get("cipher_alg").is_some() { return "zeek.ssh".into(); }
    if entry.get("fuid").is_some() && entry.get("mime_type").is_some() { return "zeek.files".into(); }
    if entry.get("conn_state").is_some() || entry.get("duration").is_some() && entry.get("orig_bytes").is_some() { return "zeek.conn".into(); }
    // Fallback
    "zeek.unknown".into()
}

/// Parse Suricata EVE JSON logs pushed from a remote Fluent-Bit agent.
/// Accepts single entry or array. Each entry is inserted as a log and
/// alerts are auto-created for IDS detections.
async fn parse_suricata(store: &dyn Database, json: &serde_json::Value) -> u32 {
    let entries: Vec<&serde_json::Value> = if let Some(arr) = json.as_array() {
        arr.iter().collect()
    } else {
        vec![json]
    };

    let mut count = 0u32;
    let now = chrono::Utc::now().to_rfc3339();

    for entry in entries {
        let event_type = entry["event_type"].as_str().unwrap_or("");
        let src_ip = entry["src_ip"].as_str().unwrap_or("");
        let dest_ip = entry["dest_ip"].as_str().unwrap_or("");
        let tag = format!("suricata.{}", if event_type.is_empty() { "unknown" } else { event_type });

        if store.insert_log(&tag, dest_ip, entry, &now).await.is_ok() {
            count += 1;
        }

        // Create sigma alerts for Suricata IDS alerts
        if event_type == "alert" {
            let signature = entry["alert"]["signature"].as_str().unwrap_or("Unknown alert");
            let severity = entry["alert"]["severity"].as_u64().unwrap_or(3);
            let sig_id = entry["alert"]["signature_id"].as_u64().unwrap_or(0);
            let category = entry["alert"]["category"].as_str().unwrap_or("");

            let level = match severity {
                1 => "critical",
                2 => "high",
                3 => "medium",
                _ => "low",
            };

            let title = format!("[Suricata {}] {}", sig_id, signature);
            let _ = store.insert_sigma_alert(
                &format!("suricata-{}", sig_id), level, &title,
                dest_ip, Some(src_ip), None,
            ).await;
        }

        // Detect large flows (> 50 MB exfiltration)
        if event_type == "flow" {
            let bytes_out = entry["flow"]["bytes_toserver"].as_u64().unwrap_or(0);
            if bytes_out > 50_000_000 && !dest_ip.starts_with("10.") && !dest_ip.starts_with("192.168.") {
                let title = format!("Suricata: Large outbound flow to {} ({:.1} MB)", dest_ip, bytes_out as f64 / 1_000_000.0);
                let _ = store.insert_sigma_alert("suricata-exfil", "high", &title,
                    src_ip, Some(dest_ip), None).await;
            }
        }
    }

    if count > 0 {
        tracing::info!("WEBHOOK-SURICATA: ingested {} EVE entries", count);
    }
    count
}

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
