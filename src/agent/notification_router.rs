//! Notification Router — dispatches alerts to the right channels based on RSSI preferences.
//!
//! The RSSI configures which channels receive which notification levels:
//!   - Silence → nothing (no channel)
//!   - Digest  → email, or telegram (1x/day)
//!   - Alert   → telegram + ntfy (immediate)
//!   - Critical → ALL configured channels (immediate + HITL)
//!
//! Configuration stored in DB as `tc_config_notification_routing`.
//! Default routing applied if no config exists.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::agent::intelligence_engine::NotificationLevel;
use crate::db::Database;

/// Notification routing configuration per level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRouting {
    pub digest: Vec<String>,    // channels for digest (e.g., ["email", "telegram"])
    pub alert: Vec<String>,     // channels for alert
    pub critical: Vec<String>,  // channels for critical
}

impl Default for NotificationRouting {
    fn default() -> Self {
        Self {
            digest: vec!["telegram".into()],
            alert: vec!["telegram".into()],
            critical: vec!["telegram".into(), "ntfy".into()],
        }
    }
}

/// Load notification routing config from DB, or use defaults.
pub async fn load_routing(store: &dyn Database) -> NotificationRouting {
    if let Ok(Some(val)) = store.get_setting("_system", "tc_config_notification_routing").await {
        if let Ok(routing) = serde_json::from_value(val) {
            return routing;
        }
    }
    NotificationRouting::default()
}

/// Save notification routing config to DB.
pub async fn save_routing(store: &dyn Database, routing: &NotificationRouting) -> Result<(), String> {
    let val = serde_json::to_value(routing).map_err(|e| e.to_string())?;
    store.set_setting("_system", "tc_config_notification_routing", &val).await
        .map_err(|e| e.to_string())
}

/// Route a notification to configured channels based on level.
pub async fn route_notification(
    store: &dyn Database,
    level: NotificationLevel,
    alert_message: &str,
    digest_message: &str,
) -> Vec<(String, Result<(), String>)> {
    let routing = load_routing(store).await;

    let channels = match level {
        NotificationLevel::Silence => return vec![],
        NotificationLevel::Digest => &routing.digest,
        NotificationLevel::Alert => &routing.alert,
        NotificationLevel::Critical => &routing.critical,
    };

    let message = if level == NotificationLevel::Digest { digest_message } else { alert_message };

    // Check which channels are actually configured
    let configured_channels = get_configured_channels(store).await;

    let mut results = vec![];
    for channel in channels {
        if !configured_channels.contains(channel) {
            tracing::debug!("NOTIF_ROUTER: Skipping {} — not configured", channel);
            continue;
        }

        let result = send_to_channel(store, channel, message, level).await;
        if let Err(ref e) = result {
            tracing::warn!("NOTIF_ROUTER: Failed to send to {}: {}", channel, e);
        } else {
            tracing::info!("NOTIF_ROUTER: Sent {:?} notification to {}", level, channel);
        }
        results.push((channel.clone(), result));
    }

    // Audit
    let _ = store.set_setting("_audit", &format!("notif_{}_{}", format!("{:?}", level).to_lowercase(), chrono::Utc::now().timestamp()), &json!({
        "level": format!("{:?}", level),
        "channels_attempted": channels,
        "channels_configured": configured_channels,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })).await;

    results
}

/// Get list of channels that have been configured (have tokens/URLs).
async fn get_configured_channels(store: &dyn Database) -> Vec<String> {
    let mut configured = vec![];

    if let Ok(Some(channels)) = store.get_setting("_system", "tc_config_channels").await {
        let check = |name: &str, key: &str| -> bool {
            channels[name]["enabled"].as_bool() == Some(true) &&
            channels[name][key].as_str().map(|s| !s.trim().is_empty()) == Some(true)
        };

        if check("telegram", "botToken") { configured.push("telegram".into()); }
        if check("slack", "botToken") { configured.push("slack".into()); }
        if check("discord", "botToken") { configured.push("discord".into()); }
        if check("mattermost", "webhookUrl") { configured.push("mattermost".into()); }
        if check("ntfy", "topic") { configured.push("ntfy".into()); }
        if check("gotify", "appToken") { configured.push("gotify".into()); }
        if check("email", "host") { configured.push("email".into()); }
        if check("signal", "account") { configured.push("signal".into()); }
        if check("whatsapp", "accessToken") { configured.push("whatsapp".into()); }
    }

    configured
}

/// Send a message to a specific channel.
async fn send_to_channel(
    store: &dyn Database,
    channel: &str,
    message: &str,
    _level: NotificationLevel,
) -> Result<(), String> {
    match channel {
        "telegram" => {
            let token = crate::channels::web::handlers::threatclaw_api::get_telegram_token(store).await
                .ok_or("Telegram token not configured")?;
            let chat_id = get_channel_field(store, "telegram", "chatId").await
                .ok_or("Telegram chat_id not configured")?;

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            let resp = client.post(format!("https://api.telegram.org/bot{}/sendMessage", token))
                .json(&json!({ "chat_id": chat_id.trim(), "text": message, "parse_mode": "Markdown" }))
                .send().await.map_err(|e| e.to_string())?;

            if resp.status().is_success() { Ok(()) }
            else { Err(format!("Telegram HTTP {}", resp.status())) }
        }
        "mattermost" => {
            let webhook_url = get_channel_field(store, "mattermost", "webhookUrl").await
                .ok_or("Mattermost webhook not configured")?;
            crate::integrations::mattermost_hitl::send_notification(
                &crate::integrations::mattermost_hitl::MattermostHitlConfig {
                    enabled: true, webhook_url, channel: String::new(), callback_url: String::new(),
                },
                message,
            ).await
        }
        "ntfy" => {
            let server = get_channel_field(store, "ntfy", "server").await.unwrap_or("https://ntfy.sh".into());
            let topic = get_channel_field(store, "ntfy", "topic").await
                .ok_or("Ntfy topic not configured")?;
            crate::integrations::ntfy_hitl::send_notification(
                &crate::integrations::ntfy_hitl::NtfyHitlConfig {
                    enabled: true, server_url: server, topic,
                    callback_url: String::new(), auth_token: None,
                },
                "ThreatClaw Alerte", message, "high",
            ).await
        }
        "gotify" => {
            let url = get_channel_field(store, "gotify", "url").await
                .ok_or("Gotify URL not configured")?;
            let token = get_channel_field(store, "gotify", "appToken").await
                .ok_or("Gotify token not configured")?;
            crate::integrations::gotify_notify::send_notification(
                &crate::integrations::gotify_notify::GotifyConfig { enabled: true, server_url: url, app_token: token },
                "ThreatClaw", message, "high",
            ).await
        }
        "slack" => {
            let token = get_channel_field(store, "slack", "botToken").await
                .ok_or("Slack bot token not configured")?;
            // Use Slack chat.postMessage API — need a default channel
            // Slack requires a channel ID or name. Use #general as fallback.
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            let resp = client.post("https://slack.com/api/chat.postMessage")
                .header("Authorization", format!("Bearer {}", token))
                .json(&json!({
                    "channel": "#general",
                    "text": message,
                    "unfurl_links": false,
                }))
                .send().await.map_err(|e| e.to_string())?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                if body["ok"].as_bool() == Some(true) { Ok(()) }
                else { Err(format!("Slack API error: {}", body["error"].as_str().unwrap_or("unknown"))) }
            } else { Err(format!("Slack HTTP {}", resp.status())) }
        }
        "discord" => {
            // Discord webhook — botToken field stores the webhook URL for notifications
            let webhook_url = get_channel_field(store, "discord", "botToken").await
                .ok_or("Discord webhook not configured")?;

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            let resp = client.post(&webhook_url)
                .json(&json!({
                    "content": message,
                    "username": "ThreatClaw",
                }))
                .send().await.map_err(|e| e.to_string())?;

            if resp.status().is_success() || resp.status().as_u16() == 204 { Ok(()) }
            else { Err(format!("Discord HTTP {}", resp.status())) }
        }
        "email" => {
            let host = get_channel_field(store, "email", "host").await
                .ok_or("Email SMTP host not configured")?;
            let port: u16 = get_channel_field(store, "email", "port").await
                .and_then(|p| p.parse().ok()).unwrap_or(587);
            let from = get_channel_field(store, "email", "from").await
                .ok_or("Email from address not configured")?;
            let to = get_channel_field(store, "email", "to").await
                .ok_or("Email to address not configured")?;

            // Use lettre crate for SMTP if available, otherwise raw TCP
            // For now, use a simple HTTP approach via a local sendmail or direct SMTP
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .danger_accept_invalid_certs(true)
                .build().map_err(|e| e.to_string())?;

            // Try SMTP via direct socket (minimal implementation)
            use std::io::{Read, Write};
            let addr = format!("{}:{}", host, port);
            match std::net::TcpStream::connect_timeout(&addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?, std::time::Duration::from_secs(10)) {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf); // Read greeting
                    let commands = [
                        format!("EHLO threatclaw\r\n"),
                        format!("MAIL FROM:<{}>\r\n", from),
                        format!("RCPT TO:<{}>\r\n", to),
                        "DATA\r\n".to_string(),
                        format!("From: ThreatClaw <{}>\r\nTo: {}\r\nSubject: ThreatClaw Security Alert\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n.\r\n", from, to, message),
                        "QUIT\r\n".to_string(),
                    ];
                    for cmd in &commands {
                        let _ = stream.write_all(cmd.as_bytes());
                        let _ = stream.read(&mut buf);
                    }
                    Ok(())
                }
                Err(e) => Err(format!("SMTP connection to {} failed: {}", addr, e)),
            }
        }
        "signal" => {
            let http_url = get_channel_field(store, "signal", "httpUrl").await
                .unwrap_or("http://localhost:8080".into());
            let account = get_channel_field(store, "signal", "account").await
                .ok_or("Signal account not configured")?;
            // Signal-cli REST API
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            let resp = client.post(format!("{}/v2/send", http_url))
                .json(&json!({
                    "message": message,
                    "number": account,
                    "recipients": [account],
                }))
                .send().await.map_err(|e| e.to_string())?;

            if resp.status().is_success() { Ok(()) }
            else { Err(format!("Signal HTTP {}", resp.status())) }
        }
        "whatsapp" => {
            let access_token = get_channel_field(store, "whatsapp", "accessToken").await
                .ok_or("WhatsApp access token not configured")?;
            let phone_id = get_channel_field(store, "whatsapp", "phoneNumberId").await
                .ok_or("WhatsApp phone number ID not configured")?;

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build().map_err(|e| e.to_string())?;

            let resp = client.post(format!("https://graph.facebook.com/v18.0/{}/messages", phone_id))
                .header("Authorization", format!("Bearer {}", access_token))
                .json(&json!({
                    "messaging_product": "whatsapp",
                    "to": phone_id,
                    "type": "text",
                    "text": { "body": message },
                }))
                .send().await.map_err(|e| e.to_string())?;

            if resp.status().is_success() { Ok(()) }
            else { Err(format!("WhatsApp HTTP {}", resp.status())) }
        }
        _ => Err(format!("Channel {} not implemented for routing", channel)),
    }
}

/// Get a field from channel config in DB.
async fn get_channel_field(store: &dyn Database, channel: &str, field: &str) -> Option<String> {
    let channels = store.get_setting("_system", "tc_config_channels").await.ok()??;
    channels[channel][field].as_str().filter(|s| !s.trim().is_empty()).map(String::from)
}

// ── V3: Route investigation verdict notifications ──

use crate::agent::incident_dossier::IncidentDossier;
use crate::agent::verdict::InvestigationResult;

/// Route a notification based on an investigation verdict (not an IE score).
pub async fn route_verdict_notification(
    store: &dyn Database,
    result: &InvestigationResult,
    dossier: &IncidentDossier,
) -> Vec<(String, Result<(), String>)> {
    let message = match result.format_telegram(dossier) {
        Some(msg) => msg,
        None => return vec![],
    };

    let level = match result.verdict.severity() {
        "CRITICAL" => NotificationLevel::Critical,
        "HIGH" => NotificationLevel::Alert,
        _ => NotificationLevel::Alert,
    };

    route_notification(store, level, &message, &message).await
}
