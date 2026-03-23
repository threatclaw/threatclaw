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
        if check("mattermost", "webhookUrl") { configured.push("mattermost".into()); }
        if check("ntfy", "topic") { configured.push("ntfy".into()); }
        if check("gotify", "appToken") { configured.push("gotify".into()); }
        if check("email", "host") { configured.push("email".into()); }
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
        _ => Err(format!("Channel {} not implemented for routing", channel)),
    }
}

/// Get a field from channel config in DB.
async fn get_channel_field(store: &dyn Database, channel: &str, field: &str) -> Option<String> {
    let channels = store.get_setting("_system", "tc_config_channels").await.ok()??;
    channels[channel][field].as_str().filter(|s| !s.trim().is_empty()).map(String::from)
}
