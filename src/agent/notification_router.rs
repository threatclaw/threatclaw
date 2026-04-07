//! Notification Router — dispatches alerts to configured channels.

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

/// See ADR-043: Route an incident notification with HITL inline buttons.
pub async fn route_incident_notification(
    store: &dyn Database,
    incident_id: i32,
    asset: &str,
    title: &str,
    summary: &str,
    severity: &str,
    alert_count: i32,
) -> Vec<(String, Result<(), String>)> {
    let routing = load_routing(store).await;
    let configured = get_configured_channels(store).await;
    let channels = &routing.alert;

    let summary_clean = if summary.is_empty() { "Investigation en cours...".to_string() }
        else { summary.replace("Confirmed { ", "").replace(" }", "").replace('"', "") };

    let severity_icon = match severity {
        "CRITICAL" => "🔴",
        "HIGH" => "🟠",
        "MEDIUM" => "🟡",
        _ => "🔵",
    };

    let text = format!(
        "{icon} INCIDENT #{id} — {sev}\n\
         ━━━━━━━━━━━━━━━━━━━━━━\n\
         Asset : {asset}\n\
         Alertes : {count}\n\
         ━━━━━━━━━━━━━━━━━━━━━━\n\n\
         {summary}",
        icon = severity_icon,
        id = incident_id,
        sev = severity,
        asset = asset,
        count = alert_count,
        summary = summary_clean,
    );

    // Get dashboard URL for channels without interactive buttons
    let dashboard_url = get_channel_field(store, "general", "dashboardUrl").await
        .unwrap_or_else(|| "https://your-threatclaw/incidents".into());
    let text_with_link = format!("{}\n\n→ Repondre: {}", text, dashboard_url);

    let mut results = vec![];
    for channel in channels {
        if !configured.contains(channel) { continue; }

        // See ADR-044: send with HITL buttons where supported, text+link otherwise
        let result = match channel.as_str() {
            "telegram" => send_telegram_with_buttons(store, &text, incident_id).await,
            "slack" => send_slack_with_buttons(store, &text, incident_id).await,
            "mattermost" => send_mattermost_with_buttons(store, &text, incident_id).await,
            "ntfy" => send_ntfy_with_buttons(store, &text, incident_id).await,
            "discord" => send_discord_with_buttons(store, &text, incident_id).await,
            _ => send_to_channel(store, channel, &text_with_link, NotificationLevel::Alert).await,
        };

        if let Err(ref e) = result {
            tracing::warn!("INCIDENT_NOTIF: Failed to send to {}: {}", channel, e);
        } else {
            tracing::info!("INCIDENT_NOTIF: Incident #{} sent to {} (with HITL buttons)", incident_id, channel);
        }
        results.push((channel.clone(), result));
    }
    results
}

/// Truncate text to Telegram's 4096 char limit, preserving UTF-8 boundaries.
fn truncate_for_telegram(text: &str) -> String {
    const MAX_LEN: usize = 4000; // Leave margin for safety (limit is 4096)
    if text.len() <= MAX_LEN {
        return text.to_string();
    }
    // Find a clean UTF-8 boundary
    let mut end = MAX_LEN;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n\n[... tronqué]", &text[..end])
}

/// Send Telegram message with inline HITL buttons for an incident.
async fn send_telegram_with_buttons(store: &dyn Database, text: &str, incident_id: i32) -> Result<(), String> {
    let token = crate::channels::web::handlers::threatclaw_api::get_telegram_token(store).await
        .ok_or("Telegram token not configured")?;
    let chat_id = get_channel_field(store, "telegram", "chatId").await
        .ok_or("Telegram chat_id not configured")?;

    let keyboard = json!({
        "inline_keyboard": [[
            { "text": "✅ Remédier", "callback_data": format!("incident_{}_approve", incident_id) },
            { "text": "❌ Faux positif", "callback_data": format!("incident_{}_reject", incident_id) },
            { "text": "🔍 Investiguer", "callback_data": format!("incident_{}_investigate", incident_id) },
        ]]
    });

    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| e.to_string())?
        .post(format!("https://api.telegram.org/bot{}/sendMessage", token))
        .json(&json!({
            "chat_id": chat_id.trim(),
            "text": truncate_for_telegram(text),
            "reply_markup": keyboard,
        }))
        .send().await.map_err(|e| e.to_string())?;

    let status = resp.status();
    if status.is_success() { Ok(()) }
    else {
        let body = resp.text().await.unwrap_or_default();
        Err(format!("Telegram HTTP {}: {}", status, body.chars().take(200).collect::<String>()))
    }
}

/// Send Slack message with Block Kit HITL buttons for an incident.
async fn send_slack_with_buttons(store: &dyn Database, text: &str, incident_id: i32) -> Result<(), String> {
    let token = get_channel_field(store, "slack", "botToken").await
        .ok_or("Slack bot token not configured")?;
    let channel = get_channel_field(store, "slack", "channel").await
        .unwrap_or("#general".into());

    // Get callback URL for button actions
    let callback_url = get_channel_field(store, "general", "dashboardUrl").await
        .unwrap_or("http://localhost:3000".into());

    let blocks = json!([
        { "type": "section", "text": { "type": "mrkdwn", "text": text } },
        { "type": "actions", "elements": [
            { "type": "button", "text": { "type": "plain_text", "text": "Remedier" }, "style": "danger",
              "url": format!("{}/api/tc/incidents/{}/hitl?response=approve_remediate&responded_by=slack", callback_url, incident_id) },
            { "type": "button", "text": { "type": "plain_text", "text": "Faux positif" },
              "url": format!("{}/api/tc/incidents/{}/hitl?response=false_positive&responded_by=slack", callback_url, incident_id) },
            { "type": "button", "text": { "type": "plain_text", "text": "Investiguer" },
              "url": format!("{}/api/tc/incidents/{}/hitl?response=investigate_more&responded_by=slack", callback_url, incident_id) },
        ]}
    ]);

    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| e.to_string())?
        .post("https://slack.com/api/chat.postMessage")
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "channel": channel, "text": text, "blocks": blocks }))
        .send().await.map_err(|e| e.to_string())?;

    if resp.status().is_success() { Ok(()) }
    else { Err(format!("Slack HTTP {}", resp.status())) }
}

/// Send Mattermost message with interactive buttons for an incident.
async fn send_mattermost_with_buttons(store: &dyn Database, text: &str, incident_id: i32) -> Result<(), String> {
    let webhook_url = get_channel_field(store, "mattermost", "webhookUrl").await
        .ok_or("Mattermost webhook not configured")?;
    let callback_url = get_channel_field(store, "general", "dashboardUrl").await
        .unwrap_or("http://localhost:3000".into());

    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| e.to_string())?
        .post(&webhook_url)
        .json(&json!({
            "text": text,
            "attachments": [{
                "actions": [
                    { "name": "Remedier", "type": "button", "style": "danger",
                      "integration": { "url": format!("{}/api/tc/incidents/{}/hitl", callback_url, incident_id),
                                       "context": { "response": "approve_remediate", "responded_by": "mattermost" } } },
                    { "name": "Faux positif", "type": "button",
                      "integration": { "url": format!("{}/api/tc/incidents/{}/hitl", callback_url, incident_id),
                                       "context": { "response": "false_positive", "responded_by": "mattermost" } } },
                    { "name": "Investiguer", "type": "button",
                      "integration": { "url": format!("{}/api/tc/incidents/{}/hitl", callback_url, incident_id),
                                       "context": { "response": "investigate_more", "responded_by": "mattermost" } } },
                ]
            }]
        }))
        .send().await.map_err(|e| e.to_string())?;

    if resp.status().is_success() { Ok(()) }
    else { Err(format!("Mattermost HTTP {}", resp.status())) }
}

/// Send Discord message with button components for an incident.
async fn send_discord_with_buttons(store: &dyn Database, text: &str, incident_id: i32) -> Result<(), String> {
    let webhook_url = get_channel_field(store, "discord", "botToken").await
        .ok_or("Discord webhook not configured")?;
    let callback_url = get_channel_field(store, "general", "dashboardUrl").await
        .unwrap_or("http://localhost:3000".into());

    // Discord webhooks don't support interactive buttons — use link buttons
    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| e.to_string())?
        .post(&webhook_url)
        .json(&json!({
            "content": text,
            "username": "ThreatClaw",
            "components": [{
                "type": 1,
                "components": [
                    { "type": 2, "style": 5, "label": "Remedier",
                      "url": format!("{}/api/tc/incidents/{}/hitl?response=approve_remediate&responded_by=discord", callback_url, incident_id) },
                    { "type": 2, "style": 5, "label": "Faux positif",
                      "url": format!("{}/api/tc/incidents/{}/hitl?response=false_positive&responded_by=discord", callback_url, incident_id) },
                    { "type": 2, "style": 5, "label": "Dashboard",
                      "url": format!("{}/incidents", callback_url) },
                ]
            }]
        }))
        .send().await.map_err(|e| e.to_string())?;

    if resp.status().is_success() || resp.status().as_u16() == 204 { Ok(()) }
    else { Err(format!("Discord HTTP {}", resp.status())) }
}

/// Send Ntfy notification with HTTP action buttons for an incident.
async fn send_ntfy_with_buttons(store: &dyn Database, text: &str, incident_id: i32) -> Result<(), String> {
    let server = get_channel_field(store, "ntfy", "server").await.unwrap_or("https://ntfy.sh".into());
    let topic = get_channel_field(store, "ntfy", "topic").await
        .ok_or("Ntfy topic not configured")?;
    let callback_url = get_channel_field(store, "general", "dashboardUrl").await
        .unwrap_or("http://localhost:3000".into());

    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| e.to_string())?
        .post(format!("{}/{}", server, topic))
        .header("Title", format!("Incident #{}", incident_id))
        .header("Priority", "urgent")
        .header("Tags", "rotating_light,shield")
        .header("Actions", format!(
            "http, Remedier, {}/api/tc/incidents/{}/hitl?response=approve_remediate&responded_by=ntfy, method=POST; http, Faux positif, {}/api/tc/incidents/{}/hitl?response=false_positive&responded_by=ntfy, method=POST; view, Dashboard, {}/incidents",
            callback_url, incident_id, callback_url, incident_id, callback_url
        ))
        .body(text.to_string())
        .send().await.map_err(|e| e.to_string())?;

    if resp.status().is_success() { Ok(()) }
    else { Err(format!("Ntfy HTTP {}", resp.status())) }
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
        if check("olvid", "clientKey") { configured.push("olvid".into()); }
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
                .json(&json!({ "chat_id": chat_id.trim(), "text": truncate_for_telegram(message) }))
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
        "olvid" => {
            // See ADR-044: Olvid certified ANSSI messenger integration
            let daemon_url = get_channel_field(store, "olvid", "daemonUrl").await
                .unwrap_or("http://localhost:50051".into());
            let client_key = get_channel_field(store, "olvid", "clientKey").await
                .ok_or("Olvid client key not configured")?;
            let discussion_id = get_channel_field(store, "olvid", "discussionId").await
                .ok_or("Olvid discussion ID not configured")?;

            crate::connectors::olvid::send_message(&daemon_url, &client_key, &discussion_id, message).await
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

/// Route a notification based on an investigation verdict.
/// For HIGH/CRITICAL incidents, sends with HITL buttons so the RSSI can act directly.
pub async fn route_verdict_notification(
    store: &dyn Database,
    result: &InvestigationResult,
    dossier: &IncidentDossier,
    incident_id: i32,
) -> Vec<(String, Result<(), String>)> {
    let message = match result.format_telegram(dossier) {
        Some(msg) => msg,
        None => return vec![],
    };

    // Use HITL buttons for confirmed HIGH/CRITICAL incidents
    if incident_id > 0 && matches!(result.verdict.severity(), "CRITICAL" | "HIGH") {
        return route_incident_notification(
            store,
            incident_id,
            &result.asset,
            &format!("{} — {}", result.asset, result.verdict.verdict_type()),
            &message,
            result.verdict.severity(),
            dossier.findings.len() as i32,
        ).await;
    }

    let level = match result.verdict.severity() {
        "CRITICAL" => NotificationLevel::Critical,
        "HIGH" => NotificationLevel::Alert,
        _ => NotificationLevel::Alert,
    };

    route_notification(store, level, &message, &message).await
}
