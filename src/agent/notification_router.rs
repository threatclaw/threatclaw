//! Notification Router — dispatches alerts to configured channels.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::agent::intelligence_engine::NotificationLevel;
use crate::db::Database;

/// Notification routing configuration per level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRouting {
    pub digest: Vec<String>, // channels for digest (e.g., ["email", "telegram"])
    pub alert: Vec<String>,  // channels for alert
    pub critical: Vec<String>, // channels for critical
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

/// Advanced notification settings — configurable by the RSSI in Config > Notifications.
/// Controls cooldowns, severity threshold, reminders, escalation, quiet hours, and digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    /// Per-severity cooldown in seconds. Same asset + same verdict_type won't re-notify
    /// within this window. CRITICAL is shorter so urgent issues get attention.
    pub cooldown_critical_secs: i64,
    pub cooldown_high_secs: i64,
    pub cooldown_medium_secs: i64,
    /// LOW incidents: 0 = never notify (dashboard only).
    pub cooldown_low_secs: i64,

    /// Minimum severity to send a notification. "HIGH" = HIGH+CRITICAL, "CRITICAL" = CRITICAL only.
    pub min_severity: String,

    /// Re-notify if a CRITICAL incident is still unresolved after this many seconds. 0 = off.
    pub remind_unresolved_critical_secs: i64,
    /// Re-notify if a HIGH incident is still unresolved after this many seconds. 0 = off.
    pub remind_unresolved_high_secs: i64,

    /// If true, a severity escalation (e.g. HIGH → CRITICAL) bypasses the cooldown.
    pub escalation_always_notify: bool,

    /// If true, only CRITICAL notifications are sent outside business hours.
    /// Business hours are read from company_profile.business_hours.
    pub quiet_hours_enabled: bool,
    /// Minimum severity during quiet hours. Default: "CRITICAL".
    pub quiet_hours_min_severity: String,

    /// Daily digest: sends a summary at a fixed time.
    pub daily_digest_enabled: bool,
    /// Digest time in "HH:MM" format (UTC).
    pub daily_digest_time: String,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            cooldown_critical_secs: 2 * 3600, // 2h
            cooldown_high_secs: 12 * 3600,    // 12h
            cooldown_medium_secs: 24 * 3600,  // 24h
            cooldown_low_secs: 0,             // never

            min_severity: "HIGH".into(), // HIGH + CRITICAL

            remind_unresolved_critical_secs: 4 * 3600, // 4h
            remind_unresolved_high_secs: 0,            // off

            escalation_always_notify: true,

            quiet_hours_enabled: false,
            quiet_hours_min_severity: "CRITICAL".into(),

            daily_digest_enabled: true,
            daily_digest_time: "08:00".into(),
        }
    }
}

impl NotificationSettings {
    /// Get the cooldown for a given severity string.
    pub fn cooldown_for_severity(&self, severity: &str) -> i64 {
        match severity.to_uppercase().as_str() {
            "CRITICAL" => self.cooldown_critical_secs,
            "HIGH" => self.cooldown_high_secs,
            "MEDIUM" => self.cooldown_medium_secs,
            "LOW" => self.cooldown_low_secs,
            _ => self.cooldown_high_secs,
        }
    }

    /// Check if a severity level meets the minimum notification threshold.
    pub fn severity_meets_threshold(&self, severity: &str) -> bool {
        let order = |s: &str| match s.to_uppercase().as_str() {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            _ => 0,
        };
        order(severity) >= order(&self.min_severity)
    }

    /// Check if a severity level meets the quiet-hours threshold.
    pub fn severity_meets_quiet_threshold(&self, severity: &str) -> bool {
        let order = |s: &str| match s.to_uppercase().as_str() {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            _ => 0,
        };
        order(severity) >= order(&self.quiet_hours_min_severity)
    }
}

const NOTIFICATION_SETTINGS_KEY: &str = "tc_config_notification_settings";

/// Load notification settings from DB, or use defaults.
pub async fn load_notification_settings(store: &dyn Database) -> NotificationSettings {
    if let Ok(Some(val)) = store
        .get_setting("_system", NOTIFICATION_SETTINGS_KEY)
        .await
    {
        if let Ok(settings) = serde_json::from_value(val) {
            return settings;
        }
    }
    NotificationSettings::default()
}

/// Save notification settings to DB.
pub async fn save_notification_settings(
    store: &dyn Database,
    settings: &NotificationSettings,
) -> Result<(), String> {
    let val = serde_json::to_value(settings).map_err(|e| e.to_string())?;
    store
        .set_setting("_system", NOTIFICATION_SETTINGS_KEY, &val)
        .await
        .map_err(|e| e.to_string())
}

/// Load notification routing config from DB, or use defaults.
pub async fn load_routing(store: &dyn Database) -> NotificationRouting {
    if let Ok(Some(val)) = store
        .get_setting("_system", "tc_config_notification_routing")
        .await
    {
        if let Ok(routing) = serde_json::from_value(val) {
            return routing;
        }
    }
    NotificationRouting::default()
}

/// Save notification routing config to DB.
pub async fn save_routing(
    store: &dyn Database,
    routing: &NotificationRouting,
) -> Result<(), String> {
    let val = serde_json::to_value(routing).map_err(|e| e.to_string())?;
    store
        .set_setting("_system", "tc_config_notification_routing", &val)
        .await
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

    let message = if level == NotificationLevel::Digest {
        digest_message
    } else {
        alert_message
    };

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
    let _ = store
        .set_setting(
            "_audit",
            &format!(
                "notif_{}_{}",
                format!("{:?}", level).to_lowercase(),
                chrono::Utc::now().timestamp()
            ),
            &json!({
                "level": format!("{:?}", level),
                "channels_attempted": channels,
                "channels_configured": configured_channels,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        )
        .await;

    results
}

/// See ADR-043: Route an incident notification.
///
/// HITL model (Option A, 2026-04-10): no inline buttons. The message contains
/// a concrete description (IP, rule, tool) and numbered actions. The RSSI
/// replies with "1", "2", "3", "ignore", or a free-form command in the same
/// chat, and the conversational bot (L0) routes the response to the right
/// remediation action. This prevents destructive one-click mistakes.
pub async fn route_incident_notification(
    store: &dyn Database,
    incident_id: i32,
    asset: &str,
    title: &str,
    summary: &str,
    severity: &str,
    alert_count: i32,
) -> Vec<(String, Result<(), String>)> {
    let _ = title; // title is now derived from asset + verdict inside the summary
    let routing = load_routing(store).await;
    let configured = get_configured_channels(store).await;
    let channels = &routing.alert;

    // Build the rich message once, reused across channels
    let text =
        build_incident_message(store, incident_id, asset, summary, severity, alert_count).await;

    let dashboard_url = get_channel_field(store, "general", "dashboardUrl")
        .await
        .unwrap_or_else(|| "https://your-threatclaw/incidents".into());
    let text_with_link = format!("{}\n\n🔗 Dashboard : {}", text, dashboard_url);

    let mut results = vec![];
    for channel in channels {
        if !configured.contains(channel) {
            continue;
        }

        // Plain text on every channel — no inline buttons.
        // The RSSI replies in the same chat; conversational_bot parses the response.
        let result =
            send_to_channel(store, channel, &text_with_link, NotificationLevel::Alert).await;

        if let Err(ref e) = result {
            tracing::warn!("INCIDENT_NOTIF: Failed to send to {}: {}", channel, e);
        } else {
            tracing::info!(
                "INCIDENT_NOTIF: Incident #{} sent to {} (plain, actions inline)",
                incident_id,
                channel
            );
            // Remember which incident the user is now expected to reply about (per channel).
            remember_pending_incident(store, channel, incident_id).await;
        }
        results.push((channel.clone(), result));
    }
    results
}

/// Build a rich incident message with concrete IOCs and numbered actions.
async fn build_incident_message(
    store: &dyn Database,
    incident_id: i32,
    asset: &str,
    summary: &str,
    severity: &str,
    alert_count: i32,
) -> String {
    let summary_clean = if summary.is_empty() {
        "Investigation en cours...".to_string()
    } else {
        summary
            .replace("Confirmed { ", "")
            .replace(" }", "")
            .replace('"', "")
    };

    let severity_icon = match severity {
        "CRITICAL" => "🔴",
        "HIGH" => "🟠",
        "MEDIUM" => "🟡",
        _ => "🔵",
    };

    // Try to extract a concrete attacker IP so the RSSI sees exactly what will happen
    let attacker_ip =
        crate::agent::remediation_engine::extract_attacker_ip(store, asset, incident_id).await;

    // Detect which connectors are configured (to name them in the proposals)
    let fw_info = crate::agent::remediation_engine::load_firewall_config(store)
        .await
        .map(|(ty, _url, _u, _s, _no_tls)| ty);
    let glpi_configured = crate::agent::remediation_engine::load_glpi_config(store)
        .await
        .is_some();

    // Build numbered proposals
    let mut actions: Vec<String> = Vec::new();
    match (&attacker_ip, &fw_info) {
        (Some(ip), Some(fw)) => {
            actions.push(format!(
                "Bloquer {} sur {} (règle ThreatClaw auto, réversible)",
                ip, fw
            ));
        }
        (Some(ip), None) => {
            actions.push(format!(
                "Bloquer {} — ⚠️ aucun firewall (pfSense/OPNsense) configuré",
                ip
            ));
        }
        (None, _) => {
            actions
                .push("Bloquer l'IP source — ⚠️ IP attaquante introuvable dans les alertes".into());
        }
    }
    if glpi_configured {
        actions.push(format!(
            "Créer un ticket GLPI pour l'incident #{}",
            incident_id
        ));
    } else {
        actions.push("Créer un ticket GLPI — ⚠️ connecteur non configuré".into());
    }
    actions.push("Marquer comme faux positif (clôt l'incident)".into());

    let actions_block = actions
        .iter()
        .enumerate()
        .map(|(i, a)| format!("  {}. {}", i + 1, a))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "{icon} INCIDENT #{id} — {sev}\n\
         ━━━━━━━━━━━━━━━━━━━━━━\n\
         Asset : {asset}\n\
         Alertes : {count}\n\
         {ip_line}\
         ━━━━━━━━━━━━━━━━━━━━━━\n\n\
         {summary}\n\n\
         💡 Actions proposées :\n\
         {actions}\n\n\
         Réponds : \"1\", \"2\", \"3\", \"ignore\", ou une commande libre.",
        icon = severity_icon,
        id = incident_id,
        sev = severity,
        asset = asset,
        count = alert_count,
        ip_line = attacker_ip
            .as_ref()
            .map(|ip| format!("Source   : {}\n", ip))
            .unwrap_or_default(),
        summary = summary_clean,
        actions = actions_block,
    )
}

/// Remember the incident that the RSSI is now expected to reply about, per channel.
/// Used by conversational_bot to route "1"/"2"/"3" responses to the right incident.
async fn remember_pending_incident(store: &dyn Database, channel: &str, incident_id: i32) {
    let key = format!("pending_incident:{}", channel);
    let _ = store
        .set_setting(
            "_system",
            &key,
            &serde_json::json!({
                "incident_id": incident_id,
                "at": chrono::Utc::now().to_rfc3339(),
            }),
        )
        .await;
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

/// Get list of channels that have been configured (have tokens/URLs).
async fn get_configured_channels(store: &dyn Database) -> Vec<String> {
    let mut configured = vec![];

    if let Ok(Some(channels)) = store.get_setting("_system", "tc_config_channels").await {
        let check = |name: &str, key: &str| -> bool {
            channels[name]["enabled"].as_bool() == Some(true)
                && channels[name][key].as_str().map(|s| !s.trim().is_empty()) == Some(true)
        };

        if check("telegram", "botToken") {
            configured.push("telegram".into());
        }
        if check("slack", "botToken") {
            configured.push("slack".into());
        }
        if check("discord", "botToken") {
            configured.push("discord".into());
        }
        if check("mattermost", "webhookUrl") {
            configured.push("mattermost".into());
        }
        if check("ntfy", "topic") {
            configured.push("ntfy".into());
        }
        if check("gotify", "appToken") {
            configured.push("gotify".into());
        }
        if check("email", "host") {
            configured.push("email".into());
        }
        if check("signal", "account") {
            configured.push("signal".into());
        }
        if check("whatsapp", "accessToken") {
            configured.push("whatsapp".into());
        }
        if check("olvid", "clientKey") {
            configured.push("olvid".into());
        }
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
            let token = crate::channels::web::handlers::threatclaw_api::get_telegram_token(store)
                .await
                .ok_or("Telegram token not configured")?;
            let chat_id = get_channel_field(store, "telegram", "chatId")
                .await
                .ok_or("Telegram chat_id not configured")?;

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| e.to_string())?;

            let resp = client
                .post(format!("https://api.telegram.org/bot{}/sendMessage", token))
                .json(&json!({ "chat_id": chat_id.trim(), "text": truncate_for_telegram(message) }))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if resp.status().is_success() {
                Ok(())
            } else {
                Err(format!("Telegram HTTP {}", resp.status()))
            }
        }
        "mattermost" => {
            let webhook_url = get_channel_field(store, "mattermost", "webhookUrl")
                .await
                .ok_or("Mattermost webhook not configured")?;
            crate::integrations::mattermost_hitl::send_notification(
                &crate::integrations::mattermost_hitl::MattermostHitlConfig {
                    enabled: true,
                    webhook_url,
                    channel: String::new(),
                    callback_url: String::new(),
                },
                message,
            )
            .await
        }
        "ntfy" => {
            let server = get_channel_field(store, "ntfy", "server")
                .await
                .unwrap_or("https://ntfy.sh".into());
            let topic = get_channel_field(store, "ntfy", "topic")
                .await
                .ok_or("Ntfy topic not configured")?;
            crate::integrations::ntfy_hitl::send_notification(
                &crate::integrations::ntfy_hitl::NtfyHitlConfig {
                    enabled: true,
                    server_url: server,
                    topic,
                    callback_url: String::new(),
                    auth_token: None,
                },
                "ThreatClaw Alerte",
                message,
                "high",
            )
            .await
        }
        "gotify" => {
            let url = get_channel_field(store, "gotify", "url")
                .await
                .ok_or("Gotify URL not configured")?;
            let token = get_channel_field(store, "gotify", "appToken")
                .await
                .ok_or("Gotify token not configured")?;
            crate::integrations::gotify_notify::send_notification(
                &crate::integrations::gotify_notify::GotifyConfig {
                    enabled: true,
                    server_url: url,
                    app_token: token,
                },
                "ThreatClaw",
                message,
                "high",
            )
            .await
        }
        "slack" => {
            let token = get_channel_field(store, "slack", "botToken")
                .await
                .ok_or("Slack bot token not configured")?;
            // Use Slack chat.postMessage API — need a default channel
            // Slack requires a channel ID or name. Use #general as fallback.
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| e.to_string())?;

            let resp = client
                .post("https://slack.com/api/chat.postMessage")
                .header("Authorization", format!("Bearer {}", token))
                .json(&json!({
                    "channel": "#general",
                    "text": message,
                    "unfurl_links": false,
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if resp.status().is_success() {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                if body["ok"].as_bool() == Some(true) {
                    Ok(())
                } else {
                    Err(format!(
                        "Slack API error: {}",
                        body["error"].as_str().unwrap_or("unknown")
                    ))
                }
            } else {
                Err(format!("Slack HTTP {}", resp.status()))
            }
        }
        "discord" => {
            // Discord webhook — botToken field stores the webhook URL for notifications
            let webhook_url = get_channel_field(store, "discord", "botToken")
                .await
                .ok_or("Discord webhook not configured")?;

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| e.to_string())?;

            let resp = client
                .post(&webhook_url)
                .json(&json!({
                    "content": message,
                    "username": "ThreatClaw",
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if resp.status().is_success() || resp.status().as_u16() == 204 {
                Ok(())
            } else {
                Err(format!("Discord HTTP {}", resp.status()))
            }
        }
        "email" => {
            let host = get_channel_field(store, "email", "host")
                .await
                .ok_or("Email SMTP host not configured")?;
            let port: u16 = get_channel_field(store, "email", "port")
                .await
                .and_then(|p| p.parse().ok())
                .unwrap_or(587);
            let from = get_channel_field(store, "email", "from")
                .await
                .ok_or("Email from address not configured")?;
            let to = get_channel_field(store, "email", "to")
                .await
                .ok_or("Email to address not configured")?;

            // Use lettre crate for SMTP if available, otherwise raw TCP
            // For now, use a simple HTTP approach via a local sendmail or direct SMTP
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| e.to_string())?;

            // Try SMTP via direct socket (minimal implementation)
            use std::io::{Read, Write};
            let addr = format!("{}:{}", host, port);
            match std::net::TcpStream::connect_timeout(
                &addr
                    .parse()
                    .map_err(|e: std::net::AddrParseError| e.to_string())?,
                std::time::Duration::from_secs(10),
            ) {
                Ok(mut stream) => {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf); // Read greeting
                    let commands = [
                        format!("EHLO threatclaw\r\n"),
                        format!("MAIL FROM:<{}>\r\n", from),
                        format!("RCPT TO:<{}>\r\n", to),
                        "DATA\r\n".to_string(),
                        format!(
                            "From: ThreatClaw <{}>\r\nTo: {}\r\nSubject: ThreatClaw Security Alert\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n.\r\n",
                            from, to, message
                        ),
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
            let http_url = get_channel_field(store, "signal", "httpUrl")
                .await
                .unwrap_or("http://localhost:8080".into());
            let account = get_channel_field(store, "signal", "account")
                .await
                .ok_or("Signal account not configured")?;
            // Signal-cli REST API
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| e.to_string())?;

            let resp = client
                .post(format!("{}/v2/send", http_url))
                .json(&json!({
                    "message": message,
                    "number": account,
                    "recipients": [account],
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if resp.status().is_success() {
                Ok(())
            } else {
                Err(format!("Signal HTTP {}", resp.status()))
            }
        }
        "whatsapp" => {
            let access_token = get_channel_field(store, "whatsapp", "accessToken")
                .await
                .ok_or("WhatsApp access token not configured")?;
            let phone_id = get_channel_field(store, "whatsapp", "phoneNumberId")
                .await
                .ok_or("WhatsApp phone number ID not configured")?;

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| e.to_string())?;

            let resp = client
                .post(format!(
                    "https://graph.facebook.com/v18.0/{}/messages",
                    phone_id
                ))
                .header("Authorization", format!("Bearer {}", access_token))
                .json(&json!({
                    "messaging_product": "whatsapp",
                    "to": phone_id,
                    "type": "text",
                    "text": { "body": message },
                }))
                .send()
                .await
                .map_err(|e| e.to_string())?;

            if resp.status().is_success() {
                Ok(())
            } else {
                Err(format!("WhatsApp HTTP {}", resp.status()))
            }
        }
        "olvid" => {
            // See ADR-044: Olvid certified ANSSI messenger integration
            let daemon_url = get_channel_field(store, "olvid", "daemonUrl")
                .await
                .unwrap_or("http://localhost:50051".into());
            let client_key = get_channel_field(store, "olvid", "clientKey")
                .await
                .ok_or("Olvid client key not configured")?;
            let discussion_id = get_channel_field(store, "olvid", "discussionId")
                .await
                .ok_or("Olvid discussion ID not configured")?;

            crate::connectors::olvid::send_message(
                &daemon_url,
                &client_key,
                &discussion_id,
                message,
            )
            .await
        }
        _ => Err(format!("Channel {} not implemented for routing", channel)),
    }
}

/// Get a field from channel config in DB.
async fn get_channel_field(store: &dyn Database, channel: &str, field: &str) -> Option<String> {
    let channels = store
        .get_setting("_system", "tc_config_channels")
        .await
        .ok()??;
    channels[channel][field]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(String::from)
}

// ── V3: Route investigation verdict notifications ──

use crate::agent::incident_dossier::IncidentDossier;
use crate::agent::verdict::InvestigationResult;

/// Route a notification based on an investigation verdict.
///
/// For HIGH/CRITICAL incidents with a valid incident_id, the IE already sent
/// the notification via route_incident_notification() with HITL actions.
/// This function only handles the low-severity fallback (LOW/MEDIUM plain digest).
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

    // HIGH/CRITICAL incidents are already handled by route_incident_notification
    // in the IE pipeline. Skip here to avoid double-sending.
    if incident_id > 0 && matches!(result.verdict.severity(), "CRITICAL" | "HIGH") {
        return vec![];
    }

    let level = match result.verdict.severity() {
        "CRITICAL" => NotificationLevel::Critical,
        "HIGH" => NotificationLevel::Alert,
        _ => NotificationLevel::Alert,
    };

    route_notification(store, level, &message, &message).await
}
