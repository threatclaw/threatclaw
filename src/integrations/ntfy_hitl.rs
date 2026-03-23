//! Ntfy HITL integration — ultra-lightweight on-premise notifications.
//!
//! Ntfy supports up to 3 action buttons per notification.
//! Uses HTTP actions to POST approval/rejection to ThreatClaw callback URL.
//! Perfect for NIS2-sensitive clients who need fully on-premise notifications.

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Ntfy HITL configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtfyHitlConfig {
    pub enabled: bool,
    /// Ntfy server URL (default: https://ntfy.sh for cloud, or self-hosted).
    pub server_url: String,
    /// Topic name (acts as the "channel").
    pub topic: String,
    /// ThreatClaw callback URL for button actions.
    pub callback_url: String,
    /// Optional auth token for private ntfy servers.
    pub auth_token: Option<String>,
}

impl Default for NtfyHitlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: "https://ntfy.sh".into(),
            topic: "threatclaw-alerts".into(),
            callback_url: "http://localhost:3000".into(),
            auth_token: None,
        }
    }
}

/// Ntfy priority levels.
fn severity_to_priority(risk: &str) -> &'static str {
    match risk {
        "Critical" => "urgent",    // 5 — maps to ntfy urgent (phone rings)
        "High" => "high",          // 4
        "Medium" => "default",     // 3
        _ => "low",                // 2
    }
}

/// Send a HITL approval request via Ntfy with action buttons.
pub async fn send_approval(
    config: &NtfyHitlConfig,
    summary: &str,
    command: &str,
    risk: &str,
    nonce: &str,
    playbook: &[String],
) -> Result<(), String> {
    if !config.enabled || config.topic.is_empty() {
        return Err("Ntfy not configured".into());
    }

    let mut body = format!("{}\n\nCommande: {}\nRisque: {}", summary, command, risk);
    if !playbook.is_empty() {
        body.push_str("\n\nPlaybook suggéré:");
        for (i, step) in playbook.iter().enumerate() {
            body.push_str(&format!("\n{}. {}", i + 1, step));
        }
    }

    let approve_url = format!("{}/api/tc/hitl/callback?action=approve&nonce={}", config.callback_url, nonce);
    let reject_url = format!("{}/api/tc/hitl/callback?action=reject&nonce={}", config.callback_url, nonce);

    let url = format!("{}/{}", config.server_url.trim_end_matches('/'), config.topic);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let mut req = client.post(&url)
        .header("Title", "ThreatClaw — HITL Approbation")
        .header("Priority", severity_to_priority(risk))
        .header("Tags", format!("warning,threatclaw,{}", risk.to_lowercase()))
        // Ntfy action buttons: up to 3 buttons
        // Format: action=http, label, url, method=POST
        .header("Actions", format!(
            "http, Approuver, {}, method=POST, headers.Authorization=Bearer {}; \
             http, Rejeter, {}, method=POST, headers.Authorization=Bearer {}",
            approve_url, nonce, reject_url, nonce
        ))
        .body(body);

    // Add auth if configured
    if let Some(ref token) = config.auth_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let resp = req.send().await
        .map_err(|e| format!("Ntfy send failed: {e}"))?;

    if resp.status().is_success() {
        tracing::info!("HITL: Ntfy approval sent to topic={} (nonce: {})", config.topic, &nonce[..8.min(nonce.len())]);
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(format!("Ntfy returned {}: {}", status, body.chars().take(200).collect::<String>()))
    }
}

/// Send a simple notification via Ntfy (no buttons).
pub async fn send_notification(
    config: &NtfyHitlConfig,
    title: &str,
    message: &str,
    priority: &str,
) -> Result<(), String> {
    if !config.enabled || config.topic.is_empty() {
        return Err("Ntfy not configured".into());
    }

    let url = format!("{}/{}", config.server_url.trim_end_matches('/'), config.topic);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let mut req = client.post(&url)
        .header("Title", title)
        .header("Priority", priority)
        .header("Tags", "shield,threatclaw")
        .body(message.to_string());

    if let Some(ref token) = config.auth_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let resp = req.send().await
        .map_err(|e| format!("Ntfy: {e}"))?;

    if resp.status().is_success() { Ok(()) }
    else { Err(format!("Ntfy HTTP {}", resp.status())) }
}

/// Test Ntfy connectivity by sending a test notification.
pub async fn test_connection(server_url: &str, topic: &str, auth_token: Option<&str>) -> Result<String, String> {
    let url = format!("{}/{}", server_url.trim_end_matches('/'), topic);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let mut req = client.post(&url)
        .header("Title", "ThreatClaw — Test")
        .header("Priority", "low")
        .header("Tags", "white_check_mark,threatclaw")
        .body("Connexion Ntfy réussie depuis ThreatClaw");

    if let Some(token) = auth_token {
        req = req.header("Authorization", format!("Bearer {}", token));
    }

    let resp = req.send().await
        .map_err(|e| format!("Ntfy: {e}"))?;

    if resp.status().is_success() {
        Ok(format!("Ntfy connecté — topic: {}", topic))
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}
