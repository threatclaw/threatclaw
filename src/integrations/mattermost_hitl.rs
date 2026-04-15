//! Mattermost HITL integration — on-premise Slack alternative.
//!
//! Uses Mattermost Incoming Webhooks (Slack-compatible format)
//! with interactive message buttons for HITL approval.

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Mattermost HITL configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MattermostHitlConfig {
    pub enabled: bool,
    pub webhook_url: String,
    pub channel: String,
    pub callback_url: String,
}

/// Send a HITL approval request to Mattermost.
/// Uses Slack-compatible webhook format with interactive buttons.
pub async fn send_approval(
    config: &MattermostHitlConfig,
    summary: &str,
    command: &str,
    risk: &str,
    nonce: &str,
    playbook: &[String],
) -> Result<(), String> {
    if !config.enabled || config.webhook_url.is_empty() {
        return Err("Mattermost not configured".into());
    }

    let mut playbook_text = String::new();
    if !playbook.is_empty() {
        playbook_text.push_str("\n**Playbook suggéré :**\n");
        for (i, step) in playbook.iter().enumerate() {
            playbook_text.push_str(&format!("{}. {}\n", i + 1, step));
        }
    }

    let payload = json!({
        "channel": config.channel,
        "username": "ThreatClaw",
        "icon_url": "https://threatclaw.io/icon.png",
        "attachments": [{
            "color": match risk {
                "Critical" => "#e84040",
                "High" => "#d07020",
                _ => "#d09020",
            },
            "title": "HITL — Approbation requise",
            "text": format!("{}{}\n\n**Commande :** `{}`\n**Risque :** {}\n**Nonce :** `{}`",
                summary, playbook_text, command, risk, &nonce[..8.min(nonce.len())]),
            "actions": [
                {
                    "id": format!("approve_{}", nonce),
                    "name": "Approuver",
                    "type": "button",
                    "style": "good",
                    "integration": {
                        "url": format!("{}/api/tc/hitl/callback", config.callback_url),
                        "context": {
                            "action": "approve",
                            "nonce": nonce,
                        }
                    }
                },
                {
                    "id": format!("reject_{}", nonce),
                    "name": "Rejeter",
                    "type": "button",
                    "style": "danger",
                    "integration": {
                        "url": format!("{}/api/tc/hitl/callback", config.callback_url),
                        "context": {
                            "action": "reject",
                            "nonce": nonce,
                        }
                    }
                }
            ]
        }]
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client
        .post(&config.webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Mattermost webhook failed: {e}"))?;

    if resp.status().is_success() {
        tracing::info!(
            "HITL: Mattermost approval sent (nonce: {})",
            &nonce[..8.min(nonce.len())]
        );
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(format!(
            "Mattermost returned {}: {}",
            status,
            body.chars().take(200).collect::<String>()
        ))
    }
}

/// Send a simple notification to Mattermost (no buttons).
pub async fn send_notification(config: &MattermostHitlConfig, text: &str) -> Result<(), String> {
    if !config.enabled || config.webhook_url.is_empty() {
        return Err("Mattermost not configured".into());
    }

    let payload = json!({
        "channel": config.channel,
        "username": "ThreatClaw",
        "text": text,
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client
        .post(&config.webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Mattermost send failed: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Mattermost returned {}", resp.status()))
    }
}

/// Test Mattermost webhook connectivity.
pub async fn test_connection(webhook_url: &str) -> Result<String, String> {
    let payload = json!({
        "username": "ThreatClaw",
        "text": "ThreatClaw — Test de connexion Mattermost réussi",
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let resp = client
        .post(webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Mattermost: {e}"))?;

    if resp.status().is_success() {
        Ok("Mattermost connecté".into())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}
