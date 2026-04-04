//! HITL Bridge — approval flow. See ADR-031.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::agent::executor;
use crate::agent::hitl_nonce::{NonceError, NonceManager};
use crate::agent::remediation_whitelist::{self, RiskLevel, ValidatedCommand};
use crate::integrations::slack_hitl::{
    ApprovalAction, ApprovalRequest, ApprovalStatus, SlackHitlConfig, SlackMessageBuilder,
    Urgency,
};

/// Result of sending an approval request to Slack.
#[derive(Debug, Clone, Serialize)]
pub struct HitlSendResult {
    pub request_id: String,
    pub nonce: String,
    pub cmd_id: String,
    pub slack_sent: bool,
    pub error: Option<String>,
}

/// Result of processing a Slack callback (approve/reject).
#[derive(Debug, Clone, Serialize)]
pub struct HitlCallbackResult {
    pub cmd_id: String,
    pub approved: bool,
    pub executed: bool,
    pub execution_success: Option<bool>,
    pub execution_output: Option<String>,
    pub error: Option<String>,
}

/// Error types for the HITL bridge.
#[derive(Debug, Clone)]
pub enum HitlBridgeError {
    SlackNotConfigured,
    SlackSendFailed(String),
    NonceError(NonceError),
    ExecutionFailed(String),
    ValidationFailed(String),
}

impl std::fmt::Display for HitlBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SlackNotConfigured => write!(f, "Slack HITL not configured"),
            Self::SlackSendFailed(e) => write!(f, "Slack send failed: {e}"),
            Self::NonceError(e) => write!(f, "Nonce error: {e}"),
            Self::ExecutionFailed(e) => write!(f, "Execution failed: {e}"),
            Self::ValidationFailed(e) => write!(f, "Validation failed: {e}"),
        }
    }
}

impl std::error::Error for HitlBridgeError {}

/// Maps remediation risk level to Slack urgency.
fn risk_to_urgency(risk: RiskLevel) -> Urgency {
    match risk {
        RiskLevel::Low => Urgency::Low,
        RiskLevel::Medium => Urgency::Medium,
        RiskLevel::High => Urgency::High,
        RiskLevel::Critical => Urgency::Critical,
    }
}

/// Send an approval request to Slack for a validated command.
///
/// Returns the nonce that must be included in the callback.
pub async fn send_approval_to_slack(
    cmd: &ValidatedCommand,
    rationale: &str,
    nonce_manager: &NonceManager,
    slack_config: &SlackHitlConfig,
) -> Result<HitlSendResult, HitlBridgeError> {
    if !slack_config.enabled {
        return Err(HitlBridgeError::SlackNotConfigured);
    }

    // Generate anti-replay nonce
    let nonce = nonce_manager.generate(&cmd.id).await;

    // Build the approval request
    let action = ApprovalAction::Remediation {
        action: cmd.rendered_cmd.clone(),
        target: cmd.params.values().next().cloned().unwrap_or_default(),
        risk_level: cmd.risk.to_string(),
    };

    let mut request = ApprovalRequest::new(
        action,
        "ThreatClaw Agent".to_string(),
        risk_to_urgency(cmd.risk),
        format!("{}\n\nNonce: `{}`\nCommande: `{}`", rationale, &nonce[..8], cmd.rendered_cmd),
        slack_config.default_channel.clone(),
    );

    // Override the ID with the nonce for callback matching
    request.id = nonce.clone();

    // Build Slack Block Kit message
    let message = SlackMessageBuilder::build_approval_message(&request);

    // Send to Slack via webhook
    match send_slack_webhook(&slack_config.webhook_url, &message).await {
        Ok(_) => {
            tracing::info!(
                "HITL: Approval request sent to Slack for {} (nonce: {})",
                cmd.id,
                &nonce[..8]
            );
            Ok(HitlSendResult {
                request_id: request.id.clone(),
                nonce: nonce.clone(),
                cmd_id: cmd.id.clone(),
                slack_sent: true,
                error: None,
            })
        }
        Err(e) => {
            tracing::error!("HITL: Failed to send Slack message: {e}");
            Ok(HitlSendResult {
                request_id: request.id,
                nonce,
                cmd_id: cmd.id.clone(),
                slack_sent: false,
                error: Some(e),
            })
        }
    }
}

/// Process a Slack callback (approve or reject).
///
/// Validates the nonce, then executes the command if approved.
pub async fn process_slack_callback(
    nonce: &str,
    approved: bool,
    approved_by: &str,
    nonce_manager: &NonceManager,
    params: &std::collections::HashMap<String, String>,
) -> Result<HitlCallbackResult, HitlBridgeError> {
    // Verify and consume nonce (anti-replay)
    let cmd_id = nonce_manager
        .verify_and_consume(nonce)
        .await
        .map_err(HitlBridgeError::NonceError)?;

    if !approved {
        tracing::info!("HITL: Action {} rejected by {}", cmd_id, approved_by);
        return Ok(HitlCallbackResult {
            cmd_id,
            approved: false,
            executed: false,
            execution_success: None,
            execution_output: None,
            error: None,
        });
    }

    tracing::info!("HITL: Action {} approved by {}", cmd_id, approved_by);

    // Validate the command again (defense in depth)
    let validated = remediation_whitelist::validate_remediation(&cmd_id, params)
        .map_err(|e| HitlBridgeError::ValidationFailed(e.to_string()))?;

    // Execute
    match executor::execute_validated(&validated) {
        Ok(result) => {
            tracing::info!(
                "HITL: Action {} executed successfully (exit {})",
                cmd_id,
                result.exit_code.unwrap_or(-1)
            );
            Ok(HitlCallbackResult {
                cmd_id,
                approved: true,
                executed: true,
                execution_success: Some(result.success),
                execution_output: Some(if result.success {
                    result.stdout
                } else {
                    result.stderr
                }),
                error: None,
            })
        }
        Err(e) => {
            tracing::error!("HITL: Action {} execution failed: {e}", cmd_id);
            Ok(HitlCallbackResult {
                cmd_id,
                approved: true,
                executed: true,
                execution_success: Some(false),
                execution_output: None,
                error: Some(e.to_string()),
            })
        }
    }
}

// ══════════════════════════════════════════════════════════
// HITL ENRICHMENT via L2.5 Instruct
// When Reasoning (L2) decides HITL is required, Instruct enriches
// the approval message with playbook + summary before sending.
// Timeout: 30s — fallback to basic message if Instruct unavailable.
// ══════════════════════════════════════════════════════════

/// Enriched HITL message produced by Instruct model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HitlEnrichedMessage {
    /// Human-readable incident summary (not JSON).
    pub summary: String,
    /// Suggested playbook steps (3-5 max).
    pub playbook: Vec<String>,
    /// Estimated NIS2 impact.
    pub nis2_impact: String,
    /// Whether enrichment came from Instruct or is a basic fallback.
    pub enriched_by: String,
}

/// Enrich a HITL message using the Instruct model (L2.5).
/// Falls back to basic message if Instruct is unavailable or times out (30s).
pub async fn enrich_hitl_with_instruct(
    analysis: &str,
    severity: &str,
    actions: &[String],
    llm_config: &crate::agent::llm_router::LlmRouterConfig,
) -> HitlEnrichedMessage {
    let instruct = &llm_config.instruct;
    let prompt = format!(
        "Un incident de sécurité nécessite l'approbation du RSSI. Génère un message clair et concis.\n\n\
        ANALYSE L2:\n{analysis}\n\n\
        SÉVÉRITÉ: {severity}\n\
        ACTIONS PROPOSÉES: {}\n\n\
        Réponds avec EXACTEMENT ce format (pas de JSON, texte naturel) :\n\
        RÉSUMÉ: [1-2 phrases résumant l'incident en langage naturel]\n\
        PLAYBOOK:\n1. [étape 1]\n2. [étape 2]\n3. [étape 3]\n\
        IMPACT NIS2: [impact estimé sur la conformité NIS2]",
        actions.join(", ")
    );

    let url = format!("{}/api/chat", instruct.base_url);
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30)) // Strict 30s timeout
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build() {
        Ok(c) => c,
        Err(_) => return basic_hitl_message(analysis, severity),
    };

    let body = serde_json::json!({
        "model": instruct.model,
        "messages": [{ "role": "user", "content": prompt }],
        "stream": false,
        "options": { "temperature": 0.3, "num_predict": 1024 }
    });

    match client.post(&url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let content = data["message"]["content"].as_str()
                    .or_else(|| data["response"].as_str())
                    .unwrap_or("");

                if !content.is_empty() {
                    let parsed = parse_instruct_response(content);
                    tracing::info!("HITL: Enriched by threatclaw_ai_8b_instruct ({} playbook steps)", parsed.playbook.len());
                    return parsed;
                }
            }
            tracing::warn!("HITL: Instruct returned empty response, using basic message");
            basic_hitl_message(analysis, severity)
        }
        Ok(resp) => {
            tracing::warn!("HITL: Instruct returned {}, using basic message", resp.status());
            basic_hitl_message(analysis, severity)
        }
        Err(e) => {
            tracing::warn!("HITL: Instruct unreachable ({}), using basic message", e);
            basic_hitl_message(analysis, severity)
        }
    }
}

/// Parse Instruct model response into structured HITL message.
fn parse_instruct_response(content: &str) -> HitlEnrichedMessage {
    let mut summary = String::new();
    let mut playbook = Vec::new();
    let mut nis2_impact = String::new();

    let mut section = "";
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("RÉSUMÉ:") || trimmed.starts_with("RESUME:") {
            section = "summary";
            summary = trimmed.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        } else if trimmed.starts_with("PLAYBOOK:") {
            section = "playbook";
        } else if trimmed.starts_with("IMPACT NIS2:") || trimmed.starts_with("IMPACT:") {
            section = "nis2";
            nis2_impact = trimmed.split_once(':').map(|(_, v)| v.trim().to_string()).unwrap_or_default();
        } else if section == "summary" && !trimmed.is_empty() {
            if !summary.is_empty() { summary.push(' '); }
            summary.push_str(trimmed);
        } else if section == "playbook" && !trimmed.is_empty() {
            // Remove leading "1. ", "2. ", "- ", etc.
            let step = trimmed.trim_start_matches(|c: char| c.is_numeric() || c == '.' || c == '-' || c == ' ');
            if !step.is_empty() {
                playbook.push(step.to_string());
            }
        } else if section == "nis2" && !trimmed.is_empty() {
            if !nis2_impact.is_empty() { nis2_impact.push(' '); }
            nis2_impact.push_str(trimmed);
        }
    }

    // Limit playbook to 5 steps max
    playbook.truncate(5);

    HitlEnrichedMessage {
        summary: if summary.is_empty() { content.chars().take(200).collect() } else { summary },
        playbook,
        nis2_impact: if nis2_impact.is_empty() { "Non évalué".to_string() } else { nis2_impact },
        enriched_by: "threatclaw_ai_8b_instruct".to_string(),
    }
}

/// Fallback basic HITL message when Instruct is unavailable.
fn basic_hitl_message(analysis: &str, severity: &str) -> HitlEnrichedMessage {
    HitlEnrichedMessage {
        summary: format!("[{}] {}", severity, analysis.chars().take(200).collect::<String>()),
        playbook: vec![],
        nis2_impact: "Non évalué — Instruct indisponible".to_string(),
        enriched_by: "basic_fallback".to_string(),
    }
}

/// Format enriched HITL message for Telegram (Markdown).
pub fn format_hitl_telegram(enriched: &HitlEnrichedMessage, cmd: &ValidatedCommand) -> String {
    let mut msg = format!(
        "*HITL — Approbation requise*\n\n{}\n\nCommande: `{}`\nRisque: {}\n",
        enriched.summary, cmd.rendered_cmd, cmd.risk
    );

    if !enriched.playbook.is_empty() {
        msg.push_str("\n*Playbook suggéré :*\n");
        for (i, step) in enriched.playbook.iter().enumerate() {
            msg.push_str(&format!("{}. {}\n", i + 1, step));
        }
    }

    msg.push_str(&format!("\n*Impact NIS2 :* {}\n", enriched.nis2_impact));
    msg.push_str(&format!("_enrichi par: {}_", enriched.enriched_by));
    msg
}

/// Send a HITL approval request to Telegram (enriched with Instruct).
pub async fn send_hitl_to_telegram(
    cmd: &ValidatedCommand,
    enriched: &HitlEnrichedMessage,
    store: &dyn crate::db::Database,
) -> Result<bool, String> {
    // Get Telegram config from DB
    let token = crate::channels::web::handlers::threatclaw_api::get_telegram_token(store).await
        .ok_or("Telegram bot token not configured")?;

    let chat_id = match store.get_setting("_system", "tc_config_channels").await {
        Ok(Some(channels)) => channels["telegram"]["chatId"].as_str()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .ok_or("Telegram chat_id not configured")?,
        _ => return Err("Telegram channels not configured".to_string()),
    };

    let text = format_hitl_telegram(enriched, cmd);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client.post(format!("https://api.telegram.org/bot{token}/sendMessage"))
        .json(&serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }))
        .send().await
        .map_err(|e| format!("Telegram send failed: {e}"))?;

    let data: serde_json::Value = resp.json().await.unwrap_or_default();
    if data["ok"].as_bool() == Some(true) {
        tracing::info!("HITL: Telegram message sent to chat_id={} (hitl_enriched_by: {})", chat_id, enriched.enriched_by);
        Ok(true)
    } else {
        Err(format!("Telegram error: {}", data["description"].as_str().unwrap_or("unknown")))
    }
}

/// Send a simple text HITL message to Telegram (no buttons, just notification with proposed actions).
pub async fn send_hitl_to_telegram_text(
    store: &dyn crate::db::Database,
    text: &str,
) -> Result<bool, String> {
    let token = crate::channels::web::handlers::threatclaw_api::get_telegram_token(store).await
        .ok_or("Telegram bot token not configured")?;

    let chat_id = match store.get_setting("_system", "tc_config_channels").await {
        Ok(Some(channels)) => channels["telegram"]["chatId"].as_str()
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .ok_or("Telegram chat_id not configured")?,
        _ => return Err("Telegram channels not configured".to_string()),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build().map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client.post(format!("https://api.telegram.org/bot{token}/sendMessage"))
        .json(&serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }))
        .send().await
        .map_err(|e| format!("Telegram send failed: {e}"))?;

    let data: serde_json::Value = resp.json().await.unwrap_or_default();
    if data["ok"].as_bool() == Some(true) {
        tracing::info!("HITL: Telegram HITL proposal sent to chat_id={}", chat_id);
        Ok(true)
    } else {
        Err(format!("Telegram error: {}", data["description"].as_str().unwrap_or("unknown")))
    }
}

/// Send a JSON payload to a Slack webhook URL.
async fn send_slack_webhook(webhook_url: &str, payload: &serde_json::Value) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client
        .post(webhook_url)
        .json(payload)
        .send()
        .await
        .map_err(|e| format!("Webhook send failed: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(format!("Slack returned {status}: {body}"))
    }
}

/// Send a result notification to Slack after execution.
pub async fn send_result_to_slack(
    request: &ApprovalRequest,
    slack_config: &SlackHitlConfig,
) -> Result<(), String> {
    let message = SlackMessageBuilder::build_result_message(request);
    send_slack_webhook(&slack_config.webhook_url, &message).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;

    fn test_nonce_manager() -> NonceManager {
        NonceManager::new(Duration::from_secs(3600))
    }

    fn test_slack_config() -> SlackHitlConfig {
        SlackHitlConfig {
            enabled: true,
            webhook_url: "https://hooks.slack.com/test".to_string(),
            bot_token: "xoxb-test".to_string(),
            default_channel: "#test-approvals".to_string(),
            approval_timeout_secs: 3600,
            allowed_approvers: vec!["U123".to_string()],
        }
    }

    fn test_validated_cmd() -> ValidatedCommand {
        let params: HashMap<String, String> = [("IP".to_string(), "10.0.0.42".to_string())].into();
        remediation_whitelist::validate_remediation("net-002", &params).unwrap()
    }

    #[test]
    fn test_risk_to_urgency() {
        assert!(matches!(risk_to_urgency(RiskLevel::Low), Urgency::Low));
        assert!(matches!(risk_to_urgency(RiskLevel::Medium), Urgency::Medium));
        assert!(matches!(risk_to_urgency(RiskLevel::High), Urgency::High));
        assert!(matches!(risk_to_urgency(RiskLevel::Critical), Urgency::Critical));
    }

    #[tokio::test]
    async fn test_send_approval_slack_not_configured() {
        let nonce_mgr = test_nonce_manager();
        let mut config = test_slack_config();
        config.enabled = false;

        let cmd = test_validated_cmd();
        let result = send_approval_to_slack(&cmd, "test", &nonce_mgr, &config).await;
        assert!(matches!(result, Err(HitlBridgeError::SlackNotConfigured)));
    }

    #[tokio::test]
    async fn test_process_callback_rejected() {
        let nonce_mgr = test_nonce_manager();
        let nonce = nonce_mgr.generate("net-002").await;

        let params: HashMap<String, String> = [("IP".to_string(), "10.0.0.42".to_string())].into();
        let result = process_slack_callback(&nonce, false, "rssi@test.com", &nonce_mgr, &params).await;

        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(!r.approved);
        assert!(!r.executed);
    }

    #[tokio::test]
    async fn test_process_callback_replay_blocked() {
        let nonce_mgr = test_nonce_manager();
        let nonce = nonce_mgr.generate("net-002").await;

        let params: HashMap<String, String> = [("IP".to_string(), "10.0.0.42".to_string())].into();

        // First use: OK (rejected so no execution)
        let r1 = process_slack_callback(&nonce, false, "admin", &nonce_mgr, &params).await;
        assert!(r1.is_ok());

        // Second use: REPLAY
        let r2 = process_slack_callback(&nonce, true, "attacker", &nonce_mgr, &params).await;
        assert!(matches!(r2, Err(HitlBridgeError::NonceError(NonceError::AlreadyUsed))));
    }

    #[tokio::test]
    async fn test_process_callback_invalid_nonce() {
        let nonce_mgr = test_nonce_manager();
        let params: HashMap<String, String> = HashMap::new();

        let result = process_slack_callback("fake-nonce-12345678901234567890", true, "admin", &nonce_mgr, &params).await;
        assert!(matches!(result, Err(HitlBridgeError::NonceError(NonceError::NotFound))));
    }

    #[tokio::test]
    async fn test_process_callback_approved_executes() {
        let nonce_mgr = test_nonce_manager();
        let nonce = nonce_mgr.generate("net-002").await;

        let params: HashMap<String, String> = [("IP".to_string(), "10.0.0.42".to_string())].into();

        let result = process_slack_callback(&nonce, true, "rssi@test.com", &nonce_mgr, &params).await;
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.approved);
        assert!(r.executed);
        // fail2ban might not be installed, but the executor ran
        assert!(r.execution_success.is_some());
    }

    #[test]
    fn test_hitl_bridge_error_display() {
        assert!(HitlBridgeError::SlackNotConfigured.to_string().contains("not configured"));
        assert!(HitlBridgeError::SlackSendFailed("timeout".to_string()).to_string().contains("timeout"));
        assert!(HitlBridgeError::NonceError(NonceError::AlreadyUsed).to_string().contains("replay"));
    }
}
