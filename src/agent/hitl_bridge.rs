//! HITL Bridge — connects the ReAct cycle to Slack approval flow.
//!
//! Flow:
//! 1. ReAct cycle proposes validated actions
//! 2. Bridge creates ApprovalRequest with nonce
//! 3. Sends Block Kit message to Slack via webhook
//! 4. Webhook callback validates nonce + executes via executor
//! 5. Result written to audit log
//!
//! This module is the glue between:
//! - `react_cycle.rs` (proposes actions)
//! - `hitl_nonce.rs` (anti-replay)
//! - `slack_hitl.rs` (Slack Block Kit)
//! - `executor.rs` (executes validated commands)
//! - `remediation_whitelist.rs` (validates commands)

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
