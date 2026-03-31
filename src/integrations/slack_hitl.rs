//! Human-in-the-Loop Slack Integration
//!
//! Sends approval requests to Slack and waits for human response.
//! Used for security-sensitive actions that require explicit human
//! authorization before execution (phishing campaigns, remediations,
//! destructive operations, external notifications).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Types of actions requiring approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalAction {
    /// Launch a phishing simulation campaign.
    PhishingCampaignLaunch {
        campaign_name: String,
        target_count: usize,
    },
    /// Execute a remediation action.
    Remediation {
        action: String,
        target: String,
        risk_level: String,
    },
    /// Destructive operation (delete, reset, revoke).
    DestructiveOp {
        operation: String,
        resource: String,
    },
    /// Send external notification.
    ExternalNotification {
        channel: String,
        message_preview: String,
    },
    /// Custom approval request.
    Custom {
        title: String,
        description: String,
    },
}

impl ApprovalAction {
    /// Human-readable label for the action type.
    pub fn label(&self) -> &str {
        match self {
            Self::PhishingCampaignLaunch { .. } => "Phishing Campaign Launch",
            Self::Remediation { .. } => "Remediation",
            Self::DestructiveOp { .. } => "Destructive Operation",
            Self::ExternalNotification { .. } => "External Notification",
            Self::Custom { .. } => "Custom Request",
        }
    }

    /// Short summary of the action for display in Slack messages.
    pub fn summary(&self) -> String {
        match self {
            Self::PhishingCampaignLaunch {
                campaign_name,
                target_count,
            } => format!(
                "Launch phishing campaign \"{campaign_name}\" targeting {target_count} users"
            ),
            Self::Remediation {
                action,
                target,
                risk_level,
            } => format!("{action} on {target} (risk: {risk_level})"),
            Self::DestructiveOp {
                operation,
                resource,
            } => format!("{operation} {resource}"),
            Self::ExternalNotification {
                channel,
                message_preview,
            } => {
                let preview = if message_preview.len() > 80 {
                    format!("{}...", &message_preview[..77])
                } else {
                    message_preview.clone()
                };
                format!("Send to {channel}: {preview}")
            }
            Self::Custom { title, .. } => title.clone(),
        }
    }

    /// Emoji icon for this action type (used in Slack blocks).
    pub fn icon(&self) -> &str {
        match self {
            Self::PhishingCampaignLaunch { .. } => ":fishing_pole_and_fish:",
            Self::Remediation { .. } => ":wrench:",
            Self::DestructiveOp { .. } => ":warning:",
            Self::ExternalNotification { .. } => ":mega:",
            Self::Custom { .. } => ":clipboard:",
        }
    }
}

/// Status of an approval request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    Approved {
        by: String,
        at: String,
    },
    Rejected {
        by: String,
        at: String,
        reason: Option<String>,
    },
    Expired,
}

impl ApprovalStatus {
    /// Whether the request has been finalized (approved, rejected, or expired).
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// Human-readable label.
    pub fn label(&self) -> &str {
        match self {
            Self::Pending => "Pending",
            Self::Approved { .. } => "Approved",
            Self::Rejected { .. } => "Rejected",
            Self::Expired => "Expired",
        }
    }
}

/// Urgency level — determines the approval timeout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Urgency {
    /// 24 h timeout.
    Low,
    /// 4 h timeout.
    Medium,
    /// 1 h timeout.
    High,
    /// 15 min timeout.
    Critical,
}

impl Urgency {
    /// Timeout for this urgency level in seconds.
    pub fn timeout_secs(&self) -> u64 {
        match self {
            Self::Low => 86400,      // 24 h
            Self::Medium => 14400,   // 4 h
            Self::High => 3600,      // 1 h
            Self::Critical => 900,   // 15 min
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }

    /// Slack colour attachment bar.
    pub fn color(&self) -> &str {
        match self {
            Self::Low => "#36a64f",      // green
            Self::Medium => "#daa038",   // amber
            Self::High => "#e01e5a",     // red
            Self::Critical => "#8b0000", // dark red
        }
    }
}

/// An approval request sent to Slack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub action: ApprovalAction,
    pub requester: String,
    pub urgency: Urgency,
    pub context: String,
    pub status: ApprovalStatus,
    pub created_at: String,
    pub expires_at: String,
    pub slack_channel: String,
    pub slack_message_ts: Option<String>,
}

impl ApprovalRequest {
    /// Create a new pending approval request with an auto-generated UUID.
    pub fn new(
        action: ApprovalAction,
        requester: String,
        urgency: Urgency,
        context: String,
        slack_channel: String,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let expires_at =
            now + chrono::Duration::seconds(urgency.timeout_secs() as i64);

        Self {
            id,
            action,
            requester,
            urgency,
            context,
            status: ApprovalStatus::Pending,
            created_at: now.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            slack_channel,
            slack_message_ts: None,
        }
    }

    /// Mark the request as approved.
    pub fn approve(&mut self, by: String) {
        self.status = ApprovalStatus::Approved {
            by,
            at: chrono::Utc::now().to_rfc3339(),
        };
    }

    /// Mark the request as rejected.
    pub fn reject(&mut self, by: String, reason: Option<String>) {
        self.status = ApprovalStatus::Rejected {
            by,
            at: chrono::Utc::now().to_rfc3339(),
            reason,
        };
    }

    /// Mark the request as expired.
    pub fn expire(&mut self) {
        self.status = ApprovalStatus::Expired;
    }

    /// Whether the request is still waiting for a decision.
    pub fn is_pending(&self) -> bool {
        matches!(self.status, ApprovalStatus::Pending)
    }
}

// ---------------------------------------------------------------------------
// Slack Block Kit message builder
// ---------------------------------------------------------------------------

/// Slack Block Kit message builder for approval requests.
pub struct SlackMessageBuilder;

impl SlackMessageBuilder {
    /// Build an interactive approval request message (Block Kit).
    pub fn build_approval_message(request: &ApprovalRequest) -> serde_json::Value {
        let action_summary = request.action.summary();
        let icon = request.action.icon();
        let urgency_label = request.urgency.label();
        let color = request.urgency.color();

        serde_json::json!({
            "channel": request.slack_channel,
            "text": format!("{icon} Approval required: {action_summary}"),
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": format!("{icon} Approval Required"),
                                "emoji": true
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": format!("*Action:*\n{action_summary}")
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": format!("*Type:*\n{}", request.action.label())
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": format!("*Urgency:*\n{urgency_label}")
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": format!("*Requester:*\n{}", request.requester)
                                }
                            ]
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": format!("*Context:*\n{}", request.context)
                            }
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": format!(
                                    "_Request ID: `{}`_\n_Expires: {}_",
                                    request.id, request.expires_at
                                )
                            }
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {
                                        "type": "plain_text",
                                        "text": "Approve",
                                        "emoji": true
                                    },
                                    "style": "primary",
                                    "action_id": "hitl_approve",
                                    "value": request.id
                                },
                                {
                                    "type": "button",
                                    "text": {
                                        "type": "plain_text",
                                        "text": "Reject",
                                        "emoji": true
                                    },
                                    "style": "danger",
                                    "action_id": "hitl_reject",
                                    "value": request.id
                                }
                            ]
                        }
                    ]
                }
            ]
        })
    }

    /// Build a result / follow-up message after a decision has been made.
    pub fn build_result_message(request: &ApprovalRequest) -> serde_json::Value {
        let action_summary = request.action.summary();
        let (status_text, status_emoji) = match &request.status {
            ApprovalStatus::Approved { by, at, .. } => {
                (format!("Approved by {by} at {at}"), ":white_check_mark:")
            }
            ApprovalStatus::Rejected {
                by,
                at,
                reason,
            } => {
                let reason_str = reason
                    .as_deref()
                    .map(|r| format!("\n*Reason:* {r}"))
                    .unwrap_or_default();
                (
                    format!("Rejected by {by} at {at}{reason_str}"),
                    ":x:",
                )
            }
            ApprovalStatus::Expired => {
                ("Request expired without a decision.".to_string(), ":hourglass:")
            }
            ApprovalStatus::Pending => {
                ("Pending".to_string(), ":hourglass_flowing_sand:")
            }
        };

        serde_json::json!({
            "channel": request.slack_channel,
            "text": format!("{status_emoji} {action_summary}: {}", request.status.label()),
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!(
                            "{status_emoji} *{}*\n\n*Action:* {action_summary}\n*Status:* {status_text}",
                            request.action.label()
                        )
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": format!("Request ID: `{}`", request.id)
                        }
                    ]
                }
            ]
        })
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for Slack HITL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackHitlConfig {
    /// Whether the HITL integration is enabled.
    pub enabled: bool,
    /// Slack incoming webhook URL.
    pub webhook_url: String,
    /// Slack bot token for interactive messages.
    pub bot_token: String,
    /// Default channel for approval requests.
    pub default_channel: String,
    /// Default approval timeout in seconds (overridden by urgency).
    pub approval_timeout_secs: u64,
    /// Slack user IDs allowed to approve/reject requests.
    pub allowed_approvers: Vec<String>,
}

impl Default for SlackHitlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_url: String::new(),
            bot_token: String::new(),
            default_channel: "#security-approvals".to_string(),
            approval_timeout_secs: 3600,
            allowed_approvers: Vec::new(),
        }
    }
}

impl SlackHitlConfig {
    /// Validate that the configuration has the minimum required fields.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.enabled {
            if self.webhook_url.is_empty() {
                errors.push("webhook_url is required when HITL is enabled".to_string());
            }
            if self.bot_token.is_empty() {
                errors.push("bot_token is required when HITL is enabled".to_string());
            }
            if self.default_channel.is_empty() {
                errors.push("default_channel is required when HITL is enabled".to_string());
            }
            if self.allowed_approvers.is_empty() {
                errors.push("at least one allowed_approver is required".to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check whether a Slack user ID is an allowed approver.
    pub fn is_allowed_approver(&self, user_id: &str) -> bool {
        self.allowed_approvers.iter().any(|id| id == user_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- ApprovalAction variants -------------------------------------------

    #[test]
    fn test_phishing_action_label() {
        let action = ApprovalAction::PhishingCampaignLaunch {
            campaign_name: "Q1 Test".to_string(),
            target_count: 150,
        };
        assert_eq!(action.label(), "Phishing Campaign Launch");
    }

    #[test]
    fn test_remediation_action_summary() {
        let action = ApprovalAction::Remediation {
            action: "Quarantine".to_string(),
            target: "host-42".to_string(),
            risk_level: "high".to_string(),
        };
        assert_eq!(action.summary(), "Quarantine on host-42 (risk: high)");
    }

    #[test]
    fn test_destructive_op_summary() {
        let action = ApprovalAction::DestructiveOp {
            operation: "Revoke".to_string(),
            resource: "API key abc123".to_string(),
        };
        assert_eq!(action.summary(), "Revoke API key abc123");
    }

    #[test]
    fn test_external_notification_truncation() {
        let long_msg = "A".repeat(200);
        let action = ApprovalAction::ExternalNotification {
            channel: "#alerts".to_string(),
            message_preview: long_msg,
        };
        let summary = action.summary();
        assert!(summary.len() < 120, "Summary should be truncated");
        assert!(summary.ends_with("..."));
    }

    #[test]
    fn test_custom_action_icon() {
        let action = ApprovalAction::Custom {
            title: "Test".to_string(),
            description: "Desc".to_string(),
        };
        assert_eq!(action.icon(), ":clipboard:");
    }

    // -- Urgency timeout values -------------------------------------------

    #[test]
    fn test_urgency_low_timeout() {
        assert_eq!(Urgency::Low.timeout_secs(), 86400);
    }

    #[test]
    fn test_urgency_medium_timeout() {
        assert_eq!(Urgency::Medium.timeout_secs(), 14400);
    }

    #[test]
    fn test_urgency_high_timeout() {
        assert_eq!(Urgency::High.timeout_secs(), 3600);
    }

    #[test]
    fn test_urgency_critical_timeout() {
        assert_eq!(Urgency::Critical.timeout_secs(), 900);
    }

    // -- Message builder output -------------------------------------------

    #[test]
    fn test_approval_message_is_valid_json_with_blocks() {
        let request = ApprovalRequest {
            id: "req-001".to_string(),
            action: ApprovalAction::DestructiveOp {
                operation: "Delete".to_string(),
                resource: "user jdoe".to_string(),
            },
            requester: "threatclaw-agent".to_string(),
            urgency: Urgency::High,
            context: "Compromised account detected".to_string(),
            status: ApprovalStatus::Pending,
            created_at: "2026-03-18T10:00:00Z".to_string(),
            expires_at: "2026-03-18T11:00:00Z".to_string(),
            slack_channel: "#security-approvals".to_string(),
            slack_message_ts: None,
        };

        let msg = SlackMessageBuilder::build_approval_message(&request);

        // Must be a valid JSON object.
        assert!(msg.is_object());

        // Must contain channel.
        assert_eq!(msg["channel"], "#security-approvals");

        // Must contain attachments with blocks.
        let attachments = msg["attachments"].as_array().expect("attachments array");
        assert!(!attachments.is_empty());
        let blocks = attachments[0]["blocks"].as_array().expect("blocks array");
        assert!(blocks.len() >= 4, "Expected at least 4 blocks, got {}", blocks.len());

        // First block must be a header.
        assert_eq!(blocks[0]["type"], "header");

        // Last block must be actions with approve/reject buttons.
        let last_block = blocks.last().unwrap();
        assert_eq!(last_block["type"], "actions");
        let elements = last_block["elements"].as_array().expect("elements");
        assert_eq!(elements.len(), 2);
        assert_eq!(elements[0]["action_id"], "hitl_approve");
        assert_eq!(elements[1]["action_id"], "hitl_reject");
    }

    #[test]
    fn test_result_message_approved() {
        let request = ApprovalRequest {
            id: "req-002".to_string(),
            action: ApprovalAction::Remediation {
                action: "Isolate".to_string(),
                target: "workstation-7".to_string(),
                risk_level: "critical".to_string(),
            },
            requester: "soc-analyst".to_string(),
            urgency: Urgency::Critical,
            context: "Lateral movement detected".to_string(),
            status: ApprovalStatus::Approved {
                by: "U12345".to_string(),
                at: "2026-03-18T10:05:00Z".to_string(),
            },
            created_at: "2026-03-18T10:00:00Z".to_string(),
            expires_at: "2026-03-18T10:15:00Z".to_string(),
            slack_channel: "#sec-ops".to_string(),
            slack_message_ts: Some("1710756000.000001".to_string()),
        };

        let msg = SlackMessageBuilder::build_result_message(&request);
        assert!(msg.is_object());

        let text = msg["text"].as_str().unwrap();
        assert!(text.contains("Approved"), "Result text should contain 'Approved'");

        let blocks = msg["blocks"].as_array().expect("blocks");
        assert!(!blocks.is_empty());
    }

    #[test]
    fn test_result_message_rejected_with_reason() {
        let request = ApprovalRequest {
            id: "req-003".to_string(),
            action: ApprovalAction::PhishingCampaignLaunch {
                campaign_name: "Spring Campaign".to_string(),
                target_count: 500,
            },
            requester: "auto-scheduler".to_string(),
            urgency: Urgency::Medium,
            context: "Quarterly phishing simulation".to_string(),
            status: ApprovalStatus::Rejected {
                by: "U99999".to_string(),
                at: "2026-03-18T12:00:00Z".to_string(),
                reason: Some("Too many targets for a single campaign".to_string()),
            },
            created_at: "2026-03-18T10:00:00Z".to_string(),
            expires_at: "2026-03-18T14:00:00Z".to_string(),
            slack_channel: "#phishing-ops".to_string(),
            slack_message_ts: None,
        };

        let msg = SlackMessageBuilder::build_result_message(&request);
        let text = msg["text"].as_str().unwrap();
        assert!(text.contains("Rejected"));
    }

    // -- ApprovalStatus transitions ----------------------------------------

    #[test]
    fn test_status_pending_is_not_terminal() {
        assert!(!ApprovalStatus::Pending.is_terminal());
    }

    #[test]
    fn test_status_approved_is_terminal() {
        let status = ApprovalStatus::Approved {
            by: "U111".to_string(),
            at: "2026-03-18T10:00:00Z".to_string(),
        };
        assert!(status.is_terminal());
    }

    #[test]
    fn test_status_rejected_is_terminal() {
        let status = ApprovalStatus::Rejected {
            by: "U222".to_string(),
            at: "2026-03-18T10:00:00Z".to_string(),
            reason: None,
        };
        assert!(status.is_terminal());
    }

    #[test]
    fn test_status_expired_is_terminal() {
        assert!(ApprovalStatus::Expired.is_terminal());
    }

    #[test]
    fn test_approve_transitions_status() {
        let mut req = ApprovalRequest::new(
            ApprovalAction::Custom {
                title: "Test".to_string(),
                description: "Test approval".to_string(),
            },
            "tester".to_string(),
            Urgency::Low,
            "Testing transition".to_string(),
            "#test".to_string(),
        );
        assert!(req.is_pending());
        req.approve("U555".to_string());
        assert!(!req.is_pending());
        assert!(matches!(req.status, ApprovalStatus::Approved { .. }));
    }

    #[test]
    fn test_reject_transitions_status() {
        let mut req = ApprovalRequest::new(
            ApprovalAction::DestructiveOp {
                operation: "Reset".to_string(),
                resource: "MFA for user X".to_string(),
            },
            "tester".to_string(),
            Urgency::High,
            "Suspicious MFA reset request".to_string(),
            "#test".to_string(),
        );
        req.reject("U666".to_string(), Some("Not authorized".to_string()));
        assert!(matches!(
            req.status,
            ApprovalStatus::Rejected { reason: Some(_), .. }
        ));
    }

    #[test]
    fn test_expire_transitions_status() {
        let mut req = ApprovalRequest::new(
            ApprovalAction::ExternalNotification {
                channel: "#public".to_string(),
                message_preview: "Incident update".to_string(),
            },
            "tester".to_string(),
            Urgency::Critical,
            "Time-sensitive notification".to_string(),
            "#test".to_string(),
        );
        req.expire();
        assert_eq!(req.status, ApprovalStatus::Expired);
    }

    // -- Config defaults ---------------------------------------------------

    #[test]
    fn test_config_default_values() {
        let config = SlackHitlConfig::default();
        assert!(!config.enabled);
        assert!(config.webhook_url.is_empty());
        assert!(config.bot_token.is_empty());
        assert_eq!(config.default_channel, "#security-approvals");
        assert_eq!(config.approval_timeout_secs, 3600);
        assert!(config.allowed_approvers.is_empty());
    }

    #[test]
    fn test_config_disabled_validates_ok() {
        let config = SlackHitlConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_enabled_without_fields_fails() {
        let mut config = SlackHitlConfig::default();
        config.enabled = true;
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.len() >= 3, "Expected at least 3 validation errors");
    }

    #[test]
    fn test_config_enabled_with_all_fields_validates() {
        let config = SlackHitlConfig {
            enabled: true,
            webhook_url: "https://hooks.slack.com/services/T00/B00/xxx".to_string(),
            bot_token: "xoxb-test-token".to_string(),
            default_channel: "#approvals".to_string(),
            approval_timeout_secs: 1800,
            allowed_approvers: vec!["U123".to_string(), "U456".to_string()],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_is_allowed_approver() {
        let config = SlackHitlConfig {
            enabled: true,
            webhook_url: "https://hooks.slack.com/test".to_string(),
            bot_token: "xoxb-token".to_string(),
            default_channel: "#approvals".to_string(),
            approval_timeout_secs: 3600,
            allowed_approvers: vec!["U111".to_string(), "U222".to_string()],
        };
        assert!(config.is_allowed_approver("U111"));
        assert!(config.is_allowed_approver("U222"));
        assert!(!config.is_allowed_approver("U999"));
    }

    // -- Serialization round-trip ------------------------------------------

    #[test]
    fn test_approval_request_serialization_roundtrip() {
        let req = ApprovalRequest::new(
            ApprovalAction::PhishingCampaignLaunch {
                campaign_name: "Q2 Campaign".to_string(),
                target_count: 75,
            },
            "scheduler".to_string(),
            Urgency::Medium,
            "Quarterly test".to_string(),
            "#phishing".to_string(),
        );

        let json = serde_json::to_string(&req).expect("serialize");
        let deserialized: ApprovalRequest =
            serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.id, req.id);
        assert_eq!(deserialized.requester, "scheduler");
        assert_eq!(deserialized.slack_channel, "#phishing");
        assert!(deserialized.is_pending());
    }

    // -- Urgency colour values ---------------------------------------------

    #[test]
    fn test_urgency_colors_are_hex() {
        for urgency in &[Urgency::Low, Urgency::Medium, Urgency::High, Urgency::Critical] {
            let color = urgency.color();
            assert!(color.starts_with('#'), "Color should start with #");
            assert!(color.len() == 7, "Color should be #RRGGBB format");
        }
    }
}
