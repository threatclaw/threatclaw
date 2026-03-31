//! Investigation Verdict — the output of a ReAct investigation.
//!
//! After the investigation runner completes its analysis (L1/L2 + skills),
//! it produces a verdict that determines whether to notify the RSSI,
//! auto-close findings, or add to the daily digest.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent::incident_dossier::IncidentDossier;

/// Verdict produced by the ReAct investigation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InvestigationVerdict {
    /// Incident confirmed — notify RSSI + propose HITL actions
    Confirmed {
        analysis: String,
        severity: String,
        confidence: f64,
        correlations: Vec<String>,
        proposed_actions: Vec<ProposedAction>,
        llm_level: String,
    },
    /// False positive — auto-close findings, no notification
    FalsePositive {
        analysis: String,
        confidence: f64,
        reason: String,
    },
    /// Inconclusive — notify with real confidence level
    Inconclusive {
        analysis: String,
        confidence: f64,
        partial_findings: Vec<String>,
    },
    /// Informational — not urgent, add to daily digest
    Informational {
        analysis: String,
        summary: String,
    },
    /// Error or timeout during investigation
    Error {
        reason: String,
        partial_analysis: Option<String>,
    },
}

/// Proposed HITL action for the RSSI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    pub cmd_id: String,
    pub params: Value,
    pub rationale: String,
    pub label: String,
}

/// Complete investigation result (verdict + metadata)
#[derive(Debug, Clone, Serialize)]
pub struct InvestigationResult {
    pub dossier_id: uuid::Uuid,
    pub asset: String,
    pub verdict: InvestigationVerdict,
    pub duration_secs: u64,
    pub iterations: usize,
    pub skill_calls: usize,
    pub completed_at: DateTime<Utc>,
}

impl InvestigationVerdict {
    /// Should the RSSI be notified for this verdict?
    pub fn should_notify(&self) -> bool {
        matches!(self, Self::Confirmed { .. } | Self::Inconclusive { .. })
    }

    /// Severity string for notification routing
    pub fn severity(&self) -> &str {
        match self {
            Self::Confirmed { severity, .. } => severity.as_str(),
            Self::Inconclusive { .. } => "MEDIUM",
            Self::Informational { .. } => "LOW",
            Self::FalsePositive { .. } | Self::Error { .. } => "INFO",
        }
    }

    /// Confidence level (0.0 - 1.0)
    pub fn confidence(&self) -> f64 {
        match self {
            Self::Confirmed { confidence, .. } => *confidence,
            Self::FalsePositive { confidence, .. } => *confidence,
            Self::Inconclusive { confidence, .. } => *confidence,
            _ => 0.0,
        }
    }

    /// Verdict type as string (for delta-based re-notification)
    pub fn verdict_type(&self) -> &str {
        match self {
            Self::Confirmed { .. } => "confirmed",
            Self::FalsePositive { .. } => "false_positive",
            Self::Inconclusive { .. } => "inconclusive",
            Self::Informational { .. } => "informational",
            Self::Error { .. } => "error",
        }
    }
}

impl InvestigationResult {
    /// Format Telegram notification message from the verdict
    pub fn format_telegram(&self, dossier: &IncidentDossier) -> Option<String> {
        match &self.verdict {
            InvestigationVerdict::Confirmed {
                analysis,
                severity,
                confidence,
                correlations,
                proposed_actions,
                llm_level,
            } => {
                let emoji = match severity.as_str() {
                    "CRITICAL" => "\u{1f534}",
                    "HIGH" => "\u{1f7e0}",
                    _ => "\u{1f7e1}",
                };

                let mut msg = format!(
                    "{emoji} *INCIDENT {severity}* \u{2014} {asset}\n\
                     \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\n\
                     {analysis}\n\n",
                    asset = self.asset,
                );

                // Kill chain
                if dossier.correlations.kill_chain_detected
                    && !dossier.correlations.kill_chain_steps.is_empty()
                {
                    let chain: Vec<&str> = dossier
                        .correlations
                        .kill_chain_steps
                        .iter()
                        .map(|s| s.technique_id.as_str())
                        .collect();
                    msg.push_str(&format!(
                        "\u{1f4ca} Kill chain : {}\n",
                        chain.join(" \u{2192} ")
                    ));
                }

                // Enriched IPs
                for rep in dossier.enrichment.ip_reputations.iter().take(3) {
                    msg.push_str(&format!(
                        "\u{1f3af} {} ({} \u{2014} {})\n",
                        rep.ip, rep.classification, rep.details
                    ));
                }

                // Correlations
                if !correlations.is_empty() {
                    msg.push_str(&format!(
                        "\u{1f517} {}\n",
                        correlations.join(", ")
                    ));
                }

                msg.push_str(&format!(
                    "\n\u{1f4c8} Confiance : {:.0}% ({llm_level})\n\
                     \u{1f553} Investigation : {}s, {} it\u{00e9}rations, {} skills\n",
                    confidence * 100.0,
                    self.duration_secs,
                    self.iterations,
                    self.skill_calls,
                ));

                // HITL actions
                if !proposed_actions.is_empty() {
                    msg.push_str("\nActions recommand\u{00e9}es :\n");
                    for action in proposed_actions {
                        msg.push_str(&format!("  \u{25b6} {}\n", action.label));
                    }
                }

                Some(msg)
            }

            InvestigationVerdict::Inconclusive {
                analysis,
                confidence,
                ..
            } => Some(format!(
                "\u{1f7e1} *SITUATION SUSPECTE* \u{2014} {asset}\n\
                 \u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\u{2501}\n\n\
                 Investigation non concluante ({conf:.0}% confiance).\n\n\
                 {analysis}\n\n\
                 \u{1f50d} Investiguer manuellement recommand\u{00e9}.",
                asset = self.asset,
                conf = confidence * 100.0,
            )),

            _ => None,
        }
    }
}
