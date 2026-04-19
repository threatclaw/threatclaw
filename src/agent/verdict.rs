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
        /// Phase 4 (v1.1.0-beta): evidence citations that support the verdict.
        /// Serde default + skip_serializing_if keep backward-compat with
        /// historical verdicts that never had this field.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        evidence_citations: Vec<crate::agent::evidence_tracker::EvidenceCitation>,
    },
    /// False positive — auto-close findings, no notification
    FalsePositive {
        analysis: String,
        confidence: f64,
        reason: String,
    },
    /// Inconclusive — visible in dashboard but never notified (not actionable)
    Inconclusive {
        analysis: String,
        confidence: f64,
        partial_findings: Vec<String>,
    },
    /// Informational — not urgent, add to daily digest
    Informational { analysis: String, summary: String },
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
    /// Only confirmed threats warrant a notification. Inconclusive verdicts
    /// are visible in the dashboard but never spam the RSSI — a "I don't know"
    /// is not actionable and drowns real alerts.
    pub fn should_notify(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
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

    /// Human-readable analysis text (for notifications / incidents page)
    pub fn analysis_text(&self) -> String {
        match self {
            Self::Confirmed { analysis, .. } => analysis.clone(),
            Self::FalsePositive {
                analysis, reason, ..
            } => format!("{} (raison : {})", analysis, reason),
            Self::Inconclusive { analysis, .. } => analysis.clone(),
            Self::Informational { analysis, summary } => format!("{}\n\n{}", analysis, summary),
            Self::Error {
                reason,
                partial_analysis,
            } => {
                if let Some(p) = partial_analysis {
                    format!("Erreur : {} — {}", reason, p)
                } else {
                    format!("Erreur : {}", reason)
                }
            }
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
                evidence_citations: _,
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
                    msg.push_str(&format!("\u{1f517} {}\n", correlations.join(", ")));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::evidence_tracker::{EvidenceCitation, EvidenceType};

    #[test]
    fn test_confirmed_without_citations_serializes_without_the_field() {
        let v = InvestigationVerdict::Confirmed {
            analysis: "x".into(),
            severity: "HIGH".into(),
            confidence: 0.9,
            correlations: vec![],
            proposed_actions: vec![],
            llm_level: "L2".into(),
            evidence_citations: vec![],
        };
        let json = serde_json::to_value(&v).unwrap();
        assert!(
            json.get("evidence_citations").is_none(),
            "empty citations must be skipped for BC: {json}"
        );
    }

    #[test]
    fn test_confirmed_with_citations_serializes_them() {
        let v = InvestigationVerdict::Confirmed {
            analysis: "x".into(),
            severity: "HIGH".into(),
            confidence: 0.9,
            correlations: vec![],
            proposed_actions: vec![],
            llm_level: "L2".into(),
            evidence_citations: vec![EvidenceCitation {
                claim: "13 failed auths".into(),
                evidence_type: EvidenceType::Alert,
                evidence_id: "42".into(),
                excerpt: None,
            }],
        };
        let json = serde_json::to_value(&v).unwrap();
        assert!(json["evidence_citations"].is_array());
        assert_eq!(json["evidence_citations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_legacy_confirmed_deserializes_without_citations() {
        let legacy = r#"{
            "type": "Confirmed",
            "analysis": "x",
            "severity": "HIGH",
            "confidence": 0.9,
            "correlations": [],
            "proposed_actions": [],
            "llm_level": "L1"
        }"#;
        let v: InvestigationVerdict = serde_json::from_str(legacy).unwrap();
        match v {
            InvestigationVerdict::Confirmed {
                evidence_citations, ..
            } => assert!(evidence_citations.is_empty()),
            _ => panic!("expected Confirmed"),
        }
    }
}
