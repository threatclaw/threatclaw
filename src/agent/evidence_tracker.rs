//! Evidence citation tracker (phase 4 v1.1.0-beta).
//!
//! Each LLM verdict may carry `evidence_citations`: explicit pointers from
//! natural-language claims to the row IDs (alert, finding, log, graph node)
//! that support the claim. The phase-4 pipeline:
//!
//! 1. The LLM produces citations as part of its structured JSON output
//!    (schema constraint — see `forensic_schema`).
//! 2. `validate_citations(cit, dossier)` cross-checks each citation's
//!    `evidence_id` against the corresponding collection in the dossier.
//! 3. A `CitationReport` summarizes verified, unverified, and fabricated
//!    citations. Rule E of the reconciler consumes this report.
//!
//! Design: pure sync functions, no DB I/O. The dossier in memory is the
//! ground truth for "what the LLM saw", so if an evidence_id is absent
//! from the dossier the citation is necessarily fabricated.

use serde::{Deserialize, Serialize};

use crate::agent::incident_dossier::IncidentDossier;

/// Type of evidence referenced by a citation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    Alert,
    Finding,
    Log,
    GraphNode,
}

/// A single evidence citation produced by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceCitation {
    /// Short natural-language claim (e.g. "13 failed auth events from the same IP").
    pub claim: String,
    /// Which family of evidence this points to.
    pub evidence_type: EvidenceType,
    /// Identifier of the evidence row (string so we can represent both
    /// i64 row IDs and log-line hashes uniformly).
    pub evidence_id: String,
    /// Optional snippet used by the dashboard for quick preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
}

/// Classification of a citation after cross-checking against a dossier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationStatus {
    /// evidence_id matches an entry in the dossier's corresponding collection.
    Verified,
    /// evidence_id is not in the dossier, but its type is unverifiable
    /// in-process (Log, GraphNode). Treat as warning.
    Unverifiable,
    /// evidence_id claims to point to an alert/finding but no such ID is
    /// in the dossier — definitely fabricated.
    Fabricated,
}

/// Report built by `validate_citations`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CitationReport {
    pub verified: Vec<EvidenceCitation>,
    pub unverifiable: Vec<EvidenceCitation>,
    pub fabricated: Vec<EvidenceCitation>,
}

impl CitationReport {
    pub fn total(&self) -> usize {
        self.verified.len() + self.unverifiable.len() + self.fabricated.len()
    }

    pub fn fabricated_count(&self) -> usize {
        self.fabricated.len()
    }

    pub fn verified_ratio(&self) -> f64 {
        let t = self.total();
        if t == 0 {
            return 1.0;
        }
        self.verified.len() as f64 / t as f64
    }
}

/// Cross-check each citation against what the dossier actually contains.
pub fn validate_citations(
    citations: &[EvidenceCitation],
    dossier: &IncidentDossier,
) -> CitationReport {
    let mut report = CitationReport::default();

    let alert_ids: std::collections::HashSet<String> = dossier
        .sigma_alerts
        .iter()
        .map(|a| a.id.to_string())
        .collect();
    let finding_ids: std::collections::HashSet<String> =
        dossier.findings.iter().map(|f| f.id.to_string()).collect();

    for citation in citations {
        let status = match citation.evidence_type {
            EvidenceType::Alert => {
                if alert_ids.contains(&citation.evidence_id) {
                    CitationStatus::Verified
                } else {
                    CitationStatus::Fabricated
                }
            }
            EvidenceType::Finding => {
                if finding_ids.contains(&citation.evidence_id) {
                    CitationStatus::Verified
                } else {
                    CitationStatus::Fabricated
                }
            }
            EvidenceType::Log | EvidenceType::GraphNode => CitationStatus::Unverifiable,
        };

        match status {
            CitationStatus::Verified => report.verified.push(citation.clone()),
            CitationStatus::Unverifiable => report.unverifiable.push(citation.clone()),
            CitationStatus::Fabricated => report.fabricated.push(citation.clone()),
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::incident_dossier::*;
    use crate::agent::intelligence_engine::NotificationLevel;
    use chrono::Utc;
    use uuid::Uuid;

    fn dossier_with_ids(alert_ids: &[i64], finding_ids: &[i64]) -> IncidentDossier {
        IncidentDossier {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            primary_asset: "test".into(),
            findings: finding_ids
                .iter()
                .map(|&id| DossierFinding {
                    id,
                    title: format!("finding {id}"),
                    description: None,
                    severity: "MEDIUM".into(),
                    asset: None,
                    source: None,
                    metadata: serde_json::json!({}),
                    detected_at: Utc::now(),
                })
                .collect(),
            sigma_alerts: alert_ids
                .iter()
                .map(|&id| DossierAlert {
                    id,
                    rule_name: format!("rule {id}"),
                    level: "medium".into(),
                    matched_fields: serde_json::json!({}),
                    created_at: Utc::now(),
                })
                .collect(),
            enrichment: EnrichmentBundle {
                ip_reputations: vec![],
                cve_details: vec![],
                threat_intel: vec![],
                enrichment_lines: vec![],
            },
            correlations: CorrelationBundle {
                kill_chain_detected: false,
                kill_chain_steps: vec![],
                active_attack: false,
                known_exploits: vec![],
                related_assets: vec![],
                campaign_id: None,
            },
            graph_intel: None,
            ml_scores: MlBundle {
                anomaly_score: 0.0,
                dga_domains: vec![],
                behavioral_cluster: None,
            },
            asset_score: 0.0,
            global_score: 0.0,
            notification_level: NotificationLevel::Silence,
            connected_skills: vec![],
            graph_context: None,
        }
    }

    fn cite(kind: EvidenceType, id: &str) -> EvidenceCitation {
        EvidenceCitation {
            claim: "some claim".into(),
            evidence_type: kind,
            evidence_id: id.into(),
            excerpt: None,
        }
    }

    #[test]
    fn test_evidence_type_serializes_snake_case() {
        let json = serde_json::to_string(&EvidenceType::GraphNode).unwrap();
        assert_eq!(json, "\"graph_node\"");
    }

    #[test]
    fn test_citation_report_empty_is_100pct_verified() {
        let r = CitationReport::default();
        assert_eq!(r.total(), 0);
        assert_eq!(r.fabricated_count(), 0);
        assert!((r.verified_ratio() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_validate_verified_alert() {
        let dossier = dossier_with_ids(&[42, 43], &[]);
        let report = validate_citations(&[cite(EvidenceType::Alert, "42")], &dossier);
        assert_eq!(report.verified.len(), 1);
        assert_eq!(report.fabricated.len(), 0);
    }

    #[test]
    fn test_validate_fabricated_alert() {
        let dossier = dossier_with_ids(&[42], &[]);
        let report = validate_citations(&[cite(EvidenceType::Alert, "999")], &dossier);
        assert_eq!(report.verified.len(), 0);
        assert_eq!(report.fabricated.len(), 1);
    }

    #[test]
    fn test_validate_verified_finding() {
        let dossier = dossier_with_ids(&[], &[7]);
        let report = validate_citations(&[cite(EvidenceType::Finding, "7")], &dossier);
        assert_eq!(report.verified.len(), 1);
    }

    #[test]
    fn test_validate_log_is_unverifiable() {
        let dossier = dossier_with_ids(&[], &[]);
        let report = validate_citations(&[cite(EvidenceType::Log, "hash-abc")], &dossier);
        assert_eq!(report.unverifiable.len(), 1);
        assert_eq!(report.fabricated.len(), 0);
    }

    #[test]
    fn test_validate_graph_node_is_unverifiable() {
        let dossier = dossier_with_ids(&[], &[]);
        let report = validate_citations(&[cite(EvidenceType::GraphNode, "node-1")], &dossier);
        assert_eq!(report.unverifiable.len(), 1);
    }

    #[test]
    fn test_validate_mixed_report() {
        let dossier = dossier_with_ids(&[42], &[7]);
        let citations = vec![
            cite(EvidenceType::Alert, "42"),
            cite(EvidenceType::Alert, "99"),
            cite(EvidenceType::Finding, "7"),
            cite(EvidenceType::Finding, "100"),
            cite(EvidenceType::Log, "x"),
        ];
        let report = validate_citations(&citations, &dossier);
        assert_eq!(report.verified.len(), 2);
        assert_eq!(report.fabricated.len(), 2);
        assert_eq!(report.unverifiable.len(), 1);
        assert!((report.verified_ratio() - 0.4).abs() < 1e-9);
    }
}
