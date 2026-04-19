//! Phase-3 verdict reconciler: combine the LLM verdict with deterministic
//! signals (Rust scoring, ML anomaly, Sigma matches, CISA KEV flag) and
//! the phase-2 validation report to decide the final verdict.
//!
//! Design principles:
//! - **Pure sync rules** — every rule is a `fn(inputs) -> Option<Modification>`.
//! - **Conservative** — when signals disagree with the LLM, we downgrade
//!   to `inconclusive`, we do not upgrade to `confirmed` unless a hard
//!   deterministic signal (CISA KEV + high global score) justifies it.
//! - **Always logged** — every reconciliation run (even a no-op) produces
//!   a structured record suitable for persistence in `investigation_log`.
//! - **Strict mode applies, Lenient only observes** — Lenient reconciles
//!   and logs the outcome but keeps the LLM verdict; Strict modifies.
//!
//! The four built-in rules are applied in priority order (first match wins):
//! 1. `rule_d_validation_errors` — structural errors block confident verdict
//! 2. `rule_a_confirmed_but_weak` — downgrade confirmed when signals weak
//! 3. `rule_b_false_positive_but_strong` — escalate dismissal when signals strong
//! 4. `rule_c_inconclusive_but_kev` — upgrade on CISA KEV hit + high score

use serde::{Deserialize, Serialize};

use crate::agent::incident_dossier::IncidentDossier;
use crate::agent::validation_mode::ValidationMode;
use crate::agent::validators::ValidationReport;

/// Deterministic signals snapshot taken at reconcile time.
/// Serialized into the investigation_log for audit trails.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignalsSnapshot {
    pub global_score: f64,
    pub ml_anomaly_score: f64,
    pub sigma_critical_count: usize,
    pub sigma_high_count: usize,
    pub kev_cve_count: usize,
    pub validation_error_count: usize,
    pub validation_warning_count: usize,
}

impl SignalsSnapshot {
    /// Build a snapshot from a dossier + validation report.
    pub fn from_context(dossier: &IncidentDossier, report: &ValidationReport) -> Self {
        let sigma_critical_count = dossier
            .sigma_alerts
            .iter()
            .filter(|a| a.level.eq_ignore_ascii_case("critical"))
            .count();
        let sigma_high_count = dossier
            .sigma_alerts
            .iter()
            .filter(|a| a.level.eq_ignore_ascii_case("high"))
            .count();
        let kev_cve_count = dossier
            .enrichment
            .cve_details
            .iter()
            .filter(|cve| cve.is_kev)
            .count();

        Self {
            global_score: dossier.global_score,
            ml_anomaly_score: dossier.ml_scores.anomaly_score,
            sigma_critical_count,
            sigma_high_count,
            kev_cve_count,
            validation_error_count: report.errors.len(),
            validation_warning_count: report.warnings.len(),
        }
    }
}

/// Inputs to the LLM verdict (as strings — `ParsedLlmResponse` internal shape).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmVerdictSnapshot {
    pub verdict: String,
    pub severity: String,
    pub confidence: f64,
}

/// Modification proposed by a rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Modification {
    pub new_verdict: String,
    pub new_severity: String,
    pub new_confidence: f64,
    pub reason_code: String,
    pub reason_text: String,
}

/// Structured log of a reconciliation run. Persisted in `investigation_log`
/// JSONB alongside the LLM response for audit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReconciliationLog {
    pub mode: ValidationMode,
    pub applied: bool,
    pub original: LlmVerdictSnapshot,
    pub reconciled: LlmVerdictSnapshot,
    pub signals: SignalsSnapshot,
    pub modification: Option<Modification>,
}

/// Rule A: LLM claims `confirmed` but deterministic signals are weak.
///
/// Triggers when ALL of the following hold:
/// - LLM verdict = "confirmed"
/// - global_score < 30 (Rust scoring says the asset is not in trouble)
/// - zero Sigma critical alerts (no rule-based confirmation)
/// - ml_anomaly_score < 0.3 (ML agrees nothing unusual)
///
/// Downgrades to `inconclusive` with confidence × 0.7.
pub fn rule_a_confirmed_but_weak(
    llm: &LlmVerdictSnapshot,
    signals: &SignalsSnapshot,
) -> Option<Modification> {
    if llm.verdict != "confirmed" {
        return None;
    }
    if signals.global_score < 30.0
        && signals.sigma_critical_count == 0
        && signals.ml_anomaly_score < 0.3
    {
        Some(Modification {
            new_verdict: "inconclusive".into(),
            new_severity: "MEDIUM".into(),
            new_confidence: (llm.confidence * 0.7).clamp(0.0, 1.0),
            reason_code: "rule_a_confirmed_but_weak".into(),
            reason_text: format!(
                "LLM claimed 'confirmed' but deterministic signals are weak: \
                 global_score={:.1} (< 30), sigma_critical=0, ml_anomaly={:.2} (< 0.3)",
                signals.global_score, signals.ml_anomaly_score
            ),
        })
    } else {
        None
    }
}

/// Rule B: LLM dismisses as `false_positive` but deterministic signals are
/// strong.
///
/// Triggers when ALL of:
/// - LLM verdict = "false_positive"
/// - ml_anomaly_score > 0.85
/// - sigma_critical_count >= 1
///
/// Escalates to `inconclusive` (not `confirmed` — we lack hard evidence
/// to overturn the LLM) with confidence reduced to 80%.
pub fn rule_b_false_positive_but_strong(
    llm: &LlmVerdictSnapshot,
    signals: &SignalsSnapshot,
) -> Option<Modification> {
    if llm.verdict != "false_positive" {
        return None;
    }
    if signals.ml_anomaly_score > 0.85 && signals.sigma_critical_count >= 1 {
        Some(Modification {
            new_verdict: "inconclusive".into(),
            new_severity: "HIGH".into(),
            new_confidence: (llm.confidence * 0.8).clamp(0.0, 1.0),
            reason_code: "rule_b_false_positive_but_strong".into(),
            reason_text: format!(
                "LLM dismissed as 'false_positive' but signals are strong: \
                 ml_anomaly={:.2} (> 0.85), sigma_critical={}",
                signals.ml_anomaly_score, signals.sigma_critical_count
            ),
        })
    } else {
        None
    }
}

/// Rule C: LLM stays `inconclusive` but a CISA KEV-listed CVE was found
/// AND the overall score is high.
///
/// Triggers when ALL of:
/// - LLM verdict = "inconclusive"
/// - global_score > 70
/// - kev_cve_count >= 1
///
/// Upgrades to `confirmed MEDIUM` with confidence clamped to [0.60, 0.75]
/// (we trust the deterministic signals, but not enough to claim CRITICAL).
pub fn rule_c_inconclusive_but_kev(
    llm: &LlmVerdictSnapshot,
    signals: &SignalsSnapshot,
) -> Option<Modification> {
    if llm.verdict != "inconclusive" {
        return None;
    }
    if signals.global_score > 70.0 && signals.kev_cve_count >= 1 {
        let new_confidence = llm.confidence.max(0.6).min(0.75);
        Some(Modification {
            new_verdict: "confirmed".into(),
            new_severity: "MEDIUM".into(),
            new_confidence,
            reason_code: "rule_c_inconclusive_but_kev".into(),
            reason_text: format!(
                "LLM was uncertain but signals override: global_score={:.1} (> 70), \
                 CISA KEV CVE count={}",
                signals.global_score, signals.kev_cve_count
            ),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::incident_dossier::*;
    use crate::agent::intelligence_engine::NotificationLevel;
    use chrono::Utc;
    use uuid::Uuid;

    fn empty_dossier() -> IncidentDossier {
        IncidentDossier {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            primary_asset: "test".into(),
            findings: vec![],
            sigma_alerts: vec![],
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
        }
    }

    #[test]
    fn test_signals_snapshot_empty_dossier() {
        let dossier = empty_dossier();
        let report = ValidationReport::default();
        let snap = SignalsSnapshot::from_context(&dossier, &report);
        assert_eq!(snap.global_score, 0.0);
        assert_eq!(snap.sigma_critical_count, 0);
        assert_eq!(snap.kev_cve_count, 0);
    }

    #[test]
    fn test_signals_snapshot_counts_sigma_critical() {
        let mut dossier = empty_dossier();
        dossier.sigma_alerts = vec![
            DossierAlert {
                id: 1,
                rule_name: "x".into(),
                level: "critical".into(),
                matched_fields: serde_json::json!({}),
                created_at: Utc::now(),
            },
            DossierAlert {
                id: 2,
                rule_name: "y".into(),
                level: "Critical".into(), // case-insensitive
                matched_fields: serde_json::json!({}),
                created_at: Utc::now(),
            },
            DossierAlert {
                id: 3,
                rule_name: "z".into(),
                level: "high".into(),
                matched_fields: serde_json::json!({}),
                created_at: Utc::now(),
            },
        ];
        let report = ValidationReport::default();
        let snap = SignalsSnapshot::from_context(&dossier, &report);
        assert_eq!(snap.sigma_critical_count, 2);
        assert_eq!(snap.sigma_high_count, 1);
    }

    #[test]
    fn test_signals_snapshot_counts_kev_cves() {
        let mut dossier = empty_dossier();
        dossier.enrichment.cve_details = vec![
            CveDetail {
                cve_id: "CVE-2021-44228".into(),
                cvss_score: Some(10.0),
                epss_score: Some(0.97),
                is_kev: true,
                description: "Log4Shell".into(),
            },
            CveDetail {
                cve_id: "CVE-2023-99999".into(),
                cvss_score: Some(5.0),
                epss_score: Some(0.1),
                is_kev: false,
                description: "minor".into(),
            },
        ];
        let report = ValidationReport::default();
        let snap = SignalsSnapshot::from_context(&dossier, &report);
        assert_eq!(snap.kev_cve_count, 1);
    }

    #[test]
    fn test_signals_snapshot_counts_validation_issues() {
        let dossier = empty_dossier();
        let mut report = ValidationReport::default();
        report.push_error(crate::agent::validators::ValidationError {
            field: "x".into(),
            value: "y".into(),
            kind: crate::agent::validators::ErrorKind::InvalidFormat,
            message: "m".into(),
        });
        report.push_warning(crate::agent::validators::ValidationError {
            field: "a".into(),
            value: "b".into(),
            kind: crate::agent::validators::ErrorKind::UnknownIdentifier,
            message: "m".into(),
        });
        let snap = SignalsSnapshot::from_context(&dossier, &report);
        assert_eq!(snap.validation_error_count, 1);
        assert_eq!(snap.validation_warning_count, 1);
    }

    #[test]
    fn test_llm_verdict_snapshot_serializes() {
        let snap = LlmVerdictSnapshot {
            verdict: "confirmed".into(),
            severity: "HIGH".into(),
            confidence: 0.9,
        };
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["verdict"], "confirmed");
        assert_eq!(json["severity"], "HIGH");
    }

    fn snap(verdict: &str, severity: &str, confidence: f64) -> LlmVerdictSnapshot {
        LlmVerdictSnapshot {
            verdict: verdict.into(),
            severity: severity.into(),
            confidence,
        }
    }

    fn signals_weak() -> SignalsSnapshot {
        SignalsSnapshot {
            global_score: 15.0,
            ml_anomaly_score: 0.1,
            sigma_critical_count: 0,
            sigma_high_count: 0,
            kev_cve_count: 0,
            validation_error_count: 0,
            validation_warning_count: 0,
        }
    }

    fn signals_strong() -> SignalsSnapshot {
        SignalsSnapshot {
            global_score: 80.0,
            ml_anomaly_score: 0.9,
            sigma_critical_count: 2,
            sigma_high_count: 3,
            kev_cve_count: 1,
            validation_error_count: 0,
            validation_warning_count: 0,
        }
    }

    #[test]
    fn test_rule_a_downgrades_confirmed_on_weak_signals() {
        let llm = snap("confirmed", "HIGH", 0.92);
        let m = rule_a_confirmed_but_weak(&llm, &signals_weak()).expect("rule must trigger");
        assert_eq!(m.new_verdict, "inconclusive");
        assert!((m.new_confidence - 0.92 * 0.7).abs() < 1e-9);
        assert_eq!(m.reason_code, "rule_a_confirmed_but_weak");
    }

    #[test]
    fn test_rule_a_skips_when_llm_not_confirmed() {
        let llm = snap("false_positive", "LOW", 0.9);
        assert!(rule_a_confirmed_but_weak(&llm, &signals_weak()).is_none());
    }

    #[test]
    fn test_rule_a_skips_when_any_signal_strong() {
        let mut s = signals_weak();
        s.sigma_critical_count = 1; // one critical = strong enough
        let llm = snap("confirmed", "HIGH", 0.9);
        assert!(rule_a_confirmed_but_weak(&llm, &s).is_none());
    }

    #[test]
    fn test_rule_b_escalates_false_positive_on_strong_signals() {
        let llm = snap("false_positive", "LOW", 0.9);
        let m = rule_b_false_positive_but_strong(&llm, &signals_strong())
            .expect("rule must trigger");
        assert_eq!(m.new_verdict, "inconclusive");
        assert_eq!(m.new_severity, "HIGH");
        assert!((m.new_confidence - 0.72).abs() < 1e-9);
    }

    #[test]
    fn test_rule_b_skips_when_llm_not_false_positive() {
        let llm = snap("confirmed", "HIGH", 0.9);
        assert!(rule_b_false_positive_but_strong(&llm, &signals_strong()).is_none());
    }

    #[test]
    fn test_rule_b_skips_when_ml_anomaly_borderline() {
        let mut s = signals_strong();
        s.ml_anomaly_score = 0.85; // not strictly > 0.85
        let llm = snap("false_positive", "LOW", 0.9);
        assert!(rule_b_false_positive_but_strong(&llm, &s).is_none());
    }

    #[test]
    fn test_rule_c_upgrades_inconclusive_on_kev_plus_score() {
        let llm = snap("inconclusive", "MEDIUM", 0.5);
        let mut s = signals_strong();
        s.kev_cve_count = 1;
        let m = rule_c_inconclusive_but_kev(&llm, &s).expect("rule must trigger");
        assert_eq!(m.new_verdict, "confirmed");
        assert_eq!(m.new_severity, "MEDIUM");
        assert!(m.new_confidence <= 0.75);
        assert!(m.new_confidence >= 0.6);
    }

    #[test]
    fn test_rule_c_skips_without_kev() {
        let llm = snap("inconclusive", "MEDIUM", 0.4);
        let mut s = signals_strong();
        s.kev_cve_count = 0;
        assert!(rule_c_inconclusive_but_kev(&llm, &s).is_none());
    }

    #[test]
    fn test_rule_c_skips_when_score_insufficient() {
        let llm = snap("inconclusive", "MEDIUM", 0.4);
        let mut s = signals_strong();
        s.global_score = 60.0; // <= 70
        assert!(rule_c_inconclusive_but_kev(&llm, &s).is_none());
    }
}
