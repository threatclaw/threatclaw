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
    /// Phase C — graph-derived signals on the primary asset. Used by
    /// rule_f_confirmed_but_isolated_graph to downgrade a Confirmed
    /// verdict when the asset has zero lateral paths AND zero linked
    /// CVEs — i.e. the LLM probably hallucinated propagation.
    pub graph_lateral_paths: u32,
    pub graph_linked_cves: usize,
    pub graph_known: bool,
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

        let (graph_lateral_paths, graph_linked_cves, graph_known) = match &dossier.graph_context {
            Some(ctx) => (ctx.lateral_paths, ctx.linked_cves.len(), true),
            None => (0, 0, false),
        };

        Self {
            global_score: dossier.global_score,
            ml_anomaly_score: dossier.ml_scores.anomaly_score,
            sigma_critical_count,
            sigma_high_count,
            kev_cve_count,
            validation_error_count: report.errors.len(),
            validation_warning_count: report.warnings.len(),
            graph_lateral_paths,
            graph_linked_cves,
            graph_known,
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

/// Rule D: Validation report contains blocking errors.
///
/// Triggers only in Strict mode. When the LLM produced a `confirmed`
/// verdict but the phase-2 validators flagged format violations (invented
/// MITRE IDs, malformed CVEs, etc.), the verdict is untrustworthy —
/// downgrade to `inconclusive`.
///
/// Lenient / Off modes observe the report but leave the verdict alone.
pub fn rule_d_validation_errors(
    llm: &LlmVerdictSnapshot,
    signals: &SignalsSnapshot,
    mode: ValidationMode,
) -> Option<Modification> {
    if mode != ValidationMode::Strict {
        return None;
    }
    if signals.validation_error_count == 0 {
        return None;
    }
    if llm.verdict != "confirmed" {
        return None;
    }
    Some(Modification {
        new_verdict: "inconclusive".into(),
        new_severity: "MEDIUM".into(),
        new_confidence: (llm.confidence * 0.6).clamp(0.0, 1.0),
        reason_code: "rule_d_validation_errors".into(),
        reason_text: format!(
            "Strict mode: {} validation error(s) in LLM output block the \
             confirmed verdict. Downgraded to inconclusive for analyst review.",
            signals.validation_error_count
        ),
    })
}

/// Rule F: LLM claims `confirmed` but the graph context says the asset
/// is isolated (no lateral path, no linked CVE).
///
/// Triggers when ALL of:
/// - LLM verdict = "confirmed"
/// - Graph context was successfully fetched (we know the asset)
/// - lateral_paths == 0 AND linked_cves == 0
/// - sigma_critical_count == 0 (no rule-based hard signal either)
///
/// Downgrades to `inconclusive MEDIUM` with confidence × 0.7. The idea:
/// the LLM hallucinated propagation / kill chain that the graph doesn't
/// support. We don't kill the alert (still inconclusive for analyst
/// review), we just refuse to call it "confirmed".
pub fn rule_f_confirmed_but_isolated_graph(
    llm: &LlmVerdictSnapshot,
    signals: &SignalsSnapshot,
) -> Option<Modification> {
    if llm.verdict != "confirmed" {
        return None;
    }
    // Skip if the graph wasn't queried — we can't argue from absence.
    if !signals.graph_known {
        return None;
    }
    if signals.graph_lateral_paths == 0
        && signals.graph_linked_cves == 0
        && signals.sigma_critical_count == 0
    {
        Some(Modification {
            new_verdict: "inconclusive".into(),
            new_severity: "MEDIUM".into(),
            new_confidence: (llm.confidence * 0.7).clamp(0.0, 1.0),
            reason_code: "rule_f_confirmed_but_isolated_graph".into(),
            reason_text: format!(
                "LLM claimed 'confirmed' but the asset graph shows no lateral \
                 path AND no linked CVE AND no sigma critical. Possible \
                 hallucination of kill chain / propagation. Downgraded for \
                 analyst review (sigma_critical={}, lateral_paths={}, \
                 linked_cves={}).",
                signals.sigma_critical_count,
                signals.graph_lateral_paths,
                signals.graph_linked_cves
            ),
        })
    } else {
        None
    }
}

/// Rule E: LLM claims `confirmed` but at least one cited evidence is
/// absent from the dossier (i.e. fabricated).
///
/// Triggers only in Strict mode. Downgrades to `inconclusive MEDIUM`
/// with confidence reduced to 50% — we cannot trust any part of a
/// verdict whose evidence does not exist.
pub fn rule_e_fabricated_citations(
    llm: &LlmVerdictSnapshot,
    citation_report: &crate::agent::evidence_tracker::CitationReport,
    mode: ValidationMode,
) -> Option<Modification> {
    if mode != ValidationMode::Strict {
        return None;
    }
    if llm.verdict != "confirmed" {
        return None;
    }
    if citation_report.fabricated_count() == 0 {
        return None;
    }
    Some(Modification {
        new_verdict: "inconclusive".into(),
        new_severity: "MEDIUM".into(),
        new_confidence: (llm.confidence * 0.5).clamp(0.0, 1.0),
        reason_code: "rule_e_fabricated_citations".into(),
        reason_text: format!(
            "Strict mode: {} fabricated citation(s) — LLM cited evidence not present in the dossier. \
             Verdict downgraded for analyst review.",
            citation_report.fabricated_count()
        ),
    })
}

/// Outcome of a full reconciliation run.
#[derive(Debug, Clone)]
pub struct ReconciliationOutcome {
    pub log: ReconciliationLog,
    /// Whether the caller should apply the modification (true only in
    /// Strict mode with a rule match).
    pub apply: bool,
}

/// Run the full rule cascade and produce a log + outcome.
///
/// Priority order (first match wins):
///   D (strict-only validation errors) → A → B → C
///
/// In Lenient mode the rules still run and the log records their verdict,
/// but `apply` is `false` so the caller keeps the LLM output. In Off mode
/// we short-circuit and return an empty log with `apply=false`.
pub fn reconcile_verdict(
    llm: &LlmVerdictSnapshot,
    dossier: &IncidentDossier,
    report: &ValidationReport,
    citation_report: &crate::agent::evidence_tracker::CitationReport,
    mode: ValidationMode,
) -> ReconciliationOutcome {
    let signals = SignalsSnapshot::from_context(dossier, report);

    if mode == ValidationMode::Off {
        return ReconciliationOutcome {
            log: ReconciliationLog {
                mode,
                applied: false,
                original: llm.clone(),
                reconciled: llm.clone(),
                signals,
                modification: None,
            },
            apply: false,
        };
    }

    let modification = rule_d_validation_errors(llm, &signals, mode)
        .or_else(|| rule_e_fabricated_citations(llm, citation_report, mode))
        .or_else(|| rule_a_confirmed_but_weak(llm, &signals))
        .or_else(|| rule_f_confirmed_but_isolated_graph(llm, &signals))
        .or_else(|| rule_b_false_positive_but_strong(llm, &signals))
        .or_else(|| rule_c_inconclusive_but_kev(llm, &signals));

    let reconciled = match &modification {
        Some(m) => LlmVerdictSnapshot {
            verdict: m.new_verdict.clone(),
            severity: m.new_severity.clone(),
            confidence: m.new_confidence,
        },
        None => llm.clone(),
    };

    let apply = mode == ValidationMode::Strict && modification.is_some();

    ReconciliationOutcome {
        log: ReconciliationLog {
            mode,
            applied: apply,
            original: llm.clone(),
            reconciled,
            signals,
            modification,
        },
        apply,
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
            connected_skills: vec![],
            graph_context: None,
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
            graph_lateral_paths: 0,
            graph_linked_cves: 0,
            graph_known: false,
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
            graph_lateral_paths: 2,
            graph_linked_cves: 1,
            graph_known: true,
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
        let m =
            rule_b_false_positive_but_strong(&llm, &signals_strong()).expect("rule must trigger");
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

    #[test]
    fn test_rule_d_downgrades_in_strict_with_errors() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let mut s = signals_weak();
        s.validation_error_count = 2;
        let m =
            rule_d_validation_errors(&llm, &s, ValidationMode::Strict).expect("rule must trigger");
        assert_eq!(m.new_verdict, "inconclusive");
        assert!((m.new_confidence - 0.54).abs() < 1e-9);
    }

    #[test]
    fn test_rule_d_skips_in_lenient_mode() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let mut s = signals_weak();
        s.validation_error_count = 5;
        assert!(rule_d_validation_errors(&llm, &s, ValidationMode::Lenient).is_none());
    }

    #[test]
    fn test_rule_d_skips_when_no_errors() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let s = signals_weak(); // validation_error_count = 0
        assert!(rule_d_validation_errors(&llm, &s, ValidationMode::Strict).is_none());
    }

    #[test]
    fn test_reconcile_off_mode_is_noop() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let dossier = empty_dossier();
        let report = ValidationReport::default();
        let outcome = reconcile_verdict(
            &llm,
            &dossier,
            &report,
            &crate::agent::evidence_tracker::CitationReport::default(),
            ValidationMode::Off,
        );
        assert!(!outcome.apply);
        assert!(outcome.log.modification.is_none());
        assert_eq!(outcome.log.reconciled, llm);
    }

    #[test]
    fn test_reconcile_lenient_logs_but_does_not_apply() {
        // Rule A should trigger but apply=false in Lenient.
        let llm = snap("confirmed", "HIGH", 0.9);
        let dossier = empty_dossier(); // weak signals
        let report = ValidationReport::default();
        let outcome = reconcile_verdict(
            &llm,
            &dossier,
            &report,
            &crate::agent::evidence_tracker::CitationReport::default(),
            ValidationMode::Lenient,
        );
        assert!(!outcome.apply);
        assert!(outcome.log.modification.is_some());
        assert_eq!(
            outcome.log.modification.as_ref().unwrap().reason_code,
            "rule_a_confirmed_but_weak"
        );
    }

    #[test]
    fn test_reconcile_strict_applies_modification() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let dossier = empty_dossier();
        let report = ValidationReport::default();
        let outcome = reconcile_verdict(
            &llm,
            &dossier,
            &report,
            &crate::agent::evidence_tracker::CitationReport::default(),
            ValidationMode::Strict,
        );
        assert!(outcome.apply);
        assert_eq!(outcome.log.reconciled.verdict, "inconclusive");
    }

    #[test]
    fn test_reconcile_priority_d_over_a() {
        // Build a case where BOTH rule D and rule A would match.
        // In Strict mode, rule D must win (priority).
        let llm = snap("confirmed", "HIGH", 0.9);
        let dossier = empty_dossier(); // weak → rule A would match
        let mut report = ValidationReport::default();
        report.push_error(crate::agent::validators::ValidationError {
            field: "x".into(),
            value: "y".into(),
            kind: crate::agent::validators::ErrorKind::InvalidFormat,
            message: "m".into(),
        });
        let outcome = reconcile_verdict(
            &llm,
            &dossier,
            &report,
            &crate::agent::evidence_tracker::CitationReport::default(),
            ValidationMode::Strict,
        );
        assert!(outcome.apply);
        assert_eq!(
            outcome.log.modification.as_ref().unwrap().reason_code,
            "rule_d_validation_errors",
            "rule D must win over rule A when both apply"
        );
    }

    fn fab_report(n: usize) -> crate::agent::evidence_tracker::CitationReport {
        use crate::agent::evidence_tracker::{CitationReport, EvidenceCitation, EvidenceType};
        let mut r = CitationReport::default();
        for i in 0..n {
            r.fabricated.push(EvidenceCitation {
                claim: format!("claim {i}"),
                evidence_type: EvidenceType::Alert,
                evidence_id: format!("fake-{i}"),
                excerpt: None,
            });
        }
        r
    }

    #[test]
    fn test_rule_e_downgrades_on_fabricated_in_strict() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let report = fab_report(2);
        let m = rule_e_fabricated_citations(&llm, &report, ValidationMode::Strict)
            .expect("rule must trigger");
        assert_eq!(m.new_verdict, "inconclusive");
        assert!((m.new_confidence - 0.45).abs() < 1e-9);
    }

    #[test]
    fn test_rule_e_skips_in_lenient() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let report = fab_report(5);
        assert!(rule_e_fabricated_citations(&llm, &report, ValidationMode::Lenient).is_none());
    }

    #[test]
    fn test_rule_e_skips_when_no_fabricated() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let report = crate::agent::evidence_tracker::CitationReport::default();
        assert!(rule_e_fabricated_citations(&llm, &report, ValidationMode::Strict).is_none());
    }

    #[test]
    fn test_reconcile_priority_d_over_e() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let dossier = empty_dossier();
        let mut report = ValidationReport::default();
        report.push_error(crate::agent::validators::ValidationError {
            field: "x".into(),
            value: "y".into(),
            kind: crate::agent::validators::ErrorKind::InvalidFormat,
            message: "m".into(),
        });
        let citation_report = fab_report(2);
        let outcome = reconcile_verdict(
            &llm,
            &dossier,
            &report,
            &citation_report,
            ValidationMode::Strict,
        );
        assert_eq!(
            outcome.log.modification.as_ref().unwrap().reason_code,
            "rule_d_validation_errors"
        );
    }

    // ── Regression tests — fix/pipeline-reconciler-v2 (bugs 1/2/3) ──

    // Bug 1 regression: Rule A must fire when ml_anomaly_score is actually low
    // (before the fix, anomaly_score was always 0.5 so the < 0.3 condition never triggered).
    #[test]
    fn test_rule_a_fires_when_ml_score_correctly_wired() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let mut s = signals_weak();
        s.ml_anomaly_score = 0.2; // realistic low-anomaly ML output
        s.global_score = 20.0;
        s.sigma_critical_count = 0;
        let m = rule_a_confirmed_but_weak(&llm, &s)
            .expect("Rule A must fire: ml=0.2 < 0.3, global=20 < 30, sigma_critical=0");
        assert_eq!(m.new_verdict, "inconclusive");
        assert_eq!(m.reason_code, "rule_a_confirmed_but_weak");
    }

    // Bug 2 regression: SignalsSnapshot must count critical sigma alerts from
    // dossier.sigma_alerts (before the fix that field was always vec![] so
    // sigma_critical_count was always 0, making Rule B impossible to trigger).
    #[test]
    fn test_signals_snapshot_counts_sigma_critical_from_dossier_alerts() {
        let mut dossier = empty_dossier();
        dossier.sigma_alerts = vec![
            DossierAlert {
                id: 1,
                rule_name: "Malicious PowerShell Execution".into(),
                level: "critical".into(),
                matched_fields: serde_json::json!({}),
                created_at: Utc::now(),
            },
            DossierAlert {
                id: 2,
                rule_name: "SSH Brute Force".into(),
                level: "high".into(),
                matched_fields: serde_json::json!({}),
                created_at: Utc::now(),
            },
        ];
        let report = ValidationReport::default();
        let snap = SignalsSnapshot::from_context(&dossier, &report);
        assert_eq!(snap.sigma_critical_count, 1, "critical sigma alert must be counted");
        assert_eq!(snap.sigma_high_count, 1, "high sigma alert must be counted");
    }

    // Bug 2 regression: Rule B must fire when sigma_alerts are correctly populated.
    #[test]
    fn test_rule_b_fires_when_sigma_alerts_correctly_wired() {
        let llm = snap("false_positive", "LOW", 0.9);
        let mut s = signals_strong();
        s.ml_anomaly_score = 0.9; // anomalous ML
        s.sigma_critical_count = 1; // critical sigma alert present
        let m = rule_b_false_positive_but_strong(&llm, &s)
            .expect("Rule B must fire: ml=0.9 > 0.85, sigma_critical=1");
        assert_eq!(m.new_verdict, "inconclusive");
        assert_eq!(m.reason_code, "rule_b_false_positive_but_strong");
    }

    // Bug 3 regression: Rule F must not fire when lateral_paths > 0
    // (before the fix, lateral_paths was always 0 from the hardcoded Cypher query).
    #[test]
    fn test_rule_f_skips_when_lateral_paths_nonzero() {
        let llm = snap("confirmed", "HIGH", 0.9);
        let mut s = SignalsSnapshot {
            global_score: 50.0,
            ml_anomaly_score: 0.5,
            sigma_critical_count: 0,
            sigma_high_count: 1,
            kev_cve_count: 0,
            validation_error_count: 0,
            validation_warning_count: 0,
            graph_lateral_paths: 2, // real lateral paths from attack_paths_predicted
            graph_linked_cves: 0,
            graph_known: true,
        };
        assert!(
            rule_f_confirmed_but_isolated_graph(&llm, &s).is_none(),
            "Rule F must not fire when lateral_paths=2 (asset is not isolated)"
        );

        // Now set to 0 — Rule F should fire
        s.graph_lateral_paths = 0;
        assert!(
            rule_f_confirmed_but_isolated_graph(&llm, &s).is_some(),
            "Rule F must fire when lateral_paths=0 and no CVE and no sigma critical"
        );
    }
}
