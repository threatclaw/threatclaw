//! Phase 6 deterministic grounding benchmark.
//!
//! For each fixture in eval/fixtures/*.json, builds a synthetic
//! IncidentDossier + parsed LLM Value + ValidationReport, runs the
//! grounding layer (validate_citations + reconcile_verdict) and
//! compares the outcome against the `expected` block of the fixture.
//!
//! 100% deterministic — no DB, no network, no Ollama. Fast enough to
//! run in every `cargo test` invocation (<100ms for the full corpus).

use std::fs;
use std::path::PathBuf;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use threatclaw::agent::evidence_tracker::{self, EvidenceCitation};
use threatclaw::agent::incident_dossier::{
    CorrelationBundle, CveDetail, DossierAlert, DossierFinding, EnrichmentBundle, IncidentDossier,
    MlBundle,
};
use threatclaw::agent::intelligence_engine::NotificationLevel;
use threatclaw::agent::validation_mode::ValidationMode;
use threatclaw::agent::validators::{self, ValidationReport};
use threatclaw::agent::verdict_reconciler::{self, LlmVerdictSnapshot};

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    #[allow(dead_code)]
    description: String,
    dossier: FxDossier,
    llm_output: FxLlmOutput,
    expected: FxExpected,
}

#[derive(Debug, Deserialize)]
struct FxDossier {
    global_score: f64,
    ml_anomaly_score: f64,
    sigma_alert_ids: Vec<FxAlert>,
    finding_ids: Vec<i64>,
    kev_cves: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FxAlert {
    id: i64,
    level: String,
}

#[derive(Debug, Deserialize)]
struct FxLlmOutput {
    verdict: String,
    severity: String,
    confidence: f64,
    #[serde(default)]
    mitre_techniques: Vec<String>,
    #[serde(default)]
    cves: Vec<String>,
    #[serde(default)]
    evidence_citations: Vec<EvidenceCitation>,
}

#[derive(Debug, Deserialize)]
struct FxExpected {
    mode: String,
    final_verdict: String,
    #[serde(default)]
    #[allow(dead_code)]
    final_severity: Option<String>,
    #[serde(default)]
    rule_code: Option<String>,
    applied: bool,
}

#[derive(Debug, Serialize)]
struct ScenarioOutcome {
    name: String,
    passed: bool,
    actual_verdict: String,
    expected_verdict: String,
    actual_rule_code: String,
    expected_rule_code: String,
    applied: bool,
    expected_applied: bool,
}

fn load_fixtures() -> Vec<Fixture> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval/fixtures");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).expect("read eval/fixtures") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path).expect("read fixture");
        let fx: Fixture =
            serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path:?}: {e}"));
        out.push(fx);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn build_dossier(fx: &FxDossier) -> IncidentDossier {
    IncidentDossier {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        primary_asset: "bench".into(),
        findings: fx
            .finding_ids
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
        sigma_alerts: fx
            .sigma_alert_ids
            .iter()
            .map(|a| DossierAlert {
                id: a.id,
                rule_id: format!("rule-{}", a.id),
                rule_name: format!("rule {}", a.id),
                level: a.level.clone(),
                matched_fields: serde_json::json!({}),
                created_at: Utc::now(),
                username: None,
            })
            .collect(),
        enrichment: EnrichmentBundle {
            ip_reputations: vec![],
            cve_details: fx
                .kev_cves
                .iter()
                .map(|cve| CveDetail {
                    cve_id: cve.clone(),
                    cvss_score: Some(10.0),
                    epss_score: Some(0.97),
                    is_kev: true,
                    description: "KEV".into(),
                })
                .collect(),
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
            anomaly_score: fx.ml_anomaly_score,
            dga_domains: vec![],
            behavioral_cluster: None,
        },
        asset_score: fx.global_score,
        global_score: fx.global_score,
        notification_level: NotificationLevel::Silence,
        connected_skills: vec![],
        graph_context: None,
    }
}

fn parse_mode(s: &str) -> ValidationMode {
    match s {
        "off" => ValidationMode::Off,
        "lenient" => ValidationMode::Lenient,
        "strict" => ValidationMode::Strict,
        other => panic!("unknown mode in fixture: {other}"),
    }
}

fn build_validation_report(fx: &FxLlmOutput) -> ValidationReport {
    let mut report = ValidationReport::default();
    for (i, mitre) in fx.mitre_techniques.iter().enumerate() {
        let field = format!("mitre_techniques[{i}]");
        if let Err(e) = validators::mitre::validate_format(&field, mitre) {
            report.push_error(e);
        }
    }
    for (i, cve) in fx.cves.iter().enumerate() {
        let field = format!("cves[{i}]");
        if let Err(e) = validators::cve::validate_format(&field, cve) {
            report.push_error(e);
        }
    }
    report
}

fn run_scenario(fx: &Fixture) -> ScenarioOutcome {
    let dossier = build_dossier(&fx.dossier);
    let report = build_validation_report(&fx.llm_output);
    let citation_report =
        evidence_tracker::validate_citations(&fx.llm_output.evidence_citations, &dossier);
    let llm = LlmVerdictSnapshot {
        verdict: fx.llm_output.verdict.clone(),
        severity: fx.llm_output.severity.clone(),
        confidence: fx.llm_output.confidence,
    };
    let mode = parse_mode(&fx.expected.mode);
    let outcome =
        verdict_reconciler::reconcile_verdict(&llm, &dossier, &report, &citation_report, mode);

    let actual_rule_code = outcome
        .log
        .modification
        .as_ref()
        .map(|m| m.reason_code.clone())
        .unwrap_or_else(|| "none".into());
    let expected_rule_code = fx
        .expected
        .rule_code
        .clone()
        .unwrap_or_else(|| "none".into());

    let passed = outcome.log.reconciled.verdict == fx.expected.final_verdict
        && outcome.apply == fx.expected.applied
        && actual_rule_code == expected_rule_code;

    ScenarioOutcome {
        name: fx.name.clone(),
        passed,
        actual_verdict: outcome.log.reconciled.verdict.clone(),
        expected_verdict: fx.expected.final_verdict.clone(),
        actual_rule_code,
        expected_rule_code,
        applied: outcome.apply,
        expected_applied: fx.expected.applied,
    }
}

#[test]
fn benchmark_all_fixtures_pass() {
    let fixtures = load_fixtures();
    assert!(
        fixtures.len() >= 6,
        "expected at least 6 fixtures covering rules A-E + passthrough, got {}",
        fixtures.len()
    );
    let mut failures = Vec::new();
    for fx in &fixtures {
        let outcome = run_scenario(fx);
        if !outcome.passed {
            failures.push(outcome);
        }
    }
    if !failures.is_empty() {
        panic!(
            "{} scenario(s) failed:\n{}",
            failures.len(),
            serde_json::to_string_pretty(&failures).unwrap()
        );
    }
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    version: &'static str,
    timestamp: String,
    total_scenarios: usize,
    passed: usize,
    failed: usize,
    rule_coverage: std::collections::BTreeMap<String, usize>,
    scenarios: Vec<ScenarioOutcome>,
    metrics: Metrics,
}

#[derive(Debug, Serialize)]
struct Metrics {
    rule_match_accuracy: f64,
    reconciliation_agreement_rate: f64,
    mode_coverage_off: usize,
    mode_coverage_lenient: usize,
    mode_coverage_strict: usize,
}

#[test]
#[ignore]
fn benchmark_emit_report() {
    let fixtures = load_fixtures();
    let mut scenarios = Vec::with_capacity(fixtures.len());
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut rule_coverage: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut mode_off = 0usize;
    let mut mode_lenient = 0usize;
    let mut mode_strict = 0usize;

    for fx in &fixtures {
        let outcome = run_scenario(fx);
        if outcome.passed {
            passed += 1;
        } else {
            failed += 1;
        }
        *rule_coverage
            .entry(outcome.expected_rule_code.clone())
            .or_insert(0) += 1;
        match fx.expected.mode.as_str() {
            "off" => mode_off += 1,
            "lenient" => mode_lenient += 1,
            "strict" => mode_strict += 1,
            _ => {}
        }
        scenarios.push(outcome);
    }

    let total = scenarios.len() as f64;
    let rule_match_accuracy = if total > 0.0 {
        scenarios
            .iter()
            .filter(|s| s.actual_rule_code == s.expected_rule_code)
            .count() as f64
            / total
    } else {
        1.0
    };
    let reconciliation_agreement_rate = if total > 0.0 {
        scenarios
            .iter()
            .filter(|s| s.actual_verdict == s.expected_verdict)
            .count() as f64
            / total
    } else {
        1.0
    };

    let report = BenchmarkReport {
        version: "1.0.0-phase6",
        timestamp: Utc::now().to_rfc3339(),
        total_scenarios: scenarios.len(),
        passed,
        failed,
        rule_coverage,
        scenarios,
        metrics: Metrics {
            rule_match_accuracy,
            reconciliation_agreement_rate,
            mode_coverage_off: mode_off,
            mode_coverage_lenient: mode_lenient,
            mode_coverage_strict: mode_strict,
        },
    };

    let report_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("eval/latest-benchmark-report.json");
    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    fs::write(&report_path, &json).expect("write benchmark report");

    eprintln!("\n=== Benchmark report ===\n{json}\n========================\n");
    eprintln!("Written to: {}", report_path.display());

    assert_eq!(failed, 0, "benchmark reported {failed} failure(s)");
}
