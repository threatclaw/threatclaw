//! Live end-to-end test of the grounding pipeline against a real Ollama
//! server.
//!
//! Builds a realistic dossier (brute-force scenario), asks Ollama to
//! produce a forensic verdict via forensic_schema, then runs the FULL
//! phase-1→phase-4 pipeline (parse → validators → citations → reconciler)
//! in Lenient + Strict modes and prints the outcome.
//!
//! `#[ignore]` by default because it needs a live Ollama. Run with:
//!
//!     OLLAMA_URL=http://localhost:11434 OLLAMA_MODEL=qwen3:14b \
//!         cargo test --test grounding_live_pipeline -- --ignored --nocapture
//!
//! Assertions are minimal on purpose (the LLM is stochastic) — we only
//! check that the pipeline doesn't panic and that the outcome shape is
//! coherent. The eprintln! output is the real deliverable: operators
//! read it to gain confidence that the grounding layer makes sensible
//! decisions on realistic prompts.

use chrono::Utc;
use uuid::Uuid;

use threatclaw::agent::evidence_tracker::{self, EvidenceCitation};
use threatclaw::agent::incident_dossier::{
    CorrelationBundle, CveDetail, DossierAlert, DossierFinding, EnrichmentBundle, IncidentDossier,
    MlBundle,
};
use threatclaw::agent::intelligence_engine::NotificationLevel;
use threatclaw::agent::llm_parsing::{parse_or_repair, strip_markdown_fences};
use threatclaw::agent::llm_schemas::forensic_schema;
use threatclaw::agent::react_runner::call_ollama_with_schema;
use threatclaw::agent::validation_mode::ValidationMode;
use threatclaw::agent::validators::{self, ValidationReport};
use threatclaw::agent::verdict_reconciler::{self, LlmVerdictSnapshot};

fn ollama_url() -> String {
    std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".to_string())
}

fn ollama_model() -> String {
    std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "qwen3:14b".to_string())
}

/// Minimal synthetic dossier that matches the brute-force scenario:
/// - 13 SSH alerts from the same Tor exit node IP
/// - No kill chain yet
/// - ML anomaly moderate (not enough alone to flag)
/// - Score 55 (medium-high)
fn brute_force_dossier() -> IncidentDossier {
    IncidentDossier {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        primary_asset: "srv-web-01".into(),
        findings: vec![DossierFinding {
            id: 7,
            title: "Repeated SSH authentication failures".into(),
            description: Some("13 failed SSH attempts from 185.220.101.42".into()),
            severity: "HIGH".into(),
            asset: Some("srv-web-01".into()),
            source: Some("sshd".into()),
            metadata: serde_json::json!({"attempts": 13, "src_ip": "185.220.101.42"}),
            detected_at: Utc::now(),
        }],
        sigma_alerts: vec![
            DossierAlert {
                id: 42,
                rule_name: "SSH Brute Force".into(),
                level: "high".into(),
                matched_fields: serde_json::json!({"src_ip": "185.220.101.42"}),
                created_at: Utc::now(),
            },
            DossierAlert {
                id: 43,
                rule_name: "Tor Exit Node Connection".into(),
                level: "medium".into(),
                matched_fields: serde_json::json!({"ip": "185.220.101.42"}),
                created_at: Utc::now(),
            },
        ],
        enrichment: EnrichmentBundle {
            ip_reputations: vec![],
            cve_details: vec![],
            threat_intel: vec![],
            enrichment_lines: vec![
                "185.220.101.42 is a known Tor exit node".into(),
                "GreyNoise: Tor exit, seen probing many services".into(),
            ],
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
            anomaly_score: 0.65,
            dga_domains: vec![],
            behavioral_cluster: None,
        },
        asset_score: 55.0,
        global_score: 55.0,
        notification_level: NotificationLevel::Alert,
    }
}

fn brute_force_prompt() -> String {
    r#"You are a SOC L2 forensic analyst. Analyze the following incident and produce a verdict
in strict JSON matching the schema.

INCIDENT:
- Primary asset: srv-web-01
- 13 failed SSH authentication attempts from source IP 185.220.101.42 (a known Tor exit node)
- Sigma rule "SSH Brute Force" (level: high) fired
- Sigma rule "Tor Exit Node Connection" (level: medium) fired
- ML anomaly score: 0.65 (moderate)
- Global score: 55/100
- No lateral movement observed yet
- No CVE involvement

RULES:
- verdict must be one of: confirmed / false_positive / inconclusive / informational
- severity must be one of: LOW / MEDIUM / HIGH / CRITICAL
- confidence must be a decimal between 0.0 and 1.0 (e.g. 0.85, not 85)
- cite concrete evidence via evidence_citations when you claim something specific
- use alert IDs 42 and 43 for the two Sigma alerts; finding ID 7 for the failures
- MITRE IDs must match the pattern T#### or T####.###
"#
    .into()
}

fn run_pipeline(
    raw_llm_output: &str,
    dossier: &IncidentDossier,
    mode: ValidationMode,
) -> (ValidationReport, usize, String, String, String) {
    // Parse LLM output.
    let json_str = strip_markdown_fences(raw_llm_output);
    let parsed_value = parse_or_repair(json_str).expect("repair must produce something");

    // Build validation report from the parsed value.
    let mut report = ValidationReport::default();
    if let Some(arr) = parsed_value
        .get("mitre_techniques")
        .and_then(|v| v.as_array())
    {
        for (i, v) in arr.iter().enumerate() {
            let field = format!("mitre_techniques[{i}]");
            if let Some(id) = v.as_str() {
                if let Err(e) = validators::mitre::validate_format(&field, id) {
                    report.push_error(e);
                }
            }
        }
    }
    if let Some(arr) = parsed_value.get("cves").and_then(|v| v.as_array()) {
        for (i, v) in arr.iter().enumerate() {
            let field = format!("cves[{i}]");
            if let Some(id) = v.as_str() {
                if let Err(e) = validators::cve::validate_format(&field, id) {
                    report.push_error(e);
                }
            }
        }
    }

    // Citations.
    let citations: Vec<EvidenceCitation> = parsed_value
        .get("evidence_citations")
        .and_then(|c| serde_json::from_value(c.clone()).ok())
        .unwrap_or_default();
    let citation_report = evidence_tracker::validate_citations(&citations, dossier);
    let fab_count = citation_report.fabricated_count();

    // Reconcile.
    let llm_snap = LlmVerdictSnapshot {
        verdict: parsed_value
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("inconclusive")
            .to_string(),
        severity: parsed_value
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("MEDIUM")
            .to_string(),
        confidence: parsed_value
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5),
    };
    let outcome =
        verdict_reconciler::reconcile_verdict(&llm_snap, dossier, &report, &citation_report, mode);

    let rule_code = outcome
        .log
        .modification
        .as_ref()
        .map(|m| m.reason_code.clone())
        .unwrap_or_else(|| "none".into());

    (
        report,
        fab_count,
        outcome.log.reconciled.verdict.clone(),
        outcome.log.original.verdict.clone(),
        rule_code,
    )
}

#[tokio::test]
#[ignore]
async fn live_ssh_brute_force_lenient_then_strict() {
    let url = ollama_url();
    let model = ollama_model();
    let dossier = brute_force_dossier();
    let prompt = brute_force_prompt();

    // Try with schema first; fall back to legacy "json" mode if the model
    // rejects the schema (some GGUFs lack the grammar metadata).
    eprintln!("\n=== Calling {model} on {url} (with forensic_schema) ===");
    let raw = match call_ollama_with_schema(&url, &model, &prompt, Some(forensic_schema())).await {
        Ok(r) => r,
        Err(e) if e.contains("vocabulary required for format") => {
            eprintln!("  (model does not support schema FSM, retrying in legacy JSON mode)");
            call_ollama_with_schema(&url, &model, &prompt, None)
                .await
                .expect("legacy JSON mode must succeed")
        }
        Err(e) => panic!("Ollama call failed: {e}"),
    };

    eprintln!("\n=== RAW LLM OUTPUT ===\n{raw}\n======================");

    // Lenient pass.
    let (report_lenient, fab_lenient, final_lenient, original_lenient, rule_lenient) =
        run_pipeline(&raw, &dossier, ValidationMode::Lenient);
    eprintln!("\n=== LENIENT PIPELINE RESULT ===");
    eprintln!(
        "  Validation: {} errors, {} warnings",
        report_lenient.errors.len(),
        report_lenient.warnings.len()
    );
    for e in &report_lenient.errors {
        eprintln!("    ERROR   {} = {:?}: {}", e.field, e.value, e.message);
    }
    for w in &report_lenient.warnings {
        eprintln!("    WARN    {} = {:?}: {}", w.field, w.value, w.message);
    }
    eprintln!("  Fabricated citations: {fab_lenient}");
    eprintln!("  Original verdict : {original_lenient}");
    eprintln!("  Reconciled verdict (NOT applied in Lenient): {final_lenient}");
    eprintln!("  Rule code: {rule_lenient}");
    eprintln!("===============================");

    // Strict pass (same LLM output replayed for comparison).
    let (_, _, final_strict, _, rule_strict) =
        run_pipeline(&raw, &dossier, ValidationMode::Strict);
    eprintln!("\n=== STRICT PIPELINE RESULT ===");
    eprintln!("  Final verdict (APPLIED in Strict): {final_strict}");
    eprintln!("  Rule code: {rule_strict}");
    eprintln!("==============================");

    eprintln!(
        "\n=== COMPARISON ===\n  LLM said          : {original_lenient}\n  Lenient would say : {final_lenient} (rule: {rule_lenient})\n  Strict applies    : {final_strict} (rule: {rule_strict})\n==================\n"
    );

    // Sanity assertions only — no LLM-behavior assumptions.
    assert!(
        !original_lenient.is_empty(),
        "LLM must at least produce a verdict field"
    );
    assert!(
        matches!(
            original_lenient.as_str(),
            "confirmed" | "false_positive" | "inconclusive" | "informational"
        ),
        "LLM must respect the enum (schema FSM guarantee): got {original_lenient}"
    );
}
