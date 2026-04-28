//! Investigation Runner — automated incident investigation. See ADR-024.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::agent::incident_dossier::IncidentDossier;
use crate::agent::investigation_skills::{SkillRequest, execute_investigation_skill};
use crate::agent::llm_router::LlmRouterConfig;
use crate::agent::prompt_builder::build_investigation_prompt;
use crate::agent::verdict::{InvestigationResult, InvestigationVerdict, ProposedAction};
use crate::db::Database;

// ── Configuration ──

/// Investigation guard-rails
#[derive(Debug, Clone)]
pub struct InvestigationConfig {
    pub max_iterations: usize,
    pub timeout: Duration,
    pub max_skill_calls: usize,
    pub skill_timeout: Duration,
    pub confidence_accept: f64,
}

impl Default for InvestigationConfig {
    fn default() -> Self {
        Self {
            // Phase B revisited — calibrated for CPU-only Ollama on CASE
            // (no GPU layers). Previous 1800 s was absurdly generous; my
            // first cut at 300 s was too tight and caused systematic L2
            // timeouts on heavy dossiers. 900 s = 1.5 calls × 600 s
            // per-call budget. The RSSI doesn't wait for it — Phase B2
            // surfaces the incident immediately with a human title;
            // L2 just enriches the verdict in the background.
            max_iterations: 2,
            timeout: Duration::from_secs(1800),
            max_skill_calls: 10,
            skill_timeout: Duration::from_secs(15),
            confidence_accept: 0.70,
        }
    }
}

// ── Registry (one investigation per asset) ──

struct ActiveInvestigation {
    dossier_id: uuid::Uuid,
    started_at: Instant,
}

pub struct InvestigationRegistry {
    active: Mutex<HashMap<String, ActiveInvestigation>>,
}

impl InvestigationRegistry {
    pub fn new() -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Try to register an investigation. Returns false if one is already running for this asset.
    pub async fn try_register(&self, asset: &str, dossier_id: uuid::Uuid) -> bool {
        let mut active = self.active.lock().await;

        // Clean up stale entries (> 30 min = orphaned). Aligned with the
        // Phase B 300 s outer timeout × generous safety margin for skill
        // calls / network blips. Anything older means the worker died.
        active.retain(|_, state| state.started_at.elapsed() < Duration::from_secs(1800));

        if active.contains_key(asset) {
            return false;
        }

        active.insert(
            asset.to_string(),
            ActiveInvestigation {
                dossier_id,
                started_at: Instant::now(),
            },
        );
        true
    }

    /// Remove a completed investigation
    pub async fn unregister(&self, asset: &str) {
        self.active.lock().await.remove(asset);
    }

    /// Check if an asset has an active investigation
    pub async fn is_investigating(&self, asset: &str) -> bool {
        let active = self.active.lock().await;
        active.contains_key(asset)
    }
}

// ── Global singleton ──

use std::sync::OnceLock;

static REGISTRY: OnceLock<Arc<InvestigationRegistry>> = OnceLock::new();

pub fn get_registry() -> Arc<InvestigationRegistry> {
    REGISTRY
        .get_or_init(|| Arc::new(InvestigationRegistry::new()))
        .clone()
}

// ── LLM response parsing ──

#[derive(Debug)]
struct ParsedLlmResponse {
    verdict: String,
    analysis: String,
    severity: String,
    confidence: f64,
    correlations: Vec<String>,
    needs_more_info: bool,
    skill_requests: Vec<SkillRequest>,
    proposed_actions: Vec<ProposedAction>,
    evidence_citations: Vec<crate::agent::evidence_tracker::EvidenceCitation>,
    incident_title_fr: Option<String>,
}

fn parse_llm_response(raw: &str) -> Result<ParsedLlmResponse, String> {
    // Fence stripping + parse-with-repair are shared with react_cycle.
    let json_str = crate::agent::llm_parsing::strip_markdown_fences(raw);
    let v: Value = crate::agent::llm_parsing::parse_or_repair(json_str)?;

    Ok(ParsedLlmResponse {
        verdict: v
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("inconclusive")
            .to_string(),
        analysis: v
            .get("analysis")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        severity: v
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("MEDIUM")
            .to_string(),
        confidence: v.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.5),
        correlations: v
            .get("correlations")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        needs_more_info: v
            .get("needs_more_info")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        skill_requests: v
            .get("skill_requests")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        Some(SkillRequest {
                            skill_name: v.get("skill_name")?.as_str()?.to_string(),
                            params: v
                                .get("params")
                                .cloned()
                                .unwrap_or(Value::Object(Default::default())),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
        proposed_actions: v
            .get("proposed_actions")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default(),
        evidence_citations: v
            .get("evidence_citations")
            .and_then(|c| serde_json::from_value(c.clone()).ok())
            .unwrap_or_default(),
        incident_title_fr: v
            .get("incident_title_fr")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
    })
}

// ── Main investigation loop ──

/// Run a full investigation on an incident dossier.
///
/// This is the core of stage 2: the ReAct loop analyzes the dossier,
/// optionally calls investigation skills for more data, and produces a verdict.
#[tracing::instrument(
    name = "run_investigation",
    skip(dossier, store, llm_config, config),
    fields(
        threatclaw_dossier_id = %dossier.id,
        threatclaw_primary_asset = %dossier.primary_asset,
        threatclaw_global_score = dossier.global_score,
    ),
)]
pub async fn run_investigation(
    dossier: IncidentDossier,
    store: Arc<dyn Database>,
    llm_config: &LlmRouterConfig,
    config: &InvestigationConfig,
) -> InvestigationResult {
    let start = Instant::now();
    let dossier_id = dossier.id;
    let asset = dossier.primary_asset.clone();
    let mut iteration = 0usize;
    let mut skill_calls = 0usize;
    let mut skill_results: Vec<(String, Value)> = Vec::new();
    let mut failed_skills: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Track the best response from the LLM across iterations (for fallback on max_iterations)
    let mut best_parsed: Option<(String, f64, Vec<String>)> = None; // (analysis, confidence, correlations)

    info!(
        "INVESTIGATION: Starting {} for asset {} ({} findings, score={:.0})",
        &dossier_id.to_string()[..8],
        asset,
        dossier.findings.len(),
        dossier.asset_score,
    );

    // Get language preference
    let lang = crate::agent::prompt_builder::get_language(store.as_ref()).await;

    loop {
        // Guard-rails
        if iteration >= config.max_iterations {
            warn!(
                "INVESTIGATION: Max iterations ({}) reached for {}",
                config.max_iterations, asset
            );
            break;
        }
        if start.elapsed() > config.timeout {
            warn!(
                "INVESTIGATION: Timeout ({:?}) reached for {}",
                config.timeout, asset
            );
            break;
        }

        iteration += 1;
        info!(
            "INVESTIGATION: Iteration {}/{} for {} ({}s elapsed)",
            iteration,
            config.max_iterations,
            asset,
            start.elapsed().as_secs()
        );

        // Build prompt with dossier + accumulated skill results
        let prompt = build_investigation_prompt(&dossier, &skill_results, &lang);

        // Call L1 LLM with triage_schema (phase 1 structured outputs).
        // Phase B revisited (CPU-only Ollama on CASE) — qwen3:8b runs
        // entirely on CPU (`offloaded 0/37 layers to GPU`), at ~5-15
        // tok/s. With Phase C's graph context + adaptive skill list
        // making the prompt heavier, 180 s was tripping systematically.
        // 600 s is the sweet spot: enough headroom on CPU for a real
        // verdict (L2 typically completes in 60-300 s on this profile)
        // while the outer config.timeout (900 s) still caps the loop.
        // The user perceives no delay because Phase B2 already creates
        // the incident with a human title BEFORE the L2 runs — only the
        // verdict enrichment lands later.
        let llm_raw = match tokio::time::timeout(
            Duration::from_secs(1500),
            crate::agent::react_runner::call_ollama_with_schema(
                &llm_config.primary.base_url,
                &llm_config.primary.model,
                &prompt,
                Some(crate::agent::llm_schemas::triage_schema()),
            ),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                error!("INVESTIGATION: LLM call failed: {e}");
                return make_error_result(
                    dossier_id,
                    asset,
                    &format!("LLM failed: {e}"),
                    start,
                    iteration,
                    skill_calls,
                );
            }
            Err(_) => {
                error!("INVESTIGATION: LLM call timed out (1500s per call)");
                return make_error_result(
                    dossier_id,
                    asset,
                    "LLM timeout (1500 s per call — CPU-only Ollama)",
                    start,
                    iteration,
                    skill_calls,
                );
            }
        };

        // Parse LLM response
        let mut parsed = match parse_llm_response(&llm_raw) {
            Ok(p) => p,
            Err(e) => {
                warn!("INVESTIGATION: Parse failed (iter {iteration}): {e}");
                if iteration >= config.max_iterations {
                    break;
                }
                continue;
            }
        };

        info!(
            "INVESTIGATION: verdict={} confidence={:.0}% needs_more_info={} skills={}",
            parsed.verdict,
            parsed.confidence * 100.0,
            parsed.needs_more_info,
            parsed.skill_requests.len()
        );

        // ── Phase 2 + 3 : validation typée + reconciler ──
        // (contrôlé par tc_config_llm_validation_mode ; Off court-circuite tout)
        let validation_mode =
            crate::agent::validation_mode::load_validation_mode(store.as_ref()).await;
        if validation_mode != crate::agent::validation_mode::ValidationMode::Off {
            let json_str = crate::agent::llm_parsing::strip_markdown_fences(&llm_raw);
            if let Ok(generic) = crate::agent::llm_parsing::parse_or_repair(json_str) {
                let report =
                    crate::agent::validators::validate_parsed_response(&generic, store.as_ref())
                        .await;

                if !report.is_clean() {
                    warn!(
                        "INVESTIGATION: validation report (mode={:?}) errors={} warnings={}",
                        validation_mode,
                        report.errors.len(),
                        report.warnings.len()
                    );
                    for err in &report.errors {
                        warn!(
                            "  validation error: {} = {:?} ({})",
                            err.field, err.value, err.message
                        );
                    }
                    for warn_item in &report.warnings {
                        info!(
                            "  validation warning: {} = {:?} ({})",
                            warn_item.field, warn_item.value, warn_item.message
                        );
                    }
                } else {
                    tracing::debug!("INVESTIGATION: validation clean");
                }

                // Phase 3 : reconciler the LLM verdict against deterministic signals.
                let llm_snapshot = crate::agent::verdict_reconciler::LlmVerdictSnapshot {
                    verdict: parsed.verdict.clone(),
                    severity: parsed.severity.clone(),
                    confidence: parsed.confidence,
                };
                let citation_report = crate::agent::evidence_tracker::validate_citations(
                    &parsed.evidence_citations,
                    &dossier,
                );
                if !citation_report.fabricated.is_empty() {
                    warn!(
                        "INVESTIGATION: {} fabricated citation(s) detected",
                        citation_report.fabricated.len()
                    );
                }
                let outcome = crate::agent::verdict_reconciler::reconcile_verdict(
                    &llm_snapshot,
                    &dossier,
                    &report,
                    &citation_report,
                    validation_mode,
                );

                if let Some(modif) = &outcome.log.modification {
                    warn!(
                        "INVESTIGATION: reconciler matched '{}' (apply={}): {} -> {} (conf {:.2} -> {:.2})",
                        modif.reason_code,
                        outcome.apply,
                        outcome.log.original.verdict,
                        outcome.log.reconciled.verdict,
                        outcome.log.original.confidence,
                        outcome.log.reconciled.confidence,
                    );
                } else {
                    tracing::debug!(
                        "INVESTIGATION: reconciler clean (no rule matched, mode={:?})",
                        validation_mode
                    );
                }

                // Phase 5: structured telemetry events (OTel-consumable).
                crate::telemetry::log_reconcile_outcome(
                    None,
                    &format!("{:?}", validation_mode).to_lowercase(),
                    outcome.apply,
                    &outcome.log.original.verdict,
                    &outcome.log.reconciled.verdict,
                    outcome
                        .log
                        .modification
                        .as_ref()
                        .map(|m| m.reason_code.as_str()),
                    report.errors.len(),
                    citation_report.fabricated_count(),
                );
                crate::telemetry::log_citation_report(
                    None,
                    citation_report.verified.len(),
                    citation_report.unverifiable.len(),
                    citation_report.fabricated_count(),
                );

                // Strict mode: mutate `parsed` so the downstream match that
                // builds the InvestigationVerdict uses the reconciled values.
                if outcome.apply {
                    parsed.verdict = outcome.log.reconciled.verdict.clone();
                    parsed.severity = outcome.log.reconciled.severity.clone();
                    parsed.confidence = outcome.log.reconciled.confidence;
                    info!(
                        "INVESTIGATION: reconciler applied in STRICT mode — verdict is now '{}'",
                        parsed.verdict
                    );
                }
            }
        }

        // Track the best LLM response for fallback (keep highest confidence)
        if best_parsed
            .as_ref()
            .map_or(true, |(_, c, _)| parsed.confidence > *c)
        {
            best_parsed = Some((
                parsed.analysis.clone(),
                parsed.confidence,
                parsed.correlations.clone(),
            ));
        }

        // LLM wants more info → execute requested skills (skip previously failed ones)
        if parsed.needs_more_info && !parsed.skill_requests.is_empty() {
            let actionable_requests: Vec<&SkillRequest> = parsed
                .skill_requests
                .iter()
                .filter(|r| !failed_skills.contains(&r.skill_name))
                .collect();

            if actionable_requests.is_empty() {
                debug!(
                    "INVESTIGATION: All requested skills already failed — skipping re-request, using current analysis"
                );
                // Don't continue looping — fall through to verdict logic
            } else {
                for req in &actionable_requests {
                    if skill_calls >= config.max_skill_calls {
                        warn!(
                            "INVESTIGATION: Max skill calls ({}) reached",
                            config.max_skill_calls
                        );
                        break;
                    }

                    info!(
                        "INVESTIGATION: Calling skill {} ({:?})",
                        req.skill_name, req.params
                    );
                    match tokio::time::timeout(
                        config.skill_timeout,
                        execute_investigation_skill(req, &store),
                    )
                    .await
                    {
                        Ok(result) => {
                            info!(
                                "INVESTIGATION: Skill {} → success={} ({}ms)",
                                result.skill_name, result.success, result.duration_ms
                            );
                            if !result.success {
                                failed_skills.insert(req.skill_name.clone());
                            }
                            skill_results.push((req.skill_name.clone(), result.data));
                        }
                        Err(_) => {
                            warn!("INVESTIGATION: Skill {} timed out", req.skill_name);
                            failed_skills.insert(req.skill_name.clone());
                            skill_results.push((
                                req.skill_name.clone(),
                                serde_json::json!({"error": "timeout"}),
                            ));
                        }
                    }
                    skill_calls += 1;
                }
                continue; // Re-loop with new skill results
            }
        }

        // Validate severity
        let severity = crate::agent::production_safeguards::validate_severity(&parsed.severity)
            .unwrap_or_else(|| "MEDIUM".to_string());

        // CRITICAL → escalate to L2 Forensic (once)
        if severity == "CRITICAL" && iteration <= 2 {
            info!("INVESTIGATION: CRITICAL → escalating to L2 Forensic");
            let l2_prompt =
                format!("{prompt}\n\n--- L2 FORENSIC: Analyse root-cause complète requise. ---\n");

            if let Ok(Ok(l2_raw)) = tokio::time::timeout(
                Duration::from_secs(180),
                crate::agent::react_runner::call_ollama_with_schema(
                    &llm_config.forensic.base_url,
                    &llm_config.forensic.model,
                    &l2_prompt,
                    Some(crate::agent::llm_schemas::forensic_schema()),
                ),
            )
            .await
            {
                if let Ok(l2) = parse_llm_response(&l2_raw) {
                    info!(
                        "INVESTIGATION: L2 verdict={} confidence={:.0}%",
                        l2.verdict,
                        l2.confidence * 100.0
                    );
                    return InvestigationResult {
                        dossier_id,
                        asset,
                        verdict: InvestigationVerdict::Confirmed {
                            analysis: l2.analysis,
                            severity,
                            confidence: l2.confidence,
                            correlations: l2.correlations,
                            proposed_actions: l2.proposed_actions,
                            llm_level: "L2 Forensique".into(),
                            evidence_citations: vec![],
                        },
                        duration_secs: start.elapsed().as_secs(),
                        iterations: iteration,
                        skill_calls,
                        completed_at: Utc::now(),
                        incident_title_fr: l2.incident_title_fr,
                    };
                }
            }
            warn!("INVESTIGATION: L2 failed, using L1 result");
        }

        // Final verdict from L1
        if parsed.confidence >= config.confidence_accept || !parsed.needs_more_info {
            let title_fr = parsed.incident_title_fr.clone();
            let verdict = match parsed.verdict.as_str() {
                "confirmed" => InvestigationVerdict::Confirmed {
                    analysis: parsed.analysis,
                    severity,
                    confidence: parsed.confidence,
                    correlations: parsed.correlations,
                    proposed_actions: parsed.proposed_actions,
                    llm_level: "L1 Triage".into(),
                    evidence_citations: parsed.evidence_citations,
                },
                "false_positive" => InvestigationVerdict::FalsePositive {
                    analysis: parsed.analysis.clone(),
                    confidence: parsed.confidence,
                    reason: parsed.analysis,
                },
                "informational" => InvestigationVerdict::Informational {
                    analysis: parsed.analysis.clone(),
                    summary: parsed.analysis,
                },
                _ => InvestigationVerdict::Inconclusive {
                    analysis: parsed.analysis,
                    confidence: parsed.confidence,
                    partial_findings: parsed.correlations,
                },
            };

            return InvestigationResult {
                dossier_id,
                asset,
                verdict,
                duration_secs: start.elapsed().as_secs(),
                iterations: iteration,
                skill_calls,
                completed_at: Utc::now(),
                incident_title_fr: title_fr,
            };
        }
    }

    // Timeout or max iterations without verdict — use best LLM response if available
    let (fallback_analysis, fallback_confidence, fallback_findings) =
        best_parsed.unwrap_or_else(|| {
            (
                "Investigation non concluante — timeout ou max itérations atteint".into(),
                0.4,
                vec![],
            )
        });
    InvestigationResult {
        dossier_id,
        asset,
        verdict: InvestigationVerdict::Inconclusive {
            analysis: fallback_analysis,
            confidence: fallback_confidence,
            partial_findings: fallback_findings,
        },
        duration_secs: start.elapsed().as_secs(),
        iterations: iteration,
        skill_calls,
        completed_at: Utc::now(),
        incident_title_fr: None,
    }
}

fn make_error_result(
    dossier_id: uuid::Uuid,
    asset: String,
    reason: &str,
    start: Instant,
    iterations: usize,
    skill_calls: usize,
) -> InvestigationResult {
    InvestigationResult {
        dossier_id,
        asset,
        verdict: InvestigationVerdict::Error {
            reason: reason.to_string(),
            partial_analysis: None,
        },
        duration_secs: start.elapsed().as_secs(),
        iterations,
        skill_calls,
        completed_at: Utc::now(),
        incident_title_fr: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_llm_response_valid_json() {
        let raw = r#"{
            "verdict":"confirmed",
            "analysis":"Brute force detected",
            "severity":"HIGH",
            "confidence":0.9,
            "correlations":[],
            "needs_more_info":false,
            "skill_requests":[],
            "proposed_actions":[]
        }"#;
        let parsed = parse_llm_response(raw).expect("valid JSON must parse");
        assert_eq!(parsed.verdict, "confirmed");
        assert_eq!(parsed.severity, "HIGH");
        assert!((parsed.confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn test_parse_llm_response_strips_markdown_fences() {
        let raw = "```json\n{\"verdict\":\"inconclusive\",\"analysis\":\"\",\"severity\":\"MEDIUM\",\"confidence\":0.5,\"correlations\":[],\"needs_more_info\":false,\"skill_requests\":[],\"proposed_actions\":[]}\n```";
        let parsed = parse_llm_response(raw).expect("fenced JSON must parse");
        assert_eq!(parsed.verdict, "inconclusive");
    }

    #[test]
    fn test_parse_llm_response_repairs_trailing_comma() {
        // Trailing comma is invalid JSON but a common LLM slip; llm_json should
        // repair it and the second parse must succeed.
        let raw = r#"{"verdict":"confirmed","analysis":"ok","severity":"HIGH","confidence":0.9,"correlations":[],"needs_more_info":false,"skill_requests":[],"proposed_actions":[],}"#;
        let parsed = parse_llm_response(raw);
        assert!(
            parsed.is_ok(),
            "llm_json must repair the trailing comma; got: {:?}",
            parsed.err()
        );
        assert_eq!(parsed.unwrap().verdict, "confirmed");
    }

    #[test]
    fn test_parse_llm_response_irreparable_returns_err() {
        let raw = "this is definitely not JSON and llm_json cannot help here <<<>>>";
        let result = parse_llm_response(raw);
        assert!(result.is_err(), "irreparable garbage must return Err");
    }

    #[test]
    fn test_parse_llm_response_extracts_evidence_citations() {
        let raw = r#"{
            "verdict": "confirmed",
            "analysis": "Brute force confirmed.",
            "severity": "HIGH",
            "confidence": 0.9,
            "correlations": [],
            "needs_more_info": false,
            "skill_requests": [],
            "proposed_actions": [],
            "evidence_citations": [
                { "claim": "13 failed auths", "evidence_type": "alert", "evidence_id": "42" },
                { "claim": "Tor exit node", "evidence_type": "log", "evidence_id": "hash-abc" }
            ]
        }"#;
        let parsed = parse_llm_response(raw).expect("parse");
        assert_eq!(parsed.evidence_citations.len(), 2);
        assert_eq!(parsed.evidence_citations[0].evidence_id, "42");
    }

    #[test]
    fn test_parse_llm_response_no_citations_defaults_empty() {
        let raw = r#"{
            "verdict": "confirmed",
            "analysis": "x",
            "severity": "MEDIUM",
            "confidence": 0.5,
            "correlations": [],
            "needs_more_info": false,
            "skill_requests": [],
            "proposed_actions": []
        }"#;
        let parsed = parse_llm_response(raw).expect("parse");
        assert!(parsed.evidence_citations.is_empty());
    }
}
