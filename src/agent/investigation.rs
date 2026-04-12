//! Investigation Runner — automated incident investigation. See ADR-024.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::agent::incident_dossier::IncidentDossier;
use crate::agent::investigation_skills::{execute_investigation_skill, SkillRequest};
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

        // Clean up stale entries (> 1 hour = crashed)
        // Aligned with 900s per-iteration LLM timeout * 5 iterations max.
        active.retain(|_, state| state.started_at.elapsed() < Duration::from_secs(3600));

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
}

fn parse_llm_response(raw: &str) -> Result<ParsedLlmResponse, String> {
    // Strip markdown code fences if present
    let json_str = raw
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let v: Value = serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {e}"))?;

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
    })
}

// ── Main investigation loop ──

/// Run a full investigation on an incident dossier.
///
/// This is the core of stage 2: the ReAct loop analyzes the dossier,
/// optionally calls investigation skills for more data, and produces a verdict.
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
    let lang = crate::agent::prompt_builder::get_language(store.as_ref())
        .await;

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

        // Call L1 LLM
        let llm_raw = match tokio::time::timeout(
            Duration::from_secs(900),
            crate::agent::react_runner::call_ollama(
                &llm_config.primary.base_url,
                &llm_config.primary.model,
                &prompt,
            ),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                error!("INVESTIGATION: LLM call failed: {e}");
                return make_error_result(dossier_id, asset, &format!("LLM failed: {e}"), start, iteration, skill_calls);
            }
            Err(_) => {
                error!("INVESTIGATION: LLM call timed out (900s)");
                return make_error_result(dossier_id, asset, "LLM timeout 900s", start, iteration, skill_calls);
            }
        };

        // Parse LLM response
        let parsed = match parse_llm_response(&llm_raw) {
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

        // Track the best LLM response for fallback (keep highest confidence)
        if best_parsed.as_ref().map_or(true, |(_, c, _)| parsed.confidence > *c) {
            best_parsed = Some((parsed.analysis.clone(), parsed.confidence, parsed.correlations.clone()));
        }

        // LLM wants more info → execute requested skills (skip previously failed ones)
        if parsed.needs_more_info && !parsed.skill_requests.is_empty() {
            let actionable_requests: Vec<&SkillRequest> = parsed.skill_requests.iter()
                .filter(|r| !failed_skills.contains(&r.skill_name))
                .collect();

            if actionable_requests.is_empty() {
                debug!("INVESTIGATION: All requested skills already failed — skipping re-request, using current analysis");
                // Don't continue looping — fall through to verdict logic
            } else {
                for req in &actionable_requests {
                    if skill_calls >= config.max_skill_calls {
                        warn!("INVESTIGATION: Max skill calls ({}) reached", config.max_skill_calls);
                        break;
                    }

                    info!("INVESTIGATION: Calling skill {} ({:?})", req.skill_name, req.params);
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
            let l2_prompt = format!(
                "{prompt}\n\n--- L2 FORENSIC: Analyse root-cause complète requise. ---\n"
            );

            if let Ok(Ok(l2_raw)) = tokio::time::timeout(
                Duration::from_secs(180),
                crate::agent::react_runner::call_ollama(
                    &llm_config.forensic.base_url,
                    &llm_config.forensic.model,
                    &l2_prompt,
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
                        },
                        duration_secs: start.elapsed().as_secs(),
                        iterations: iteration,
                        skill_calls,
                        completed_at: Utc::now(),
                    };
                }
            }
            warn!("INVESTIGATION: L2 failed, using L1 result");
        }

        // Final verdict from L1
        if parsed.confidence >= config.confidence_accept || !parsed.needs_more_info {
            let verdict = match parsed.verdict.as_str() {
                "confirmed" => InvestigationVerdict::Confirmed {
                    analysis: parsed.analysis,
                    severity,
                    confidence: parsed.confidence,
                    correlations: parsed.correlations,
                    proposed_actions: parsed.proposed_actions,
                    llm_level: "L1 Triage".into(),
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
            };
        }
    }

    // Timeout or max iterations without verdict — use best LLM response if available
    let (fallback_analysis, fallback_confidence, fallback_findings) = best_parsed
        .unwrap_or_else(|| (
            "Investigation non concluante — timeout ou max itérations atteint".into(),
            0.4,
            vec![],
        ));
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
    }
}
