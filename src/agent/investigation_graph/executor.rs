//! Exécuteur du graph d'investigation — traversée du DAG compilé et
//! exécution des steps.
//!
//! G1a — version synchrone, pas encore de task queue (G1b s'en chargera).
//! Les `action` qui appellent une skill ou un LLM sont stubbed pour
//! l'instant (renvoient une trace `pending_async`) — l'exécution réelle
//! arrive avec G1b.
//!
//! L'executor gère :
//! - Start → on suit `on_completion`
//! - End → terminal
//! - Action(Archive)        → terminal avec verdict `archive`
//! - Action(EmitIncident)   → terminal avec verdict `incident`
//! - Action(InvestigateLlm) → stub G1a (renvoie `pending_async`)
//! - Action(SkillCall)      → stub G1a (renvoie `pending_async`)
//! - IfCondition            → eval CEL sur `condition`, suit `on_true` /
//!   `on_false`
//! - SwitchCondition        → stub G1a (à activer avec un cas réel en G1d)
//! - Parallel               → stub G1a (G1b avec task queue)
//! - PlaybookAction         → stub G1a (G1c avec sub-graphs Cypher)
//!
//! Pour chaque exécution on construit une `ExecutionTrace` qui liste tous
//! les steps visités, leurs durées, leur résultat. Cette trace est ce
//! qu'on persistera en table `graph_executions` (G1b).

use std::time::Instant;

use serde::Serialize;
use thiserror::Error;
use tracing::{debug, info, warn};

use super::cel_eval::{self, EvalContext};
use super::graph::CompiledGraph;
use super::types::{Command, Step};

// ── Erreurs ──

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("step '{0}' not found in graph")]
    StepNotFound(String),

    #[error("CEL evaluation failed at step '{step}': {source}")]
    CelFailed {
        step: String,
        #[source]
        source: cel_eval::CelError,
    },

    #[error("step kind '{0}' not yet supported in G1a runtime")]
    UnsupportedStepKind(String),

    #[error("graph exceeded max steps ({0}) — likely a logic error")]
    #[allow(dead_code)] // surfaced once max-steps hard-stop is wired in (G1b)
    MaxStepsExceeded(usize),
}

// ── Trace d'exécution ──

/// Résultat d'un step individuel — accumulé dans la trace.
#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub step_name: String,
    pub step_kind: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration_ms: u64,
    pub branch_taken: Option<String>,
    pub note: Option<String>,
}

/// Trace complète d'une exécution de graph.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionTrace {
    pub graph_name: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub total_duration_ms: u64,
    pub steps_visited: Vec<StepResult>,
    pub outcome: ExecutionOutcome,
}

/// Verdict final de l'exécution.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// Terminé : auto-archive avec motif (exemple : "résolu par firewall")
    Archive { reason: String },
    /// Terminé : incident promu pour le RSSI
    Incident {
        severity: String,
        proposed_actions: Vec<serde_json::Value>,
    },
    /// Le graph s'est arrêté à un step async (LLM call, skill call, parallel).
    /// G1b reprendra depuis ce point via la task queue.
    PendingAsync {
        at_step: String,
        task_kind: String,
        params: serde_json::Value,
    },
    /// Le graph a atteint un step `End` sans verdict particulier — fallback
    /// "rien à faire". Auto-archive avec motif "graph terminé sans verdict".
    Inconclusive,
}

// ── Executor ──

const MAX_STEPS_PER_RUN: usize = 64;

/// Exécute un graph compilé sur un contexte d'évaluation. Synchrone pour
/// l'instant — G1b refactorera vers async + task queue.
pub struct GraphExecutor;

impl GraphExecutor {
    pub fn run(
        graph: &CompiledGraph,
        ctx: &EvalContext,
    ) -> Result<ExecutionTrace, ExecutorError> {
        let started_at = chrono::Utc::now();
        let run_start = Instant::now();
        let mut visited: Vec<StepResult> = Vec::new();

        let mut current = graph.start_step.clone();
        let mut outcome: Option<ExecutionOutcome> = None;

        info!(
            "GRAPH RUN: starting graph='{}' from step='{}'",
            graph.name, current
        );

        for _ in 0..MAX_STEPS_PER_RUN {
            let step_start = Instant::now();
            let step_started_at = chrono::Utc::now();

            let step = graph
                .steps
                .get(&current)
                .ok_or_else(|| ExecutorError::StepNotFound(current.clone()))?;

            let step_kind = step.step_kind().to_string();
            debug!("GRAPH STEP: {} (kind={})", current, step_kind);

            let (next, branch, outcome_step, note) = exec_step(graph, step, ctx, &current)?;

            let dur = step_start.elapsed();
            visited.push(StepResult {
                step_name: current.clone(),
                step_kind,
                started_at: step_started_at,
                duration_ms: dur.as_millis() as u64,
                branch_taken: branch,
                note,
            });

            match (outcome_step, next) {
                (Some(o), _) => {
                    outcome = Some(o);
                    break;
                }
                (None, Some(n)) => {
                    current = n;
                }
                (None, None) => {
                    // step terminal sans outcome explicite → inconclusive
                    outcome = Some(ExecutionOutcome::Inconclusive);
                    break;
                }
            }
        }

        let outcome = outcome.unwrap_or_else(|| {
            warn!(
                "GRAPH RUN: max steps ({}) reached on graph='{}'",
                MAX_STEPS_PER_RUN, graph.name
            );
            ExecutionOutcome::Inconclusive
        });

        let trace = ExecutionTrace {
            graph_name: graph.name.clone(),
            started_at,
            total_duration_ms: run_start.elapsed().as_millis() as u64,
            steps_visited: visited,
            outcome,
        };

        info!(
            "GRAPH DONE: graph='{}' steps={} duration={}ms outcome={:?}",
            trace.graph_name,
            trace.steps_visited.len(),
            trace.total_duration_ms,
            trace.outcome
        );

        Ok(trace)
    }
}

/// Exécute un step. Retourne (next_step, branch_label, outcome, note).
/// Si `outcome` est Some, on s'arrête.
fn exec_step(
    _graph: &CompiledGraph,
    step: &Step,
    ctx: &EvalContext,
    current: &str,
) -> Result<
    (
        Option<String>,
        Option<String>,
        Option<ExecutionOutcome>,
        Option<String>,
    ),
    ExecutorError,
> {
    match step {
        Step::Start { on_completion } => {
            Ok((Some(on_completion.clone()), None, None, None))
        }
        Step::End => Ok((None, None, None, None)),
        Step::Action {
            command,
            on_completion,
        } => exec_action_command(command, on_completion.as_deref()),
        Step::IfCondition {
            condition,
            on_true,
            on_false,
        } => {
            let program = cel_eval::compile(condition).map_err(|e| {
                ExecutorError::CelFailed {
                    step: current.to_string(),
                    source: e,
                }
            })?;
            let result =
                cel_eval::evaluate(&program, ctx).map_err(|e| ExecutorError::CelFailed {
                    step: current.to_string(),
                    source: e,
                })?;
            let next = if result {
                on_true.clone()
            } else {
                on_false.clone()
            };
            let branch = if result { "true" } else { "false" }.to_string();
            Ok((Some(next), Some(branch), None, None))
        }
        Step::SwitchCondition { .. } => {
            Err(ExecutorError::UnsupportedStepKind("switch-condition".into()))
        }
        Step::Parallel { .. } => Ok((
            None,
            None,
            Some(ExecutionOutcome::PendingAsync {
                at_step: current.to_string(),
                task_kind: "parallel".into(),
                params: serde_json::json!({}),
            }),
            Some("parallel deferred to G1b".into()),
        )),
        Step::PlaybookAction { .. } => Ok((
            None,
            None,
            Some(ExecutionOutcome::PendingAsync {
                at_step: current.to_string(),
                task_kind: "playbook-action".into(),
                params: serde_json::json!({}),
            }),
            Some("sub-graph deferred to G1c".into()),
        )),
    }
}

/// Exécute un step `Action` selon le type de commande.
fn exec_action_command(
    cmd: &Command,
    on_completion: Option<&str>,
) -> Result<
    (
        Option<String>,
        Option<String>,
        Option<ExecutionOutcome>,
        Option<String>,
    ),
    ExecutorError,
> {
    match cmd {
        Command::ThreatclawArchive { reason } => Ok((
            None,
            None,
            Some(ExecutionOutcome::Archive {
                reason: reason.clone(),
            }),
            None,
        )),
        Command::ThreatclawEmitIncident {
            severity,
            proposed_actions,
        } => Ok((
            None,
            None,
            Some(ExecutionOutcome::Incident {
                severity: severity.clone(),
                proposed_actions: proposed_actions.clone(),
            }),
            None,
        )),
        Command::ThreatclawInvestigateLlm { timeout_secs } => Ok((
            None,
            None,
            Some(ExecutionOutcome::PendingAsync {
                at_step: on_completion
                    .unwrap_or("(no_continuation)")
                    .to_string(),
                task_kind: "investigate-llm".into(),
                params: serde_json::json!({"timeout_secs": timeout_secs}),
            }),
            Some("LLM call deferred to G1b queue".into()),
        )),
        Command::ThreatclawSkillCall {
            skill_name,
            params,
        } => Ok((
            None,
            None,
            Some(ExecutionOutcome::PendingAsync {
                at_step: on_completion
                    .unwrap_or("(no_continuation)")
                    .to_string(),
                task_kind: "skill-call".into(),
                params: serde_json::json!({
                    "skill_name": skill_name,
                    "params": params,
                }),
            }),
            Some("skill call deferred to G1b queue".into()),
        )),
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::investigation_graph::graph::compile;
    use crate::agent::investigation_graph::types::{Graph, Trigger};
    use serde_json::json;
    use std::collections::HashMap;

    fn graph_backdoor_block_handled() -> Graph {
        let mut steps = HashMap::new();
        steps.insert(
            "start".to_string(),
            Step::Start {
                on_completion: "check_block".into(),
            },
        );
        steps.insert(
            "check_block".to_string(),
            Step::IfCondition {
                condition: r#"alert.firewall_action == "block""#.into(),
                on_true: "check_ip_internal".into(),
                on_false: "route_to_llm".into(),
            },
        );
        steps.insert(
            "check_ip_internal".to_string(),
            Step::IfCondition {
                condition: "graph.asset_in_graph".into(),
                on_true: "route_to_llm".into(),
                on_false: "archive_resolved".into(),
            },
        );
        steps.insert(
            "archive_resolved".to_string(),
            Step::Action {
                command: Command::ThreatclawArchive {
                    reason: "résolu par firewall".into(),
                },
                on_completion: None,
            },
        );
        steps.insert(
            "route_to_llm".to_string(),
            Step::Action {
                command: Command::ThreatclawInvestigateLlm {
                    timeout_secs: 1500,
                },
                on_completion: Some("end".into()),
            },
        );
        steps.insert("end".to_string(), Step::End);

        Graph {
            spec_version: "cacao-2.0".into(),
            name: "backdoor-port-block-handled".into(),
            description: None,
            trigger: Trigger {
                sigma_rule: "opnsense_block_backdoor_port".into(),
            },
            steps,
        }
    }

    #[test]
    fn backdoor_block_external_ip_archives() {
        let g = graph_backdoor_block_handled();
        let compiled = compile(&g).unwrap();
        let ctx = EvalContext::new()
            .with_alert(json!({
                "firewall_action": "block",
                "src_ip": "185.78.113.253",
            }))
            .with_graph(json!({
                "asset_in_graph": false,
            }));
        let trace = GraphExecutor::run(&compiled, &ctx).unwrap();

        match trace.outcome {
            ExecutionOutcome::Archive { ref reason } => {
                assert_eq!(reason, "résolu par firewall");
            }
            other => panic!("expected Archive, got {:?}", other),
        }
        // start → check_block → check_ip_internal → archive_resolved
        assert_eq!(trace.steps_visited.len(), 4);
    }

    #[test]
    fn backdoor_block_internal_ip_routes_to_llm() {
        let g = graph_backdoor_block_handled();
        let compiled = compile(&g).unwrap();
        let ctx = EvalContext::new()
            .with_alert(json!({
                "firewall_action": "block",
                "src_ip": "10.77.0.50",
            }))
            .with_graph(json!({
                "asset_in_graph": true,
            }));
        let trace = GraphExecutor::run(&compiled, &ctx).unwrap();

        match trace.outcome {
            ExecutionOutcome::PendingAsync { task_kind, .. } => {
                assert_eq!(task_kind, "investigate-llm");
            }
            other => panic!("expected PendingAsync(investigate-llm), got {:?}", other),
        }
    }

    #[test]
    fn non_block_action_routes_to_llm() {
        let g = graph_backdoor_block_handled();
        let compiled = compile(&g).unwrap();
        let ctx = EvalContext::new()
            .with_alert(json!({
                "firewall_action": "alert",
                "src_ip": "1.2.3.4",
            }))
            .with_graph(json!({
                "asset_in_graph": false,
            }));
        let trace = GraphExecutor::run(&compiled, &ctx).unwrap();

        match trace.outcome {
            ExecutionOutcome::PendingAsync { .. } => {}
            other => panic!("expected PendingAsync, got {:?}", other),
        }
    }

    #[test]
    fn malformed_predicate_returns_error() {
        let mut g = graph_backdoor_block_handled();
        // Casser la condition du if
        if let Some(Step::IfCondition { condition, .. }) = g.steps.get_mut("check_block") {
            *condition = "alert.x ==".into();
        }
        let compiled = compile(&g).unwrap();
        let ctx = EvalContext::new();
        let err = GraphExecutor::run(&compiled, &ctx).unwrap_err();
        assert!(matches!(err, ExecutorError::CelFailed { .. }));
    }
}
