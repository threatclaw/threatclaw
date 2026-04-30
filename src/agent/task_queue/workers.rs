//! Workers concrets — fonctions d'exécution pour les 3 kinds de tasks.
//!
//! Les `WorkerFn` ci-dessous sont des closures `Arc` qui capturent ce
//! dont elles ont besoin (store DB, library de graphs, ...). Le supervisor
//! les invoque via `dispatch_one`.

use std::sync::Arc;

use serde_json::{Value, json};
use tracing::{info, warn};

use super::pool::{WorkerError, WorkerFn};
use super::store::GraphExecutionStatus;
use crate::agent::investigation_graph::{
    EvalContext, ExecutionOutcome, GraphExecutor, GraphLibrary,
};
use crate::agent::investigation_skills::{SkillRequest, execute_investigation_skill};
use crate::db::Database;

/// Worker pour `TaskKind::SkillCall`. Payload attendu :
/// `{"skill_name": "...", "params": { ... }}`. Retourne le `data` JSON
/// de la `SkillResult` si succès, sinon `WorkerError::Failed`.
pub fn skill_worker_fn(store: Arc<dyn Database>) -> WorkerFn {
    Arc::new(move |task| {
        let store = store.clone();
        Box::pin(async move {
            let skill_name = task
                .payload
                .get("skill_name")
                .and_then(Value::as_str)
                .ok_or_else(|| WorkerError::Failed("payload manque 'skill_name'".into()))?
                .to_string();
            let params = task
                .payload
                .get("params")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));

            let req = SkillRequest {
                skill_name: skill_name.clone(),
                params,
            };
            let result = execute_investigation_skill(&req, &store).await;
            if result.success {
                Ok(result.data)
            } else {
                Err(WorkerError::Failed(format!(
                    "skill '{}' a renvoyé success=false",
                    skill_name
                )))
            }
        })
    })
}

/// Worker pour `TaskKind::LlmCall`. Payload attendu :
/// `{"base_url": "...", "model": "...", "prompt": "...", "schema": {...}?}`.
/// Retourne le résultat JSON de l'appel Ollama (parsed en `Value`).
pub fn llm_worker_fn() -> WorkerFn {
    Arc::new(move |task| {
        Box::pin(async move {
            let base_url = task
                .payload
                .get("base_url")
                .and_then(Value::as_str)
                .ok_or_else(|| WorkerError::Failed("payload manque 'base_url'".into()))?
                .to_string();
            let model = task
                .payload
                .get("model")
                .and_then(Value::as_str)
                .ok_or_else(|| WorkerError::Failed("payload manque 'model'".into()))?
                .to_string();
            let prompt = task
                .payload
                .get("prompt")
                .and_then(Value::as_str)
                .ok_or_else(|| WorkerError::Failed("payload manque 'prompt'".into()))?
                .to_string();
            let schema = task.payload.get("schema").cloned();

            let raw = crate::agent::react_runner::call_ollama_with_schema(
                &base_url, &model, &prompt, schema,
            )
            .await
            .map_err(|e| WorkerError::Failed(format!("ollama: {}", e)))?;

            // Le caller peut décider de parser ou pas, mais on tente d'abord
            // le parse JSON puisque la plupart des prompts demandent du JSON
            // structuré (cf. llm_schemas).
            match serde_json::from_str::<Value>(&raw) {
                Ok(v) => Ok(v),
                Err(e) => {
                    warn!(
                        "LLM WORKER: réponse non-JSON ({}), encapsulation en raw string",
                        e
                    );
                    Ok(json!({"raw": raw}))
                }
            }
        })
    })
}

/// Worker pour `TaskKind::GraphStep` — exécute un Investigation Graph
/// complet depuis la library, persiste le verdict en `graph_executions`.
///
/// Payload attendu :
/// ```json
/// {
///   "graph_name": "backdoor-port-block-handled",
///   "ctx": {
///     "alert":   { ... },
///     "asset":   { ... },
///     "dossier": { ... },
///     "signals": { ... },
///     "graph":   { ... }
///   }
/// }
/// ```
///
/// Si `task.graph_run_id` est `Some(id)`, on finalise la row
/// `graph_executions` avec le verdict (status + motif/incident_id + trace).
/// Sinon (call orphelin), on log et on retourne juste la trace.
pub fn graph_step_worker_fn(library: Arc<GraphLibrary>, store: Arc<dyn Database>) -> WorkerFn {
    Arc::new(move |task| {
        let library = library.clone();
        let store = store.clone();
        Box::pin(async move {
            let graph_name = task
                .payload
                .get("graph_name")
                .and_then(Value::as_str)
                .ok_or_else(|| WorkerError::Failed("payload manque 'graph_name'".into()))?
                .to_string();

            let compiled = library.find_by_name(&graph_name).cloned().ok_or_else(|| {
                WorkerError::Failed(format!("graph '{}' introuvable", graph_name))
            })?;

            let ctx_payload = task
                .payload
                .get("ctx")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            let ctx = build_eval_context(&ctx_payload);

            let trace = GraphExecutor::run(&compiled, &ctx)
                .map_err(|e| WorkerError::Failed(format!("executor: {}", e)))?;

            // Persist verdict en `graph_executions` si on a un id parent.
            if let Some(exec_id) = task.graph_run_id {
                persist_outcome(&store, exec_id, &ctx_payload, &trace).await;
            }

            info!(
                "GRAPH STEP WORKER: graph='{}' done in {}ms outcome={:?}",
                graph_name, trace.total_duration_ms, trace.outcome
            );

            // Retourne la trace sérialisée comme résultat de la task.
            Ok(serde_json::to_value(&trace).unwrap_or(json!({})))
        })
    })
}

/// Construit un `EvalContext` à partir du payload JSON envoyé via la queue.
/// Les champs absents deviennent des `{}` vides — le predicate engine
/// propagera l'erreur d'accès si un graph s'attend à un champ manquant.
fn build_eval_context(payload: &Value) -> EvalContext {
    EvalContext::new()
        .with_alert(
            payload
                .get("alert")
                .cloned()
                .unwrap_or(Value::Object(Default::default())),
        )
        .with_asset(
            payload
                .get("asset")
                .cloned()
                .unwrap_or(Value::Object(Default::default())),
        )
        .with_dossier(
            payload
                .get("dossier")
                .cloned()
                .unwrap_or(Value::Object(Default::default())),
        )
        .with_signals(
            payload
                .get("signals")
                .cloned()
                .unwrap_or(Value::Object(Default::default())),
        )
        .with_graph(
            payload
                .get("graph")
                .cloned()
                .unwrap_or(Value::Object(Default::default())),
        )
}

async fn persist_outcome(
    store: &Arc<dyn Database>,
    exec_id: i64,
    ctx_payload: &Value,
    trace: &crate::agent::investigation_graph::ExecutionTrace,
) {
    let (status, archive_reason, incident_id) = match &trace.outcome {
        ExecutionOutcome::Archive { reason } => {
            (GraphExecutionStatus::Archived, Some(reason.clone()), None)
        }
        ExecutionOutcome::Incident {
            severity,
            proposed_actions,
        } => {
            // Phase G1d (corrected): le graph rend Incident, on doit créer
            // une row dans `incidents` pour que le pipeline HITL existant
            // (Slack/Telegram, page /incidents, license gate sur execute)
            // y trouve les `proposed_actions`. Sans ça, le verdict reste
            // cloisonné dans `graph_executions` et invisible pour le RSSI.
            let inc_id =
                create_incident_from_graph(store, ctx_payload, trace, severity, proposed_actions)
                    .await;

            // Phase G4: post-graph conditional L1 trigger.
            // HIGH/CRITICAL incidents get an automatic L1 analysis to enrich
            // the investigation dossier before the RSSI opens the page.
            if let Some(iid) = inc_id {
                let sev_up = severity.to_uppercase();
                if sev_up == "HIGH" || sev_up == "CRITICAL" {
                    let store_l1 = store.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            crate::agent::incident_investigator::run_l1_analysis(iid, store_l1)
                                .await
                        {
                            warn!("POST_GRAPH L1: incident #{iid} — {e}");
                        }
                    });
                }
            }

            (GraphExecutionStatus::Incident, None, inc_id)
        }
        ExecutionOutcome::Inconclusive => (GraphExecutionStatus::Inconclusive, None, None),
        ExecutionOutcome::PendingAsync {
            task_kind, at_step, ..
        } => {
            // Sprint 5 #1 — the graph delegated to an async path. The
            // only async kind currently shipped is `investigate-llm`;
            // when that's the case ReAct is running in parallel
            // (see intelligence_engine.rs — TC_GRAPH_ONLY no longer
            // skips ReAct when the matched graph contains
            // `threatclaw-investigate-llm`). We finalize the
            // graph_execution row as Inconclusive with a clear
            // archive_reason so it doesn't hang in `running` forever
            // and so the audit trail records that the graph chose to
            // delegate.
            //
            // For `skill-call` (no shipped graph uses it yet) we apply
            // the same finalization — when the worker for that kind
            // gets wired, this becomes a real resume point.
            let reason = format!("delegated → {} (resume at step '{}')", task_kind, at_step);
            (GraphExecutionStatus::Inconclusive, Some(reason), None)
        }
    };

    let trace_json = serde_json::to_value(trace).unwrap_or(json!({}));
    if let Err(e) = store
        .finalize_graph_execution(
            exec_id,
            status,
            archive_reason.as_deref(),
            incident_id,
            &trace_json,
            None,
        )
        .await
    {
        warn!(
            "GRAPH STEP WORKER: finalize_graph_execution({}) failed: {}",
            exec_id, e
        );
    }
}

/// Crée une row `incidents` à partir d'un verdict Incident produit par
/// un graph. Le RSSI verra cet incident dans /incidents avec ses
/// `proposed_actions` exposés en HITL — exactement comme un verdict
/// ReAct. Le `investigation_log` contient la trace du graph (steps
/// visités, branchements, durées) pour fournir le contexte décisionnel.
///
/// Retourne `Some(incident_id)` en cas de succès, ou `None` si la
/// création échoue (logué en warn, le graph_executions reste status =
/// 'incident' sans incident_id lié).
async fn create_incident_from_graph(
    store: &Arc<dyn Database>,
    ctx_payload: &Value,
    trace: &crate::agent::investigation_graph::ExecutionTrace,
    severity: &str,
    proposed_actions: &[Value],
) -> Option<i32> {
    let asset = ctx_payload
        .pointer("/asset/id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let action_count = proposed_actions.len();
    let title = if action_count > 0 {
        format!(
            "[graph] {} — {} action(s) proposée(s)",
            trace.graph_name, action_count
        )
    } else {
        format!("[graph] {} — verdict {}", trace.graph_name, severity)
    };

    let sev_db = severity.to_uppercase();

    // Dedup : si un incident open existe déjà pour cet asset dans la
    // fenêtre de 4h (même politique que `intelligence_engine`), on
    // l'update au lieu d'en créer un doublon. Sinon on crée.
    let existing = store
        .find_open_incident_for_asset(&asset)
        .await
        .unwrap_or_else(|e| {
            warn!(
                "GRAPH STEP WORKER: find_open_incident_for_asset({}) failed: {} — fallback create",
                asset, e
            );
            None
        });

    let inc_id = if let Some(existing_id) = existing {
        // Bump alert_count pour indiquer la récurrence + on update verdict
        // ci-dessous avec les actions du graph (qui peuvent avoir changé).
        // Sprint 5 #2 — pattern key = graph name. If the same graph keeps
        // firing on the same asset (e.g. a port scan that touches the
        // canary every minute), alert_count is no-op'd; we only update
        // `updated_at`. Counter still grows when a *different* graph
        // (genuine new evidence) folds into this incident.
        if let Err(e) = store
            .touch_incident(existing_id, 1, Some(&trace.graph_name))
            .await
        {
            warn!(
                "GRAPH STEP WORKER: touch_incident({}) failed: {}",
                existing_id, e
            );
        }
        info!(
            "GRAPH STEP WORKER: réutilisation incident #{} pour asset={} (dedup 4h)",
            existing_id, asset
        );
        existing_id
    } else {
        match store
            .create_incident(&asset, &title, &sev_db, &[], &[], 0)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                warn!("GRAPH STEP WORKER: create_incident failed: {}", e);
                return None;
            }
        }
    };

    let actions_json = Value::Array(proposed_actions.to_vec());
    let investigation_log = json!({
        "source": "investigation_graph",
        "graph_name": trace.graph_name,
        "duration_ms": trace.total_duration_ms,
        "trace": trace,
    });
    let summary = format!(
        "Verdict déterministe via graph '{}' en {}ms ({} étape(s)). \
         Branchement final → outcome = Incident (severity={}).",
        trace.graph_name,
        trace.total_duration_ms,
        trace.steps_visited.len(),
        severity
    );

    if let Err(e) = store
        .update_incident_verdict(
            inc_id,
            // verdict en lowercase pour cohérence avec le reste du
            // code (llm_schemas, llm_parsing, frontend verdictBadge).
            // Le SQL CASE dans update_incident_verdict matche aussi en
            // lowercase. Avec "Confirmed" capital, le frontend affichait
            // "En cours..." au lieu de "Confirme".
            "confirmed",
            0.85,
            &summary,
            &[],
            &actions_json,
            &investigation_log,
            &json!([]),
            Some("graph"),
        )
        .await
    {
        warn!(
            "GRAPH STEP WORKER: update_incident_verdict({}) failed: {}",
            inc_id, e
        );
    }

    info!(
        "GRAPH STEP WORKER: incident #{} created (asset={} graph={} actions={})",
        inc_id, asset, trace.graph_name, action_count
    );
    Some(inc_id)
}
