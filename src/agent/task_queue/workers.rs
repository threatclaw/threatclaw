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
pub fn graph_step_worker_fn(
    library: Arc<GraphLibrary>,
    store: Arc<dyn Database>,
) -> WorkerFn {
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
                persist_outcome(&store, exec_id, &trace).await;
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
    trace: &crate::agent::investigation_graph::ExecutionTrace,
) {
    let (status, archive_reason, incident_id) = match &trace.outcome {
        ExecutionOutcome::Archive { reason } => (
            GraphExecutionStatus::Archived,
            Some(reason.clone()),
            None,
        ),
        ExecutionOutcome::Incident { .. } => {
            // L'incident_id concret sera lié par la couche IE (G1d) qui
            // fait l'INSERT dans incidents en parallèle. Ici on marque
            // le verdict, l'IE updatera incident_id quand prêt.
            (GraphExecutionStatus::Incident, None, None)
        }
        ExecutionOutcome::Inconclusive => (GraphExecutionStatus::Inconclusive, None, None),
        ExecutionOutcome::PendingAsync { .. } => {
            // Un graph G1a ne devrait pas finir en PendingAsync ici (on
            // exécute synchrone). Si ça arrive c'est un step async qu'on
            // n'a pas encore wired — on garde running, un retry le
            // reprendra.
            return;
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
