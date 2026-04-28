//! Worker pool générique avec Semaphore — Phase G1b.
//!
//! Un `WorkerPool` est paramétré par :
//! - un `kind` de tasks à traiter (skill_call / llm_call / graph_step)
//! - une concurrence max via `Semaphore`
//! - une fonction `WorkerFn` qui exécute une `Task` et renvoie un résultat
//!
//! Le pool boucle :
//! 1. Acquiert un permit du Semaphore
//! 2. Pull une task `queued` de son kind via `claim_next_task`
//! 3. Spawn une tokio task qui exécute la `WorkerFn`
//! 4. Selon le résultat : `complete_task` ou `fail_task`
//!
//! En G1b on fournit l'infrastructure ; les `WorkerFn` concrètes pour
//! LLM / skills sont câblées dans des modules séparés (G1c) — l'idée
//! c'est de keep le pool générique et testable en isolation.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::store::{Task, TaskKind};

/// Erreur d'exécution d'un worker. Le pool log + bumpe `attempts` ;
/// après `max_attempts` la task passe en `error`.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("worker execution failed: {0}")]
    Failed(String),
    #[error("worker timeout")]
    Timeout,
}

/// Signature des fonctions d'exécution. Async + Send + Sync car appelées
/// depuis tokio::spawn.
pub type WorkerFn = Arc<
    dyn Fn(Task) -> Pin<Box<dyn Future<Output = Result<serde_json::Value, WorkerError>> + Send>>
        + Send
        + Sync,
>;

#[derive(Debug, Clone)]
pub struct WorkerPoolConfig {
    pub kind: TaskKind,
    /// Concurrence max simultanée pour ce kind. LLM = 1-2, skills = 50,
    /// graphs = 20.
    pub max_concurrency: usize,
    /// Identifiant lisible du worker (`worker-llm-1`, …) — propagé en DB.
    pub worker_id_prefix: String,
    /// Délai entre deux tentatives de pull quand la queue est vide
    /// (évite de hammerer la DB).
    pub idle_poll_interval: Duration,
    /// Timeout d'une exécution individuelle (au-delà → WorkerError::Timeout
    /// + retry si attempts < max_attempts).
    pub task_timeout: Duration,
}

impl WorkerPoolConfig {
    pub fn for_llm() -> Self {
        Self {
            kind: TaskKind::LlmCall,
            max_concurrency: 1,
            worker_id_prefix: "worker-llm".into(),
            idle_poll_interval: Duration::from_millis(500),
            task_timeout: Duration::from_secs(1500), // 25 min, aligné CPU-only Ollama
        }
    }

    pub fn for_skills() -> Self {
        Self {
            kind: TaskKind::SkillCall,
            max_concurrency: 50,
            worker_id_prefix: "worker-skill".into(),
            idle_poll_interval: Duration::from_millis(200),
            task_timeout: Duration::from_secs(60),
        }
    }

    pub fn for_graph_steps() -> Self {
        Self {
            kind: TaskKind::GraphStep,
            max_concurrency: 20,
            worker_id_prefix: "worker-graph".into(),
            idle_poll_interval: Duration::from_millis(200),
            task_timeout: Duration::from_secs(30),
        }
    }
}

/// Le pool. Lance `max_concurrency` workers en parallèle qui pullent
/// chacun à leur rythme via le `Semaphore`.
pub struct WorkerPool {
    config: WorkerPoolConfig,
    semaphore: Arc<Semaphore>,
    worker_fn: WorkerFn,
}

impl WorkerPool {
    pub fn new(config: WorkerPoolConfig, worker_fn: WorkerFn) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrency));
        Self {
            config,
            semaphore,
            worker_fn,
        }
    }

    pub fn config(&self) -> &WorkerPoolConfig {
        &self.config
    }

    /// Permits actuellement disponibles (utile pour les métriques /
    /// l'onglet `/admin/queue-state`).
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Clone du Semaphore pour les supervisors qui veulent acquire des
    /// permits owned (relâchés à la fin du dispatch).
    pub fn semaphore_clone(&self) -> Arc<Semaphore> {
        self.semaphore.clone()
    }

    /// Clone du worker_fn — partagé entre dispatch tasks.
    pub fn worker_fn(&self) -> WorkerFn {
        self.worker_fn.clone()
    }
}

/// Décrit le résultat d'une exécution unitaire. Le superviseur du pool
/// le passe au store pour update (complete / fail).
#[derive(Debug)]
pub enum WorkerOutcome {
    Done(serde_json::Value),
    Failed(String),
}

/// Helper qui exécute la `worker_fn` avec timeout + capture des paniques.
/// Ne touche pas à la DB — la traduction en complete_task/fail_task est
/// faite par le caller (via le store).
pub async fn dispatch_one(
    worker_fn: &WorkerFn,
    task: Task,
    timeout: Duration,
) -> WorkerOutcome {
    let task_id = task.id;
    let task_kind = task.kind;
    debug!("WORKER: dispatching task {} (kind={:?})", task_id, task_kind);

    let fut = (worker_fn)(task);
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => {
            info!("WORKER: task {} completed", task_id);
            WorkerOutcome::Done(v)
        }
        Ok(Err(WorkerError::Failed(msg))) => {
            warn!("WORKER: task {} failed: {}", task_id, msg);
            WorkerOutcome::Failed(msg)
        }
        Ok(Err(WorkerError::Timeout)) => {
            warn!("WORKER: task {} self-timeout", task_id);
            WorkerOutcome::Failed("self-reported timeout".into())
        }
        Err(_) => {
            error!(
                "WORKER: task {} hit pool timeout ({}s)",
                task_id,
                timeout.as_secs()
            );
            WorkerOutcome::Failed(format!("pool timeout {}s", timeout.as_secs()))
        }
    }
}

/// Délai d'attente quand le store renvoie "rien à pull". Évite le busy-loop.
/// Wrappé dans une fonction pour pouvoir mocker en test.
pub async fn idle_sleep(d: Duration) {
    sleep(d).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn fake_task() -> Task {
        Task {
            id: 1,
            kind: TaskKind::SkillCall,
            graph_run_id: None,
            payload: json!({"skill": "ip_reputation"}),
            status: super::super::store::TaskStatus::Running,
            priority: 5,
            attempts: 1,
            max_attempts: 3,
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: None,
            worker_id: Some("worker-skill-1".into()),
            result: None,
            error: None,
        }
    }

    #[tokio::test]
    async fn dispatch_returns_done_on_success() {
        let f: WorkerFn =
            Arc::new(|_t| Box::pin(async move { Ok(json!({"verdict": "clean"})) }));
        let outcome = dispatch_one(&f, fake_task(), Duration::from_secs(5)).await;
        match outcome {
            WorkerOutcome::Done(v) => assert_eq!(v["verdict"], "clean"),
            _ => panic!("expected Done"),
        }
    }

    #[tokio::test]
    async fn dispatch_returns_failed_on_error() {
        let f: WorkerFn =
            Arc::new(|_t| Box::pin(async move { Err(WorkerError::Failed("boom".into())) }));
        let outcome = dispatch_one(&f, fake_task(), Duration::from_secs(5)).await;
        assert!(matches!(outcome, WorkerOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn dispatch_returns_failed_on_pool_timeout() {
        let f: WorkerFn = Arc::new(|_t| {
            Box::pin(async move {
                sleep(Duration::from_secs(10)).await;
                Ok(json!({}))
            })
        });
        let outcome = dispatch_one(&f, fake_task(), Duration::from_millis(50)).await;
        match outcome {
            WorkerOutcome::Failed(msg) => assert!(msg.contains("timeout")),
            _ => panic!("expected Failed(timeout)"),
        }
    }

    #[test]
    fn config_presets_have_sensible_concurrency() {
        assert_eq!(WorkerPoolConfig::for_llm().max_concurrency, 1);
        assert_eq!(WorkerPoolConfig::for_skills().max_concurrency, 50);
        assert_eq!(WorkerPoolConfig::for_graph_steps().max_concurrency, 20);
    }
}
