//! Task queue + worker pools — Phase G1b.
//!
//! L'`investigation_graph` runtime (G1a) émet `PendingAsync` quand il
//! rencontre un step async (skill call, LLM call, sub-graph). Cette queue
//! prend le relais : push → workers pull → résultat → resume.
//!
//! Bénéfices :
//! - **Crash-resistant** : status persiste en Postgres, recovery au boot.
//! - **Scaling borné** : Semaphore par kind (LLM = 1-2, skills = 50,
//!   graphs = 20) évite de saturer Ollama / les API tierces.
//! - **Backpressure** : si la queue dépasse un seuil critique on refuse
//!   les nouveaux graphs gracieusement (dégrade au lieu de crasher).
//!
//! Voir `migrations/V62__task_queue.sql` et
//! `internal/PHASE_G_INVESTIGATION_GRAPHS.md` pour le contexte.

pub mod backpressure;
pub mod dispatcher;
pub mod pool;
pub mod store;
pub mod supervisor;
pub mod workers;

pub use backpressure::{BackpressureCheck, OverloadDecision, QueueDepths};
pub use dispatcher::{library, set_library, try_enqueue_graph_for_dossier};
pub use pool::{WorkerFn, WorkerPool, WorkerPoolConfig};
pub use store::{
    GraphExecutionRecord, GraphExecutionStatus, NewGraphExecution, NewTask, Task, TaskKind,
    TaskStatus,
};
pub use supervisor::{recover_on_boot, spawn_pool_supervisors};
pub use workers::{graph_step_worker_fn, llm_worker_fn, skill_worker_fn};

use std::path::Path;
use std::sync::Arc;

use crate::agent::investigation_graph::GraphLibrary;
use crate::db::Database;

/// Helper d'amorçage : recovery + spawn des 3 supervisors (LLM, skills,
/// graph_step) avec leurs workers concrets. À appeler une fois au boot,
/// après les migrations.
///
/// `graphs_dir` pointe vers le dossier des YAML CACAO v2 (typiquement
/// `graphs/sigma/` du repo). Si le dossier n'existe pas ou si le chargement
/// échoue, on continue sans library (graph_step worker sera fonctionnel
/// mais ne trouvera aucun graph — fallback ReAct dans intelligence_engine
/// continue d'être utilisé).
pub async fn boot(store: Arc<dyn Database>, graphs_dir: &Path) {
    recover_on_boot(&store).await;

    let library = match GraphLibrary::load_from_dir(graphs_dir) {
        Ok(lib) => {
            tracing::info!(
                "AUTO-START: GraphLibrary chargée — {} graphs depuis {}",
                lib.len(),
                graphs_dir.display()
            );
            Arc::new(lib)
        }
        Err(e) => {
            tracing::warn!(
                "AUTO-START: GraphLibrary non chargée ({}), fallback ReAct only — {}",
                graphs_dir.display(),
                e
            );
            Arc::new(GraphLibrary::empty())
        }
    };
    // Expose la library via le static global pour que le dispatcher
    // (intelligence_engine) puisse la consulter sans dépendre du WorkerPool.
    set_library(library.clone());

    let llm_pool = Arc::new(WorkerPool::new(
        WorkerPoolConfig::for_llm(),
        llm_worker_fn(),
    ));
    let skill_pool = Arc::new(WorkerPool::new(
        WorkerPoolConfig::for_skills(),
        skill_worker_fn(store.clone()),
    ));
    let graph_pool = Arc::new(WorkerPool::new(
        WorkerPoolConfig::for_graph_steps(),
        graph_step_worker_fn(library, store.clone()),
    ));

    spawn_pool_supervisors(store, vec![llm_pool, skill_pool, graph_pool]);
    tracing::info!("AUTO-START: Investigation Graph task queue + 3 worker pools online");
}
