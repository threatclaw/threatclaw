//! Supervisors de pool — boucle de pull / dispatch / persiste.
//!
//! Un supervisor est associé à un `WorkerPool` (1 par kind). Il tourne
//! dans une tokio task forever, avec ce loop :
//!
//! 1. acquérir un permit du Semaphore (max_concurrency)
//! 2. claim_next_task(kind) — atomique en DB
//! 3. soit pas de task → drop permit + idle sleep
//!    soit task → spawn une dispatch task qui appelle `worker_fn`,
//!    persiste le résultat (complete_task / fail_task), puis relâche
//!    le permit
//!
//! Le permit est tenu pendant toute la durée d'exécution de la task,
//! garantissant que la concurrence simultanée ≤ `max_concurrency`.

use std::sync::Arc;

use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::pool::{WorkerOutcome, WorkerPool, dispatch_one};
use crate::db::Database;

/// Spawn N supervisors (un par pool fourni). Chaque supervisor tourne
/// dans une tokio task indépendante. À appeler une fois au boot, après
/// que la DB ait migrate.
pub fn spawn_pool_supervisors(store: Arc<dyn Database>, pools: Vec<Arc<WorkerPool>>) {
    for pool in pools {
        let store = store.clone();
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            run_supervisor(store, pool_clone).await;
        });
    }
}

async fn run_supervisor(store: Arc<dyn Database>, pool: Arc<WorkerPool>) {
    let kind = pool.config().kind;
    let prefix = pool.config().worker_id_prefix.clone();
    let idle = pool.config().idle_poll_interval;
    let timeout = pool.config().task_timeout;
    info!(
        "TASK QUEUE SUPERVISOR: started kind={:?} max_concurrency={}",
        kind,
        pool.config().max_concurrency
    );

    // Compteur monotone pour fabriquer un worker_id unique par dispatch.
    let mut seq: u64 = 0;

    loop {
        // 1. Acquérir un permit. Si tous les permits sont pris, on attend
        //    qu'un dispatch finisse — pas de busy loop.
        let permit = match pool.semaphore_clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                error!("TASK QUEUE SUPERVISOR: semaphore closed, exiting: {}", e);
                return;
            }
        };

        // 2. Claim next task (atomique, FOR UPDATE SKIP LOCKED côté SQL).
        seq = seq.wrapping_add(1);
        let worker_id = format!("{}-{}", prefix, seq);

        match store.claim_next_task(kind, &worker_id).await {
            Ok(Some(task)) => {
                let task_id = task.id;
                debug!(
                    "SUPERVISOR {}: claimed task {} (kind={:?})",
                    worker_id, task_id, kind
                );

                let store_disp = store.clone();
                let worker_fn = pool.worker_fn();
                tokio::spawn(async move {
                    let outcome = dispatch_one(&worker_fn, task, timeout).await;
                    match outcome {
                        WorkerOutcome::Done(v) => {
                            if let Err(e) = store_disp.complete_task(task_id, &v).await {
                                error!("SUPERVISOR: complete_task({}) failed: {}", task_id, e);
                            }
                        }
                        WorkerOutcome::Failed(msg) => {
                            if let Err(e) = store_disp.fail_task(task_id, &msg).await {
                                error!("SUPERVISOR: fail_task({}) failed: {}", task_id, e);
                            }
                        }
                    }
                    drop(permit); // libère un permit
                });
            }
            Ok(None) => {
                // Queue vide pour ce kind. Drop le permit et idle.
                drop(permit);
                sleep(idle).await;
            }
            Err(e) => {
                error!("SUPERVISOR {}: claim_next_task error: {}", worker_id, e);
                drop(permit);
                sleep(idle).await;
            }
        }
    }
}

/// Recovery au boot : remet en `queued` les tasks `running` plus vieilles
/// que `STALE_TASK_THRESHOLD_SECS` secondes (5 min par défaut).
/// À appeler une fois, après les migrations, avant `spawn_pool_supervisors`.
pub async fn recover_on_boot(store: &Arc<dyn Database>) {
    match store
        .recover_stale_tasks(super::store::STALE_TASK_THRESHOLD_SECS)
        .await
    {
        Ok(0) => {
            info!("TASK QUEUE BOOT: no stale tasks to recover");
        }
        Ok(n) => {
            warn!(
                "TASK QUEUE BOOT: recovered {} stale tasks (worker died without cleanup)",
                n
            );
        }
        Err(e) => {
            error!("TASK QUEUE BOOT: recover_stale_tasks failed: {}", e);
        }
    }
}
