//! Ingest worker pool (Phase 2a).
//!
//! Spawns N workers at startup. Each worker atomically claims a batch of queued
//! webhook payloads from `ingest_queue` (`SELECT … FOR UPDATE SKIP LOCKED` so
//! workers don't trample each other), runs the EXISTING ingestion pipeline
//! (`process_webhook_trusted` — parsers + Sigma + insert_log, unchanged) for
//! each payload OFF the HTTP request thread, then deletes the processed rows.
//!
//! This decouples the webhook's HTTP response from the DB work: a burst of
//! events no longer blocks (and so no longer times out) the request, which
//! killed the retry→collapse loop on slow links / under flood.
//!
//! Configuration:
//!   - `TC_INGEST_WORKERS` env var, default 4
//!   - `BATCH` payloads claimed per poll; `IDLE_BACKOFF_MS` when the queue is empty.

use crate::db::Database;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

/// Payloads claimed per poll. Each payload may itself hold many events; the
/// per-row insert inside process_webhook_trusted is the throughput ceiling until
/// Phase 2b batches the final writes — keep this modest so a worker commits its
/// deletes promptly and the queue stays shallow.
const BATCH: i64 = 200;
const IDLE_BACKOFF_MS: u64 = 200;

/// Spawn the ingest worker pool. Idempotent guard is the caller's responsibility
/// (mirrors spawn_scan_workers).
pub fn spawn_ingest_workers(store: Arc<dyn Database>) {
    let n = std::env::var("TC_INGEST_WORKERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(4);
    for i in 0..n {
        let s = store.clone();
        tokio::spawn(async move { run_ingest_worker(format!("ingest-w{i}"), s).await });
    }
    tracing::info!("INGEST: spawned {n} ingest workers");
}

async fn run_ingest_worker(worker_id: String, store: Arc<dyn Database>) {
    loop {
        match store.claim_ingest_batch(&worker_id, BATCH).await {
            Ok(rows) if !rows.is_empty() => {
                let mut done: Vec<i64> = Vec::with_capacity(rows.len());
                for row in &rows {
                    // Token was already verified on the hot path before enqueue,
                    // so call the trusted pipeline directly (no token re-check,
                    // and no plaintext token persisted in the queue).
                    let _ = crate::connectors::webhook_ingest::process_webhook_trusted(
                        store.as_ref(),
                        &row.source,
                        &row.body,
                    )
                    .await;
                    done.push(row.id);
                }
                crate::ingest::metrics::add_processed(done.len() as u64);
                // Delete what we processed. A crash between process and delete at
                // worst re-runs a payload next claim; server-side dedup
                // (burst-dedup / Phase 2b ON CONFLICT) absorbs the duplicate.
                if let Err(e) = store.delete_ingest(&done).await {
                    tracing::warn!("INGEST worker {worker_id}: delete error: {e}");
                }
            }
            Ok(_) => sleep(Duration::from_millis(IDLE_BACKOFF_MS)).await,
            Err(e) => {
                tracing::warn!("INGEST worker {worker_id}: claim error: {e}");
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
