//! Online builder for the `logs` content-dedup index (Phase 2b).
//!
//! The agent/webhook ingest path is at-least-once: the async ingest worker
//! re-runs a claimed payload after a crash, so it relies on a server-side
//! `ON CONFLICT DO NOTHING` to stay idempotent. The conflict target is a UNIQUE
//! index on the content key `(time, hostname, tag, md5(data::text))`.
//!
//! Two things make that index unsafe to create in a blocking startup migration:
//!
//!   1. On a populated install the build (dedup of historical re-run duplicates
//!      plus the index over the whole `logs` hypertable, decompressing chunks as
//!      it goes) takes minutes — it would freeze the core's startup, and much
//!      longer on a large install.
//!   2. The index MUST be partial — `WHERE collector IS NULL`. Only the
//!      agent/webhook path writes NULL-collector rows; the fluent-bit syslog
//!      trigger writes `collector = 'fluent-bit'`, where two identical lines at
//!      the same second are TWO real events (e.g. repeated auth failures), not a
//!      duplicate. A global unique index would silently drop genuine syslog
//!      events — and a one-shot historical dedup would delete them outright.
//!
//! So the index is built here instead: spawned non-blocking at startup, the core
//! serves immediately while this dedups NULL-collector rows in gentle batches and
//! then creates the partial index (plain `CREATE INDEX` — TimescaleDB forbids
//! `CONCURRENTLY` on a hypertable; it builds per-chunk and is fast once the dups
//! are gone). Until the index exists the batched/single writers fall back to a
//! plain insert (see `insert_logs_batch`
//! and `insert_log`), so ingestion is never blocked on the one-time build.
//! Idempotent: a fast path returns at once when the index already exists, so this
//! is cheap on every subsequent boot, and a fresh (empty) install builds it in
//! milliseconds.

use std::time::Duration;

use deadpool_postgres::Pool;
use tokio_postgres::error::SqlState;

/// Name of the partial dedup index. Shared with the `ON CONFLICT` arbiter
/// inference in `insert_log` / `insert_logs_batch` (matched by columns +
/// predicate, not by name, but kept in one place for clarity).
pub const INDEX_NAME: &str = "idx_logs_dedup";

/// Predicate of the partial index — only the agent/webhook path (NULL collector)
/// is deduped; the fluent-bit syslog path is left untouched.
const INDEX_PREDICATE: &str = "collector IS NULL";

/// Rows removed per dedup DELETE so each statement stays a small, lock-light
/// transaction even when an old staging box carries hundreds of thousands of
/// re-run duplicates.
const DEDUP_BATCH: i64 = 10_000;

/// Bound on dedup+build rounds. Each round re-dedups then rebuilds; a round is
/// only retried when a racing duplicate (a writer's plain-insert fallback during
/// this window) makes the unique build fail. The dup rate is bounded so this
/// converges in one or two rounds — the cap is just a guard against a pathological
/// hot loop.
const MAX_BUILD_ATTEMPTS: u32 = 6;

/// Outcome of a build pass, for logging.
enum BuildOutcome {
    AlreadyPresent,
    Built { deduped: u64 },
}

/// Entry point — spawn with `tokio::spawn` right after migrations. Only logs;
/// never propagates an error, because a failed build must not take the core
/// down (writers fall back to plain inserts until the index appears).
pub async fn ensure_logs_dedup_index(pool: Pool) {
    match build(&pool).await {
        Ok(BuildOutcome::AlreadyPresent) => {}
        Ok(BuildOutcome::Built { deduped }) => {
            tracing::info!(
                "logs dedup index built online (removed {deduped} historical duplicate rows)"
            );
        }
        Err(e) => {
            tracing::error!(
                "logs dedup index build deferred — ingestion unaffected, writers fall back to \
                 plain insert until a later boot succeeds: {e}"
            );
        }
    }
}

async fn build(pool: &Pool) -> Result<BuildOutcome, String> {
    // Fast path: already there → nothing to do (the common case on every boot
    // after the first, and instant on a fresh empty install once built).
    if index_exists(pool).await? {
        return Ok(BuildOutcome::AlreadyPresent);
    }
    tracing::info!("logs dedup index missing — building online, core stays available");

    // Best-effort: decompress compressed chunks up front so the dedup DELETEs
    // below don't decompress the same Timescale segments over and over. No-op
    // (and harmless) when TimescaleDB isn't installed (dev/CI) or nothing is
    // compressed.
    decompress_logs_chunks_best_effort(pool).await;

    let mut total_deduped: u64 = 0;
    for attempt in 1..=MAX_BUILD_ATTEMPTS {
        total_deduped += dedup_null_collector(pool).await?;

        // Defensive: clear any leftover index from a previous failed attempt so
        // the rebuild starts clean (a failed plain CREATE rolls back, but this
        // also covers an invalid index left by an older CONCURRENTLY build).
        drop_index_best_effort(pool).await;

        let conn = pool.get().await.map_err(|e| e.to_string())?;
        // Plain CREATE INDEX, not CONCURRENTLY: TimescaleDB rejects
        // `CREATE INDEX CONCURRENTLY` on a hypertable ("hypertables do not
        // support concurrent index creation"). It builds per-chunk and, with the
        // duplicates already removed above, is fast (~1.4s on a populated staging
        // box); running here off the startup path keeps it out of boot, and the
        // 42P10 fallback in the writers covers the brief build window.
        let sql = format!(
            "CREATE UNIQUE INDEX IF NOT EXISTS {INDEX_NAME} \
             ON logs (time, hostname, tag, md5(data::text)) WHERE {INDEX_PREDICATE}"
        );
        match conn.execute(sql.as_str(), &[]).await {
            Ok(_) => return Ok(BuildOutcome::Built { deduped: total_deduped }),
            Err(e) if is_unique_violation(&e) => {
                // A new NULL-collector duplicate landed mid-build (a writer's
                // plain-insert fallback during this window). Re-dedup and rebuild.
                tracing::warn!(
                    "logs dedup index hit a racing duplicate (round {attempt}/{MAX_BUILD_ATTEMPTS}), retrying"
                );
                continue;
            }
            Err(e) => return Err(format!("CREATE INDEX CONCURRENTLY: {e}")),
        }
    }
    Err(format!(
        "gave up after {MAX_BUILD_ATTEMPTS} rounds (persistent racing duplicates)"
    ))
}

async fn index_exists(pool: &Pool) -> Result<bool, String> {
    let conn = pool.get().await.map_err(|e| e.to_string())?;
    let row = conn
        .query_one(
            "SELECT count(*) FROM pg_indexes WHERE indexname = $1",
            &[&INDEX_NAME],
        )
        .await
        .map_err(|e| e.to_string())?;
    let n: i64 = row.get(0);
    Ok(n > 0)
}

/// Remove exact NULL-collector duplicates (same time/hostname/tag/content),
/// keeping the lowest `id` of each group, in `DEDUP_BATCH`-sized transactions.
/// Uses `row_number()` (a single sort) rather than a self-join on `data` — a
/// jsonb-equality self-join over the whole table is what made the original
/// blocking migration take minutes.
async fn dedup_null_collector(pool: &Pool) -> Result<u64, String> {
    let mut removed: u64 = 0;
    loop {
        let conn = pool.get().await.map_err(|e| e.to_string())?;
        let n = conn
            .execute(
                "WITH d AS ( \
                     SELECT id FROM ( \
                         SELECT id, row_number() OVER ( \
                             PARTITION BY time, hostname, tag, md5(data::text) ORDER BY id \
                         ) AS rn \
                         FROM logs WHERE collector IS NULL \
                     ) t WHERE rn > 1 LIMIT $1 \
                 ) DELETE FROM logs WHERE id IN (SELECT id FROM d)",
                &[&DEDUP_BATCH],
            )
            .await
            .map_err(|e| e.to_string())?;
        removed += n;
        // Fewer than a full batch removed → the duplicate set is exhausted.
        if (n as i64) < DEDUP_BATCH {
            break;
        }
        // Be gentle: yield between batches so this background sweep never
        // monopolises the pool or bloats WAL on a busy box.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(removed)
}

/// Decompress every compressed `logs` chunk, best-effort. Guarded so it is a
/// silent no-op when TimescaleDB is absent (dev/CI plain table) or nothing is
/// compressed; any error is swallowed because decompression is an optimisation,
/// not a correctness requirement.
async fn decompress_logs_chunks_best_effort(pool: &Pool) {
    let Ok(conn) = pool.get().await else {
        return;
    };
    let sql = "DO $$ \
               BEGIN \
                 IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN \
                   PERFORM public.decompress_chunk(c, true) FROM public.show_chunks('logs') c; \
                 END IF; \
               EXCEPTION WHEN others THEN NULL; \
               END $$;";
    if let Err(e) = conn.execute(sql, &[]).await {
        tracing::debug!("logs chunk decompress skipped: {e}");
    }
}

async fn drop_index_best_effort(pool: &Pool) {
    if let Ok(conn) = pool.get().await {
        let _ = conn
            .execute(&format!("DROP INDEX IF EXISTS {INDEX_NAME}"), &[])
            .await;
    }
}

fn is_unique_violation(e: &tokio_postgres::Error) -> bool {
    e.as_db_error()
        .map(|d| d.code() == &SqlState::UNIQUE_VIOLATION)
        .unwrap_or(false)
}
