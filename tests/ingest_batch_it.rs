//! Integration test for Phase 2b batched log writes (`insert_logs_batch`) and
//! the online partial dedup index (`logs_dedup`).
//!
//! Proves, on a real Postgres:
//!   - the online builder creates the partial dedup index `idx_logs_dedup`,
//!   - a batch round-trips (all distinct rows land — return value = row count),
//!   - re-inserting the SAME batch is idempotent (ON CONFLICT DO NOTHING →
//!     0 new rows), which is what makes the at-least-once ingest worker safe,
//!   - the future-clamp still applies (a >60s-ahead timestamp inserts, pinned to
//!     now, rather than being rejected),
//!   - REGRESSION: two identical `collector = 'fluent-bit'` (syslog) rows BOTH
//!     survive — the partial index `WHERE collector IS NULL` must never dedup
//!     genuine repeated syslog events,
//!   - before the index exists the writer falls back to a plain insert (42P10),
//!     so ingestion is never blocked on the one-time build.
//!
//! Requires a local Postgres (TimescaleDB optional — the builder degrades to a
//! plain table). No migration needs the index; the test builds it itself:
//!   DATABASE_URL=postgres://threatclaw:...@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test ingest_batch_it -- --ignored
//!
//! Rows are made globally unique per run (nonce in `data`), so runs neither
//! collide nor need cleanup on a shared dev DB. Single sequential test on
//! purpose: it drops/rebuilds the shared index, which must not race a sibling.

#![cfg(feature = "postgres")]

use threatclaw::config::DatabaseConfig;
use threatclaw::db::logs_dedup::{self, INDEX_NAME};
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::threatclaw_store::{LogRow, ThreatClawStore};

async fn backend() -> PgBackend {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw".into());
    let cfg = DatabaseConfig {
        backend: threatclaw::config::DatabaseBackend::Postgres,
        url: secrecy::SecretString::new(url.into()),
        pool_size: 2,
        ssl_mode: threatclaw::config::SslMode::Disable,
        libsql_path: None,
        libsql_url: None,
        libsql_auth_token: None,
    };
    PgBackend::new(&cfg).await.expect("pg backend")
}

fn row(nonce: i64, host: &str, n: i64, time: &str) -> LogRow {
    LogRow {
        tag: "ittest.batch".into(),
        hostname: host.into(),
        // nonce makes every run's rows globally unique against the dedup index.
        data: serde_json::json!({ "run": nonce, "n": n }),
        time: time.into(),
    }
}

async fn index_exists(be: &PgBackend) -> bool {
    let conn = be.pool().get().await.expect("conn");
    let n: i64 = conn
        .query_one(
            "SELECT count(*) FROM pg_indexes WHERE indexname = $1",
            &[&INDEX_NAME],
        )
        .await
        .expect("query")
        .get(0);
    n > 0
}

#[tokio::test]
#[ignore]
async fn batch_dedups_clamps_and_spares_syslog() {
    let be = backend().await;
    let nonce = chrono::Utc::now().timestamp_micros();
    let now = chrono::Utc::now().to_rfc3339();

    // ── Online builder creates the partial dedup index ──
    logs_dedup::ensure_logs_dedup_index(be.pool()).await;
    assert!(index_exists(&be).await, "online builder created idx_logs_dedup");

    // ── Idempotency (the at-least-once worker's safety net) ──
    let rows = vec![
        row(nonce, "it-host-a", 1, &now),
        row(nonce, "it-host-a", 2, &now),
        row(nonce, "it-host-b", 3, &now),
    ];
    let n1 = be.insert_logs_batch(&rows).await.expect("batch 1");
    assert_eq!(n1, 3, "all distinct rows inserted on first write");

    let n2 = be.insert_logs_batch(&rows).await.expect("batch 2 (retry)");
    assert_eq!(n2, 0, "re-inserting an identical batch is idempotent");

    let n3 = be
        .insert_logs_batch(&[row(nonce, "it-host-a", 99, &now)])
        .await
        .expect("batch 3");
    assert_eq!(n3, 1, "a new distinct row still inserts");

    // ── Future-clamp: a 2h-ahead timestamp is pinned to ~now, not rejected ──
    let ahead = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
    let n4 = be
        .insert_logs_batch(&[row(nonce, "it-host-clamp", 1, &ahead)])
        .await
        .expect("batch 4 (future time)");
    assert_eq!(n4, 1, "future-timestamped row inserts (clamped, not rejected)");

    // ── REGRESSION: identical syslog (collector='fluent-bit') rows are NOT
    // deduped. The partial index covers only collector IS NULL, so two real
    // repeated syslog lines (e.g. two auth failures in the same second) both
    // survive. Insert the same content twice via the syslog shape and count. ──
    {
        let conn = be.pool().get().await.expect("conn");
        let syslog_data = serde_json::json!({ "syslogrun": nonce, "msg": "Failed password" });
        for _ in 0..2 {
            conn.execute(
                "INSERT INTO logs (tag, hostname, data, time, collector) \
                 VALUES ('sshd', 'it-syslog', $1, now(), 'fluent-bit')",
                &[&syslog_data],
            )
            .await
            .expect("syslog insert must not be blocked by the partial index");
        }
        let kept: i64 = conn
            .query_one(
                "SELECT count(*) FROM logs \
                 WHERE collector = 'fluent-bit' AND (data->>'syslogrun')::bigint = $1",
                &[&nonce],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(kept, 2, "identical syslog events are preserved, never deduped");
    }

    // ── Fallback: before the index exists the writer must still ingest (42P10
    // → plain insert). Drop the index, insert, expect success, then rebuild so
    // the dev DB is left in a clean (indexed) state for the next run. ──
    {
        let conn = be.pool().get().await.expect("conn");
        conn.execute(&format!("DROP INDEX IF EXISTS {INDEX_NAME}"), &[])
            .await
            .expect("drop index");
    }
    assert!(!index_exists(&be).await, "index dropped for the fallback case");
    let n5 = be
        .insert_logs_batch(&[row(nonce, "it-host-fallback", 1, &now)])
        .await
        .expect("batch inserts via plain-insert fallback when the index is absent");
    assert_eq!(n5, 1, "writer falls back to a plain insert, ingestion not blocked");

    logs_dedup::ensure_logs_dedup_index(be.pool()).await;
    assert!(index_exists(&be).await, "builder rebuilds the index after the fallback window");
}

/// T7: the batched fluent-bit drainer moves staged syslog rows into `logs` with
/// the SAME field mapping the old per-row trigger used (hostname from
/// data.hostname → data.host → tag, collector defaulting to 'fluent-bit'), and
/// empties the staging table.
#[tokio::test]
#[ignore]
async fn fluentbit_drainer_moves_with_mapping() {
    let be = backend().await;
    let nonce = chrono::Utc::now().timestamp_micros();
    let conn = be.pool().get().await.expect("conn");

    // Defensive: ensure the per-row trigger is gone (migration V100) so staged
    // rows wait for the batched drainer rather than auto-moving on insert.
    conn.execute(
        "DROP TRIGGER IF EXISTS trg_fluentbit_ingest ON logs_fluentbit",
        &[],
    )
    .await
    .expect("drop trigger");

    // Stage two syslog rows: one carries hostname, one only `host` (fallback).
    let d1 = serde_json::json!({ "hostname": "fb-host-1", "fbrun": nonce, "msg": "a" });
    let d2 = serde_json::json!({ "host": "fb-host-2", "fbrun": nonce, "msg": "b" });
    for d in [&d1, &d2] {
        conn.execute(
            "INSERT INTO logs_fluentbit (tag, time, data) VALUES ('sshd.auth.host', now(), $1)",
            &[d],
        )
        .await
        .expect("stage row");
    }

    let moved = be.drain_fluentbit_batch(1000).await.expect("drain");
    assert!(moved >= 2, "both staged rows drained (got {moved})");

    // Landed in logs as syslog (collector='fluent-bit', so OUTSIDE the dedup
    // index) with the mapped hostnames.
    let rows = conn
        .query(
            "SELECT hostname FROM logs WHERE collector = 'fluent-bit' \
             AND (data->>'fbrun')::bigint = $1 ORDER BY hostname",
            &[&nonce],
        )
        .await
        .expect("query logs");
    assert_eq!(rows.len(), 2, "two syslog rows landed in logs");
    let h0: Option<String> = rows[0].get(0);
    let h1: Option<String> = rows[1].get(0);
    assert_eq!(h0.as_deref(), Some("fb-host-1"), "hostname from data.hostname");
    assert_eq!(h1.as_deref(), Some("fb-host-2"), "hostname falls back to data.host");

    let staged: i64 = conn
        .query_one(
            "SELECT count(*) FROM logs_fluentbit WHERE (data->>'fbrun')::bigint = $1",
            &[&nonce],
        )
        .await
        .expect("count staging")
        .get(0);
    assert_eq!(staged, 0, "staging table drained for this run");

    let _ = conn
        .execute(
            "DELETE FROM logs WHERE (data->>'fbrun')::bigint = $1",
            &[&nonce],
        )
        .await;
}
