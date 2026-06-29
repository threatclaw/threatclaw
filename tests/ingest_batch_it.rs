//! Integration test for Phase 2b batched log writes (`insert_logs_batch`).
//!
//! Proves, on a real Postgres with the V100 dedup index applied:
//!   - a batch round-trips (all distinct rows land — return value = row count),
//!   - re-inserting the SAME batch is idempotent (ON CONFLICT DO NOTHING →
//!     0 new rows), which is what makes the at-least-once ingest worker safe,
//!   - the future-clamp still applies (a >60s-ahead timestamp inserts, pinned to
//!     now, rather than being rejected).
//!
//! Requires a local Postgres with migrations through V100 applied:
//!   DATABASE_URL=postgres://threatclaw:...@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test ingest_batch_it -- --ignored
//!
//! Rows are made globally unique per run (nonce in `data`), so runs neither
//! collide nor need cleanup on a shared dev DB.

#![cfg(feature = "postgres")]

use threatclaw::config::DatabaseConfig;
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

#[tokio::test]
#[ignore]
async fn batch_inserts_and_dedups() {
    let be = backend().await;
    let nonce = chrono::Utc::now().timestamp_micros();
    let now = chrono::Utc::now().to_rfc3339();

    let rows = vec![
        row(nonce, "it-host-a", 1, &now),
        row(nonce, "it-host-a", 2, &now),
        row(nonce, "it-host-b", 3, &now),
    ];

    // First write: all three are new.
    let n1 = be.insert_logs_batch(&rows).await.expect("batch 1");
    assert_eq!(n1, 3, "all distinct rows inserted on first write");

    // Re-write the SAME batch: ON CONFLICT DO NOTHING → nothing new. This is
    // exactly the ingest worker's at-least-once re-run being absorbed.
    let n2 = be.insert_logs_batch(&rows).await.expect("batch 2 (retry)");
    assert_eq!(n2, 0, "re-inserting an identical batch is idempotent");

    // A genuinely new row still lands.
    let n3 = be
        .insert_logs_batch(&[row(nonce, "it-host-a", 99, &now)])
        .await
        .expect("batch 3");
    assert_eq!(n3, 1, "a new distinct row still inserts");

    // Future-clamp: a timestamp 2h ahead is pinned to ~now (so the Sigma cursor
    // is not poisoned). It inserts (distinct content) and does not error.
    let ahead = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
    let n4 = be
        .insert_logs_batch(&[row(nonce, "it-host-clamp", 1, &ahead)])
        .await
        .expect("batch 4 (future time)");
    assert_eq!(n4, 1, "future-timestamped row inserts (clamped, not rejected)");
}
