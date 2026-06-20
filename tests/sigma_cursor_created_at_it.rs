//! Integration test: the Sigma scan cursor advances on `created_at` (DB insert
//! time), NOT the event `time`.
//!
//! Regression for the detection-chain audit 2026-06-20 clock-robustness fix
//! (#10). The old cursor keyed on `time`, which is source-controlled: an
//! out-of-order / backfilled event (older `time`, inserted later) was scanned
//! once, advanced the cursor to "now", and then any subsequent row with an
//! older `time` fell *behind* the cursor and was never seen — a silent
//! detection blind window. Keying on the monotonic `created_at` removes that
//! whole failure class.
//!
//! Real Postgres:
//!   DATABASE_URL=postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test sigma_cursor_created_at_it -- --ignored
#![cfg(feature = "postgres")]

use threatclaw::config::{DatabaseBackend, DatabaseConfig, SslMode};
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::threatclaw_store::ThreatClawStore;

async fn backend() -> PgBackend {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw".into());
    let cfg = DatabaseConfig {
        backend: DatabaseBackend::Postgres,
        url: secrecy::SecretString::new(url.into()),
        pool_size: 2,
        ssl_mode: SslMode::Disable,
        libsql_path: None,
        libsql_url: None,
        libsql_auth_token: None,
    };
    PgBackend::new(&cfg).await.expect("pg backend")
}

const HOST: &str = "test-cursor-created-at";

#[tokio::test]
#[ignore = "requires local Postgres with migrations applied"]
async fn cursor_advances_on_created_at_not_event_time() {
    let be = backend().await;
    let client = be.pool().get().await.expect("pool client");

    let purge = "DELETE FROM logs WHERE hostname = $1";
    client.execute(purge, &[&HOST]).await.expect("pre-clean");

    // Row A — normal event, inserted FIRST (created_at earlier).
    let row_a = client
        .query_one(
            "INSERT INTO logs (tag, hostname, data, time, created_at) \
             VALUES ('test.cursor', $1, '{}'::jsonb, now(), now() - INTERVAL '10 seconds') \
             RETURNING id, created_at",
            &[&HOST],
        )
        .await
        .expect("insert A");
    let a_id: i64 = row_a.get(0);
    let a_created: chrono::DateTime<chrono::Utc> = row_a.get(1);

    // Row B — OLDER event time (1h in the past, like a backfill) but inserted
    // LATER, so its created_at is greater than A's. Under a `time`-keyed cursor
    // positioned at A, B would be invisible; under a `created_at`-keyed cursor
    // it is correctly still ahead of the cursor.
    let row_b = client
        .query_one(
            "INSERT INTO logs (tag, hostname, data, time, created_at) \
             VALUES ('test.cursor', $1, '{}'::jsonb, now() - INTERVAL '1 hour', now()) \
             RETURNING id, created_at",
            &[&HOST],
        )
        .await
        .expect("insert B");
    let b_id: i64 = row_b.get(0);

    // 1. Fresh scan from the floor returns both, ordered by created_at ASC, so
    //    A precedes B even though B's event time is an hour older.
    let logs = be
        .query_logs_after_cursor(None, 0, 120, 5000)
        .await
        .expect("scan from floor");
    let ours: Vec<i64> = logs
        .iter()
        .filter(|l| l.hostname.as_deref() == Some(HOST))
        .map(|l| l.id)
        .collect();
    assert_eq!(
        ours,
        vec![a_id, b_id],
        "rows must be ordered by created_at (A then B), not by event time"
    );

    // 2. The returned created_at must be RFC 3339 so the cursor round-trips
    //    through load/save_sigma_cursor (which parse with parse_from_rfc3339).
    let b_rec = logs
        .iter()
        .find(|l| l.id == b_id)
        .expect("B present in scan");
    assert!(
        chrono::DateTime::parse_from_rfc3339(&b_rec.created_at).is_ok(),
        "LogRecord.created_at must be RFC 3339, got {:?}",
        b_rec.created_at
    );

    // 3. Advance the cursor to A (created_at, id). B must STILL be returned,
    //    because B.created_at > A.created_at. This is the anti-starvation core
    //    of the fix: the old `time` cursor would have jumped to ~now and
    //    excluded B (event time = now - 1h).
    let after_a = be
        .query_logs_after_cursor(Some(a_created), a_id, 120, 5000)
        .await
        .expect("scan after A");
    let after_a_ids: Vec<i64> = after_a
        .iter()
        .filter(|l| l.hostname.as_deref() == Some(HOST))
        .map(|l| l.id)
        .collect();
    assert!(
        after_a_ids.contains(&b_id),
        "B must remain visible after the cursor advances past A (created_at keyset)"
    );
    assert!(
        !after_a_ids.contains(&a_id),
        "A must not be re-returned once the cursor has passed it"
    );

    client.execute(purge, &[&HOST]).await.expect("cleanup");
}
