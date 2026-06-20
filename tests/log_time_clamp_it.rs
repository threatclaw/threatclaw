//! Integration test: the V90 trigger clamps future-dated log timestamps.
//!
//! Real Postgres. A direct INSERT into `logs` with a `time` hours ahead of the
//! server clock (simulating fluent-bit's direct PG output or a clock-drifted
//! source) must be clamped to now(), so the Sigma cursor cannot be poisoned by
//! future-dated rows. A normal timestamp passes through unchanged.
//! See detection-chain audit 2026-06-20.
//!
//!   DATABASE_URL=postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test log_time_clamp_it -- --ignored
#![cfg(feature = "postgres")]

use threatclaw::config::{DatabaseBackend, DatabaseConfig, SslMode};
use threatclaw::db::postgres::PgBackend;

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

const HOST_FUTURE: &str = "test-clamp-future";
const HOST_NORMAL: &str = "test-clamp-normal";

#[tokio::test]
#[ignore = "requires local Postgres with migrations (incl. V90) applied"]
async fn trigger_clamps_future_log_time() {
    let be = backend().await;
    let client = be.pool().get().await.expect("pool client");

    let purge = "DELETE FROM logs WHERE hostname = ANY($1)";
    let hosts = vec![HOST_FUTURE.to_string(), HOST_NORMAL.to_string()];
    client.execute(purge, &[&hosts]).await.expect("pre-clean");

    // Direct insert with a time 2h in the future (bypasses the Rust insert_log
    // clamp, like fluent-bit's PG output does).
    client
        .execute(
            "INSERT INTO logs (tag, hostname, data, time) \
             VALUES ('test.clamp', $1, '{}'::jsonb, now() + INTERVAL '2 hours')",
            &[&HOST_FUTURE],
        )
        .await
        .expect("insert future");
    // Direct insert with a normal (current) time.
    client
        .execute(
            "INSERT INTO logs (tag, hostname, data, time) \
             VALUES ('test.clamp', $1, '{}'::jsonb, now())",
            &[&HOST_NORMAL],
        )
        .await
        .expect("insert normal");

    // Future row must have been clamped to ~now; normal row untouched.
    let future_clamped: bool = client
        .query_one(
            "SELECT time <= now() + INTERVAL '5 seconds' FROM logs WHERE hostname = $1",
            &[&HOST_FUTURE],
        )
        .await
        .expect("read future")
        .get(0);
    let normal_ok: bool = client
        .query_one(
            "SELECT time <= now() + INTERVAL '5 seconds' FROM logs WHERE hostname = $1",
            &[&HOST_NORMAL],
        )
        .await
        .expect("read normal")
        .get(0);

    assert!(future_clamped, "future-dated time must be clamped to now()");
    assert!(normal_ok, "a normal timestamp must pass through unchanged");

    client.execute(purge, &[&hosts]).await.expect("cleanup");
}
