//! Integration test: incident remediation anti-replay / execute-once guard.
//!
//! Regression for the HITL audit finding — an approved remediation could be
//! executed more than once (no execute-once guard; the same incident is shown
//! on the dashboard AND on the comms channels, so a second approval from any
//! surface re-fired the action). The fix is a central atomic claim in
//! `execute_incident_remediation_for`, backed by these two store methods.
//!
//! Real Postgres:
//!   DATABASE_URL=postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test incident_action_replay_it -- --ignored
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

const ASSET: &str = "e2e-replay-guard-host";

async fn count_markers(be: &PgBackend, id: i32, subject: &str, status: &str) -> usize {
    let inc = be.get_incident(id).await.expect("get").expect("exists");
    inc["executed_actions"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|e| e["subject"] == subject && e["status"] == status)
                .count()
        })
        .unwrap_or(0)
}

#[tokio::test]
#[ignore = "requires local Postgres with migrations applied"]
async fn claim_blocks_replay_and_releases_on_failure() {
    let be = backend().await;
    let client = be.pool().get().await.expect("pool client");
    client
        .execute("DELETE FROM incidents WHERE asset = $1", &[&ASSET])
        .await
        .expect("pre-clean");

    let id: i32 = client
        .query_one(
            "INSERT INTO incidents (asset, title, severity, status, verdict) \
             VALUES ($1, 'replay guard test', 'critical', 'open', 'malicious') RETURNING id",
            &[&ASSET],
        )
        .await
        .expect("insert")
        .get(0);

    // 1. First claim succeeds.
    assert!(
        be.try_claim_incident_action(id, "block_ip").await.unwrap(),
        "first claim must succeed"
    );
    assert_eq!(count_markers(&be, id, "block_ip", "in_progress").await, 1);

    // 2. Concurrent / second claim while in flight is refused (replay).
    assert!(
        !be.try_claim_incident_action(id, "block_ip").await.unwrap(),
        "second claim while in_progress must be refused"
    );

    // 3. A DIFFERENT action on the same incident is independent.
    assert!(
        be.try_claim_incident_action(id, "isolate_host")
            .await
            .unwrap(),
        "a different action must be claimable independently"
    );

    // 4. Finalize block_ip as FAILURE → marker released → retry allowed.
    be.finalize_incident_action(id, "block_ip", false, "connector down")
        .await
        .unwrap();
    assert_eq!(count_markers(&be, id, "block_ip", "in_progress").await, 0);
    assert!(
        be.try_claim_incident_action(id, "block_ip").await.unwrap(),
        "after a failed attempt the action must be retryable"
    );

    // 5. Finalize block_ip as SUCCESS → permanent done tombstone.
    be.finalize_incident_action(id, "block_ip", true, "blocked 1.2.3.4")
        .await
        .unwrap();
    assert_eq!(count_markers(&be, id, "block_ip", "done").await, 1);
    assert_eq!(count_markers(&be, id, "block_ip", "in_progress").await, 0);

    // 6. Replay after success is permanently refused.
    assert!(
        !be.try_claim_incident_action(id, "block_ip").await.unwrap(),
        "a completed action must never be claimable again (execute-once)"
    );

    // The done tombstone carries the outcome for the dashboard.
    let inc = be.get_incident(id).await.unwrap().unwrap();
    let done = inc["executed_actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["subject"] == "block_ip" && e["status"] == "done")
        .expect("done marker");
    assert_eq!(done["success"], serde_json::json!(true));
    assert_eq!(done["message"], serde_json::json!("blocked 1.2.3.4"));

    client
        .execute("DELETE FROM incidents WHERE asset = $1", &[&ASSET])
        .await
        .expect("cleanup");
}
