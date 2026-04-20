//! Integration test — see ADR-047.
//!
//! Exercises the full suppression lifecycle against a live Postgres:
//! create rule via store → reload engine → evaluate → disable → reload.
//!
//! Run with:
//!   DATABASE_URL=postgres://... cargo test --features postgres \
//!       --test suppression_api_it -- --ignored

#![cfg(feature = "postgres")]

use threatclaw::agent::suppression::{SuppressionDecision, global as supp_global};
use threatclaw::config::DatabaseConfig;
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::threatclaw_store::ThreatClawStore;

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

async fn cleanup_all(store: &PgBackend) {
    let conn = store.pool().get().await.expect("pool");
    conn.execute("DELETE FROM suppression_rules", &[])
        .await
        .ok();
}

#[tokio::test]
#[ignore]
async fn create_reload_evaluate_disable_flow() {
    let store = backend().await;
    cleanup_all(&store).await;

    let predicate = r#"event.skill_id == "skill-itsupp" && event.category == "internal_scan""#;
    let id = store
        .create_suppression_rule(
            "it-test-rule",
            &serde_json::json!({"cel": predicate}),
            predicate,
            "drop",
            None,
            "global",
            "Scans internes planifiés du mardi",
            "it-tester",
            None,
            "manual",
        )
        .await
        .expect("create");

    // Reload engine from DB → rule should be active.
    supp_global::reload(&store).await.expect("reload");
    let engine = supp_global::engine();
    assert!(engine.rule_count().await >= 1);

    let event = serde_json::json!({
        "skill_id": "skill-itsupp",
        "category": "internal_scan",
        "severity": "LOW",
    });
    match engine.evaluate(&event, "skill-itsupp", None).await {
        SuppressionDecision::Drop { .. } => {}
        other => panic!("expected Drop, got {:?}", other),
    }

    // Non-matching event.
    let other = serde_json::json!({
        "skill_id": "skill-itsupp",
        "category": "brute_force",
    });
    assert_eq!(
        engine.evaluate(&other, "skill-itsupp", None).await,
        SuppressionDecision::Keep
    );

    // Disable and reload → no longer matches.
    store.disable_suppression_rule(id).await.expect("disable");
    supp_global::reload(&store).await.expect("reload");
    assert_eq!(
        engine.evaluate(&event, "skill-itsupp", None).await,
        SuppressionDecision::Keep
    );

    cleanup_all(&store).await;
}

#[tokio::test]
#[ignore]
async fn constraint_reason_too_short_rejected() {
    let store = backend().await;
    let result = store
        .create_suppression_rule(
            "short-reason",
            &serde_json::json!({}),
            "event.skill_id == \"x\"",
            "drop",
            None,
            "global",
            "too",
            "it",
            None,
            "manual",
        )
        .await;
    assert!(result.is_err(), "DB CHECK should reject reason < 10 chars");
}
