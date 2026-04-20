//! Integration test — see ADR-048.
//!
//! Requires a local Postgres with V42 + V43 applied. Runs with:
//!   DATABASE_URL=postgres://threatclaw:...@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test blast_radius_auto_trigger_it -- --ignored
//!
//! Idempotent: creates its own rows with a test-only asset prefix and
//! cleans up at the end.

#![cfg(feature = "postgres")]

use threatclaw::agent::blast_radius_trigger;
use threatclaw::config::DatabaseConfig;
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::threatclaw_store::ThreatClawStore;
use threatclaw::graph::normalized::{self, GraphCache};

use std::sync::Arc;

const TEST_PREFIX: &str = "itblast-";

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

async fn seed_graph(cache: &Arc<GraphCache>) {
    use normalized::edge::Edge;
    use normalized::node::{Node, NodeKind};

    cache
        .rebuild(
            vec![
                Node::new(format!("{TEST_PREFIX}user:alice"), NodeKind::User),
                Node::new(format!("{TEST_PREFIX}host:prod-sql01"), NodeKind::Host)
                    .with_criticality(9),
                Node::new(
                    format!("{TEST_PREFIX}data_class:finance"),
                    NodeKind::DataClass,
                )
                .with_criticality(9),
            ],
            vec![
                Edge::new(
                    format!("{TEST_PREFIX}user:alice"),
                    format!("{TEST_PREFIX}host:prod-sql01"),
                    "CanRDP",
                )
                .with_weight(2),
                Edge::new(
                    format!("{TEST_PREFIX}host:prod-sql01"),
                    format!("{TEST_PREFIX}data_class:finance"),
                    "Stores",
                )
                .with_weight(1),
            ],
        )
        .await;
}

async fn cleanup(store: &PgBackend, incident_id: i32) {
    let conn = store.pool().get().await.expect("pool");
    conn.execute("DELETE FROM incidents WHERE id = $1", &[&incident_id])
        .await
        .ok();
}

#[tokio::test]
#[ignore] // requires live Postgres
async fn auto_trigger_persists_snapshot() {
    let store = backend().await;
    let cache = Arc::new(GraphCache::new());
    seed_graph(&cache).await;

    let asset = format!("{TEST_PREFIX}user:alice");
    let incident_id = store
        .create_incident(&asset, "phishing click on alice", "HIGH", &[], &[], 1)
        .await
        .expect("create");

    let snapshot = blast_radius_trigger::compute_and_persist(&store, &cache, incident_id, &asset)
        .await
        .expect("compute");

    assert!(
        snapshot.score > 0,
        "score should be positive when data_class is reachable"
    );
    assert!(snapshot.reachable_count >= 2);

    let fetched = store
        .get_incident(incident_id)
        .await
        .expect("fetch")
        .expect("exists");
    let persisted_score = fetched
        .get("blast_radius_score")
        .and_then(|v| v.as_i64())
        .expect("score persisted");
    assert_eq!(persisted_score, snapshot.score as i64);

    cleanup(&store, incident_id).await;
}

#[tokio::test]
#[ignore]
async fn low_severity_does_not_trigger() {
    let store = backend().await;
    let cache = Arc::new(GraphCache::new());
    seed_graph(&cache).await;

    let asset = format!("{TEST_PREFIX}user:alice");
    let incident_id = store
        .create_incident(&asset, "scan", "LOW", &[], &[], 1)
        .await
        .expect("create");

    blast_radius_trigger::try_auto_trigger(
        &store,
        incident_id,
        &asset,
        &["T1566".to_string()],
        "LOW",
    )
    .await;

    let fetched = store
        .get_incident(incident_id)
        .await
        .expect("fetch")
        .expect("exists");
    let score = fetched.get("blast_radius_score").and_then(|v| v.as_i64());
    assert!(
        score.is_none(),
        "blast radius should not run at LOW severity"
    );

    cleanup(&store, incident_id).await;
}

#[tokio::test]
#[ignore]
async fn recompute_is_idempotent() {
    let store = backend().await;
    let cache = Arc::new(GraphCache::new());
    seed_graph(&cache).await;

    let asset = format!("{TEST_PREFIX}user:alice");
    let incident_id = store
        .create_incident(&asset, "re-run test", "HIGH", &[], &[], 1)
        .await
        .expect("create");

    let s1 = blast_radius_trigger::compute_and_persist(&store, &cache, incident_id, &asset)
        .await
        .expect("compute 1");
    let s2 = blast_radius_trigger::compute_and_persist(&store, &cache, incident_id, &asset)
        .await
        .expect("compute 2");

    assert_eq!(s1.score, s2.score);
    assert_eq!(s1.reachable_count, s2.reachable_count);

    cleanup(&store, incident_id).await;
}
