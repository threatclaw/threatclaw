//! Integration test: `get_all_ml_scores` filters out stale rows.
//!
//! On a real Postgres. The ML engine re-scores every active asset each cycle
//! (~5 min); a score older than the freshness window (30 min) means the asset
//! dropped out of the ML feature window or the engine is down — either way the
//! score is stale and must NOT be returned to the Intelligence Engine, which
//! would otherwise apply a month-old anomaly score as if current.
//! See detection-chain audit 2026-06-20.
//!
//!   DATABASE_URL=postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test ml_score_freshness_it -- --ignored
//!
//! Idempotent: uses a test-only `asset_id` prefix and purges its rows around the
//! assertions.
#![cfg(feature = "postgres")]

use threatclaw::config::{DatabaseBackend, DatabaseConfig, SslMode};
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::threatclaw_store::ThreatClawStore;

const FRESH: &str = "test-mlfresh-fresh";
const STALE: &str = "test-mlfresh-stale";

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

async fn purge(be: &PgBackend) {
    let client = be.pool().get().await.expect("pool client");
    let ids = vec![FRESH.to_string(), STALE.to_string()];
    client
        .execute("DELETE FROM ml_scores WHERE asset_id = ANY($1)", &[&ids])
        .await
        .expect("cleanup ml_scores");
}

#[tokio::test]
#[ignore = "requires local Postgres with migrations applied"]
async fn get_all_ml_scores_excludes_stale_rows() {
    let be = backend().await;
    purge(&be).await;

    let feats = serde_json::json!({});
    be.set_ml_score(FRESH, 0.91, "fresh", &feats)
        .await
        .expect("set fresh score");
    be.set_ml_score(STALE, 0.80, "stale", &feats)
        .await
        .expect("set stale score");

    // Backdate the stale row well beyond the 30-min freshness window.
    {
        let client = be.pool().get().await.expect("pool client");
        client
            .execute(
                "UPDATE ml_scores SET computed_at = NOW() - INTERVAL '2 hours' \
                 WHERE asset_id = $1",
                &[&STALE.to_string()],
            )
            .await
            .expect("backdate stale row");
    }

    let scores = be.get_all_ml_scores().await.expect("get_all_ml_scores");
    assert!(
        scores.contains_key(FRESH),
        "a freshly-computed score must be returned"
    );
    assert!(
        !scores.contains_key(STALE),
        "a stale (>30 min) score must be filtered out"
    );

    purge(&be).await;
}
