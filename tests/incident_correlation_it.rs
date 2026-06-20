//! Integration test: set_incident_correlation persists related_assets + campaign_id.
//!
//! Real Postgres (incidents is a PG-only table; libSQL stubs not_supported).
//! Validates the V89 columns + the persistence method that lets a multi-host
//! attack reference the other assets it touched. See detection-chain audit
//! 2026-06-20.
//!
//!   DATABASE_URL=postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test incident_correlation_it -- --ignored
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

#[tokio::test]
#[ignore = "requires local Postgres with migrations applied"]
async fn set_incident_correlation_persists_related_assets() {
    let be = backend().await;

    let id = be
        .create_incident("test-corr-primary", "e2e correlation test", "HIGH", &[], &[], 0)
        .await
        .expect("create incident");

    let related = vec!["test-corr-b".to_string(), "test-corr-c".to_string()];
    be.set_incident_correlation(id, &related, Some("camp-e2e-1"))
        .await
        .expect("set correlation");

    // Read the columns back directly.
    let client = be.pool().get().await.expect("pool client");
    let row = client
        .query_one(
            "SELECT related_assets, campaign_id FROM incidents WHERE id = $1",
            &[&id],
        )
        .await
        .expect("read incident");
    let related_json: serde_json::Value = row.get(0);
    let campaign: Option<String> = row.get(1);

    assert_eq!(
        related_json,
        serde_json::json!(["test-corr-b", "test-corr-c"]),
        "related_assets must round-trip"
    );
    assert_eq!(campaign.as_deref(), Some("camp-e2e-1"));

    // Cleanup.
    client
        .execute("DELETE FROM incidents WHERE id = $1", &[&id])
        .await
        .expect("cleanup");
}
