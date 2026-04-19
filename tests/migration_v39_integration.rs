//! Integration test for migration V39 (evidence_citations JSONB column).

#![cfg(feature = "postgres")]

use threatclaw::config::{DatabaseBackend, DatabaseConfig, SslMode};
use threatclaw::db::Database;
use threatclaw::db::postgres::PgBackend;

fn load_database_config() -> DatabaseConfig {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw".to_string()
    });
    DatabaseConfig {
        backend: DatabaseBackend::Postgres,
        url: secrecy::SecretString::from(url),
        pool_size: 2,
        ssl_mode: SslMode::Disable,
        libsql_path: None,
        libsql_url: None,
        libsql_auth_token: None,
    }
}

#[tokio::test]
#[ignore]
async fn v39_adds_evidence_citations_column_with_default() {
    let config = load_database_config();
    let backend = PgBackend::new(&config).await.expect("connect");
    backend.run_migrations().await.expect("migrate");

    let pool = backend.pool();
    let conn = pool.get().await.expect("connection");

    let rows = conn
        .query(
            "SELECT column_name, data_type, column_default \
             FROM information_schema.columns \
             WHERE table_name = 'incidents' AND column_name = 'evidence_citations'",
            &[],
        )
        .await
        .expect("query");

    assert_eq!(rows.len(), 1, "evidence_citations column must exist");
    let row = &rows[0];
    let data_type: String = row.get("data_type");
    assert_eq!(data_type, "jsonb");
    let default: Option<String> = row.get("column_default");
    assert!(
        default.as_deref().unwrap_or("").contains("'[]'"),
        "default must be '[]'::jsonb, got: {default:?}"
    );
}

#[tokio::test]
#[ignore]
async fn v39_creates_gin_index() {
    let config = load_database_config();
    let backend = PgBackend::new(&config).await.expect("connect");
    backend.run_migrations().await.expect("migrate");

    let pool = backend.pool();
    let conn = pool.get().await.expect("connection");

    let rows = conn
        .query(
            "SELECT indexname FROM pg_indexes \
             WHERE tablename = 'incidents' \
               AND indexname = 'idx_incidents_evidence_citations'",
            &[],
        )
        .await
        .expect("query");

    assert_eq!(rows.len(), 1, "GIN index must exist after V39");
}
