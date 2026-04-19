//! Integration test for migration V38 (`tc_config_llm_validation_mode` seed).
//!
//! This test applies ALL migrations (V01 → latest) against a real PostgreSQL
//! instance and then verifies that V38 correctly seeded the validation mode
//! setting with the default `"off"` value.
//!
//! It is marked `#[ignore]` so it does not run in default `cargo test` runs.
//! To execute it explicitly, export `DATABASE_URL` and run:
//!
//!     DATABASE_URL=postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw \
//!         cargo test --test migration_v38_integration -- --ignored --nocapture
//!
//! The test also serves as a permanent audit-trail: running it confirms that
//! a fresh instance will receive `tc_config_llm_validation_mode = "off"`
//! immediately after the migration runner completes.

#![cfg(feature = "postgres")]

use threatclaw::config::{DatabaseBackend, DatabaseConfig, SslMode};
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::{Database, SettingsStore};

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
async fn v38_seeds_validation_mode_off() {
    let config = load_database_config();

    let backend = PgBackend::new(&config)
        .await
        .expect("failed to connect to PostgreSQL at DATABASE_URL");

    backend
        .run_migrations()
        .await
        .expect("failed to run migrations (V01..=latest)");

    let value = backend
        .get_setting("_system", "tc_config_llm_validation_mode")
        .await
        .expect("get_setting should not fail on a healthy store");

    let raw = value.expect(
        "V38 migration must seed `tc_config_llm_validation_mode` for the _system scope",
    );

    assert_eq!(
        raw,
        serde_json::json!("off"),
        "V38 must seed the setting value to JSON string \"off\" (backward-compatible default)"
    );
}

#[tokio::test]
#[ignore]
async fn v38_is_idempotent() {
    let config = load_database_config();

    let backend = PgBackend::new(&config)
        .await
        .expect("failed to connect to PostgreSQL");

    // First migration run (may no-op if already applied by another test run).
    backend.run_migrations().await.expect("first migration run");

    // Manually set a non-default value to simulate an operator who changed it.
    backend
        .set_setting(
            "_system",
            "tc_config_llm_validation_mode",
            &serde_json::json!("strict"),
        )
        .await
        .expect("set_setting should succeed");

    // Second migration run must NOT overwrite the operator's choice.
    backend
        .run_migrations()
        .await
        .expect("second migration run");

    let value = backend
        .get_setting("_system", "tc_config_llm_validation_mode")
        .await
        .expect("get_setting failed")
        .expect("setting disappeared after second migration run");

    assert_eq!(
        value,
        serde_json::json!("strict"),
        "V38 must be idempotent: re-running migrations must NOT overwrite an operator-chosen value"
    );

    // Restore default for subsequent test runs.
    backend
        .set_setting(
            "_system",
            "tc_config_llm_validation_mode",
            &serde_json::json!("off"),
        )
        .await
        .expect("restore default");
}
