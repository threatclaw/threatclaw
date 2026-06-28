//! Regression test for the asset notes persistence bug.
//!
//! Before the fix, `NewAsset` had no `notes` field and `upsert_asset` never
//! wrote the `notes` column — operator notes typed in the dashboard were
//! silently dropped. This test proves, on a real Postgres, that:
//!   - a note supplied on upsert is persisted and read back,
//!   - a later connector-style sync (notes = None) does NOT wipe the note,
//!   - re-editing the note via upsert applies the new value (never frozen).
//!
//! Requires a local Postgres with the asset migrations applied:
//!   DATABASE_URL=postgres://threatclaw:...@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test asset_notes_persist_it -- --ignored
//!
//! Idempotent: uses a test-only id and purges its row at the start and end.

#![cfg(feature = "postgres")]

use threatclaw::config::DatabaseConfig;
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::threatclaw_store::{NewAsset, ThreatClawStore};

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

/// Build an asset with a chosen source + notes, everything else minimal.
fn asset(id: &str, source: &str, notes: Option<&str>) -> NewAsset {
    NewAsset {
        id: id.into(),
        name: id.into(),
        category: "server".into(),
        subcategory: None,
        role: None,
        criticality: "low".into(),
        ip_addresses: vec![],
        mac_address: None,
        hostname: Some(id.into()),
        fqdn: None,
        url: None,
        os: None,
        mac_vendor: None,
        services: serde_json::json!([]),
        source: source.into(),
        owner: None,
        location: None,
        tags: vec![],
        notes: notes.map(String::from),
    }
}

#[tokio::test]
#[ignore]
async fn notes_persist_and_survive_sync() {
    let be = backend().await;
    let id = "itnotes-host";

    // Clean any residue from a previous run.
    let _ = be.purge_asset(id, "purge", false).await;

    // 1. Operator creates the asset with a note → it must persist.
    be.upsert_asset(&asset(id, "manual", Some("first note")))
        .await
        .expect("upsert with note");
    let got = be.get_asset(id).await.expect("get").expect("exists");
    assert_eq!(
        got.notes.as_deref(),
        Some("first note"),
        "note typed by the operator must be persisted"
    );

    // 2. A connector sync arrives (notes = None) → the note must NOT be wiped.
    be.upsert_asset(&asset(id, "nmap", None))
        .await
        .expect("connector sync");
    let got = be.get_asset(id).await.expect("get").expect("exists");
    assert_eq!(
        got.notes.as_deref(),
        Some("first note"),
        "a connector sync (notes=None) must preserve the existing note"
    );

    // 3. Operator edits the note again → re-editable, never frozen.
    be.upsert_asset(&asset(id, "manual", Some("edited note")))
        .await
        .expect("re-edit note");
    let got = be.get_asset(id).await.expect("get").expect("exists");
    assert_eq!(
        got.notes.as_deref(),
        Some("edited note"),
        "notes must stay re-editable on subsequent upserts"
    );

    // Cleanup.
    let _ = be.purge_asset(id, "purge", false).await;
}
