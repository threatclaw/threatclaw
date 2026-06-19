//! Integration test — a merged asset alias must disappear from the default
//! inventory listing. Regression for the bug where `merge_assets` set the alias
//! to status='merged' but `list_assets` / `count_assets_filtered` did not filter
//! it out, so a manual merge "did nothing" in the UI (both rows kept showing).
//!
//! Requires a local Postgres with the assets + merge_aliases migrations applied.
//! Runs with:
//!   DATABASE_URL=postgres://threatclaw:...@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test asset_merge_hides_merged_it -- --ignored
//!
//! Idempotent: uses a test-only id prefix and cleans up at the end.

#![cfg(feature = "postgres")]

use threatclaw::config::DatabaseConfig;
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::threatclaw_store::{NewAsset, ThreatClawStore};

const PREFIX: &str = "itmerge-";

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

fn asset(id: &str, hostname: &str) -> NewAsset {
    NewAsset {
        id: id.into(),
        name: hostname.into(),
        category: "server".into(),
        subcategory: None,
        role: None,
        criticality: "low".into(),
        ip_addresses: vec![],
        mac_address: None,
        hostname: Some(hostname.into()),
        fqdn: None,
        url: None,
        os: None,
        mac_vendor: None,
        services: serde_json::json!([]),
        source: "test".into(),
        owner: None,
        location: None,
        tags: vec![],
    }
}

#[tokio::test]
#[ignore]
async fn merged_alias_hidden_from_default_listing() {
    let be = backend().await;
    let canonical_id = format!("{PREFIX}canonical");
    let alias_id = format!("{PREFIX}alias");

    // Clean any residue from a previous run.
    let _ = be.delete_asset(&canonical_id).await;
    let _ = be.delete_asset(&alias_id).await;

    be.upsert_asset(&asset(&canonical_id, "itmerge-host-a"))
        .await
        .expect("insert canonical");
    be.upsert_asset(&asset(&alias_id, "itmerge-host-b"))
        .await
        .expect("insert alias");

    // Before the merge both are visible in the default listing.
    let before = be.list_assets(None, None, 10000, 0).await.expect("list before");
    assert!(before.iter().any(|a| a.id == canonical_id), "canonical visible before");
    assert!(before.iter().any(|a| a.id == alias_id), "alias visible before");

    be.merge_assets(&alias_id, &canonical_id, "test", "regression")
        .await
        .expect("merge");

    // After the merge the alias is hidden, the canonical stays.
    let after = be.list_assets(None, None, 10000, 0).await.expect("list after");
    assert!(after.iter().any(|a| a.id == canonical_id), "canonical must remain");
    assert!(
        !after.iter().any(|a| a.id == alias_id),
        "merged alias must be hidden from the default listing"
    );

    // count_assets_filtered must apply the same merged exclusion: the alias is
    // not in the default count but is counted under an explicit merged filter.
    let merged_count = be
        .count_assets_filtered(None, Some("merged"))
        .await
        .expect("count merged");
    assert!(
        merged_count >= 1,
        "merged alias must be counted under an explicit status='merged' filter"
    );

    // An explicit status='merged' filter still surfaces the alias on demand.
    let merged = be
        .list_assets(None, Some("merged"), 10000, 0)
        .await
        .expect("list merged");
    assert!(
        merged.iter().any(|a| a.id == alias_id),
        "explicit status='merged' filter must still surface the alias"
    );

    // Cleanup.
    let _ = be.delete_asset(&canonical_id).await;
    let _ = be.delete_asset(&alias_id).await;
}
