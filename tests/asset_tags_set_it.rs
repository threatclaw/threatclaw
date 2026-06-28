//! Regression test for the V98 tag entity (operator tag management on the
//! `tags` / `asset_tags` many-to-many model).
//!
//! Proves, on a real Postgres:
//!   - `set_asset_tags` is a true set on the m2m (add AND remove user tags),
//!   - `list_asset_user_tags` returns only user tags (system flags excluded),
//!   - system flags (possible-duplicate) live in `assets.tags`, untouched,
//!   - `get_or_create_tag` is idempotent and keeps a stable colour,
//!   - `list_tags` reports a live usage count,
//!   - `bulk_add_tag` attaches one tag to many assets,
//!   - merging an alias carries its user tags onto the canonical.
//!
//! Requires a local Postgres with the asset + V98 migrations applied:
//!   DATABASE_URL=postgres://threatclaw:...@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test asset_tags_set_it -- --ignored

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

fn asset(id: &str) -> NewAsset {
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
        source: "manual".into(),
        owner: None,
        location: None,
        tags: vec![],
        notes: None,
    }
}

async fn user_tag_labels(be: &PgBackend, id: &str) -> Vec<String> {
    let mut v: Vec<String> = be
        .list_asset_user_tags(&[id.to_string()])
        .await
        .expect("list user tags")
        .into_iter()
        .map(|l| l.label)
        .collect();
    v.sort();
    v
}

#[tokio::test]
#[ignore]
async fn tag_entity_set_remove_bulk_and_merge() {
    let be = backend().await;
    let a = "ittag-a";
    let b = "ittag-b";
    for id in [a, b] {
        let _ = be.purge_asset(id, "purge", false).await;
    }

    be.upsert_asset(&asset(a)).await.expect("create a");
    be.upsert_asset(&asset(b)).await.expect("create b");

    // Set two user tags on A; a system flag also present must stay separate.
    be.add_asset_tag(a, "possible-duplicate").await.expect("flag");
    be.set_asset_tags(a, &["env-prod".into(), "owner-it".into()])
        .await
        .expect("set tags");
    assert_eq!(
        user_tag_labels(&be, a).await,
        vec!["env-prod".to_string(), "owner-it".to_string()],
        "both user tags linked"
    );
    let sys = be.get_asset(a).await.unwrap().unwrap().tags;
    assert_eq!(sys, vec!["possible-duplicate".to_string()], "system flag untouched in assets.tags");

    // Removal: shrinking the set actually removes the link.
    be.set_asset_tags(a, &["env-prod".into()]).await.expect("shrink");
    assert_eq!(user_tag_labels(&be, a).await, vec!["env-prod".to_string()], "owner-it removed");

    // get_or_create_tag idempotent + stable colour.
    let id1 = be.get_or_create_tag("env-prod").await.expect("goc1");
    let id2 = be.get_or_create_tag("ENV-PROD").await.expect("goc2"); // case-normalised
    assert_eq!(id1, id2, "same tag id regardless of case");

    // list_tags usage count: env-prod is on A only here.
    let envprod = be
        .list_tags()
        .await
        .expect("list tags")
        .into_iter()
        .find(|t| t.label == "env-prod")
        .expect("env-prod present");
    assert_eq!(envprod.usage_count, 1, "usage count reflects links");
    assert!(envprod.color.starts_with('#'), "tag carries a colour");

    // bulk_add_tag attaches one label to many assets.
    be.bulk_add_tag(&[a.into(), b.into()], "lyon").await.expect("bulk");
    assert!(user_tag_labels(&be, a).await.contains(&"lyon".to_string()));
    assert!(user_tag_labels(&be, b).await.contains(&"lyon".to_string()));

    // Merge: A's user tags land on the canonical B.
    be.merge_assets(a, b, "tester@example.com", "dup").await.expect("merge");
    let bt = user_tag_labels(&be, b).await;
    assert!(bt.contains(&"env-prod".to_string()), "merge carried env-prod to canonical");
    assert!(bt.contains(&"lyon".to_string()));

    for id in [a, b] {
        let _ = be.purge_asset(id, "purge", false).await;
    }
}
