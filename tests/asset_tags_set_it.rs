//! Regression test for operator tag management (`set_asset_tags`).
//!
//! The upsert path unions tags (add-only, so a manual edit could never remove
//! a tag). The dedicated set endpoint replaces the operator tags while keeping
//! the platform-managed system tags. This test proves, on a real Postgres:
//!   - set replaces the user tags (add),
//!   - a system tag present on the row (possible-duplicate) is preserved,
//!   - removing a tag from the set actually removes it,
//!   - a system tag echoed back by the caller can't be injected as a user tag
//!     (it's only kept because it was already on the row).
//!
//! Requires a local Postgres with the asset migrations applied:
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

async fn tags_of(be: &PgBackend, id: &str) -> Vec<String> {
    let mut t = be.get_asset(id).await.expect("get").expect("exists").tags;
    t.sort();
    t
}

#[tokio::test]
#[ignore]
async fn set_tags_replaces_user_tags_and_keeps_system_tags() {
    let be = backend().await;
    let id = "ittags-host";
    let _ = be.purge_asset(id, "purge", false).await;

    be.upsert_asset(&asset(id)).await.expect("create");
    // Simulate the auto-flagger marking this host as a possible duplicate.
    be.add_asset_tag(id, "possible-duplicate")
        .await
        .expect("flag dup");

    // Operator sets two tags. The system tag must survive.
    be.set_asset_tags(id, &["env-prod".into(), "owner-it".into()])
        .await
        .expect("set tags");
    assert_eq!(
        tags_of(&be, id).await,
        vec![
            "env-prod".to_string(),
            "owner-it".to_string(),
            "possible-duplicate".to_string()
        ],
        "user tags set, system tag preserved"
    );

    // Operator removes one tag — removal must actually take effect.
    be.set_asset_tags(id, &["env-prod".into()])
        .await
        .expect("shrink tags");
    assert_eq!(
        tags_of(&be, id).await,
        vec!["env-prod".to_string(), "possible-duplicate".to_string()],
        "owner-it removed; system tag still preserved"
    );

    // A caller echoing a system tag can't inject it as a user tag, and
    // clearing to empty keeps only the row's system tags.
    be.set_asset_tags(id, &["public_ip".into()])
        .await
        .expect("inject attempt");
    assert_eq!(
        tags_of(&be, id).await,
        vec!["possible-duplicate".to_string()],
        "injected system tag dropped; existing system tag kept"
    );

    let _ = be.purge_asset(id, "purge", false).await;
}
