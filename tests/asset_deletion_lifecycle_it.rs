//! Integration test for the asset deletion lifecycle (steps 3a–3c).
//!
//! Covers, on a real Postgres:
//!   - reset  : wipes the asset's analysis rows (findings here) but keeps the
//!     asset active; a DIFFERENT asset's rows are untouched (isolation).
//!   - delete : soft-deletes the asset (status='deleted') and sets the tombstone.
//!   - tombstone: resolve_asset refuses to resurrect a blocked, soft-deleted host.
//!   - reactivate: clears the tombstone and brings the row back to 'active'.
//!   - purge  : hard-deletes the asset row.
//!
//! Requires a local Postgres with the asset migrations (incl. V87) applied:
//!   DATABASE_URL=postgres://threatclaw:...@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test asset_deletion_lifecycle_it -- --ignored
//!
//! Idempotent: uses a test-only prefix and purges its rows at the start and end.

#![cfg(feature = "postgres")]

use threatclaw::config::DatabaseConfig;
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::threatclaw_store::{NewAsset, NewFinding, ThreatClawStore};
use threatclaw::graph::asset_resolution::{self, DiscoveredAsset, ResolutionAction};

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
        name: id.into(),
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
        notes: None,
    }
}

fn finding(skill_id: &str, asset: &str) -> NewFinding {
    NewFinding {
        skill_id: skill_id.into(),
        title: "lifecycle test finding".into(),
        description: None,
        severity: "low".into(),
        category: None,
        asset: Some(asset.into()),
        source: Some("test".into()),
        metadata: None,
    }
}

async fn n_findings(be: &PgBackend, skill: &str) -> usize {
    be.list_findings(None, None, Some(skill), 100, 0)
        .await
        .unwrap()
        .len()
}

fn discovered(hostname: &str) -> DiscoveredAsset {
    DiscoveredAsset {
        mac: None,
        hostname: Some(hostname.into()),
        fqdn: None,
        ip: None,
        os: None,
        ports: None,
        services: serde_json::json!([]),
        ou: None,
        vlan: None,
        vm_id: None,
        criticality: None,
        source: "syslog".into(),
    }
}

#[tokio::test]
#[ignore]
async fn deletion_lifecycle() {
    let be = backend().await;
    let host_a = "itdel-host-a";
    let host_b = "itdel-host-b";
    let skill_a = "itdel-skill-a";
    let skill_b = "itdel-skill-b";

    // Clean any residue from a previous run (purge cascades to findings).
    let _ = be.purge_asset(host_a, "purge", false).await;
    let _ = be.purge_asset(host_b, "purge", false).await;

    be.upsert_asset(&asset(host_a, host_a)).await.unwrap();
    be.upsert_asset(&asset(host_b, host_b)).await.unwrap();
    be.insert_finding(&finding(skill_a, host_a)).await.unwrap();
    be.insert_finding(&finding(skill_b, host_b)).await.unwrap();

    // ── reset: scrub A's findings, keep A active, leave B alone ──
    be.purge_asset(host_a, "reset", false).await.unwrap();
    assert_eq!(n_findings(&be, skill_a).await, 0, "reset wipes A findings");
    assert_eq!(
        n_findings(&be, skill_b).await,
        1,
        "B findings untouched (isolation)"
    );
    let a = be
        .get_asset(host_a)
        .await
        .unwrap()
        .expect("A still exists after reset");
    assert_eq!(a.status, "active", "reset keeps A active");

    // ── delete + block: soft-delete + tombstone ──
    be.insert_finding(&finding(skill_a, host_a)).await.unwrap();
    be.purge_asset(host_a, "delete", true).await.unwrap();
    let a = be
        .get_asset(host_a)
        .await
        .unwrap()
        .expect("A row kept after soft delete");
    assert_eq!(a.status, "deleted", "delete soft-deletes A");
    assert!(a.reenrol_blocked, "delete + block sets the tombstone");
    assert_eq!(n_findings(&be, skill_a).await, 0, "delete wipes A findings");

    // ── tombstone: resolve_asset must NOT resurrect a blocked host ──
    let r = asset_resolution::resolve_asset(&be, &discovered(host_a)).await;
    assert!(
        matches!(r.action, ResolutionAction::Conflict),
        "tombstoned host returns Conflict (skipped), got {:?}",
        r.action
    );
    let a = be.get_asset(host_a).await.unwrap().unwrap();
    assert_eq!(a.status, "deleted", "still deleted after a blocked resolve");

    // ── reactivate: clears the tombstone, back to active ──
    be.reactivate_asset(host_a).await.unwrap();
    let a = be.get_asset(host_a).await.unwrap().unwrap();
    assert_eq!(a.status, "active", "reactivate restores active");
    assert!(!a.reenrol_blocked, "reactivate clears the tombstone");

    // ── purge: hard delete, B survives ──
    be.purge_asset(host_a, "purge", false).await.unwrap();
    assert!(
        be.get_asset(host_a).await.unwrap().is_none(),
        "purge hard-deletes A"
    );
    assert!(
        be.get_asset(host_b).await.unwrap().is_some(),
        "B survives A's purge"
    );
    assert_eq!(
        n_findings(&be, skill_b).await,
        1,
        "B findings survive A's purge"
    );

    // cleanup
    let _ = be.purge_asset(host_b, "purge", false).await;
}
