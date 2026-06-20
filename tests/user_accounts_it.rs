//! Integration test for the dashboard user-accounts + RBAC feature, on a real
//! Postgres. Covers the store + auth + permission layers end to end:
//!   - an invited account cannot authenticate until it accepts;
//!   - the invitation token is single-use;
//!   - after accepting, the user authenticates and carries its overrides;
//!   - an analyst with remediation denied has triage but not remediate;
//!   - active-admin count (the last-admin guard's input) tracks status.
//!
//! Requires a local Postgres with migrations (incl. V88) applied:
//!   DATABASE_URL=postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw \
//!   cargo test --features postgres --test user_accounts_it -- --ignored
//!
//! Idempotent: all rows use the `ituser_` email prefix and are purged at the
//! start and end of each test.

#![cfg(feature = "postgres")]

use std::sync::Arc;

use threatclaw::channels::web::dashboard_auth as auth;
use threatclaw::channels::web::permissions::effective_permissions;
use threatclaw::config::{DatabaseBackend, DatabaseConfig, SslMode};
use threatclaw::db::Database;
use threatclaw::db::dashboard_user_store::{DashboardUserStore, NewDashboardUser, UserPatch};
use threatclaw::db::postgres::PgBackend;

// Tests run concurrently against the same DB, so each uses its own email
// prefix and cleans up only its own rows (no reliance on serial execution).

async fn db() -> Arc<dyn Database> {
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
    // Migrations are assumed already applied to the test DB (incl. V88), like
    // the other *_it.rs tests — re-running them against a populated DB conflicts.
    let be = PgBackend::new(&cfg).await.expect("pg backend");
    Arc::new(be)
}

async fn cleanup(store: &Arc<dyn Database>, prefix: &str) {
    for u in store.dbu_list().await.unwrap_or_default() {
        if u.email.starts_with(prefix) {
            let _ = store.dbu_delete(&u.id).await;
        }
    }
}

#[tokio::test]
#[ignore]
async fn invitation_and_permissions_flow() {
    let p = "ituser_inv_";
    let store = db().await;
    cleanup(&store, p).await;

    let email = format!("{p}analyst@example.com");
    let id = store
        .dbu_create(&NewDashboardUser {
            email: email.clone(),
            display_name: "Analyst".into(),
            role: "analyst".into(),
            granted: vec![],
            denied: vec!["incidents:remediate".into()],
            created_by: Some("test".into()),
        })
        .await
        .expect("create");

    // Invited account: no password, cannot authenticate yet.
    let rec = store.dbu_get(&id).await.unwrap().unwrap();
    assert_eq!(rec.status, "invited");
    assert!(rec.password_hash.is_none());
    assert!(
        auth::authenticate(&store, &email, "anything", "ip", "ua")
            .await
            .is_err(),
        "invited account must not authenticate"
    );

    // Issue + consume an invitation token (single-use).
    let (raw, hash) = auth::generate_session_token();
    let exp = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();
    store
        .dbu_create_invitation(&hash, &id, "invite", &exp)
        .await
        .unwrap();
    let taken = store
        .dbu_take_invitation(&auth::token_hash(&raw))
        .await
        .unwrap();
    assert_eq!(taken, Some((id.clone(), "invite".to_string())));
    assert!(
        store
            .dbu_take_invitation(&auth::token_hash(&raw))
            .await
            .unwrap()
            .is_none(),
        "invitation token must be single-use"
    );

    // Accept: set the password + activate.
    let pwhash = auth::hash_password("SuperSecret123").unwrap();
    store
        .dbu_patch(
            &id,
            &UserPatch {
                password_hash: Some(Some(pwhash)),
                status: Some("active".into()),
                must_change_password: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Now authentication works and carries the overrides.
    let (info, _token) = auth::authenticate(&store, &email, "SuperSecret123", "ip", "ua")
        .await
        .expect("active analyst authenticates");
    assert_eq!(info.role, "analyst");
    assert!(info.denied.contains(&"incidents:remediate".to_string()));

    // Effective permissions: triage yes, remediate no, admin powers no.
    let perms = effective_permissions(&info.role, &info.granted, &info.denied);
    assert!(perms.contains("incidents:triage"));
    assert!(!perms.contains("incidents:remediate"));
    assert!(!perms.contains("users:manage"));

    // Wrong password is rejected.
    assert!(
        auth::authenticate(&store, &email, "wrong", "ip", "ua")
            .await
            .is_err()
    );

    cleanup(&store, p).await;
}

#[tokio::test]
#[ignore]
async fn active_admin_count_tracks_status() {
    let p = "ituser_adm_";
    let store = db().await;
    cleanup(&store, p).await;

    let before = store.dbu_count_active_admins().await.unwrap();
    let id = store
        .dbu_create(&NewDashboardUser {
            email: format!("{p}admin@example.com"),
            display_name: "Admin".into(),
            role: "admin".into(),
            granted: vec![],
            denied: vec![],
            created_by: None,
        })
        .await
        .expect("create");

    // Created as 'invited' → not yet an active admin.
    assert_eq!(store.dbu_count_active_admins().await.unwrap(), before);

    // Activate → counted.
    store
        .dbu_patch(
            &id,
            &UserPatch {
                status: Some("active".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(store.dbu_count_active_admins().await.unwrap(), before + 1);

    // Disable → no longer counted.
    store
        .dbu_patch(
            &id,
            &UserPatch {
                status: Some("disabled".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(store.dbu_count_active_admins().await.unwrap(), before);

    cleanup(&store, p).await;
}
