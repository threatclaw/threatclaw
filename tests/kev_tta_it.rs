//! CISA KEV time-to-alert integration. See roadmap §3.5.
//!
//! Verifies that record_kev_observation is idempotent, GENERATED
//! tta_ingest_sec fires when a publish date is supplied, and the
//! aggregate view returns the expected shape.

#![cfg(feature = "postgres")]

use threatclaw::config::DatabaseConfig;
use threatclaw::db::postgres::PgBackend;
use threatclaw::db::threatclaw_store::ThreatClawStore;

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

async fn cleanup(store: &PgBackend, cve: &str) {
    let conn = store.pool().get().await.expect("pool");
    conn.execute("DELETE FROM cve_exposure_alerts WHERE cve_id = $1", &[&cve])
        .await
        .ok();
}

#[tokio::test]
#[ignore]
async fn record_observation_is_idempotent() {
    let store = backend().await;
    let cve = "IT-CVE-2099-TEST-001";
    cleanup(&store, cve).await;

    let published = Some(chrono::Utc::now() - chrono::Duration::hours(2));

    let first = store
        .record_kev_observation(cve, published)
        .await
        .expect("record 1");
    assert!(first, "first call should insert");

    let second = store
        .record_kev_observation(cve, published)
        .await
        .expect("record 2");
    assert!(!second, "second call must be no-op (ON CONFLICT)");

    cleanup(&store, cve).await;
}

#[tokio::test]
#[ignore]
async fn first_match_sets_tta_alert() {
    let store = backend().await;
    let cve = "IT-CVE-2099-TEST-002";
    cleanup(&store, cve).await;
    let published = Some(chrono::Utc::now() - chrono::Duration::minutes(45));
    store
        .record_kev_observation(cve, published)
        .await
        .expect("observe");

    store
        .record_kev_first_match(cve, None)
        .await
        .expect("match");

    // Second match is a no-op thanks to COALESCE.
    store
        .record_kev_first_match(cve, None)
        .await
        .expect("match again");

    let conn = store.pool().get().await.expect("pool");
    let row = conn
        .query_one(
            "SELECT tta_alert_sec, tta_ingest_sec, first_asset_match_at
               FROM cve_exposure_alerts WHERE cve_id = $1",
            &[&cve],
        )
        .await
        .expect("select");
    let tta_alert: Option<i32> = row.get(0);
    let tta_ingest: Option<i32> = row.get(1);
    assert!(
        tta_alert.unwrap_or(0) > 0,
        "tta_alert_sec should be populated"
    );
    assert!(
        tta_ingest.unwrap_or(0) > 0,
        "tta_ingest_sec should be populated (pub date in the past)"
    );

    cleanup(&store, cve).await;
}

#[tokio::test]
#[ignore]
async fn metrics_view_returns_shape() {
    let store = backend().await;
    let m = store.kev_tta_metrics().await.expect("metrics");
    assert!(m.get("matched_count").is_some());
    assert!(m.get("observed_count").is_some());
    assert!(m.get("tta_alert_p50_sec").is_some());
}
