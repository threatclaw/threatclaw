//! Integration tests for the phase 2 validators against a live PostgreSQL.
//!
//! Requires the same DATABASE_URL + migrated schema as the V38 integration
//! test. Seeds one fake MITRE technique (T9999) and one fake CVE
//! (CVE-2099-99999) into the settings table, then asserts:
//!
//! - validate_exists returns Ok for the seeded IDs.
//! - validate_exists returns UnknownIdentifier for absent IDs.
//! - validate_parsed_response produces the expected report for a mixed
//!   payload.
//!
//! Run:
//!
//!     DATABASE_URL=postgres://threatclaw:threatclaw@127.0.0.1:5432/threatclaw \
//!         cargo test --test validators_integration -- --ignored --test-threads=1

#![cfg(feature = "postgres")]

use serde_json::json;

use threatclaw::agent::validators::{
    ErrorKind, cve, mitre, validate_parsed_response,
};
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

async fn seed_fixtures(backend: &PgBackend) {
    // Seed one MITRE technique under user_id='_mitre'.
    // Must include every field of enrichment::mitre_attack::MitreTechnique
    // or the lookup_technique deserialize will silently return None.
    backend
        .set_setting(
            "_mitre",
            "T9999",
            &json!({
                "technique_id": "T9999",
                "name": "Synthetic test technique",
                "description": "For validator integration tests",
                "tactic": "Impact",
                "platform": ["Linux", "Windows"],
                "detection": "Not a real detection",
                "url": "https://attack.mitre.org/techniques/T9999/"
            }),
        )
        .await
        .expect("seed _mitre");

    // Seed one CVE under user_id='_cve_cache'.
    backend
        .set_setting(
            "_cve_cache",
            "CVE-2099-99999",
            &json!({
                "cve_id": "CVE-2099-99999",
                "cvss_score": 7.5,
                "published": "2099-01-01T00:00:00Z"
            }),
        )
        .await
        .expect("seed _cve_cache");
}

#[tokio::test]
#[ignore]
async fn mitre_existence_check_finds_seeded_technique() {
    let config = load_database_config();
    let backend = PgBackend::new(&config).await.expect("connect");
    backend.run_migrations().await.expect("migrate");
    seed_fixtures(&backend).await;

    let ok = mitre::validate_exists("mitre[0]", "T9999", &backend).await;
    assert!(ok.is_ok(), "seeded T9999 must be found");

    let err = mitre::validate_exists("mitre[0]", "T0001.999", &backend)
        .await
        .expect_err("T0001.999 must be absent");
    assert_eq!(err.kind, ErrorKind::UnknownIdentifier);
}

#[tokio::test]
#[ignore]
async fn cve_existence_check_finds_seeded_cve() {
    let config = load_database_config();
    let backend = PgBackend::new(&config).await.expect("connect");
    backend.run_migrations().await.expect("migrate");
    seed_fixtures(&backend).await;

    let ok = cve::validate_exists("cves[0]", "CVE-2099-99999", &backend).await;
    assert!(ok.is_ok(), "seeded CVE must be found");

    let err = cve::validate_exists("cves[0]", "CVE-1999-00001", &backend)
        .await
        .expect_err("unseeded CVE must be absent");
    assert_eq!(err.kind, ErrorKind::UnknownIdentifier);
}

#[tokio::test]
#[ignore]
async fn validate_parsed_response_produces_mixed_report() {
    let config = load_database_config();
    let backend = PgBackend::new(&config).await.expect("connect");
    backend.run_migrations().await.expect("migrate");
    seed_fixtures(&backend).await;

    // Crafted payload that exercises every branch:
    // - one valid MITRE ID (seeded)
    // - one malformed MITRE ID
    // - one well-formed MITRE ID that does not exist
    // - one malformed IP
    // - one valid SHA256
    // - one malformed CVE
    let parsed = json!({
        "mitre_techniques": ["T9999", "T1055.xxx", "T1234.567"],
        "cves": ["CVE-XX-YY"],
        "iocs": [
            { "type": "ip", "value": "999.999.999.999" },
            { "type": "sha256", "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
        ]
    });

    let report = validate_parsed_response(&parsed, &backend).await;

    // 3 hard errors: malformed MITRE (T1055.xxx) + malformed CVE (CVE-XX-YY) + malformed IP
    assert_eq!(
        report.errors.len(),
        3,
        "expected 3 format errors, got report={report:?}"
    );
    // 1 warning: T1234.567 well-formed but unknown in DB
    assert_eq!(
        report.warnings.len(),
        1,
        "expected 1 existence warning, got report={report:?}"
    );
}
