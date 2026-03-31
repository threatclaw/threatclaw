//! ThreatClaw Branding — build identity, report signatures, STIX identity.
//!
//! Every report, export, and log entry carries ThreatClaw's identity.
//! This is both for user trust and for protecting the project's identity.

/// Build ID generated at compile time (version-date-githash).
pub const BUILD_ID: &str = env!("TC_BUILD_ID");

/// Build date (YYYYMMDD).
pub const BUILD_DATE: &str = env!("TC_BUILD_DATE");

/// Git hash at build time.
pub const BUILD_GIT: &str = env!("TC_BUILD_GIT");

/// Package version from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// STIX 2.1 Identity for ThreatClaw (used in created_by_ref).
pub const STIX_IDENTITY: &str = "identity--threatclaw-cyberconsulting-fr";

/// Full version string for display.
pub fn version_string() -> String {
    format!("ThreatClaw v{} (build {})", VERSION, BUILD_ID)
}

/// Footer for generated reports (text format).
pub fn report_footer() -> String {
    format!(
        "Genere par ThreatClaw v{}\nBuild {}\nhttps://threatclaw.io",
        VERSION, BUILD_ID
    )
}

/// Footer for Telegram/notification messages.
pub fn notification_footer() -> String {
    format!("_ThreatClaw v{} · threatclaw.io_", VERSION)
}

/// STIX 2.1 created_by_ref object.
pub fn stix_identity() -> serde_json::Value {
    serde_json::json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": STIX_IDENTITY,
        "name": "ThreatClaw",
        "description": "Autonomous cybersecurity agent for SMBs",
        "identity_class": "system",
        "created": "2026-03-24T00:00:00.000Z",
        "modified": BUILD_DATE,
        "contact_information": "https://threatclaw.io",
    })
}

/// Log the startup banner.
pub fn log_startup() {
    tracing::info!("ThreatClaw {} — build {}", VERSION, BUILD_ID);
    tracing::info!("  Git: {} | Date: {}", BUILD_GIT, BUILD_DATE);
    tracing::info!("  https://threatclaw.io | AGPL v3 + Commercial");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_string() {
        let v = version_string();
        assert!(v.contains("ThreatClaw"));
        assert!(v.contains("build"));
    }

    #[test]
    fn test_report_footer() {
        let f = report_footer();
        assert!(f.contains("threatclaw.io"));
    }

    #[test]
    fn test_stix_identity() {
        let id = stix_identity();
        assert_eq!(id["type"], "identity");
        assert_eq!(id["name"], "ThreatClaw");
    }
}
