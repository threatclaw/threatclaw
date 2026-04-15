//! MAC OUI Lookup — identify device manufacturer from MAC address.
//!
//! Uses the mac_oui crate with embedded IEEE OUI database.
//! Loads once at first use, then instant lookups.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

static OUI_DB: OnceLock<Option<mac_oui::Oui>> = OnceLock::new();

fn get_db() -> &'static Option<mac_oui::Oui> {
    OUI_DB.get_or_init(|| {
        // Try loading from the crate's bundled CSV
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let csv_paths = [
            format!("{}/assets/oui.csv", manifest_dir),
            "assets/oui.csv".into(),
            "/usr/share/threatclaw/oui.csv".into(),
        ];
        let result = csv_paths
            .iter()
            .filter_map(|p| mac_oui::Oui::from_csv_file(p.as_str()).ok())
            .next();
        match result {
            Some(db) => {
                tracing::info!("MAC OUI: Loaded {} records", db.get_total_records());
                Some(db)
            }
            None => {
                tracing::warn!("MAC OUI: No OUI database found");
                None
            }
        }
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacVendorResult {
    pub mac: String,
    pub vendor: Option<String>,
    pub country: Option<String>,
}

/// Lookup the manufacturer/vendor from a MAC address.
/// Accepts formats: "00:1A:2B:3C:4D:5E", "00-1A-2B-3C-4D-5E"
pub fn lookup(mac: &str) -> MacVendorResult {
    let clean = mac.replace('-', ":").to_uppercase();

    if let Some(db) = get_db() {
        match db.lookup_by_mac(&clean) {
            Ok(Some(entry)) => MacVendorResult {
                mac: clean,
                vendor: Some(entry.company_name.clone()),
                country: Some(entry.country_code.clone()),
            },
            _ => MacVendorResult {
                mac: clean,
                vendor: None,
                country: None,
            },
        }
    } else {
        MacVendorResult {
            mac: clean,
            vendor: None,
            country: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_no_panic() {
        let r = lookup("00:1A:2B:3C:4D:5E");
        assert_eq!(r.mac, "00:1A:2B:3C:4D:5E");
    }

    #[test]
    fn test_dash_format() {
        let r = lookup("00-1A-2B-3C-4D-5E");
        assert_eq!(r.mac, "00:1A:2B:3C:4D:5E");
    }
}
