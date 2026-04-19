//! CVE identifier validators.
//!
//! Two layers (parallel with mitre.rs):
//! - `validate_format` : pure sync regex check.
//! - `validate_exists` : async DB lookup against the local CVE cache.
//!
//! CVE IDs follow the shape `CVE-YYYY-N{4,}` per MITRE's numbering
//! convention. The year is 4 digits; the sequence is at least 4 digits
//! but can be longer (CVE-2023-100000+ exists).

use std::sync::LazyLock;

use regex::Regex;

use super::{ErrorKind, ValidationError};

static CVE_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^CVE-\d{4}-\d{4,}$").expect("static regex"));

/// Validate the textual shape of a CVE identifier.
pub fn validate_format(field: &str, id: &str) -> Result<(), ValidationError> {
    if CVE_ID_RE.is_match(id) {
        Ok(())
    } else {
        Err(ValidationError {
            field: field.to_string(),
            value: id.to_string(),
            kind: ErrorKind::InvalidFormat,
            message: format!("{id:?} does not match CVE-YYYY-NNNN shape"),
        })
    }
}

/// Async existence check against the local CVE cache (settings scope
/// `user_id='_cve_cache'`, seeded by NVD lookups over time).
///
/// Returns:
/// - `Ok(())` on hit
/// - `Err(ValidationError { kind: UnknownIdentifier })` on miss
///
/// **Important caveat**: an `Err` here is NOT proof that the CVE does not
/// exist — it may simply not have been queried yet. Callers should treat
/// this as a warning rather than a blocking error.
pub async fn validate_exists(
    field: &str,
    id: &str,
    store: &dyn crate::db::Database,
) -> Result<(), ValidationError> {
    let cached = store.get_setting("_cve_cache", id).await.ok().flatten();
    if cached.is_some() {
        Ok(())
    } else {
        Err(ValidationError {
            field: field.to_string(),
            value: id.to_string(),
            kind: ErrorKind::UnknownIdentifier,
            message: format!(
                "{id:?} is well-formed but absent from the local CVE cache. \
                 Note: this only means NVD has not been queried for this ID yet."
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_standard_cve() {
        assert!(validate_format("cves[0]", "CVE-2021-44228").is_ok());
    }

    #[test]
    fn test_accepts_six_digit_sequence() {
        assert!(validate_format("cves[0]", "CVE-2023-123456").is_ok());
    }

    #[test]
    fn test_rejects_short_sequence() {
        assert!(validate_format("cves[0]", "CVE-2023-001").is_err());
    }

    #[test]
    fn test_rejects_short_year() {
        assert!(validate_format("cves[0]", "CVE-21-00001").is_err());
    }

    #[test]
    fn test_rejects_lowercase() {
        assert!(validate_format("cves[0]", "cve-2021-44228").is_err());
    }

    #[test]
    fn test_rejects_trailing_whitespace() {
        assert!(validate_format("cves[0]", "CVE-2021-44228 ").is_err());
    }
}
