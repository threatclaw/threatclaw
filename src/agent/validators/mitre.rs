//! MITRE ATT&CK technique validators.
//!
//! Two layers:
//! - `validate_format` : pure sync regex check on the ID shape.
//! - `validate_exists` : async DB lookup via the enrichment module.
//!
//! Technique IDs follow the canonical shape `T####` (parent) or
//! `T####.###` (sub-technique), as documented on
//! https://attack.mitre.org/techniques/.

use std::sync::LazyLock;

use regex::Regex;

use super::{ErrorKind, ValidationError};

static MITRE_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^T\d{4}(\.\d{3})?$").expect("static regex"));

/// Validate the textual shape of a MITRE technique ID.
///
/// Returns `Ok(())` on shape match, `Err(ValidationError)` otherwise.
pub fn validate_format(field: &str, id: &str) -> Result<(), ValidationError> {
    if MITRE_ID_RE.is_match(id) {
        Ok(())
    } else {
        Err(ValidationError {
            field: field.to_string(),
            value: id.to_string(),
            kind: ErrorKind::InvalidFormat,
            message: format!(
                "{id:?} does not match the MITRE technique shape T#### or T####.###"
            ),
        })
    }
}

/// Async existence check: verify that a MITRE technique ID is present in
/// our local copy of the ATT&CK catalog (seeded via the enrichment sync).
///
/// Returns:
/// - `Ok(())` when the technique is found
/// - `Err(ValidationError { kind: UnknownIdentifier })` otherwise
///
/// Assumes `validate_format` has already passed (caller's responsibility).
pub async fn validate_exists(
    field: &str,
    id: &str,
    store: &dyn crate::db::Database,
) -> Result<(), ValidationError> {
    let found = crate::enrichment::mitre_attack::lookup_technique(store, id)
        .await
        .is_some();
    if found {
        Ok(())
    } else {
        Err(ValidationError {
            field: field.to_string(),
            value: id.to_string(),
            kind: ErrorKind::UnknownIdentifier,
            message: format!(
                "{id:?} is well-formed but not present in the local MITRE catalog. \
                 Run POST /api/tc/enrichment/mitre/sync to refresh."
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_parent_technique() {
        assert!(validate_format("mitre[0]", "T1055").is_ok());
    }

    #[test]
    fn test_accepts_sub_technique() {
        assert!(validate_format("mitre[0]", "T1055.001").is_ok());
    }

    #[test]
    fn test_rejects_missing_t_prefix() {
        let err = validate_format("mitre[0]", "1055").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidFormat);
    }

    #[test]
    fn test_rejects_lowercase_t() {
        let err = validate_format("mitre[0]", "t1055").unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidFormat);
    }

    #[test]
    fn test_rejects_wrong_digit_count() {
        assert!(validate_format("mitre[0]", "T10555").is_err());
        assert!(validate_format("mitre[0]", "T105").is_err());
    }

    #[test]
    fn test_rejects_non_numeric_suffix() {
        assert!(validate_format("mitre[0]", "T1055.xyz").is_err());
    }

    #[test]
    fn test_error_carries_field_and_value() {
        let err = validate_format("mitre_techniques[3]", "BOGUS").unwrap_err();
        assert_eq!(err.field, "mitre_techniques[3]");
        assert_eq!(err.value, "BOGUS");
    }
}
