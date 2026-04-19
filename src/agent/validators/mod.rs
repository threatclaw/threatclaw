//! Typed validators for LLM output claims (phase 2 v1.1.0-beta).
//!
//! Each sub-module exposes format-check functions (pure, sync) and — where
//! applicable — existence-check functions (async, require a `Database` ref).
//!
//! Validation is controlled by [`ValidationMode`] from phase 0:
//! - `Off`     : no validation runs
//! - `Lenient` : validation runs, report is logged, verdict kept as-is
//! - `Strict`  : validation runs, report is logged, phase 3 reconciler will
//!               downgrade the verdict if blocking errors were found
//!
//! Phase 2 does NOT modify the verdict — it only produces the report.

pub mod cve;
pub mod hash;
pub mod ioc;
pub mod mitre;

use serde::{Deserialize, Serialize};

/// A single validation issue (error or warning).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationError {
    /// Source field where the invalid value was found (ex: "mitre_techniques[2]").
    pub field: String,
    /// The offending value (for log + debug).
    pub value: String,
    /// Machine-readable error kind.
    pub kind: ErrorKind,
    /// Human-readable message.
    pub message: String,
}

/// Error severity/kind taxonomy. Mapped to ValidationReport buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// Format regex or type mismatch (ex: T1055.999 has wrong shape).
    InvalidFormat,
    /// Format is valid but the identifier is unknown in our reference DB.
    UnknownIdentifier,
    /// Identifier is self-inconsistent (ex: IP 999.999.999.999).
    Malformed,
}

/// Aggregated report produced by `validate_parsed_response`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationReport {
    /// Hard errors: format violations or known-bad values.
    pub errors: Vec<ValidationError>,
    /// Soft warnings: unknown but well-formed identifiers (phase 2 treats
    /// these as non-blocking; phase 3 reconciler may consider them).
    pub warnings: Vec<ValidationError>,
}

impl ValidationReport {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty() && self.warnings.is_empty()
    }

    pub fn has_blocking_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn push_error(&mut self, err: ValidationError) {
        self.errors.push(err);
    }

    pub fn push_warning(&mut self, warn: ValidationError) {
        self.warnings.push(warn);
    }

    /// Merge two reports (used when validating multiple fields).
    pub fn merge(&mut self, other: ValidationReport) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
    }
}

/// Run all relevant validators on a parsed LLM response object.
///
/// Scans the following fields (if present):
/// - `mitre_techniques`  : array of strings → format + existence
/// - `cves`              : array of strings → format + existence (warnings)
/// - `iocs`              : array of {type, value} → per-type format check
///
/// Format violations go to `errors`. Existence misses go to `warnings`
/// (per phase-2 design: not our job to say the CVE is fabricated, just
/// to flag "we didn't verify this").
///
/// Returns a `ValidationReport` (never errors out — validation collects,
/// it does not propagate).
pub async fn validate_parsed_response(
    parsed: &serde_json::Value,
    store: &dyn crate::db::Database,
) -> ValidationReport {
    let mut report = ValidationReport::default();

    // MITRE techniques
    if let Some(arr) = parsed.get("mitre_techniques").and_then(|v| v.as_array()) {
        for (i, item) in arr.iter().enumerate() {
            let field = format!("mitre_techniques[{i}]");
            if let Some(id) = item.as_str() {
                match mitre::validate_format(&field, id) {
                    Ok(()) => {
                        if let Err(e) = mitre::validate_exists(&field, id, store).await {
                            report.push_warning(e);
                        }
                    }
                    Err(e) => report.push_error(e),
                }
            } else {
                report.push_error(ValidationError {
                    field,
                    value: item.to_string(),
                    kind: ErrorKind::InvalidFormat,
                    message: "mitre_technique entry is not a string".into(),
                });
            }
        }
    }

    // CVEs
    if let Some(arr) = parsed.get("cves").and_then(|v| v.as_array()) {
        for (i, item) in arr.iter().enumerate() {
            let field = format!("cves[{i}]");
            if let Some(id) = item.as_str() {
                match cve::validate_format(&field, id) {
                    Ok(()) => {
                        if let Err(e) = cve::validate_exists(&field, id, store).await {
                            report.push_warning(e);
                        }
                    }
                    Err(e) => report.push_error(e),
                }
            } else {
                report.push_error(ValidationError {
                    field,
                    value: item.to_string(),
                    kind: ErrorKind::InvalidFormat,
                    message: "cve entry is not a string".into(),
                });
            }
        }
    }

    // IoCs (array of { type, value })
    if let Some(arr) = parsed.get("iocs").and_then(|v| v.as_array()) {
        for (i, item) in arr.iter().enumerate() {
            let field = format!("iocs[{i}]");
            let ioc_type = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let ioc_value = item.get("value").and_then(|v| v.as_str()).unwrap_or("");
            let result = match ioc_type {
                "ip" => ioc::validate_ip(&field, ioc_value),
                "sha256" => hash::validate_sha256(&field, ioc_value),
                "sha1" => hash::validate_sha1(&field, ioc_value),
                "md5" => hash::validate_md5(&field, ioc_value),
                // For domain/url/email we do not enforce format in phase 2
                // (see comments in ioc.rs). Skip cleanly.
                _ => Ok(()),
            };
            if let Err(e) = result {
                report.push_error(e);
            }
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_report_is_clean() {
        let r = ValidationReport::default();
        assert!(r.is_clean());
        assert!(!r.has_blocking_errors());
    }

    #[test]
    fn test_push_error_flips_blocking() {
        let mut r = ValidationReport::default();
        r.push_error(ValidationError {
            field: "mitre_techniques[0]".into(),
            value: "T1055.999".into(),
            kind: ErrorKind::UnknownIdentifier,
            message: "not in DB".into(),
        });
        assert!(!r.is_clean());
        assert!(r.has_blocking_errors());
        assert_eq!(r.errors.len(), 1);
    }

    #[test]
    fn test_push_warning_does_not_flip_blocking() {
        let mut r = ValidationReport::default();
        r.push_warning(ValidationError {
            field: "cves[0]".into(),
            value: "CVE-2099-99999".into(),
            kind: ErrorKind::UnknownIdentifier,
            message: "not in cache".into(),
        });
        assert!(!r.is_clean());
        assert!(!r.has_blocking_errors());
        assert_eq!(r.warnings.len(), 1);
    }

    #[test]
    fn test_merge_combines_buckets() {
        let mut a = ValidationReport::default();
        a.push_error(ValidationError {
            field: "a".into(),
            value: "x".into(),
            kind: ErrorKind::InvalidFormat,
            message: "msg".into(),
        });
        let mut b = ValidationReport::default();
        b.push_warning(ValidationError {
            field: "b".into(),
            value: "y".into(),
            kind: ErrorKind::UnknownIdentifier,
            message: "msg".into(),
        });
        a.merge(b);
        assert_eq!(a.errors.len(), 1);
        assert_eq!(a.warnings.len(), 1);
    }
}
