//! Hash format validators (MD5 / SHA1 / SHA256).
//!
//! Sync regex checks on canonical hex strings. Length-based discrimination:
//! - MD5    : 32 hex chars
//! - SHA1   : 40 hex chars
//! - SHA256 : 64 hex chars

use std::sync::LazyLock;

use regex::Regex;

use super::{ErrorKind, ValidationError};

static SHA256_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{64}$").expect("static regex"));
static SHA1_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{40}$").expect("static regex"));
static MD5_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{32}$").expect("static regex"));

/// Validate a SHA256 hex digest (64 chars).
pub fn validate_sha256(field: &str, h: &str) -> Result<(), ValidationError> {
    if SHA256_RE.is_match(h) {
        Ok(())
    } else {
        Err(ValidationError {
            field: field.to_string(),
            value: h.to_string(),
            kind: ErrorKind::InvalidFormat,
            message: format!("{h:?} is not a valid 64-hex SHA256 digest"),
        })
    }
}

/// Validate a SHA1 hex digest (40 chars).
pub fn validate_sha1(field: &str, h: &str) -> Result<(), ValidationError> {
    if SHA1_RE.is_match(h) {
        Ok(())
    } else {
        Err(ValidationError {
            field: field.to_string(),
            value: h.to_string(),
            kind: ErrorKind::InvalidFormat,
            message: format!("{h:?} is not a valid 40-hex SHA1 digest"),
        })
    }
}

/// Validate an MD5 hex digest (32 chars).
pub fn validate_md5(field: &str, h: &str) -> Result<(), ValidationError> {
    if MD5_RE.is_match(h) {
        Ok(())
    } else {
        Err(ValidationError {
            field: field.to_string(),
            value: h.to_string(),
            kind: ErrorKind::InvalidFormat,
            message: format!("{h:?} is not a valid 32-hex MD5 digest"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SHA256: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
    const VALID_SHA1: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
    const VALID_MD5: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

    #[test]
    fn test_sha256_accepts_valid() {
        assert!(validate_sha256("f", VALID_SHA256).is_ok());
    }

    #[test]
    fn test_sha256_accepts_uppercase() {
        assert!(validate_sha256("f", &VALID_SHA256.to_uppercase()).is_ok());
    }

    #[test]
    fn test_sha256_rejects_wrong_length() {
        assert!(validate_sha256("f", VALID_SHA1).is_err());
        assert!(validate_sha256("f", VALID_MD5).is_err());
    }

    #[test]
    fn test_sha256_rejects_non_hex() {
        let bad = "z".repeat(64);
        assert!(validate_sha256("f", &bad).is_err());
    }

    #[test]
    fn test_sha1_accepts_valid() {
        assert!(validate_sha1("f", VALID_SHA1).is_ok());
    }

    #[test]
    fn test_sha1_rejects_sha256_length() {
        assert!(validate_sha1("f", VALID_SHA256).is_err());
    }

    #[test]
    fn test_md5_accepts_valid() {
        assert!(validate_md5("f", VALID_MD5).is_ok());
    }

    #[test]
    fn test_md5_rejects_sha1_length() {
        assert!(validate_md5("f", VALID_SHA1).is_err());
    }

    #[test]
    fn test_empty_rejected_everywhere() {
        assert!(validate_sha256("f", "").is_err());
        assert!(validate_sha1("f", "").is_err());
        assert!(validate_md5("f", "").is_err());
    }
}
