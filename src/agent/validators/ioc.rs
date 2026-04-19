//! Network-IoC validators.
//!
//! Only formats that are cheap and unambiguous to validate in-process:
//! - IPv4 / IPv6 via std::net::IpAddr
//!
//! Domain and URL checks are intentionally NOT implemented here: domain
//! regex is a well-known rabbit hole, and we already have the enrichment
//! sources (Safe Browsing, URLScan, etc.) for semantic checks. Phase 2
//! stays within what's unambiguous.

use std::net::IpAddr;
use std::str::FromStr;

use super::{ErrorKind, ValidationError};

/// Validate that a string parses as a well-formed IPv4 or IPv6 address.
pub fn validate_ip(field: &str, ip: &str) -> Result<(), ValidationError> {
    match IpAddr::from_str(ip) {
        Ok(_) => Ok(()),
        Err(_) => Err(ValidationError {
            field: field.to_string(),
            value: ip.to_string(),
            kind: ErrorKind::Malformed,
            message: format!("{ip:?} is not a valid IPv4 or IPv6 address"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accepts_ipv4() {
        assert!(validate_ip("iocs[0]", "185.220.101.42").is_ok());
    }

    #[test]
    fn test_accepts_ipv6() {
        assert!(validate_ip("iocs[0]", "2001:db8::1").is_ok());
    }

    #[test]
    fn test_accepts_loopback() {
        assert!(validate_ip("iocs[0]", "127.0.0.1").is_ok());
        assert!(validate_ip("iocs[0]", "::1").is_ok());
    }

    #[test]
    fn test_rejects_out_of_range_octet() {
        assert!(validate_ip("iocs[0]", "999.1.1.1").is_err());
    }

    #[test]
    fn test_rejects_too_few_octets() {
        assert!(validate_ip("iocs[0]", "1.2.3").is_err());
    }

    #[test]
    fn test_rejects_bare_text() {
        let err = validate_ip("iocs[0]", "not-an-ip").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Malformed);
    }

    #[test]
    fn test_rejects_empty_string() {
        assert!(validate_ip("iocs[0]", "").is_err());
    }
}
