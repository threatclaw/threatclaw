//! Regex patterns for detecting sensitive data in LLM-bound text.
//!
//! Each pattern group has:
//! - A compiled `LazyLock<Regex>` (compiled once, thread-safe).
//! - A category tag used to generate reversible placeholders like `[IP_1]`,
//!   `[HOST_2]`, `[EMAIL_3]`.

use regex::Regex;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Internal / RFC-1918 IPv4 addresses
// ---------------------------------------------------------------------------
// Matches: 10.x.x.x, 172.16.0.0 - 172.31.255.255, 192.168.x.x
pub(crate) static RE_INTERNAL_IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2})\b",
    )
    .expect("RE_INTERNAL_IPV4 is a valid regex")
});

// ---------------------------------------------------------------------------
// IPv6 ULA (fd00::/8)
// ---------------------------------------------------------------------------
pub(crate) static RE_INTERNAL_IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bfd[0-9a-f]{2}(?::[0-9a-f]{1,4}){1,7}\b")
        .expect("RE_INTERNAL_IPV6 is a valid regex")
});

// ---------------------------------------------------------------------------
// Email addresses
// ---------------------------------------------------------------------------
pub(crate) static RE_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
        .expect("RE_EMAIL is a valid regex")
});

// ---------------------------------------------------------------------------
// Internal hostnames: *.internal, *.local, *.corp, *.lan
// ---------------------------------------------------------------------------
pub(crate) static RE_INTERNAL_HOSTNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.(?:internal|local|corp|lan)\b")
        .expect("RE_INTERNAL_HOSTNAME is a valid regex")
});

// ---------------------------------------------------------------------------
// Credential patterns: password=xxx, token=xxx, key=xxx, secret=xxx
// ---------------------------------------------------------------------------
// Matches key=value pairs where key is a credential keyword.
// The value is captured in group 2.
pub(crate) static RE_CREDENTIAL_KV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)((?:password|passwd|pwd|token|api_?key|api_?token|secret|access_?key|auth_?key|auth_?token|bearer|private_?key|client_?secret)\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)"#,
    )
    .expect("RE_CREDENTIAL_KV is a valid regex")
});

// ---------------------------------------------------------------------------
// SSH private keys
// ---------------------------------------------------------------------------
pub(crate) static RE_SSH_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    )
    .expect("RE_SSH_KEY is a valid regex")
});

// ---------------------------------------------------------------------------
// AWS access key IDs (AKIA...)
// ---------------------------------------------------------------------------
pub(crate) static RE_AWS_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b").expect("RE_AWS_KEY is a valid regex")
});

// ---------------------------------------------------------------------------
// Azure connection strings
// ---------------------------------------------------------------------------
pub(crate) static RE_AZURE_CONN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:DefaultEndpointsProtocol|AccountName|AccountKey|EndpointSuffix)\s*=\s*[^\s;]+",
    )
    .expect("RE_AZURE_CONN is a valid regex")
});

// ---------------------------------------------------------------------------
// GCP service account keys ({"type": "service_account" ...})
// ---------------------------------------------------------------------------
pub(crate) static RE_GCP_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""type"\s*:\s*"service_account""#).expect("RE_GCP_KEY is a valid regex")
});

// ---------------------------------------------------------------------------
// French phone numbers
// ---------------------------------------------------------------------------
pub(crate) static RE_FRENCH_PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\+33\s?|0)[1-9](?:[\s.\-]?\d{2}){4}\b")
        .expect("RE_FRENCH_PHONE is a valid regex")
});

// ---------------------------------------------------------------------------
// SIRET (14 digits) / SIREN (9 digits) numbers
// ---------------------------------------------------------------------------
pub(crate) static RE_SIRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b\d{3}\s?\d{3}\s?\d{3}\s?\d{5}\b").expect("RE_SIRET is a valid regex")
});

pub(crate) static RE_SIREN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{3}\s?\d{3}\s?\d{3}\b").expect("RE_SIREN is a valid regex"));

// ---------------------------------------------------------------------------
// MAC addresses (EUI-48)
// ---------------------------------------------------------------------------
pub(crate) static RE_MAC_ADDR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{2}(?:[:\-][0-9a-f]{2}){5}\b").expect("RE_MAC_ADDR is a valid regex")
});

/// Category tags for placeholder generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Category {
    Ip,
    Host,
    Email,
    Credential,
    SshKey,
    AwsKey,
    AzureConn,
    GcpKey,
    Phone,
    Siret,
    Siren,
    Mac,
    Custom(usize), // index into custom patterns
}

impl Category {
    /// Returns the prefix used in placeholders, e.g. `IP`, `HOST`.
    pub(crate) fn prefix(&self) -> String {
        match self {
            Self::Ip => "IP".to_string(),
            Self::Host => "HOST".to_string(),
            Self::Email => "EMAIL".to_string(),
            Self::Credential => "CRED".to_string(),
            Self::SshKey => "SSHKEY".to_string(),
            Self::AwsKey => "AWSKEY".to_string(),
            Self::AzureConn => "AZURECONN".to_string(),
            Self::GcpKey => "GCPKEY".to_string(),
            Self::Phone => "PHONE".to_string(),
            Self::Siret => "SIRET".to_string(),
            Self::Siren => "SIREN".to_string(),
            Self::Mac => "MAC".to_string(),
            Self::Custom(idx) => format!("CUSTOM{idx}"),
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- IP pattern tests ---

    #[test]
    fn test_internal_ipv4_10_range() {
        assert!(RE_INTERNAL_IPV4.is_match("10.0.0.1"));
        assert!(RE_INTERNAL_IPV4.is_match("10.255.255.255"));
    }

    #[test]
    fn test_internal_ipv4_172_range() {
        assert!(RE_INTERNAL_IPV4.is_match("172.16.0.1"));
        assert!(RE_INTERNAL_IPV4.is_match("172.31.255.255"));
        // 172.15 and 172.32 are NOT internal
        assert!(!RE_INTERNAL_IPV4.is_match("172.15.0.1"));
        assert!(!RE_INTERNAL_IPV4.is_match("172.32.0.1"));
    }

    #[test]
    fn test_internal_ipv4_192_range() {
        assert!(RE_INTERNAL_IPV4.is_match("192.168.0.1"));
        assert!(RE_INTERNAL_IPV4.is_match("192.168.255.255"));
    }

    #[test]
    fn test_public_ipv4_not_matched() {
        assert!(!RE_INTERNAL_IPV4.is_match("8.8.8.8"));
        assert!(!RE_INTERNAL_IPV4.is_match("1.1.1.1"));
        assert!(!RE_INTERNAL_IPV4.is_match("203.0.113.1"));
    }

    #[test]
    fn test_internal_ipv6_ula() {
        assert!(RE_INTERNAL_IPV6.is_match("fd12:3456:789a:1::1"));
        assert!(RE_INTERNAL_IPV6.is_match("fdab:cdef:0123:4567:89ab:cdef:0123:4567"));
    }

    // --- Hostname pattern tests ---

    #[test]
    fn test_internal_hostnames() {
        assert!(RE_INTERNAL_HOSTNAME.is_match("db-server.internal"));
        assert!(RE_INTERNAL_HOSTNAME.is_match("printer.local"));
        assert!(RE_INTERNAL_HOSTNAME.is_match("dc01.ad.corp"));
        assert!(RE_INTERNAL_HOSTNAME.is_match("nas.home.lan"));
    }

    #[test]
    fn test_public_hostname_not_matched() {
        assert!(!RE_INTERNAL_HOSTNAME.is_match("www.google.com"));
        assert!(!RE_INTERNAL_HOSTNAME.is_match("api.github.com"));
    }

    // --- Email pattern tests ---

    #[test]
    fn test_email_addresses() {
        assert!(RE_EMAIL.is_match("admin@example.com"));
        assert!(RE_EMAIL.is_match("john.doe+tag@sub.domain.org"));
        assert!(!RE_EMAIL.is_match("not-an-email"));
    }

    // --- Credential pattern tests ---

    #[test]
    fn test_credential_kv_patterns() {
        assert!(RE_CREDENTIAL_KV.is_match("password=s3cret123"));
        assert!(RE_CREDENTIAL_KV.is_match("API_KEY=abcdef1234"));
        assert!(RE_CREDENTIAL_KV.is_match("token: bearer_xyz"));
        assert!(RE_CREDENTIAL_KV.is_match("secret = my-secret-value"));
        assert!(RE_CREDENTIAL_KV.is_match(r#"api_token="some_value""#));
    }

    // --- SSH key pattern tests ---

    #[test]
    fn test_ssh_key_detection() {
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKC...\n-----END RSA PRIVATE KEY-----";
        assert!(RE_SSH_KEY.is_match(key));

        let ec_key = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQE...\n-----END EC PRIVATE KEY-----";
        assert!(RE_SSH_KEY.is_match(ec_key));

        let openssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r...\n-----END OPENSSH PRIVATE KEY-----";
        assert!(RE_SSH_KEY.is_match(openssh_key));
    }

    // --- AWS key pattern tests ---

    #[test]
    fn test_aws_key_detection() {
        assert!(RE_AWS_KEY.is_match("AKIAIOSFODNN7EXAMPLE"));
        assert!(RE_AWS_KEY.is_match("ASIAIOSFODNN7EXAMPLE"));
        assert!(!RE_AWS_KEY.is_match("ANPA1234567890ABCDEF")); // Not AKIA/ASIA
    }

    // --- French phone pattern tests ---

    #[test]
    fn test_french_phone_numbers() {
        assert!(RE_FRENCH_PHONE.is_match("06 12 34 56 78"));
        assert!(RE_FRENCH_PHONE.is_match("+33 6 12 34 56 78"));
        assert!(RE_FRENCH_PHONE.is_match("01.23.45.67.89"));
        assert!(RE_FRENCH_PHONE.is_match("0612345678"));
    }

    // --- MAC address tests ---

    #[test]
    fn test_mac_address() {
        assert!(RE_MAC_ADDR.is_match("aa:bb:cc:dd:ee:ff"));
        assert!(RE_MAC_ADDR.is_match("AA-BB-CC-DD-EE-FF"));
        assert!(!RE_MAC_ADDR.is_match("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ"));
    }

    // --- Azure connection string tests ---

    #[test]
    fn test_azure_connection_string() {
        assert!(RE_AZURE_CONN.is_match("AccountKey=base64encodedkey=="));
        assert!(RE_AZURE_CONN.is_match("DefaultEndpointsProtocol=https"));
    }

    // --- GCP key tests ---

    #[test]
    fn test_gcp_service_account_key() {
        assert!(RE_GCP_KEY.is_match(r#""type": "service_account""#));
        assert!(RE_GCP_KEY.is_match(r#""type":"service_account""#));
    }

    // --- Category prefix tests ---

    #[test]
    fn test_category_prefixes() {
        assert_eq!(Category::Ip.prefix(), "IP");
        assert_eq!(Category::Host.prefix(), "HOST");
        assert_eq!(Category::Email.prefix(), "EMAIL");
        assert_eq!(Category::Credential.prefix(), "CRED");
        assert_eq!(Category::SshKey.prefix(), "SSHKEY");
        assert_eq!(Category::Custom(3).prefix(), "CUSTOM3");
    }
}
