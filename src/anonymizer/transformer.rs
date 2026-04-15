//! LLM anonymizer — reversible placeholder substitution. See ADR-021.

use std::collections::HashMap;

use regex::Regex;

use crate::anonymizer::patterns::{
    Category, RE_AWS_KEY, RE_AZURE_CONN, RE_CREDENTIAL_KV, RE_EMAIL, RE_FRENCH_PHONE, RE_GCP_KEY,
    RE_INTERNAL_HOSTNAME, RE_INTERNAL_IPV4, RE_INTERNAL_IPV6, RE_MAC_ADDR, RE_SIREN, RE_SIRET,
    RE_SSH_KEY,
};

// =========================================================================
// Public types
// =========================================================================

/// Configuration knobs for the anonymizer, one flag per sensitive-data family.
#[derive(Debug, Clone)]
pub struct AnonymizeConfig {
    /// Master switch.
    pub enabled: bool,
    pub strip_internal_ips: bool,
    pub strip_usernames: bool,
    pub strip_credentials: bool,
    pub strip_hostnames: bool,
    pub strip_emails: bool,
    pub strip_phone_numbers: bool,
    /// Extra `(regex_source, replacement_prefix)` pairs provided by the user.
    pub custom_patterns: Vec<(String, String)>,
}

impl Default for AnonymizeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strip_internal_ips: true,
            strip_usernames: true,
            strip_credentials: true,
            strip_hostnames: true,
            strip_emails: true,
            strip_phone_numbers: true,
            custom_patterns: Vec::new(),
        }
    }
}

/// The result of anonymizing a piece of text.
#[derive(Debug, Clone)]
pub struct AnonymizeResult {
    /// The anonymized text with placeholders.
    pub text: String,
    /// Reverse mapping: placeholder -> original value (e.g. `[IP_1]` -> `192.168.1.1`).
    pub mapping: HashMap<String, String>,
    /// Aggregate statistics.
    pub stats: AnonymizeStats,
}

/// Counters for each category of redacted data.
#[derive(Debug, Clone, Default)]
pub struct AnonymizeStats {
    pub ips_redacted: usize,
    pub hostnames_redacted: usize,
    pub credentials_redacted: usize,
    pub emails_redacted: usize,
    pub phones_redacted: usize,
    pub cloud_keys_redacted: usize,
    pub mac_addresses_redacted: usize,
    pub custom_redacted: usize,
    pub total_redactions: usize,
}

// =========================================================================
// Anonymizer
// =========================================================================

/// Thread-safe, stateless anonymizer.
///
/// All mutable state (the entity-to-placeholder mapping) lives in the
/// per-call [`AnonymizeResult`], so the struct itself is `Send + Sync`.
pub struct Anonymizer {
    config: AnonymizeConfig,
    /// Compiled custom regexes (built once at construction time).
    custom_regexes: Vec<(Regex, String)>,
}

impl Anonymizer {
    /// Create a new anonymizer from an [`AnonymizeConfig`].
    pub fn new(config: AnonymizeConfig) -> Self {
        let custom_regexes = config
            .custom_patterns
            .iter()
            .filter_map(|(pat, prefix)| Regex::new(pat).ok().map(|re| (re, prefix.clone())))
            .collect();
        Self {
            config,
            custom_regexes,
        }
    }

    /// Build an [`Anonymizer`] from the `[anonymizer]` section of a TOML file.
    ///
    /// Missing keys fall back to [`AnonymizeConfig::default`].
    pub fn from_toml_config(value: &toml::Value) -> Self {
        let get_bool = |key: &str, default: bool| -> bool {
            value.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
        };

        let config = AnonymizeConfig {
            enabled: get_bool("enabled", true),
            strip_internal_ips: get_bool("strip_internal_ips", true),
            strip_usernames: get_bool("strip_usernames", true),
            strip_credentials: get_bool("strip_credentials", true),
            strip_hostnames: get_bool("strip_hostnames", true),
            strip_emails: get_bool("strip_emails", true),
            strip_phone_numbers: get_bool("strip_phone_numbers", true),
            custom_patterns: Vec::new(),
        };
        Self::new(config)
    }

    /// Returns `true` if the anonymizer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Anonymize `text`, returning the redacted text together with the
    /// reverse mapping and statistics.
    ///
    /// Replacement order is deterministic:
    /// 1. SSH keys (longest matches first to avoid partial hits)
    /// 2. Cloud provider keys (AWS, Azure, GCP)
    /// 3. Credential key=value pairs
    /// 4. Internal IPs (v4 + v6)
    /// 5. Internal hostnames
    /// 6. Email addresses
    /// 7. Phone numbers, SIRET/SIREN, MAC addresses
    /// 8. Custom patterns
    pub fn anonymize(&self, text: &str) -> AnonymizeResult {
        if !self.config.enabled {
            return AnonymizeResult {
                text: text.to_string(),
                mapping: HashMap::new(),
                stats: AnonymizeStats::default(),
            };
        }

        let mut ctx = ReplaceContext::new(text.to_string());

        // --- 1. SSH keys (multi-line, do first) ---
        if self.config.strip_credentials {
            ctx.replace_all(&RE_SSH_KEY, Category::SshKey);
        }

        // --- 2. Cloud provider keys ---
        if self.config.strip_credentials {
            ctx.replace_all(&RE_AWS_KEY, Category::AwsKey);
            ctx.replace_all(&RE_AZURE_CONN, Category::AzureConn);
            ctx.replace_all(&RE_GCP_KEY, Category::GcpKey);
        }

        // --- 3. Credential key=value pairs ---
        if self.config.strip_credentials {
            ctx.replace_credential_kv();
        }

        // --- 4. Internal IPs ---
        if self.config.strip_internal_ips {
            ctx.replace_all(&RE_INTERNAL_IPV4, Category::Ip);
            ctx.replace_all(&RE_INTERNAL_IPV6, Category::Ip);
        }

        // --- 5. Internal hostnames ---
        if self.config.strip_hostnames {
            ctx.replace_all(&RE_INTERNAL_HOSTNAME, Category::Host);
        }

        // --- 6. Emails ---
        if self.config.strip_emails {
            ctx.replace_all(&RE_EMAIL, Category::Email);
        }

        // --- 7. Phone numbers, SIRET/SIREN, MAC ---
        if self.config.strip_phone_numbers {
            ctx.replace_all(&RE_FRENCH_PHONE, Category::Phone);
            ctx.replace_all(&RE_SIRET, Category::Siret);
            ctx.replace_all(&RE_SIREN, Category::Siren);
        }

        if self.config.strip_internal_ips {
            // MAC addresses are network identifiers, group with IPs
            ctx.replace_all(&RE_MAC_ADDR, Category::Mac);
        }

        // --- 8. Custom patterns ---
        for (idx, (re, _prefix)) in self.custom_regexes.iter().enumerate() {
            ctx.replace_all(re, Category::Custom(idx));
        }

        // Build stats
        let stats = ctx.build_stats();
        let mapping = ctx.build_reverse_mapping();

        AnonymizeResult {
            text: ctx.text,
            mapping,
            stats,
        }
    }

    /// Reverse the anonymization: replace every `[TAG_N]` placeholder in
    /// `text` with the original value from `mapping`.
    pub fn deanonymize(&self, text: &str, mapping: &HashMap<String, String>) -> String {
        let mut result = text.to_string();
        for (placeholder, original) in mapping {
            result = result.replace(placeholder.as_str(), original);
        }
        result
    }
}

// =========================================================================
// Internal replacement context
// =========================================================================

/// Per-call mutable state used during a single `anonymize()` invocation.
struct ReplaceContext {
    text: String,
    /// Maps an original value to its placeholder (e.g. "192.168.1.1" -> "[IP_1]").
    value_to_placeholder: HashMap<String, String>,
    /// Per-category counter for numbering placeholders.
    category_counters: HashMap<String, usize>,
}

impl ReplaceContext {
    fn new(text: String) -> Self {
        Self {
            text,
            value_to_placeholder: HashMap::new(),
            category_counters: HashMap::new(),
        }
    }

    /// Get or create a placeholder for `original` in the given category.
    fn placeholder_for(&mut self, original: &str, category: Category) -> String {
        if let Some(existing) = self.value_to_placeholder.get(original) {
            return existing.clone();
        }
        let prefix = category.prefix();
        let counter = self.category_counters.entry(prefix.clone()).or_insert(0);
        *counter += 1;
        let placeholder = format!("[{prefix}_{counter}]");
        self.value_to_placeholder
            .insert(original.to_string(), placeholder.clone());
        placeholder
    }

    /// Replace all non-overlapping matches of `re` in the current text.
    fn replace_all(&mut self, re: &Regex, category: Category) {
        // Collect matches first to avoid borrow issues.
        let matches: Vec<String> = re
            .find_iter(&self.text)
            .map(|m| m.as_str().to_string())
            .collect();

        for matched in matches {
            let placeholder = self.placeholder_for(&matched, category);
            self.text = self.text.replace(&matched, &placeholder);
        }
    }

    /// Special handling for credential key=value pairs: we keep the key
    /// visible but redact only the value portion.
    fn replace_credential_kv(&mut self) {
        // Collect (full_match, key_part, value_part) triples.
        let captures: Vec<(String, String, String)> = RE_CREDENTIAL_KV
            .captures_iter(&self.text)
            .map(|cap| (cap[0].to_string(), cap[1].to_string(), cap[2].to_string()))
            .collect();

        for (full_match, key_part, value_part) in captures {
            let placeholder = self.placeholder_for(&value_part, Category::Credential);
            let replacement = format!("{key_part}{placeholder}");
            self.text = self.text.replace(&full_match, &replacement);
        }
    }

    /// Build the reverse mapping (placeholder -> original).
    fn build_reverse_mapping(&self) -> HashMap<String, String> {
        self.value_to_placeholder
            .iter()
            .map(|(orig, ph)| (ph.clone(), orig.clone()))
            .collect()
    }

    /// Compute aggregate statistics from the value map.
    fn build_stats(&self) -> AnonymizeStats {
        let mut stats = AnonymizeStats::default();

        for placeholder in self.value_to_placeholder.values() {
            stats.total_redactions += 1;

            if placeholder.starts_with("[IP_") {
                stats.ips_redacted += 1;
            } else if placeholder.starts_with("[HOST_") {
                stats.hostnames_redacted += 1;
            } else if placeholder.starts_with("[EMAIL_") {
                stats.emails_redacted += 1;
            } else if placeholder.starts_with("[CRED_") || placeholder.starts_with("[SSHKEY_") {
                stats.credentials_redacted += 1;
            } else if placeholder.starts_with("[AWSKEY_")
                || placeholder.starts_with("[AZURECONN_")
                || placeholder.starts_with("[GCPKEY_")
            {
                stats.cloud_keys_redacted += 1;
            } else if placeholder.starts_with("[PHONE_")
                || placeholder.starts_with("[SIRET_")
                || placeholder.starts_with("[SIREN_")
            {
                stats.phones_redacted += 1;
            } else if placeholder.starts_with("[MAC_") {
                stats.mac_addresses_redacted += 1;
            } else if placeholder.starts_with("[CUSTOM") {
                stats.custom_redacted += 1;
            }
        }

        stats
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_anonymizer() -> Anonymizer {
        Anonymizer::new(AnonymizeConfig::default())
    }

    // --- Basic anonymization ---

    #[test]
    fn test_basic_ip_anonymization() {
        let anon = default_anonymizer();
        let result = anon.anonymize("Server at 192.168.1.1 is down");
        assert!(!result.text.contains("192.168.1.1"));
        assert!(result.text.contains("[IP_"));
        assert_eq!(result.stats.ips_redacted, 1);
        assert_eq!(result.stats.total_redactions, 1);
    }

    #[test]
    fn test_basic_hostname_anonymization() {
        let anon = default_anonymizer();
        let result = anon.anonymize("Connect to db-primary.internal on port 5432");
        assert!(!result.text.contains("db-primary.internal"));
        assert!(result.text.contains("[HOST_"));
        assert_eq!(result.stats.hostnames_redacted, 1);
    }

    #[test]
    fn test_basic_email_anonymization() {
        let anon = default_anonymizer();
        let result = anon.anonymize("Contact admin@cyberconsulting.fr for access");
        assert!(!result.text.contains("admin@cyberconsulting.fr"));
        assert!(result.text.contains("[EMAIL_"));
        assert_eq!(result.stats.emails_redacted, 1);
    }

    #[test]
    fn test_basic_credential_anonymization() {
        let anon = default_anonymizer();
        let result = anon.anonymize("Set password=hunter2 in config");
        assert!(!result.text.contains("hunter2"));
        assert!(result.text.contains("[CRED_"));
        // The key "password=" is preserved for context.
        assert!(result.text.contains("password="));
        assert_eq!(result.stats.credentials_redacted, 1);
    }

    // --- De-anonymization roundtrip ---

    #[test]
    fn test_deanonymize_roundtrip() {
        let anon = default_anonymizer();
        let original = "Server 10.0.0.5 has alert from admin@corp.local";
        let result = anon.anonymize(original);

        // Text should not contain originals
        assert!(!result.text.contains("10.0.0.5"));
        assert!(!result.text.contains("admin@corp.local"));

        // De-anonymize should restore them
        let restored = anon.deanonymize(&result.text, &result.mapping);
        assert!(restored.contains("10.0.0.5"));
        assert!(restored.contains("admin@corp.local"));
    }

    // --- Config flags respected ---

    #[test]
    fn test_disabled_anonymizer() {
        let config = AnonymizeConfig {
            enabled: false,
            ..Default::default()
        };
        let anon = Anonymizer::new(config);
        let text = "password=secret 192.168.1.1";
        let result = anon.anonymize(text);
        assert_eq!(result.text, text);
        assert!(result.mapping.is_empty());
    }

    #[test]
    fn test_ips_disabled() {
        let config = AnonymizeConfig {
            strip_internal_ips: false,
            ..Default::default()
        };
        let anon = Anonymizer::new(config);
        let result = anon.anonymize("Host 192.168.0.1 is up");
        assert!(
            result.text.contains("192.168.0.1"),
            "IP should remain when strip_internal_ips=false"
        );
        assert_eq!(result.stats.ips_redacted, 0);
    }

    #[test]
    fn test_credentials_disabled() {
        let config = AnonymizeConfig {
            strip_credentials: false,
            ..Default::default()
        };
        let anon = Anonymizer::new(config);
        let result = anon.anonymize("password=hunter2 token=abc123");
        assert!(result.text.contains("hunter2"));
        assert!(result.text.contains("abc123"));
    }

    // --- Consistent numbering ---

    #[test]
    fn test_consistent_numbering() {
        let anon = default_anonymizer();
        let text = "IP 10.1.1.1 then 10.2.2.2 then 10.1.1.1 again";
        let result = anon.anonymize(text);

        // 10.1.1.1 should always map to the same placeholder
        let ph1 = result
            .mapping
            .iter()
            .find(|(_, v)| v.as_str() == "10.1.1.1")
            .map(|(k, _)| k.clone())
            .expect("10.1.1.1 should be in mapping");

        // Count occurrences of this placeholder in the text
        let count = result.text.matches(&ph1).count();
        assert_eq!(count, 2, "Same IP should use the same placeholder");

        // Two distinct IPs -> two distinct placeholders
        assert_eq!(result.stats.ips_redacted, 2);
    }

    // --- Multiple entity types ---

    #[test]
    fn test_multiple_entity_types() {
        let anon = default_anonymizer();
        let text = "Server 10.0.0.1 host db.local email admin@test.com password=x";
        let result = anon.anonymize(text);

        assert!(!result.text.contains("10.0.0.1"));
        assert!(!result.text.contains("db.local"));
        assert!(!result.text.contains("admin@test.com"));
        // "x" is the password value
        assert!(result.text.contains("[CRED_"));
        assert!(result.text.contains("[IP_"));
        assert!(result.text.contains("[HOST_"));
        assert!(result.text.contains("[EMAIL_"));

        assert!(result.stats.total_redactions >= 4);
    }

    // --- No false positives on public IPs ---

    #[test]
    fn test_no_false_positive_public_ips() {
        let anon = default_anonymizer();
        let text = "DNS 8.8.8.8 and 1.1.1.1 are public resolvers";
        let result = anon.anonymize(text);
        assert_eq!(result.text, text, "Public IPs should not be redacted");
        assert_eq!(result.stats.ips_redacted, 0);
    }

    // --- Empty input ---

    #[test]
    fn test_empty_input() {
        let anon = default_anonymizer();
        let result = anon.anonymize("");
        assert_eq!(result.text, "");
        assert!(result.mapping.is_empty());
        assert_eq!(result.stats.total_redactions, 0);
    }

    // --- SSH key detection ---

    #[test]
    fn test_ssh_key_redaction() {
        let anon = default_anonymizer();
        let text = "Key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\nEnd";
        let result = anon.anonymize(text);
        assert!(!result.text.contains("BEGIN RSA PRIVATE KEY"));
        assert!(result.text.contains("[SSHKEY_"));
        assert_eq!(result.stats.credentials_redacted, 1);
    }

    // --- AWS key detection ---

    #[test]
    fn test_aws_key_redaction() {
        let anon = default_anonymizer();
        let result = anon.anonymize("aws_key=AKIAIOSFODNN7EXAMPLE");
        assert!(!result.text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(result.stats.cloud_keys_redacted, 1);
    }

    // --- Custom patterns ---

    #[test]
    fn test_custom_patterns() {
        let config = AnonymizeConfig {
            custom_patterns: vec![(r"TICKET-\d+".to_string(), "TICKET".to_string())],
            ..Default::default()
        };
        let anon = Anonymizer::new(config);
        let result = anon.anonymize("See TICKET-1234 for details");
        assert!(!result.text.contains("TICKET-1234"));
        assert!(result.text.contains("[CUSTOM0_"));
        assert_eq!(result.stats.custom_redacted, 1);
    }

    // --- French phone numbers ---

    #[test]
    fn test_french_phone_redaction() {
        let anon = default_anonymizer();
        let result = anon.anonymize("Call 06 12 34 56 78 or +33 1 23 45 67 89");
        assert!(!result.text.contains("06 12 34 56 78"));
        assert!(!result.text.contains("+33 1 23 45 67 89"));
        assert_eq!(result.stats.phones_redacted, 2);
    }

    // --- MAC address ---

    #[test]
    fn test_mac_address_redaction() {
        let anon = default_anonymizer();
        let result = anon.anonymize("NIC aa:bb:cc:dd:ee:ff is down");
        assert!(!result.text.contains("aa:bb:cc:dd:ee:ff"));
        assert!(result.text.contains("[MAC_"));
    }

    // --- from_toml_config ---

    #[test]
    fn test_from_toml_config() {
        let toml_str = r#"
            enabled = true
            strip_internal_ips = true
            strip_usernames = true
            strip_credentials = false
            strip_hostnames = true
        "#;
        let value: toml::Value = toml_str.parse().unwrap();
        let anon = Anonymizer::from_toml_config(&value);
        assert!(anon.is_enabled());
        assert!(!anon.config.strip_credentials);
        assert!(anon.config.strip_internal_ips);
    }

    #[test]
    fn test_from_toml_config_defaults() {
        let value: toml::Value = "".parse().unwrap();
        let anon = Anonymizer::from_toml_config(&value);
        // All defaults should be true
        assert!(anon.is_enabled());
        assert!(anon.config.strip_internal_ips);
        assert!(anon.config.strip_credentials);
    }

    // --- Integration test: mixed sensitive data ---

    #[test]
    fn test_integration_mixed_sensitive_data() {
        let anon = default_anonymizer();

        let text = concat!(
            "ALERT: Intrusion detected on 192.168.10.5 (db-master.internal)\n",
            "Source: 10.0.0.42, MAC: de:ad:be:ef:ca:fe\n",
            "Attacker email: hacker@evil.com\n",
            "Compromised credentials found: password=P@ssw0rd! api_key=sk-proj-abc123\n",
            "SSH key found:\n",
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIEowIBAAKCAQEAtestkey\n",
            "-----END RSA PRIVATE KEY-----\n",
            "AWS key: AKIAIOSFODNN7EXAMPLE\n",
            "Contact SOC: +33 1 44 55 66 77\n",
            "Public IOC IP (keep): 203.0.113.50\n",
        );

        let result = anon.anonymize(text);

        // Sensitive data should be gone
        assert!(!result.text.contains("192.168.10.5"));
        assert!(!result.text.contains("db-master.internal"));
        assert!(!result.text.contains("10.0.0.42"));
        assert!(!result.text.contains("de:ad:be:ef:ca:fe"));
        assert!(!result.text.contains("hacker@evil.com"));
        assert!(!result.text.contains("P@ssw0rd!"));
        assert!(!result.text.contains("sk-proj-abc123"));
        assert!(!result.text.contains("BEGIN RSA PRIVATE KEY"));
        assert!(!result.text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!result.text.contains("+33 1 44 55 66 77"));

        // Public IPs should remain
        assert!(result.text.contains("203.0.113.50"));

        // Structure should be preserved
        assert!(result.text.contains("ALERT: Intrusion detected on"));
        assert!(result.text.contains("password="));

        // Placeholders should be present
        assert!(result.text.contains("[IP_"));
        assert!(result.text.contains("[HOST_"));
        assert!(result.text.contains("[EMAIL_"));
        assert!(result.text.contains("[CRED_"));
        assert!(result.text.contains("[SSHKEY_"));
        assert!(result.text.contains("[AWSKEY_"));
        assert!(result.text.contains("[MAC_"));
        assert!(result.text.contains("[PHONE_"));

        // Verify roundtrip
        let restored = anon.deanonymize(&result.text, &result.mapping);
        assert!(restored.contains("192.168.10.5"));
        assert!(restored.contains("db-master.internal"));
        assert!(restored.contains("hacker@evil.com"));
        assert!(restored.contains("P@ssw0rd!"));

        // Stats
        assert!(result.stats.total_redactions >= 8);
        assert!(result.stats.ips_redacted >= 2);
        assert!(result.stats.hostnames_redacted >= 1);
        assert!(result.stats.credentials_redacted >= 2); // password + api_key + ssh key
        assert!(result.stats.emails_redacted >= 1);
    }
}
