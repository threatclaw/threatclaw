//! Cloud LLM Caller — appels anonymisés vers les API cloud (Anthropic, Mistral, OpenAI).
//!
//! Les données sont anonymisées AVANT l'envoi et dé-anonymisées au retour.
//! Le mapping de dé-anonymisation est gardé en mémoire uniquement (jamais persisté).

use std::collections::HashMap;

use regex::Regex;
use serde_json::json;

use crate::agent::llm_router::CloudLlmConfig;

/// Résultat d'un appel cloud.
#[derive(Debug, Clone)]
pub struct CloudCallResult {
    pub response: String,
    pub anonymized: bool,
    pub tokens_used: Option<u64>,
}

/// Mapping d'anonymisation réversible.
///
/// Couvre 17+ catégories de données sensibles internationales :
/// réseau, identifiants, credentials, données personnelles (RGPD),
/// identifiants d'entreprise, secrets techniques.
#[derive(Debug, Clone)]
pub struct AnonymizationMap {
    mappings: Vec<(String, String)>,
    /// Optional custom rules loaded from database (RSSI-defined patterns).
    custom_rules: Vec<CustomAnonymizationRule>,
}

/// A custom anonymization rule defined by the RSSI.
#[derive(Debug, Clone)]
pub struct CustomAnonymizationRule {
    pub label: String,
    pub pattern: String,
    pub token_prefix: String,
    pub capture_group: usize,
}

impl AnonymizationMap {
    pub fn new() -> Self {
        Self { mappings: Vec::new(), custom_rules: Vec::new() }
    }

    /// Create with custom RSSI-defined rules.
    pub fn with_custom_rules(rules: Vec<CustomAnonymizationRule>) -> Self {
        Self { mappings: Vec::new(), custom_rules: rules }
    }

    /// Helper: register a match if not already mapped.
    fn register(&mut self, original: &str, prefix: &str, counters: &mut HashMap<String, usize>) {
        let orig = original.to_string();
        if !self.mappings.iter().any(|(o, _)| o == &orig) {
            let count = counters.entry(prefix.to_string()).and_modify(|c| *c += 1).or_insert(1);
            let token = format!("[{}-{:03}]", prefix, count);
            self.mappings.push((orig, token));
        }
    }

    /// Helper: scan with a regex (full match) and register all hits.
    fn scan_full(&mut self, text: &str, pattern: &str, prefix: &str, counters: &mut HashMap<String, usize>) {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.find_iter(text) {
                self.register(cap.as_str(), prefix, counters);
            }
        }
    }

    /// Helper: scan with a regex (capture group 1) and register all hits.
    fn scan_group(&mut self, text: &str, pattern: &str, prefix: &str, group: usize, counters: &mut HashMap<String, usize>) {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(text) {
                if let Some(m) = cap.get(group) {
                    self.register(m.as_str(), prefix, counters);
                }
            }
        }
    }

    /// Anonymise un texte en remplaçant les données sensibles par des tokens.
    ///
    /// 17 catégories de patterns built-in + custom rules RSSI.
    /// Ordre : secrets en premier (plus longs), puis réseau, identité, données perso.
    pub fn anonymize(&mut self, text: &str) -> String {
        let mut counters: HashMap<String, usize> = HashMap::new();

        // ══════════════════════════════════════════════════════════
        // SECRETS & CREDENTIALS (match first — highest priority)
        // ══════════════════════════════════════════════════════════

        // SSH private keys (multi-line markers)
        self.scan_full(text,
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            "SSHKEY", &mut counters);

        // Database connection strings (postgres://, mysql://, mongodb://, redis://)
        self.scan_full(text,
            r"(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp)://\S+",
            "DBCONN", &mut counters);

        // API keys — AWS
        self.scan_full(text, r"\bAKIA[0-9A-Z]{16}\b", "APIKEY", &mut counters);
        // API keys — Slack
        self.scan_full(text, r"\bxox[bporas]-[0-9a-zA-Z-]+", "APIKEY", &mut counters);
        // API keys — GitHub
        self.scan_full(text, r"\bgh[ps]_[A-Za-z0-9_]{36,}\b", "APIKEY", &mut counters);
        // API keys — GitLab
        self.scan_full(text, r"\bglpat-[A-Za-z0-9_-]{20,}\b", "APIKEY", &mut counters);
        // API keys — Anthropic
        self.scan_full(text, r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", "APIKEY", &mut counters);
        // API keys — OpenAI
        self.scan_full(text, r"\bsk-[A-Za-z0-9]{20,}\b", "APIKEY", &mut counters);
        // API keys — Stripe
        self.scan_full(text, r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b", "APIKEY", &mut counters);
        // API keys — SendGrid
        self.scan_full(text, r"\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{10,}\b", "APIKEY", &mut counters);
        // API keys — Twilio
        self.scan_full(text, r"\bSK[0-9a-fA-F]{32}\b", "APIKEY", &mut counters);

        // Bearer tokens
        self.scan_group(text,
            r"(?i)(?:Bearer|Authorization[:\s]+Bearer)\s+([A-Za-z0-9_.\-/+=]{20,})",
            "BEARER", 1, &mut counters);

        // Passwords in key=value context
        self.scan_group(text,
            r"(?i)(?:password|passwd|pwd|secret|token)[=:\s]+(\S{4,})",
            "SECRET", 1, &mut counters);

        // ══════════════════════════════════════════════════════════
        // NETWORK & INFRASTRUCTURE
        // ══════════════════════════════════════════════════════════

        // CIDR subnets (before IPs to match the longer pattern first)
        self.scan_full(text,
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b",
            "CIDR", &mut counters);

        // IPv4
        self.scan_full(text,
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "IP", &mut counters);

        // MAC addresses — scan BEFORE IPv6 (aa:bb:cc:dd:ee:ff can look like short IPv6)
        self.scan_full(text,
            r"(?i)\b[0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}\b",
            "MAC", &mut counters);

        // IPv6 (full, compressed, and link-local)
        self.scan_full(text,
            r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:)*::[0-9a-f:]*\b|(?i)\bfe80::[0-9a-f:%]+\b",
            "IPV6", &mut counters);

        // Hostnames (server naming patterns)
        self.scan_full(text,
            r"\b(?:[a-z]+-[a-z]+-\d+|[a-z]+-\d+|srv-[a-z]+)\b",
            "HOST", &mut counters);

        // Windows file paths
        self.scan_full(text,
            r"[A-Z]:\\(?:Users|Windows|Program Files|ProgramData)\\\S+",
            "PATH", &mut counters);

        // Unix sensitive paths
        self.scan_full(text,
            r"(?:/home/|/root/|/etc/|/var/log/|/opt/)\S+",
            "PATH", &mut counters);

        // Active Directory distinguished names
        self.scan_full(text,
            r"(?i)(?:CN|OU|DC)=[^,]+(?:,\s*(?:CN|OU|DC)=[^,]+){1,}",
            "ADPATH", &mut counters);

        // Windows SIDs
        self.scan_full(text,
            r"\bS-1-5-21-\d+-\d+-\d+(?:-\d+)?\b",
            "SID", &mut counters);

        // Internal URLs (common intranet patterns)
        self.scan_full(text,
            r"https?://[a-zA-Z0-9.-]+\.(?:local|internal|corp|intranet|lan)[^\s]*",
            "INTURL", &mut counters);

        // ══════════════════════════════════════════════════════════
        // IDENTITY & PERSONAL DATA (GDPR)
        // ══════════════════════════════════════════════════════════

        // Email addresses
        self.scan_full(text,
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            "EMAIL", &mut counters);

        // International phone numbers (E.164 and common formats)
        // +XX followed by 7-14 digits with optional separators
        self.scan_full(text,
            r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{0,4}",
            "PHONE", &mut counters);
        // French local format (06, 07, 01-05, 09)
        self.scan_full(text,
            r"\b0[1-79][\s.-]?\d{2}[\s.-]?\d{2}[\s.-]?\d{2}[\s.-]?\d{2}\b",
            "PHONE", &mut counters);

        // IBAN (international: 2 letters + 2 check digits + up to 30 alphanumeric)
        self.scan_full(text,
            r"\b[A-Z]{2}\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,4}[\s]?\d{0,3}\b",
            "IBAN", &mut counters);

        // Credit card numbers (13-19 digits, optional spaces/dashes)
        self.scan_full(text,
            r"\b(?:\d{4}[\s-]?){3,4}\d{1,4}\b",
            "CARD", &mut counters);

        // French NIR (social security: 1 or 2 + 13 digits)
        self.scan_full(text,
            r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b",
            "NIR", &mut counters);

        // Usernames (after "user:" or "username:")
        self.scan_group(text,
            r"(?i)(?:user(?:name)?[:\s=]+)([a-zA-Z0-9._-]+)",
            "USER", 1, &mut counters);

        // ══════════════════════════════════════════════════════════
        // BUSINESS IDENTIFIERS
        // ══════════════════════════════════════════════════════════

        // French SIRET (14 digits) / SIREN (9 digits)
        self.scan_full(text,
            r"\b\d{3}\s?\d{3}\s?\d{3}\s?\d{5}\b",
            "SIRET", &mut counters);
        self.scan_full(text,
            r"\b\d{3}\s?\d{3}\s?\d{3}\b",
            "SIREN", &mut counters);

        // EU VAT numbers (FR, DE, IT, ES, GB, BE, NL, AT, PL, PT, etc.)
        self.scan_full(text,
            r"\b(?:FR|DE|IT|ES|GB|BE|NL|AT|PL|PT|IE|SE|DK|FI|CZ|RO|BG|HR|SI|SK|HU|LT|LV|EE|LU|MT|CY|EL)\d{2,13}\b",
            "VAT", &mut counters);

        // ══════════════════════════════════════════════════════════
        // CUSTOM RULES (RSSI-defined patterns from database)
        // ══════════════════════════════════════════════════════════
        let custom_rules = self.custom_rules.clone();
        for rule in &custom_rules {
            if rule.capture_group > 0 {
                self.scan_group(text, &rule.pattern, &rule.token_prefix, rule.capture_group, &mut counters);
            } else {
                self.scan_full(text, &rule.pattern, &rule.token_prefix, &mut counters);
            }
        }

        // Apply all mappings (longest first to avoid partial replacements)
        let mut result = text.to_string();
        let mut sorted_mappings = self.mappings.clone();
        sorted_mappings.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (original, token) in &sorted_mappings {
            result = result.replace(original, token);
        }

        result
    }

    /// Dé-anonymise un texte en restaurant les données originales.
    pub fn deanonymize(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (original, token) in &self.mappings {
            result = result.replace(token, original);
        }
        result
    }

    /// Nombre de mappings actifs.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Retourne les catégories de données anonymisées.
    pub fn categories(&self) -> Vec<String> {
        let mut cats: Vec<String> = self.mappings.iter()
            .filter_map(|(_, token)| {
                token.strip_prefix('[')?.split('-').next().map(|s| s.to_string())
            })
            .collect();
        cats.sort();
        cats.dedup();
        cats
    }
}

impl Default for AnonymizationMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Appelle une API cloud LLM.
pub async fn call_cloud_llm(
    config: &CloudLlmConfig,
    prompt: &str,
) -> Result<CloudCallResult, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    match config.backend.as_str() {
        "anthropic" => call_anthropic(&client, config, prompt).await,
        "mistral" => call_openai_compatible(&client, config, prompt, "https://api.mistral.ai/v1").await,
        "openai_compatible" => {
            let base = config.base_url.as_deref().unwrap_or("https://api.openai.com/v1");
            call_openai_compatible(&client, config, prompt, base).await
        }
        other => Err(format!("Unknown cloud backend: {other}")),
    }
}

async fn call_anthropic(
    client: &reqwest::Client,
    config: &CloudLlmConfig,
    prompt: &str,
) -> Result<CloudCallResult, String> {
    let body = json!({
        "model": config.model,
        "max_tokens": 2048,
        "messages": [{ "role": "user", "content": prompt }],
        "temperature": 0.3,
    });

    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", &config.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Anthropic request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Anthropic {status}: {text}"));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON parse: {e}"))?;
    let content = data["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let tokens = data["usage"]["output_tokens"].as_u64();

    Ok(CloudCallResult {
        response: content,
        anonymized: true,
        tokens_used: tokens,
    })
}

async fn call_openai_compatible(
    client: &reqwest::Client,
    config: &CloudLlmConfig,
    prompt: &str,
    base_url: &str,
) -> Result<CloudCallResult, String> {
    let body = json!({
        "model": config.model,
        "messages": [{ "role": "user", "content": prompt }],
        "temperature": 0.3,
        "max_tokens": 2048,
    });

    let resp = client
        .post(format!("{base_url}/chat/completions"))
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Cloud request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Cloud {status}: {text}"));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON parse: {e}"))?;
    let content = data["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let tokens = data["usage"]["total_tokens"].as_u64();

    Ok(CloudCallResult {
        response: content,
        anonymized: true,
        tokens_used: tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Existing tests (preserved) ──

    #[test]
    fn test_anonymize_ips() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Attack from 10.0.0.42 targeting 192.168.1.10");
        assert!(result.contains("[IP-001]"));
        assert!(result.contains("[IP-002]"));
        assert!(!result.contains("10.0.0.42"));
        assert!(!result.contains("192.168.1.10"));
    }

    #[test]
    fn test_anonymize_emails() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Credentials for admin@example.com found");
        assert!(result.contains("[EMAIL-001]"));
        assert!(!result.contains("admin@example.com"));
    }

    #[test]
    fn test_anonymize_hostnames() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("RDP from bastion-01 to srv-finance");
        assert!(result.contains("[HOST-001]"));
        assert!(result.contains("[HOST-002]"));
        assert!(!result.contains("bastion-01"));
    }

    #[test]
    fn test_deanonymize() {
        let mut map = AnonymizationMap::new();
        let anonymized = map.anonymize("Attack from 10.0.0.42 on srv-finance");
        let restored = map.deanonymize(&anonymized);
        assert!(restored.contains("10.0.0.42"));
        assert!(restored.contains("srv-finance"));
    }

    #[test]
    fn test_deanonymize_roundtrip() {
        let mut map = AnonymizationMap::new();
        let original = "Brute force from 10.0.0.42 user: admin on bastion-01";
        let anonymized = map.anonymize(original);
        let restored = map.deanonymize(&anonymized);
        assert_eq!(restored, original);
    }

    #[test]
    fn test_same_ip_same_token() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("10.0.0.42 attacked 192.168.1.10 then 10.0.0.42 came back");
        let count = result.matches("[IP-001]").count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_no_sensitive_data_unchanged() {
        let mut map = AnonymizationMap::new();
        let text = "No sensitive data here, just a normal log entry";
        let result = map.anonymize(text);
        assert_eq!(result, text);
        assert_eq!(map.mapping_count(), 0);
    }

    // ── Network & infrastructure ──

    #[test]
    fn test_anonymize_ipv6() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Connection from 2001:db8::1 to fe80::1%eth0");
        assert!(result.contains("[IPV6-"));
        assert!(!result.contains("2001:db8::1"));
    }

    #[test]
    fn test_anonymize_cidr() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Scanning subnet 192.168.1.0/24");
        assert!(result.contains("[CIDR-001]"));
        assert!(!result.contains("192.168.1.0/24"));
    }

    #[test]
    fn test_anonymize_mac() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Device MAC aa:bb:cc:dd:ee:ff detected");
        assert!(result.contains("[MAC-001]"));
        assert!(!result.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn test_anonymize_windows_path() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize(r"Malware found at C:\Users\jean.dupont\Downloads\payload.exe");
        assert!(result.contains("[PATH-001]"));
        assert!(!result.contains("jean.dupont"));
    }

    #[test]
    fn test_anonymize_unix_path() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("SSH key at /home/admin/.ssh/id_rsa");
        assert!(result.contains("[PATH-001]"));
        assert!(!result.contains("/home/admin"));
    }

    #[test]
    fn test_anonymize_ad_path() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("User CN=Jean Dupont,OU=IT,DC=corp,DC=local");
        assert!(result.contains("[ADPATH-001]"));
        assert!(!result.contains("Jean Dupont"));
    }

    #[test]
    fn test_anonymize_windows_sid() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Account SID S-1-5-21-3623811015-3361044348-30300820-1013");
        assert!(result.contains("[SID-001]"));
        assert!(!result.contains("3623811015"));
    }

    #[test]
    fn test_anonymize_internal_url() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Dashboard at https://grafana.corp.local/d/api-latency");
        assert!(result.contains("[INTURL-001]"));
        assert!(!result.contains("grafana.corp.local"));
    }

    // ── Credentials & secrets ──

    #[test]
    fn test_anonymize_aws_key() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("AWS key AKIAIOSFODNN7EXAMPLE found in config");
        assert!(result.contains("[APIKEY-"));
        assert!(!result.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_anonymize_slack_token() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Slack token xoxb-123456789-abcdefgh in .env");
        assert!(result.contains("[APIKEY-"));
        assert!(!result.contains("xoxb-"));
    }

    #[test]
    fn test_anonymize_github_token() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234 leaked");
        assert!(result.contains("[APIKEY-"));
        assert!(!result.contains("ghp_"));
    }

    #[test]
    fn test_anonymize_anthropic_key() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Key sk-ant-api03-abcdefghijklmnopqrst in config");
        assert!(result.contains("[APIKEY-"));
        assert!(!result.contains("sk-ant-"));
    }

    #[test]
    fn test_anonymize_bearer_token() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig");
        assert!(result.contains("[BEARER-001]"));
        assert!(!result.contains("eyJhbGci"));
    }

    #[test]
    fn test_anonymize_db_connection() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("DB at postgres://admin:s3cret@db.corp.local:5432/production");
        assert!(result.contains("[DBCONN-001]"));
        assert!(!result.contains("s3cret"));
    }

    #[test]
    fn test_anonymize_ssh_key_marker() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Found -----BEGIN RSA PRIVATE KEY----- in /tmp/leak");
        assert!(result.contains("[SSHKEY-001]"));
    }

    #[test]
    fn test_anonymize_password_in_context() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Login with password=SuperS3cret123!");
        assert!(result.contains("[SECRET-001]"));
        assert!(!result.contains("SuperS3cret123!"));
    }

    // ── Personal data (GDPR) ──

    #[test]
    fn test_anonymize_phone_fr() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Contact: 06 12 34 56 78");
        assert!(result.contains("[PHONE-001]"));
        assert!(!result.contains("06 12 34"));
    }

    #[test]
    fn test_anonymize_phone_international() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Call +44 20 7946 0958 for support");
        assert!(result.contains("[PHONE-001]"));
        assert!(!result.contains("+44"));
    }

    #[test]
    fn test_anonymize_iban() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Wire to FR76 3000 6000 0112 3456 7890 189");
        assert!(result.contains("[IBAN-001]"));
        assert!(!result.contains("3000 6000"));
    }

    #[test]
    fn test_anonymize_credit_card() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Card 4111 1111 1111 1111 compromised");
        assert!(result.contains("[CARD-001]"));
        assert!(!result.contains("4111"));
    }

    #[test]
    fn test_anonymize_french_nir() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("NIR 1 85 05 78 006 084 36 found in leak");
        assert!(result.contains("[NIR-001]"));
        assert!(!result.contains("85 05 78"));
    }

    // ── Business identifiers ──

    #[test]
    fn test_anonymize_siret() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("Company SIRET 832 654 789 00015");
        assert!(result.contains("[SIRET-001]"));
        assert!(!result.contains("832 654 789"));
    }

    #[test]
    fn test_anonymize_vat_eu() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("VAT FR76832654789 registered");
        assert!(result.contains("[VAT-001]"));
        assert!(!result.contains("FR76832654789"));
    }

    // ── Custom rules ──

    #[test]
    fn test_custom_rule() {
        let rules = vec![CustomAnonymizationRule {
            label: "Project name".to_string(),
            pattern: r"\bProject-Neptune\b".to_string(),
            token_prefix: "PROJECT".to_string(),
            capture_group: 0,
        }];
        let mut map = AnonymizationMap::with_custom_rules(rules);
        let result = map.anonymize("Breach in Project-Neptune infrastructure");
        assert!(result.contains("[PROJECT-001]"));
        assert!(!result.contains("Project-Neptune"));
    }

    // ── Roundtrip & categories ──

    #[test]
    fn test_full_roundtrip_complex() {
        let mut map = AnonymizationMap::new();
        let original = "Attack from 10.0.0.42 user: admin targeting admin@corp.com on bastion-01";
        let anonymized = map.anonymize(original);
        assert!(!anonymized.contains("10.0.0.42"));
        assert!(!anonymized.contains("admin@corp.com"));
        let restored = map.deanonymize(&anonymized);
        assert_eq!(restored, original);
    }

    #[test]
    fn test_categories() {
        let mut map = AnonymizationMap::new();
        map.anonymize("IP 10.0.0.1, email a@b.com, MAC aa:bb:cc:dd:ee:ff");
        let cats = map.categories();
        assert!(cats.contains(&"IP".to_string()));
        assert!(cats.contains(&"EMAIL".to_string()));
        assert!(cats.contains(&"MAC".to_string()));
    }

    #[tokio::test]
    async fn test_cloud_call_invalid_url() {
        let config = CloudLlmConfig {
            backend: "openai_compatible".to_string(),
            model: "test".to_string(),
            base_url: Some("http://localhost:99999".to_string()),
            api_key: "fake".to_string(),
        };
        let result = call_cloud_llm(&config, "test").await;
        assert!(result.is_err());
    }
}
