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
#[derive(Debug, Clone)]
pub struct AnonymizationMap {
    mappings: Vec<(String, String)>,
}

impl AnonymizationMap {
    pub fn new() -> Self {
        Self { mappings: Vec::new() }
    }

    /// Anonymise un texte en remplaçant les données sensibles par des tokens.
    pub fn anonymize(&mut self, text: &str) -> String {
        let mut result = text.to_string();
        let mut counters: HashMap<&str, usize> = HashMap::new();

        // IPs (v4)
        let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap();
        for cap in ip_re.find_iter(text) {
            let original = cap.as_str().to_string();
            if !self.mappings.iter().any(|(o, _)| o == &original) {
                let count = counters.entry("IP").and_modify(|c| *c += 1).or_insert(1);
                let token = format!("[IP-{:03}]", count);
                self.mappings.push((original.clone(), token.clone()));
            }
        }

        // Hostnames (word-word patterns, common server names)
        let host_re = Regex::new(r"\b([a-z]+-[a-z]+-\d+|[a-z]+-\d+|srv-[a-z]+)\b").unwrap();
        for cap in host_re.find_iter(text) {
            let original = cap.as_str().to_string();
            if !self.mappings.iter().any(|(o, _)| o == &original) {
                let count = counters.entry("HOST").and_modify(|c| *c += 1).or_insert(1);
                let token = format!("[HOST-{:03}]", count);
                self.mappings.push((original.clone(), token.clone()));
            }
        }

        // Email addresses
        let email_re = Regex::new(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b").unwrap();
        for cap in email_re.find_iter(text) {
            let original = cap.as_str().to_string();
            if !self.mappings.iter().any(|(o, _)| o == &original) {
                let count = counters.entry("EMAIL").and_modify(|c| *c += 1).or_insert(1);
                let token = format!("[EMAIL-{:03}]", count);
                self.mappings.push((original.clone(), token.clone()));
            }
        }

        // Usernames (after "user:" or "username:")
        let user_re = Regex::new(r"(?i)(?:user(?:name)?[:\s=]+)([a-zA-Z0-9._-]+)").unwrap();
        for cap in user_re.captures_iter(text) {
            if let Some(m) = cap.get(1) {
                let original = m.as_str().to_string();
                if !self.mappings.iter().any(|(o, _)| o == &original) {
                    let count = counters.entry("USER").and_modify(|c| *c += 1).or_insert(1);
                    let token = format!("[USER-{:03}]", count);
                    self.mappings.push((original.clone(), token.clone()));
                }
            }
        }

        // Apply all mappings (longest first to avoid partial replacements)
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
        // Apply in reverse order (tokens → originals)
        for (original, token) in &self.mappings {
            result = result.replace(token, original);
        }
        result
    }

    /// Nombre de mappings actifs.
    pub fn mapping_count(&self) -> usize {
        self.mappings.len()
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
        let original = "Brute force from 10.0.0.42 user admin@corp.com on bastion-01";
        let anonymized = map.anonymize(original);
        let restored = map.deanonymize(&anonymized);
        assert_eq!(restored, original);
    }

    #[test]
    fn test_same_ip_same_token() {
        let mut map = AnonymizationMap::new();
        let result = map.anonymize("10.0.0.42 attacked 192.168.1.10 then 10.0.0.42 came back");
        // Same IP should get same token
        let count = result.matches("[IP-001]").count();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_mapping_count() {
        let mut map = AnonymizationMap::new();
        map.anonymize("10.0.0.1 and 10.0.0.2 and admin@test.com");
        assert_eq!(map.mapping_count(), 3);
    }

    #[test]
    fn test_no_sensitive_data_unchanged() {
        let mut map = AnonymizationMap::new();
        let text = "No sensitive data here, just a normal log entry";
        let result = map.anonymize(text);
        assert_eq!(result, text);
        assert_eq!(map.mapping_count(), 0);
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
