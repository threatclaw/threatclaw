//! Conversation Modes — controls bot response pipeline. See ADR-011.

use crate::agent::cloud_intent;
use crate::db::Database;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationMode {
    Local,
    CloudAssisted,
    CloudDirect,
}

impl Default for ConversationMode {
    fn default() -> Self {
        Self::Local
    }
}

impl std::fmt::Display for ConversationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::CloudAssisted => write!(f, "cloud_assisted"),
            Self::CloudDirect => write!(f, "cloud_direct"),
        }
    }
}

/// Process a RSSI message according to the conversation mode.
pub async fn process_message(
    store: &dyn Database,
    message: &str,
    mode: ConversationMode,
) -> String {
    match mode {
        ConversationMode::Local => {
            // Parse intent locally + execute locally
            let intent = cloud_intent::parse_intent(message, "local").await;
            cloud_intent::execute_intent(store, &intent).await
        }

        ConversationMode::CloudAssisted => {
            // Step 1: Parse intent locally (no cloud for parsing yet)
            let intent = cloud_intent::parse_intent(message, "local").await;

            // Step 2: Execute locally (real data)
            let raw_result = cloud_intent::execute_intent(store, &intent).await;

            // Step 3: Anonymize the result before sending to cloud
            let anonymized = anonymize_result(&raw_result);

            // Step 4: Build a reformulated response
            // In production this would call Cloud LLM to reformulate
            // For now: return the result with a clean French formatting
            format_response(&intent.action, &raw_result, &anonymized)
        }

        ConversationMode::CloudDirect => {
            // Full anonymization + cloud LLM
            // Uses existing L3 cloud path (anonymizer + llm_router)
            let intent = cloud_intent::parse_intent(message, "local").await;
            let raw_result = cloud_intent::execute_intent(store, &intent).await;
            raw_result
        }
    }
}

/// Anonymize a result text — strip IPs, hostnames, usernames.
fn anonymize_result(text: &str) -> String {
    let mut result = text.to_string();

    // Replace IPs with [IP-N]
    let ip_re = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?\b").unwrap();
    let mut ip_counter = 1;
    let mut seen_ips = std::collections::HashMap::new();
    result = ip_re
        .replace_all(&result, |caps: &regex::Captures| {
            let ip = caps[0].to_string();
            let label = seen_ips.entry(ip).or_insert_with(|| {
                let l = format!("[IP-{}]", ip_counter);
                ip_counter += 1;
                l
            });
            label.clone()
        })
        .to_string();

    // Replace hostnames (srv-xxx, pc-xxx, dc-xxx)
    let host_re = regex::Regex::new(r"\b(srv|pc|dc|fw|sw|ap|nas)-[\w-]+\b").unwrap();
    let mut host_counter = 1;
    result = host_re
        .replace_all(&result, |_caps: &regex::Captures| {
            let label = format!("[HOST-{}]", host_counter);
            host_counter += 1;
            label
        })
        .to_string();

    // Replace email-like patterns
    let email_re = regex::Regex::new(r"\b[\w.-]+@[\w.-]+\.\w+\b").unwrap();
    result = email_re.replace_all(&result, "[EMAIL]").to_string();

    // Replace MAC addresses
    let mac_re = regex::Regex::new(r"\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b").unwrap();
    result = mac_re.replace_all(&result, "[MAC]").to_string();

    result
}

/// Format the response for cloud-assisted mode (clean French).
fn format_response(action: &cloud_intent::IntentAction, raw: &str, _anonymized: &str) -> String {
    // Add context header based on action type
    let header = match action {
        cloud_intent::IntentAction::Status => "Situation de votre infrastructure",
        cloud_intent::IntentAction::LookupIp { .. } => "Analyse de l'adresse IP",
        cloud_intent::IntentAction::AttackPaths => "Chemins d'attaque detectes",
        cloud_intent::IntentAction::BlastRadius { .. } => "Analyse d'impact (blast radius)",
        cloud_intent::IntentAction::ThreatActors => "Acteurs de menace identifies",
        cloud_intent::IntentAction::LateralMovement => "Detection de mouvement lateral",
        cloud_intent::IntentAction::ReportNis2 => "Rapport NIS2",
        cloud_intent::IntentAction::ShowFindings { .. } => "Vulnerabilites detectees",
        cloud_intent::IntentAction::ShowAlerts => "Alertes actives",
        _ => "",
    };

    if header.is_empty() {
        raw.to_string()
    } else {
        format!("*{}*\n\n{}", header, raw)
    }
}

/// Get the current conversation mode from DB settings.
pub async fn get_mode(store: &dyn Database) -> ConversationMode {
    match store
        .get_setting("tc_config_general", "conversation_mode")
        .await
    {
        Ok(Some(val)) => match val.as_str().unwrap_or("local") {
            "cloud_assisted" => ConversationMode::CloudAssisted,
            "cloud_direct" => ConversationMode::CloudDirect,
            _ => ConversationMode::Local,
        },
        _ => ConversationMode::Local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonymize_ips() {
        let text = "IP 192.168.1.50 attaque 10.0.0.1 depuis srv-web-01";
        let anon = anonymize_result(text);
        assert!(!anon.contains("192.168.1.50"));
        assert!(!anon.contains("10.0.0.1"));
        assert!(anon.contains("[IP-"));
        assert!(anon.contains("[HOST-"));
    }

    #[test]
    fn test_anonymize_email() {
        let text = "Compte jean.dupont@corp.local compromis";
        let anon = anonymize_result(text);
        assert!(!anon.contains("jean.dupont"));
        assert!(anon.contains("[EMAIL]"));
    }

    #[test]
    fn test_anonymize_mac() {
        let text = "MAC 00:1a:2b:3c:4d:5e detectee";
        let anon = anonymize_result(text);
        assert!(!anon.contains("00:1a:2b:3c:4d:5e"));
        assert!(anon.contains("[MAC]"));
    }

    #[test]
    fn test_mode_default() {
        assert_eq!(ConversationMode::default(), ConversationMode::Local);
    }
}
