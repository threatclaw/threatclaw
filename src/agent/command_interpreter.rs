//! Command Interpreter — parse natural language commands from RSSI.
//!
//! Receives messages from any channel (Telegram, Slack, Signal, etc.)
//! and translates them into structured actions.
//!
//! Flow:
//! 1. RSSI sends: "scan de port sur 192.168.1.50"
//! 2. L1 LLM parses → { action: "scan", target: "192.168.1.50", params: {...} }
//! 3. Agent confirms: "Je vais lancer un scan Nmap sur 192.168.1.50. Confirmer ?"
//! 4. RSSI replies: "oui" / "ok" / "go"
//! 5. Agent executes and returns results on the same channel

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::Database;

/// A parsed command from natural language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCommand {
    /// What the RSSI wants to do.
    pub action: String,
    /// Target (IP, hostname, domain, etc.).
    pub target: Option<String>,
    /// Additional parameters.
    pub params: HashMap<String, String>,
    /// Confidence that the parse is correct (0-1).
    pub confidence: f64,
    /// Human-readable summary of what will happen.
    pub summary: String,
    /// The skill or whitelist command to execute.
    pub execution_type: ExecutionType,
}

/// How the command will be executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionType {
    /// Execute a skill (e.g., vuln-scan, abuseipdb lookup).
    Skill { skill_id: String },
    /// Execute a whitelist remediation command.
    Remediation { cmd_id: String },
    /// Run a ReAct analysis cycle.
    ReactCycle,
    /// Generate a playbook/report via Instruct.
    Instruct { gen_type: String },
    /// Query status or information.
    Query { query_type: String },
    /// Unknown / cannot parse.
    Unknown,
}

/// Result of executing a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

/// Pending confirmation state for a command.
#[derive(Debug, Clone, Serialize)]
pub struct PendingConfirmation {
    pub command: ParsedCommand,
    pub channel: String,
    pub chat_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Parse a natural language message with conversation context.
pub async fn parse_command_with_context(
    message: &str,
    context: &str,
    llm_config: &crate::agent::llm_router::LlmRouterConfig,
) -> ParsedCommand {
    if context.is_empty() {
        return parse_command(message, llm_config).await;
    }

    // Enhanced prompt with context
    let contextual_message = format!(
        "Contexte de la conversation :\n{context}\n\nNouveau message du RSSI : {message}"
    );

    parse_command(&contextual_message, llm_config).await
}

/// Parse a natural language message into a structured command using L1 LLM.
pub async fn parse_command(
    message: &str,
    llm_config: &crate::agent::llm_router::LlmRouterConfig,
) -> ParsedCommand {
    let prompt = format!(
        r#"Tu es un interpréteur de commandes pour ThreatClaw, un agent de cybersécurité.
Le RSSI envoie un message en langage naturel. Tu dois le traduire en action structurée.

Actions possibles :
- scan_port : scanner les ports d'une cible (nécessite target IP/hostname)
- scan_vuln : scanner les vulnérabilités (nécessite target)
- lookup_ip : vérifier la réputation d'une IP (AbuseIPDB, CrowdSec)
- lookup_domain : vérifier un domaine (VirusTotal, DNS)
- check_breach : vérifier les fuites de données (HIBP)
- status : afficher le statut du système
- findings : afficher les findings récents
- alerts : afficher les alertes récentes
- playbook : générer un playbook pour un incident
- report : générer un rapport de sécurité
- sigma_rule : générer une règle Sigma
- block_ip : bloquer une IP (iptables)
- lock_user : verrouiller un compte utilisateur
- react : lancer un cycle d'analyse ReAct

Message du RSSI : "{message}"

Réponds UNIQUEMENT en JSON valide :
{{
  "action": "nom_action",
  "target": "IP ou hostname ou null",
  "params": {{}},
  "confidence": 0.0-1.0,
  "summary": "description en français de ce qui va être fait"
}}
/no_think"#
    );

    let url = format!("{}/api/chat", llm_config.primary.base_url);
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
    {
        Ok(c) => c,
        Err(_) => return fallback_parse(message),
    };

    let body = json!({
        "model": llm_config.primary.model,
        "messages": [{ "role": "user", "content": prompt }],
        "stream": false,
        "options": { "temperature": 0.1, "num_predict": 512 }
    });

    match client.post(&url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let content = data["message"]["content"].as_str()
                    .or_else(|| data["response"].as_str())
                    .unwrap_or("");

                if let Some(parsed) = parse_llm_json(content) {
                    tracing::info!("CMD_INTERPRETER: parsed '{}' → action={} confidence={:.0}%",
                        message, parsed.action, parsed.confidence * 100.0);
                    return parsed;
                }
            }
            fallback_parse(message)
        }
        _ => fallback_parse(message),
    }
}

/// Parse the LLM JSON response into a ParsedCommand.
fn parse_llm_json(content: &str) -> Option<ParsedCommand> {
    // Extract JSON from response (might be wrapped in markdown)
    let json_str = if let Some(start) = content.find('{') {
        if let Some(end) = content.rfind('}') {
            &content[start..=end]
        } else {
            return None;
        }
    } else {
        return None;
    };

    let val: serde_json::Value = serde_json::from_str(json_str).ok()?;

    let action = val["action"].as_str()?.to_string();
    let target = val["target"].as_str().filter(|s| !s.is_empty() && *s != "null").map(String::from);
    let confidence = val["confidence"].as_f64().unwrap_or(0.5);
    let summary = val["summary"].as_str().unwrap_or("").to_string();

    let params: HashMap<String, String> = val["params"].as_object()
        .map(|obj| obj.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
        .unwrap_or_default();

    let execution_type = match action.as_str() {
        "scan_port" | "scan_vuln" => ExecutionType::Skill { skill_id: "skill-vuln-scan".into() },
        "lookup_ip" => ExecutionType::Skill { skill_id: "skill-abuseipdb".into() },
        "lookup_domain" => ExecutionType::Skill { skill_id: "skill-virustotal".into() },
        "check_breach" => ExecutionType::Skill { skill_id: "skill-darkweb-monitor".into() },
        "block_ip" => ExecutionType::Remediation { cmd_id: "net-001".into() },
        "lock_user" => ExecutionType::Remediation { cmd_id: "usr-001".into() },
        "react" => ExecutionType::ReactCycle,
        "playbook" => ExecutionType::Instruct { gen_type: "playbook".into() },
        "report" => ExecutionType::Instruct { gen_type: "report".into() },
        "sigma_rule" => ExecutionType::Instruct { gen_type: "sigma".into() },
        "status" | "findings" | "alerts" => ExecutionType::Query { query_type: action.clone() },
        _ => ExecutionType::Unknown,
    };

    Some(ParsedCommand { action, target, params, confidence, summary, execution_type })
}

/// Fallback keyword-based parsing when LLM is unavailable.
fn fallback_parse(message: &str) -> ParsedCommand {
    let lower = message.to_lowercase();

    // Extract IP addresses
    let ip = extract_ip(&lower);

    let (action, execution_type, summary) = if lower.contains("scan") && (lower.contains("port") || lower.contains("nmap")) {
        ("scan_port".into(), ExecutionType::Skill { skill_id: "skill-vuln-scan".into() },
         format!("Scanner les ports{}", ip.as_ref().map(|i| format!(" de {i}")).unwrap_or_default()))
    } else if lower.contains("scan") && lower.contains("vuln") {
        ("scan_vuln".into(), ExecutionType::Skill { skill_id: "skill-vuln-scan".into() },
         format!("Scanner les vulnérabilités{}", ip.as_ref().map(|i| format!(" de {i}")).unwrap_or_default()))
    } else if lower.contains("block") || lower.contains("bloqu") {
        ("block_ip".into(), ExecutionType::Remediation { cmd_id: "net-001".into() },
         format!("Bloquer l'IP{}", ip.as_ref().map(|i| format!(" {i}")).unwrap_or_default()))
    } else if lower.contains("reputation") || lower.contains("abuseipdb") || (lower.contains("check") && lower.contains("ip")) {
        ("lookup_ip".into(), ExecutionType::Skill { skill_id: "skill-abuseipdb".into() },
         format!("Vérifier la réputation{}", ip.as_ref().map(|i| format!(" de {i}")).unwrap_or_default()))
    } else if lower.contains("playbook") {
        ("playbook".into(), ExecutionType::Instruct { gen_type: "playbook".into() }, "Générer un playbook".into())
    } else if lower.contains("rapport") || lower.contains("report") {
        ("report".into(), ExecutionType::Instruct { gen_type: "report".into() }, "Générer un rapport".into())
    } else if lower.contains("status") || lower.contains("état") || lower.contains("statut") {
        ("status".into(), ExecutionType::Query { query_type: "status".into() }, "Afficher le statut".into())
    } else if lower.contains("finding") || lower.contains("vulnérab") {
        ("findings".into(), ExecutionType::Query { query_type: "findings".into() }, "Afficher les findings".into())
    } else if lower.contains("alert") || lower.contains("sigma") {
        ("alerts".into(), ExecutionType::Query { query_type: "alerts".into() }, "Afficher les alertes".into())
    } else if lower.contains("react") || lower.contains("analyse") {
        ("react".into(), ExecutionType::ReactCycle, "Lancer un cycle d'analyse".into())
    } else {
        ("unknown".into(), ExecutionType::Unknown, "Commande non reconnue".into())
    };

    ParsedCommand {
        action, target: ip, params: HashMap::new(),
        confidence: 0.4, summary, execution_type,
    }
}

/// Extract an IP address from text.
fn extract_ip(text: &str) -> Option<String> {
    for word in text.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_numeric() && c != '.');
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return Some(clean.to_string());
        }
    }
    None
}

/// Execute a parsed command and return the result.
pub async fn execute_command(
    cmd: &ParsedCommand,
    store: &dyn Database,
    llm_config: &crate::agent::llm_router::LlmRouterConfig,
) -> CommandResult {
    match &cmd.execution_type {
        ExecutionType::Query { query_type } => execute_query(query_type, store).await,
        ExecutionType::Skill { skill_id } => execute_skill_lookup(skill_id, &cmd.target, &cmd.params, store).await,
        ExecutionType::ReactCycle => execute_react(store).await,
        ExecutionType::Instruct { gen_type } => execute_instruct(gen_type, &cmd.summary, llm_config).await,
        ExecutionType::Remediation { cmd_id } => {
            // Remediations always need explicit HITL — return confirmation request
            CommandResult {
                success: true,
                message: format!("Action de remédiation requise : {}. Envoyez 'confirmer' pour exécuter.", cmd.summary),
                data: Some(json!({ "needs_confirmation": true, "cmd_id": cmd_id, "params": cmd.params })),
            }
        }
        ExecutionType::Unknown => {
            CommandResult {
                success: false,
                message: "Commande non reconnue. Essayez : scan, status, findings, alerts, playbook, block, lookup".into(),
                data: None,
            }
        }
    }
}

/// Execute a status/findings/alerts query.
async fn execute_query(query_type: &str, store: &dyn Database) -> CommandResult {
    use crate::db::threatclaw_store::ThreatClawStore;

    match query_type {
        "status" => {
            let mode = store.get_setting("_system", "agent_mode").await.ok().flatten()
                .and_then(|v| v.as_str().map(String::from)).unwrap_or("investigator".into());
            CommandResult {
                success: true,
                message: format!("ThreatClaw — Mode: {mode}"),
                data: Some(json!({ "mode": mode })),
            }
        }
        "findings" => {
            match store.list_findings(None, Some("open"), None, 10, 0).await {
                Ok(findings) => {
                    let count = findings.len();
                    let summary: Vec<String> = findings.iter().take(5).map(|f| {
                        format!("[{}] {} — {}", f.severity, f.title, f.asset.as_deref().unwrap_or("?"))
                    }).collect();
                    CommandResult {
                        success: true,
                        message: format!("{count} findings ouverts :\n{}", summary.join("\n")),
                        data: Some(json!({ "count": count })),
                    }
                }
                Err(e) => CommandResult { success: false, message: format!("Erreur: {e}"), data: None },
            }
        }
        "alerts" => {
            match store.list_alerts(None, Some("new"), 10, 0).await {
                Ok(alerts) => {
                    let count = alerts.len();
                    let summary: Vec<String> = alerts.iter().take(5).map(|a| {
                        format!("[{}] {} — {}", a.level, a.title, a.hostname.as_deref().unwrap_or("?"))
                    }).collect();
                    CommandResult {
                        success: true,
                        message: format!("{count} alertes :\n{}", summary.join("\n")),
                        data: Some(json!({ "count": count })),
                    }
                }
                Err(e) => CommandResult { success: false, message: format!("Erreur: {e}"), data: None },
            }
        }
        _ => CommandResult { success: false, message: "Query inconnue".into(), data: None },
    }
}

/// Execute a skill lookup (read-only API call).
async fn execute_skill_lookup(
    skill_id: &str,
    target: &Option<String>,
    params: &HashMap<String, String>,
    store: &dyn Database,
) -> CommandResult {
    // Load skill config from DB
    use crate::db::threatclaw_store::ThreatClawStore;
    let config = store.get_skill_config(skill_id).await.unwrap_or_default();
    let mut merged_params: HashMap<String, String> = config.iter()
        .map(|c| (c.key.clone(), c.value.clone())).collect();
    merged_params.extend(params.clone());
    if let Some(t) = target {
        merged_params.insert("target".into(), t.clone());
        merged_params.insert("IP".into(), t.clone());
    }

    // Call the skill test endpoint
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build() {
        Ok(c) => c,
        Err(e) => return CommandResult { success: false, message: format!("HTTP: {e}"), data: None },
    };

    let auth_token = std::env::var("GATEWAY_AUTH_TOKEN").unwrap_or_default();
    let resp = client.post(format!("http://127.0.0.1:3000/api/tc/skills/{}/test", skill_id))
        .header("Authorization", format!("Bearer {}", auth_token))
        .json(&merged_params)
        .send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let data: serde_json::Value = r.json().await.unwrap_or_default();
            let detail = data["detail"].as_str().unwrap_or("OK");
            CommandResult {
                success: data["ok"].as_bool().unwrap_or(true),
                message: format!("{} : {}", skill_id, detail),
                data: Some(data),
            }
        }
        Ok(r) => CommandResult { success: false, message: format!("Skill {} : HTTP {}", skill_id, r.status()), data: None },
        Err(e) => CommandResult { success: false, message: format!("Skill {} : {}", skill_id, e), data: None },
    }
}

/// Execute a ReAct cycle (returns status only — actual cycle runs via scheduler).
async fn execute_react(_store: &dyn Database) -> CommandResult {
    // Trigger react cycle via internal API (same as dashboard button)
    let auth_token = std::env::var("GATEWAY_AUTH_TOKEN").unwrap_or_default();
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(120)).build() {
        Ok(c) => c,
        Err(e) => return CommandResult { success: false, message: format!("HTTP: {e}"), data: None },
    };

    match client.post("http://127.0.0.1:3000/api/tc/agent/react-cycle")
        .header("Authorization", format!("Bearer {}", auth_token))
        .send().await
    {
        Ok(r) if r.status().is_success() => {
            let data: serde_json::Value = r.json().await.unwrap_or_default();
            let obs = data["observations"].as_u64().unwrap_or(0);
            let level = data["escalation_level"].as_u64().unwrap_or(0);
            let status = data["status"].as_str().unwrap_or("?");
            CommandResult {
                success: true,
                message: format!("ReAct L{level}: {status} — {obs} observations"),
                data: Some(data),
            }
        }
        Ok(r) => CommandResult { success: false, message: format!("ReAct HTTP {}", r.status()), data: None },
        Err(e) => CommandResult { success: false, message: format!("ReAct: {e}"), data: None },
    }
}

/// Execute an Instruct generation.
async fn execute_instruct(
    gen_type: &str,
    context: &str,
    llm_config: &crate::agent::llm_router::LlmRouterConfig,
) -> CommandResult {
    let instruct = &llm_config.instruct;
    let prompt = match gen_type {
        "playbook" => format!("Génère un playbook SOAR concis pour : {context}"),
        "report" => format!("Génère un rapport d'incident pour : {context}"),
        "sigma" => format!("Génère une règle Sigma pour : {context}"),
        _ => format!("Analyse : {context}"),
    };

    let url = format!("{}/api/chat", instruct.base_url);
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(60))
        .danger_accept_invalid_certs(true).no_proxy().build() {
        Ok(c) => c,
        Err(e) => return CommandResult { success: false, message: format!("HTTP: {e}"), data: None },
    };

    let body = json!({
        "model": instruct.model,
        "messages": [{ "role": "user", "content": prompt }],
        "stream": false,
        "options": { "temperature": 0.3, "num_predict": 2048 }
    });

    match client.post(&url).json(&body).send().await {
        Ok(r) if r.status().is_success() => {
            if let Ok(data) = r.json::<serde_json::Value>().await {
                let content = data["message"]["content"].as_str().unwrap_or("Pas de réponse");
                // Truncate for Telegram (4096 char limit)
                let truncated = if content.len() > 3500 {
                    format!("{}...\n\n[tronqué — voir dashboard pour le rapport complet]", &content[..3500])
                } else {
                    content.to_string()
                };
                CommandResult { success: true, message: truncated, data: None }
            } else {
                CommandResult { success: false, message: "Erreur parsing réponse Instruct".into(), data: None }
            }
        }
        Ok(r) => CommandResult { success: false, message: format!("Instruct HTTP {}", r.status()), data: None },
        Err(e) => CommandResult { success: false, message: format!("Instruct: {e}"), data: None },
    }
}

/// Format a command result for Telegram (Markdown).
pub fn format_for_telegram(result: &CommandResult) -> String {
    if result.success {
        format!("✅ {}", result.message)
    } else {
        format!("❌ {}", result.message)
    }
}

/// Format a confirmation request for Telegram.
pub fn format_confirmation_request(cmd: &ParsedCommand) -> String {
    format!(
        "🔍 *Commande reçue*\n\n{}\n\nCible : {}\nConfiance : {:.0}%\n\nRépondez *oui* pour exécuter ou *non* pour annuler.",
        cmd.summary,
        cmd.target.as_deref().unwrap_or("aucune"),
        cmd.confidence * 100.0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ip() {
        assert_eq!(extract_ip("scan 192.168.1.50"), Some("192.168.1.50".into()));
        assert_eq!(extract_ip("block 10.0.0.42 now"), Some("10.0.0.42".into()));
        assert_eq!(extract_ip("no ip here"), None);
    }

    #[test]
    fn test_fallback_parse() {
        let cmd = fallback_parse("scan de port sur 192.168.1.50");
        assert_eq!(cmd.action, "scan_port");
        assert_eq!(cmd.target, Some("192.168.1.50".into()));

        let cmd2 = fallback_parse("affiche les findings");
        assert_eq!(cmd2.action, "findings");

        let cmd3 = fallback_parse("bloque l'ip 10.0.0.42");
        assert_eq!(cmd3.action, "block_ip");
        assert_eq!(cmd3.target, Some("10.0.0.42".into()));
    }

    #[test]
    fn test_parse_llm_json() {
        let json = r#"{"action":"scan_port","target":"192.168.1.50","params":{},"confidence":0.95,"summary":"Scanner les ports"}"#;
        let cmd = parse_llm_json(json).unwrap();
        assert_eq!(cmd.action, "scan_port");
        assert_eq!(cmd.target, Some("192.168.1.50".into()));
        assert!(cmd.confidence > 0.9);
    }
}
