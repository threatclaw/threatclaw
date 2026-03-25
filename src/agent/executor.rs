//! Executor — exécution sécurisée des commandes de remédiation.
//!
//! Module Rust natif sur l'hôte — PAS dans WASM.
//! Exécute uniquement les commandes validées par la whitelist.
//! Chaque exécution est auditée. Jamais de shell=true.

use std::collections::HashMap;
use std::process::Command;

use crate::agent::remediation_whitelist::{validate_remediation, ValidatedCommand, RemediationError, RiskLevel};

/// Résultat d'une exécution de commande.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    pub cmd_id: String,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub rendered_cmd: String,
}

/// Erreur d'exécution.
#[derive(Debug, Clone)]
pub enum ExecutorError {
    /// La commande n'est pas dans la whitelist.
    Validation(RemediationError),
    /// L'exécution a échoué (commande introuvable, permissions, etc.).
    ExecutionFailed(String),
    /// Kill switch actif — exécution interdite.
    KillSwitchActive,
    /// HITL requis mais non approuvé.
    HitlRequired,
    /// Quota journalier dépassé.
    QuotaExceeded { used: u32, max: u32 },
}

impl std::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(e) => write!(f, "Validation: {e}"),
            Self::ExecutionFailed(e) => write!(f, "Execution failed: {e}"),
            Self::KillSwitchActive => write!(f, "Kill switch is active — all executions blocked"),
            Self::HitlRequired => write!(f, "HITL approval required"),
            Self::QuotaExceeded { used, max } => write!(f, "Daily quota exceeded: {used}/{max}"),
        }
    }
}

impl std::error::Error for ExecutorError {}

/// Exécute une commande validée.
///
/// Les commandes `skill-*` sont routées vers l'API interne (HTTP localhost).
/// Les autres commandes sont exécutées en subprocess natif.
/// Jamais de shell=true — pas d'injection possible.
pub fn execute_validated(cmd: &ValidatedCommand) -> Result<ExecutionResult, ExecutorError> {
    // Route skill commands to internal API
    if cmd.id.starts_with("skill-") {
        return execute_skill_command(cmd);
    }

    let parts = split_command(&cmd.rendered_cmd);
    if parts.is_empty() {
        return Err(ExecutorError::ExecutionFailed("Empty command".to_string()));
    }

    let program = &parts[0];
    let args = &parts[1..];

    tracing::info!(
        "EXECUTOR: Running {} — {} {:?}",
        cmd.id, program, args
    );

    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| ExecutorError::ExecutionFailed(format!("{program}: {e}")))?;

    let result = ExecutionResult {
        cmd_id: cmd.id.clone(),
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        rendered_cmd: cmd.rendered_cmd.clone(),
    };

    if result.success {
        tracing::info!("EXECUTOR: {} completed successfully", cmd.id);
    } else {
        tracing::warn!(
            "EXECUTOR: {} failed (exit {}): {}",
            cmd.id,
            result.exit_code.unwrap_or(-1),
            result.stderr.trim()
        );
    }

    Ok(result)
}

/// Exécute une commande skill via l'API de test interne.
///
/// Les skills officielles sont des lookups API en lecture seule.
/// On les exécute via POST /api/tc/skills/{id}/test qui fait le vrai appel API.
/// Le résultat est retourné comme stdout pour que le ReAct cycle puisse l'analyser.
fn execute_skill_command(cmd: &ValidatedCommand) -> Result<ExecutionResult, ExecutorError> {
    // Extract skill ID from cmd_id: "skill-abuseipdb-check" → "skill-abuseipdb"
    let skill_id = extract_skill_id(&cmd.id);

    tracing::info!("EXECUTOR: Skill lookup {} — params: {:?}", skill_id, cmd.params);

    // Build the API call synchronously (we're in a blocking context)
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| ExecutorError::ExecutionFailed(format!("HTTP client: {e}")))?;

    let resp = client
        .post(format!("http://127.0.0.1:3000/api/tc/skills/{}/test", skill_id))
        .json(&cmd.params)
        .send()
        .map_err(|e| ExecutorError::ExecutionFailed(format!("Skill API call failed: {e}")))?;

    let status_ok = resp.status().is_success();
    let body = resp.text().unwrap_or_default();

    let result = ExecutionResult {
        cmd_id: cmd.id.clone(),
        success: status_ok,
        exit_code: if status_ok { Some(0) } else { Some(1) },
        stdout: body,
        stderr: String::new(),
        rendered_cmd: format!("skill-exec {} {:?}", skill_id, cmd.params),
    };

    if status_ok {
        tracing::info!("EXECUTOR: Skill {} lookup completed", skill_id);
    } else {
        tracing::warn!("EXECUTOR: Skill {} lookup failed", skill_id);
    }

    Ok(result)
}

/// Extrait l'ID du skill depuis l'ID de commande.
/// "skill-abuseipdb-check" → "skill-abuseipdb"
/// "skill-virustotal-url" → "skill-virustotal"
/// "skill-email-audit" → "skill-email-audit"
fn extract_skill_id(cmd_id: &str) -> String {
    // Known skill IDs
    let known = [
        "skill-abuseipdb", "skill-cti-crowdsec", "skill-shodan",
        "skill-virustotal", "skill-darkweb-monitor", "skill-email-audit",
        "skill-wazuh", "skill-report-gen",
    ];
    for kid in &known {
        if cmd_id.starts_with(kid) {
            return kid.to_string();
        }
    }
    // Fallback: take first two parts
    let parts: Vec<&str> = cmd_id.splitn(3, '-').collect();
    if parts.len() >= 2 {
        format!("{}-{}", parts[0], parts[1])
    } else {
        cmd_id.to_string()
    }
}

/// Valide et exécute en une étape (convenience function).
pub fn validate_and_execute(
    cmd_id: &str,
    params: &HashMap<String, String>,
) -> Result<ExecutionResult, ExecutorError> {
    let validated = validate_remediation(cmd_id, params)
        .map_err(ExecutorError::Validation)?;
    execute_validated(&validated)
}

/// Décompose une commande en programme + arguments.
/// Ne passe PAS par un shell — chaque token est un argument séparé.
fn split_command(cmd: &str) -> Vec<String> {
    // Simple split par espaces, respecte les guillemets simples
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = ' ';

    for ch in cmd.chars() {
        if in_quotes {
            if ch == quote_char {
                in_quotes = false;
            } else {
                current.push(ch);
            }
        } else if ch == '\'' || ch == '"' {
            in_quotes = true;
            quote_char = ch;
        } else if ch == ' ' {
            if !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

/// Exécute la commande d'annulation (undo) si disponible.
pub fn execute_undo(cmd: &ValidatedCommand) -> Option<Result<ExecutionResult, ExecutorError>> {
    cmd.undo_cmd.as_ref().map(|undo| {
        let undo_validated = ValidatedCommand {
            id: format!("{}-undo", cmd.id),
            rendered_cmd: undo.clone(),
            undo_cmd: None,
            risk: cmd.risk,
            requires_hitl: cmd.requires_hitl,
            params: cmd.params.clone(),
        };
        execute_validated(&undo_validated)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_simple() {
        let parts = split_command("echo hello world");
        assert_eq!(parts, vec!["echo", "hello", "world"]);
    }

    #[test]
    fn test_split_with_flags() {
        let parts = split_command("iptables -A INPUT -s 10.0.0.1 -j DROP");
        assert_eq!(parts, vec!["iptables", "-A", "INPUT", "-s", "10.0.0.1", "-j", "DROP"]);
    }

    #[test]
    fn test_split_quoted() {
        let parts = split_command("echo 'hello world'");
        assert_eq!(parts, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_split_empty() {
        let parts = split_command("");
        assert!(parts.is_empty());
    }

    #[test]
    fn test_validate_and_execute_echo() {
        // This tests the full pipeline with a real command
        // We can't test iptables/usermod without root, but we can test the validation
        let params: HashMap<String, String> = [("IP".to_string(), "10.0.0.99".to_string())].into();
        let validated = validate_remediation("net-001", &params).unwrap();

        assert_eq!(validated.rendered_cmd, "iptables -A INPUT -s 10.0.0.99 -j DROP");
        assert_eq!(validated.risk, RiskLevel::Medium);
        assert!(validated.requires_hitl);

        // Don't actually execute iptables in tests
    }

    #[test]
    fn test_validate_rejects_injection() {
        let params: HashMap<String, String> = [("IP".to_string(), "1.2.3.4; cat /etc/shadow".to_string())].into();
        let result = validate_and_execute("net-001", &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_rejects_unknown_command() {
        let params: HashMap<String, String> = HashMap::new();
        let result = validate_and_execute("evil-cmd", &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_executor_error_display() {
        let err = ExecutorError::KillSwitchActive;
        assert!(err.to_string().contains("Kill switch"));

        let err = ExecutorError::QuotaExceeded { used: 21, max: 20 };
        assert!(err.to_string().contains("21/20"));

        let err = ExecutorError::HitlRequired;
        assert!(err.to_string().contains("HITL"));
    }
}
