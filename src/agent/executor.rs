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
/// La commande est décomposée en programme + arguments.
/// Jamais de shell=true — pas d'injection possible.
pub fn execute_validated(cmd: &ValidatedCommand) -> Result<ExecutionResult, ExecutorError> {
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
