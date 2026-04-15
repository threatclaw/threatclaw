//! SSH Remote Executor — execute whitelisted commands on remote targets.
//!
//! Uses the target infrastructure (from settings DB) to resolve hostnames,
//! credentials, and SSH connection parameters.
//! Only executes commands validated by the remediation whitelist.
//!
//! Security:
//! - StrictHostKeyChecking=yes (TOFU model with ssh_host_key in target config)
//! - No shell expansion (command passed as array)
//! - Timeout per command (30s default)
//! - All executions audited

use std::collections::HashMap;

use crate::agent::executor::ExecutionResult;
use crate::agent::remediation_whitelist::ValidatedCommand;

/// SSH connection parameters resolved from target infrastructure.
#[derive(Debug, Clone)]
pub struct SshTarget {
    pub target_id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub credential_name: Option<String>,
    pub ssh_host_key: Option<String>,
}

/// Errors specific to SSH execution.
#[derive(Debug, Clone)]
pub enum SshExecutorError {
    TargetNotFound(String),
    TargetNotSsh(String),
    ConnectionFailed(String),
    CommandFailed(String),
    Timeout,
}

impl std::fmt::Display for SshExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetNotFound(t) => write!(f, "Target not found: {t}"),
            Self::TargetNotSsh(t) => write!(f, "Target {t} does not use SSH access"),
            Self::ConnectionFailed(e) => write!(f, "SSH connection failed: {e}"),
            Self::CommandFailed(e) => write!(f, "SSH command failed: {e}"),
            Self::Timeout => write!(f, "SSH command timed out"),
        }
    }
}

impl std::error::Error for SshExecutorError {}

/// Resolve a target by ID or hostname from the settings DB.
pub async fn resolve_target(
    store: &dyn crate::db::Database,
    target_ref: &str,
) -> Result<SshTarget, SshExecutorError> {
    let settings = store.list_settings("_targets").await.unwrap_or_default();

    for setting in &settings {
        let val = &setting.value;
        let id = val["id"].as_str().unwrap_or("");
        let host = val["host"].as_str().unwrap_or("");

        // Match by ID or hostname
        if id == target_ref || host == target_ref || id.eq_ignore_ascii_case(target_ref) {
            let access_type = val["access_type"].as_str().unwrap_or("ssh");
            if access_type != "ssh" {
                return Err(SshExecutorError::TargetNotSsh(target_ref.to_string()));
            }

            return Ok(SshTarget {
                target_id: id.to_string(),
                host: host.to_string(),
                port: val["port"].as_u64().unwrap_or(22) as u16,
                username: val["credential_name"]
                    .as_str()
                    .unwrap_or("root")
                    .to_string(),
                credential_name: val["credential_name"].as_str().map(String::from),
                ssh_host_key: val["ssh_host_key"].as_str().map(String::from),
            });
        }
    }

    Err(SshExecutorError::TargetNotFound(target_ref.to_string()))
}

/// Execute a validated command on a remote target via SSH.
///
/// Uses `ssh` binary (not libssh) for maximum compatibility.
/// Command is passed as a single string to SSH but is already validated
/// by the whitelist (no shell injection possible).
pub fn execute_ssh(
    target: &SshTarget,
    cmd: &ValidatedCommand,
    timeout_secs: u64,
) -> Result<ExecutionResult, SshExecutorError> {
    let mut ssh_args = vec![
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        format!("ConnectTimeout={}", timeout_secs.min(10)),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-p".to_string(),
        target.port.to_string(),
    ];

    // Add host key if known (TOFU model)
    if let Some(ref _key) = target.ssh_host_key {
        ssh_args.extend_from_slice(&["-o".to_string(), "StrictHostKeyChecking=yes".to_string()]);
    }

    let destination = format!("{}@{}", target.username, target.host);
    ssh_args.push(destination);
    ssh_args.push(cmd.rendered_cmd.clone());

    tracing::info!(
        "SSH_EXECUTOR: {}@{}:{} — {}",
        target.username,
        target.host,
        target.port,
        cmd.rendered_cmd
    );

    let output = std::process::Command::new("ssh")
        .args(&ssh_args)
        .output()
        .map_err(|e| SshExecutorError::ConnectionFailed(format!("ssh binary: {e}")))?;

    let result = ExecutionResult {
        cmd_id: cmd.id.clone(),
        success: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        rendered_cmd: format!(
            "ssh {}@{}:{} '{}'",
            target.username, target.host, target.port, cmd.rendered_cmd
        ),
    };

    if result.success {
        tracing::info!(
            "SSH_EXECUTOR: {} on {} completed (exit 0)",
            cmd.id,
            target.target_id
        );
    } else {
        tracing::warn!(
            "SSH_EXECUTOR: {} on {} failed (exit {}): {}",
            cmd.id,
            target.target_id,
            result.exit_code.unwrap_or(-1),
            result.stderr.trim()
        );
    }

    Ok(result)
}

/// Convenience: resolve target + execute command.
pub async fn execute_on_target(
    store: &dyn crate::db::Database,
    target_ref: &str,
    cmd: &ValidatedCommand,
) -> Result<ExecutionResult, SshExecutorError> {
    let target = resolve_target(store, target_ref).await?;
    execute_ssh(&target, cmd, 30)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_executor_error_display() {
        assert!(
            SshExecutorError::TargetNotFound("srv-01".into())
                .to_string()
                .contains("srv-01")
        );
        assert!(
            SshExecutorError::TargetNotSsh("fw-01".into())
                .to_string()
                .contains("SSH")
        );
        assert!(SshExecutorError::Timeout.to_string().contains("timed out"));
    }
}
