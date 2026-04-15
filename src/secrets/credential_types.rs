//! Credential type taxonomy for multi-target infrastructure.
//!
//! Each credential type defines what data is stored and how it's used
//! to connect to a target (SSH, API, WinRM, etc.).

use serde::{Deserialize, Serialize};

/// Type of credential stored in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialType {
    /// SSH private key (ed25519 or RSA).
    SshKey {
        key_type: SshKeyType,
        username: String,
        #[serde(default)]
        has_passphrase: bool,
    },

    /// REST API key (firewalls, cloud services).
    ApiKey {
        provider: String,
        #[serde(default)]
        scopes: Vec<String>,
    },

    /// WinRM Basic auth (NTLM — less secure, functional).
    /// ⚠️ Vulnerable to pass-the-hash. Recommend WinrmCert for AD environments.
    WinrmBasic {
        username: String,
        #[serde(default)]
        domain: Option<String>,
    },

    /// WinRM Certificate auth (recommended for AD environments).
    WinrmCert {
        #[serde(default)]
        has_cert_password: bool,
    },

    /// Generic bearer token.
    Token { provider: String },
}

/// SSH key algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshKeyType {
    Ed25519,
    Rsa,
}

impl std::fmt::Display for SshKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "ed25519"),
            Self::Rsa => write!(f, "rsa"),
        }
    }
}

/// Metadata for a stored credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMeta {
    /// Unique name for this credential (referenced by targets).
    pub name: String,
    /// Type-specific configuration.
    pub credential_type: CredentialType,
    /// Target host this credential is for (IP or hostname pattern).
    pub target_host: String,
    /// Target port.
    pub target_port: Option<u16>,
    /// When the credential was last tested.
    pub last_tested: Option<String>,
    /// Whether the last test was successful.
    pub last_test_ok: Option<bool>,
    /// When the credential was created.
    pub created_at: String,
    /// When the credential expires (if applicable).
    pub expires_at: Option<String>,
}

impl CredentialMeta {
    pub fn new(name: &str, cred_type: CredentialType, target_host: &str) -> Self {
        Self {
            name: name.to_string(),
            credential_type: cred_type,
            target_host: target_host.to_string(),
            target_port: None,
            last_tested: None,
            last_test_ok: None,
            created_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
        }
    }

    /// Whether this credential needs a connection test.
    pub fn needs_test(&self) -> bool {
        self.last_tested.is_none() || self.last_test_ok != Some(true)
    }

    /// Human-readable label for the credential type.
    pub fn type_label(&self) -> &str {
        match &self.credential_type {
            CredentialType::SshKey { .. } => "SSH Key",
            CredentialType::ApiKey { .. } => "API Key",
            CredentialType::WinrmBasic { .. } => "WinRM (NTLM)",
            CredentialType::WinrmCert { .. } => "WinRM (Certificate)",
            CredentialType::Token { .. } => "Bearer Token",
        }
    }
}

/// Configuration for a target server/firewall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub name: String,
    pub host: String,
    #[serde(rename = "type")]
    pub target_type: TargetType,
    pub access: AccessType,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_mode")]
    pub mode: String,
    pub credential: String,
    #[serde(default)]
    pub ssh_host_key: Option<String>,
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub driver: Option<String>,
}

fn default_port() -> u16 {
    22
}
fn default_mode() -> String {
    "investigator".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Linux,
    Windows,
    Firewall,
    Network,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessType {
    Ssh,
    Winrm,
    Api,
    Local,
}

impl TargetConfig {
    /// Default port for this access type.
    pub fn default_port_for_access(&self) -> u16 {
        match self.access {
            AccessType::Ssh => 22,
            AccessType::Winrm => 5985,
            AccessType::Api => 443,
            AccessType::Local => 0,
        }
    }

    /// Whether this target can execute actions (vs read-only).
    pub fn can_execute(&self) -> bool {
        self.mode != "investigator" && !self.allowed_actions.is_empty()
    }

    /// Whether an action is allowed on this target.
    pub fn is_action_allowed(&self, action_id: &str) -> bool {
        self.allowed_actions.iter().any(|a| a == action_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_key_credential() {
        let cred = CredentialType::SshKey {
            key_type: SshKeyType::Ed25519,
            username: "threatclaw-remote".to_string(),
            has_passphrase: false,
        };
        let meta = CredentialMeta::new("srv-prod-01-ssh", cred, "192.168.1.10");
        assert_eq!(meta.type_label(), "SSH Key");
        assert!(meta.needs_test());
    }

    #[test]
    fn test_api_key_credential() {
        let cred = CredentialType::ApiKey {
            provider: "pfsense".to_string(),
            scopes: vec!["firewall".to_string()],
        };
        let meta = CredentialMeta::new("pfsense-key", cred, "192.168.1.1");
        assert_eq!(meta.type_label(), "API Key");
    }

    #[test]
    fn test_winrm_basic_credential() {
        let cred = CredentialType::WinrmBasic {
            username: "threatclaw-svc".to_string(),
            domain: Some("CORP.LOCAL".to_string()),
        };
        let meta = CredentialMeta::new("win-srv-01", cred, "192.168.1.20");
        assert_eq!(meta.type_label(), "WinRM (NTLM)");
    }

    #[test]
    fn test_target_config_can_execute() {
        let target = TargetConfig {
            name: "srv-prod-01".to_string(),
            host: "192.168.1.10".to_string(),
            target_type: TargetType::Linux,
            access: AccessType::Ssh,
            port: 22,
            mode: "responder".to_string(),
            credential: "srv-prod-01-ssh".to_string(),
            ssh_host_key: Some("sha256:ABC123".to_string()),
            allowed_actions: vec!["net-002".to_string(), "usr-001".to_string()],
            tags: vec!["production".to_string()],
            driver: None,
        };
        assert!(target.can_execute());
        assert!(target.is_action_allowed("net-002"));
        assert!(!target.is_action_allowed("proc-001"));
    }

    #[test]
    fn test_target_investigator_cannot_execute() {
        let target = TargetConfig {
            name: "srv-ad-01".to_string(),
            host: "192.168.1.20".to_string(),
            target_type: TargetType::Windows,
            access: AccessType::Winrm,
            port: 5985,
            mode: "investigator".to_string(),
            credential: "win-cred".to_string(),
            ssh_host_key: None,
            allowed_actions: vec![],
            tags: vec![],
            driver: None,
        };
        assert!(!target.can_execute());
    }

    #[test]
    fn test_target_local() {
        let target = TargetConfig {
            name: "threatclaw-local".to_string(),
            host: "127.0.0.1".to_string(),
            target_type: TargetType::Local,
            access: AccessType::Local,
            port: 0,
            mode: "responder".to_string(),
            credential: "".to_string(),
            ssh_host_key: None,
            allowed_actions: vec!["net-001".to_string(), "net-002".to_string()],
            tags: vec![],
            driver: None,
        };
        assert!(target.can_execute());
    }

    #[test]
    fn test_serialize_credential_type() {
        let cred = CredentialType::SshKey {
            key_type: SshKeyType::Ed25519,
            username: "user".to_string(),
            has_passphrase: false,
        };
        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("ssh_key"));
        assert!(json.contains("ed25519"));

        let parsed: CredentialType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cred);
    }

    #[test]
    fn test_serialize_target_config() {
        let target = TargetConfig {
            name: "test".to_string(),
            host: "10.0.0.1".to_string(),
            target_type: TargetType::Firewall,
            access: AccessType::Api,
            port: 443,
            mode: "responder".to_string(),
            credential: "fw-key".to_string(),
            ssh_host_key: None,
            allowed_actions: vec!["fw-block-ip".to_string()],
            tags: vec!["network".to_string()],
            driver: Some("pfsense".to_string()),
        };
        let json = serde_json::to_string(&target).unwrap();
        assert!(json.contains("firewall"));
        assert!(json.contains("pfsense"));
    }
}
