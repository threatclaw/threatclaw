//! Pilier II — Whitelist Commandes de Remédiation (OWASP ASI02: Tool Misuse)
//!
//! Liste EXHAUSTIVE des commandes autorisées. Si une commande n'est pas dans
//! cette liste, elle n'existe pas pour l'agent. Pas de shell, pas d'évaluation
//! dynamique — uniquement des templates prédéfinis avec paramètres validés.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RemediationCommand {
    pub id: &'static str,
    pub cmd_template: &'static str,
    pub description: &'static str,
    pub risk: RiskLevel,
    pub reversible: bool,
    pub undo_template: Option<&'static str>,
    pub requires_hitl: bool,
    pub max_targets: u32,
    pub forbidden_targets: &'static [&'static str],
    pub forbidden_paths: &'static [&'static str],
    pub param_keys: &'static [&'static str],
}

/// Commande validée, prête à être exécutée.
#[derive(Debug, Clone)]
pub struct ValidatedCommand {
    pub id: String,
    pub rendered_cmd: String,
    pub undo_cmd: Option<String>,
    pub risk: RiskLevel,
    pub requires_hitl: bool,
    pub params: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub enum RemediationError {
    NotInWhitelist(String),
    ForbiddenTarget(String),
    ForbiddenPath(String),
    MissingParam(String),
    ParamInjection { param: String, value: String },
    TooManyTargets { max: u32, requested: u32 },
}

impl std::fmt::Display for RemediationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInWhitelist(id) => write!(f, "Command '{id}' is not in the remediation whitelist"),
            Self::ForbiddenTarget(t) => write!(f, "Target '{t}' is forbidden (system/protected account)"),
            Self::ForbiddenPath(p) => write!(f, "Path '{p}' is in a forbidden directory"),
            Self::MissingParam(p) => write!(f, "Required parameter '{p}' is missing"),
            Self::ParamInjection { param, value } => {
                write!(f, "Parameter '{param}' contains injection characters: '{value}'")
            }
            Self::TooManyTargets { max, requested } => {
                write!(f, "Too many targets: max {max}, requested {requested}")
            }
        }
    }
}

impl std::error::Error for RemediationError {}

// ── WHITELIST ──

pub static REMEDIATION_WHITELIST: &[RemediationCommand] = &[
    // === RÉSEAU ===
    RemediationCommand {
        id: "net-001",
        cmd_template: "iptables -A INPUT -s {IP} -j DROP",
        description: "Bloquer une IP entrante",
        risk: RiskLevel::Medium,
        reversible: true,
        undo_template: Some("iptables -D INPUT -s {IP} -j DROP"),
        requires_hitl: true,
        max_targets: 10,
        forbidden_targets: &["127.0.0.1", "::1", "0.0.0.0"],
        forbidden_paths: &[],
        param_keys: &["IP"],
    },
    RemediationCommand {
        id: "net-002",
        cmd_template: "fail2ban-client set sshd banip {IP}",
        description: "Bannir une IP via fail2ban SSH",
        risk: RiskLevel::Low,
        reversible: true,
        undo_template: Some("fail2ban-client set sshd unbanip {IP}"),
        requires_hitl: true,
        max_targets: 50,
        forbidden_targets: &["127.0.0.1", "::1"],
        forbidden_paths: &[],
        param_keys: &["IP"],
    },
    RemediationCommand {
        id: "net-003",
        cmd_template: "ss -K dst {IP}",
        description: "Couper les connexions actives depuis une IP",
        risk: RiskLevel::Medium,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 1,
        forbidden_targets: &["127.0.0.1", "::1"],
        forbidden_paths: &[],
        param_keys: &["IP"],
    },
    // === UTILISATEURS ===
    RemediationCommand {
        id: "usr-001",
        cmd_template: "usermod -L {USERNAME}",
        description: "Verrouiller un compte utilisateur",
        risk: RiskLevel::High,
        reversible: true,
        undo_template: Some("usermod -U {USERNAME}"),
        requires_hitl: true,
        max_targets: 1,
        forbidden_targets: &["root", "daemon", "www-data", "threatclaw", "nobody", "systemd-network"],
        forbidden_paths: &[],
        param_keys: &["USERNAME"],
    },
    RemediationCommand {
        id: "usr-002",
        cmd_template: "passwd -l {USERNAME}",
        description: "Désactiver le mot de passe d'un compte",
        risk: RiskLevel::High,
        reversible: true,
        undo_template: Some("passwd -u {USERNAME}"),
        requires_hitl: true,
        max_targets: 1,
        forbidden_targets: &["root", "daemon", "threatclaw"],
        forbidden_paths: &[],
        param_keys: &["USERNAME"],
    },
    RemediationCommand {
        id: "usr-003",
        cmd_template: "pkill -u {USERNAME}",
        description: "Terminer toutes les sessions d'un utilisateur",
        risk: RiskLevel::High,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 1,
        forbidden_targets: &["root", "threatclaw", "daemon"],
        forbidden_paths: &[],
        param_keys: &["USERNAME"],
    },
    // === SSH ===
    RemediationCommand {
        id: "ssh-001",
        cmd_template: "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
        description: "Désactiver la connexion SSH root",
        risk: RiskLevel::Medium,
        reversible: true,
        undo_template: None,
        requires_hitl: true,
        max_targets: 1,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &[],
    },
    // === PROCESSUS ===
    RemediationCommand {
        id: "proc-001",
        cmd_template: "kill -9 {PID}",
        description: "Terminer un processus suspect",
        risk: RiskLevel::Medium,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 5,
        forbidden_targets: &["1"],  // PID 1 = init
        forbidden_paths: &[],
        param_keys: &["PID"],
    },
    // === FICHIERS ===
    RemediationCommand {
        id: "file-001",
        cmd_template: "chmod 000 {FILEPATH}",
        description: "Révoquer tous les droits d'un fichier suspect",
        risk: RiskLevel::Medium,
        reversible: true,
        undo_template: None,
        requires_hitl: true,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &["/etc", "/bin", "/usr", "/lib", "/boot", "/sbin", "/dev", "/proc", "/sys"],
        param_keys: &["FILEPATH"],
    },
    // === PACKAGES ===
    RemediationCommand {
        id: "pkg-001",
        cmd_template: "apt-get install --only-upgrade -y {PACKAGE}",
        description: "Mettre à jour un package vulnérable",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 5,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["PACKAGE"],
    },
    // === DOCKER ===
    RemediationCommand {
        id: "docker-001",
        cmd_template: "docker stop {CONTAINER}",
        description: "Stopper un conteneur suspect",
        risk: RiskLevel::Medium,
        reversible: true,
        undo_template: Some("docker start {CONTAINER}"),
        requires_hitl: true,
        max_targets: 3,
        forbidden_targets: &["threatclaw-core", "threatclaw-db", "threatclaw-dashboard", "docker-threatclaw-db-1", "docker-redis-1"],
        forbidden_paths: &[],
        param_keys: &["CONTAINER"],
    },
    // === CRON ===
    RemediationCommand {
        id: "cron-001",
        cmd_template: "crontab -u {USERNAME} -r",
        description: "Supprimer le crontab d'un utilisateur suspect",
        risk: RiskLevel::High,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 1,
        forbidden_targets: &["root", "threatclaw"],
        forbidden_paths: &[],
        param_keys: &["USERNAME"],
    },
];

// ── Caractères interdits dans les paramètres (anti-injection de commande) ──
const FORBIDDEN_CHARS: &[char] = &[';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\\', '\'', '"'];

/// Valide un paramètre contre les injections de commande.
fn validate_param(key: &str, value: &str) -> Result<(), RemediationError> {
    if value.is_empty() {
        return Err(RemediationError::MissingParam(key.to_string()));
    }

    for ch in FORBIDDEN_CHARS {
        if value.contains(*ch) {
            return Err(RemediationError::ParamInjection {
                param: key.to_string(),
                value: value.to_string(),
            });
        }
    }

    // Bloquer les séquences de traversal de chemin
    if value.contains("..") {
        return Err(RemediationError::ParamInjection {
            param: key.to_string(),
            value: value.to_string(),
        });
    }

    Ok(())
}

/// Recherche une commande dans la whitelist.
pub fn find_command(cmd_id: &str) -> Option<&'static RemediationCommand> {
    REMEDIATION_WHITELIST.iter().find(|c| c.id == cmd_id)
}

/// Valide et rend une commande prête à l'exécution.
pub fn validate_remediation(
    cmd_id: &str,
    params: &HashMap<String, String>,
) -> Result<ValidatedCommand, RemediationError> {
    let cmd = find_command(cmd_id).ok_or_else(|| RemediationError::NotInWhitelist(cmd_id.to_string()))?;

    // Vérifier que tous les paramètres requis sont présents
    for key in cmd.param_keys {
        if !params.contains_key(*key) {
            return Err(RemediationError::MissingParam(key.to_string()));
        }
    }

    // Valider chaque paramètre (anti-injection)
    for (key, value) in params {
        validate_param(key, value)?;
    }

    // Vérifier les cibles interdites
    for key in &["USERNAME", "CONTAINER", "IP", "PID"] {
        if let Some(target) = params.get(*key) {
            if cmd.forbidden_targets.iter().any(|f| f == target) {
                return Err(RemediationError::ForbiddenTarget(target.clone()));
            }
        }
    }

    // Vérifier les chemins interdits
    if let Some(filepath) = params.get("FILEPATH") {
        for forbidden in cmd.forbidden_paths {
            if filepath.starts_with(forbidden) {
                return Err(RemediationError::ForbiddenPath(filepath.clone()));
            }
        }
    }

    // Rendre la commande
    let mut rendered = cmd.cmd_template.to_string();
    for (key, value) in params {
        rendered = rendered.replace(&format!("{{{key}}}"), value);
    }

    let undo = cmd.undo_template.map(|t| {
        let mut u = t.to_string();
        for (key, value) in params {
            u = u.replace(&format!("{{{key}}}"), value);
        }
        u
    });

    Ok(ValidatedCommand {
        id: cmd_id.to_string(),
        rendered_cmd: rendered,
        undo_cmd: undo,
        risk: cmd.risk,
        requires_hitl: cmd.requires_hitl,
        params: params.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(kvs: &[(&str, &str)]) -> HashMap<String, String> {
        kvs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_valid_command() {
        let p = params(&[("IP", "192.168.1.100")]);
        let result = validate_remediation("net-001", &p);
        assert!(result.is_ok());
        let cmd = result.unwrap();
        assert_eq!(cmd.rendered_cmd, "iptables -A INPUT -s 192.168.1.100 -j DROP");
        assert!(cmd.undo_cmd.is_some());
    }

    #[test]
    fn test_not_in_whitelist() {
        let p = params(&[("CMD", "rm -rf /")]);
        let result = validate_remediation("evil-001", &p);
        assert!(matches!(result, Err(RemediationError::NotInWhitelist(_))));
    }

    #[test]
    fn test_forbidden_target_root() {
        let p = params(&[("USERNAME", "root")]);
        let result = validate_remediation("usr-001", &p);
        assert!(matches!(result, Err(RemediationError::ForbiddenTarget(_))));
    }

    #[test]
    fn test_forbidden_target_localhost() {
        let p = params(&[("IP", "127.0.0.1")]);
        let result = validate_remediation("net-001", &p);
        assert!(matches!(result, Err(RemediationError::ForbiddenTarget(_))));
    }

    #[test]
    fn test_forbidden_path_etc() {
        let p = params(&[("FILEPATH", "/etc/passwd")]);
        let result = validate_remediation("file-001", &p);
        assert!(matches!(result, Err(RemediationError::ForbiddenPath(_))));
    }

    #[test]
    fn test_injection_semicolon() {
        let p = params(&[("IP", "1.2.3.4; rm -rf /")]);
        let result = validate_remediation("net-001", &p);
        assert!(matches!(result, Err(RemediationError::ParamInjection { .. })));
    }

    #[test]
    fn test_injection_pipe() {
        let p = params(&[("USERNAME", "user|cat /etc/shadow")]);
        let result = validate_remediation("usr-001", &p);
        assert!(matches!(result, Err(RemediationError::ParamInjection { .. })));
    }

    #[test]
    fn test_injection_backtick() {
        let p = params(&[("IP", "`whoami`")]);
        let result = validate_remediation("net-001", &p);
        assert!(matches!(result, Err(RemediationError::ParamInjection { .. })));
    }

    #[test]
    fn test_injection_dollar() {
        let p = params(&[("CONTAINER", "$(cat /etc/passwd)")]);
        let result = validate_remediation("docker-001", &p);
        assert!(matches!(result, Err(RemediationError::ParamInjection { .. })));
    }

    #[test]
    fn test_injection_path_traversal() {
        let p = params(&[("FILEPATH", "/tmp/../../etc/shadow")]);
        let result = validate_remediation("file-001", &p);
        assert!(matches!(result, Err(RemediationError::ParamInjection { .. })));
    }

    #[test]
    fn test_missing_param() {
        let p: HashMap<String, String> = HashMap::new();
        let result = validate_remediation("net-001", &p);
        assert!(matches!(result, Err(RemediationError::MissingParam(_))));
    }

    #[test]
    fn test_forbidden_threatclaw_container() {
        let p = params(&[("CONTAINER", "threatclaw-core")]);
        let result = validate_remediation("docker-001", &p);
        assert!(matches!(result, Err(RemediationError::ForbiddenTarget(_))));
    }

    #[test]
    fn test_forbidden_pid_1() {
        let p = params(&[("PID", "1")]);
        let result = validate_remediation("proc-001", &p);
        assert!(matches!(result, Err(RemediationError::ForbiddenTarget(_))));
    }

    #[test]
    fn test_undo_command_rendered() {
        let p = params(&[("IP", "10.0.0.5")]);
        let cmd = validate_remediation("net-001", &p).unwrap();
        assert_eq!(cmd.undo_cmd, Some("iptables -D INPUT -s 10.0.0.5 -j DROP".to_string()));
    }

    #[test]
    fn test_no_undo_for_irreversible() {
        let p = params(&[("PID", "12345")]);
        let cmd = validate_remediation("proc-001", &p).unwrap();
        assert!(cmd.undo_cmd.is_none());
    }

    #[test]
    fn test_all_whitelist_entries_have_valid_ids() {
        for cmd in REMEDIATION_WHITELIST {
            assert!(!cmd.id.is_empty());
            assert!(cmd.id.contains('-'), "ID should be category-number: {}", cmd.id);
        }
    }

    #[test]
    fn test_all_hitl_required() {
        for cmd in REMEDIATION_WHITELIST {
            assert!(cmd.requires_hitl, "Command {} must require HITL", cmd.id);
        }
    }

    #[test]
    fn test_find_command() {
        assert!(find_command("net-001").is_some());
        assert!(find_command("nonexistent").is_none());
    }

    #[test]
    fn test_valid_package_upgrade() {
        let p = params(&[("PACKAGE", "nginx")]);
        let cmd = validate_remediation("pkg-001", &p).unwrap();
        assert_eq!(cmd.rendered_cmd, "apt-get install --only-upgrade -y nginx");
        assert_eq!(cmd.risk, RiskLevel::Low);
    }

    #[test]
    fn test_ssh_no_params_needed() {
        let p: HashMap<String, String> = HashMap::new();
        let cmd = validate_remediation("ssh-001", &p).unwrap();
        assert!(cmd.rendered_cmd.contains("PermitRootLogin no"));
    }
}
