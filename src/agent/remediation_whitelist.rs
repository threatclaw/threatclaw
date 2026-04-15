//! Pilier II — Whitelist Commandes de Remédiation (OWASP ASI02: Tool Misuse)
//!
//! Liste EXHAUSTIVE des commandes autorisées. Si une commande n'est pas dans
//! cette liste, elle n'existe pas pour l'agent. Pas de shell, pas d'évaluation
//! dynamique — uniquement des templates prédéfinis avec paramètres validés.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Global command registry (core + dynamic skill commands).
static COMMAND_REGISTRY: OnceLock<CommandRegistry> = OnceLock::new();

/// Initialize the global command registry by scanning skill directories.
/// Call once at startup. Safe to call multiple times (only first wins).
pub fn init_command_registry() {
    COMMAND_REGISTRY.get_or_init(|| {
        let mut registry = CommandRegistry::new();
        // Scan both skill directories
        for dir in &["skills-src", "skills"] {
            let path = std::path::Path::new(dir);
            if path.exists() {
                registry.load_skill_actions(path);
            }
        }
        tracing::info!(
            "WHITELIST: Global registry initialized — {} total commands",
            registry.len()
        );
        registry
    });
}

/// Get a reference to the global command registry.
pub fn global_registry() -> &'static CommandRegistry {
    COMMAND_REGISTRY.get_or_init(|| {
        let mut registry = CommandRegistry::new();
        for dir in &["skills-src", "skills"] {
            let path = std::path::Path::new(dir);
            if path.exists() {
                registry.load_skill_actions(path);
            }
        }
        registry
    })
}

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
            Self::NotInWhitelist(id) => {
                write!(f, "Command '{id}' is not in the remediation whitelist")
            }
            Self::ForbiddenTarget(t) => {
                write!(f, "Target '{t}' is forbidden (system/protected account)")
            }
            Self::ForbiddenPath(p) => write!(f, "Path '{p}' is in a forbidden directory"),
            Self::MissingParam(p) => write!(f, "Required parameter '{p}' is missing"),
            Self::ParamInjection { param, value } => {
                write!(
                    f,
                    "Parameter '{param}' contains injection characters: '{value}'"
                )
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
        forbidden_targets: &[
            "root",
            "daemon",
            "www-data",
            "threatclaw",
            "nobody",
            "systemd-network",
        ],
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
        forbidden_targets: &["1"], // PID 1 = init
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
        forbidden_paths: &[
            "/etc", "/bin", "/usr", "/lib", "/boot", "/sbin", "/dev", "/proc", "/sys",
        ],
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
        forbidden_targets: &[
            "threatclaw-core",
            "threatclaw-db",
            "threatclaw-dashboard",
            "docker-threatclaw-db-1",
            "docker-redis-1",
        ],
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
    // === RÉSEAU — ANTI-EXFILTRATION ===
    RemediationCommand {
        id: "net-004",
        cmd_template: "iptables -A OUTPUT -d {IP} -j DROP",
        description: "Bloquer le trafic sortant vers une IP (anti-exfiltration C2)",
        risk: RiskLevel::Medium,
        reversible: true,
        undo_template: Some("iptables -D OUTPUT -d {IP} -j DROP"),
        requires_hitl: true,
        max_targets: 10,
        forbidden_targets: &["127.0.0.1", "::1", "0.0.0.0"],
        forbidden_paths: &[],
        param_keys: &["IP"],
    },
    RemediationCommand {
        id: "net-005",
        cmd_template: "echo {IP} {DOMAIN} >> /etc/hosts",
        description: "Sinkhole DNS — rediriger un domaine malveillant vers une IP locale",
        risk: RiskLevel::Low,
        reversible: true,
        undo_template: None,
        requires_hitl: true,
        max_targets: 20,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["IP", "DOMAIN"],
    },
    // === FORENSIQUE (READ-ONLY) ===
    RemediationCommand {
        id: "forensic-001",
        cmd_template: "sha256sum {FILEPATH}",
        description: "Calculer le hash SHA-256 d'un fichier suspect (preuve)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 20,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["FILEPATH"],
    },
    RemediationCommand {
        id: "forensic-002",
        cmd_template: "lsof -p {PID}",
        description: "Lister les fichiers ouverts par un processus suspect",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 5,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["PID"],
    },
    RemediationCommand {
        id: "forensic-003",
        cmd_template: "cp -p {FILEPATH} /var/lib/threatclaw/quarantine/",
        description: "Copier un fichier suspect en quarantaine (preuve forensique)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &["/dev", "/proc", "/sys"],
        param_keys: &["FILEPATH"],
    },
    RemediationCommand {
        id: "forensic-004",
        cmd_template: "ss -tnp",
        description: "Snapshot des connexions réseau actives (preuve forensique)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 1,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &[],
    },
    // === SERVICES (SYSTEMD) ===
    RemediationCommand {
        id: "svc-001",
        cmd_template: "systemctl stop {SERVICE}",
        description: "Stopper un service suspect",
        risk: RiskLevel::Medium,
        reversible: true,
        undo_template: Some("systemctl start {SERVICE}"),
        requires_hitl: true,
        max_targets: 3,
        forbidden_targets: &[
            "sshd",
            "ssh",
            "systemd-journald",
            "docker",
            "containerd",
            "threatclaw",
            "postgresql",
            "redis",
        ],
        forbidden_paths: &[],
        param_keys: &["SERVICE"],
    },
    RemediationCommand {
        id: "svc-002",
        cmd_template: "systemctl disable {SERVICE}",
        description: "Désactiver un service pour empêcher son redémarrage",
        risk: RiskLevel::Medium,
        reversible: true,
        undo_template: Some("systemctl enable {SERVICE}"),
        requires_hitl: true,
        max_targets: 3,
        forbidden_targets: &[
            "sshd",
            "ssh",
            "systemd-journald",
            "docker",
            "containerd",
            "threatclaw",
            "postgresql",
            "redis",
        ],
        forbidden_paths: &[],
        param_keys: &["SERVICE"],
    },
    // === FICHIERS (QUARANTAINE + IMMUTABILITÉ) ===
    RemediationCommand {
        id: "file-002",
        cmd_template: "mv {FILEPATH} /var/lib/threatclaw/quarantine/",
        description: "Déplacer un fichier suspect en quarantaine",
        risk: RiskLevel::Medium,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &[
            "/etc", "/bin", "/usr", "/lib", "/boot", "/sbin", "/dev", "/proc", "/sys",
        ],
        param_keys: &["FILEPATH"],
    },
    RemediationCommand {
        id: "file-003",
        cmd_template: "chattr +i {FILEPATH}",
        description: "Rendre un fichier immutable (empêcher toute modification)",
        risk: RiskLevel::Low,
        reversible: true,
        undo_template: Some("chattr -i {FILEPATH}"),
        requires_hitl: true,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &["/etc", "/bin", "/usr", "/lib", "/boot", "/sbin"],
        param_keys: &["FILEPATH"],
    },
    // === SSH HARDENING ===
    RemediationCommand {
        id: "ssh-002",
        cmd_template: "sed -i '/{SSHKEY}/d' /home/{USERNAME}/.ssh/authorized_keys",
        description: "Révoquer une clé SSH compromise d'un utilisateur",
        risk: RiskLevel::High,
        reversible: false,
        undo_template: None,
        requires_hitl: true,
        max_targets: 1,
        forbidden_targets: &["root", "threatclaw"],
        forbidden_paths: &[],
        param_keys: &["USERNAME", "SSHKEY"],
    },
    // === SCANNING (réseau — s'exécute localement, scanne la cible à distance) ===
    RemediationCommand {
        id: "scan-001",
        cmd_template: "nuclei -u {TARGET} -severity critical,high -jsonl -silent -rate-limit 50",
        description: "Scanner les vulnérabilités web/réseau d'une cible (Nuclei)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 5,
        forbidden_targets: &["127.0.0.1", "::1", "localhost"],
        forbidden_paths: &[],
        param_keys: &["TARGET"],
    },
    RemediationCommand {
        id: "scan-002",
        cmd_template: "trivy image --format json --severity CRITICAL,HIGH {IMAGE}",
        description: "Scanner les vulnérabilités d'une image Docker (Trivy)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["IMAGE"],
    },
    RemediationCommand {
        id: "scan-003",
        cmd_template: "nmap -sV --top-ports 1000 -T3 --open {TARGET}",
        description: "Scanner les ports ouverts et services d'une cible (Nmap)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 3,
        forbidden_targets: &["127.0.0.1", "::1", "localhost"],
        forbidden_paths: &[],
        param_keys: &["TARGET"],
    },
    RemediationCommand {
        id: "scan-004",
        cmd_template: "nuclei -u {TARGET} -t dns/ -jsonl -silent",
        description: "Scanner les misconfigurations DNS d'un domaine (Nuclei DNS)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["TARGET"],
    },
    RemediationCommand {
        id: "scan-005",
        cmd_template: "nuclei -u {TARGET} -t ssl/ -jsonl -silent",
        description: "Vérifier les certificats SSL/TLS d'une cible (Nuclei SSL)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["TARGET"],
    },
    // === SKILLS OFFICIELLES — LOOKUPS API (lecture seule, zéro risque) ===
    RemediationCommand {
        id: "skill-abuseipdb-check",
        cmd_template: "threatclaw skill-exec skill-abuseipdb check {IP}",
        description: "Vérifier la réputation d'une IP sur AbuseIPDB (score d'abus, pays, signalements)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 20,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["IP"],
    },
    RemediationCommand {
        id: "skill-crowdsec-check",
        cmd_template: "threatclaw skill-exec skill-cti-crowdsec check {IP}",
        description: "Vérifier une IP dans la base CrowdSec communautaire (scénarios d'attaque, classification)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 20,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["IP"],
    },
    RemediationCommand {
        id: "skill-shodan-lookup",
        cmd_template: "threatclaw skill-exec skill-shodan lookup {TARGET}",
        description: "Vérifier l'exposition d'une IP/domaine sur Shodan (ports ouverts, services, CVE)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["TARGET"],
    },
    RemediationCommand {
        id: "skill-virustotal-check",
        cmd_template: "threatclaw skill-exec skill-virustotal check {HASH}",
        description: "Vérifier un hash de fichier sur VirusTotal (70+ moteurs antivirus)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 20,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["HASH"],
    },
    RemediationCommand {
        id: "skill-virustotal-url",
        cmd_template: "threatclaw skill-exec skill-virustotal check-url {URL}",
        description: "Vérifier une URL suspecte sur VirusTotal",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["URL"],
    },
    RemediationCommand {
        id: "skill-hibp-check",
        cmd_template: "threatclaw skill-exec skill-darkweb-monitor check {EMAIL}",
        description: "Vérifier si un email est dans des fuites de données (HIBP)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 20,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["EMAIL"],
    },
    RemediationCommand {
        id: "skill-email-audit",
        cmd_template: "threatclaw skill-exec skill-email-audit check {DOMAIN}",
        description: "Vérifier SPF/DKIM/DMARC d'un domaine (sécurité email)",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 10,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["DOMAIN"],
    },
    RemediationCommand {
        id: "skill-wazuh-alerts",
        cmd_template: "threatclaw skill-exec skill-wazuh get-alerts {TARGET}",
        description: "Récupérer les alertes Wazuh pour un agent/host spécifique",
        risk: RiskLevel::Low,
        reversible: false,
        undo_template: None,
        requires_hitl: false,
        max_targets: 5,
        forbidden_targets: &[],
        forbidden_paths: &[],
        param_keys: &["TARGET"],
    },
];

// ── Caractères interdits dans les paramètres (anti-injection de commande) ──
const FORBIDDEN_CHARS: &[char] = &[
    ';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\\', '\'', '"',
];

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

/// Commande dynamique (chargée depuis skill.json ou DB).
/// Même structure que RemediationCommand mais avec des String owned.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DynamicCommand {
    pub id: String,
    pub cmd_template: String,
    pub description: String,
    #[serde(default = "default_risk")]
    pub risk: String,
    #[serde(default)]
    pub reversible: bool,
    pub undo_template: Option<String>,
    #[serde(default = "default_true")]
    pub requires_hitl: bool,
    #[serde(default = "default_max_targets")]
    pub max_targets: u32,
    #[serde(default)]
    pub forbidden_targets: Vec<String>,
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
    #[serde(default)]
    pub param_keys: Vec<String>,
}

fn default_risk() -> String {
    "low".to_string()
}
fn default_true() -> bool {
    true
}
fn default_max_targets() -> u32 {
    5
}

impl DynamicCommand {
    fn risk_level(&self) -> RiskLevel {
        match self.risk.to_lowercase().as_str() {
            "low" => RiskLevel::Low,
            "medium" => RiskLevel::Medium,
            "high" => RiskLevel::High,
            "critical" => RiskLevel::Critical,
            _ => RiskLevel::Medium,
        }
    }
}

/// Registre extensible de commandes — core + dynamiques.
pub struct CommandRegistry {
    dynamic_commands: Vec<DynamicCommand>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self {
            dynamic_commands: Vec::new(),
        }
    }

    /// Charge les actions déclarées par les skills depuis leurs skill.json.
    pub fn load_skill_actions(&mut self, skills_dir: &std::path::Path) {
        if let Ok(entries) = std::fs::read_dir(skills_dir) {
            for entry in entries.flatten() {
                let skill_json = entry.path().join("skill.json");
                if skill_json.exists() {
                    if let Ok(content) = std::fs::read_to_string(&skill_json) {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(actions) = val.get("actions").and_then(|a| a.as_array()) {
                                for action in actions {
                                    if let Ok(cmd) =
                                        serde_json::from_value::<DynamicCommand>(action.clone())
                                    {
                                        tracing::info!(
                                            "Loaded skill action: {} from {}",
                                            cmd.id,
                                            entry.path().display()
                                        );
                                        self.dynamic_commands.push(cmd);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tracing::info!(
            "CommandRegistry: {} core + {} skill actions loaded",
            REMEDIATION_WHITELIST.len(),
            self.dynamic_commands.len()
        );
    }

    /// Recherche une commande (core d'abord, puis dynamiques).
    pub fn find(&self, cmd_id: &str) -> Option<CommandRef<'_>> {
        // Core whitelist first
        if let Some(cmd) = REMEDIATION_WHITELIST.iter().find(|c| c.id == cmd_id) {
            return Some(CommandRef::Core(cmd));
        }
        // Dynamic skill commands
        if let Some(cmd) = self.dynamic_commands.iter().find(|c| c.id == cmd_id) {
            return Some(CommandRef::Dynamic(cmd));
        }
        None
    }

    /// Liste toutes les commandes disponibles (pour le prompt builder).
    pub fn all_command_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = REMEDIATION_WHITELIST.iter().map(|c| c.id).collect();
        ids.extend(self.dynamic_commands.iter().map(|c| c.id.as_str()));
        ids
    }

    /// Nombre total de commandes disponibles.
    pub fn len(&self) -> usize {
        REMEDIATION_WHITELIST.len() + self.dynamic_commands.len()
    }
}

/// Référence vers une commande (core ou dynamique).
pub enum CommandRef<'a> {
    Core(&'a RemediationCommand),
    Dynamic(&'a DynamicCommand),
}

/// Recherche une commande dans la whitelist core (rétro-compatible).
pub fn find_command(cmd_id: &str) -> Option<&'static RemediationCommand> {
    REMEDIATION_WHITELIST.iter().find(|c| c.id == cmd_id)
}

/// Valide et rend une commande prête à l'exécution.
/// Cherche dans la whitelist core ET les commandes dynamiques des skills.
pub fn validate_remediation(
    cmd_id: &str,
    params: &HashMap<String, String>,
) -> Result<ValidatedCommand, RemediationError> {
    // Try core whitelist first
    if let Some(cmd) = find_command(cmd_id) {
        return validate_core_command(cmd, cmd_id, params);
    }
    // Try dynamic skill commands from the global registry
    let registry = global_registry();
    if let Some(CommandRef::Dynamic(cmd)) = registry.find(cmd_id) {
        return validate_dynamic_command(cmd, cmd_id, params);
    }

    Err(RemediationError::NotInWhitelist(cmd_id.to_string()))
}

/// Valide une commande core.
fn validate_core_command(
    cmd: &RemediationCommand,
    cmd_id: &str,
    params: &HashMap<String, String>,
) -> Result<ValidatedCommand, RemediationError> {
    let cmd =
        find_command(cmd_id).ok_or_else(|| RemediationError::NotInWhitelist(cmd_id.to_string()))?;

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

/// Valide une commande dynamique (skill).
/// Mêmes contrôles anti-injection que les commandes core.
fn validate_dynamic_command(
    cmd: &DynamicCommand,
    cmd_id: &str,
    params: &HashMap<String, String>,
) -> Result<ValidatedCommand, RemediationError> {
    // Vérifier que tous les paramètres requis sont présents
    for key in &cmd.param_keys {
        if !params.contains_key(key.as_str()) {
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
        for forbidden in &cmd.forbidden_paths {
            if filepath.starts_with(forbidden.as_str()) {
                return Err(RemediationError::ForbiddenPath(filepath.clone()));
            }
        }
    }

    // Rendre la commande
    let mut rendered = cmd.cmd_template.clone();
    for (key, value) in params {
        rendered = rendered.replace(&format!("{{{key}}}"), value);
    }

    let undo = cmd.undo_template.as_ref().map(|t| {
        let mut u = t.clone();
        for (key, value) in params {
            u = u.replace(&format!("{{{key}}}"), value);
        }
        u
    });

    Ok(ValidatedCommand {
        id: cmd_id.to_string(),
        rendered_cmd: rendered,
        undo_cmd: undo,
        risk: cmd.risk_level(),
        requires_hitl: cmd.requires_hitl,
        params: params.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(kvs: &[(&str, &str)]) -> HashMap<String, String> {
        kvs.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_valid_command() {
        let p = params(&[("IP", "192.168.1.100")]);
        let result = validate_remediation("net-001", &p);
        assert!(result.is_ok());
        let cmd = result.unwrap();
        assert_eq!(
            cmd.rendered_cmd,
            "iptables -A INPUT -s 192.168.1.100 -j DROP"
        );
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
        assert!(matches!(
            result,
            Err(RemediationError::ParamInjection { .. })
        ));
    }

    #[test]
    fn test_injection_pipe() {
        let p = params(&[("USERNAME", "user|cat /etc/shadow")]);
        let result = validate_remediation("usr-001", &p);
        assert!(matches!(
            result,
            Err(RemediationError::ParamInjection { .. })
        ));
    }

    #[test]
    fn test_injection_backtick() {
        let p = params(&[("IP", "`whoami`")]);
        let result = validate_remediation("net-001", &p);
        assert!(matches!(
            result,
            Err(RemediationError::ParamInjection { .. })
        ));
    }

    #[test]
    fn test_injection_dollar() {
        let p = params(&[("CONTAINER", "$(cat /etc/passwd)")]);
        let result = validate_remediation("docker-001", &p);
        assert!(matches!(
            result,
            Err(RemediationError::ParamInjection { .. })
        ));
    }

    #[test]
    fn test_injection_path_traversal() {
        let p = params(&[("FILEPATH", "/tmp/../../etc/shadow")]);
        let result = validate_remediation("file-001", &p);
        assert!(matches!(
            result,
            Err(RemediationError::ParamInjection { .. })
        ));
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
        assert_eq!(
            cmd.undo_cmd,
            Some("iptables -D INPUT -s 10.0.0.5 -j DROP".to_string())
        );
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
            assert!(
                cmd.id.contains('-'),
                "ID should be category-number: {}",
                cmd.id
            );
        }
    }

    #[test]
    fn test_write_commands_require_hitl() {
        // Commands with risk > Low (write/destructive operations) must require HITL.
        // Low-risk read-only commands (scan, lookup, skill checks) can skip HITL.
        for cmd in REMEDIATION_WHITELIST {
            if cmd.risk != RiskLevel::Low {
                assert!(
                    cmd.requires_hitl,
                    "Non-low-risk command {} ({:?}) must require HITL",
                    cmd.id, cmd.risk
                );
            }
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

    #[test]
    fn test_dynamic_command_validation() {
        let cmd = DynamicCommand {
            id: "skill-test-001".to_string(),
            cmd_template: "echo scan {TARGET}".to_string(),
            description: "Test scan".to_string(),
            risk: "low".to_string(),
            reversible: false,
            undo_template: None,
            requires_hitl: true,
            max_targets: 5,
            forbidden_targets: vec!["localhost".to_string()],
            forbidden_paths: vec!["/etc".to_string()],
            param_keys: vec!["TARGET".to_string()],
        };

        // Valid command
        let p = params(&[("TARGET", "192.168.1.10")]);
        let result = validate_dynamic_command(&cmd, "skill-test-001", &p);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.rendered_cmd, "echo scan 192.168.1.10");
        assert_eq!(validated.risk, RiskLevel::Low);
        assert!(validated.requires_hitl);

        // Missing param
        let empty: HashMap<String, String> = HashMap::new();
        let result = validate_dynamic_command(&cmd, "skill-test-001", &empty);
        assert!(matches!(result, Err(RemediationError::MissingParam(_))));

        // Injection attempt
        let p = params(&[("TARGET", "; rm -rf /")]);
        let result = validate_dynamic_command(&cmd, "skill-test-001", &p);
        assert!(matches!(
            result,
            Err(RemediationError::ParamInjection { .. })
        ));
    }

    #[test]
    fn test_dynamic_command_forbidden_target() {
        let cmd = DynamicCommand {
            id: "skill-test-002".to_string(),
            cmd_template: "nmap {IP}".to_string(),
            description: "Scan".to_string(),
            risk: "medium".to_string(),
            reversible: false,
            undo_template: None,
            requires_hitl: true,
            max_targets: 1,
            forbidden_targets: vec!["127.0.0.1".to_string()],
            forbidden_paths: vec![],
            param_keys: vec!["IP".to_string()],
        };

        let p = params(&[("IP", "127.0.0.1")]);
        let result = validate_dynamic_command(&cmd, "skill-test-002", &p);
        assert!(matches!(result, Err(RemediationError::ForbiddenTarget(_))));
    }

    #[test]
    fn test_dynamic_command_with_undo() {
        let cmd = DynamicCommand {
            id: "skill-test-003".to_string(),
            cmd_template: "iptables -A INPUT -s {IP} -j DROP".to_string(),
            description: "Block IP".to_string(),
            risk: "high".to_string(),
            reversible: true,
            undo_template: Some("iptables -D INPUT -s {IP} -j DROP".to_string()),
            requires_hitl: true,
            max_targets: 5,
            forbidden_targets: vec![],
            forbidden_paths: vec![],
            param_keys: vec!["IP".to_string()],
        };

        let p = params(&[("IP", "10.0.0.1")]);
        let result = validate_dynamic_command(&cmd, "skill-test-003", &p).unwrap();
        assert_eq!(result.risk, RiskLevel::High);
        assert_eq!(
            result.undo_cmd,
            Some("iptables -D INPUT -s 10.0.0.1 -j DROP".to_string())
        );
    }

    #[test]
    fn test_command_registry_core_lookup() {
        let registry = CommandRegistry::new();
        assert!(registry.find("net-001").is_some());
        assert!(registry.find("nonexistent").is_none());
        assert!(registry.len() > 0);
    }

    #[test]
    fn test_global_registry_returns_same_instance() {
        let r1 = global_registry();
        let r2 = global_registry();
        assert_eq!(r1.len(), r2.len());
    }
}
