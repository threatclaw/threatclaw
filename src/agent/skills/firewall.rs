//! Trait `FirewallSkill` : abstraction commune sur les pare-feux connectés.
//!
//! Permet au pipeline (IE, dossier_enrichment, remediation_engine) de poser
//! des questions au firewall sans savoir s'il s'agit d'OPNsense, Fortigate,
//! Mikrotik, pfSense, etc.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Une entrée de log firewall normalisée. Tous les vendors mappent leurs
/// formats spécifiques sur cette structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallLogEntry {
    pub timestamp: DateTime<Utc>,
    /// "block" / "pass" / "allowed" / "drop" — le verdict de l'équipement.
    pub action: String,
    pub source_ip: String,
    pub source_port: Option<u16>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<u16>,
    /// "TCP" / "UDP" / "ICMP" / etc.
    pub proto: Option<String>,
    /// Pour les firewalls qui font de l'IDS (OPNsense+Suricata, Fortinet IPS) :
    /// la signature qui a matché. Vide si log pf classique.
    pub signature: Option<String>,
    /// Catégorie de la signature IDS si dispo (ET INFO, Misc activity, etc.)
    pub category: Option<String>,
    pub bytes_to_server: Option<u64>,
    pub bytes_to_client: Option<u64>,
    /// Identifiant du skill source (ex: "skill-opnsense"). Utile pour
    /// l'audit trail et le rendering UI ("vu sur Fortigate-edge").
    pub source_skill: String,
}

/// Erreurs possibles lors d'un appel firewall.
#[derive(Debug)]
pub enum FirewallError {
    NotConfigured,
    Auth(String),
    Network(String),
    Parse(String),
    Other(String),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "firewall skill not configured"),
            Self::Auth(s) => write!(f, "firewall auth error: {s}"),
            Self::Network(s) => write!(f, "firewall network error: {s}"),
            Self::Parse(s) => write!(f, "firewall parse error: {s}"),
            Self::Other(s) => write!(f, "firewall error: {s}"),
        }
    }
}

impl std::error::Error for FirewallError {}

/// Trait commun à tous les skills firewall.
///
/// Les implémentations encapsulent les credentials + l'URL de l'équipement.
/// Elles sont instanciées par le `SkillRegistry` à partir des `skill_configs`
/// enregistrés en DB.
#[async_trait]
pub trait FirewallSkill: Send + Sync {
    /// Identifiant machine du skill (ex: "skill-opnsense"). Utilisé pour le
    /// logging et l'audit trail.
    fn skill_id(&self) -> &'static str;

    /// Récupère les entrées de log (filter pf + IDS si dispo) pour une IP
    /// source dans une fenêtre temporelle. Cap implicite côté implémentation
    /// pour éviter de tirer trop de lignes (typiquement 50-100 max).
    async fn lookup_logs_for_ip(
        &self,
        ip: &str,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<Vec<FirewallLogEntry>, FirewallError>;
}
