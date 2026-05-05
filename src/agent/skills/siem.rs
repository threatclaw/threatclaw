//! Trait `SiemSkill` : abstraction commune sur les SIEM connectés.
//!
//! Permet au pipeline de faire `get_logs_around(asset, timestamp, window)`
//! sans savoir s'il s'agit d'Elastic, Graylog, Wazuh, etc.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemLogEntry {
    pub timestamp: DateTime<Utc>,
    pub asset: String,
    /// Niveau / sévérité tel que rapporté par le SIEM (libre).
    pub level: String,
    /// Texte du message ou du field principal.
    pub message: String,
    /// Tags / labels rapportés par le SIEM (par ex. "auth", "ssh", "win-4625").
    pub tags: Vec<String>,
    /// Identifiant du skill source (ex: "skill-elastic-siem").
    pub source_skill: String,
    /// Payload brut pour les consommateurs avancés (UI debug, exports).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub raw: Option<Value>,
}

#[derive(Debug)]
pub enum SiemError {
    NotConfigured,
    Auth(String),
    Network(String),
    Parse(String),
    Other(String),
}

impl std::fmt::Display for SiemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "siem skill not configured"),
            Self::Auth(s) => write!(f, "siem auth error: {s}"),
            Self::Network(s) => write!(f, "siem network error: {s}"),
            Self::Parse(s) => write!(f, "siem parse error: {s}"),
            Self::Other(s) => write!(f, "siem error: {s}"),
        }
    }
}

impl std::error::Error for SiemError {}

#[async_trait]
pub trait SiemSkill: Send + Sync {
    fn skill_id(&self) -> &'static str;

    /// Retourne les logs SIEM autour d'un timestamp pour un asset (fenêtre
    /// symétrique avant/après). Cap implicite côté implémentation.
    async fn get_logs_around(
        &self,
        asset: &str,
        timestamp: DateTime<Utc>,
        window: chrono::Duration,
    ) -> Result<Vec<SiemLogEntry>, SiemError>;
}
