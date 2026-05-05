//! Trait `EdrSkill` : abstraction commune sur les EDR connectés.
//!
//! Permet au pipeline de récupérer le contexte processus / FIM / events
//! d'un asset au moment d'un incident, sans connaître le vendor (Velociraptor,
//! CrowdStrike, SentinelOne, Defender).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessContext {
    /// Liste des processus actifs ou récents sur l'asset au moment du
    /// timestamp demandé. Format normalisé (vendor-independent).
    pub processes: Vec<ProcessRecord>,
    /// Connexions réseau récentes (asset comme src/dst).
    pub network_connections: Vec<NetworkConnection>,
    /// Événements récents (process creation, file modification, registry, etc.)
    pub events: Vec<EdrEvent>,
    /// Identifiant du skill source.
    pub source_skill: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRecord {
    pub pid: u32,
    pub name: String,
    pub cmdline: Option<String>,
    pub parent_pid: Option<u32>,
    pub user: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub proto: String,
    pub state: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub message: String,
    pub raw: Option<Value>,
}

#[derive(Debug)]
pub enum EdrError {
    NotConfigured,
    Auth(String),
    Network(String),
    Parse(String),
    Other(String),
}

impl std::fmt::Display for EdrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "edr skill not configured"),
            Self::Auth(s) => write!(f, "edr auth error: {s}"),
            Self::Network(s) => write!(f, "edr network error: {s}"),
            Self::Parse(s) => write!(f, "edr parse error: {s}"),
            Self::Other(s) => write!(f, "edr error: {s}"),
        }
    }
}

impl std::error::Error for EdrError {}

#[async_trait]
pub trait EdrSkill: Send + Sync {
    fn skill_id(&self) -> &'static str;

    /// Récupère le contexte processus/réseau/events d'un asset autour d'un
    /// timestamp.
    ///
    /// Le `&dyn Database` est passé pour les EDR qui ont besoin de relire des
    /// configs/credentials persistés (cas Velociraptor : certs gRPC stockés
    /// en `skill_configs`). Les autres impls peuvent ignorer ce paramètre.
    async fn get_process_context(
        &self,
        store: &dyn crate::db::Database,
        asset: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<ProcessContext, EdrError>;
}
