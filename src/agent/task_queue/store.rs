//! Types métier + interface store pour `task_queue` et `graph_executions`.
//!
//! L'implémentation Postgres concrète est dans `src/db/pg_threatclaw.rs`
//! (méthodes du trait `ThreatClawStore`). Ici on déclare juste les types
//! et l'API publique. Le store libsql renverra `not_supported`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Task kind ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// Appel d'une skill d'enrichissement (ip_reputation, threat_intel, …).
    /// Concurrence haute : Semaphore(50) par défaut.
    SkillCall,
    /// Appel L1/L2 LLM. Concurrence basse : Semaphore(1-2) car Ollama CPU.
    LlmCall,
    /// Sub-graph (`playbook-action`) — démarre une nouvelle exécution
    /// dont le résultat reprend dans le graph parent. Concurrence
    /// moyenne : Semaphore(20).
    GraphStep,
}

impl TaskKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SkillCall => "skill_call",
            Self::LlmCall => "llm_call",
            Self::GraphStep => "graph_step",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "skill_call" => Some(Self::SkillCall),
            "llm_call" => Some(Self::LlmCall),
            "graph_step" => Some(Self::GraphStep),
            _ => None,
        }
    }
}

// ── Task status ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Running,
    Done,
    Error,
}

impl TaskStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Done => "done",
            Self::Error => "error",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "queued" => Some(Self::Queued),
            "running" => Some(Self::Running),
            "done" => Some(Self::Done),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

// ── Task records ──

/// Données pour pousser une nouvelle task. `priority` est 0 (haute) à 9
/// (basse) — défaut 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewTask {
    pub kind: TaskKind,
    pub graph_run_id: Option<i64>,
    pub payload: serde_json::Value,
    #[serde(default = "default_priority")]
    pub priority: i16,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: i16,
}

fn default_priority() -> i16 {
    5
}

fn default_max_attempts() -> i16 {
    3
}

/// Row hydratée depuis `task_queue`. Utilisée par les workers après
/// `claim_next_task`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: i64,
    pub kind: TaskKind,
    pub graph_run_id: Option<i64>,
    pub payload: serde_json::Value,
    pub status: TaskStatus,
    pub priority: i16,
    pub attempts: i16,
    pub max_attempts: i16,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub worker_id: Option<String>,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

// ── Graph execution records ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphExecutionStatus {
    Running,
    Archived,
    Incident,
    Inconclusive,
    Failed,
}

impl GraphExecutionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Archived => "archived",
            Self::Incident => "incident",
            Self::Inconclusive => "inconclusive",
            Self::Failed => "failed",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "running" => Some(Self::Running),
            "archived" => Some(Self::Archived),
            "incident" => Some(Self::Incident),
            "inconclusive" => Some(Self::Inconclusive),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewGraphExecution {
    pub graph_name: String,
    pub sigma_alert_id: Option<i64>,
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphExecutionRecord {
    pub id: i64,
    pub graph_name: String,
    pub sigma_alert_id: Option<i64>,
    pub asset_id: Option<String>,
    pub status: GraphExecutionStatus,
    pub archive_reason: Option<String>,
    pub incident_id: Option<i32>,
    pub trace: Option<serde_json::Value>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i32>,
    pub error: Option<String>,
}

/// Délai après lequel un task `running` est considéré orphelin (worker
/// mort sans nettoyage). Au boot on remet en `queued` les tasks `running`
/// plus vieilles que ça.
pub const STALE_TASK_THRESHOLD_SECS: i64 = 300;
