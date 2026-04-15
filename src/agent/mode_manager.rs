//! Mode Manager — 4 niveaux d'autonomie sélectionnables par le RSSI.
//!
//! Chaque mode définit ce que l'agent peut faire :
//! - Analyst : pipeline fixe, zéro ReAct
//! - Investigator : ReAct lecture seule, propose mais n'exécute pas
//! - Responder : ReAct + HITL obligatoire pour toute action
//! - AutonomousLow : actions Low auto, Medium+ HITL

use serde::{Deserialize, Serialize};

use crate::agent::remediation_whitelist::RiskLevel;

/// Mode de fonctionnement de l'agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMode {
    /// Pipeline fixe — détection + rapport. Aucune décision IA.
    Analyst,
    /// ReAct lecture seule — corrèle et propose, le RSSI décide.
    Investigator,
    /// ReAct + HITL — exécute uniquement ce que le RSSI approuve.
    Responder,
    /// Autonomie partielle — actions Low auto, Medium+ HITL.
    AutonomousLow,
}

impl Default for AgentMode {
    fn default() -> Self {
        Self::Investigator
    }
}

impl std::fmt::Display for AgentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Analyst => write!(f, "analyst"),
            Self::Investigator => write!(f, "investigator"),
            Self::Responder => write!(f, "responder"),
            Self::AutonomousLow => write!(f, "autonomous_low"),
        }
    }
}

/// Configuration d'un mode.
#[derive(Debug, Clone)]
pub struct ModeConfig {
    pub mode: AgentMode,
    pub name: &'static str,
    pub description: &'static str,
    pub react_enabled: bool,
    pub autonomous_investigation: bool,
    pub remediation_proposals: bool,
    pub auto_execute: bool,
    pub auto_execute_risk_levels: Vec<RiskLevel>,
    pub hitl_required: bool,
    pub hitl_double_confirm_high: bool,
    pub max_react_iterations: u32,
    pub cycle_timeout_minutes: u32,
    pub max_auto_actions_per_day: u32,
}

impl ModeConfig {
    pub fn for_mode(mode: AgentMode) -> Self {
        match mode {
            AgentMode::Analyst => Self {
                mode,
                name: "Analyste Simple",
                description: "Pipeline fixe — détection + rapport. Aucune décision IA.",
                react_enabled: false,
                autonomous_investigation: false,
                remediation_proposals: false,
                auto_execute: false,
                auto_execute_risk_levels: vec![],
                hitl_required: false,
                hitl_double_confirm_high: false,
                max_react_iterations: 0,
                cycle_timeout_minutes: 0,
                max_auto_actions_per_day: 0,
            },
            AgentMode::Investigator => Self {
                mode,
                name: "Investigateur",
                description: "Agent qui corrèle et propose. Le RSSI décide et exécute.",
                react_enabled: true,
                autonomous_investigation: true,
                remediation_proposals: true,
                auto_execute: false,
                auto_execute_risk_levels: vec![],
                hitl_required: true,
                hitl_double_confirm_high: false,
                max_react_iterations: 10,
                cycle_timeout_minutes: 30,
                max_auto_actions_per_day: 0,
            },
            AgentMode::Responder => Self {
                mode,
                name: "Répondeur HITL",
                description: "Agent complet avec approbation humaine obligatoire.",
                react_enabled: true,
                autonomous_investigation: true,
                remediation_proposals: true,
                auto_execute: false,
                auto_execute_risk_levels: vec![],
                hitl_required: true,
                hitl_double_confirm_high: true,
                max_react_iterations: 15,
                cycle_timeout_minutes: 60,
                max_auto_actions_per_day: 0,
            },
            AgentMode::AutonomousLow => Self {
                mode,
                name: "Autonome Limité",
                description: "Actions Low auto. Medium+ toujours HITL.",
                react_enabled: true,
                autonomous_investigation: true,
                remediation_proposals: true,
                auto_execute: true,
                auto_execute_risk_levels: vec![RiskLevel::Low],
                hitl_required: true,
                hitl_double_confirm_high: true,
                max_react_iterations: 20,
                cycle_timeout_minutes: 60,
                max_auto_actions_per_day: 20,
            },
        }
    }

    /// Vérifie si une action de ce niveau de risque peut être auto-exécutée.
    pub fn can_auto_execute(&self, risk: RiskLevel) -> bool {
        self.auto_execute && self.auto_execute_risk_levels.contains(&risk)
    }

    /// Vérifie si le HITL double confirmation est requis pour ce niveau de risque.
    pub fn needs_double_confirm(&self, risk: RiskLevel) -> bool {
        self.hitl_double_confirm_high && matches!(risk, RiskLevel::High | RiskLevel::Critical)
    }
}

/// Parse un mode depuis une string (config/API).
pub fn parse_mode(s: &str) -> Option<AgentMode> {
    match s.to_lowercase().as_str() {
        "analyst" | "analyste" => Some(AgentMode::Analyst),
        "investigator" | "investigateur" => Some(AgentMode::Investigator),
        "responder" | "repondeur" | "répondeur" => Some(AgentMode::Responder),
        "autonomous_low" | "autonome" => Some(AgentMode::AutonomousLow),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_mode_is_investigator() {
        assert_eq!(AgentMode::default(), AgentMode::Investigator);
    }

    #[test]
    fn test_analyst_no_react() {
        let cfg = ModeConfig::for_mode(AgentMode::Analyst);
        assert!(!cfg.react_enabled);
        assert!(!cfg.autonomous_investigation);
        assert!(!cfg.remediation_proposals);
        assert!(!cfg.auto_execute);
        assert_eq!(cfg.max_react_iterations, 0);
    }

    #[test]
    fn test_investigator_read_only() {
        let cfg = ModeConfig::for_mode(AgentMode::Investigator);
        assert!(cfg.react_enabled);
        assert!(cfg.autonomous_investigation);
        assert!(cfg.remediation_proposals);
        assert!(!cfg.auto_execute);
        assert!(cfg.hitl_required);
        assert_eq!(cfg.max_react_iterations, 10);
    }

    #[test]
    fn test_responder_hitl_required() {
        let cfg = ModeConfig::for_mode(AgentMode::Responder);
        assert!(cfg.react_enabled);
        assert!(!cfg.auto_execute);
        assert!(cfg.hitl_required);
        assert!(cfg.hitl_double_confirm_high);
    }

    #[test]
    fn test_autonomous_low_only() {
        let cfg = ModeConfig::for_mode(AgentMode::AutonomousLow);
        assert!(cfg.auto_execute);
        assert!(cfg.can_auto_execute(RiskLevel::Low));
        assert!(!cfg.can_auto_execute(RiskLevel::Medium));
        assert!(!cfg.can_auto_execute(RiskLevel::High));
        assert!(!cfg.can_auto_execute(RiskLevel::Critical));
    }

    #[test]
    fn test_double_confirm_high_critical() {
        let cfg = ModeConfig::for_mode(AgentMode::Responder);
        assert!(cfg.needs_double_confirm(RiskLevel::High));
        assert!(cfg.needs_double_confirm(RiskLevel::Critical));
        assert!(!cfg.needs_double_confirm(RiskLevel::Low));
        assert!(!cfg.needs_double_confirm(RiskLevel::Medium));
    }

    #[test]
    fn test_investigator_no_double_confirm() {
        let cfg = ModeConfig::for_mode(AgentMode::Investigator);
        assert!(!cfg.needs_double_confirm(RiskLevel::High));
    }

    #[test]
    fn test_parse_mode() {
        assert_eq!(parse_mode("analyst"), Some(AgentMode::Analyst));
        assert_eq!(parse_mode("investigator"), Some(AgentMode::Investigator));
        assert_eq!(parse_mode("responder"), Some(AgentMode::Responder));
        assert_eq!(parse_mode("autonomous_low"), Some(AgentMode::AutonomousLow));
        assert_eq!(parse_mode("analyste"), Some(AgentMode::Analyst));
        assert_eq!(parse_mode("répondeur"), Some(AgentMode::Responder));
        assert_eq!(parse_mode("invalid"), None);
    }

    #[test]
    fn test_mode_display() {
        assert_eq!(AgentMode::Analyst.to_string(), "analyst");
        assert_eq!(AgentMode::Investigator.to_string(), "investigator");
        assert_eq!(AgentMode::Responder.to_string(), "responder");
        assert_eq!(AgentMode::AutonomousLow.to_string(), "autonomous_low");
    }

    #[test]
    fn test_autonomous_quota() {
        let cfg = ModeConfig::for_mode(AgentMode::AutonomousLow);
        assert_eq!(cfg.max_auto_actions_per_day, 20);
    }
}
