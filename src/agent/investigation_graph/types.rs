//! Modele Rust des graphs CACAO v2 — Phase G.
//!
//! Parse YAML CACAO v2 vers un `Graph` typed, valide la structure, et
//! expose les types consommes par `graph.rs` pour la compilation en
//! `petgraph::DiGraph`.
//!
//! Format aligne sur OASIS CACAO v2 (Course of Action) :
//! https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html
//!
//! Step types supportes :
//! - `start` — entree unique du graph
//! - `end` — etat terminal (au moins un par graph)
//! - `action` — execute une `Command` ThreatClaw (archive, LLM, skill,
//!   incident)
//! - `if-condition` — branche binaire sur un predicat CEL
//! - `switch-condition` — n-aire avec `default_case`
//! - `parallel` — fan-out + `join`
//! - `playbook-action` — sub-graph reutilisable (compose)
//!
//! La validation au parse verifie :
//! - exactement un step `start`
//! - au moins un step `end`
//! - toutes les references (`on_completion`, `on_true`/`on_false`,
//!   valeurs de `cases`, `default_case`, `next_steps`, `join`) pointent
//!   vers un step existant
//!
//! La detection de cycle et la construction du DAG se font dans
//! `graph::compile`, pas ici — la separation permet de parser un graph
//! et de l'editer en memoire avant compilation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("YAML invalide : {0}")]
    Yaml(#[from] serde_yaml_ng::Error),

    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    #[error("graph '{0}' n'a pas de step 'start'")]
    MissingStart(String),

    #[error("graph '{0}' a plusieurs steps 'start' : {1:?}")]
    MultipleStarts(String, Vec<String>),

    #[error("graph '{0}' n'a pas de step 'end'")]
    MissingEnd(String),

    #[error("graph '{name}' : le step '{from}' reference un step inexistant '{target}'")]
    UnknownReference {
        name: String,
        from: String,
        target: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Graph {
    pub spec_version: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub trigger: Trigger,
    pub steps: HashMap<String, Step>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trigger {
    /// Sigma rule id qui declenche ce graph (1 graph = 1 sigma rule pour
    /// l'instant ; on etendra a des triggers composes en G1d si besoin).
    pub sigma_rule: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Step {
    Start {
        on_completion: String,
    },
    End,
    Action {
        command: Command,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        on_completion: Option<String>,
    },
    IfCondition {
        condition: String,
        on_true: String,
        on_false: String,
    },
    SwitchCondition {
        condition: String,
        cases: HashMap<String, String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        default_case: Option<String>,
    },
    Parallel {
        next_steps: Vec<String>,
        join: String,
    },
    PlaybookAction {
        playbook_name: String,
        on_completion: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Command {
    /// Archive l'enquete avec un motif explicite. Etat terminal cote
    /// pipeline (le step `action` enchainera vers un `end`).
    ThreatclawArchive { reason: String },

    /// Delegue a L1/L2 (LLM) pour les branches que le determinisme ne
    /// tranche pas. Le verdict du LLM continue le graph via `on_completion`.
    ThreatclawInvestigateLlm {
        #[serde(default = "default_llm_timeout")]
        timeout_secs: u64,
    },

    /// Appelle une skill d'enrichissement (ip_reputation, threat_intel,
    /// etc.). Le resultat est injecte dans le contexte CEL pour les
    /// conditions suivantes.
    ThreatclawSkillCall {
        skill_name: String,
        #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
        params: serde_json::Value,
    },

    /// Emet un incident actionnable. Etat terminal cote pipeline ; le
    /// step suivant est typiquement `end`. Les `proposed_actions` sont
    /// des suggestions HITL surfacees au RSSI dans le dashboard.
    ThreatclawEmitIncident {
        severity: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        proposed_actions: Vec<serde_json::Value>,
    },
}

fn default_llm_timeout() -> u64 {
    1500
}

impl Step {
    /// Discriminant lisible (pour les logs / metrics / erreurs).
    pub fn step_kind(&self) -> &'static str {
        match self {
            Self::Start { .. } => "start",
            Self::End => "end",
            Self::Action { .. } => "action",
            Self::IfCondition { .. } => "if-condition",
            Self::SwitchCondition { .. } => "switch-condition",
            Self::Parallel { .. } => "parallel",
            Self::PlaybookAction { .. } => "playbook-action",
        }
    }

    /// Liste les noms de steps que ce step reference (ses transitions
    /// sortantes). Utilise par la validation pour verifier qu'aucun
    /// step n'envoie sur un nom inexistant.
    fn references(&self) -> Vec<&str> {
        let mut refs: Vec<&str> = Vec::new();
        match self {
            Self::Start { on_completion } => refs.push(on_completion.as_str()),
            Self::End => {}
            Self::Action {
                on_completion: Some(next),
                ..
            } => refs.push(next.as_str()),
            Self::Action {
                on_completion: None,
                ..
            } => {}
            Self::IfCondition {
                on_true, on_false, ..
            } => {
                refs.push(on_true.as_str());
                refs.push(on_false.as_str());
            }
            Self::SwitchCondition {
                cases,
                default_case,
                ..
            } => {
                for v in cases.values() {
                    refs.push(v.as_str());
                }
                if let Some(d) = default_case {
                    refs.push(d.as_str());
                }
            }
            Self::Parallel { next_steps, join } => {
                for n in next_steps {
                    refs.push(n.as_str());
                }
                refs.push(join.as_str());
            }
            Self::PlaybookAction { on_completion, .. } => {
                refs.push(on_completion.as_str());
            }
        }
        refs
    }
}

impl Graph {
    /// Parse un graph CACAO v2 depuis un blob YAML, et valide sa structure.
    pub fn from_yaml(yaml: &str) -> Result<Self, ParseError> {
        let graph: Graph = serde_yaml_ng::from_str(yaml)?;
        graph.validate()?;
        Ok(graph)
    }

    /// Verifie : start unique, end present, references valides.
    /// La detection de cycle est en `graph::compile` (necessite le DAG).
    pub fn validate(&self) -> Result<(), ValidationError> {
        let starts: Vec<&String> = self
            .steps
            .iter()
            .filter_map(|(k, s)| matches!(s, Step::Start { .. }).then_some(k))
            .collect();
        match starts.as_slice() {
            [] => return Err(ValidationError::MissingStart(self.name.clone())),
            [_] => {}
            many => {
                let mut names: Vec<String> = many.iter().map(|s| (*s).clone()).collect();
                names.sort();
                return Err(ValidationError::MultipleStarts(self.name.clone(), names));
            }
        }

        if !self.steps.values().any(|s| matches!(s, Step::End)) {
            return Err(ValidationError::MissingEnd(self.name.clone()));
        }

        for (step_name, step) in &self.steps {
            for target in step.references() {
                if !self.steps.contains_key(target) {
                    return Err(ValidationError::UnknownReference {
                        name: self.name.clone(),
                        from: step_name.clone(),
                        target: target.to_string(),
                    });
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YAML_BACKDOOR: &str =
        include_str!("../../../graphs/sigma/backdoor-port-block-handled.yaml");
    const YAML_SSH_BRUTEFORCE: &str = include_str!("../../../graphs/sigma/ssh-bruteforce.yaml");

    const YAML_MINIMAL: &str = r#"
spec_version: cacao-2.0
name: minimal
trigger:
  sigma_rule: dummy_rule
steps:
  start:
    type: start
    on_completion: terminal
  terminal:
    type: end
"#;

    fn assert_roundtrip(yaml: &str) -> Graph {
        let parsed = Graph::from_yaml(yaml).expect("parse 1");
        let dumped = serde_yaml_ng::to_string(&parsed).expect("dump");
        let reparsed = Graph::from_yaml(&dumped).expect("parse 2");
        assert_eq!(
            parsed, reparsed,
            "roundtrip identity broken — YAML -> Graph -> YAML -> Graph diverged"
        );
        parsed
    }

    #[test]
    fn roundtrip_backdoor_port_block() {
        let g = assert_roundtrip(YAML_BACKDOOR);
        assert_eq!(g.name, "backdoor-port-block-handled");
        assert_eq!(g.trigger.sigma_rule, "backdoor_port_block");
        assert!(g.steps.contains_key("archive_handled"));
    }

    #[test]
    fn roundtrip_ssh_bruteforce() {
        let g = assert_roundtrip(YAML_SSH_BRUTEFORCE);
        assert_eq!(g.name, "ssh-bruteforce");
        match g.steps.get("emit_incident") {
            Some(Step::Action {
                command: Command::ThreatclawEmitIncident { severity, .. },
                ..
            }) => assert_eq!(severity, "high"),
            other => panic!("emit_incident inattendu : {other:?}"),
        }
    }

    #[test]
    fn roundtrip_minimal() {
        let g = assert_roundtrip(YAML_MINIMAL);
        assert_eq!(g.steps.len(), 2);
    }

    #[test]
    fn rejects_graph_without_start_step() {
        let yaml = r#"
spec_version: cacao-2.0
name: no-start
trigger:
  sigma_rule: dummy
steps:
  terminal:
    type: end
"#;
        let err = Graph::from_yaml(yaml).expect_err("attendu : erreur de validation");
        assert!(
            matches!(err, ParseError::Validation(ValidationError::MissingStart(ref n)) if n == "no-start"),
            "attendu MissingStart, recu : {err:?}"
        );
    }

    #[test]
    fn rejects_reference_to_unknown_step() {
        let yaml = r#"
spec_version: cacao-2.0
name: dangling-ref
trigger:
  sigma_rule: dummy
steps:
  start:
    type: start
    on_completion: ghost
  terminal:
    type: end
"#;
        let err = Graph::from_yaml(yaml).expect_err("attendu : erreur de validation");
        match err {
            ParseError::Validation(ValidationError::UnknownReference { name, from, target }) => {
                assert_eq!(name, "dangling-ref");
                assert_eq!(from, "start");
                assert_eq!(target, "ghost");
            }
            other => panic!("attendu UnknownReference, recu : {other:?}"),
        }
    }
}
