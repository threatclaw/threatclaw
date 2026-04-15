//! Secured ReAct cycle orchestrator. See ADR-026.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::agent::executor::{self, ExecutionResult, ExecutorError};
use crate::agent::kill_switch::{KillReason, KillSwitch};
use crate::agent::memory::{AgentMemory, MemoryEntry};
use crate::agent::mode_manager::{AgentMode, ModeConfig};
use crate::agent::observation_collector::ObservationSet;
use crate::agent::prompt_builder;
use crate::agent::remediation_whitelist::{self, RiskLevel, ValidatedCommand};
use crate::agent::soul::AgentSoul;

/// Réponse structurée du LLM (schéma imposé par le prompt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmAnalysis {
    pub analysis: String,
    pub severity: String,
    #[serde(default)]
    pub correlations: Vec<String>,
    #[serde(default)]
    pub proposed_actions: Vec<ProposedAction>,
    #[serde(default)]
    pub injection_detected: bool,
    #[serde(default)]
    pub confidence: f64,
}

/// Action proposée par le LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    pub cmd_id: String,
    pub params: std::collections::HashMap<String, String>,
    pub rationale: String,
}

/// Résultat d'un cycle ReAct complet.
#[derive(Debug)]
pub enum CycleResult {
    /// Analyse terminée, pas d'action nécessaire.
    AnalysisOnly(LlmAnalysis),
    /// Actions proposées, en attente de HITL.
    ActionsProposed {
        analysis: LlmAnalysis,
        validated_actions: Vec<ValidatedCommand>,
    },
    /// Actions exécutées (après HITL ou auto-approve Low).
    ActionsExecuted {
        analysis: LlmAnalysis,
        results: Vec<ExecutionResult>,
    },
    /// Injection détectée dans les données — alerte RSSI.
    InjectionDetected(LlmAnalysis),
    /// Kill switch déclenché — arrêt immédiat.
    KillSwitchEngaged(KillReason),
    /// Soul tampered — arrêt immédiat.
    SoulCompromised,
    /// Memory corrupted — arrêt immédiat.
    MemoryCorrupted(Vec<String>),
    /// Aucune observation à analyser.
    NoObservations,
    /// Erreur pendant le cycle.
    Error(String),
}

/// Configuration du cycle ReAct.
pub struct ReactCycleConfig {
    pub soul_path: std::path::PathBuf,
    pub mode: AgentMode,
}

/// Exécute les vérifications de sécurité pré-cycle (Piliers I, IV, V).
pub fn pre_cycle_checks(
    soul: &AgentSoul,
    soul_path: &Path,
    memory: &AgentMemory,
    memory_entries: &[MemoryEntry],
    kill_switch: &KillSwitch,
) -> Result<(), CycleResult> {
    // Pilier I: Vérification Soul
    if let Err(_e) = soul.verify_runtime(soul_path) {
        tracing::error!("SECURITY: Soul hash mismatch at runtime — cycle aborted");
        return Err(CycleResult::SoulCompromised);
    }

    // Pilier IV: Vérification intégrité mémoire
    let report = memory.verify_integrity(memory_entries);
    if !report.is_clean() {
        tracing::error!("SECURITY: Memory integrity check FAILED — cycle aborted");
        return Err(CycleResult::MemoryCorrupted(report.corrupted_entries));
    }

    // Pilier V: Kill switch
    if !kill_switch.is_active() {
        tracing::error!("SECURITY: Kill switch is active — cycle aborted");
        return Err(CycleResult::KillSwitchEngaged(KillReason::ManualTrigger {
            triggered_by: "pre-cycle check".to_string(),
        }));
    }

    Ok(())
}

/// Valide la réponse JSON du LLM.
/// Robust parsing: handles common LLM JSON mistakes (wrong types, missing fields, etc.)
pub fn parse_llm_response(response: &str) -> Result<LlmAnalysis, String> {
    // Extraire le JSON du texte (le LLM peut ajouter du texte autour)
    let json_str =
        extract_json(response).ok_or_else(|| "No JSON found in LLM response".to_string())?;

    // Try strict parsing first
    if let Ok(analysis) = serde_json::from_str::<LlmAnalysis>(&json_str) {
        return Ok(sanitize_analysis(analysis));
    }

    // Strict failed — try flexible parsing from raw Value
    let val: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| format!("Failed to parse LLM JSON: {e}"))?;

    // Extract fields with type coercion
    let analysis_text = match &val["analysis"] {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(m) => serde_json::to_string(m).unwrap_or_default(),
        other => other.to_string(),
    };

    let severity_raw = val["severity"].as_str().unwrap_or("MEDIUM").to_string();
    let severity = crate::agent::production_safeguards::validate_severity(&severity_raw)
        .unwrap_or_else(|| "MEDIUM".to_string());

    let confidence_raw = val["confidence"]
        .as_f64()
        .or_else(|| val["confidence"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0.5);
    let confidence = crate::agent::production_safeguards::validate_confidence(confidence_raw);

    // Correlations: accept strings, arrays of strings, or arrays of objects
    let correlations = match &val["correlations"] {
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string().trim_matches('"').to_string(),
            })
            .collect(),
        serde_json::Value::String(s) => s.split(',').map(|s| s.trim().to_string()).collect(),
        _ => vec![],
    };

    // Proposed actions: try parsing, ignore if malformed
    let proposed_actions = val["proposed_actions"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    Some(ProposedAction {
                        cmd_id: a["cmd_id"].as_str()?.to_string(),
                        params: a["params"]
                            .as_object()
                            .map(|obj| {
                                obj.iter()
                                    .filter_map(|(k, v)| {
                                        v.as_str().map(|s| (k.clone(), s.to_string()))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                        rationale: a["rationale"].as_str().unwrap_or("").to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let injection_detected = val["injection_detected"].as_bool().unwrap_or(false);

    tracing::debug!(
        "LLM_PARSE: Flexible parsing succeeded — severity={}, confidence={:.0}%",
        severity,
        confidence * 100.0
    );

    Ok(LlmAnalysis {
        analysis: analysis_text,
        severity,
        correlations,
        proposed_actions,
        injection_detected,
        confidence,
    })
}

/// Sanitize an already-parsed analysis (fix common issues).
fn sanitize_analysis(mut analysis: LlmAnalysis) -> LlmAnalysis {
    // Fix severity
    if let Some(valid) = crate::agent::production_safeguards::validate_severity(&analysis.severity)
    {
        analysis.severity = valid;
    }
    // Fix confidence
    analysis.confidence =
        crate::agent::production_safeguards::validate_confidence(analysis.confidence);
    analysis
}

/// Valide les actions proposées contre la whitelist (Pilier II).
pub fn validate_proposed_actions(
    actions: &[ProposedAction],
    kill_switch: &Arc<KillSwitch>,
) -> (Vec<ValidatedCommand>, Vec<String>) {
    let mut validated = Vec::new();
    let mut errors = Vec::new();

    for action in actions {
        match remediation_whitelist::validate_remediation(&action.cmd_id, &action.params) {
            Ok(cmd) => {
                tracing::info!(
                    "Validated action: {} — {} [{}]",
                    cmd.id,
                    cmd.rendered_cmd,
                    cmd.risk
                );
                validated.push(cmd);
            }
            Err(e) => {
                tracing::warn!("SECURITY: Action validation failed: {e}");
                errors.push(format!("{}: {e}", action.cmd_id));

                // Note: le kill switch est vérifié au prochain pre_cycle_checks
                // On ne fait pas de tokio::spawn ici pour rester sync-compatible
            }
        }
    }

    (validated, errors)
}

/// Décide si une action peut être auto-exécutée selon le mode.
pub fn decide_execution(mode: &ModeConfig, cmd: &ValidatedCommand) -> ExecutionDecision {
    match mode.mode {
        AgentMode::Analyst => ExecutionDecision::ProposalOnly,
        AgentMode::Investigator => ExecutionDecision::ProposalOnly,
        AgentMode::Responder => ExecutionDecision::RequiresHitl,
        AgentMode::AutonomousLow => {
            if mode.can_auto_execute(cmd.risk) {
                ExecutionDecision::AutoExecute
            } else {
                ExecutionDecision::RequiresHitl
            }
        }
    }
}

/// Décision d'exécution.
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutionDecision {
    /// Ne pas exécuter, juste proposer.
    ProposalOnly,
    /// Exécuter automatiquement (Low risk en mode AutonomousLow).
    AutoExecute,
    /// Requiert approbation HITL avant exécution.
    RequiresHitl,
}

/// Exécute une liste d'actions validées.
pub fn execute_actions(actions: &[ValidatedCommand], mode: &ModeConfig) -> Vec<ActionResult> {
    actions
        .iter()
        .map(|cmd| {
            let decision = decide_execution(mode, cmd);
            match decision {
                ExecutionDecision::ProposalOnly => ActionResult {
                    cmd_id: cmd.id.clone(),
                    decision,
                    execution: None,
                    error: None,
                },
                ExecutionDecision::RequiresHitl => ActionResult {
                    cmd_id: cmd.id.clone(),
                    decision,
                    execution: None,
                    error: None,
                },
                ExecutionDecision::AutoExecute => match executor::execute_validated(cmd) {
                    Ok(result) => ActionResult {
                        cmd_id: cmd.id.clone(),
                        decision,
                        execution: Some(result),
                        error: None,
                    },
                    Err(e) => ActionResult {
                        cmd_id: cmd.id.clone(),
                        decision,
                        execution: None,
                        error: Some(e.to_string()),
                    },
                },
            }
        })
        .collect()
}

/// Résultat d'une action individuelle.
#[derive(Debug)]
pub struct ActionResult {
    pub cmd_id: String,
    pub decision: ExecutionDecision,
    pub execution: Option<ExecutionResult>,
    pub error: Option<String>,
}

/// Extrait le premier bloc JSON valide d'une réponse LLM.
fn extract_json(text: &str) -> Option<String> {
    // Chercher un bloc ```json ... ``` d'abord
    if let Some(start) = text.find("```json") {
        let json_start = start + 7;
        if let Some(end) = text[json_start..].find("```") {
            let candidate = text[json_start..json_start + end].trim();
            if serde_json::from_str::<serde_json::Value>(candidate).is_ok() {
                return Some(candidate.to_string());
            }
        }
    }

    // Chercher un bloc { ... } directement
    let mut depth = 0i32;
    let mut start = None;

    for (i, ch) in text.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        let candidate = &text[s..=i];
                        if serde_json::from_str::<serde_json::Value>(candidate).is_ok() {
                            return Some(candidate.to_string());
                        }
                    }
                    start = None;
                }
            }
            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_extract_json_code_block() {
        let text = "Here is my analysis:\n```json\n{\"analysis\": \"test\", \"severity\": \"LOW\"}\n```\nThat's it.";
        let json = extract_json(text);
        assert!(json.is_some());
        assert!(json.unwrap().contains("\"analysis\""));
    }

    #[test]
    fn test_extract_json_inline() {
        let text = "Analysis: {\"analysis\": \"found vuln\", \"severity\": \"HIGH\", \"correlations\": [], \"proposed_actions\": [], \"injection_detected\": false, \"confidence\": 0.9}";
        let json = extract_json(text);
        assert!(json.is_some());
    }

    #[test]
    fn test_extract_json_no_json() {
        let text = "Just a plain text response with no JSON.";
        assert!(extract_json(text).is_none());
    }

    #[test]
    fn test_parse_llm_response_valid() {
        let response = r#"```json
        {
            "analysis": "Brute force SSH détecté depuis 10.0.0.1",
            "severity": "HIGH",
            "correlations": ["10.0.0.1 vu dans 3 sources"],
            "proposed_actions": [
                {
                    "cmd_id": "net-001",
                    "params": {"IP": "10.0.0.1"},
                    "rationale": "Bloquer l'IP source de l'attaque"
                }
            ],
            "injection_detected": false,
            "confidence": 0.85
        }
        ```"#;

        let analysis = parse_llm_response(response).unwrap();
        assert_eq!(analysis.severity, "HIGH");
        assert_eq!(analysis.proposed_actions.len(), 1);
        assert_eq!(analysis.proposed_actions[0].cmd_id, "net-001");
        assert!(!analysis.injection_detected);
    }

    #[test]
    fn test_parse_llm_response_with_injection_flag() {
        let response = r#"{"analysis": "Injection attempt detected", "severity": "CRITICAL", "correlations": [], "proposed_actions": [], "injection_detected": true, "confidence": 0.95}"#;
        let analysis = parse_llm_response(response).unwrap();
        assert!(analysis.injection_detected);
    }

    #[test]
    fn test_parse_llm_response_no_actions() {
        let response = r#"{"analysis": "Tout va bien", "severity": "LOW", "correlations": [], "proposed_actions": [], "injection_detected": false, "confidence": 0.7}"#;
        let analysis = parse_llm_response(response).unwrap();
        assert!(analysis.proposed_actions.is_empty());
    }

    #[test]
    fn test_parse_llm_response_invalid() {
        let response = "This is not JSON at all, just text.";
        assert!(parse_llm_response(response).is_err());
    }

    #[test]
    fn test_decide_execution_analyst() {
        let mode = ModeConfig::for_mode(AgentMode::Analyst);
        let cmd = ValidatedCommand {
            id: "net-001".to_string(),
            rendered_cmd: "iptables -A INPUT -s 10.0.0.1 -j DROP".to_string(),
            undo_cmd: None,
            risk: RiskLevel::Medium,
            requires_hitl: true,
            params: HashMap::new(),
        };
        assert_eq!(
            decide_execution(&mode, &cmd),
            ExecutionDecision::ProposalOnly
        );
    }

    #[test]
    fn test_decide_execution_investigator() {
        let mode = ModeConfig::for_mode(AgentMode::Investigator);
        let cmd = ValidatedCommand {
            id: "net-001".to_string(),
            rendered_cmd: String::new(),
            undo_cmd: None,
            risk: RiskLevel::High,
            requires_hitl: true,
            params: HashMap::new(),
        };
        assert_eq!(
            decide_execution(&mode, &cmd),
            ExecutionDecision::ProposalOnly
        );
    }

    #[test]
    fn test_decide_execution_responder() {
        let mode = ModeConfig::for_mode(AgentMode::Responder);
        let cmd = ValidatedCommand {
            id: "net-001".to_string(),
            rendered_cmd: String::new(),
            undo_cmd: None,
            risk: RiskLevel::Low,
            requires_hitl: true,
            params: HashMap::new(),
        };
        assert_eq!(
            decide_execution(&mode, &cmd),
            ExecutionDecision::RequiresHitl
        );
    }

    #[test]
    fn test_decide_execution_autonomous_low() {
        let mode = ModeConfig::for_mode(AgentMode::AutonomousLow);

        let low_cmd = ValidatedCommand {
            id: "pkg-001".to_string(),
            rendered_cmd: String::new(),
            undo_cmd: None,
            risk: RiskLevel::Low,
            requires_hitl: true,
            params: HashMap::new(),
        };
        assert_eq!(
            decide_execution(&mode, &low_cmd),
            ExecutionDecision::AutoExecute
        );

        let high_cmd = ValidatedCommand {
            id: "net-001".to_string(),
            rendered_cmd: String::new(),
            undo_cmd: None,
            risk: RiskLevel::High,
            requires_hitl: true,
            params: HashMap::new(),
        };
        assert_eq!(
            decide_execution(&mode, &high_cmd),
            ExecutionDecision::RequiresHitl
        );
    }

    #[test]
    fn test_pre_cycle_checks_valid() {
        let soul_path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/AGENT_SOUL.toml"));
        let soul = AgentSoul::load_and_verify(soul_path).unwrap();
        let memory = AgentMemory::new(b"threatclaw-test-hmac-key-32bytes!").unwrap();
        let kill_switch = KillSwitch::new(Default::default());

        let result = pre_cycle_checks(&soul, soul_path, &memory, &[], &kill_switch);
        assert!(result.is_ok());
    }

    #[test]
    fn test_pre_cycle_checks_kill_switch_active() {
        let soul_path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/AGENT_SOUL.toml"));
        let soul = AgentSoul::load_and_verify(soul_path).unwrap();
        let memory = AgentMemory::new(b"threatclaw-test-hmac-key-32bytes!").unwrap();
        let kill_switch = KillSwitch::new(Default::default());

        // Deactivate via manual trigger
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            kill_switch.manual_trigger("test").await;
        });

        let result = pre_cycle_checks(&soul, soul_path, &memory, &[], &kill_switch);
        assert!(matches!(result, Err(CycleResult::KillSwitchEngaged(_))));
    }

    #[test]
    fn test_pre_cycle_checks_memory_corrupted() {
        let soul_path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/AGENT_SOUL.toml"));
        let soul = AgentSoul::load_and_verify(soul_path).unwrap();
        let memory = AgentMemory::new(b"threatclaw-test-hmac-key-32bytes!").unwrap();
        let kill_switch = KillSwitch::new(Default::default());

        let corrupted_entries = vec![MemoryEntry {
            id: "corrupted-1".to_string(),
            content: "original content".to_string(),
            source: "rssi".to_string(),
            content_hash: "wrong_hash".to_string(),
            hmac_signature: "wrong_hmac".to_string(),
            created_at: String::new(),
            created_by: "admin".to_string(),
        }];

        let result = pre_cycle_checks(&soul, soul_path, &memory, &corrupted_entries, &kill_switch);
        assert!(matches!(result, Err(CycleResult::MemoryCorrupted(_))));
    }

    #[test]
    fn test_validate_proposed_actions_valid() {
        let actions = vec![ProposedAction {
            cmd_id: "net-002".to_string(),
            params: [("IP".to_string(), "10.0.0.99".to_string())].into(),
            rationale: "Ban attacker IP".to_string(),
        }];
        let ks = Arc::new(KillSwitch::new(Default::default()));
        let (validated, errors) = validate_proposed_actions(&actions, &ks);
        assert_eq!(validated.len(), 1);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_proposed_actions_invalid() {
        let actions = vec![ProposedAction {
            cmd_id: "evil-cmd".to_string(),
            params: HashMap::new(),
            rationale: "Hack the planet".to_string(),
        }];
        let ks = Arc::new(KillSwitch::new(Default::default()));
        let (validated, errors) = validate_proposed_actions(&actions, &ks);
        assert!(validated.is_empty());
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn test_execute_actions_proposal_only() {
        let mode = ModeConfig::for_mode(AgentMode::Investigator);
        let actions = vec![ValidatedCommand {
            id: "net-001".to_string(),
            rendered_cmd: "iptables -A INPUT -s 10.0.0.1 -j DROP".to_string(),
            undo_cmd: None,
            risk: RiskLevel::Medium,
            requires_hitl: true,
            params: HashMap::new(),
        }];

        let results = execute_actions(&actions, &mode);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, ExecutionDecision::ProposalOnly);
        assert!(results[0].execution.is_none());
    }
}
