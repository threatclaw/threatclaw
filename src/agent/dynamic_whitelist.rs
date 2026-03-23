//! Dynamic Whitelist — skills declare their allowed actions in skill.json.
//!
//! Each skill can declare `allowed_actions` in its manifest, and the whitelist
//! is built dynamically at startup by scanning all installed skills.
//! This supplements (not replaces) the static REMEDIATION_WHITELIST.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// A skill-declared action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillAction {
    pub skill_id: String,
    pub action_id: String,
    pub description: String,
    pub action_type: String,     // "api_lookup", "scan", "remediation", "report"
    pub requires_hitl: bool,
    pub parameters: Vec<String>,
}

/// Load dynamic actions from all installed skill.json manifests.
pub fn load_skill_actions() -> Vec<SkillAction> {
    let mut actions = vec![];
    let manifest_dir = std::env::current_dir().unwrap_or_default().to_string_lossy().to_string();

    // Scan skills-src/ (WASM skills)
    let skills_src = std::path::Path::new(manifest_dir).join("skills-src");
    if let Ok(entries) = std::fs::read_dir(&skills_src) {
        for entry in entries.flatten() {
            let skill_json = entry.path().join("skill.json");
            if skill_json.exists() {
                if let Ok(content) = std::fs::read_to_string(&skill_json) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        extract_actions(&val, &mut actions);
                    }
                }
            }
        }
    }

    // Scan skills/ (legacy Python skills)
    let skills_dir = std::path::Path::new(manifest_dir).join("skills");
    if let Ok(entries) = std::fs::read_dir(&skills_dir) {
        for entry in entries.flatten() {
            let skill_json = entry.path().join("skill.json");
            if skill_json.exists() {
                if let Ok(content) = std::fs::read_to_string(&skill_json) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        extract_actions(&val, &mut actions);
                    }
                }
            }
        }
    }

    tracing::info!("WHITELIST: Loaded {} dynamic actions from {} skills", actions.len(),
        actions.iter().map(|a| &a.skill_id).collect::<std::collections::HashSet<_>>().len());

    actions
}

/// Extract actions from a skill.json manifest.
fn extract_actions(manifest: &serde_json::Value, actions: &mut Vec<SkillAction>) {
    let skill_id = manifest["id"].as_str().unwrap_or("").to_string();
    if skill_id.is_empty() { return; }

    // Check for declared allowed_actions
    if let Some(declared) = manifest["allowed_actions"].as_array() {
        for action in declared {
            if let Some(action_id) = action["id"].as_str() {
                actions.push(SkillAction {
                    skill_id: skill_id.clone(),
                    action_id: action_id.to_string(),
                    description: action["description"].as_str().unwrap_or("").to_string(),
                    action_type: action["type"].as_str().unwrap_or("api_lookup").to_string(),
                    requires_hitl: action["requires_hitl"].as_bool().unwrap_or(false),
                    parameters: action["parameters"].as_array()
                        .map(|p| p.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                        .unwrap_or_default(),
                });
            }
        }
    }

    // Auto-declare api_lookup action for skills with api_key_required
    if manifest["api_key_required"].as_bool() == Some(true) {
        let action_id = format!("{}-lookup", skill_id);
        if !actions.iter().any(|a| a.action_id == action_id) {
            actions.push(SkillAction {
                skill_id: skill_id.clone(),
                action_id,
                description: format!("API lookup via {}", manifest["name"].as_str().unwrap_or(&skill_id)),
                action_type: "api_lookup".to_string(),
                requires_hitl: false,
                parameters: vec![],
            });
        }
    }
}

/// Check if a skill action is allowed.
pub fn is_action_allowed(skill_id: &str, action_id: &str, actions: &[SkillAction]) -> bool {
    actions.iter().any(|a| a.skill_id == skill_id && a.action_id == action_id)
}

/// Get all actions for a specific skill.
pub fn get_skill_actions(skill_id: &str, actions: &[SkillAction]) -> Vec<&SkillAction> {
    actions.iter().filter(|a| a.skill_id == skill_id).collect()
}

// Tests moved to integration tests to avoid compilation flag conflicts
