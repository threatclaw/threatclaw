//! ThreatClaw Unified Skill Catalog — loads skill.json manifests.
//!
//! All skills (tools, connectors, enrichment) share the same JSON format.
//! This is separate from the OpenClaw SKILL.md system (used for prompt-level skills).

use serde::{Deserialize, Serialize};

/// A ThreatClaw skill manifest (from skill.json in skills-catalog/).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcSkillManifest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub trust: String,
    #[serde(rename = "type", default = "default_tool")]
    pub skill_type: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub execution: serde_json::Value,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default)]
    pub outputs: serde_json::Value,
    #[serde(default)]
    pub default_active: bool,
    #[serde(default)]
    pub requires_config: bool,
    #[serde(default)]
    pub api_key_required: bool,
    #[serde(default)]
    pub icon: String,
}

fn default_tool() -> String { "tool".into() }

/// The unified skill catalog.
#[derive(Debug, Clone, Serialize)]
pub struct TcCatalog {
    pub skills: Vec<TcSkillManifest>,
    pub total: usize,
    pub tools: usize,
    pub connectors: usize,
    pub enrichment: usize,
}

/// Load all ThreatClaw skill manifests from disk.
pub fn load_tc_catalog() -> TcCatalog {
    let mut skills = vec![];
    let mut seen_ids = std::collections::HashSet::new();

    let dirs = ["skills-catalog", "skills-src", "skills"];

    for dir in &dirs {
        let path = std::path::Path::new(dir);
        if !path.exists() { continue; }

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let skill_path = if entry.path().is_dir() {
                    entry.path().join("skill.json")
                } else if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                    entry.path()
                } else {
                    continue;
                };

                if !skill_path.exists() { continue; }

                if let Ok(content) = std::fs::read_to_string(&skill_path) {
                    match serde_json::from_str::<TcSkillManifest>(&content) {
                        Ok(manifest) => {
                            if !seen_ids.contains(&manifest.id) {
                                seen_ids.insert(manifest.id.clone());
                                skills.push(manifest);
                            }
                        }
                        Err(_) => {} // Skip invalid manifests silently
                    }
                }
            }
        }
    }

    skills.sort_by(|a, b| {
        b.default_active.cmp(&a.default_active)
            .then(a.skill_type.cmp(&b.skill_type))
            .then(a.name.cmp(&b.name))
    });

    let tools = skills.iter().filter(|s| s.skill_type == "tool").count();
    let connectors = skills.iter().filter(|s| s.skill_type == "connector").count();
    let enrichment = skills.iter().filter(|s| s.skill_type == "enrichment").count();
    let total = skills.len();

    TcCatalog { skills, total, tools, connectors, enrichment }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_manifest() {
        let json = r#"{"id":"test","name":"Test","type":"tool","category":"test","default_active":false}"#;
        let m: TcSkillManifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.id, "test");
        assert_eq!(m.skill_type, "tool");
    }

    #[test]
    fn test_deserialize_enrichment() {
        let json = r#"{"id":"nvd","name":"NVD","type":"enrichment","default_active":true,"api_key_required":false}"#;
        let m: TcSkillManifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.skill_type, "enrichment");
        assert!(m.default_active);
    }
}
