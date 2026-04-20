//! Data model for suppression rules. See ADR-047.

use cel_interpreter::Program;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Drop,
    Downgrade,
    Tag,
}

impl RuleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drop => "drop",
            Self::Downgrade => "downgrade",
            Self::Tag => "tag",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "drop" => Some(Self::Drop),
            "downgrade" => Some(Self::Downgrade),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Scope {
    Global,
    Skill(String),
    AssetGroup(String),
}

impl Scope {
    pub fn parse(s: &str) -> Self {
        if s == "global" {
            return Self::Global;
        }
        if let Some(rest) = s.strip_prefix("skill:") {
            return Self::Skill(rest.to_string());
        }
        if let Some(rest) = s.strip_prefix("asset_group:") {
            return Self::AssetGroup(rest.to_string());
        }
        Self::Global
    }

    pub fn as_db_string(&self) -> String {
        match self {
            Self::Global => "global".to_string(),
            Self::Skill(id) => format!("skill:{id}"),
            Self::AssetGroup(id) => format!("asset_group:{id}"),
        }
    }

    /// Whether this rule applies to an event tagged with the given
    /// skill id and optional asset group.
    pub fn matches(&self, skill_id: &str, asset_group: Option<&str>) -> bool {
        match self {
            Self::Global => true,
            Self::Skill(id) => id == skill_id,
            Self::AssetGroup(id) => asset_group.map(|g| g == id).unwrap_or(false),
        }
    }
}

/// As fetched from DB — before CEL compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawRule {
    pub id: Uuid,
    pub name: String,
    pub predicate_source: String,
    pub action: RuleAction,
    pub severity_cap: Option<String>,
    pub scope: Scope,
    pub enabled: bool,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// CEL-compiled form used inside the engine.
pub struct CompiledRule {
    pub id: Uuid,
    pub program: Program,
    pub action: RuleAction,
    pub severity_cap: Option<String>,
    pub scope: Scope,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_parse_roundtrip() {
        let cases = [
            Scope::Global,
            Scope::Skill("skill-suricata".into()),
            Scope::AssetGroup("prod".into()),
        ];
        for s in cases {
            let encoded = s.as_db_string();
            assert_eq!(Scope::parse(&encoded), s);
        }
    }

    #[test]
    fn scope_global_matches_any_skill() {
        assert!(Scope::Global.matches("skill-foo", Some("prod")));
        assert!(Scope::Global.matches("skill-bar", None));
    }

    #[test]
    fn scope_skill_matches_exactly() {
        let s = Scope::Skill("skill-suricata".into());
        assert!(s.matches("skill-suricata", None));
        assert!(!s.matches("skill-zeek", None));
    }

    #[test]
    fn scope_asset_group_requires_group() {
        let s = Scope::AssetGroup("prod".into());
        assert!(s.matches("skill-any", Some("prod")));
        assert!(!s.matches("skill-any", Some("dev")));
        assert!(!s.matches("skill-any", None));
    }

    #[test]
    fn unknown_scope_defaults_to_global() {
        assert_eq!(Scope::parse("gibberish"), Scope::Global);
    }

    #[test]
    fn action_parse_roundtrip() {
        for a in [RuleAction::Drop, RuleAction::Downgrade, RuleAction::Tag] {
            assert_eq!(RuleAction::parse(a.as_str()), Some(a));
        }
        assert!(RuleAction::parse("delete").is_none());
    }
}
