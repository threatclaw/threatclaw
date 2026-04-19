//! LLM validation mode for anti-hallucination grounding layer (v1.1.0-beta).
//!
//! Controls the behavior of the LLM output validators introduced in Phase 2+:
//! - `off`     : no validation (legacy behavior v1.0.x)
//! - `lenient` : validate + log errors, accept verdict with warnings
//! - `strict`  : validate + downgrade verdict on errors
//!
//! Default when the setting is absent or invalid: `Off` (backward-compatible).
//! Persisted in DB under key `tc_config_llm_validation_mode` scoped to `_system`.

use serde::{Deserialize, Serialize};

use crate::db::SettingsStore;

/// DB settings key under which the validation mode is persisted.
pub const VALIDATION_MODE_KEY: &str = "tc_config_llm_validation_mode";

/// Settings scope used for system-wide configuration (as opposed to per-user).
pub const SYSTEM_SCOPE: &str = "_system";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ValidationMode {
    #[default]
    Off,
    Lenient,
    Strict,
}

impl ValidationMode {
    /// Parse a validation mode from a raw DB JSON value.
    ///
    /// Fail-safe: returns `Off` on absent or invalid values, so a corrupted
    /// setting can never promote us to a stricter mode than operators expect.
    pub fn from_db_value(value: Option<serde_json::Value>) -> Self {
        match value {
            Some(v) => serde_json::from_value(v).unwrap_or(ValidationMode::Off),
            None => ValidationMode::Off,
        }
    }
}

/// Load the active validation mode from the settings store.
///
/// Returns `Off` when the setting is absent, invalid, or when the store
/// lookup itself fails (fail-safe default — never promote to a stricter
/// mode on error).
pub async fn load_validation_mode<S: SettingsStore + ?Sized>(store: &S) -> ValidationMode {
    match store.get_setting(SYSTEM_SCOPE, VALIDATION_MODE_KEY).await {
        Ok(value) => ValidationMode::from_db_value(value),
        Err(_) => ValidationMode::Off,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_off() {
        assert_eq!(ValidationMode::default(), ValidationMode::Off);
    }

    #[test]
    fn test_deserialize_off() {
        let mode: ValidationMode = serde_json::from_str("\"off\"").unwrap();
        assert_eq!(mode, ValidationMode::Off);
    }

    #[test]
    fn test_deserialize_lenient() {
        let mode: ValidationMode = serde_json::from_str("\"lenient\"").unwrap();
        assert_eq!(mode, ValidationMode::Lenient);
    }

    #[test]
    fn test_deserialize_strict() {
        let mode: ValidationMode = serde_json::from_str("\"strict\"").unwrap();
        assert_eq!(mode, ValidationMode::Strict);
    }

    #[test]
    fn test_deserialize_invalid_fails() {
        let result: Result<ValidationMode, _> = serde_json::from_str("\"bogus\"");
        assert!(result.is_err(), "bogus string must not deserialize");
    }

    #[test]
    fn test_serialize_lowercase() {
        let mode = ValidationMode::Lenient;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"lenient\"");
    }

    #[test]
    fn test_from_db_value_absent() {
        assert_eq!(ValidationMode::from_db_value(None), ValidationMode::Off);
    }

    #[test]
    fn test_from_db_value_lenient() {
        let v = serde_json::json!("lenient");
        assert_eq!(
            ValidationMode::from_db_value(Some(v)),
            ValidationMode::Lenient
        );
    }

    #[test]
    fn test_from_db_value_strict() {
        let v = serde_json::json!("strict");
        assert_eq!(
            ValidationMode::from_db_value(Some(v)),
            ValidationMode::Strict
        );
    }

    #[test]
    fn test_from_db_value_invalid_falls_back_to_off() {
        let v = serde_json::json!("totally-bogus");
        assert_eq!(ValidationMode::from_db_value(Some(v)), ValidationMode::Off);
    }
}
