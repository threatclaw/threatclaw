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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ValidationMode {
    #[default]
    Off,
    Lenient,
    Strict,
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
}
