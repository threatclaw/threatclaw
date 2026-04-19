//! Canonical JSON schemas for Ollama structured outputs (phase 1 v1.1.0-beta).
//!
//! These schemas are passed to Ollama via the `format` request field so that
//! the sampler constrains the output tokens at inference time (FSM-based
//! guarantee, llama.cpp 0.5+). The resulting JSON is therefore guaranteed to
//! parse and conform to our enum shapes.
//!
//! We double-validate the output with the `jsonschema` crate to guard against:
//! - Ollama backends that silently ignore unsupported schema features.
//! - Models that occasionally drift (Foundation-Sec-8B Q8_0 on long contexts).
//!
//! Three schemas cover the pipeline:
//! - `triage_schema`  : response from L1 (qwen3:8b) — short triage verdict
//! - `forensic_schema`: response from L2 (Foundation-Sec) — enriched forensic
//! - `verdict_schema` : canonical "final verdict" shape used by phase 4
//!                      (evidence citations) — not wired into the Ollama call
//!                      yet, kept here for single-source-of-truth.
//!
//! All three share a common "severity + confidence + analysis" core. Verdict
//! enum values are lowercase + underscores to match the prompt contract
//! documented in `src/agent/prompt_builder.rs`.

use serde_json::{Value, json};

/// Schema for the L1 triage response.
///
/// Minimal: the triage step should only emit a coarse verdict + whether
/// more information is needed. Heavy forensic detail belongs in L2.
pub fn triage_schema() -> Value {
    json!({
        "type": "object",
        "required": ["verdict", "severity", "confidence", "analysis"],
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["confirmed", "false_positive", "inconclusive", "informational"]
            },
            "severity": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0
            },
            "analysis": {
                "type": "string",
                "minLength": 5,
                "maxLength": 2000
            },
            "correlations": {
                "type": "array",
                "items": { "type": "string", "maxLength": 500 }
            },
            "needs_more_info": { "type": "boolean" },
            "skill_requests": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["skill_name"],
                    "properties": {
                        "skill_name": { "type": "string", "minLength": 1 },
                        "params": { "type": "object" }
                    }
                }
            },
            "proposed_actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["cmd_id", "rationale"],
                    "properties": {
                        "cmd_id": { "type": "string", "minLength": 1 },
                        "params": { "type": "object" },
                        "rationale": { "type": "string", "minLength": 1 }
                    }
                }
            }
        }
    })
}

/// Schema for the L2 forensic response.
///
/// Richer than triage: asks for MITRE techniques, CVEs and IoCs explicitly so
/// the phase-2 validators can cross-check each item against the DB.
pub fn forensic_schema() -> Value {
    json!({
        "type": "object",
        "required": ["verdict", "severity", "confidence", "analysis", "mitre_techniques"],
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["confirmed", "false_positive", "inconclusive", "informational"]
            },
            "severity": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0
            },
            "analysis": {
                "type": "string",
                "minLength": 10,
                "maxLength": 4000
            },
            "mitre_techniques": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": "^T\\d{4}(\\.\\d{3})?$"
                }
            },
            "cves": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": "^CVE-\\d{4}-\\d{4,}$"
                }
            },
            "iocs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["type", "value"],
                    "properties": {
                        "type": {
                            "type": "string",
                            "enum": ["ip", "domain", "url", "sha256", "sha1", "md5", "email"]
                        },
                        "value": { "type": "string", "minLength": 1 }
                    }
                }
            },
            "proposed_actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["cmd_id", "rationale"],
                    "properties": {
                        "cmd_id": { "type": "string", "minLength": 1 },
                        "params": { "type": "object" },
                        "rationale": { "type": "string", "minLength": 1 }
                    }
                }
            },
            "evidence_citations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["claim", "evidence_type", "evidence_id"],
                    "properties": {
                        "claim": { "type": "string", "minLength": 5 },
                        "evidence_type": {
                            "type": "string",
                            "enum": ["alert", "finding", "log", "graph_node"]
                        },
                        "evidence_id": { "type": "string", "minLength": 1 },
                        "excerpt": { "type": "string" }
                    }
                }
            }
        }
    })
}

/// Canonical final-verdict schema.
///
/// Describes the shape persisted as the final incident verdict (phase 4 will
/// wire `evidence_citations` into this). Not currently passed to Ollama — it
/// is kept here so that phase-2 validators and phase-4 evidence tracking
/// share a single source of truth.
pub fn verdict_schema() -> Value {
    json!({
        "type": "object",
        "required": ["verdict", "severity", "confidence", "analysis"],
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["confirmed", "false_positive", "inconclusive", "informational"]
            },
            "severity": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0
            },
            "analysis": {
                "type": "string",
                "minLength": 10,
                "maxLength": 4000
            },
            "mitre_techniques": {
                "type": "array",
                "items": { "type": "string", "pattern": "^T\\d{4}(\\.\\d{3})?$" }
            },
            "evidence_citations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["claim", "evidence_type", "evidence_id"],
                    "properties": {
                        "claim": { "type": "string", "minLength": 5 },
                        "evidence_type": {
                            "type": "string",
                            "enum": ["alert", "finding", "log", "graph_node"]
                        },
                        "evidence_id": { "type": "string", "minLength": 1 }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(schema: &Value) -> jsonschema::Validator {
        jsonschema::validator_for(schema).expect("schema must compile")
    }

    #[test]
    fn test_triage_schema_compiles() {
        let _ = compile(&triage_schema());
    }

    #[test]
    fn test_forensic_schema_compiles() {
        let _ = compile(&forensic_schema());
    }

    #[test]
    fn test_verdict_schema_compiles() {
        let _ = compile(&verdict_schema());
    }

    #[test]
    fn test_triage_accepts_minimal_confirmed_verdict() {
        let validator = compile(&triage_schema());
        let instance = json!({
            "verdict": "confirmed",
            "severity": "HIGH",
            "confidence": 0.87,
            "analysis": "SSH brute force from Tor exit node 185.220.101.42"
        });
        assert!(
            validator.is_valid(&instance),
            "minimal L1 verdict must validate"
        );
    }

    #[test]
    fn test_triage_rejects_unknown_verdict_enum() {
        let validator = compile(&triage_schema());
        let instance = json!({
            "verdict": "maybe",
            "severity": "HIGH",
            "confidence": 0.5,
            "analysis": "ambiguous"
        });
        assert!(
            !validator.is_valid(&instance),
            "verdict 'maybe' must be rejected (enum violation)"
        );
    }

    #[test]
    fn test_triage_rejects_confidence_out_of_range() {
        let validator = compile(&triage_schema());
        let instance = json!({
            "verdict": "inconclusive",
            "severity": "MEDIUM",
            "confidence": 1.5,
            "analysis": "noisy"
        });
        assert!(
            !validator.is_valid(&instance),
            "confidence 1.5 must be rejected (maximum 1.0)"
        );
    }

    #[test]
    fn test_forensic_accepts_full_response() {
        let validator = compile(&forensic_schema());
        let instance = json!({
            "verdict": "confirmed",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "analysis": "Log4Shell exploitation followed by webshell upload and lateral movement.",
            "mitre_techniques": ["T1190", "T1059.001", "T1021.004"],
            "cves": ["CVE-2021-44228"],
            "iocs": [
                { "type": "ip", "value": "185.220.101.42" },
                { "type": "sha256", "value": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2" }
            ]
        });
        assert!(validator.is_valid(&instance), "full L2 verdict must validate");
    }

    #[test]
    fn test_forensic_rejects_malformed_mitre_id() {
        let validator = compile(&forensic_schema());
        let instance = json!({
            "verdict": "confirmed",
            "severity": "HIGH",
            "confidence": 0.8,
            "analysis": "some activity detected",
            "mitre_techniques": ["T1055.999", "NOT_A_TECHNIQUE"]
        });
        assert!(
            !validator.is_valid(&instance),
            "malformed MITRE IDs must be rejected by the regex pattern"
        );
    }

    #[test]
    fn test_forensic_rejects_bogus_cve_id() {
        let validator = compile(&forensic_schema());
        let instance = json!({
            "verdict": "confirmed",
            "severity": "HIGH",
            "confidence": 0.8,
            "analysis": "some activity detected",
            "mitre_techniques": ["T1190"],
            "cves": ["CVE-21-001"]
        });
        assert!(
            !validator.is_valid(&instance),
            "malformed CVE id must be rejected"
        );
    }

    #[test]
    fn test_verdict_accepts_evidence_citations() {
        let validator = compile(&verdict_schema());
        let instance = json!({
            "verdict": "confirmed",
            "severity": "HIGH",
            "confidence": 0.9,
            "analysis": "Brute force confirmed by correlating 13 failed auth events with source IP geolocation.",
            "evidence_citations": [
                { "claim": "13 failed auth attempts", "evidence_type": "alert", "evidence_id": "42" },
                { "claim": "source IP is a known Tor exit node", "evidence_type": "log", "evidence_id": "log-hash-deadbeef" }
            ]
        });
        assert!(
            validator.is_valid(&instance),
            "verdict with citations must validate"
        );
    }

    #[test]
    fn test_forensic_accepts_citations() {
        let validator = compile(&forensic_schema());
        let instance = json!({
            "verdict": "confirmed",
            "severity": "HIGH",
            "confidence": 0.9,
            "analysis": "SSH brute force confirmed with 13 failed attempts.",
            "mitre_techniques": ["T1110"],
            "evidence_citations": [
                { "claim": "13 failed attempts", "evidence_type": "alert", "evidence_id": "42" }
            ]
        });
        assert!(
            validator.is_valid(&instance),
            "forensic with citations must validate"
        );
    }

    #[test]
    fn test_forensic_rejects_unknown_evidence_type() {
        let validator = compile(&forensic_schema());
        let instance = json!({
            "verdict": "confirmed",
            "severity": "HIGH",
            "confidence": 0.9,
            "analysis": "analysis text long enough",
            "mitre_techniques": ["T1110"],
            "evidence_citations": [
                { "claim": "something", "evidence_type": "file", "evidence_id": "1" }
            ]
        });
        assert!(
            !validator.is_valid(&instance),
            "evidence_type 'file' must be rejected (not in enum)"
        );
    }

    #[test]
    fn test_verdict_rejects_citation_without_evidence_id() {
        let validator = compile(&verdict_schema());
        let instance = json!({
            "verdict": "confirmed",
            "severity": "HIGH",
            "confidence": 0.9,
            "analysis": "Brute force confirmed.",
            "evidence_citations": [
                { "claim": "some claim", "evidence_type": "alert" }
            ]
        });
        assert!(
            !validator.is_valid(&instance),
            "citation missing evidence_id must be rejected (required field)"
        );
    }
}
