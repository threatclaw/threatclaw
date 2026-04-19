//! Structured telemetry helpers for LLM calls, reconciler decisions and
//! evidence citation checks (phase 5 v1.1.0-beta).
//!
//! We intentionally keep this layer dependency-free: events are emitted via
//! `tracing::info!` with structured fields. Any downstream OpenTelemetry
//! collector (Langfuse, Phoenix, Grafana, Datadog...) can consume the
//! JSON-formatted logs or attach a `tracing-opentelemetry` subscriber
//! layer — no rebuild required.
//!
//! Field naming: `tracing` macro requires valid Rust identifiers for field
//! keys, so we use underscores rather than OTel's conventional dots. A
//! downstream collector maps `gen_ai_system` <-> `gen_ai.system` trivially
//! (Langfuse ingestion rules or OTel processor). ThreatClaw-specific fields
//! are prefixed `threatclaw_`.

use sha2::{Digest, Sha256};

/// Deterministic short hash of an (anonymised) prompt body, used to
/// deduplicate identical prompts in telemetry without leaking the text.
///
/// Returns the first 16 hex chars of SHA-256 — 2^64 collision space which
/// is plenty for dedup scope.
pub fn prompt_hash(prompt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prompt.as_bytes());
    let digest = hasher.finalize();
    let mut s = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Emit a structured event for an LLM call outcome.
pub fn log_llm_call(
    system: &str,
    model: &str,
    level: &str,
    prompt: &str,
    response_len: usize,
    latency_ms: u128,
    schema_used: bool,
) {
    tracing::info!(
        target: "threatclaw.llm_call",
        gen_ai_system = system,
        gen_ai_request_model = model,
        threatclaw_llm_level = level,
        threatclaw_prompt_hash = %prompt_hash(prompt),
        threatclaw_prompt_len = prompt.len(),
        threatclaw_response_len = response_len,
        threatclaw_latency_ms = latency_ms,
        threatclaw_schema_used = schema_used,
        "llm_call_completed"
    );
}

/// Emit a structured event for a reconciliation outcome.
pub fn log_reconcile_outcome(
    incident_id: Option<i32>,
    mode: &str,
    applied: bool,
    original_verdict: &str,
    reconciled_verdict: &str,
    reason_code: Option<&str>,
    validation_errors: usize,
    fabricated_citations: usize,
) {
    tracing::info!(
        target: "threatclaw.reconciler",
        threatclaw_incident_id = incident_id.unwrap_or(-1),
        threatclaw_validation_mode = mode,
        threatclaw_reconciler_applied = applied,
        threatclaw_verdict_original = original_verdict,
        threatclaw_verdict_reconciled = reconciled_verdict,
        threatclaw_reconciler_rule_code = reason_code.unwrap_or("none"),
        threatclaw_validation_error_count = validation_errors,
        threatclaw_citation_fabricated_count = fabricated_citations,
        "reconcile_completed"
    );
}

/// Emit a structured event for a citation check outcome.
pub fn log_citation_report(
    incident_id: Option<i32>,
    verified: usize,
    unverifiable: usize,
    fabricated: usize,
) {
    if verified + unverifiable + fabricated == 0 {
        return;
    }
    tracing::info!(
        target: "threatclaw.citations",
        threatclaw_incident_id = incident_id.unwrap_or(-1),
        threatclaw_citation_verified_count = verified,
        threatclaw_citation_unverifiable_count = unverifiable,
        threatclaw_citation_fabricated_count = fabricated,
        "citation_check_completed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_hash_deterministic() {
        let a = prompt_hash("hello world");
        let b = prompt_hash("hello world");
        assert_eq!(a, b, "same input must produce same hash");
        assert_eq!(a.len(), 16, "hash must be 16 hex chars");
    }

    #[test]
    fn test_prompt_hash_changes_on_different_input() {
        let a = prompt_hash("hello");
        let b = prompt_hash("hello ");
        assert_ne!(a, b, "different inputs must produce different hashes");
    }

    #[test]
    fn test_prompt_hash_is_lowercase_hex() {
        let h = prompt_hash("x");
        assert!(
            h.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "hash must be lowercase hex: {h}"
        );
    }
}
