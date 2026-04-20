//! Shadow AI qualification pipeline.
//!
//! Consumes `shadow-ai-*` sigma_alerts and turns them into structured
//! governance artefacts :
//!   - a `finding` with category = `AI_USAGE_POLICY` and rich metadata
//!     (provider, endpoint, policy_decision) — so /findings and the
//!     Governance dashboard list them.
//!   - an `ai_systems` row upsert (status = `detected`) — so the shadow
//!     IA appears in the inventory until the RSSI declares it.
//!
//! Triggered via `POST /api/tc/governance/qualify-shadow-ai` for manual
//! runs. Wired into the intelligence_engine cycle in v0.2.
//!
//! No DB trait changes here — reuses existing `insert_finding`,
//! `upsert_ai_system` and `update_alert_status`. Pure orchestration.

use crate::db::threatclaw_store::{NewAiSystem, NewFinding, ThreatClawStore};
use serde_json::json;

/// Result of a qualification run.
#[derive(Debug, Default)]
pub struct QualificationResult {
    pub alerts_scanned: i64,
    pub findings_created: i64,
    pub ai_systems_upserted: i64,
    pub skipped_existing: i64,
}

/// Policy decision for v0.1 — deterministic default.
/// Once `[shadow_ai]` section lands in threatclaw.toml (v1.2), this will
/// consult the provider whitelist / category denylist. For now everything
/// is marked `unreviewed` — the RSSI acts via the Governance dashboard.
fn default_policy_decision() -> &'static str {
    "unreviewed"
}

/// Qualify all open shadow-ai-* alerts.
pub async fn qualify_shadow_ai_alerts(
    store: &dyn ThreatClawStore,
) -> Result<QualificationResult, String> {
    let mut out = QualificationResult::default();

    let alerts = store
        .list_alerts(None, Some("new"), 500, 0)
        .await
        .map_err(|e| format!("list_alerts: {}", e))?;

    for alert in alerts {
        if !alert.rule_id.starts_with("shadow-ai-") {
            continue;
        }
        out.alerts_scanned += 1;

        // Parse the alert's matched_fields JSONB to extract the hit value.
        let endpoint = extract_endpoint(&alert.matched_fields);
        let (provider, category) = classify_endpoint(&alert.rule_id, endpoint.as_deref());
        let decision = default_policy_decision();

        // 1) Create a finding (category = AI_USAGE_POLICY)
        let title = format!(
            "Shadow AI — {} via {}",
            provider.as_deref().unwrap_or("unknown"),
            endpoint.as_deref().unwrap_or(&alert.rule_id)
        );
        let description = format!(
            "Sigma rule {} matched — {} usage observed on asset {}.",
            alert.rule_id,
            provider.as_deref().unwrap_or("LLM"),
            alert.hostname.as_deref().unwrap_or("unknown")
        );
        let metadata = json!({
            "source_rule": alert.rule_id,
            "alert_id": alert.id,
            "llm_provider": provider,
            "llm_category": category,
            "endpoint": endpoint,
            "policy_decision": decision,
            "source_ip": alert.source_ip,
            "hostname": alert.hostname,
            "matched_at": alert.matched_at,
            "regulatory_flags": ["eu_ai_act_art12", "nis2_art21_2d", "iso_42001_a10"],
        });

        let new_finding = NewFinding {
            skill_id: "shadow-ai-monitor".into(),
            title,
            description: Some(description),
            severity: severity_from_rule(&alert.rule_id).into(),
            category: Some("AI_USAGE_POLICY".into()),
            asset: alert.hostname.clone().or(alert.source_ip.clone()),
            source: Some("zeek".into()),
            metadata: Some(metadata),
        };

        if store
            .insert_finding(&new_finding)
            .await
            .map_err(|e| format!("insert_finding: {}", e))
            .is_ok()
        {
            out.findings_created += 1;
        }

        // 2) Upsert into ai_systems (inventory) if the endpoint is identifiable
        if let Some(ep) = endpoint.as_ref() {
            let new_system = NewAiSystem {
                name: format!("{} ({})", provider.as_deref().unwrap_or("Unknown LLM"), ep),
                category: category.to_string(),
                provider: provider.clone(),
                endpoint: Some(ep.clone()),
                status: "detected".into(),
                risk_level: None, // left for RSSI to assess
                metadata: Some(json!({
                    "first_observed_rule": alert.rule_id,
                    "first_observed_asset": alert.hostname,
                })),
            };
            if store
                .upsert_ai_system(&new_system)
                .await
                .map_err(|e| format!("upsert_ai_system: {}", e))
                .is_ok()
            {
                out.ai_systems_upserted += 1;
            }
        }

        // 3) Mark alert as processed (status=investigating to avoid double-qualify).
        let _ = store
            .update_alert_status(
                alert.id,
                "investigating",
                Some("qualified by shadow-ai-monitor"),
            )
            .await;
    }

    Ok(out)
}

/// Extract the endpoint (FQDN, port, or URL path) from the alert's matched_fields.
/// The Sigma engine stores the matched values per field in JSONB — we look at
/// known keys in order of preference.
fn extract_endpoint(matched: &Option<serde_json::Value>) -> Option<String> {
    let m = matched.as_ref()?;
    let obj = m.as_object()?;
    // Common field names we emit in V40 rules
    for key in ["server_name", "query", "uri", "id.resp_p"] {
        if let Some(v) = obj.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
            if let Some(n) = v.as_i64() {
                return Some(n.to_string());
            }
            if let Some(arr) = v.as_array() {
                if let Some(first) = arr.first().and_then(|x| x.as_str()) {
                    return Some(first.to_string());
                }
            }
        }
    }
    None
}

/// Derive provider + category from the rule id and optionally the endpoint
/// substring. Deliberately conservative — we prefer "Unknown" over a wrong guess.
fn classify_endpoint(rule_id: &str, endpoint: Option<&str>) -> (Option<String>, &'static str) {
    let category = match rule_id {
        "shadow-ai-001" | "shadow-ai-002" => "llm-commercial",
        "shadow-ai-003" | "shadow-ai-004" => "llm-self-hosted",
        _ => "llm-commercial",
    };

    let ep = endpoint.unwrap_or("").to_lowercase();
    let provider = if ep.contains("openai") || ep.contains("chatgpt") || ep.contains("oaiu") {
        Some("OpenAI")
    } else if ep.contains("anthropic") || ep.contains("claude") {
        Some("Anthropic")
    } else if ep.contains("googleapis") || ep.contains("gemini") || ep.contains("aistudio") {
        Some("Google")
    } else if ep.contains("mistral") {
        Some("Mistral")
    } else if ep.contains("copilot") || ep.contains("m365.cloud.microsoft") {
        Some("Microsoft")
    } else if ep.contains("cohere") {
        Some("Cohere")
    } else if ep.contains("perplexity") {
        Some("Perplexity")
    } else if ep.contains("openrouter") {
        Some("OpenRouter")
    } else if ep.contains("together") {
        Some("Together")
    } else if ep.contains("groq") {
        Some("Groq")
    } else if ep.contains("deepseek") {
        Some("DeepSeek")
    } else if ep.contains("x.ai") || ep.contains("grok") {
        Some("xAI")
    } else if ep.contains("huggingface") {
        Some("HuggingFace")
    } else if ep.contains("cursor") {
        Some("Cursor")
    } else if ep.contains("githubcopilot") {
        Some("GitHub Copilot")
    } else if ep.contains("11434") {
        Some("Ollama")
    } else if ep.contains("1234") || ep.contains("43411") {
        Some("LM Studio")
    } else if ep.contains("8000") {
        Some("vLLM")
    } else if ep.contains("1337") {
        Some("Jan.ai")
    } else if ep.contains("4891") {
        Some("GPT4All")
    } else if ep.contains("7860") {
        Some("Text Generation WebUI")
    } else {
        None
    };

    (provider.map(String::from), category)
}

/// Map sigma rule id → finding severity.
/// DNS hits are lower severity than actual TLS/HTTP traffic (see V40 rule
/// definitions — shadow-ai-002 is `level: low`, others are `medium`).
fn severity_from_rule(rule_id: &str) -> &'static str {
    match rule_id {
        "shadow-ai-002" => "low",
        _ => "medium",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_openai_sni() {
        let (p, c) = classify_endpoint("shadow-ai-001", Some("api.openai.com"));
        assert_eq!(p.as_deref(), Some("OpenAI"));
        assert_eq!(c, "llm-commercial");
    }

    #[test]
    fn classify_ollama_port() {
        let (p, c) = classify_endpoint("shadow-ai-003", Some("11434"));
        assert_eq!(p.as_deref(), Some("Ollama"));
        assert_eq!(c, "llm-self-hosted");
    }

    #[test]
    fn classify_unknown_preserves_category() {
        let (p, c) = classify_endpoint("shadow-ai-001", Some("some-unknown-domain.example"));
        assert!(p.is_none());
        assert_eq!(c, "llm-commercial");
    }

    #[test]
    fn extract_endpoint_from_server_name() {
        let matched = Some(json!({"server_name": "api.anthropic.com"}));
        assert_eq!(
            extract_endpoint(&matched).as_deref(),
            Some("api.anthropic.com")
        );
    }

    #[test]
    fn extract_endpoint_from_port_number() {
        let matched = Some(json!({"id.resp_p": 11434}));
        assert_eq!(extract_endpoint(&matched).as_deref(), Some("11434"));
    }

    #[test]
    fn extract_endpoint_from_array() {
        let matched = Some(json!({"uri": ["/v1/chat/completions"]}));
        assert_eq!(
            extract_endpoint(&matched).as_deref(),
            Some("/v1/chat/completions")
        );
    }

    #[test]
    fn severity_is_low_for_dns_only() {
        assert_eq!(severity_from_rule("shadow-ai-002"), "low");
        assert_eq!(severity_from_rule("shadow-ai-001"), "medium");
        assert_eq!(severity_from_rule("shadow-ai-003"), "medium");
        assert_eq!(severity_from_rule("shadow-ai-004"), "medium");
    }
}
