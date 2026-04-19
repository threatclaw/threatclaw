//! Shared helpers for parsing LLM JSON responses (phase 2 v1.1.0-beta).
//!
//! Extracted from `investigation.rs` and `react_cycle.rs` to deduplicate
//! common logic. The two parsers still exist separately because their
//! return types differ (`ParsedLlmResponse` vs `LlmAnalysis`) — only the
//! fence-stripping and repair fallback are shared here.
//!
//! Defense against over-eager repair is encapsulated in `parse_or_repair`:
//! `llm_json` will happily turn arbitrary text into a JSON string or null,
//! so we require the repaired value to be an object carrying at least a
//! `verdict` or `analysis` field. Otherwise we treat the input as
//! irreparable and return Err.

use serde_json::Value;

/// Strip common markdown code fences from an LLM response.
///
/// Handles the three shapes we observe from Ollama and cloud backends:
/// - Fenced with ` ```json ... ``` `
/// - Fenced with ` ``` ... ``` `
/// - Plain JSON (no fences)
///
/// Never panics, always trims whitespace at the edges.
pub fn strip_markdown_fences(raw: &str) -> &str {
    raw.trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim()
}

/// Parse a string as JSON, attempting `llm_json::repair_json` if the first
/// parse fails. Returns the parsed `Value` on success.
///
/// Fail-safe guard against llm_json over-eager repairs: the repaired value
/// must be an object with at least a `verdict` or `analysis` field.
pub fn parse_or_repair(json_str: &str) -> Result<Value, String> {
    match serde_json::from_str::<Value>(json_str) {
        Ok(v) => Ok(v),
        Err(primary_err) => {
            tracing::warn!("LLM JSON parse failed, attempting repair via llm_json: {primary_err}");
            match llm_json::repair_json(json_str, &Default::default()) {
                Ok(repaired) => {
                    let candidate: Value = serde_json::from_str(&repaired).map_err(|e| {
                        format!(
                            "JSON parse error even after repair (primary: {primary_err}, repaired: {e})"
                        )
                    })?;
                    if !candidate.is_object()
                        || (candidate.get("verdict").is_none()
                            && candidate.get("analysis").is_none())
                    {
                        return Err(format!(
                            "JSON parse error: {primary_err} (repair produced shape without expected fields: {repaired})"
                        ));
                    }
                    Ok(candidate)
                }
                Err(repair_err) => Err(format!(
                    "JSON parse error: {primary_err} (repair also failed: {repair_err})"
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_strip_fences_json_block() {
        let raw = "```json\n{\"a\": 1}\n```";
        assert_eq!(strip_markdown_fences(raw), "{\"a\": 1}");
    }

    #[test]
    fn test_strip_fences_plain_block() {
        let raw = "```\n{\"a\": 1}\n```";
        assert_eq!(strip_markdown_fences(raw), "{\"a\": 1}");
    }

    #[test]
    fn test_strip_fences_no_fence() {
        assert_eq!(strip_markdown_fences("{\"a\": 1}"), "{\"a\": 1}");
    }

    #[test]
    fn test_strip_fences_handles_whitespace() {
        assert_eq!(
            strip_markdown_fences("   \n  {\"a\": 1}  \n "),
            "{\"a\": 1}"
        );
    }

    #[test]
    fn test_parse_or_repair_valid_json() {
        let v = parse_or_repair(r#"{"verdict":"confirmed","analysis":"x"}"#).unwrap();
        assert_eq!(v["verdict"], json!("confirmed"));
    }

    #[test]
    fn test_parse_or_repair_trailing_comma() {
        let v = parse_or_repair(r#"{"verdict":"confirmed","analysis":"x",}"#).unwrap();
        assert_eq!(v["verdict"], json!("confirmed"));
    }

    #[test]
    fn test_parse_or_repair_rejects_bare_garbage() {
        let err = parse_or_repair("this is not JSON at all <<<>>>").unwrap_err();
        assert!(
            err.contains("without expected fields") || err.contains("parse error"),
            "error must indicate repair rejected the input: {err}"
        );
    }

    #[test]
    fn test_parse_or_repair_accepts_analysis_only_object() {
        let v = parse_or_repair(r#"{"analysis":"something happened","severity":"LOW",}"#).unwrap();
        assert_eq!(v["analysis"], json!("something happened"));
    }
}
