//! Integration test: Ollama structured outputs against a live server.
//!
//! Calls Ollama with the `triage_schema` and verifies that the returned
//! JSON both parses and validates against the schema. Marked `#[ignore]`
//! so it does not run in default `cargo test` runs.
//!
//! To execute it explicitly, Ollama must be running locally with a model
//! available, then:
//!
//!     OLLAMA_URL=http://localhost:11434 OLLAMA_MODEL=qwen2.5:3b-instruct \
//!         cargo test --test ollama_structured_outputs_integration \
//!             -- --ignored --nocapture
//!
//! The test is intentionally tolerant on the content of the response
//! (we do not care what the model thinks for this smoke test) — we only
//! care that the response shape is enforced by the FSM sampler.

use threatclaw::agent::llm_schemas::triage_schema;
use threatclaw::agent::react_runner::call_ollama_with_schema;

fn ollama_url() -> String {
    std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".to_string())
}

fn ollama_model() -> String {
    // qwen3:14b reliably respects min/max numeric constraints in prompts.
    // Smaller models (qwen2.5:3b) often return integers like 95 for
    // `confidence` when the schema asks for a number in [0.0, 1.0] — the
    // Ollama FSM enforces structure but NOT value-range constraints, which
    // is precisely why our jsonschema post-validation is necessary.
    std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "qwen3:14b".to_string())
}

#[tokio::test]
#[ignore]
async fn triage_schema_is_enforced_by_ollama() {
    let url = ollama_url();
    let model = ollama_model();

    let prompt = "A single SSH brute force attempt was observed against srv-web-01 \
                  from IP 185.220.101.42. Produce a triage verdict in the required JSON schema. \
                  IMPORTANT: the `confidence` field MUST be a decimal number between 0.0 and 1.0 \
                  (for example 0.85, not 85). Do not use percentages.";

    let raw = call_ollama_with_schema(&url, &model, prompt, Some(triage_schema()))
        .await
        .expect("Ollama call failed — is it running and is the model pulled?");

    eprintln!(
        "\n=== Ollama response (len={}) ===\n{raw}\n================\n",
        raw.len()
    );

    // Step 1: the response must be valid JSON.
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).expect("response must parse as JSON (FSM-guaranteed)");

    // Step 2: the response must validate against the triage schema.
    let validator = jsonschema::validator_for(&triage_schema()).expect("triage_schema compiles");

    if !validator.is_valid(&parsed) {
        let errors: Vec<String> = validator
            .iter_errors(&parsed)
            .map(|e| format!("  - {e}"))
            .collect();
        panic!(
            "response does NOT validate against triage_schema:\n{}\n\nResponse was:\n{raw}",
            errors.join("\n")
        );
    }
}
