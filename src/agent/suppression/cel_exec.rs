//! CEL program compilation + event binding. See ADR-046.

use cel_interpreter::{Context, Program, Value};
use serde_json::Value as JsonValue;

#[derive(Debug, thiserror::Error)]
pub enum CelError {
    #[error("compile: {0}")]
    Compile(String),
    #[error("evaluate: {0}")]
    Evaluate(String),
    #[error("predicate must return bool, got {0:?}")]
    NonBool(Value),
}

/// Compile a CEL source string into a reusable program.
///
/// The underlying `antlr4rust` parser is known to panic on certain
/// malformed inputs (see cel-rust#130 tracking). We wrap in
/// `catch_unwind` so a bad user-supplied predicate never brings down
/// the agent process.
pub fn compile(source: &str) -> Result<Program, CelError> {
    let src = source.to_string();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || Program::compile(&src))) {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(e)) => Err(CelError::Compile(e.to_string())),
        Err(_) => Err(CelError::Compile("parser panic on malformed input".into())),
    }
}

/// Evaluate a program with the given `event` bound. Returns the boolean
/// match result. Non-bool results are treated as compile-time errors
/// from the user's point of view — CEL is strongly typed.
pub fn evaluate(program: &Program, event: &JsonValue) -> Result<bool, CelError> {
    let mut ctx = Context::default();
    ctx.add_variable("event", event.clone())
        .map_err(|e| CelError::Evaluate(e.to_string()))?;

    match program.execute(&ctx) {
        Ok(Value::Bool(b)) => Ok(b),
        Ok(other) => Err(CelError::NonBool(other)),
        Err(e) => Err(CelError::Evaluate(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nessus_event() -> JsonValue {
        serde_json::json!({
            "skill_id": "skill-suricata",
            "category": "port_scan",
            "severity": "MEDIUM",
            "src_ip": "10.0.5.42",
            "tags": ["internal-scan"],
            "asset": "prod-web01",
        })
    }

    #[test]
    fn simple_equality_matches() {
        let p = compile(r#"event.skill_id == "skill-suricata""#).unwrap();
        assert!(evaluate(&p, &nessus_event()).unwrap());
    }

    #[test]
    fn conjunction() {
        let p = compile(r#"event.skill_id == "skill-suricata" && event.category == "port_scan""#)
            .unwrap();
        assert!(evaluate(&p, &nessus_event()).unwrap());
    }

    #[test]
    fn no_match_on_wrong_value() {
        let p = compile(r#"event.skill_id == "skill-zeek""#).unwrap();
        assert!(!evaluate(&p, &nessus_event()).unwrap());
    }

    #[test]
    fn array_contains() {
        let p = compile(r#""internal-scan" in event.tags"#).unwrap();
        assert!(evaluate(&p, &nessus_event()).unwrap());
    }

    #[test]
    fn compile_error_is_reported() {
        // Unbalanced quote → parse error at lex time (before antlr).
        let err = compile(r#"event.skill_id == "unclosed"#).unwrap_err();
        assert!(matches!(err, CelError::Compile(_)));
    }

    #[test]
    fn non_bool_predicate_is_rejected() {
        let p = compile("event.skill_id").unwrap();
        let err = evaluate(&p, &nessus_event()).unwrap_err();
        assert!(matches!(err, CelError::NonBool(_)));
    }

    #[test]
    fn missing_field_errors_cleanly() {
        let p = compile("event.does_not_exist == 1").unwrap();
        let err = evaluate(&p, &nessus_event()).unwrap_err();
        assert!(matches!(err, CelError::Evaluate(_)));
    }
}
