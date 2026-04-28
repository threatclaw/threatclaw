//! Évaluation des prédicats CEL utilisés dans les `if-condition` /
//! `switch-condition` steps.
//!
//! On expose au CEL un contexte typé construit avant l'éval :
//! - `alert` : la sigma_alert qui a déclenché le graph (champs JSON)
//! - `asset` : l'asset cible (criticality, exposure, hostname, …)
//! - `dossier` : le dossier d'enquête en cours (findings, score, …)
//! - `signals` : compteurs précalculés (`recent_count_1h`, `corroborated`, …)
//! - `graph` : booleans précalculés (`asset_in_graph`, `lateral_path_exists`, …)
//!
//! On évite les fonctions custom CEL (l'API de cel-interpreter pour les
//! fonctions est instable) en précalculant tout côté Rust et en injectant
//! le résultat comme variable. C'est moins élégant mais plus robuste.
//!
//! Couche 4 (G1c) viendra ajouter les pré-calculs Cypher (count_recent,
//! lateral_path, …) avant l'éval.

use cel_interpreter::{Context, Program, Value};
use serde::Serialize;
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

/// Contexte construit avant l'éval CEL — tous les champs sont précalculés.
/// L'executor le construit pour chaque step `if-condition` qu'il rencontre.
#[derive(Debug, Default, Clone, Serialize)]
pub struct EvalContext {
    pub alert: JsonValue,
    pub asset: JsonValue,
    pub dossier: JsonValue,
    pub signals: JsonValue,
    pub graph: JsonValue,
}

impl EvalContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_alert(mut self, v: JsonValue) -> Self {
        self.alert = v;
        self
    }

    pub fn with_asset(mut self, v: JsonValue) -> Self {
        self.asset = v;
        self
    }

    pub fn with_dossier(mut self, v: JsonValue) -> Self {
        self.dossier = v;
        self
    }

    pub fn with_signals(mut self, v: JsonValue) -> Self {
        self.signals = v;
        self
    }

    pub fn with_graph(mut self, v: JsonValue) -> Self {
        self.graph = v;
        self
    }
}

/// Compile une expression CEL en programme réutilisable.
/// Wrappe `catch_unwind` car le parser peut paniquer sur certains inputs
/// malformés (cf. cel-rust#130, et précédent dans `suppression/cel_exec.rs`).
pub fn compile(source: &str) -> Result<Program, CelError> {
    let src = source.to_string();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || Program::compile(&src))) {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(e)) => Err(CelError::Compile(e.to_string())),
        Err(_) => Err(CelError::Compile(
            "parser panic on malformed predicate".into(),
        )),
    }
}

/// Évalue un programme CEL avec le contexte d'éval donné. Retourne le
/// booléen résultat — toute autre forme de retour est une erreur (CEL est
/// strictement typé, et nos prédicats doivent retourner un bool).
pub fn evaluate(program: &Program, ctx: &EvalContext) -> Result<bool, CelError> {
    let mut cel_ctx = Context::default();
    cel_ctx
        .add_variable("alert", ctx.alert.clone())
        .map_err(|e| CelError::Evaluate(e.to_string()))?;
    cel_ctx
        .add_variable("asset", ctx.asset.clone())
        .map_err(|e| CelError::Evaluate(e.to_string()))?;
    cel_ctx
        .add_variable("dossier", ctx.dossier.clone())
        .map_err(|e| CelError::Evaluate(e.to_string()))?;
    cel_ctx
        .add_variable("signals", ctx.signals.clone())
        .map_err(|e| CelError::Evaluate(e.to_string()))?;
    cel_ctx
        .add_variable("graph", ctx.graph.clone())
        .map_err(|e| CelError::Evaluate(e.to_string()))?;

    match program.execute(&cel_ctx) {
        Ok(Value::Bool(b)) => Ok(b),
        Ok(other) => Err(CelError::NonBool(other)),
        Err(e) => Err(CelError::Evaluate(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_simple() -> EvalContext {
        EvalContext::new()
            .with_alert(json!({
                "firewall_action": "block",
                "src_ip": "185.78.113.253",
                "severity": "HIGH",
            }))
            .with_asset(json!({
                "id": "asset-185-78-113-253",
                "criticality": 1,
                "in_internal_graph": false,
            }))
            .with_signals(json!({
                "recent_count_1h": 1,
                "corroborated": false,
            }))
            .with_graph(json!({
                "asset_in_graph": false,
                "lateral_path_exists": false,
                "linked_cves_count": 0,
            }))
    }

    #[test]
    fn predicate_action_is_block() {
        let p = compile(r#"alert.firewall_action == "block""#).unwrap();
        assert!(evaluate(&p, &ctx_simple()).unwrap());
    }

    #[test]
    fn predicate_asset_isolated() {
        let p = compile("graph.asset_in_graph == false").unwrap();
        assert!(evaluate(&p, &ctx_simple()).unwrap());
    }

    #[test]
    fn predicate_volume_threshold() {
        let p = compile("signals.recent_count_1h >= 5").unwrap();
        assert!(!evaluate(&p, &ctx_simple()).unwrap());
    }

    #[test]
    fn conjunction_archive_decision() {
        // motif "résolu par firewall" = block appliqué + IP externe
        let p = compile(r#"alert.firewall_action == "block" && graph.asset_in_graph == false"#)
            .unwrap();
        assert!(evaluate(&p, &ctx_simple()).unwrap());
    }

    #[test]
    fn malformed_predicate_does_not_panic() {
        let err = compile(r#"alert.x == "unclosed"#).unwrap_err();
        assert!(matches!(err, CelError::Compile(_)));
    }

    #[test]
    fn non_bool_result_is_rejected() {
        let p = compile("alert.severity").unwrap();
        let err = evaluate(&p, &ctx_simple()).unwrap_err();
        assert!(matches!(err, CelError::NonBool(_)));
    }
}
