//! Fixtures pour calibrer les graphs Sigma — Phase G4d-1.
//!
//! Format : un fichier `<graph-name>.test.yaml` dans `graphs/sigma/fixtures/`
//! liste des cas (ctx → outcome attendu). Le test runner charge le graph
//! original `<graph-name>.yaml`, exécute chaque cas, et vérifie que
//! l'outcome match l'attendu.
//!
//! Bénéfice : calibrage déterministe sans DB ni ReAct. Si un graph est
//! cassé, le test casse immédiatement (pas en prod).
//!
//! Format YAML :
//! ```yaml
//! graph: backdoor-port-block-handled
//! cases:
//!   - name: external_ip_block_archives
//!     ctx:
//!       alert: { firewall_action: "block", src_ip: "1.2.3.4" }
//!       graph: { asset_in_graph: false }
//!     expected:
//!       outcome: archive
//!       reason: "resolu par firewall"
//!
//!   - name: internal_asset_routes_to_llm
//!     ctx:
//!       alert: { firewall_action: "block" }
//!       graph: { asset_in_graph: true }
//!     expected:
//!       outcome: pending_async
//!       task_kind: investigate-llm
//! ```
//!
//! Outcomes possibles :
//! - `archive` (avec `reason` optionnel — substring match)
//! - `incident` (avec `severity` optionnel)
//! - `pending_async` (avec `task_kind` optionnel)
//! - `inconclusive`

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureFile {
    /// Nom du graph cible — doit matcher un `<name>.yaml` dans le même dossier.
    pub graph: String,
    pub cases: Vec<FixtureCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureCase {
    pub name: String,
    /// Sous-objets `alert`, `asset`, `dossier`, `signals`, `graph` —
    /// alimentent l'`EvalContext` directement.
    pub ctx: HashMap<String, serde_json::Value>,
    pub expected: ExpectedOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedOutcome {
    /// Type d'outcome : "archive", "incident", "pending_async", "inconclusive"
    pub outcome: String,
    /// Pour `archive` : substring attendue dans `reason`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Pour `incident` : severity attendue ("low", "medium", "high", "critical").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Pour `pending_async` : kind de task ("investigate-llm", "skill-call", ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_kind: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::investigation_graph::cel_eval::EvalContext;
    use crate::agent::investigation_graph::executor::{ExecutionOutcome, GraphExecutor};
    use crate::agent::investigation_graph::graph::compile;
    use crate::agent::investigation_graph::types::Graph;
    use serde_json::Value;
    use std::path::Path;

    /// Convertit un `HashMap<String, Value>` en `EvalContext`.
    fn build_ctx(ctx_map: &HashMap<String, Value>) -> EvalContext {
        let mut c = EvalContext::new();
        if let Some(v) = ctx_map.get("alert") {
            c = c.with_alert(v.clone());
        }
        if let Some(v) = ctx_map.get("asset") {
            c = c.with_asset(v.clone());
        }
        if let Some(v) = ctx_map.get("dossier") {
            c = c.with_dossier(v.clone());
        }
        if let Some(v) = ctx_map.get("signals") {
            c = c.with_signals(v.clone());
        }
        if let Some(v) = ctx_map.get("graph") {
            c = c.with_graph(v.clone());
        }
        c
    }

    fn check_outcome(got: &ExecutionOutcome, expected: &ExpectedOutcome) -> Result<(), String> {
        match (expected.outcome.as_str(), got) {
            ("archive", ExecutionOutcome::Archive { reason }) => {
                if let Some(expected_reason) = &expected.reason {
                    if !reason.contains(expected_reason.as_str()) {
                        return Err(format!(
                            "archive reason '{}' should contain '{}'",
                            reason, expected_reason
                        ));
                    }
                }
                Ok(())
            }
            ("incident", ExecutionOutcome::Incident { severity, .. }) => {
                if let Some(expected_sev) = &expected.severity {
                    if !severity.eq_ignore_ascii_case(expected_sev) {
                        return Err(format!(
                            "incident severity got '{}' want '{}'",
                            severity, expected_sev
                        ));
                    }
                }
                Ok(())
            }
            ("pending_async", ExecutionOutcome::PendingAsync { task_kind, .. }) => {
                if let Some(expected_kind) = &expected.task_kind {
                    if task_kind != expected_kind {
                        return Err(format!(
                            "pending_async task_kind got '{}' want '{}'",
                            task_kind, expected_kind
                        ));
                    }
                }
                Ok(())
            }
            ("inconclusive", ExecutionOutcome::Inconclusive) => Ok(()),
            (want, got) => Err(format!("expected outcome '{}', got {:?}", want, got)),
        }
    }

    /// Test d'intégration G4d-1 : pour chaque `*.test.yaml` dans
    /// `graphs/sigma/fixtures/`, charge le graph parent, exécute chaque
    /// case, vérifie l'outcome. Skip silencieusement si le dossier
    /// n'existe pas (dev / CI partielle).
    #[test]
    fn all_fixtures_match_expected_outcomes() {
        let fixtures_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("graphs/sigma/fixtures");
        let graphs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("graphs/sigma");
        if !fixtures_dir.exists() {
            eprintln!("skipping — {} not found", fixtures_dir.display());
            return;
        }

        let entries = std::fs::read_dir(&fixtures_dir)
            .expect("read fixtures dir")
            .flatten();

        let mut total_cases = 0usize;
        let mut failures: Vec<String> = Vec::new();

        for entry in entries {
            let path = entry.path();
            if !path.to_string_lossy().ends_with(".test.yaml") {
                continue;
            }
            let yaml = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
            let fixture: FixtureFile = serde_yaml_ng::from_str(&yaml)
                .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));

            let graph_path = graphs_dir.join(format!("{}.yaml", fixture.graph));
            let graph_yaml = std::fs::read_to_string(&graph_path).unwrap_or_else(|e| {
                panic!(
                    "read graph {} (referenced by {}): {}",
                    graph_path.display(),
                    path.display(),
                    e
                )
            });
            let graph: Graph = Graph::from_yaml(&graph_yaml).expect("parse graph");
            let compiled = compile(&graph).expect("compile graph");

            for case in &fixture.cases {
                total_cases += 1;
                let ctx = build_ctx(&case.ctx);
                match GraphExecutor::run(&compiled, &ctx) {
                    Ok(trace) => {
                        if let Err(msg) = check_outcome(&trace.outcome, &case.expected) {
                            failures.push(format!(
                                "[{}] case '{}': {}",
                                fixture.graph, case.name, msg
                            ));
                        }
                    }
                    Err(e) => {
                        failures.push(format!(
                            "[{}] case '{}': executor error: {}",
                            fixture.graph, case.name, e
                        ));
                    }
                }
            }
        }

        assert!(
            !failures.is_empty() || total_cases > 0,
            "no fixture cases discovered — that's a problem"
        );

        if !failures.is_empty() {
            panic!(
                "G4d-1 fixture failures ({}/{} cases):\n  - {}",
                failures.len(),
                total_cases,
                failures.join("\n  - ")
            );
        }
        eprintln!("G4d-1 fixtures: {} cases passed", total_cases);
    }
}
