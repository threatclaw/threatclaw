//! Compilation d'un `Graph` (modèle parsé) vers un `petgraph::DiGraph`
//! prêt à être traversé par l'`executor`.
//!
//! Cette compilation valide que :
//! - exactement un step `start` existe
//! - au moins un step `end` existe
//! - tous les `on_completion` / `on_true` / `on_false` / `cases` /
//!   `next_steps` / `join` / `default_case` référencent un step présent
//! - aucun cycle (DAG strict — un graph qui ferait une boucle est un bug
//!   de l'auteur du graph, pas un cas légitime à exécuter)
//!
//! Le graph compilé est immuable : `CompiledGraph` est partagé entre tous
//! les graphs en cours d'exécution (Arc).

use std::collections::HashMap;

use petgraph::Direction;
use petgraph::algo::is_cyclic_directed;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use thiserror::Error;

use super::types::{Graph, Step};

#[derive(Debug, Error)]
pub enum GraphCompileError {
    #[error("graph '{0}' missing 'start' step")]
    MissingStart(String),

    #[error("graph '{0}' has multiple 'start' steps: {1:?}")]
    MultipleStarts(String, Vec<String>),

    #[error("graph '{0}' missing any 'end' step")]
    MissingEnd(String),

    #[error("graph '{0}' references unknown step '{1}' (from '{2}')")]
    UnknownStepReference(String, String, String),

    #[error("graph '{0}' contains a cycle — only DAGs are valid")]
    CyclicGraph(String),
}

/// Graph compilé prêt à exécuter. Immuable, partagable via Arc.
#[derive(Debug, Clone)]
pub struct CompiledGraph {
    pub name: String,
    pub trigger_sigma_rule: String,
    /// petgraph DiGraph — nœuds = step name, edges = transitions.
    pub dag: DiGraph<String, EdgeKind>,
    /// step name → NodeIndex (lookup rapide pendant l'exécution)
    pub indices: HashMap<String, NodeIndex>,
    /// step name → Step (la définition originale)
    pub steps: HashMap<String, Step>,
    /// nom du step start (entrée du graph)
    pub start_step: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// transition séquentielle (on_completion)
    Sequential,
    /// branche `true` d'un `if-condition`
    ConditionTrue,
    /// branche `false` d'un `if-condition`
    ConditionFalse,
    /// case d'un `switch-condition`
    SwitchCase,
    /// case par défaut d'un `switch-condition`
    SwitchDefault,
    /// fan-out d'un `parallel` step
    ParallelFanout,
    /// fan-in vers le `join` d'un `parallel` step
    ParallelJoin,
    /// retour d'un `playbook-action` (sub-graph) vers le step suivant
    PlaybookReturn,
}

pub fn compile(graph: &Graph) -> Result<CompiledGraph, GraphCompileError> {
    let name = graph.name.clone();

    // Identifier le step `start`
    let starts: Vec<&String> = graph
        .steps
        .iter()
        .filter_map(|(k, s)| matches!(s, Step::Start { .. }).then_some(k))
        .collect();
    let start_step = match starts.as_slice() {
        [] => return Err(GraphCompileError::MissingStart(name)),
        [s] => (*s).clone(),
        many => {
            return Err(GraphCompileError::MultipleStarts(
                name,
                many.iter().map(|s| (*s).clone()).collect(),
            ));
        }
    };

    // Vérifier qu'au moins un `end` existe
    let has_end = graph.steps.values().any(|s| matches!(s, Step::End));
    if !has_end {
        return Err(GraphCompileError::MissingEnd(name));
    }

    // Construire le DAG
    let mut dag: DiGraph<String, EdgeKind> = DiGraph::new();
    let mut indices: HashMap<String, NodeIndex> = HashMap::new();

    for step_name in graph.steps.keys() {
        let idx = dag.add_node(step_name.clone());
        indices.insert(step_name.clone(), idx);
    }

    for (step_name, step) in &graph.steps {
        let from = indices[step_name];
        let refs = collect_refs(step);
        for (target, kind) in refs {
            let to = indices.get(&target).ok_or_else(|| {
                GraphCompileError::UnknownStepReference(
                    name.clone(),
                    target.clone(),
                    step_name.clone(),
                )
            })?;
            dag.add_edge(from, *to, kind);
        }
    }

    // Vérifier l'absence de cycles
    if is_cyclic_directed(&dag) {
        return Err(GraphCompileError::CyclicGraph(name));
    }

    Ok(CompiledGraph {
        name,
        trigger_sigma_rule: graph.trigger.sigma_rule.clone(),
        dag,
        indices,
        steps: graph.steps.clone(),
        start_step,
    })
}

/// Liste les transitions sortantes d'un step et leur kind d'edge.
fn collect_refs(step: &Step) -> Vec<(String, EdgeKind)> {
    let mut refs = Vec::new();
    match step {
        Step::Start { on_completion } => {
            refs.push((on_completion.clone(), EdgeKind::Sequential));
        }
        Step::End => {}
        Step::Action {
            on_completion: Some(next),
            ..
        } => {
            refs.push((next.clone(), EdgeKind::Sequential));
        }
        Step::Action {
            on_completion: None,
            ..
        } => {}
        Step::IfCondition {
            on_true, on_false, ..
        } => {
            refs.push((on_true.clone(), EdgeKind::ConditionTrue));
            refs.push((on_false.clone(), EdgeKind::ConditionFalse));
        }
        Step::SwitchCondition {
            cases,
            default_case,
            ..
        } => {
            for target in cases.values() {
                refs.push((target.clone(), EdgeKind::SwitchCase));
            }
            if let Some(target) = default_case {
                refs.push((target.clone(), EdgeKind::SwitchDefault));
            }
        }
        Step::Parallel { next_steps, join } => {
            for target in next_steps {
                refs.push((target.clone(), EdgeKind::ParallelFanout));
            }
            refs.push((join.clone(), EdgeKind::ParallelJoin));
        }
        Step::PlaybookAction { on_completion, .. } => {
            refs.push((on_completion.clone(), EdgeKind::PlaybookReturn));
        }
    }
    refs
}

impl CompiledGraph {
    /// Retourne le step suivant pour une transition séquentielle, ou
    /// `None` si terminal.
    pub fn next_sequential(&self, from: &str) -> Option<&str> {
        let from_idx = self.indices.get(from)?;
        self.dag
            .edges_directed(*from_idx, Direction::Outgoing)
            .find(|e| *e.weight() == EdgeKind::Sequential)
            .and_then(|e| {
                let target = self.dag.node_weight(e.target())?;
                Some(target.as_str())
            })
    }
}
