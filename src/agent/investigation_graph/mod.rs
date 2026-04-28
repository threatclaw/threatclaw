//! Investigation Graphs — déterministe DAG runtime pour le pipeline SOC.
//!
//! Phase G — voir `internal/PHASE_G_INVESTIGATION_GRAPHS.md` pour l'archi.
//!
//! Vue d'ensemble :
//! - **types.rs** — modèle Rust des graphs CACAO v2 (parsé depuis YAML)
//! - **graph.rs** — conversion modèle → `petgraph::DiGraph` pour traversée
//! - **executor.rs** — moteur de traversée + exécution des steps
//! - **cel_eval.rs** — évaluation des prédicats CEL avec fonctions custom
//!   (`count_recent_signals`, `asset_in_graph`, `asset_criticality`, …)
//!
//! Source de vérité des graphs : fichiers YAML dans `graphs/sigma/` du repo.
//! Loadés au boot dans une `GraphLibrary` immuable. Pas de stockage en DB —
//! les définitions sont sous git, l'AGE est utilisée seulement comme outil
//! de requête pour les patterns complexes (couche 4 de l'archi).
//!
//! Les exécutions concrètes (chemin pris, durées par step, verdict final)
//! sont persistées en table `graph_executions` (G1b — couche 2 task queue).

pub mod cel_eval;
pub mod executor;
pub mod fixtures;
pub mod graph;
pub mod library;
pub mod types;

pub use cel_eval::EvalContext;
pub use executor::{ExecutionOutcome, ExecutionTrace, GraphExecutor, StepResult};
pub use graph::{CompiledGraph, GraphCompileError};
pub use library::{GraphLibrary, LibraryError};
pub use types::{Command, Graph, Step, Trigger};
