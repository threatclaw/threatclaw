//! Suppression rules engine. See ADR-047.

pub mod cel_exec;
pub mod engine;
pub mod global;
pub mod model;

pub use engine::{CompileReport, SuppressionDecision, SuppressionEngine};
pub use model::{CompiledRule, RawRule, RuleAction, Scope};
