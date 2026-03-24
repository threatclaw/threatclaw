//! Graph Intelligence — Apache AGE integration for ThreatClaw.
//!
//! Provides graph-based threat correlation, investigation paths,
//! and STIX-compatible data model using Cypher queries.

pub mod threat_graph;
pub mod investigation;
pub mod executor;
pub mod confidence;
pub mod lateral;
pub mod notes;
