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
pub mod course_of_action;
pub mod campaign;
pub mod identity_graph;
pub mod blast_radius;
pub mod attack_path;
pub mod supply_chain;
pub mod threat_actor;
