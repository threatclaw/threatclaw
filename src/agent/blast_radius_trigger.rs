//! Auto-trigger blast-radius computation on verdict. See ADR-048.
//!
//! Called from the investigation pipeline after `update_incident_verdict`.
//! Decides whether to compute based on MITRE technique + severity, runs
//! the query against the in-memory graph cache, and persists a JSONB
//! snapshot on the incident row.

use crate::db::threatclaw_store::ThreatClawStore;
use crate::error::DatabaseError;
use crate::graph::normalized::{self, GraphCache};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Fire-and-forget variant used from the investigation pipeline.
/// Logs and swallows errors rather than propagating — the verdict
/// itself is independent of blast-radius availability.
pub async fn try_auto_trigger<S>(
    store: &S,
    incident_id: i32,
    asset: &str,
    mitre_techniques: &[String],
    severity: &str,
) where
    S: ThreatClawStore + ?Sized,
{
    if !should_compute(mitre_techniques, severity) {
        return;
    }
    let Some(cache) = normalized::global::get() else {
        tracing::debug!(
            "BLAST_RADIUS: cache not initialized, skipping incident #{}",
            incident_id
        );
        return;
    };
    match compute_and_persist(store, &cache, incident_id, asset).await {
        Ok(snapshot) => {
            tracing::info!(
                "BLAST_RADIUS: incident #{} score={} reachable={}",
                incident_id,
                snapshot.score,
                snapshot.reachable_count
            );
        }
        Err(e) => {
            tracing::warn!(
                "BLAST_RADIUS: incident #{} compute failed: {}",
                incident_id,
                e
            );
        }
    }
}

const MAX_HOPS: u8 = 3;
const REACHABLE_CAP: usize = 50;

/// MITRE technique prefixes that justify a blast-radius computation.
/// Kept tight — too permissive = wasted cycles, too narrow = misses
/// obvious lateral-risk cases.
const SENSITIVE_TECHNIQUES: &[&str] = &[
    "T1566",     // Phishing
    "T1078",     // Valid Accounts (credential theft)
    "T1003",     // OS Credential Dumping
    "T1068",     // Exploitation for Privilege Escalation
    "T1021",     // Remote Services (lateral movement)
    "T1078.001", // Default Accounts
    "T1078.002", // Domain Accounts
    "T1078.003", // Local Accounts
    "T1078.004", // Cloud Accounts
    "T1041",     // Exfiltration Over C2
    "T1567",     // Exfiltration Over Web Service
    "T1486",     // Data Encrypted for Impact
    "T1098",     // Account Manipulation
];

const SENSITIVE_SEVERITIES: &[&str] = &["HIGH", "CRITICAL"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusSnapshot {
    pub origin: String,
    pub score: u8,
    pub max_hops: u8,
    pub reachable_count: usize,
    pub reachable: Vec<normalized::query::ReachableAsset>,
}

pub fn should_compute(mitre: &[String], severity: &str) -> bool {
    if !SENSITIVE_SEVERITIES
        .iter()
        .any(|s| s.eq_ignore_ascii_case(severity))
    {
        return false;
    }
    mitre
        .iter()
        .any(|t| SENSITIVE_TECHNIQUES.iter().any(|s| t.starts_with(s)))
}

/// Normalize an asset identifier into the node-id format used by the
/// normalized graph (`kind:value`). The existing `incidents.asset`
/// column stores bare hostnames or IPs; we map them to `host:<value>`
/// when no prefix is present.
fn to_node_id(asset: &str) -> String {
    if asset.contains(':') {
        asset.to_string()
    } else {
        format!("host:{asset}")
    }
}

/// Compute + persist. Idempotent: re-running on the same incident
/// overwrites the snapshot.
pub async fn compute_and_persist<S>(
    store: &S,
    cache: &Arc<GraphCache>,
    incident_id: i32,
    asset: &str,
) -> Result<BlastRadiusSnapshot, BlastRadiusError>
where
    S: ThreatClawStore + ?Sized,
{
    let origin = to_node_id(asset);
    let result = normalized::query::blast_radius(cache, &origin, MAX_HOPS).await;
    let score = normalized::query::score(&result);

    let mut reachable = result.reachable;
    if reachable.len() > REACHABLE_CAP {
        reachable.truncate(REACHABLE_CAP);
    }

    let snapshot = BlastRadiusSnapshot {
        origin: origin.clone(),
        score,
        max_hops: MAX_HOPS,
        reachable_count: reachable.len(),
        reachable,
    };

    let snapshot_json = serde_json::to_value(&snapshot).map_err(BlastRadiusError::Serialization)?;

    store
        .attach_blast_radius_snapshot(incident_id, score, &snapshot_json)
        .await
        .map_err(BlastRadiusError::Persistence)?;

    Ok(snapshot)
}

#[derive(Debug, thiserror::Error)]
pub enum BlastRadiusError {
    #[error("serialization: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("persistence: {0}")]
    Persistence(DatabaseError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phishing_high_triggers() {
        assert!(should_compute(&["T1566.001".into()], "HIGH"));
        assert!(should_compute(&["T1566".into()], "CRITICAL"));
    }

    #[test]
    fn low_severity_skipped() {
        assert!(!should_compute(&["T1566".into()], "LOW"));
        assert!(!should_compute(&["T1021".into()], "MEDIUM"));
    }

    #[test]
    fn non_sensitive_technique_skipped() {
        assert!(!should_compute(&["T1499".into()], "CRITICAL"));
        assert!(!should_compute(&[], "HIGH"));
    }

    #[test]
    fn lateral_movement_triggers() {
        assert!(should_compute(&["T1021.001".into()], "HIGH"));
    }

    #[test]
    fn case_insensitive_severity() {
        assert!(should_compute(&["T1566".into()], "high"));
        assert!(should_compute(&["T1566".into()], "Critical"));
    }

    #[test]
    fn node_id_normalization() {
        assert_eq!(to_node_id("prod-sql01"), "host:prod-sql01");
        assert_eq!(to_node_id("host:prod-sql01"), "host:prod-sql01");
        assert_eq!(to_node_id("user:alice@corp.fr"), "user:alice@corp.fr");
        assert_eq!(to_node_id("10.0.0.1"), "host:10.0.0.1");
    }
}
