//! Graph edge types. See ADR-045 §schéma and graph_edge_catalog seed.

use super::node::NodeId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Kind string. Kept as `String` rather than an enum so skills premium
/// can extend the catalog without recompiling the core.
pub type EdgeKind = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub src: NodeId,
    pub dst: NodeId,
    pub kind: EdgeKind,
    pub weight: u8,
    #[serde(default)]
    pub properties: serde_json::Value,
    pub source_skill: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds_option", default)]
    pub observed_at: Option<DateTime<Utc>>,
    #[serde(with = "chrono::serde::ts_seconds_option", default)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl Edge {
    pub fn new(src: impl Into<NodeId>, dst: impl Into<NodeId>, kind: impl Into<EdgeKind>) -> Self {
        Self {
            src: src.into(),
            dst: dst.into(),
            kind: kind.into(),
            weight: 1,
            properties: serde_json::Value::Object(Default::default()),
            source_skill: None,
            observed_at: None,
            expires_at: None,
        }
    }

    pub fn with_weight(mut self, w: u8) -> Self {
        self.weight = w.clamp(1, 10);
        self
    }

    /// Currently unexpired = no TTL OR TTL in the future.
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            None => true,
            Some(t) => t > now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weight_is_clamped() {
        assert_eq!(Edge::new("a", "b", "CanRDP").with_weight(0).weight, 1);
        assert_eq!(Edge::new("a", "b", "CanRDP").with_weight(20).weight, 10);
        assert_eq!(Edge::new("a", "b", "CanRDP").with_weight(5).weight, 5);
    }

    #[test]
    fn liveness_respects_ttl() {
        let now = Utc::now();
        let live = Edge {
            expires_at: None,
            ..Edge::new("a", "b", "HasSession")
        };
        assert!(live.is_live(now));
        let expired = Edge {
            expires_at: Some(now - chrono::Duration::hours(1)),
            ..Edge::new("a", "b", "HasSession")
        };
        assert!(!expired.is_live(now));
        let future = Edge {
            expires_at: Some(now + chrono::Duration::hours(1)),
            ..Edge::new("a", "b", "HasSession")
        };
        assert!(future.is_live(now));
    }
}
