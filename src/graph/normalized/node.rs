//! Graph node types. See ADR-045 §schéma.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Node identifier — stable across refreshes.
///
/// Convention: `"<kind>:<stable-value>"` (e.g. `"host:prod-sql01"`,
/// `"user:alice@corp.fr"`). Keep it deterministic so two skills that
/// discover the same asset collapse onto the same node.
pub type NodeId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    User,
    Host,
    Group,
    Role,
    App,
    Database,
    Network,
    DataClass,
    Bucket,
    Vm,
    Other,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Host => "host",
            Self::Group => "group",
            Self::Role => "role",
            Self::App => "app",
            Self::Database => "database",
            Self::Network => "network",
            Self::DataClass => "data_class",
            Self::Bucket => "bucket",
            Self::Vm => "vm",
            Self::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "user" => Self::User,
            "host" => Self::Host,
            "group" => Self::Group,
            "role" => Self::Role,
            "app" => Self::App,
            "database" => Self::Database,
            "network" => Self::Network,
            "data_class" => Self::DataClass,
            "bucket" => Self::Bucket,
            "vm" => Self::Vm,
            _ => Self::Other,
        }
    }
}

/// Graph node — row projection of `graph_nodes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
    #[serde(default)]
    pub properties: serde_json::Value,
    #[serde(default)]
    pub criticality: u8,
    pub fqdn: Option<String>,
    pub display_name: Option<String>,
    pub source_skill: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds_option", default)]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Node {
    pub fn new(id: impl Into<NodeId>, kind: NodeKind) -> Self {
        Self {
            id: id.into(),
            kind,
            properties: serde_json::Value::Object(Default::default()),
            criticality: 0,
            fqdn: None,
            display_name: None,
            source_skill: None,
            updated_at: None,
        }
    }

    pub fn label(&self) -> Cow<'_, str> {
        if let Some(n) = &self.display_name {
            Cow::Borrowed(n)
        } else if let Some(f) = &self.fqdn {
            Cow::Borrowed(f)
        } else {
            Cow::Borrowed(&self.id)
        }
    }

    pub fn with_criticality(mut self, c: u8) -> Self {
        self.criticality = c.min(10);
        self
    }

    pub fn with_property(mut self, key: &str, value: serde_json::Value) -> Self {
        if let serde_json::Value::Object(m) = &mut self.properties {
            m.insert(key.to_string(), value);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_prefers_display_name() {
        let n = Node {
            display_name: Some("Alice".into()),
            fqdn: Some("alice.corp.fr".into()),
            ..Node::new("user:alice", NodeKind::User)
        };
        assert_eq!(n.label(), "Alice");
    }

    #[test]
    fn label_falls_back_to_fqdn_then_id() {
        let n = Node {
            fqdn: Some("prod-sql01.corp.fr".into()),
            ..Node::new("host:prod-sql01", NodeKind::Host)
        };
        assert_eq!(n.label(), "prod-sql01.corp.fr");
        let n2 = Node::new("other:foo", NodeKind::Other);
        assert_eq!(n2.label(), "other:foo");
    }

    #[test]
    fn criticality_is_clamped() {
        let n = Node::new("user:x", NodeKind::User).with_criticality(42);
        assert_eq!(n.criticality, 10);
    }

    #[test]
    fn kind_roundtrip() {
        for k in [
            NodeKind::User,
            NodeKind::Host,
            NodeKind::Group,
            NodeKind::Role,
            NodeKind::App,
            NodeKind::Database,
            NodeKind::Network,
            NodeKind::DataClass,
            NodeKind::Bucket,
            NodeKind::Vm,
            NodeKind::Other,
        ] {
            assert_eq!(NodeKind::parse(k.as_str()), k);
        }
    }
}
