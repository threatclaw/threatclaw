//! In-memory petgraph cache. See ADR-045.

use super::edge::Edge;
use super::node::{Node, NodeId};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::HashMap;
use tokio::sync::{RwLock, RwLockReadGuard};

/// Shared read guard exposing both the petgraph `DiGraph` and the
/// id → index map. Keeping both under the same lock makes queries
/// consistent without copying.
pub struct CacheRead<'a> {
    inner: RwLockReadGuard<'a, Inner>,
}

impl<'a> CacheRead<'a> {
    pub fn graph(&self) -> &DiGraph<Node, Edge> {
        &self.inner.graph
    }

    pub fn node_index(&self, id: &NodeId) -> Option<NodeIndex> {
        self.inner.index.get(id).copied()
    }

    pub fn node(&self, id: &NodeId) -> Option<&Node> {
        let ix = self.node_index(id)?;
        Some(&self.inner.graph[ix])
    }

    pub fn node_count(&self) -> usize {
        self.inner.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.inner.graph.edge_count()
    }
}

/// Thread-safe in-memory graph cache.
///
/// Built from the normalized tables, refreshed on `LISTEN graph_update`.
/// See `storage::spawn_cache_refresher` for the refresh loop.
pub struct GraphCache {
    inner: RwLock<Inner>,
}

struct Inner {
    graph: DiGraph<Node, Edge>,
    index: HashMap<NodeId, NodeIndex>,
}

impl Default for GraphCache {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                graph: DiGraph::new(),
                index: HashMap::new(),
            }),
        }
    }

    /// Full rebuild — replaces the entire cache atomically.
    /// Used at boot and after bulk updates.
    pub async fn rebuild(&self, nodes: Vec<Node>, edges: Vec<Edge>) {
        let mut graph = DiGraph::<Node, Edge>::with_capacity(nodes.len(), edges.len());
        let mut index = HashMap::with_capacity(nodes.len());

        for node in nodes {
            let id = node.id.clone();
            let ix = graph.add_node(node);
            index.insert(id, ix);
        }
        for edge in edges {
            let Some(&src_ix) = index.get(&edge.src) else {
                continue;
            };
            let Some(&dst_ix) = index.get(&edge.dst) else {
                continue;
            };
            graph.add_edge(src_ix, dst_ix, edge);
        }

        let mut inner = self.inner.write().await;
        inner.graph = graph;
        inner.index = index;
    }

    /// Apply an incremental update. Used by the NOTIFY-driven refresher.
    pub async fn upsert_node(&self, node: Node) {
        let mut inner = self.inner.write().await;
        if let Some(&ix) = inner.index.get(&node.id) {
            inner.graph[ix] = node;
        } else {
            let id = node.id.clone();
            let ix = inner.graph.add_node(node);
            inner.index.insert(id, ix);
        }
    }

    pub async fn delete_node(&self, id: &NodeId) {
        let mut inner = self.inner.write().await;
        if let Some(ix) = inner.index.remove(id) {
            // Collect edges to preserve for remaining nodes; remove_node
            // invalidates indices so we rebuild the index map after.
            inner.graph.remove_node(ix);
            // Rebuild index since node indices shift after removal.
            let mut new_index = HashMap::with_capacity(inner.graph.node_count());
            for ix in inner.graph.node_indices() {
                new_index.insert(inner.graph[ix].id.clone(), ix);
            }
            inner.index = new_index;
        }
    }

    pub async fn upsert_edge(&self, edge: Edge) {
        let mut inner = self.inner.write().await;
        let Some(&src_ix) = inner.index.get(&edge.src) else {
            return;
        };
        let Some(&dst_ix) = inner.index.get(&edge.dst) else {
            return;
        };
        // Replace existing edge of same kind if present.
        if let Some(ex_ix) = inner
            .graph
            .edges_connecting(src_ix, dst_ix)
            .find(|e| e.weight().kind == edge.kind)
            .map(|e| e.id())
        {
            inner.graph.remove_edge(ex_ix);
        }
        inner.graph.add_edge(src_ix, dst_ix, edge);
    }

    pub async fn read(&self) -> CacheRead<'_> {
        CacheRead {
            inner: self.inner.read().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::edge::Edge;
    use super::super::node::{Node, NodeKind};
    use super::*;

    #[tokio::test]
    async fn rebuild_inserts_nodes_and_edges() {
        let cache = GraphCache::new();
        cache
            .rebuild(
                vec![
                    Node::new("user:a", NodeKind::User),
                    Node::new("host:h", NodeKind::Host),
                ],
                vec![Edge::new("user:a", "host:h", "CanRDP").with_weight(2)],
            )
            .await;
        let g = cache.read().await;
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[tokio::test]
    async fn upsert_node_replaces() {
        let cache = GraphCache::new();
        cache
            .upsert_node(Node::new("user:a", NodeKind::User).with_criticality(3))
            .await;
        cache
            .upsert_node(Node::new("user:a", NodeKind::User).with_criticality(7))
            .await;
        let g = cache.read().await;
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.node(&"user:a".to_string()).unwrap().criticality, 7);
    }

    #[tokio::test]
    async fn delete_node_rebuilds_index() {
        let cache = GraphCache::new();
        cache
            .rebuild(
                vec![
                    Node::new("user:a", NodeKind::User),
                    Node::new("user:b", NodeKind::User),
                    Node::new("user:c", NodeKind::User),
                ],
                vec![],
            )
            .await;
        cache.delete_node(&"user:b".to_string()).await;
        let g = cache.read().await;
        assert_eq!(g.node_count(), 2);
        assert!(g.node_index(&"user:b".to_string()).is_none());
        assert!(g.node_index(&"user:a".to_string()).is_some());
        assert!(g.node_index(&"user:c".to_string()).is_some());
    }

    #[tokio::test]
    async fn edges_dropped_for_unknown_nodes() {
        let cache = GraphCache::new();
        cache
            .rebuild(
                vec![Node::new("user:a", NodeKind::User)],
                vec![
                    Edge::new("user:a", "host:does-not-exist", "CanRDP"),
                    Edge::new("host:also-nope", "user:a", "HasSession"),
                ],
            )
            .await;
        let g = cache.read().await;
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.edge_count(), 0);
    }

    #[tokio::test]
    async fn upsert_edge_replaces_same_kind() {
        let cache = GraphCache::new();
        cache
            .rebuild(
                vec![
                    Node::new("user:a", NodeKind::User),
                    Node::new("host:h", NodeKind::Host),
                ],
                vec![],
            )
            .await;
        cache
            .upsert_edge(Edge::new("user:a", "host:h", "CanRDP").with_weight(5))
            .await;
        cache
            .upsert_edge(Edge::new("user:a", "host:h", "CanRDP").with_weight(2))
            .await;
        let g = cache.read().await;
        assert_eq!(g.edge_count(), 1);
    }
}
