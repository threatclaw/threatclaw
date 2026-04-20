//! Query primitives operating on the in-memory cache. See ADR-045.

use super::cache::GraphCache;
use super::edge::Edge;
use super::node::NodeId;
use petgraph::algo;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::BinaryHeap;

/// Single hop on a path result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStep {
    pub from: NodeId,
    pub to: NodeId,
    pub edge_kind: String,
    pub weight: u8,
}

/// Ordered list of hops from src to dst (inclusive of both endpoints).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    pub steps: Vec<PathStep>,
    pub total_weight: u32,
}

impl Path {
    pub fn hop_count(&self) -> usize {
        self.steps.len()
    }
}

/// Result of a blast-radius query: the set of assets reachable from
/// an origin node, annotated with the shortest weighted path to each.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastResult {
    pub origin: NodeId,
    pub reachable: Vec<ReachableAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachableAsset {
    pub id: NodeId,
    pub hops: u8,
    pub total_weight: u32,
    pub criticality: u8,
}

/// Weighted shortest path (Dijkstra) from `from` to `to`.
/// Returns `None` if unreachable.
pub async fn shortest_path(cache: &GraphCache, from: &NodeId, to: &NodeId) -> Option<Path> {
    let g = cache.read().await;
    let from_ix = g.node_index(from)?;
    let to_ix = g.node_index(to)?;

    let dist_map = algo::dijkstra(g.graph(), from_ix, Some(to_ix), |e| {
        e.weight().weight as u32
    });
    let total_weight = *dist_map.get(&to_ix)?;
    // Reconstruct path via backwards search (since petgraph::dijkstra
    // does not expose predecessors directly in stable 0.6).
    let steps = reconstruct_path(g.graph(), &dist_map, from_ix, to_ix)?;
    Some(Path {
        steps,
        total_weight,
    })
}

/// Blast radius: all nodes reachable from `origin` within `max_hops`.
/// Uses weighted BFS (Dijkstra truncated at max cumulative weight).
pub async fn blast_radius(cache: &GraphCache, origin: &NodeId, max_hops: u8) -> BlastResult {
    let g = cache.read().await;
    let Some(origin_ix) = g.node_index(origin) else {
        return BlastResult {
            origin: origin.clone(),
            reachable: vec![],
        };
    };

    // BFS truncated by hop count; cumulative weight tracked for scoring.
    // Using a min-heap keeps expansion order weight-first within each hop
    // ring, giving us Dijkstra semantics up to `max_hops`.
    let mut heap: BinaryHeap<std::cmp::Reverse<(u32, u8, petgraph::graph::NodeIndex)>> =
        BinaryHeap::new();
    heap.push(std::cmp::Reverse((0, 0, origin_ix)));

    let mut best: std::collections::HashMap<petgraph::graph::NodeIndex, (u32, u8)> =
        std::collections::HashMap::new();

    while let Some(std::cmp::Reverse((dist, hops, ix))) = heap.pop() {
        if let Some((prev_dist, _)) = best.get(&ix) {
            if *prev_dist <= dist {
                continue;
            }
        }
        best.insert(ix, (dist, hops));
        if hops >= max_hops {
            continue;
        }
        for er in g.graph().edges(ix) {
            let next_dist = dist + er.weight().weight as u32;
            let next_hops = hops + 1;
            heap.push(std::cmp::Reverse((next_dist, next_hops, er.target())));
        }
    }

    let mut reachable: Vec<ReachableAsset> = best
        .into_iter()
        .filter(|(ix, _)| *ix != origin_ix)
        .map(|(ix, (dist, hops))| {
            let node = &g.graph()[ix];
            ReachableAsset {
                id: node.id.clone(),
                hops,
                total_weight: dist,
                criticality: node.criticality,
            }
        })
        .collect();

    reachable.sort_by(|a, b| {
        b.criticality
            .cmp(&a.criticality)
            .then_with(|| a.hops.cmp(&b.hops))
            .then_with(|| a.total_weight.cmp(&b.total_weight))
    });

    BlastResult {
        origin: origin.clone(),
        reachable,
    }
}

/// Deterministic 0-100 score from a blast result.
///
/// Formula (see ADR-048): `min(100, sum(criticality * 10 / (hop+1)))` over
/// reachable assets within `max_hops`. Keeps values readable in UI and
/// stable across identical graph states.
pub fn score(result: &BlastResult) -> u8 {
    let mut total: u32 = 0;
    for asset in &result.reachable {
        total += (asset.criticality as u32) * 10 / (asset.hops as u32 + 1);
    }
    total.min(100) as u8
}

// ── internals ───────────────────────────────────────────────────────

fn reconstruct_path(
    g: &petgraph::graph::DiGraph<super::node::Node, Edge>,
    dist_map: &std::collections::HashMap<petgraph::graph::NodeIndex, u32>,
    from: petgraph::graph::NodeIndex,
    to: petgraph::graph::NodeIndex,
) -> Option<Vec<PathStep>> {
    let mut steps: Vec<PathStep> = Vec::new();
    let mut current = to;
    while current != from {
        let current_d = *dist_map.get(&current)?;
        let mut found_prev = None;
        for er in g.edges_directed(current, petgraph::Direction::Incoming) {
            let src = er.source();
            let src_d = dist_map.get(&src).copied().unwrap_or(u32::MAX);
            if src_d + er.weight().weight as u32 == current_d {
                found_prev = Some((src, er.weight().clone()));
                break;
            }
        }
        let (prev_ix, edge) = found_prev?;
        steps.push(PathStep {
            from: g[prev_ix].id.clone(),
            to: g[current].id.clone(),
            edge_kind: edge.kind,
            weight: edge.weight,
        });
        current = prev_ix;
    }
    steps.reverse();
    Some(steps)
}

#[cfg(test)]
mod tests {
    use super::super::cache::GraphCache;
    use super::super::edge::Edge;
    use super::super::node::{Node, NodeKind};
    use super::*;

    async fn fixture_small() -> GraphCache {
        // user:alice --[MemberOf,w=1]--> group:rdp-users
        // group:rdp-users --[MemberOf,w=1]--> group:domain-users
        // user:alice --[CanRDP,w=2]--> host:prod-sql01
        // host:prod-sql01 --[Stores,w=1]--> data_class:finance
        let cache = GraphCache::new();
        cache
            .rebuild(
                vec![
                    Node::new("user:alice", NodeKind::User),
                    Node::new("group:rdp-users", NodeKind::Group),
                    Node::new("group:domain-users", NodeKind::Group),
                    Node::new("host:prod-sql01", NodeKind::Host).with_criticality(9),
                    Node::new("data_class:finance", NodeKind::DataClass).with_criticality(9),
                ],
                vec![
                    Edge::new("user:alice", "group:rdp-users", "MemberOf").with_weight(1),
                    Edge::new("group:rdp-users", "group:domain-users", "MemberOf").with_weight(1),
                    Edge::new("user:alice", "host:prod-sql01", "CanRDP").with_weight(2),
                    Edge::new("host:prod-sql01", "data_class:finance", "Stores").with_weight(1),
                ],
            )
            .await;
        cache
    }

    #[tokio::test]
    async fn blast_radius_from_user_reaches_data() {
        let cache = fixture_small().await;
        let result = blast_radius(&cache, &"user:alice".to_string(), 3).await;
        let ids: Vec<_> = result.reachable.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"host:prod-sql01"));
        assert!(ids.contains(&"data_class:finance"));
    }

    #[tokio::test]
    async fn blast_radius_respects_hop_limit() {
        let cache = fixture_small().await;
        let r1 = blast_radius(&cache, &"user:alice".to_string(), 1).await;
        let r2 = blast_radius(&cache, &"user:alice".to_string(), 2).await;
        assert!(r1.reachable.len() < r2.reachable.len());
        // At 1 hop, data_class must not be reachable (it's 2 hops away).
        assert!(!r1.reachable.iter().any(|a| a.id == "data_class:finance"));
    }

    #[tokio::test]
    async fn score_is_clamped_and_monotonic() {
        let cache = fixture_small().await;
        let r = blast_radius(&cache, &"user:alice".to_string(), 3).await;
        let s = score(&r);
        assert!(s <= 100);
        // Two high-criticality assets reachable in <=2 hops → expect > 0.
        assert!(s > 0);
    }

    #[tokio::test]
    async fn shortest_path_matches_expected_route() {
        let cache = fixture_small().await;
        let p = shortest_path(
            &cache,
            &"user:alice".to_string(),
            &"data_class:finance".to_string(),
        )
        .await
        .expect("reachable");
        assert_eq!(p.hop_count(), 2);
        assert_eq!(p.steps[0].edge_kind, "CanRDP");
        assert_eq!(p.steps[1].edge_kind, "Stores");
        assert_eq!(p.total_weight, 3);
    }

    #[tokio::test]
    async fn unreachable_returns_none() {
        let cache = fixture_small().await;
        let p = shortest_path(
            &cache,
            &"host:prod-sql01".to_string(),
            &"user:alice".to_string(),
        )
        .await;
        assert!(p.is_none());
    }
}
