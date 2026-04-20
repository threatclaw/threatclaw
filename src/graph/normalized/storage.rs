//! PostgreSQL persistence for normalized graph. See ADR-045.
//!
//! Read side uses the same deadpool-postgres pool exposed to the rest
//! of the crate. Write side is transactional per-skill (a skill that
//! re-syncs its edges should wrap its upserts in a single tx).

use super::edge::Edge;
use super::node::{Node, NodeId, NodeKind};
use chrono::{DateTime, Utc};
use deadpool_postgres::Pool;

#[derive(Debug, thiserror::Error)]
pub enum GraphStorageError {
    #[error("pool: {0}")]
    Pool(String),
    #[error("query: {0}")]
    Query(#[from] tokio_postgres::Error),
}

/// Full snapshot read — used at boot to warm the cache.
pub async fn load_all(pool: &Pool) -> Result<(Vec<Node>, Vec<Edge>), GraphStorageError> {
    let client = pool
        .get()
        .await
        .map_err(|e| GraphStorageError::Pool(e.to_string()))?;
    let node_rows = client
        .query(
            "SELECT id, kind, properties, criticality, fqdn, display_name,
                    source_skill, updated_at
               FROM graph_nodes",
            &[],
        )
        .await?;
    let mut nodes = Vec::with_capacity(node_rows.len());
    for row in node_rows {
        nodes.push(row_to_node(&row));
    }

    let edge_rows = client
        .query(
            "SELECT src_id, dst_id, kind, weight, properties,
                    source_skill, observed_at, expires_at
               FROM graph_edges
              WHERE expires_at IS NULL OR expires_at > NOW()",
            &[],
        )
        .await?;
    let mut edges = Vec::with_capacity(edge_rows.len());
    for row in edge_rows {
        edges.push(row_to_edge(&row));
    }

    Ok((nodes, edges))
}

/// Load a single node by id. Used by the NOTIFY refresher.
pub async fn load_node(pool: &Pool, id: &NodeId) -> Result<Option<Node>, GraphStorageError> {
    let client = pool
        .get()
        .await
        .map_err(|e| GraphStorageError::Pool(e.to_string()))?;
    let row = client
        .query_opt(
            "SELECT id, kind, properties, criticality, fqdn, display_name,
                    source_skill, updated_at
               FROM graph_nodes
              WHERE id = $1",
            &[&id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_node))
}

/// Upsert a node. Updates `updated_at` via trigger.
pub async fn upsert_node(pool: &Pool, node: &Node) -> Result<(), GraphStorageError> {
    let client = pool
        .get()
        .await
        .map_err(|e| GraphStorageError::Pool(e.to_string()))?;
    client
        .execute(
            "INSERT INTO graph_nodes
                 (id, kind, properties, criticality, fqdn, display_name, source_skill)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO UPDATE SET
                 kind = EXCLUDED.kind,
                 properties = EXCLUDED.properties,
                 criticality = EXCLUDED.criticality,
                 fqdn = EXCLUDED.fqdn,
                 display_name = EXCLUDED.display_name,
                 source_skill = EXCLUDED.source_skill",
            &[
                &node.id,
                &node.kind.as_str(),
                &node.properties,
                &(node.criticality as i16),
                &node.fqdn,
                &node.display_name,
                &node.source_skill,
            ],
        )
        .await?;
    Ok(())
}

/// Upsert an edge. `ON CONFLICT (src_id, dst_id, kind)` refreshes it.
pub async fn upsert_edge(pool: &Pool, edge: &Edge) -> Result<(), GraphStorageError> {
    let client = pool
        .get()
        .await
        .map_err(|e| GraphStorageError::Pool(e.to_string()))?;
    client
        .execute(
            "INSERT INTO graph_edges
                 (src_id, dst_id, kind, weight, properties, source_skill,
                  observed_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6,
                     COALESCE($7, NOW()), $8)
             ON CONFLICT (src_id, dst_id, kind) DO UPDATE SET
                 weight = EXCLUDED.weight,
                 properties = EXCLUDED.properties,
                 source_skill = EXCLUDED.source_skill,
                 observed_at = EXCLUDED.observed_at,
                 expires_at = EXCLUDED.expires_at",
            &[
                &edge.src,
                &edge.dst,
                &edge.kind,
                &(edge.weight as i16),
                &edge.properties,
                &edge.source_skill,
                &edge.observed_at,
                &edge.expires_at,
            ],
        )
        .await?;
    Ok(())
}

pub async fn delete_node(pool: &Pool, id: &NodeId) -> Result<(), GraphStorageError> {
    let client = pool
        .get()
        .await
        .map_err(|e| GraphStorageError::Pool(e.to_string()))?;
    client
        .execute("DELETE FROM graph_nodes WHERE id = $1", &[&id])
        .await?;
    Ok(())
}

fn row_to_node(row: &tokio_postgres::Row) -> Node {
    let kind_str: String = row.get("kind");
    Node {
        id: row.get("id"),
        kind: NodeKind::parse(&kind_str),
        properties: row
            .try_get("properties")
            .unwrap_or_else(|_| serde_json::Value::Null),
        criticality: row.get::<_, i16>("criticality") as u8,
        fqdn: row.get("fqdn"),
        display_name: row.get("display_name"),
        source_skill: row.get("source_skill"),
        updated_at: row.try_get::<_, DateTime<Utc>>("updated_at").ok(),
    }
}

fn row_to_edge(row: &tokio_postgres::Row) -> Edge {
    Edge {
        src: row.get("src_id"),
        dst: row.get("dst_id"),
        kind: row.get("kind"),
        weight: row.get::<_, i16>("weight") as u8,
        properties: row
            .try_get("properties")
            .unwrap_or_else(|_| serde_json::Value::Null),
        source_skill: row.get("source_skill"),
        observed_at: row.try_get::<_, DateTime<Utc>>("observed_at").ok(),
        expires_at: row.try_get::<_, DateTime<Utc>>("expires_at").ok(),
    }
}
