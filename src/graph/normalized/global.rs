//! Process-wide graph cache access. See ADR-045.

use super::{GraphCache, storage};
use deadpool_postgres::Pool;
use std::sync::Arc;
use tokio::sync::OnceCell;

static GRAPH_CACHE: OnceCell<Arc<GraphCache>> = OnceCell::const_new();

/// Initialize the cache at boot by loading the full snapshot from the
/// normalized tables. Safe to call concurrently — only the first
/// invocation runs the load.
pub async fn init(pool: &Pool) -> Result<Arc<GraphCache>, storage::GraphStorageError> {
    GRAPH_CACHE
        .get_or_try_init(|| async {
            let cache = Arc::new(GraphCache::new());
            let (nodes, edges) = storage::load_all(pool).await?;
            let node_count = nodes.len();
            let edge_count = edges.len();
            cache.rebuild(nodes, edges).await;
            tracing::info!(
                "GRAPH: cache initialized — {} nodes, {} edges",
                node_count,
                edge_count
            );
            Ok::<Arc<GraphCache>, storage::GraphStorageError>(cache)
        })
        .await
        .cloned()
}

/// Get the cache if already initialized. Returns `None` before the
/// boot-time `init` has completed, which lets callers degrade
/// gracefully (e.g. skip blast-radius computation instead of panicking).
pub fn get() -> Option<Arc<GraphCache>> {
    GRAPH_CACHE.get().cloned()
}
