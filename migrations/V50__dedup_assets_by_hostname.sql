-- Dedup assets that share the same hostname (case-insensitive) — historical
-- duplicates from Wazuh agent re-enrollments that predated hostname-based
-- matching in asset_resolution. Keeps the most recently seen asset per
-- hostname and drops the rest.
--
-- Safe because:
--   - sigma_alerts references assets only by hostname text (no FK on asset.id)
--   - findings.asset is text, not FK
--   - incidents.asset is text, not FK
--   - no FK constraint points at assets.id (verified against pg_constraint)
--
-- Apache AGE graph nodes are not touched here: the next intelligence_engine
-- sync_graph_from_db cycle rebuilds the graph from the postgres assets that
-- survive this DELETE, dropping references to the removed ids.

WITH ranked AS (
  SELECT
    id,
    LOWER(TRIM(hostname)) AS norm_hostname,
    last_seen,
    ROW_NUMBER() OVER (
      PARTITION BY LOWER(TRIM(hostname))
      ORDER BY last_seen DESC NULLS LAST, id
    ) AS rn
  FROM assets
  WHERE hostname IS NOT NULL AND TRIM(hostname) <> ''
)
DELETE FROM assets
WHERE id IN (
  SELECT id FROM ranked WHERE rn > 1
);
