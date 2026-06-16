-- migrations/V84__dedup_observed_assets_by_short_hostname.sql
--
-- Merge auto-enrolled assets that landed twice in the inventory because
-- the syslog forwarder (fluent-bit / rsyslog) and the osquery endpoint
-- agent normalised the hostname differently. fluent-bit typically
-- forwards the FQDN reported by the sender (`web-01.dexun.internal`),
-- the osquery agent the short hostname (`web-01`). Before the v1.0.41
-- find_asset_by_hostname lookup learned to match across both shapes,
-- the second enrolment path always created a fresh asset row instead
-- of converging on the existing one.
--
-- This migration normalises the existing duplicates the same way the
-- runtime lookup does now. Only auto-enrolled rows (tags contains
-- 'observed') are touched: operator-curated assets are never merged
-- automatically. The oldest row in each duplicate group becomes the
-- canonical, every cross-table reference is redirected onto it, and
-- the redundant rows are then removed.
--
-- Idempotent: re-running V84 on a clean database is a no-op because no
-- two 'observed' assets remain that share a short hostname.

BEGIN;

CREATE TEMP TABLE alias_map ON COMMIT DROP AS
WITH ranked AS (
    SELECT
        LOWER(SPLIT_PART(COALESCE(NULLIF(hostname, ''), name), '.', 1)) AS short_key,
        id,
        created_at,
        ROW_NUMBER() OVER (
            PARTITION BY LOWER(SPLIT_PART(COALESCE(NULLIF(hostname, ''), name), '.', 1))
            ORDER BY created_at ASC, id ASC
        ) AS rn
    FROM assets
    WHERE 'observed' = ANY(tags)
      AND COALESCE(NULLIF(hostname, ''), name) IS NOT NULL
      AND COALESCE(NULLIF(hostname, ''), name) <> ''
),
canonical AS (
    SELECT short_key, id AS canonical_id FROM ranked WHERE rn = 1
)
SELECT r.id AS alias_id, c.canonical_id
FROM ranked r
JOIN canonical c USING (short_key)
WHERE r.rn > 1;

-- Redirect every cross-table reference from the alias rows to the
-- canonical row. The six tables below are every column in the schema
-- whose value carries an `assets.id` payload (FK or text).

UPDATE findings SET asset = m.canonical_id
FROM alias_map m WHERE findings.asset = m.alias_id;

UPDATE graph_executions SET asset_id = m.canonical_id
FROM alias_map m WHERE graph_executions.asset_id = m.alias_id;

UPDATE incidents SET asset = m.canonical_id
FROM alias_map m WHERE incidents.asset = m.alias_id;

UPDATE ml_scores SET asset_id = m.canonical_id
FROM alias_map m WHERE ml_scores.asset_id = m.alias_id;

UPDATE scan_queue SET asset_id = m.canonical_id
FROM alias_map m WHERE scan_queue.asset_id = m.alias_id;

-- sentinel_entities.asset_id is typed UUID while assets.id is text,
-- so the column does not actually carry an assets.id value end-to-end
-- (the Sentinel connector populates it with its own GUID). Skip it.

-- merge_aliases is dropped via ON DELETE CASCADE when the duplicate
-- asset row is removed below; no explicit rewrite is necessary.

-- Finally drop the duplicate asset rows. Any residual merge_aliases
-- rows that pointed to them are removed via ON DELETE CASCADE.
DELETE FROM assets WHERE id IN (SELECT alias_id FROM alias_map);

DO $$
DECLARE merged_count INT;
BEGIN
    SELECT COUNT(*) INTO merged_count FROM alias_map;
    IF merged_count > 0 THEN
        RAISE NOTICE 'V84: merged % observed-asset duplicate(s) into canonical rows', merged_count;
    END IF;
END $$;

COMMIT;
