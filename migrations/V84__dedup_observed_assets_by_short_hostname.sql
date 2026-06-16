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

-- Smart-merge field-level info from the aliases into the canonical
-- row before deletion. The osquery agent populates fields that the
-- syslog path does not (os hint, fqdn, mac), so the surviving row
-- carries the union of the available facts. Scalars: canonical value
-- wins if non-empty, otherwise the first non-empty alias value.
-- Arrays (ip_addresses, tags): union de-duplicated.
WITH agg AS (
    SELECT
        m.canonical_id,
        MAX(NULLIF(a.os, '')) AS alias_os,
        MAX(NULLIF(a.fqdn, '')) AS alias_fqdn,
        MAX(NULLIF(a.mac_address, '')) AS alias_mac_address,
        MAX(NULLIF(a.mac_vendor, '')) AS alias_mac_vendor,
        MAX(NULLIF(a.location, '')) AS alias_location,
        MAX(NULLIF(a.owner, '')) AS alias_owner,
        MAX(NULLIF(a.role, '')) AS alias_role,
        MAX(NULLIF(a.subcategory, '')) AS alias_subcategory,
        MAX(NULLIF(a.url, '')) AS alias_url,
        ARRAY(
            SELECT DISTINCT v
            FROM alias_map m2
            JOIN assets a2 ON a2.id = m2.alias_id
            CROSS JOIN LATERAL unnest(COALESCE(a2.ip_addresses, ARRAY[]::text[])) AS v
            WHERE m2.canonical_id = m.canonical_id AND v IS NOT NULL AND v <> ''
        ) AS alias_ips,
        ARRAY(
            SELECT DISTINCT v
            FROM alias_map m3
            JOIN assets a3 ON a3.id = m3.alias_id
            CROSS JOIN LATERAL unnest(COALESCE(a3.tags, ARRAY[]::text[])) AS v
            WHERE m3.canonical_id = m.canonical_id AND v IS NOT NULL AND v <> ''
        ) AS alias_tags
    FROM alias_map m
    JOIN assets a ON a.id = m.alias_id
    GROUP BY m.canonical_id
)
UPDATE assets SET
    os          = COALESCE(NULLIF(assets.os, ''),          agg.alias_os),
    fqdn        = COALESCE(NULLIF(assets.fqdn, ''),        agg.alias_fqdn),
    mac_address = COALESCE(NULLIF(assets.mac_address, ''), agg.alias_mac_address),
    mac_vendor  = COALESCE(NULLIF(assets.mac_vendor, ''),  agg.alias_mac_vendor),
    location    = COALESCE(NULLIF(assets.location, ''),    agg.alias_location),
    owner       = COALESCE(NULLIF(assets.owner, ''),       agg.alias_owner),
    role        = COALESCE(NULLIF(assets.role, ''),        agg.alias_role),
    subcategory = COALESCE(NULLIF(assets.subcategory, ''), agg.alias_subcategory),
    url         = COALESCE(NULLIF(assets.url, ''),         agg.alias_url),
    ip_addresses = ARRAY(
        SELECT DISTINCT v
        FROM (
            SELECT unnest(COALESCE(assets.ip_addresses, ARRAY[]::text[])) AS v
            UNION ALL
            SELECT unnest(agg.alias_ips)
        ) t
        WHERE v IS NOT NULL AND v <> ''
    ),
    tags = ARRAY(
        SELECT DISTINCT v
        FROM (
            SELECT unnest(COALESCE(assets.tags, ARRAY[]::text[])) AS v
            UNION ALL
            SELECT unnest(agg.alias_tags)
        ) t
        WHERE v IS NOT NULL AND v <> ''
    )
FROM agg WHERE assets.id = agg.canonical_id;

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
