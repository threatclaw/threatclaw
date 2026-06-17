-- migrations/V85__dedup_assets_by_hostname_observed.sql
--
-- Merge auto-enrolled assets that landed twice in the inventory due
-- to the asset_resolution path not consulting PostgreSQL before
-- mining a new id. Symptom on the operator dashboard: two rows
-- with the same `name`/`hostname` (e.g. both `W10-1`) but
-- different ids — one `osquery-observed-W10-1` (from the observe
-- -and-enrol pass in connectors/osquery.rs) and one `w10-1` (from
-- generate_asset_id() in graph/asset_resolution.rs).
--
-- v1.0.43 closes that hole in the code path; this migration cleans
-- up rows that already exist on operators upgrading from <= v1.0.42.
--
-- Safety constraints:
--   1. Only merge when at least one row of the pair carries the
--      `observed` tag. Two operator-declared assets that happen to
--      share a hostname are never collapsed.
--   2. The oldest row in each group becomes canonical.
--   3. Cross-table references are redirected onto the canonical id
--      before the alias row is deleted.
--   4. Smart field merge: nullable scalar fields take the canonical
--      value when present and fall back to the alias value otherwise.
--      Array fields (ip_addresses, tags) are union de-duplicated.
--   5. Idempotent: a re-run on a clean database is a no-op.

BEGIN;

CREATE TEMP TABLE alias_map ON COMMIT DROP AS
WITH ranked AS (
    SELECT
        LOWER(TRIM(COALESCE(NULLIF(hostname, ''), name))) AS key,
        id,
        tags,
        created_at,
        ROW_NUMBER() OVER (
            PARTITION BY LOWER(TRIM(COALESCE(NULLIF(hostname, ''), name)))
            ORDER BY created_at ASC, id ASC
        ) AS rn
    FROM assets
    WHERE COALESCE(NULLIF(hostname, ''), name) IS NOT NULL
      AND COALESCE(NULLIF(hostname, ''), name) <> ''
),
canonical AS (
    SELECT key, id AS canonical_id FROM ranked WHERE rn = 1
),
groups_with_observed AS (
    -- Constraint #1: only collapse groups where at least one row was
    -- auto-enrolled. Two operator-declared assets sharing a hostname
    -- are out of scope.
    SELECT DISTINCT r.key
    FROM ranked r
    WHERE 'observed' = ANY(r.tags)
)
SELECT r.id AS alias_id, c.canonical_id
FROM ranked r
JOIN canonical c USING (key)
JOIN groups_with_observed g USING (key)
WHERE r.rn > 1;

-- Redirect cross-table references onto the canonical row before
-- deleting the alias.

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

-- Smart-merge field-level info from the aliases into the canonical
-- row. The two enrolment paths populate different fields (osquery
-- agent ships os/fqdn/mac; asset_resolution.rs ships ip discovery).
-- Scalars: canonical wins if non-empty, else first non-empty alias.
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

-- Finally drop the alias rows. Any residual merge_aliases rows are
-- removed via ON DELETE CASCADE (V68).
DELETE FROM assets WHERE id IN (SELECT alias_id FROM alias_map);

DO $$
DECLARE merged_count INT;
BEGIN
    SELECT COUNT(*) INTO merged_count FROM alias_map;
    IF merged_count > 0 THEN
        RAISE NOTICE 'V85: merged % asset duplicate(s) sharing a hostname into canonical rows', merged_count;
    END IF;
END $$;

COMMIT;
