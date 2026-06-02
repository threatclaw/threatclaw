-- V73 (Phase 11d) — Normalise legacy `assets.ip_addresses` rows.
--
-- Background
-- ----------
-- Up to V72 the `upsert_asset` writer accepted IP strings verbatim. That
-- meant the UPSERT's UNION DISTINCT kept every variant the ingestion
-- pipeline produced :
--   `10.77.0.174:51788`, `10.77.0.174`, `10.77.0.174:51078`, `10.77.0.174:52862`
-- All four sit in the same `ip_addresses` array because the trailing
-- `:ephemeralPort` (typical of outbound flow logs) made them distinct
-- strings. The UI ended up displaying a meaningless cluster instead of
-- the single host IP.
--
-- Phase 11d patches the writer to canonicalise on-the-fly. This migration
-- catches up the existing rows in one pass : strip `:port`, strip
-- `/cidr`, drop empties, dedup.
--
-- Implementation note : we use a two-step UPDATE rather than a direct
-- expression because PostgreSQL's `regexp_replace` over `unnest()` needs
-- a subquery to fold back into an array, and we want to preserve order
-- where possible (first occurrence wins after dedup).

UPDATE assets
SET ip_addresses = sub.cleaned
FROM (
    SELECT
        a.id,
        ARRAY(
            SELECT DISTINCT ON (ip_clean) ip_clean
            FROM (
                SELECT
                    -- Strip leading/trailing whitespace then drop everything
                    -- after the first `:` (port) or `/` (mask).
                    regexp_replace(
                        regexp_replace(trim(ip_raw), '/.*$', ''),
                        ':.*$', ''
                    ) AS ip_clean
                FROM unnest(a.ip_addresses) AS ip_raw
            ) t
            WHERE ip_clean <> ''
        ) AS cleaned
    FROM assets a
    WHERE a.ip_addresses IS NOT NULL
      AND array_length(a.ip_addresses, 1) > 0
) AS sub
WHERE assets.id = sub.id
  AND assets.ip_addresses IS DISTINCT FROM sub.cleaned;

-- Sanity probe : surface how many rows were touched. Migrations don't
-- normally print, but this NOTICE is harmless and shows up in the
-- migration log so an operator can confirm the pass actually ran.
DO $$
DECLARE
    affected INT;
BEGIN
    SELECT COUNT(*) INTO affected
    FROM assets
    WHERE ip_addresses IS NOT NULL
      AND array_length(ip_addresses, 1) > 0;
    RAISE NOTICE 'V73 — assets with normalised ip_addresses : %', affected;
END $$;
