-- Phase 7e of the 2026-04-28 pricing pivot — manual merge UI and
-- single-toggle exclusion (billing + monitoring at once).
--
-- Two needs that surfaced after V67 went LIVE:
--
-- 1. The Proxmox connector reports VMs without MAC/IP, so the same
--    physical machine can appear twice in /assets (once via Proxmox,
--    once via DHCP / firewall / Wazuh). V68/A enriches the connector
--    going forward, but for legacy duplicates we need a manual merge.
--
-- 2. Operators sometimes need to retire an asset from both the
--    billable count AND the surveillance pipeline (honeypot they
--    don't want to monitor anymore, decommissioned server still in
--    AD, third-party box visible on the network they don't own).
--    A single 'excluded' toggle handles both at once.
--
-- ─── Manual merge — alias table ────────────────────────────────────
--
-- When the operator selects 2+ rows in /assets and clicks "Fusionner",
-- we pick a canonical row (the one with the most identifiers) and
-- mark the others as aliases of it via this table. The
-- asset_resolution pipeline consults the table on every upsert and
-- redirects writes to the canonical row instead of recreating the
-- alias.
--
-- We keep the alias rows in `assets` (with status='merged') rather
-- than DELETE them so:
--   - findings/alerts that referenced the alias still work
--   - the operator can undo the merge within 30 days
--   - audit history is preserved

CREATE TABLE IF NOT EXISTS merge_aliases (
    alias_id     TEXT PRIMARY KEY,
    canonical_id TEXT NOT NULL,
    merged_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    merged_by    TEXT NOT NULL DEFAULT 'system',
    reason       TEXT NOT NULL DEFAULT '',
    -- Soft-delete: NULL = active merge, set when the operator unmerges
    -- (within the 30-day undo window).
    unmerged_at  TIMESTAMPTZ,

    FOREIGN KEY (alias_id)     REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (canonical_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_merge_aliases_canonical
    ON merge_aliases(canonical_id) WHERE unmerged_at IS NULL;

-- Add a 'merged' value to the assets.status conceptual enum (no CHECK
-- constraint, validated in code) so we can hide alias rows from the
-- default /assets listing.

-- ─── Single exclusion toggle ───────────────────────────────────────
--
-- excluded=true means BOTH:
--   - billable filter excludes this row (count untouched)
--   - the touch trigger and the sigma_engine / finding pipeline
--     skip events targeting this row (no new monitoring activity)
--
-- exclusion_until is set 90 days ahead by default so a forgotten
-- exclusion automatically lapses and the asset returns to normal
-- billing+monitoring. The reclassify cron (see src/agent/billing.rs)
-- expires excluded rows past their `exclusion_until`.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS excluded BOOLEAN
    NOT NULL DEFAULT false;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS exclusion_reason TEXT
    NOT NULL DEFAULT '';
ALTER TABLE assets ADD COLUMN IF NOT EXISTS exclusion_until TIMESTAMPTZ;
ALTER TABLE assets ADD COLUMN IF NOT EXISTS exclusion_by TEXT
    NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_assets_excluded
    ON assets(excluded) WHERE excluded = true;

-- The V67 touch trigger now also short-circuits when the asset is
-- excluded — no last_event_at update, no inventory_status promotion,
-- nothing. Effectively cuts the asset out of the entire detection
-- pipeline at the database boundary.

CREATE OR REPLACE FUNCTION tc_touch_asset_last_event() RETURNS trigger AS $$
DECLARE
    target_id   TEXT;
    target_host TEXT;
    target_ip   TEXT;
    today_str   TEXT := to_char(NOW(), 'YYYY-MM-DD');
BEGIN
    IF TG_TABLE_NAME = 'findings' THEN
        target_id := NEW.asset;
    ELSIF TG_TABLE_NAME = 'sigma_alerts' THEN
        target_host := NEW.hostname;
        target_ip   := NEW.source_ip::text;
    ELSIF TG_TABLE_NAME = 'firewall_events' THEN
        target_ip   := NEW.dst_ip::text;
    END IF;

    UPDATE assets
       SET last_event_at = NOW(),
           billable_status = CASE
               WHEN billable_status IN ('discovered','inactive') THEN 'monitored'
               ELSE billable_status
           END,
           inventory_status = CASE
               WHEN inventory_status = 'inactive' THEN 'observed_transient'
               ELSE inventory_status
           END,
           seen_days_30d = (
               SELECT array_agg(d ORDER BY d DESC) FROM (
                   SELECT DISTINCT d
                     FROM unnest(
                              CASE WHEN today_str = ANY(seen_days_30d)
                                   THEN seen_days_30d
                                   ELSE today_str || seen_days_30d
                              END
                          ) AS d
                     ORDER BY d DESC
                     LIMIT 30
               ) trimmed
           ),
           distinct_days_seen_30d = LEAST(30, COALESCE(array_length(seen_days_30d, 1), 0) + 1)
     WHERE excluded = false   -- V68: skip touched events on excluded assets
       AND (id = target_id
            OR (target_host IS NOT NULL AND lower(hostname) = lower(target_host))
            OR (target_ip IS NOT NULL AND target_ip = ANY(ip_addresses)));

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
