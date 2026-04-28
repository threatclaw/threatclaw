-- Phase A.2 of the 2026-04-28 pricing pivot (see internal/PRICING_PIVOT_2026-04-28.md).
--
-- Adds the columns the new asset-count-based pricing model needs:
--
--   billable_status       lifecycle marker: discovered → monitored → inactive
--                         a row only counts toward the tier limit when status
--                         is 'monitored'
--   dedup_confidence      'high'    : matched by MAC, definitely the same device
--                         'medium'  : matched by hostname / FQDN
--                         'uncertain' : only IP-based, may be DHCP rotation
--                         (the asset_resolution module already computes this
--                         in-memory; this column persists it so the billable
--                         filter can exclude uncertain rows)
--   last_event_at         most recent finding/sigma_alert/firewall_event that
--                         targeted this asset. Maintained by triggers below.
--                         Drives the "active in last 30 days" rule.
--   demo                  true for rows inserted by the setup wizard demo data
--                         path. Always excluded from billable count.
--
-- The new pricing tiers:
--   Free       → 0-50  monitored assets
--   Starter    → 51-200
--   Pro        → 201-600
--   Business   → 601-1500
--   Enterprise → 1500+ or MSSP

ALTER TABLE assets ADD COLUMN IF NOT EXISTS billable_status TEXT
    NOT NULL DEFAULT 'discovered';
-- Allowed values enforced in code, not as a CHECK constraint, so future
-- statuses ('grace', 'flagged', etc.) don't need a migration.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS dedup_confidence TEXT
    NOT NULL DEFAULT 'medium';

ALTER TABLE assets ADD COLUMN IF NOT EXISTS last_event_at TIMESTAMPTZ;

ALTER TABLE assets ADD COLUMN IF NOT EXISTS demo BOOLEAN
    NOT NULL DEFAULT false;

-- Index used by count_billable_assets and the reclassify cron.
CREATE INDEX IF NOT EXISTS idx_assets_billable_filter
    ON assets (billable_status, last_event_at)
    WHERE demo = false;

-- Triggers — keep last_event_at fresh as findings / sigma_alerts / firewall_events
-- arrive. We match on the assets.id directly (the dispatcher resolves the
-- finding's `asset` column to a real asset id during ingestion) and as a
-- fallback on hostname + IP arrays so legacy rows that didn't go through
-- the resolution pipeline still get touched.

CREATE OR REPLACE FUNCTION tc_touch_asset_last_event() RETURNS trigger AS $$
DECLARE
    target_id   TEXT;
    target_host TEXT;
    target_ip   TEXT;
BEGIN
    -- Each insert source has a different column for the asset reference.
    -- TG_TABLE_NAME tells us which one.
    IF TG_TABLE_NAME = 'findings' THEN
        target_id := NEW.asset;          -- findings.asset = assets.id (or hostname)
    ELSIF TG_TABLE_NAME = 'sigma_alerts' THEN
        target_host := NEW.hostname;
        target_ip   := NEW.source_ip::text;
    ELSIF TG_TABLE_NAME = 'firewall_events' THEN
        target_ip   := NEW.dst_ip::text;
    END IF;

    UPDATE assets
       SET last_event_at = NOW(),
           billable_status = CASE
               -- discovered → monitored at first event
               WHEN billable_status = 'discovered' THEN 'monitored'
               -- inactive → monitored if a new event comes in (asset
               -- came back online)
               WHEN billable_status = 'inactive' THEN 'monitored'
               ELSE billable_status
           END
     WHERE id = target_id
        OR (target_host IS NOT NULL AND lower(hostname) = lower(target_host))
        OR (target_ip IS NOT NULL AND target_ip = ANY(ip_addresses));

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tc_findings_touch_asset ON findings;
CREATE TRIGGER tc_findings_touch_asset
    AFTER INSERT ON findings
    FOR EACH ROW EXECUTE FUNCTION tc_touch_asset_last_event();

-- sigma_alerts and firewall_events triggers are conditional on the
-- tables existing in this database (older deployments may not have them).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
                WHERE table_name = 'sigma_alerts') THEN
        EXECUTE 'DROP TRIGGER IF EXISTS tc_sigma_alerts_touch_asset ON sigma_alerts';
        EXECUTE 'CREATE TRIGGER tc_sigma_alerts_touch_asset
                 AFTER INSERT ON sigma_alerts
                 FOR EACH ROW EXECUTE FUNCTION tc_touch_asset_last_event()';
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.tables
                WHERE table_name = 'firewall_events') THEN
        EXECUTE 'DROP TRIGGER IF EXISTS tc_firewall_events_touch_asset ON firewall_events';
        EXECUTE 'CREATE TRIGGER tc_firewall_events_touch_asset
                 AFTER INSERT ON firewall_events
                 FOR EACH ROW EXECUTE FUNCTION tc_touch_asset_last_event()';
    END IF;
END $$;

-- Bootstrap: seed last_event_at for existing rows from the most recent
-- finding/alert we already have. Keeps the first count_billable() call
-- after the migration honest instead of returning 0 monitored assets.
UPDATE assets a
   SET last_event_at = sub.last_event,
       billable_status = CASE WHEN sub.last_event > NOW() - INTERVAL '30 days'
                              THEN 'monitored'
                              ELSE 'inactive'
                          END
  FROM (
        SELECT asset AS asset_id, MAX(detected_at) AS last_event
          FROM findings
         WHERE asset IS NOT NULL
         GROUP BY asset
       ) sub
 WHERE a.id = sub.asset_id;
