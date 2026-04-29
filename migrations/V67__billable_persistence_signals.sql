-- Phase 7d of the 2026-04-28 pricing pivot — refine the billable
-- definition so an asset that ThreatClaw is actually monitoring counts,
-- even if no security event has hit it yet.
--
-- The V66 model required `billable_status = 'monitored' AND last_event_at >
-- NOW() - 30 days`. That returned 0 billable for a fresh install with 19
-- assets in inventory because none had findings yet. Wrong intuition for
-- a pricing tier called "monitored assets".
--
-- New model: an asset is BILLABLE when one of these persistence signals
-- is true (computed via the new `inventory_status` column):
--
--   declared            : enrolled by an explicit identity / agent source.
--                         AD, M365 / Entra, osquery (agent installed),
--                         Velociraptor (agent installed), Intune / MDM.
--                         Implicit consent on the customer's part.
--
--   observed_persistent : reported by a network connector that owns the
--                         asset as a managed entity. Firewall (pfSense,
--                         OPNsense, Fortinet), switch (future skill),
--                         AP/controller. The connector's job is to enumerate
--                         these once per cycle.
--
--   observed_transient  : seen passively (firewall pass-through traffic,
--                         single Sigma alert, single nmap response). Counts
--                         only after `distinct_days_seen_30d >= 3` —
--                         filters one-off Wi-Fi guests, ephemeral scans.
--
--   inactive            : not seen for >30 days. Stays in DB for history,
--                         not billable.
--
-- The billable count is computed in code (src/agent/billing.rs) using
-- this new column; the V66 `billable_status` column is left in place for
-- backward-compat but its values are no longer the gate.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS inventory_status TEXT
    NOT NULL DEFAULT 'observed_transient';
-- Allowed values:
--   'declared' | 'observed_persistent' | 'observed_transient' | 'inactive'
-- Enforced in code (src/agent/billing.rs) so adding a new state doesn't
-- need another migration.

-- Distinct calendar days the asset was seen in the last 30 days. Used by
-- the transient → billable promotion rule (>=3 distinct days).
-- Maintained by the touch trigger (V66 → updated below) on every
-- finding/sigma_alert/firewall_event hit.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS distinct_days_seen_30d INTEGER
    NOT NULL DEFAULT 0;

-- The set of YYYY-MM-DD strings the asset was seen on, capped to the
-- last 30 distinct days. Cheaper to maintain than a full event log and
-- gives us the rolling window without a window function on every
-- INSERT.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS seen_days_30d TEXT[]
    NOT NULL DEFAULT '{}';

-- Index used by the new billable filter — the most common query is
-- "every active asset whose inventory_status is in the billable set".
CREATE INDEX IF NOT EXISTS idx_assets_inventory_status
    ON assets (inventory_status)
    WHERE demo = false;

-- ─── Backfill ───────────────────────────────────────────────────────
--
-- Promote existing rows to inventory_status based on the data we
-- already have:
--
--   - sources includes 'active_directory' / 'osquery' / 'velociraptor'
--     / 'm365' / 'entra_id' / 'intune' → 'declared'
--   - sources includes 'pfsense' / 'opnsense' / 'fortinet' / 'mikrotik'
--     / 'unifi' / 'wazuh-agent-list' → 'observed_persistent'
--   - billable_status = 'monitored' (V66 trigger fired)             → 'observed_transient'
--     PLUS distinct_days_seen_30d will be backfilled by the trigger
--   - billable_status = 'inactive'                                  → 'inactive'
--   - everything else (pure 'discovered')                           → 'observed_transient'
--     (will roll forward to declared / persistent on next sync)

UPDATE assets a
   SET inventory_status = CASE
       -- Declared by an identity or agent source
       WHEN sources && ARRAY['active_directory','osquery','velociraptor',
                             'm365','entra_id','intune','wazuh-agent']
           THEN 'declared'
       -- Reported by a network connector
       WHEN sources && ARRAY['pfsense','opnsense','fortinet','mikrotik',
                             'unifi','cisco','aruba']
           THEN 'observed_persistent'
       WHEN billable_status = 'inactive'
           THEN 'inactive'
       ELSE 'observed_transient'
   END
 WHERE inventory_status = 'observed_transient';

-- Bootstrap distinct_days_seen_30d from existing findings/alerts. Best
-- effort: COUNT DISTINCT date_trunc('day', detected_at) for findings,
-- min(30, that count). Existing transient rows that already have
-- enough distinct days will become billable on the next count.
UPDATE assets a
   SET distinct_days_seen_30d = LEAST(30, sub.n)
  FROM (
        SELECT asset AS asset_id,
               COUNT(DISTINCT date_trunc('day', detected_at))::int AS n
          FROM findings
         WHERE asset IS NOT NULL
           AND detected_at > NOW() - INTERVAL '30 days'
         GROUP BY asset
       ) sub
 WHERE a.id = sub.asset_id;

-- ─── Updated touch trigger ───────────────────────────────────────────
--
-- Builds on V66's tc_touch_asset_last_event by also maintaining
-- distinct_days_seen_30d. The function gets a ::date string for today,
-- appends to seen_days_30d if not already present, and trims to the
-- last 30 distinct days (sorted DESC, kept most recent).

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
           -- inventory_status promotion:
           --   declared / observed_persistent are stronger signals
           --   than transient, never demote them.
           --   inactive → transient (back online, will rebuild distinct days)
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
                     -- Keep only the last 30 distinct days, trimming the
                     -- tail. We sort DESC and LIMIT 30 in a sub-CTE.
                     ORDER BY d DESC
                     LIMIT 30
               ) trimmed
           ),
           distinct_days_seen_30d = LEAST(30, COALESCE(array_length(seen_days_30d, 1), 0) + 1)
     WHERE id = target_id
        OR (target_host IS NOT NULL AND lower(hostname) = lower(target_host))
        OR (target_ip IS NOT NULL AND target_ip = ANY(ip_addresses));

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers stay attached as set up by V66; no DROP/CREATE needed since
-- we replaced the FUNCTION body in place.
