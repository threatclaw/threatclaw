-- migrations/V86__cleanup_orphan_pipeline_rows.sql
--
-- Three classes of orphan rows accumulated on operator stacks running
-- versions earlier than 1.0.45-beta. The runtime code paths that
-- produced them have been fixed in code; this migration drops the
-- existing detritus so the dashboard inventory and the matview stats
-- stop carrying ghost entries.
--
-- 1. ml_scores keyed on hostnames the assets table has dropped (the
--    ML engine ran before the asset-dedup migrations V84/V85 reduced
--    duplicates, or against junk hostnames the syslog observe-and-enrol
--    blocklist now filters out — `syslog-observed-kernel`,
--    `syslog-observed-systemd-logind`, `syslog-observed-bc130c79e5dd`,
--    etc.). The scores are read by the IE when building the dossier;
--    an orphan row contributes a stale score on every cycle.
--
-- 2. findings keyed on `kernel`, `dockerd`, `sshd`, `sshd-session`,
--    `lynis`, a 12-hex Docker container id, etc. Pre-1.0.45-beta the
--    sigma engine did not apply `looks_like_program_or_container_id`
--    to the finding insert path, so a sigma rule firing on a log
--    whose host slot had collapsed to the program name produced a
--    finding on a non-existent asset. The runtime fix lives in
--    sigma_engine.rs; this drops the legacy rows.
--
-- 3. sigma_rules that were auto-stubbed by the legacy
--    `insert_sigma_alert_with_fields` path with status='test',
--    enabled=true. They never carried a real detection body but
--    leaked into `sigma_rule_stats` and the dashboard sigma list as
--    ghost rules. Code now writes status='auto-stub' with
--    enabled=false; this migration retro-fits the same shape on
--    pre-existing stubs (identified by their canonical placeholder
--    rule_yaml).
--
-- Idempotent: a re-run on a clean stack is a no-op for all three.

BEGIN;

-- (1) Drop ml_scores whose asset_id no longer references an existing row.
WITH d AS (
    DELETE FROM ml_scores m
    WHERE NOT EXISTS (SELECT 1 FROM assets a WHERE a.id = m.asset_id)
    RETURNING m.asset_id
)
SELECT COUNT(*) AS ml_scores_dropped FROM d;

-- (2) Drop findings whose asset string does not match any asset row.
-- Match the same shape recent_sigma_alerts_for_asset uses (case-
-- insensitive id, name, hostname). A finding without an asset (NULL)
-- is left alone — those came from non-asset-scoped detectors.
WITH d AS (
    DELETE FROM findings f
    WHERE f.asset IS NOT NULL
      AND f.asset <> ''
      AND NOT EXISTS (
          SELECT 1 FROM assets a
          WHERE LOWER(a.id) = LOWER(f.asset)
             OR LOWER(a.name) = LOWER(f.asset)
             OR LOWER(a.hostname) = LOWER(f.asset)
      )
    RETURNING f.asset
)
SELECT COUNT(*) AS findings_dropped FROM d;

-- (3) Retire legacy auto-stub sigma_rules (canonical placeholder body,
-- never carried a real detection block). Identify them by the exact
-- shape the legacy code wrote and flip them to the new inert state
-- so the matview refresh stops counting them.
UPDATE sigma_rules
SET status = 'auto-stub', enabled = false
WHERE status = 'test'
  AND rule_yaml LIKE '%detection:\n  condition: test%'
  AND (detection_json IS NULL OR detection_json::text = '{}');

DO $$
DECLARE
    stubs_retired INT;
BEGIN
    GET DIAGNOSTICS stubs_retired = ROW_COUNT;
    IF stubs_retired > 0 THEN
        RAISE NOTICE 'V86: retired % legacy auto-stub sigma_rules', stubs_retired;
    END IF;
END $$;

-- Refresh the matview so the cleanup lands in the dashboard at next read.
-- CONCURRENTLY because the matview was created with the unique index
-- in V78 specifically to allow non-blocking refresh.
REFRESH MATERIALIZED VIEW CONCURRENTLY sigma_rule_stats;

COMMIT;
