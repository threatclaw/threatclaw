-- V61: Pipeline refoundation cleanup (Phase E).
--
-- Goes with Phase A/B/C of the 27/04 refoundation. Two changes:
--
--   1. sigma_alerts retention drops from 365 d to 30 d. The rule was
--      "matière brute, on garde 1 an au cas où" but in practice
--      ~70 k rows accumulated noise that nobody queries past 30 d.
--      The cleanup_old_logs cron will keep purging > 30 d going
--      forward; this migration deletes the back-catalogue in one shot.
--
--   2. The 56 incidents stuck in `status='error'` from the broken L2
--      pipeline (timeouts on 900 s budget, no fallback title) are
--      reclassified as `status='open'` so the RSSI sees them in the
--      regular queue. The verdict stays `error` for traceability —
--      it's just no longer a terminal status that buries the row.
--      An audit note is added so it's clear this happened via
--      migration, not by an actual L2 retry.

-- 1. Purge old sigma_alerts (> 30 days)
DELETE FROM sigma_alerts
WHERE matched_at < NOW() - INTERVAL '30 days';

-- 2. Reclassify 'error' incidents to 'open' so they re-surface
UPDATE incidents
SET status = 'open',
    updated_at = NOW()
WHERE status = 'error';

-- 2b. Patch the cleanup_old_logs function so the 30 d window applies
--     going forward, not just to the back-catalogue purge above.
CREATE OR REPLACE FUNCTION cleanup_old_logs() RETURNS void AS $$
BEGIN
    DELETE FROM logs WHERE created_at < NOW() - INTERVAL '90 days';
    DELETE FROM sigma_alerts WHERE matched_at < NOW() - INTERVAL '30 days';
    REFRESH MATERIALIZED VIEW CONCURRENTLY soc_alert_summary;
END;
$$ LANGUAGE plpgsql;

-- 3. Trace the migration in the audit log so we know in 6 months
--    what flipped these statuses. NOTE: incident_audit_log may not
--    exist on every install — protect with a DO block.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables
               WHERE table_name = 'incident_audit_log') THEN
        INSERT INTO incident_audit_log (incident_id, author, message, created_at)
        SELECT id, 'migration_v61', 'Status reclassified from `error` to `open` by V61 (pipeline refoundation). Verdict left as-is for traceability.', NOW()
        FROM incidents
        WHERE status = 'open' AND verdict = 'error';
    END IF;
END $$;
