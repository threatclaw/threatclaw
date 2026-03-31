-- V26: Database performance optimizations for production scale (500+ assets, 1M+ logs)

-- ═══════════════════════════════════════════════════════════════
-- 1. COMPOSITE INDEXES on frequent queries
-- ═══════════════════════════════════════════════════════════════

-- Alerts: queried by hostname + time (intelligence engine groups by asset, sorts by time)
CREATE INDEX IF NOT EXISTS idx_sigma_alerts_hostname_time
ON sigma_alerts (hostname, matched_at DESC);

-- Alerts: queried by level + status (dashboard filters)
CREATE INDEX IF NOT EXISTS idx_sigma_alerts_level_status
ON sigma_alerts (level, status);

-- Alerts: source_ip lookups (graph sync, IP classification)
CREATE INDEX IF NOT EXISTS idx_sigma_alerts_source_ip
ON sigma_alerts (source_ip) WHERE source_ip IS NOT NULL;

-- Findings: queried by severity + status (dashboard, intelligence engine)
CREATE INDEX IF NOT EXISTS idx_findings_severity_status
ON findings (severity, status);

-- Findings: queried by asset (intelligence engine groups by asset)
CREATE INDEX IF NOT EXISTS idx_findings_asset
ON findings (asset) WHERE asset IS NOT NULL;

-- Findings: queried by skill_id (skill-specific lookups)
CREATE INDEX IF NOT EXISTS idx_findings_skill_detected
ON findings (skill_id, detected_at DESC);

-- Logs: queried by time + tag (intelligence engine scans recent logs)
CREATE INDEX IF NOT EXISTS idx_logs_time_tag
ON logs (time DESC, tag);

-- Logs: queried by hostname (DHCP parser, per-host analysis)
CREATE INDEX IF NOT EXISTS idx_logs_hostname_time
ON logs (hostname, time DESC) WHERE hostname IS NOT NULL;

-- ML scores: queried by score (find anomalies)
CREATE INDEX IF NOT EXISTS idx_ml_scores_score_desc
ON ml_scores (score DESC);

-- Enrichment cache: cleanup expired entries
CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires
ON enrichment_cache (expires_at);

-- Assets: queried by IP (find_asset_by_ip is called for every alert)
-- GIN index already exists on ip_addresses, but add btree for hostname
CREATE INDEX IF NOT EXISTS idx_assets_hostname
ON assets (hostname) WHERE hostname IS NOT NULL;

-- Assets: last_seen for cleanup/staleness detection
CREATE INDEX IF NOT EXISTS idx_assets_last_seen
ON assets (last_seen DESC);

-- ═══════════════════════════════════════════════════════════════
-- 2. PARTITIONING — logs table by week (if not already partitioned)
-- Note: PostgreSQL cannot convert a regular table to partitioned in-place.
-- We create a new partitioned table and migrate data if needed.
-- For existing installations, this is handled by the application.
-- ═══════════════════════════════════════════════════════════════

-- We can't ALTER TABLE to add partitioning on an existing table.
-- Instead, we add a time-based index that gives most of the benefit.
-- TimescaleDB (if installed) will handle this automatically.

-- For now: ensure the time index is optimal
CREATE INDEX IF NOT EXISTS idx_logs_time_brin
ON logs USING BRIN (time) WITH (pages_per_range = 32);

-- BRIN index: ~100x smaller than btree for time-series data, fast for range scans

-- ═══════════════════════════════════════════════════════════════
-- 3. RETENTION — auto-cleanup old data
-- ═══════════════════════════════════════════════════════════════

-- Function to cleanup old logs (called by ML Engine nightly cron)
CREATE OR REPLACE FUNCTION cleanup_old_data(retention_days INTEGER DEFAULT 90) RETURNS TEXT AS $$
DECLARE
    logs_deleted BIGINT;
    alerts_resolved BIGINT;
    cache_expired BIGINT;
    old_scores BIGINT;
BEGIN
    -- Delete logs older than retention period
    DELETE FROM logs WHERE time < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS logs_deleted = ROW_COUNT;

    -- Auto-resolve old alerts (>30 days)
    UPDATE sigma_alerts SET status = 'resolved', resolved_at = NOW()
    WHERE status = 'new' AND matched_at < NOW() - INTERVAL '30 days';
    GET DIAGNOSTICS alerts_resolved = ROW_COUNT;

    -- Delete expired enrichment cache
    DELETE FROM enrichment_cache WHERE expires_at < NOW();
    GET DIAGNOSTICS cache_expired = ROW_COUNT;

    -- Delete stale ML scores (>7 days old)
    DELETE FROM ml_scores WHERE computed_at < NOW() - INTERVAL '7 days';
    GET DIAGNOSTICS old_scores = ROW_COUNT;

    RETURN format('Cleanup: %s logs, %s alerts resolved, %s cache expired, %s stale ML scores',
                   logs_deleted, alerts_resolved, cache_expired, old_scores);
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════
-- 4. STATISTICS — update planner stats for better query plans
-- ═══════════════════════════════════════════════════════════════

-- Increase statistics target for frequently queried columns
ALTER TABLE sigma_alerts ALTER COLUMN hostname SET STATISTICS 500;
ALTER TABLE sigma_alerts ALTER COLUMN level SET STATISTICS 200;
ALTER TABLE findings ALTER COLUMN severity SET STATISTICS 200;
ALTER TABLE findings ALTER COLUMN asset SET STATISTICS 500;
ALTER TABLE logs ALTER COLUMN tag SET STATISTICS 200;

-- Run ANALYZE on critical tables
ANALYZE sigma_alerts;
ANALYZE findings;
ANALYZE logs;
ANALYZE assets;
ANALYZE ml_scores;
