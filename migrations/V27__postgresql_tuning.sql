-- V27: PostgreSQL tuning — per-table settings + monitoring
-- Note: ALTER SYSTEM settings applied via install script, not migration
-- (requires PostgreSQL restart to take effect)

-- Per-table autovacuum for high-churn tables
ALTER TABLE logs SET (autovacuum_vacuum_scale_factor = 0.01);
ALTER TABLE logs SET (autovacuum_vacuum_cost_delay = 0);
ALTER TABLE sigma_alerts SET (autovacuum_vacuum_scale_factor = 0.01);
ALTER TABLE sigma_alerts SET (autovacuum_vacuum_cost_delay = 0);

-- Monitoring view
CREATE OR REPLACE VIEW db_health AS
SELECT
    (SELECT count(*) FROM logs) AS total_logs,
    (SELECT count(*) FROM sigma_alerts) AS total_alerts,
    (SELECT count(*) FROM findings) AS total_findings,
    (SELECT count(*) FROM assets WHERE status = 'active') AS active_assets,
    (SELECT pg_size_pretty(pg_database_size(current_database()))) AS db_size;
