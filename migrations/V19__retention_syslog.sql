-- ThreatClaw — Rétention données + config Syslog sources

-- ── Table des sources Syslog configurées ──
CREATE TABLE IF NOT EXISTS syslog_sources (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    ip              TEXT NOT NULL,
    parser          TEXT NOT NULL DEFAULT 'syslog-rfc3164',
    source_type     TEXT NOT NULL DEFAULT 'linux',  -- linux, windows, firewall, switch
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_received   TIMESTAMPTZ,
    events_today    INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_syslog_sources_ip ON syslog_sources (ip);

-- ── Rétention configurable ──
CREATE TABLE IF NOT EXISTS retention_config (
    table_name      TEXT PRIMARY KEY,
    retention_days  INTEGER NOT NULL,
    last_cleanup    TIMESTAMPTZ,
    rows_deleted    BIGINT NOT NULL DEFAULT 0
);

-- Valeurs par défaut
INSERT INTO retention_config (table_name, retention_days) VALUES
    ('logs', 30),
    ('sigma_alerts', 90),
    ('findings', 365),
    ('metrics_snapshots', 180),
    ('agent_audit_log', -1),  -- -1 = jamais supprimer (obligation NIS2)
    ('agent_memory', 180)
ON CONFLICT (table_name) DO NOTHING;

-- ── Fonction de nettoyage nocturne ──
CREATE OR REPLACE FUNCTION run_retention_cleanup() RETURNS TABLE(cleaned_table TEXT, deleted_count BIGINT) AS $$
DECLARE
    r RECORD;
    del_count BIGINT;
BEGIN
    FOR r IN SELECT * FROM retention_config WHERE retention_days > 0
    LOOP
        EXECUTE format(
            'DELETE FROM %I WHERE created_at < NOW() - INTERVAL ''%s days''',
            r.table_name, r.retention_days
        );
        GET DIAGNOSTICS del_count = ROW_COUNT;

        UPDATE retention_config
        SET last_cleanup = NOW(), rows_deleted = rows_deleted + del_count
        WHERE table_name = r.table_name;

        cleaned_table := r.table_name;
        deleted_count := del_count;
        RETURN NEXT;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
