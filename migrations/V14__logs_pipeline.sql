-- ThreatClaw — SOC Log Pipeline Tables
-- Fluent Bit → PostgreSQL log ingestion + Sigma rule matching

-- ── Raw logs table (Fluent Bit pgsql output) ──────────────
CREATE TABLE IF NOT EXISTS logs (
    id              BIGSERIAL PRIMARY KEY,
    tag             TEXT NOT NULL DEFAULT '',
    time            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data            JSONB NOT NULL DEFAULT '{}',
    -- Enrichment fields added by Fluent Bit filters
    hostname        TEXT,
    collector       TEXT,
    -- Indexing
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX idx_logs_time ON logs (time DESC);
CREATE INDEX idx_logs_tag ON logs (tag);
CREATE INDEX idx_logs_hostname ON logs (hostname);
CREATE INDEX idx_logs_data_gin ON logs USING GIN (data);
CREATE INDEX idx_logs_created_at ON logs (created_at DESC);

-- ── Sigma rules metadata ──────────────────────────────────
CREATE TABLE IF NOT EXISTS sigma_rules (
    id              TEXT PRIMARY KEY,          -- Sigma rule UUID
    title           TEXT NOT NULL,
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'experimental', -- stable/test/experimental
    level           TEXT NOT NULL DEFAULT 'medium',       -- critical/high/medium/low/informational
    author          TEXT,
    logsource_category TEXT,                  -- e.g., process_creation, authentication
    logsource_product  TEXT,                  -- e.g., linux, windows, aws
    logsource_service  TEXT,                  -- e.g., sshd, syslog, cloudtrail
    tags            TEXT[] DEFAULT '{}',       -- MITRE ATT&CK tags
    rule_yaml       TEXT NOT NULL,            -- Full YAML content
    detection_json  JSONB,                    -- Parsed detection block
    enabled         BOOLEAN NOT NULL DEFAULT true,
    loaded_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sigma_rules_level ON sigma_rules (level);
CREATE INDEX idx_sigma_rules_logsource ON sigma_rules (logsource_category, logsource_product);
CREATE INDEX idx_sigma_rules_enabled ON sigma_rules (enabled) WHERE enabled = true;
CREATE INDEX idx_sigma_rules_tags ON sigma_rules USING GIN (tags);

-- ── Sigma alerts (matched rules) ──────────────────────────
CREATE TABLE IF NOT EXISTS sigma_alerts (
    id              BIGSERIAL PRIMARY KEY,
    rule_id         TEXT NOT NULL REFERENCES sigma_rules(id),
    log_id          BIGINT REFERENCES logs(id),
    matched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    level           TEXT NOT NULL,             -- copied from rule for fast queries
    title           TEXT NOT NULL,             -- copied from rule
    matched_fields  JSONB,                     -- fields that triggered the match
    source_ip       INET,                      -- extracted if available
    dest_ip         INET,                      -- extracted if available
    username        TEXT,                       -- extracted if available
    hostname        TEXT,                       -- from log record
    -- Triage
    status          TEXT NOT NULL DEFAULT 'new', -- new/investigating/resolved/false_positive
    analyst_notes   TEXT,
    resolved_at     TIMESTAMPTZ,
    resolved_by     TEXT
);

CREATE INDEX idx_sigma_alerts_matched_at ON sigma_alerts (matched_at DESC);
CREATE INDEX idx_sigma_alerts_rule_id ON sigma_alerts (rule_id);
CREATE INDEX idx_sigma_alerts_level ON sigma_alerts (level);
CREATE INDEX idx_sigma_alerts_status ON sigma_alerts (status);
CREATE INDEX idx_sigma_alerts_hostname ON sigma_alerts (hostname);

-- ── SOC dashboard materialized view ───────────────────────
CREATE MATERIALIZED VIEW IF NOT EXISTS soc_alert_summary AS
SELECT
    date_trunc('hour', matched_at) AS hour,
    level,
    COUNT(*) AS alert_count,
    COUNT(DISTINCT rule_id) AS unique_rules,
    COUNT(DISTINCT hostname) AS unique_hosts
FROM sigma_alerts
WHERE matched_at > NOW() - INTERVAL '7 days'
GROUP BY date_trunc('hour', matched_at), level
ORDER BY hour DESC, level;

CREATE UNIQUE INDEX idx_soc_summary_hour_level
    ON soc_alert_summary (hour, level);

-- ── Cloud posture findings ────────────────────────────────
CREATE TABLE IF NOT EXISTS cloud_findings (
    id              BIGSERIAL PRIMARY KEY,
    provider        TEXT NOT NULL,             -- aws/azure/gcp
    service         TEXT NOT NULL,             -- e.g., iam, s3, ec2
    check_id        TEXT NOT NULL,             -- Prowler check ID
    check_title     TEXT NOT NULL,
    status          TEXT NOT NULL,             -- PASS/FAIL/WARNING
    severity        TEXT NOT NULL,             -- critical/high/medium/low
    region          TEXT,
    resource_arn    TEXT,
    resource_name   TEXT,
    description     TEXT,
    remediation     TEXT,
    compliance      TEXT[],                    -- frameworks: NIS2, ISO27001, etc.
    raw_result      JSONB,
    scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cloud_findings_provider ON cloud_findings (provider);
CREATE INDEX idx_cloud_findings_status ON cloud_findings (status);
CREATE INDEX idx_cloud_findings_severity ON cloud_findings (severity);
CREATE INDEX idx_cloud_findings_scanned_at ON cloud_findings (scanned_at DESC);
CREATE INDEX idx_cloud_findings_compliance ON cloud_findings USING GIN (compliance);

-- ── Log retention policy (auto-cleanup) ───────────────────
-- Keep raw logs for 90 days, alerts for 1 year
CREATE OR REPLACE FUNCTION cleanup_old_logs() RETURNS void AS $$
BEGIN
    DELETE FROM logs WHERE created_at < NOW() - INTERVAL '90 days';
    DELETE FROM sigma_alerts WHERE matched_at < NOW() - INTERVAL '365 days';
    REFRESH MATERIALIZED VIEW CONCURRENTLY soc_alert_summary;
END;
$$ LANGUAGE plpgsql;
