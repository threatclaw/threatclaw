-- ThreatClaw — Generic Findings + Skill Config Tables
-- Used by Core API for cross-skill findings and per-skill configuration

-- ── Generic findings (any skill can write here) ─────────
CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    skill_id        TEXT NOT NULL,              -- e.g., "skill-vuln-scan"
    title           TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',  -- critical/high/medium/low/info
    status          TEXT NOT NULL DEFAULT 'open',  -- open/in_progress/resolved/false_positive
    category        TEXT,                       -- scanning, compliance, monitoring, etc.
    asset           TEXT,                       -- affected host/resource
    source          TEXT,                       -- tool that produced the finding
    metadata        JSONB DEFAULT '{}',         -- skill-specific extra data
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    resolved_by     TEXT
);

CREATE INDEX idx_findings_skill ON findings (skill_id);
CREATE INDEX idx_findings_severity ON findings (severity);
CREATE INDEX idx_findings_status ON findings (status);
CREATE INDEX idx_findings_detected ON findings (detected_at DESC);
CREATE INDEX idx_findings_category ON findings (category);
CREATE INDEX idx_findings_metadata ON findings USING GIN (metadata);

-- ── Skill configurations ────────────────────────────────
CREATE TABLE IF NOT EXISTS skill_configs (
    skill_id        TEXT NOT NULL,
    key             TEXT NOT NULL,
    value           TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (skill_id, key)
);

CREATE INDEX idx_skill_configs_skill ON skill_configs (skill_id);

-- ── Metrics snapshots (for dashboard widgets) ───────────
CREATE TABLE IF NOT EXISTS metrics_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    metric_name     TEXT NOT NULL,              -- e.g., "security_score", "vuln_critical_count"
    metric_value    DOUBLE PRECISION NOT NULL,
    labels          JSONB DEFAULT '{}',         -- e.g., {"skill": "vuln-scan", "scope": "network"}
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_metrics_name ON metrics_snapshots (metric_name, recorded_at DESC);
CREATE INDEX idx_metrics_recorded ON metrics_snapshots (recorded_at DESC);
