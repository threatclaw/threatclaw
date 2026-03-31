-- V21: CVE cache, MITRE ATT&CK store, CERT-FR alerts, offline bundle metadata
-- Part of v0.4.0 — Enrichissement & Offline

-- ── CVE Cache (NVD API results, 7-day TTL) ──
CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT NOT NULL DEFAULT '',
    cvss_score      DOUBLE PRECISION,
    cvss_severity   TEXT,
    published       TEXT,
    exploited_in_wild BOOLEAN NOT NULL DEFAULT FALSE,
    patch_urls      JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw_data        JSONB,
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days')
);

CREATE INDEX IF NOT EXISTS idx_cve_cache_expires ON cve_cache (expires_at);
CREATE INDEX IF NOT EXISTS idx_cve_cache_severity ON cve_cache (cvss_severity);

-- ── MITRE ATT&CK techniques (synced from STIX JSON) ──
CREATE TABLE IF NOT EXISTS mitre_techniques (
    technique_id    TEXT PRIMARY KEY,       -- e.g. T1059.001
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    tactic          TEXT NOT NULL DEFAULT '',  -- e.g. execution, persistence
    platform        TEXT[] NOT NULL DEFAULT '{}',
    detection       TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL DEFAULT '',
    data_sources    TEXT[] NOT NULL DEFAULT '{}',
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mitre_tactic ON mitre_techniques (tactic);

-- ── CERT-FR alerts (RSS feed, daily sync) ──
CREATE TABLE IF NOT EXISTS certfr_alerts (
    alert_id        TEXT PRIMARY KEY,       -- e.g. CERTFR-2026-AVI-0234
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'medium',
    published       TIMESTAMPTZ,
    link            TEXT NOT NULL DEFAULT '',
    cve_ids         TEXT[] NOT NULL DEFAULT '{}',
    affected        TEXT NOT NULL DEFAULT '',
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_certfr_published ON certfr_alerts (published DESC);

-- ── Offline bundle metadata ──
CREATE TABLE IF NOT EXISTS offline_bundle (
    bundle_id       TEXT PRIMARY KEY DEFAULT 'default',
    cve_count       INTEGER NOT NULL DEFAULT 0,
    mitre_count     INTEGER NOT NULL DEFAULT 0,
    certfr_count    INTEGER NOT NULL DEFAULT 0,
    sigma_count     INTEGER NOT NULL DEFAULT 0,
    crowdsec_count  INTEGER NOT NULL DEFAULT 0,
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bundle_size_mb  DOUBLE PRECISION NOT NULL DEFAULT 0,
    mode            TEXT NOT NULL DEFAULT 'online'  -- online, degraded, offline, airgap
);

-- Insert default bundle metadata
INSERT INTO offline_bundle (bundle_id) VALUES ('default') ON CONFLICT DO NOTHING;

-- Add retention config for new tables
INSERT INTO retention_config (table_name, retention_days) VALUES
    ('cve_cache', 30),
    ('certfr_alerts', 365)
ON CONFLICT (table_name) DO NOTHING;
