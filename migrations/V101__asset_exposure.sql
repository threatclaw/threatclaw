-- Per-asset prioritised exposure score: the cross of software-vuln (Grype) ×
-- CISA KEV × EPSS × asset criticality × network exposure, rolled up to one
-- explainable 0-100 number. Computed by the daily Grype scan
-- (src/enrichment/software_vuln.rs via src/enrichment/exposure_score.rs),
-- surfaced in the asset detail and the "Actions prioritaires" view, and — when
-- notable — pushed into the RBA pipeline as a risk_event so it escalates to an
-- incident. See ADR-018 (CVSS+KEV+EPSS scoring).
--
-- Mirrors the ml_scores layout (asset_id PK, one row per asset, recomputed in
-- place). The top_* columns carry the single most actionable remediation so the
-- "Actions prioritaires" list is a single sorted read (asset → patch X to fix).
CREATE TABLE IF NOT EXISTS asset_exposure (
    asset_id      TEXT PRIMARY KEY,
    score         SMALLINT NOT NULL CHECK (score BETWEEN 0 AND 100),
    severity      TEXT NOT NULL,              -- LOW | MEDIUM | HIGH | CRITICAL
    breakdown     JSONB NOT NULL DEFAULT '[]'::jsonb,  -- human "why" lines
    max_cvss      REAL,
    in_kev        BOOLEAN NOT NULL DEFAULT FALSE,
    epss_max      REAL,
    exposed       BOOLEAN NOT NULL DEFAULT FALSE,
    top_cve       TEXT,                        -- the CVE driving the action
    top_fix       TEXT,                        -- fixed version = the remediation
    top_software  TEXT,                        -- package to patch
    computed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sort the asset list / the Actions prioritaires view by worst exposure first.
CREATE INDEX IF NOT EXISTS idx_asset_exposure_score ON asset_exposure (score DESC);
