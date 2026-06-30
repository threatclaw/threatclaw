-- EPSS (Exploit Prediction Scoring System, FIRST.org) — bulk local mirror.
--
-- Until now EPSS was a per-CVE live lookup against first.org, cached one row at
-- a time in `settings(_epss, <cve>)`. If first.org was unreachable when a CVE
-- first appeared, there was no score. The hub-R2 `epss` pack ships FIRST's daily
-- full CSV dump (~280k CVEs); this table holds it so scoring is continuous and
-- offline-safe. `lookup_epss_cached` reads here first, then falls back to the
-- live API for a brand-new CVE not yet in the dump. See ADR-018, roadmap §5ter.
--
-- 280k rows in `settings` (config key-value) would be an abuse; a dedicated
-- indexed table bulk-loaded via UNNEST is the right home.
CREATE TABLE IF NOT EXISTS epss_scores (
    cve         TEXT PRIMARY KEY,
    epss        REAL NOT NULL,        -- 0.0-1.0 probability of exploitation in 30d
    percentile  REAL NOT NULL,        -- 0.0-1.0 rank among all CVEs
    score_date  TEXT NOT NULL,        -- FIRST dump date (YYYY-MM-DD)
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
