-- V25: Enrichment cache + ML scores dedicated table

-- ═══════════════════════════════════════════════════════════════
-- ENRICHMENT CACHE — avoid repeated external API calls
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS enrichment_cache (
    source      TEXT NOT NULL,           -- e.g. "ssllabs", "safebrowsing", "observatory"
    key         TEXT NOT NULL,           -- e.g. "monsite.fr", "192.168.1.10"
    value       JSONB NOT NULL,          -- cached API response
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,    -- TTL-based expiration
    PRIMARY KEY (source, key)
);

CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires ON enrichment_cache (expires_at);

-- ═══════════════════════════════════════════════════════════════
-- ML SCORES — dedicated table (moved from settings hack)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ml_scores (
    asset_id    TEXT PRIMARY KEY,
    score       REAL NOT NULL DEFAULT 0.0,
    reason      TEXT,
    features    JSONB DEFAULT '{}',
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ml_scores_score ON ml_scores (score DESC);
