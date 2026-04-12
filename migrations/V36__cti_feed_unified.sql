-- Unified CTI (Cyber Threat Intelligence) feed table.
-- Aggregates IoCs from all sources with confidence scoring.
-- Multi-source IoCs = higher confidence. Single-source = lower.
-- Feeds into Bloom filter for real-time detection.

CREATE TABLE IF NOT EXISTS ioc_feed (
    id              BIGSERIAL PRIMARY KEY,
    ioc_type        TEXT NOT NULL,                -- ip, domain, url, hash_md5, hash_sha256, hash_sha1, email, ja3, hassh
    ioc_value       TEXT NOT NULL,                -- the actual IoC value
    sources         TEXT[] NOT NULL DEFAULT '{}',  -- which feeds reported it (openphish, threatfox, etc.)
    confidence      SMALLINT NOT NULL DEFAULT 50,  -- 0-100, computed from source count + recency
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags            TEXT[] DEFAULT '{}',           -- malware family, campaign, etc.
    threat_type     TEXT,                          -- malware, phishing, c2, botnet, scanner
    malware_family  TEXT,                          -- emotet, cobalt_strike, etc.
    reference_url   TEXT,                          -- link to source report
    active          BOOLEAN NOT NULL DEFAULT true,
    UNIQUE(ioc_type, ioc_value)
);

-- Fast lookups by value (the primary use case)
CREATE INDEX IF NOT EXISTS idx_ioc_feed_value ON ioc_feed (ioc_value);
CREATE INDEX IF NOT EXISTS idx_ioc_feed_type_value ON ioc_feed (ioc_type, ioc_value);
-- Active IoCs for Bloom filter loading
CREATE INDEX IF NOT EXISTS idx_ioc_feed_active ON ioc_feed (active) WHERE active = true;
-- Recency-based queries
CREATE INDEX IF NOT EXISTS idx_ioc_feed_last_seen ON ioc_feed (last_seen DESC);
-- Source-based queries
CREATE INDEX IF NOT EXISTS idx_ioc_feed_sources ON ioc_feed USING GIN (sources);
-- Threat type filtering
CREATE INDEX IF NOT EXISTS idx_ioc_feed_threat ON ioc_feed (threat_type) WHERE threat_type IS NOT NULL;

-- Stats view for dashboard
CREATE OR REPLACE VIEW ioc_feed_stats AS
SELECT
    ioc_type,
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '24 hours') as last_24h,
    COUNT(*) FILTER (WHERE array_length(sources, 1) > 1) as multi_source,
    AVG(confidence) as avg_confidence
FROM ioc_feed
WHERE active = true
GROUP BY ioc_type;
