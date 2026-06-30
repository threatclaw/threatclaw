-- IOC indicators — local mirror of the consolidated threat-intel indicator set
-- shipped by the hub-R2 `ioc` pack (abuse.ch ThreatFox/URLhaus/Feodo, MISP, …).
--
-- The agent already runs a Bloom filter (src/agent/ioc_bloom.rs) for real-time
-- log matching, backed by scattered `settings` keys. Rather than feed the pack
-- into that tangled (and partly dead-wired) path, this dedicated, indexed table
-- is the pack's own clean home: build_from_feeds inserts its values into the
-- Bloom, and verify_in_cache confirms a Bloom hit with an O(1) PK lookup here —
-- additive, leaving the existing feeds (OpenPhish/MISP/KEV/JA3) untouched.
-- See roadmap §5ter (ioc → bloom + TTL), ADR-001 (Bloom IoC detection).
CREATE TABLE IF NOT EXISTS ioc_indicators (
    value       TEXT PRIMARY KEY,     -- normalized (trimmed, lowercased) indicator
    ioc_type    TEXT NOT NULL,        -- ip | domain | url | hash
    source      TEXT,                 -- originating feed (threatfox, urlhaus, …)
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ioc_indicators_type ON ioc_indicators (ioc_type);
