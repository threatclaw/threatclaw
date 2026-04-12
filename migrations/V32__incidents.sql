-- See ADR-043: Incidents layer above alerts and findings
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,

    -- Context
    asset TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT,

    -- Verdict (from LLM investigation)
    verdict TEXT NOT NULL DEFAULT 'pending',
    confidence REAL DEFAULT 0.0,
    severity TEXT DEFAULT 'MEDIUM',

    -- Correlation
    alert_ids INTEGER[] DEFAULT '{}',
    finding_ids INTEGER[] DEFAULT '{}',
    alert_count INTEGER DEFAULT 0,

    -- Investigation
    investigation_log JSONB DEFAULT '[]',
    mitre_techniques TEXT[] DEFAULT '{}',

    -- Remediation
    proposed_actions JSONB DEFAULT '[]',
    executed_actions JSONB DEFAULT '[]',

    -- HITL
    hitl_status TEXT DEFAULT 'none',
    hitl_nonce TEXT,
    hitl_responded_at TIMESTAMPTZ,
    hitl_responded_by TEXT,
    hitl_response TEXT,

    -- Notification
    notified_channels TEXT[] DEFAULT '{}',
    notification_message_id TEXT,

    -- Lifecycle
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_incidents_asset ON incidents(asset);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);
