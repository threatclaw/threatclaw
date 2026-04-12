-- Retroact: re-scan suspect findings with updated threat intel.
-- Inspired by Gatewatcher Retroact — "ThreatClaw ne lâche jamais un suspect."

-- Add rescan_at column for findings that need re-evaluation
ALTER TABLE findings ADD COLUMN IF NOT EXISTS rescan_at TIMESTAMPTZ;

-- Index for efficient nocturnal rescan query
CREATE INDEX IF NOT EXISTS idx_findings_rescan ON findings (rescan_at)
    WHERE rescan_at IS NOT NULL AND status IN ('open', 'in_progress');
