-- V22: LLM training data collection for future L1 fine-tuning.
-- Logs every L1 LLM call with prompt, response, and parsing result.
-- This data stays ON-PREMISE — never sent externally.
-- Used to build the fine-tuning dataset when ready.

CREATE TABLE IF NOT EXISTS llm_training_data (
    id              BIGSERIAL PRIMARY KEY,
    model           TEXT NOT NULL,                -- e.g., "threatclaw-l1", "threatclaw-l2"
    prompt_hash     TEXT NOT NULL,                -- SHA-256 of prompt (for dedup, not the actual prompt)
    prompt_length   INTEGER NOT NULL,             -- Token count approximation
    response_json   JSONB,                        -- The parsed JSON response (if valid)
    raw_response    TEXT,                          -- Raw LLM output (for debugging malformed JSON)
    parsing_ok      BOOLEAN NOT NULL DEFAULT TRUE, -- Did the JSON parse on first try?
    parsing_method  TEXT,                          -- "strict", "flexible", "fallback"
    severity        TEXT,                          -- Extracted severity
    confidence      DOUBLE PRECISION,             -- Extracted confidence
    actions_count   INTEGER DEFAULT 0,            -- Number of proposed actions
    escalation      TEXT,                          -- "accept", "retry_local", "escalate_cloud"
    cycle_duration_ms INTEGER,                    -- How long the LLM call took
    observations_count INTEGER DEFAULT 0,         -- How many observations were in the prompt
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_llm_training_model ON llm_training_data (model);
CREATE INDEX IF NOT EXISTS idx_llm_training_parsing ON llm_training_data (parsing_ok);
CREATE INDEX IF NOT EXISTS idx_llm_training_created ON llm_training_data (created_at DESC);

-- Retention: 180 days (enough for fine-tuning dataset)
INSERT INTO retention_config (table_name, retention_days)
VALUES ('llm_training_data', 180)
ON CONFLICT (table_name) DO NOTHING;
