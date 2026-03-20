-- ThreatClaw — Pilier Audit : Log immuable avec chaîne de hash
-- Chaque action de l'agent est enregistrée.
-- Les entrées ne peuvent JAMAIS être modifiées ou supprimées (trigger).

CREATE TABLE IF NOT EXISTS agent_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Qui a fait quoi
    event_type      TEXT NOT NULL,        -- OBSERVATION, REASONING, ACTION_PROPOSED, HITL_SENT, HITL_APPROVED, HITL_DENIED, EXECUTION_START, EXECUTION_COMPLETE, KILL_SWITCH, SOUL_CHECK, MEMORY_CHECK
    agent_mode      TEXT NOT NULL,        -- analyst, investigator, responder, autonomous_low

    -- Détails de l'action
    cmd_id          TEXT,                 -- ID whitelist (si applicable)
    cmd_params      JSONB,               -- Paramètres de la commande

    -- Approbation humaine
    approved_by     TEXT,                 -- Email RSSI ou 'AUTO_LOW_RISK'
    approval_token  TEXT,                 -- Nonce Slack anti-replay

    -- Résultat
    success         BOOLEAN,
    error_message   TEXT,
    output_hash     TEXT,                 -- Hash du résultat (pas le résultat lui-même)

    -- Intégrité — chaîne de hash type blockchain
    row_hash        TEXT NOT NULL,        -- SHA-256 de cette row
    previous_hash   TEXT,                 -- Hash de la row précédente

    -- Contexte
    react_iteration INTEGER,
    session_id      UUID,
    skill_id        TEXT
);

CREATE INDEX idx_audit_timestamp ON agent_audit_log (timestamp DESC);
CREATE INDEX idx_audit_event_type ON agent_audit_log (event_type);
CREATE INDEX idx_audit_session ON agent_audit_log (session_id);
CREATE INDEX idx_audit_cmd ON agent_audit_log (cmd_id);

-- Trigger : empêcher toute modification ou suppression
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Modification du audit log interdite — accès forensic requis';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_immutability
    BEFORE UPDATE OR DELETE ON agent_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- Vue lecture seule pour le dashboard RSSI
CREATE VIEW audit_log_rssi AS
SELECT
    timestamp,
    event_type,
    agent_mode,
    cmd_id,
    approved_by,
    success,
    error_message,
    react_iteration
FROM agent_audit_log
ORDER BY timestamp DESC;
