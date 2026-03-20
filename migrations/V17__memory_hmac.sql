-- ThreatClaw — Pilier IV : Mémoire Agent avec intégrité HMAC
-- Seul le RSSI authentifié peut écrire. Les outils ne peuvent que lire.
-- Chaque entrée est signée HMAC pour détecter les modifications.

CREATE TABLE IF NOT EXISTS agent_memory (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content         TEXT NOT NULL,
    source          TEXT NOT NULL,          -- 'rssi', 'onboarding', 'system'
    content_hash    TEXT NOT NULL,          -- SHA-256 du content
    hmac_signature  TEXT NOT NULL,          -- HMAC-SHA256 pour vérification intégrité
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      TEXT NOT NULL           -- email RSSI ou 'system'
);

CREATE INDEX idx_agent_memory_source ON agent_memory (source);
CREATE INDEX idx_agent_memory_created ON agent_memory (created_at DESC);

-- Trigger : empêcher la modification après insertion (immuabilité)
CREATE OR REPLACE FUNCTION prevent_memory_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Modification de la mémoire agent interdite — écriture RSSI requise via API';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER memory_immutability
    BEFORE UPDATE OR DELETE ON agent_memory
    FOR EACH ROW EXECUTE FUNCTION prevent_memory_modification();
