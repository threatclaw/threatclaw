-- Governance layer v1 — AI system inventory + compliance metadata on findings.
--
-- Prépare l'onglet Governance (dashboard v1.2) et les skills compliance
-- EU AI Act / ISO 42001 / NIST AI RMF (v1.3). Voir internal/governance-roadmap.md.
--
-- Backward-compatible :
--  - ai_systems = nouvelle table, aucune app existante ne s'en sert
--  - compliance_metadata = colonne nullable avec default NULL, zéro impact
--    sur les findings existants (serde strip_if_none à prévoir côté Rust)

-- ── Table ai_systems ───────────────────────────────────────
-- Inventaire unifié : IA déclarées par le RSSI + IA détectées en shadow
-- par skill-shadow-ai-monitor. La colonne `status` trace le cycle de vie
-- (detected → declared → assessed → retired).

CREATE TABLE IF NOT EXISTS ai_systems (
    id                BIGSERIAL PRIMARY KEY,
    name              TEXT NOT NULL,                        -- ex: "ChatGPT Enterprise", "Ollama-gpu-server"
    category          TEXT NOT NULL,                        -- llm-commercial | llm-self-hosted | agent | embedding | coding-assistant
    provider          TEXT,                                 -- OpenAI, Anthropic, Mistral, Ollama, internal, ...
    endpoint          TEXT,                                 -- FQDN ou IP:port
    status            TEXT NOT NULL DEFAULT 'detected',     -- detected | declared | assessed | retired
    risk_level        TEXT,                                 -- high | medium | low (EU AI Act Annex III)
    assessment_status TEXT,                                 -- pending | in_progress | completed
    declared_by       TEXT,                                 -- user/email qui a déclaré
    declared_at       TIMESTAMPTZ,
    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    remediation       TEXT,                                 -- note libre sur actions à prendre
    metadata          JSONB NOT NULL DEFAULT '{}',          -- extensibilité (policy_decision, tier, etc.)
    UNIQUE (category, provider, endpoint)
);

CREATE INDEX IF NOT EXISTS idx_ai_systems_status      ON ai_systems (status);
CREATE INDEX IF NOT EXISTS idx_ai_systems_risk_level  ON ai_systems (risk_level) WHERE risk_level IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_systems_provider    ON ai_systems (provider)   WHERE provider IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ai_systems_last_seen   ON ai_systems (last_seen DESC);

-- Vue stats pour le dashboard Governance
CREATE OR REPLACE VIEW ai_systems_stats AS
SELECT
    status,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE risk_level = 'high')   AS high_risk,
    COUNT(*) FILTER (WHERE risk_level = 'medium') AS medium_risk,
    COUNT(*) FILTER (WHERE risk_level = 'low')    AS low_risk,
    COUNT(DISTINCT provider)                      AS providers,
    COUNT(*) FILTER (WHERE last_seen > NOW() - INTERVAL '7 days') AS seen_last_7d
FROM ai_systems
GROUP BY status;

-- ── Extension findings ─────────────────────────────────────
-- Ajout d'une colonne JSONB dédiée à la metadata compliance structurée.
-- Distincte du `metadata` générique pour ne pas polluer les findings
-- techniques et permettre un index GIN efficace sur les requêtes
-- regulatory_framework / regulatory_reference / compliance_status.
--
-- Schéma attendu (documenté dans governance-roadmap.md §7.2) :
--   {
--     "regulatory_framework": "eu_ai_act" | "iso42001" | "nist_ai_rmf" | "nis2" | "iso27001" | "gdpr",
--     "regulatory_reference": "art.12" | "A.5.2" | ...,
--     "evidence_ids": [{"type": "sigma_alert|finding|log_hash|graph_node", "id": "..."}],
-- "compliance_status": "compliant" | "gap" | "remediation_pending",
--     "risk_level": "high" | "medium" | "low",
--     "remediation_action": "string"
--   }

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS compliance_metadata JSONB DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_findings_compliance_meta
    ON findings USING GIN (compliance_metadata)
    WHERE compliance_metadata IS NOT NULL;

-- Expression index pour queries "findings by regulatory framework"
CREATE INDEX IF NOT EXISTS idx_findings_compliance_framework
    ON findings ((compliance_metadata->>'regulatory_framework'))
    WHERE compliance_metadata IS NOT NULL;
