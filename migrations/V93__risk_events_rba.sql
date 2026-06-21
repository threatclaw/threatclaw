-- V93 — Risk-Based Aggregation (Phase D1)
--
-- RBA (pattern Splunk Risk-Based Alerting) : les règles taguées `tier='rba_only'`
-- n'émettent PAS d'alerte individuelle — chaque match écrit un `risk_event` scoré
-- sur un objet de risque (asset ou user). Un agrégateur (risk_aggregator.rs)
-- crée un incident "notable" quand le risque accumulé franchit un seuil :
--   RIR (a) : SUM(score) par objet sur 24h > seuil
--   RIR (b) : >= N tactiques MITRE distinctes par objet sur 7j (largeur kill-chain)
--
-- Voir internal/PLAN_PHASE_D_RBA.md. La colonne `tier` (page/queue/rba_only)
-- existe depuis V79 ; cette migration ajoute le stockage des events + le poids.

-- ── Table des événements de risque ────────────────────────────────────
CREATE TABLE IF NOT EXISTS risk_events (
    id              BIGSERIAL PRIMARY KEY,
    -- L'objet sur lequel le risque s'accumule (asset id canonique, ou username).
    risk_object     TEXT NOT NULL,
    object_type     TEXT NOT NULL DEFAULT 'asset'
                    CHECK (object_type IN ('asset', 'user')),
    -- Contribution de risque de ce match (0-100, dérivé du level ou risk_score règle).
    score           INTEGER NOT NULL,
    -- Règle source (rule_id) — traçabilité + dédup + "histoire" de l'incident.
    source_rule     TEXT NOT NULL,
    -- Annotations MITRE (risk annotations Splunk) : alimentent la RIR (b)
    -- "diversité de tactiques". Extraites des tags de la règle.
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    -- Lien vers le log source (forensic).
    log_id          BIGINT,
    -- Titre/résumé du match, pour la chronologie de l'incident notable.
    message         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index pour l'agrégation par objet sur fenêtre (le hot path de l'agrégateur).
CREATE INDEX IF NOT EXISTS idx_risk_events_object_time
    ON risk_events (risk_object, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_created
    ON risk_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_source_rule
    ON risk_events (source_rule);

-- ── Poids de risque par règle (override) ──────────────────────────────
-- NULL → l'agrégateur dérive le score du `level`
-- (informational=5, low=10, medium=25, high=50, critical=100).
-- Un opérateur peut surpondérer une règle précise sans toucher son level.
ALTER TABLE sigma_rules
    ADD COLUMN IF NOT EXISTS risk_score INTEGER
    CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100));

-- ── Rétention ─────────────────────────────────────────────────────────
-- Les RIR n'utilisent que des fenêtres 24h / 7j. Au-delà de 30j, les
-- risk_events sont du bruit historique. Purge via cleanup_old_logs() (V14)
-- étendu, ou DELETE périodique — documenté, pas câblé dans cette migration.
