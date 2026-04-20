-- Blast radius snapshot per incident. See ADR-048.
--
-- Le snapshot capture l'impact potentiel au moment du verdict pour
-- cohérence d'audit NIS2. Le score 0-100 est indexé pour tri dans
-- la liste d'incidents et pour "Top 3 blast radius" du rapport mensuel.
--
-- Backward-compatible : colonnes nullables, NULL = pas encore calculé,
-- les incidents pré-v1.0.8 restent non-impactés.

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS blast_radius_snapshot   JSONB,
    ADD COLUMN IF NOT EXISTS blast_radius_computed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS blast_radius_score       SMALLINT
        CHECK (blast_radius_score IS NULL OR blast_radius_score BETWEEN 0 AND 100);

-- Index partiel : seuls les incidents avec snapshot apparaissent au tri.
-- Les NULL vont en fin de tri (NULLS LAST par défaut en DESC).
CREATE INDEX IF NOT EXISTS idx_incidents_blast_score
    ON incidents (blast_radius_score DESC)
    WHERE blast_radius_snapshot IS NOT NULL;

-- Index pour "incidents computed in last 24h" — ops monitoring.
CREATE INDEX IF NOT EXISTS idx_incidents_blast_computed
    ON incidents (blast_radius_computed_at DESC)
    WHERE blast_radius_computed_at IS NOT NULL;
