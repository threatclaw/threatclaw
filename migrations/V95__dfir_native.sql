-- V95 — DFIR natif (Phase 1) : timeline forensique + marqueur de collecte.
--
-- Le triage DFIR natif assemble, à partir de la télémétrie déjà ingérée
-- (osquery/sysmon), une chronologie d'événements forensiques rattachée à un
-- incident : lignée de process, persistance, réseau, comptes — labellisée MITRE.
-- Voir internal/PLAN_NATIVE_DFIR.md / PLAN_NATIVE_DFIR_BUILD.md.
--
-- NB ordre des migrations : V94 = risk_events_consumed (bundle RBA re-fire). Cette
-- migration (V95) doit atterrir APRÈS V94 (rebaser la branche DFIR sur le main
-- post-bundle avant tout déploiement).

-- ── Timeline forensique (une ligne = un événement de la chronologie) ──────
CREATE TABLE IF NOT EXISTS forensic_timeline (
    id                BIGSERIAL PRIMARY KEY,
    incident_id       INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    -- Instant de l'événement, normalisé UTC (l'erreur de timeline n°1 = mélanger
    -- UTC et local ; on stocke UTC + le fuseau d'origine pour traçabilité).
    ts                TIMESTAMPTZ NOT NULL,
    tz_origin         TEXT,
    -- process_spawn | net_connect | persistence_install | logon | file_event |
    -- account_change | defense_evasion | ...
    event_type        TEXT NOT NULL,
    asset             TEXT NOT NULL,
    actor             TEXT,                          -- user / process parent / IP source
    description       TEXT NOT NULL,
    severity          TEXT NOT NULL DEFAULT 'info',
    -- Annotations MITRE ATT&CK (labellisées sur le trigger, pas le chemin).
    mitre_tactic      TEXT,
    mitre_technique   TEXT,
    ioc               TEXT,                          -- hash / IP / domaine / chemin
    related_artifacts JSONB NOT NULL DEFAULT '[]',   -- ids de nœuds graph liés
    source_artifact   TEXT,                          -- evtx | mft | prefetch | osquery | ...
    collected_hash    TEXT,                          -- BLAKE3 (chain of custody)
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_forensic_timeline_incident_ts
    ON forensic_timeline (incident_id, ts ASC);
CREATE INDEX IF NOT EXISTS idx_forensic_timeline_asset
    ON forensic_timeline (asset);

-- ── Marqueur de collecte DFIR (poll idempotent, pattern forensic_enriched_at) ──
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS dfir_collected_at TIMESTAMPTZ;
