-- V97 — DFIR : suivi des collectes Velociraptor déclenchées par incident.
--
-- Chantier 2 (auto-collecte T0). À la création d'un incident HIGH+ sur un asset
-- enrôlé Velociraptor, on déclenche IMMÉDIATEMENT une collecte volatile (course
-- contre le wipe) via le connecteur du skill. La collecte VR est ASYNCHRONE : on
-- obtient un `flow_id`, les résultats arrivent quelques s/min plus tard. Cette
-- table suit chaque collecte (1 ligne = 1 artefact collecté sur 1 hôte pour 1
-- incident) : le trigger insère en `collecting`, l'ingesteur lit le flow terminé,
-- mappe les résultats dans forensic_timeline, puis passe en `done`.
--
-- status : collecting → done | failed | no_client | skipped
-- trigger : auto (T0) | manual (bouton analyste)

CREATE TABLE IF NOT EXISTS dfir_collections (
    id          BIGSERIAL PRIMARY KEY,
    incident_id INTEGER NOT NULL,
    client_id   TEXT,                 -- C.xxxx ; NULL si l'asset n'est pas un client VR
    artifact    TEXT NOT NULL,        -- ex. Linux.Sys.Pslist
    flow_id     TEXT,                 -- F.xxxx renvoyé par collect_client
    status      TEXT NOT NULL DEFAULT 'collecting',
    trigger_kind TEXT NOT NULL DEFAULT 'auto',
    row_count   INTEGER,              -- lignes ingérées une fois le flow terminé
    error       TEXT,
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMPTZ
);

-- Hot path ingesteur : lister les collectes encore en cours.
CREATE INDEX IF NOT EXISTS idx_dfir_collections_collecting
    ON dfir_collections (status, requested_at)
    WHERE status = 'collecting';

-- Le trigger vérifie "cet incident a-t-il déjà une collecte auto ?" (once-per-incident).
CREATE INDEX IF NOT EXISTS idx_dfir_collections_incident
    ON dfir_collections (incident_id);
