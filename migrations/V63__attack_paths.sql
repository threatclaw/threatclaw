-- V63: Attack paths prediction (Phase G2 — predictive).
--
-- Job batch (toutes les 4-6h) qui calcule les chemins d'attaque les plus
-- probables sur le graph d'assets : Dijkstra ponderé depuis les nœuds
-- exposes (internet/dmz/vlan_dev) vers les crown jewels (assets de
-- criticality high/critical).
--
-- Edge weight = `1 / (EPSS_max_dest * KEV_boost * CVSS_exploitability)`.
-- Plus un edge a de probabilité d'exploitation, plus il est "leger" en
-- coût Dijkstra → les paths qui en passent par la sont les plus
-- probables.
--
-- Sortie : top-N paths par run, persistés ici. Le RSSI les voit dans
-- `/security/attack-paths` (Phase G4) et le job G3 (PageRank inverse)
-- les utilise pour calculer les choke points.
--
-- Référence : EPSS v4 (FIRST), KEV (CISA), CVSS exploitability metric.
-- Seuil combinatoire OK pour < 500 nodes (cf MulVAL/CAULDRON survey).

CREATE TABLE IF NOT EXISTS attack_paths_predicted (
    id              BIGSERIAL PRIMARY KEY,
    -- Run group : tous les paths du même calcul partagent ce timestamp,
    -- permet de purger les vieux runs ou de comparer entre dates.
    run_id          UUID NOT NULL,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Path metadata
    src_asset       TEXT NOT NULL,            -- exposed entry point
    dst_asset       TEXT NOT NULL,            -- crown jewel target
    path_assets     TEXT[] NOT NULL,          -- ordered list incl. src + dst
    hops            SMALLINT NOT NULL,        -- length of path - 1
    -- Score + breakdown
    score           DOUBLE PRECISION NOT NULL, -- 0.0 (unlikely) à 1.0 (très probable)
    epss_max        DOUBLE PRECISION,          -- max EPSS sur les CVE traversées
    has_kev         BOOLEAN NOT NULL DEFAULT false,
    cves_chain      TEXT[] NOT NULL DEFAULT '{}',
    mitre_techniques TEXT[] NOT NULL DEFAULT '{}',
    -- Lifecycle
    explanation     TEXT,                      -- "via CVE-X (EPSS=0.87, KEV) sur asset Y, lateral SMB → asset Z"
    superseded_by   UUID                       -- set when next run replaces this one
);

-- Hot path : "donne-moi les top-10 les plus dangereux du dernier run"
CREATE INDEX IF NOT EXISTS attack_paths_run_score_idx
    ON attack_paths_predicted (run_id, score DESC);

-- Per-asset history : "qu'est-ce qui menace SRV-DB-01 récemment ?"
CREATE INDEX IF NOT EXISTS attack_paths_dst_idx
    ON attack_paths_predicted (dst_asset, computed_at DESC);

-- Cleanup : purge les runs anciens
CREATE INDEX IF NOT EXISTS attack_paths_computed_at_idx
    ON attack_paths_predicted (computed_at);

COMMENT ON TABLE attack_paths_predicted IS
    'Predicted attack paths (Phase G2). Top-N par run, batch toutes les 4-6h.';
COMMENT ON COLUMN attack_paths_predicted.score IS
    '0.0 (unlikely) to 1.0 (very likely). Composite of EPSS, KEV presence, CVSS exploitability, hops.';
