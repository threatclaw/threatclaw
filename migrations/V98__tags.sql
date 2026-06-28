-- V98 — Tags first-class : entité Tag + liaison many-to-many asset_tags.
--
-- Jusqu'ici les tags utilisateur vivaient en tableau de strings sur
-- `assets.tags`. Le brief de refonte de l'inventaire veut un modèle porteur :
-- une couleur par tag et, à terme, une POLITIQUE (criticité par défaut,
-- périmètre de détection, rattachement de licence) attachable au tag sans
-- remigrer. On promeut donc le tag en entité et on relie les assets via une
-- table de jonction.
--
-- IMPORTANT : les 3 tags SYSTÈME (possible-duplicate / public_ip /
-- keep-separate) NE sont PAS des tags utilisateur — ce sont des flags posés
-- par le moteur (asset_resolution / dashboard dismiss). Ils RESTENT dans
-- `assets.tags`. Seuls les tags utilisateur migrent vers l'entité.

CREATE TABLE IF NOT EXISTS tags (
    id         BIGSERIAL PRIMARY KEY,
    label      TEXT NOT NULL UNIQUE,
    color      TEXT NOT NULL,              -- hex, ex. '#4b8ef0'
    policy     JSONB,                      -- réservé v2 (non câblé en v1)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS asset_tags (
    asset_id   TEXT   NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tag_id     BIGINT NOT NULL REFERENCES tags(id)   ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, tag_id)
);
CREATE INDEX IF NOT EXISTS idx_asset_tags_tag ON asset_tags (tag_id);

-- ── Data migration : strings existants → entité ──────────────────────────
-- 1. Une ligne `tags` par tag utilisateur distinct (couleur neutre par
--    défaut ; une vraie couleur de palette est posée à la (re)création via
--    l'API). Les flags système sont exclus.
-- Labels normalisés en minuscules (le code applicatif fait de même → pas de doublon de casse).
INSERT INTO tags (label, color)
    SELECT DISTINCT lower(t), '#808a99'
    FROM assets, unnest(tags) AS t
    WHERE t NOT IN ('possible-duplicate', 'public_ip', 'keep-separate')
ON CONFLICT (label) DO NOTHING;

-- 2. Liens asset ↔ tag pour chaque tag utilisateur porté par un asset.
INSERT INTO asset_tags (asset_id, tag_id)
    SELECT a.id, tg.id
    FROM assets a, unnest(a.tags) AS t
    JOIN tags tg ON tg.label = lower(t)
    WHERE t NOT IN ('possible-duplicate', 'public_ip', 'keep-separate')
ON CONFLICT DO NOTHING;

-- 3. `assets.tags` ne garde plus que les flags système.
UPDATE assets
    SET tags = ARRAY(
        SELECT t FROM unnest(tags) t
        WHERE t IN ('possible-duplicate', 'public_ip', 'keep-separate')
    )
    WHERE EXISTS (
        SELECT 1 FROM unnest(tags) t
        WHERE t NOT IN ('possible-duplicate', 'public_ip', 'keep-separate')
    );
