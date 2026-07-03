-- Doctrine inventaire v2 (2026-07-02) — deux états : declared / quarantine.
-- Voir internal/DOCTRINE_INVENTORY_GATE_V2_2026-07-02.md
--
-- On collapse les 4 valeurs V67 en 2 (+ inactive conservé pour l'historique) :
--   observed_persistent  → declared   (issu d'un CONNECTEUR authentifié —
--                          pfSense/OPNsense/Fortinet/Proxmox/… — l'opérateur a
--                          configuré des creds pour cette source, décision 5 :
--                          pare-feu via pull-API = de confiance)
--   observed_transient   → quarantine (vu passivement : syslog, scan, alerte
--                          isolée — non validé, à adopter par l'opérateur)
--   declared / inactive  → inchangés
--
-- La confiance (ML, incidents, LLM, remédiation, billing) part de `declared`.
-- La quarantaine est ingérée + stockée (puits de log) mais n'escalade pas tant
-- qu'un humain ne l'a pas adoptée.

-- 1) Remap des données existantes.
UPDATE assets SET inventory_status = 'declared'
 WHERE inventory_status = 'observed_persistent';
UPDATE assets SET inventory_status = 'quarantine'
 WHERE inventory_status = 'observed_transient';

-- 2) Nouveau défaut de colonne (une source non authentifiée naît en quarantaine).
ALTER TABLE assets ALTER COLUMN inventory_status SET DEFAULT 'quarantine';

-- 3) Trigger de "touch" : un asset qui redevient actif repasse de `inactive`
--    vers `quarantine` (et non plus `observed_transient`). On remplace le corps
--    de la fonction en place ; le reste de la logique V67 est préservé.
CREATE OR REPLACE FUNCTION tc_touch_asset_last_event() RETURNS trigger AS $$
DECLARE
    target_id   TEXT;
    target_host TEXT;
    target_ip   TEXT;
    today_str   TEXT := to_char(NOW(), 'YYYY-MM-DD');
BEGIN
    IF TG_TABLE_NAME = 'findings' THEN
        target_id := NEW.asset;
    ELSIF TG_TABLE_NAME = 'sigma_alerts' THEN
        target_host := NEW.hostname;
        target_ip   := NEW.source_ip::text;
    ELSIF TG_TABLE_NAME = 'firewall_events' THEN
        target_ip   := NEW.dst_ip::text;
    END IF;

    UPDATE assets
       SET last_event_at = NOW(),
           billable_status = CASE
               WHEN billable_status IN ('discovered','inactive') THEN 'monitored'
               ELSE billable_status
           END,
           -- inventory_status : ne jamais rétrograder un asset declared.
           -- inactive → quarantine (revenu en ligne, non validé).
           inventory_status = CASE
               WHEN inventory_status = 'inactive' THEN 'quarantine'
               ELSE inventory_status
           END,
           seen_days_30d = (
               SELECT array_agg(d ORDER BY d DESC) FROM (
                   SELECT DISTINCT d
                     FROM unnest(
                              CASE WHEN today_str = ANY(seen_days_30d)
                                   THEN seen_days_30d
                                   ELSE today_str || seen_days_30d
                              END
                          ) AS d
                     ORDER BY d DESC
                     LIMIT 30
               ) trimmed
           ),
           distinct_days_seen_30d = LEAST(30, COALESCE(array_length(seen_days_30d, 1), 0) + 1)
     WHERE id = target_id
        OR (target_host IS NOT NULL AND lower(hostname) = lower(target_host))
        OR (target_ip IS NOT NULL AND target_ip = ANY(ip_addresses));

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
