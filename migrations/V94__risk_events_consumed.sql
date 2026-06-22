-- V94 — RBA re-fire fix : marquer les risk_events comme "consommés".
--
-- Bug (Phase D1) : l'agrégateur re-lit TOUS les risk_events de la fenêtre (7j)
-- à chaque cycle. La dédup `find_open_incident_for_asset` ne bloque un nouveau
-- notable que tant qu'un incident reste OUVERT sur l'asset. Dès qu'il est
-- résolu/fermé, les mêmes vieux events (toujours dans la fenêtre) re-franchissent
-- le seuil → nouvel incident → boucle (#10 → #12 → #13 → #14 sur le même signal).
--
-- Correctif : un event ne doit financer QU'UN seul notable. Quand un notable est
-- créé, ses events contributeurs sont marqués consommés (`consumed_at` + lien
-- `incident_id`) et l'agrégateur ne les relit plus. De nouveaux events repartent
-- de zéro et peuvent légitimement financer un notable ultérieur.

ALTER TABLE risk_events
    ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS incident_id INTEGER;

-- Hot path de l'agrégateur : il ne lit QUE les events non consommés dans la
-- fenêtre. Index partiel → le scan reste serré même quand l'historique consommé
-- grossit. Remplace en pratique idx_risk_events_object_time pour ce chemin.
CREATE INDEX IF NOT EXISTS idx_risk_events_unconsumed
    ON risk_events (risk_object, created_at DESC)
    WHERE consumed_at IS NULL;
