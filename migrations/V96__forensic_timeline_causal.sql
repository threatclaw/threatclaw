-- V96 — DFIR attack map : liens causaux sur la timeline forensique.
--
-- Pour passer d'une timeline À PLAT à un vrai GRAPHE DE PROVENANCE (arbre de
-- process keyé sur ProcessGuid + arêtes typées), chaque événement transporte
-- les clés qui permettent de tisser les arêtes causales :
--   proc_guid    : identité stable du process concerné (Sysmon ProcessGuid — JAMAIS le PID)
--   parent_guid  : process parent (arête SPAWNED parent -> enfant)
--   related_to   : cible d'une arête non-spawn (IP/domaine/fichier/process injecté/lsass)
-- Voir internal/PLAN_NATIVE_DFIR.md + recherche attack-graph (process tree spine).

ALTER TABLE forensic_timeline
    ADD COLUMN IF NOT EXISTS proc_guid   TEXT,
    ADD COLUMN IF NOT EXISTS parent_guid TEXT,
    ADD COLUMN IF NOT EXISTS related_to  TEXT;
