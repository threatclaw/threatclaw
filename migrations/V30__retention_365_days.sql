-- ═══════════════════════════════════════════════════════════
-- V30 — Rétention logs 365 jours (conformité LCEN + NIS2)
--
-- Avant : logs 30j, alertes 90j
-- Après : logs 365j, alertes 730j (2 ans)
--
-- Justification :
--   LCEN (hébergeur)     : 1 an minimum
--   NIS2 (si applicable) : 18 mois recommandé
--   ANSSI                : 6-12 mois minimum
--   Assurance cyber      : souvent 12 mois exigé
--   APT dwell time moyen : 6-9 mois → besoin de remonter
-- ═══════════════════════════════════════════════════════════

UPDATE retention_config SET retention_days = 365 WHERE table_name = 'logs';
UPDATE retention_config SET retention_days = 730 WHERE table_name = 'sigma_alerts';
UPDATE retention_config SET retention_days = 730 WHERE table_name = 'findings';
