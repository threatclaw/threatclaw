-- V71: Persist EnrichmentBundle on incidents for the attack timeline UI.
--
-- Le pipeline IE construit un `EnrichmentBundle` riche (cve_details,
-- ip_reputations depuis Spamhaus/ThreatFox/cache, et enrichment_lines
-- factuelles produites par le cross-correlation FirewallSkill/SiemSkill/
-- EdrSkill — voir Phase 1d et 3 de la roadmap mai 2026). Aujourd'hui ce
-- bundle alimente uniquement le prompt L2 puis disparaît. Cette colonne
-- le persiste pour que le dashboard /incidents/[id] puisse rendre la
-- chronologie d'attaque enrichie (IPs colorisées par classification,
-- signatures Suricata, direction firewall, bytes échangés).
--
-- Format JSONB attendu (sérialisation directe de IncidentDossier.enrichment) :
-- {
--   "ip_reputations": [
--     {"ip": "...", "is_malicious": true, "classification": "malicious",
--      "source": "spamhaus", "details": "listed in DROP, EDROP"}
--   ],
--   "cve_details": [
--     {"cve_id": "CVE-...", "cvss_score": 7.5, "epss_score": 0.94,
--      "is_kev": true, "description": "..."}
--   ],
--   "threat_intel": [],
--   "enrichment_lines": [
--     "[skill-opnsense] 2026-05-05 03:55:10 — 14.102.231.203:80 → ..., sig=ET INFO Packed Executable Download, action=allowed bytes_dl=47054"
--   ]
-- }

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS enrichment JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN incidents.enrichment IS
    'EnrichmentBundle persisted at incident creation: ip_reputations, cve_details, threat_intel, enrichment_lines. Consumed by /incidents/[id] for the attack timeline. See internal/roadmap-mai.md Phase 4.';
