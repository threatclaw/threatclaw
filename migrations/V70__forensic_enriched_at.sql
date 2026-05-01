-- V70: Forensic enrichment timestamp.
-- NULL = not yet enriched. NOT NULL = enrichment complete (or skipped).
-- The background enricher stamps this after producing the deep forensic analysis.

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS forensic_enriched_at TIMESTAMPTZ;

COMMENT ON COLUMN incidents.forensic_enriched_at IS
    'Stamped by the forensic enricher when deep analysis is complete. NULL = pending.';
