-- V70: Forensic enrichment timestamp for async post-confirmed analysis.
--
-- The forensic_enricher background task (see forensic_enricher.rs) picks
-- confirmed incidents with NULL forensic_enriched_at, runs Foundation-Sec
-- Reasoning Q8_0 over them (no time constraint, up to 20 min), then updates
-- summary / mitre_techniques / evidence_citations and stamps this column.
--
-- NULL = not yet enriched (pending or verdict != confirmed).
-- NOT NULL = enriched (or explicitly skipped for very old incidents).
--
-- Idempotent: if the core restarts mid-enrichment, the column stays NULL
-- and the next scheduler pass picks it up cleanly.

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS forensic_enriched_at TIMESTAMPTZ;

COMMENT ON COLUMN incidents.forensic_enriched_at IS
    'Set when Foundation-Sec Reasoning Q8_0 has completed async forensic enrichment. NULL = pending.';
