-- V39: Evidence citations for verdict auditability (phase 4 v1.1.0-beta)
--
-- Adds a JSONB column to incidents to store the list of evidence
-- citations attached to the verdict by the LLM. Each citation is an
-- object:
--
--   { "claim": "...",
--     "evidence_type": "alert" | "finding" | "log" | "graph_node",
--     "evidence_id": "42",
--     "excerpt": "optional snippet for UI preview" }
--
-- We use JSONB (not a separate table) because citations are always read
-- together with their incident and the volume per incident is small
-- (typically 2-8 entries). A GIN index allows for future queries like
-- "find all incidents citing alert 42" without a separate schema.
--
-- DEFAULT '[]' guarantees backward compatibility with every incident row
-- created before this migration.

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS evidence_citations JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_incidents_evidence_citations
    ON incidents USING GIN (evidence_citations);
