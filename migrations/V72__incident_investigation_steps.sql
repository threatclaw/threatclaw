-- Phase 9o — Investigation timeline storage.
--
-- Each row records one verifiable step of the agent's reasoning on an
-- incident: a skill call (firewall lookup, IP reputation), a LLM call
-- (L1 ReAct triage, L2 forensic narrative), a CACAO graph step, the
-- deterministic derive_response_actions output, etc. The dashboard reads
-- this table to render a collapsible "Chronologie d'analyse" accordion
-- so the operator can audit *what the agent actually did* on this
-- incident, when, and with what payload.
--
-- The table is append-only (no UPDATE / DELETE in production code paths)
-- so the trace is immutable evidence for post-mortem reviews.
--
-- Lifecycle: rows are inserted in two phases —
--   (a) pre-incident buffering: helpers like `enrich_ip_reputations`
--       collect steps in `IncidentDossier.investigation_log` because the
--       incident_id does not exist yet. Flushed in bulk by the IE right
--       after `create_incident`.
--   (b) post-incident streaming: `forensic_enricher`, graph workers,
--       remediation_engine call `append_investigation_step` directly with
--       the now-known incident_id.

CREATE TABLE IF NOT EXISTS incident_investigation_steps (
    id          BIGSERIAL PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    -- 'skill_call' | 'llm_call' | 'graph_step' | 'derive_actions'
    -- | 'incident_created' | 'remediation_executed' | 'note'
    kind        TEXT    NOT NULL,
    -- e.g. 'skill-greynoise', 'skill-opnsense', 'skill-velociraptor'
    -- NULL for non-skill steps (LLM calls, graph nodes).
    skill_id    TEXT,
    -- One-line summary the operator will see in the accordion header.
    summary     TEXT    NOT NULL,
    -- Structured detail for the expanded view: raw API response, prompt
    -- length, derived action list, etc. Capped to 10 KB application-side
    -- to keep the row reasonably sized.
    payload     JSONB   NOT NULL DEFAULT '{}'::jsonb,
    -- Wall-clock duration of the step. NULL when not measured (e.g. for
    -- buffered pre-incident steps, the timing is in the payload).
    duration_ms INTEGER,
    -- 'ok' | 'error' | 'timeout' | 'no_match' | 'fallback'
    status      TEXT    NOT NULL DEFAULT 'ok',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS incident_investigation_steps_incident_idx
    ON incident_investigation_steps (incident_id, created_at ASC);

CREATE INDEX IF NOT EXISTS incident_investigation_steps_kind_idx
    ON incident_investigation_steps (kind);

COMMENT ON TABLE incident_investigation_steps IS
    'Phase 9o investigation timeline — append-only audit trail of every '
    'agent action on an incident. Read by the dashboard to render the '
    '"Chronologie d''analyse" accordion.';

COMMENT ON COLUMN incident_investigation_steps.kind IS
    'Step taxonomy: skill_call | llm_call | graph_step | derive_actions | incident_created | remediation_executed | note';

COMMENT ON COLUMN incident_investigation_steps.status IS
    'Outcome of the step: ok | error | timeout | no_match | fallback';
