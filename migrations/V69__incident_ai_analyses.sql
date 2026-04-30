-- V69: Layered AI analyses for incidents (Phase G4 — investigation workspace).
--
-- Stores per-incident LLM opinions from 3 sources:
--   react_l1 : L1 triage triggered post-graph or on RSSI demand
--   react_l2 : L2 forensic deep analysis on demand
--   manual   : RSSI annotation
--
-- Kept separate from incidents.investigation_log (which stores raw ReAct
-- tool calls) so the frontend can render clean analysis cards without
-- parsing the full log.
--
-- The graph verdict stays in graph_executions.trace + incidents.verdict_source.
-- This table only stores the LLM opinion layers that come AFTER the graph.

CREATE TABLE IF NOT EXISTS incident_ai_analyses (
    id           SERIAL PRIMARY KEY,
    incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    source       TEXT NOT NULL CHECK (source IN ('react_l1', 'react_l2', 'manual')),
    confidence   REAL,                     -- 0.0 to 1.0
    summary      TEXT NOT NULL,            -- natural language summary
    skills_used  TEXT[] NOT NULL DEFAULT '{}',
    mitre_added  TEXT[] NOT NULL DEFAULT '{}',
    raw_output   JSONB,                    -- full LLM output for debug
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS incident_ai_analyses_incident_idx
    ON incident_ai_analyses (incident_id, created_at DESC);

COMMENT ON TABLE incident_ai_analyses IS
    'Per-incident layered AI opinions (Phase G4). Sources: react_l1, react_l2, manual.';
COMMENT ON COLUMN incident_ai_analyses.source IS
    'react_l1: L1 triage | react_l2: L2 forensic | manual: RSSI note';
