-- Sprint 1 #2 — verdict source tracking.
--
-- Until now, the incidents card frontend distinguished a graph-decided
-- verdict from a ReAct LLM verdict by parsing a "[graph] " prefix in the
-- title. Brittle (locale, future title changes). This column persists the
-- source explicitly so the frontend can read it directly.
--
-- Values: 'graph' | 'react' | 'manual'. NULL on legacy rows; the worker
-- sets it on every new incident. Frontend treats NULL as 'react' (legacy
-- default) for backward compat with the 88 incidents already in DB.

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS verdict_source TEXT;
