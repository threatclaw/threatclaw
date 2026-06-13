-- V77 — Saved hunt queries
--
-- Stores user-named filter presets for the Hunt panel. `params` keeps the
-- full filter payload (hostname/tag/q/from/to) as JSONB so the schema
-- doesn't need to evolve every time we add a new filter dimension.

CREATE TABLE IF NOT EXISTS hunt_saved_queries (
    id          BIGSERIAL PRIMARY KEY,
    user_id     TEXT,
    name        TEXT NOT NULL,
    params      JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS hunt_saved_queries_user_idx
    ON hunt_saved_queries (user_id, created_at DESC);
