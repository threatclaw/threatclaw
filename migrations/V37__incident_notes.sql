-- V37: Incident notes field for RSSI comments and audit trail
--
-- Adds a JSONB column to incidents to store a chronological list of notes
-- added by the RSSI from the dashboard or from bots (Telegram, Slack, etc.).
-- Each note is an object: {text, author, at}.
--
-- We use JSONB (not a separate table) because notes are always read together
-- with their incident, and the volume per incident is small (a handful max).

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS notes JSONB NOT NULL DEFAULT '[]'::jsonb;
