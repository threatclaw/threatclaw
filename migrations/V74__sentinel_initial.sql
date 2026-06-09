-- migrations/V74__sentinel_initial.sql
-- Storage for skill-microsoft-sentinel: generic external-id columns on incidents
-- (reusable by any SIEM connector), plus 4 satellite tables for Sentinel-specific
-- metadata, alerts, entities, and a TTL cache of analytic rules.

-- 1. Generic external identification on incidents (also used by graph_defender
--    in phase B of skill-microsoft-graph)
ALTER TABLE incidents
  ADD COLUMN IF NOT EXISTS external_id     TEXT,
  ADD COLUMN IF NOT EXISTS external_source TEXT,
  ADD COLUMN IF NOT EXISTS external_url    TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS incidents_external_uidx
  ON incidents (external_source, external_id)
  WHERE external_id IS NOT NULL;

-- 2. Sentinel incident metadata (1:1 with incidents)
CREATE TABLE IF NOT EXISTS sentinel_incident_metadata (
  incident_id              INTEGER PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
  sentinel_incident_id     UUID NOT NULL,
  sentinel_incident_number INT  NOT NULL,
  sentinel_etag            TEXT NOT NULL,
  workspace_id             UUID NOT NULL,
  provider_name            TEXT NOT NULL,
  provider_incident_id     TEXT,
  provider_incident_url    TEXT,
  related_analytic_rule_ids TEXT[] NOT NULL DEFAULT '{}',
  mitre_tactics            TEXT[] NOT NULL DEFAULT '{}',
  mitre_techniques         TEXT[] NOT NULL DEFAULT '{}',
  sentinel_status          TEXT,
  sentinel_classification  TEXT,
  sentinel_classification_reason TEXT,
  sentinel_last_modified_utc TIMESTAMPTZ NOT NULL,
  sentinel_comment_posted  BOOLEAN NOT NULL DEFAULT FALSE,
  inserted_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sim_workspace_idx ON sentinel_incident_metadata (workspace_id);
CREATE INDEX IF NOT EXISTS sim_last_modified_idx ON sentinel_incident_metadata (sentinel_last_modified_utc DESC);

-- 3. Sentinel alerts (N:1 with incidents)
CREATE TABLE IF NOT EXISTS sentinel_alerts (
  id                    UUID PRIMARY KEY,
  incident_id           INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  system_alert_id       UUID NOT NULL UNIQUE,
  provider_alert_id     TEXT NOT NULL,
  provider_name         TEXT NOT NULL,
  vendor_name           TEXT,
  product_name          TEXT,
  alert_display_name    TEXT NOT NULL,
  description           TEXT,
  severity              TEXT NOT NULL,
  confidence_level      TEXT,
  status                TEXT,
  tactics               TEXT[] NOT NULL DEFAULT '{}',
  techniques            TEXT[] NOT NULL DEFAULT '{}',
  alert_link            TEXT,
  start_time_utc        TIMESTAMPTZ,
  end_time_utc          TIMESTAMPTZ,
  time_generated        TIMESTAMPTZ,
  additional_data       JSONB,
  dedup_merged_with_graph BOOLEAN NOT NULL DEFAULT FALSE,
  graph_alert_id        UUID,
  inserted_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sa_provider_alert_id_idx ON sentinel_alerts (provider_alert_id);
CREATE INDEX IF NOT EXISTS sa_incident_idx ON sentinel_alerts (incident_id);

-- 4. Sentinel entities (N:1 with incidents): raw forensic evidence
CREATE TABLE IF NOT EXISTS sentinel_entities (
  id                  UUID PRIMARY KEY,
  incident_id         INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  kind                TEXT NOT NULL,
  friendly_name       TEXT,
  raw_properties      JSONB NOT NULL,
  asset_id            UUID,
  inserted_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS se_incident_idx ON sentinel_entities (incident_id);
CREATE INDEX IF NOT EXISTS se_kind_idx ON sentinel_entities (kind);

-- 5. Analytic rules TTL cache
CREATE TABLE IF NOT EXISTS sentinel_analytic_rules_cache (
  rule_id          UUID NOT NULL,
  workspace_id     UUID NOT NULL,
  kind             TEXT,
  display_name     TEXT,
  description      TEXT,
  severity         TEXT,
  tactics          TEXT[] NOT NULL DEFAULT '{}',
  techniques       TEXT[] NOT NULL DEFAULT '{}',
  query            TEXT,
  query_frequency  TEXT,
  query_period     TEXT,
  trigger_operator TEXT,
  trigger_threshold INT,
  enabled          BOOLEAN,
  raw_json         JSONB,
  fetched_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (rule_id, workspace_id)
);
