-- V23: Apache AGE — Graph Intelligence for ThreatClaw
-- Note: AGE extension and graph creation are handled at runtime by the application,
-- not in this migration, because AGE requires LOAD and SET per-session
-- which are not compatible with migration runners.
-- This migration only documents the schema.

-- The graph 'threat_graph' with STIX-inspired vertex/edge labels
-- is created by the Rust code at first health check.
-- See src/graph/threat_graph.rs for the schema definition.

SELECT 1;  -- No-op migration (graph managed at runtime)
