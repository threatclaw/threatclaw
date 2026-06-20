-- Cross-asset correlation columns for the incident model.
--
-- Until now an incident was strictly mono-asset: a multi-host attack (lateral
-- movement, or a campaign hitting several machines) produced N disconnected
-- incidents, and the IncidentDossier's `related_assets` / `campaign_id` — already
-- carried by the CorrelationBundle struct — were computed by the lateral/campaign
-- detectors and then thrown away because there was nowhere to persist them.
--
-- These additive columns let an incident reference the other assets touched by
-- the same attack so a multi-host intrusion reads as ONE story instead of N.
--   related_assets : JSON array of canonical asset ids (excluding the primary).
--   campaign_id    : stable id shared by incidents attributed to one campaign.
--
-- See detection-chain audit 2026-06-20.
ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS related_assets JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS campaign_id TEXT;
