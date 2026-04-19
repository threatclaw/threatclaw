-- V38: LLM validation mode setting for anti-hallucination grounding layer (v1.1.0-beta)
--
-- This setting controls the behavior of the LLM output validators:
--   - "off"     : no validation (legacy behavior v1.0.x)
--   - "lenient" : validate + log errors, accept verdict with warnings
--   - "strict"  : validate + downgrade verdict on errors
--
-- Default is "off" to preserve v1.0.x behavior until the grounding layer
-- is fully rolled out (phase by phase through v1.1.0-beta).
--
-- The setting is seeded here idempotently so every instance has a known
-- starting point. Administrators can change it via the dashboard
-- (Config > Advanced) or directly via the settings API.

INSERT INTO settings (user_id, key, value)
VALUES ('_system', 'tc_config_llm_validation_mode', '"off"'::jsonb)
ON CONFLICT (user_id, key) DO NOTHING;
