-- Ship fresh installs with grounding in Strict mode. See roadmap §4.2.
--
-- Background: the anti-hallucination grounding layer has three modes — Off,
-- Lenient, and Strict — persisted under `tc_config_llm_validation_mode` in
-- the settings table. The code default was Off (fail-safe), so every beta
-- deploy that skipped the Config page ran without grounding enforcement.
--
-- This migration is idempotent and *non-destructive*:
--   - If the setting is already set (even to 'off' or 'lenient'), leave it.
--     Operators who explicitly picked a mode keep their choice.
--   - If the setting is absent, insert 'strict' so new deploys opt into
--     grounding by default.
--
-- Rationale for Strict by default: NIS2 audit trail expects every LLM
-- statement to be cited against a DB source. A silent Off can slip an
-- hallucinated CVE ID into an incident note — hard failure beats soft.
--
-- Operators can always dial back via the Config page or directly:
--   UPDATE settings SET value = '"lenient"'::jsonb
--   WHERE user_id = '_system' AND key = 'tc_config_llm_validation_mode';

INSERT INTO settings (user_id, key, value, updated_at)
VALUES ('_system', 'tc_config_llm_validation_mode', '"strict"'::jsonb, NOW())
ON CONFLICT (user_id, key) DO NOTHING;
