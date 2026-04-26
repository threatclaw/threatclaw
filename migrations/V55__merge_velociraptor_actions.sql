-- V55: skill-velociraptor-actions was a placeholder premium SKU used
-- to validate the Stripe + license flow. C17 merges its 3 declared
-- actions (quarantine, kill_process, isolate_host) into the main
-- skill-velociraptor manifest under the new `hitl_actions` section.
-- The license model pivots from "per-skill premium" to "global HITL
-- Action Pack" — see ADR-049 (to be written) for the doctrine.
--
-- This migration:
-- 1. Drops the orphaned skill_configs rows for skill-velociraptor-actions
--    (operators who installed it just to test the purchase flow).
-- 2. Cleans the _skills.installed / _skills.disabled JSON arrays so the
--    catalog state stops listing a skill that no longer exists.
-- 3. Idempotent: WHERE clauses match the old id only.

DELETE FROM skill_configs WHERE skill_id = 'skill-velociraptor-actions';

UPDATE skill_configs
SET value = REPLACE(REPLACE(value, ',"skill-velociraptor-actions"', ''), '"skill-velociraptor-actions",', '')
WHERE skill_id = '_skills'
  AND key IN ('installed', 'disabled')
  AND value LIKE '%skill-velociraptor-actions%';

-- After the REPLACE there might be a stray "skill-velociraptor-actions"
-- if it was the only entry. Strip the bare token too.
UPDATE skill_configs
SET value = REPLACE(value, '"skill-velociraptor-actions"', '')
WHERE skill_id = '_skills'
  AND key IN ('installed', 'disabled');

-- Clean up any [, ,] artifacts produced by the replaces above.
UPDATE skill_configs
SET value = REPLACE(REPLACE(value, ',,', ','), '[,', '[')
WHERE skill_id = '_skills'
  AND key IN ('installed', 'disabled')
  AND (value LIKE '%,,%' OR value LIKE '[,%');

UPDATE skill_configs
SET value = REPLACE(value, ',]', ']')
WHERE skill_id = '_skills'
  AND key IN ('installed', 'disabled')
  AND value LIKE '%,]%';
