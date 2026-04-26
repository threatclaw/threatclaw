-- V53: skill-pfsense was a unified manifest covering both pfSense and
-- OPNsense via a `fw_type` config field. C12 splits the catalog into
-- two dedicated skills (skill-pfsense, skill-opnsense) so the operator
-- picks the one that matches their gear without a confusing dropdown.
--
-- This migration moves any existing skill-pfsense rows whose stored
-- fw_type is 'opnsense' over to skill-opnsense. Rows for pfSense itself
-- are left in place (they keep skill_id=skill-pfsense).
--
-- Idempotent: re-running this migration after a partial move is safe
-- because the WHERE clauses target only rows still under the old id
-- with the OPNsense fw_type marker.

-- Determine if the current install is OPNsense (look for the marker
-- row first, then move every related skill-pfsense config row).
DO $$
DECLARE
    is_opnsense boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM skill_configs
        WHERE skill_id = 'skill-pfsense'
          AND key = 'fw_type'
          AND value = 'opnsense'
    ) INTO is_opnsense;

    IF is_opnsense THEN
        RAISE NOTICE 'V53: detected OPNsense flavour, migrating skill-pfsense → skill-opnsense';

        -- Move every key from skill-pfsense to skill-opnsense, except
        -- the now-internal fw_type which the new manifests pin in code.
        UPDATE skill_configs
        SET skill_id = 'skill-opnsense'
        WHERE skill_id = 'skill-pfsense'
          AND key <> 'fw_type';

        -- Drop the fw_type row (no longer surfaced — backend infers
        -- from the skill_id).
        DELETE FROM skill_configs
        WHERE skill_id = 'skill-pfsense'
          AND key = 'fw_type';

        -- Move the global "_skills" installed/disabled lists too: if
        -- the operator had skill-pfsense in their installed array,
        -- rename it to skill-opnsense.
        UPDATE skill_configs
        SET value = REPLACE(value, '"skill-pfsense"', '"skill-opnsense"')
        WHERE skill_id = '_skills'
          AND key IN ('installed', 'disabled');
    END IF;
END
$$;
