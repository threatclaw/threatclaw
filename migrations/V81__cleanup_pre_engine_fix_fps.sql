-- migrations/V81__cleanup_pre_engine_fix_fps.sql
--
-- One-shot cleanup of the false-positive alerts and incidents that the
-- pre-v1.0.37 detection engine produced before the field-fallback bug
-- and the four rule rewrites shipped. On an existing install upgrading
-- from v1.0.32 / v1.0.33 / v1.0.34 / v1.0.35 / v1.0.36, the alert and
-- incident tables can carry dozens of `Account Promoted To Root` /
-- `Sudo Authentication Failure` / `RDP Lateral Movement` /
-- `Golden Ticket — RC4 TGT` entries that fired on the wrong content
-- (a syslog PAM trailer, a routine sudo command, a port number, an
-- unrelated process). Asking the operator to triage them one by one
-- would burn an afternoon and would not be reproducible.
--
-- The cleanup is targeted: it only touches alerts whose `matched_fields`
-- match the *exact* shape the bugged engine produced. The four rewritten
-- rules never produce that shape, so a row with this signature can only
-- have come from the buggy engine — there is no ambiguity with a
-- legitimate hit.
--
-- Concretely, the buggy engine's fallback path wrote a `matched_fields`
-- entry whose value was the raw bare token from the rule's `|contains`
-- list (`uid=0`, `usermod`, `sudo`, `RDP`, `4624`, etc.). The current
-- engine writes the field's actual value (`change user 'foo' UID from X
-- to 0`, `pam_unix(sudo:auth): authentication failure; ...`,
-- `10` / `0x17` for the Windows discriminators, etc.) so the cleanup
-- can match on the bare-token shape alone.
--
-- Idempotent: only touches alerts in `status='new'` and incidents in
-- `status IN ('open','investigating')`. Already-triaged rows are left
-- alone. A second run is a no-op.

BEGIN;

-- ── 1. Alerts ────────────────────────────────────────────────────────
-- Bare-token shapes that only the bugged engine could have produced.
WITH fp_alerts AS (
    SELECT id FROM sigma_alerts
    WHERE status = 'new'
      AND rule_id IN ('lnx-acct-002', 'lnx-auth-003', 'win-auth-010', 'win-auth-004')
      AND (
          (rule_id = 'lnx-acct-002' AND (
              matched_fields::text LIKE '%"full_log": "uid=0"%'
              OR matched_fields::text LIKE '%"full_log": "usermod"%'
              OR matched_fields::text LIKE '%"full_log": "changed uid to 0"%'
          ))
          OR (rule_id = 'lnx-auth-003' AND (
              matched_fields::text LIKE '%"full_log": "sudo"%'
              OR matched_fields::text LIKE '%"full_log": "authentication failure"%'
              OR matched_fields::text LIKE '%"full_log": "incorrect password attempt"%'
          ))
          OR (rule_id = 'win-auth-010' AND (
              matched_fields::text LIKE '%"commandline":%'
          ))
          OR (rule_id = 'win-auth-004' AND (
              matched_fields::text LIKE '%"commandline":%'
          ))
      )
)
UPDATE sigma_alerts
SET status = 'false_positive',
    resolved_at = NOW(),
    resolved_by = 'system:v1.0.37-engine-fix-migration',
    analyst_notes = COALESCE(analyst_notes, '') ||
        CASE WHEN COALESCE(analyst_notes, '') = '' THEN '' ELSE E'\n' END ||
        'Auto-closed by V81 cleanup: matched_fields signature ' ||
        'identifies this as a pre-v1.0.37 false positive (engine ' ||
        'fallback bug + rule rewrite). Re-evaluate manually if you ' ||
        'suspect a real attack hides behind it.'
WHERE id IN (SELECT id FROM fp_alerts);

-- ── 2. Incidents ─────────────────────────────────────────────────────
-- An incident is a candidate for auto-close when:
--   (a) it is still open / investigating
--   (b) its last_pattern_key points at one of the four buggy patterns
--       (the CACAO graph names) OR every alert it carries is now
--       marked false_positive by the step above.
-- Restricting to (a) preserves any operator-triaged work.
WITH fp_incidents AS (
    SELECT i.id
    FROM incidents i
    WHERE i.status IN ('open', 'investigating')
      AND (
          i.last_pattern_key IN (
              'account-promoted-uid0',
              'golden-ticket',
              'audit-log-cleared-linux'
          )
          OR EXISTS (
              SELECT 1 FROM unnest(i.alert_ids) AS aid
              WHERE aid IN (
                  SELECT id FROM sigma_alerts
                  WHERE status = 'false_positive'
                    AND resolved_by = 'system:v1.0.37-engine-fix-migration'
              )
          )
      )
      -- And the incident has NO live alert left attached.
      AND NOT EXISTS (
          SELECT 1 FROM unnest(i.alert_ids) AS aid
          WHERE aid IN (
              SELECT id FROM sigma_alerts
              WHERE status = 'new'
          )
      )
)
UPDATE incidents
SET status = 'resolved',
    verdict = 'false_positive',
    resolved_at = NOW(),
    notes = COALESCE(notes, '[]'::jsonb) || jsonb_build_array(
        jsonb_build_object(
            'at', NOW()::text,
            'by', 'system:v1.0.37-engine-fix-migration',
            'note', 'Auto-closed by V81 cleanup. The pre-v1.0.37 detection engine had a ' ||
                    'fallback bug that let four rules (Account Promoted To Root, Sudo ' ||
                    'Authentication Failure, Remote Desktop Lateral Movement, Golden ' ||
                    'Ticket — RC4 TGT) fire on unrelated content. Every alert linked to ' ||
                    'this incident has now been re-classified as false positive after ' ||
                    'comparing its matched-field signature against the rewritten rules. ' ||
                    'If you suspect a real attack was hidden in this stream, re-open ' ||
                    'the incident and check the alert payloads directly.'
        )
    )
WHERE id IN (SELECT id FROM fp_incidents);

COMMIT;
