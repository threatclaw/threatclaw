-- migrations/V81__cleanup_pre_engine_fix_fps.sql
--
-- One-shot cleanup of the false-positive alerts and incidents produced
-- by the pre-v1.0.37 detection engine. Four rewritten rules
-- (Account Promoted To Root, Sudo Authentication Failure, Remote
-- Desktop Lateral Movement, Golden Ticket — RC4 TGT) used to fire on
-- the rule's bare contains tokens — every operator that ran a
-- v1.0.32 → v1.0.36 engine has those rows in their alert and incident
-- tables and would otherwise need to triage them manually on upgrade.
--
-- The discriminator is the matched_field VALUE itself. The buggy
-- engine recorded the literal contains token (`uid=0`, `usermod`,
-- `sudo`, `4624`, `RDP`, `RC4`, `0x17`, …). The rewritten rules
-- always record the field's actual content (`change user 'foo' UID
-- from X to 0`, a full PAM trailer, the LogonType / EncryptionType
-- field name). The two shapes never overlap, so matching on the bare
-- token list lets us auto-close FPs without touching a legitimate hit.
--
-- Three safety constraints, in line with the security review:
--   1. Pin VALUES, not just keys. Match `commandline = '4624'` etc.,
--      never `commandline = anything`.
--   2. Only auto-close an incident when *every* linked alert was
--      flagged by THIS migration. An analyst's prior triage on any
--      alert blocks the auto-close.
--   3. Stay inside the four rewritten rules' pattern_keys. Other
--      patterns (audit-log-cleared, ml-anomaly, …) get their own
--      dedicated migration when they need one.
--
-- Idempotent — operator-triaged rows (status outside `new` /
-- `open` / `investigating`) are skipped. Re-running V81 is a no-op.

BEGIN;

-- ── 1. Alerts ────────────────────────────────────────────────────────
-- Bare-token shapes the buggy engine produced. Each rule lists the
-- exact pre-rewrite contains tokens; only an alert whose matched_field
-- value matches one of those tokens is auto-closed.
WITH fp_alerts AS (
    SELECT id FROM sigma_alerts
    WHERE status = 'new'
      AND rule_id IN (
            'lnx-acct-002',
            'lnx-auth-003',
            'win-auth-010',
            'win-auth-004'
      )
      AND (
          -- lnx-acct-002 old tokens: usermod / uid=0 / changed uid to 0
          (rule_id = 'lnx-acct-002' AND (
              matched_fields::text LIKE '%"full_log": "uid=0"%'
              OR matched_fields::text LIKE '%"full_log": "usermod"%'
              OR matched_fields::text LIKE '%"full_log": "changed uid to 0"%'
          ))
          -- lnx-auth-003 old tokens: sudo / authentication failure /
          -- incorrect password attempt
          OR (rule_id = 'lnx-auth-003' AND (
              matched_fields::text LIKE '%"full_log": "sudo"%'
              OR matched_fields::text LIKE '%"full_log": "authentication failure"%'
              OR matched_fields::text LIKE '%"full_log": "incorrect password attempt"%'
          ))
          -- win-auth-010 old tokens: 4624 / RemoteInteractive / Type 10 / RDP
          OR (rule_id = 'win-auth-010' AND (
              matched_fields::text LIKE '%"commandline": "4624"%'
              OR matched_fields::text LIKE '%"commandline": "RemoteInteractive"%'
              OR matched_fields::text LIKE '%"commandline": "Type 10"%'
              OR matched_fields::text LIKE '%"commandline": "RDP"%'
              OR matched_fields::text LIKE '%"commandline": "23"%'   -- token-fragment fallback
          ))
          -- win-auth-004 old tokens: 4768 / 4769 / 0x17 / RC4 / krbtgt / golden
          OR (rule_id = 'win-auth-004' AND (
              matched_fields::text LIKE '%"commandline": "4768"%'
              OR matched_fields::text LIKE '%"commandline": "4769"%'
              OR matched_fields::text LIKE '%"commandline": "0x17"%'
              OR matched_fields::text LIKE '%"commandline": "RC4"%'
              OR matched_fields::text LIKE '%"commandline": "krbtgt"%'
              OR matched_fields::text LIKE '%"commandline": "golden"%'
          ))
      )
)
UPDATE sigma_alerts
SET status = 'false_positive',
    resolved_at = NOW(),
    resolved_by = 'system:v1.0.37-engine-fix-migration',
    analyst_notes = COALESCE(analyst_notes, '') ||
        CASE WHEN COALESCE(analyst_notes, '') = '' THEN '' ELSE E'\n' END ||
        'Auto-closed by V81 cleanup: matched_fields value matches the ' ||
        'pre-v1.0.37 engine signature for this rule (bare contains token ' ||
        'instead of full field content). Re-evaluate manually if you ' ||
        'suspect a real attack hides behind it.'
WHERE id IN (SELECT id FROM fp_alerts);

-- ── 2. Incidents ─────────────────────────────────────────────────────
-- Only auto-close an incident when *every* alert it carries was just
-- flagged FP by this migration. As soon as one linked alert is in any
-- other state (operator-triaged FP from a different source, still
-- 'new', or anything else), the incident is left alone so analyst
-- work cannot be silently overwritten.
WITH fp_incidents AS (
    SELECT i.id
    FROM incidents i
    WHERE i.status IN ('open', 'investigating')
      AND i.last_pattern_key IN (
          'account-promoted-uid0',
          'golden-ticket'
      )
      -- Every linked alert must be FP-flagged BY THIS migration.
      AND NOT EXISTS (
          SELECT 1 FROM unnest(i.alert_ids) AS aid
          WHERE aid NOT IN (
              SELECT id FROM sigma_alerts
              WHERE status = 'false_positive'
                AND resolved_by = 'system:v1.0.37-engine-fix-migration'
          )
      )
      AND array_length(i.alert_ids, 1) > 0
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
                    'this incident was a textbook instance of that bug. If you suspect ' ||
                    'a real attack was hidden in this stream, re-open the incident and ' ||
                    'check the alert payloads directly.'
        )
    )
WHERE id IN (SELECT id FROM fp_incidents);

COMMIT;
