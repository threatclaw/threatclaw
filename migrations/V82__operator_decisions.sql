-- migrations/V82__operator_decisions.sql
--
-- Schema for the v1.0.38 Operator decisions workflow. The dashboard
-- previously surfaced three vague buttons (Archive / FP / Ignore) that
-- left the operator unsure what each one actually did. The redesign
-- replaces them with four concrete actions:
--
--   - Resolve         — "I handled this. Real incident, now closed."
--   - False Positive  — "Detection was wrong" (with an optional
--                       follow-up that creates a sigma exception
--                       scoped to the asset, the user or the
--                       source IP).
--   - Accept Risk     — "Real, but the business accepts the risk."
--   - Snooze          — "Remind me in N hours."
--
-- Plus an admin-only Delete (no schema change — handled in the
-- application layer with an audit trail).
--
-- The migration:
--   (1) Adds three nullable columns: `snoozed_until` for the snooze
--       deadline, `decision_reason` for the free-text justification,
--       and `exception_scope` for the FP-with-exception payload (so
--       the rule-exception write that follows is reproducible).
--   (2) Maps the existing `status='closed'` rows to `status='resolved'`
--       so the dashboard's filter only has to know about two terminal
--       states going forward.
--   (3) Adds an index on `snoozed_until` to let the wake-up scanner
--       sweep efficiently.

BEGIN;

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS snoozed_until timestamptz,
    ADD COLUMN IF NOT EXISTS decision_reason text,
    ADD COLUMN IF NOT EXISTS exception_scope jsonb;

COMMENT ON COLUMN incidents.snoozed_until IS
    'When the snooze expires and the incident returns to the active '
    'queue. NULL when the incident is not snoozed. Status moves to '
    '''snoozed'' while a future value is set here.';

COMMENT ON COLUMN incidents.decision_reason IS
    'Free-text justification typed by the operator when they pick '
    'Accept Risk / False Positive / Snooze. Persisted alongside the '
    'verdict so the next operator sees why a previous one closed it.';

COMMENT ON COLUMN incidents.exception_scope IS
    'When the operator combines a False Positive verdict with the '
    '"create exception" follow-up, this column records the scope '
    'they chose (asset / username / source_ip) so the rule-exception '
    'write that follows is reproducible from this row alone. '
    'Shape: {"kind":"asset"|"username"|"source_ip","value":"..."} '
    'or NULL when no exception was created.';

-- (2) Map historical `status='closed'` rows to `status='resolved'`.
-- The two terms have been used interchangeably until now; the
-- dashboard filter goes to a single canonical value from v1.0.38.
UPDATE incidents SET status = 'resolved' WHERE status = 'closed';

-- (3) Index on snoozed_until so the wake-up scanner can find the
-- expired snoozes with a simple range scan. Partial index: only the
-- still-snoozed rows are indexed, so an exhausted snooze trail does
-- not bloat the index.
CREATE INDEX IF NOT EXISTS idx_incidents_snoozed_until
    ON incidents (snoozed_until)
    WHERE snoozed_until IS NOT NULL;

COMMIT;
