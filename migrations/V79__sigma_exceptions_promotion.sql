-- V79 — Sigma rule exceptions + promotion ladder
--
-- Phase B of the Sigma roadmap. Two related additions:
--   1) sigma_rule_exceptions — scoped allowlist that lets an operator
--      silence a rule on a specific entity (hostname / source_ip /
--      username / tag value) for a bounded period, instead of disabling
--      the whole rule. Audit-friendly: every exception has a reason,
--      an owner, an optional expiry.
--   2) Promotion ladder columns on sigma_rules — disposition (monitor /
--      detect / block) and tier (page / queue / rba_only). Together they
--      describe how an alert from this rule should be handled before any
--      log is even looked at: which sphere reads it, which sphere acts
--      on it.

-- ── Exceptions ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sigma_rule_exceptions (
    id            BIGSERIAL PRIMARY KEY,
    rule_id       TEXT NOT NULL REFERENCES sigma_rules(id) ON DELETE CASCADE,
    -- Which alert field this exception scopes against. Validated at
    -- engine load time; out-of-range values are dropped with a warning.
    scope_field   TEXT NOT NULL CHECK (scope_field IN
                   ('hostname', 'source_ip', 'username', 'tag')),
    -- The literal value to match against. Comparison is case-insensitive
    -- for textual fields (hostname / username / tag), exact for IPs.
    scope_value   TEXT NOT NULL,
    -- Free-text rationale (mandatory at API level even if NULL is
    -- allowed in DB, so a future operator can read history).
    reason        TEXT,
    owner         TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- NULL = permanent. Otherwise the engine filter ignores the row.
    expires_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS sigma_rule_exceptions_rule_idx
    ON sigma_rule_exceptions (rule_id);

-- Composite lookup index for the engine reload path. The expiry check
-- happens in the WHERE clause of the SELECT — Postgres won't accept a
-- partial index predicate that depends on NOW() since NOW() is not
-- IMMUTABLE, and the table is small enough that a full index suffices.
CREATE INDEX IF NOT EXISTS sigma_rule_exceptions_lookup_idx
    ON sigma_rule_exceptions (rule_id, scope_field, scope_value);

-- ── Promotion ladder columns ────────────────────────────────────────

-- disposition controls the operational disposition of the alert:
--   monitor — write to sigma_alerts but force level to 'informational',
--             never promote to a finding, never page anyone (shadow /
--             audit-only mode for new rules);
--   detect  — current default behaviour (write alert + promote per level
--             rules);
--   block   — write alert AND surface an explicit "auto-action
--             recommended" hint to the HITL panel (the actual blocking
--             still goes through the HITL gate).
ALTER TABLE sigma_rules
    ADD COLUMN IF NOT EXISTS disposition TEXT NOT NULL DEFAULT 'detect'
    CHECK (disposition IN ('monitor', 'detect', 'block'));

-- tier is the alerting sphere. Wired by phase D (risk-based aggregation)
-- but defined here so the column exists when rules are tagged for it
-- before D ships:
--   page     — overrides existing notification path, wakes on-call
--   queue    — current default, lands in the analyst queue
--   rba_only — no individual alert; the rule's hits feed risk_events
--              and are surfaced only when aggregated risk crosses a
--              threshold.
ALTER TABLE sigma_rules
    ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'queue'
    CHECK (tier IN ('page', 'queue', 'rba_only'));

-- Optional owner / steward of the rule — useful for "who tuned this
-- last" once rule editing lands. Defaults to NULL on legacy rows.
ALTER TABLE sigma_rules
    ADD COLUMN IF NOT EXISTS owner TEXT;

-- Promoted_at lets the audit page show the lifecycle: when did this
-- rule last move from experimental → test → stable?
ALTER TABLE sigma_rules
    ADD COLUMN IF NOT EXISTS promoted_at TIMESTAMPTZ;
