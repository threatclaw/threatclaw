-- Suppression rules v1 — TTL mandatory + audit trail. See ADR-047.
--
-- CEL-based predicates (ADR-046) évalués côté Rust contre chaque
-- event ingéré avant insertion. Drop silencieux, downgrade ou tag.
--
-- Toute rule a :
--  * une raison obligatoire ≥10 chars (NIS2-auditable)
--  * une expiration par défaut à 90 jours (pas de cimetière)
--  * un audit trail séparé (create/update/disable/expire)
--  * un compteur de matches pour détecter les rules stale (count=0 après 7j)

CREATE TABLE IF NOT EXISTS suppression_rules (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT NOT NULL,
    predicate        JSONB NOT NULL,
    predicate_source TEXT NOT NULL,
    action           TEXT NOT NULL DEFAULT 'drop'
                     CHECK (action IN ('drop', 'downgrade', 'tag')),
    severity_cap     TEXT
                     CHECK (severity_cap IS NULL
                            OR severity_cap IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    scope            TEXT NOT NULL DEFAULT 'global',
    reason           TEXT NOT NULL
                     CHECK (length(reason) >= 10),
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '90 days'),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    match_count      BIGINT NOT NULL DEFAULT 0,
    last_match_at    TIMESTAMPTZ,
    source           TEXT NOT NULL DEFAULT 'manual'
                     CHECK (source IN ('manual','suggested','imported_sigma'))
);

CREATE INDEX IF NOT EXISTS idx_supp_active
    ON suppression_rules (enabled, expires_at)
    WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_supp_scope
    ON suppression_rules (scope);
CREATE INDEX IF NOT EXISTS idx_supp_stale
    ON suppression_rules (match_count, created_at)
    WHERE enabled = TRUE;

-- ── Audit trail séparé ─────────────────────────────────────
-- Retention infinie (1 ligne/seconde max en prod, négligeable).

CREATE TABLE IF NOT EXISTS suppression_audit (
    id        BIGSERIAL PRIMARY KEY,
    rule_id   UUID NOT NULL REFERENCES suppression_rules(id) ON DELETE CASCADE,
    action    TEXT NOT NULL
              CHECK (action IN ('created','updated','disabled','enabled',
                                'expired','deleted','matched_milestone')),
    diff      JSONB,
    actor     TEXT NOT NULL,
    at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    note      TEXT
);
CREATE INDEX IF NOT EXISTS idx_supp_audit_rule
    ON suppression_audit (rule_id, at DESC);

-- ── Trigger LISTEN/NOTIFY pour reload du moteur en mémoire ──

CREATE OR REPLACE FUNCTION suppression_notify_change()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('suppression_update',
                      COALESCE(NEW.id, OLD.id)::text);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_suppression_notify ON suppression_rules;
CREATE TRIGGER trg_suppression_notify
    AFTER INSERT OR UPDATE OR DELETE ON suppression_rules
    FOR EACH ROW
    EXECUTE FUNCTION suppression_notify_change();

-- ── Audit auto sur create/disable/expire ────────────────────

CREATE OR REPLACE FUNCTION suppression_audit_on_change()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO suppression_audit (rule_id, action, actor, note)
        VALUES (NEW.id, 'created', NEW.created_by, NEW.reason);
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.enabled = TRUE AND NEW.enabled = FALSE THEN
            INSERT INTO suppression_audit (rule_id, action, actor)
            VALUES (NEW.id, 'disabled', 'system');
        ELSIF OLD.enabled = FALSE AND NEW.enabled = TRUE THEN
            INSERT INTO suppression_audit (rule_id, action, actor)
            VALUES (NEW.id, 'enabled', 'system');
        ELSE
            INSERT INTO suppression_audit (rule_id, action, actor, diff)
            VALUES (NEW.id, 'updated', 'system',
                    jsonb_build_object(
                        'name_changed',   OLD.name IS DISTINCT FROM NEW.name,
                        'pred_changed',   OLD.predicate IS DISTINCT FROM NEW.predicate,
                        'action_changed', OLD.action IS DISTINCT FROM NEW.action,
                        'scope_changed',  OLD.scope IS DISTINCT FROM NEW.scope,
                        'expires_changed',OLD.expires_at IS DISTINCT FROM NEW.expires_at
                    ));
        END IF;
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_suppression_audit ON suppression_rules;
CREATE TRIGGER trg_suppression_audit
    AFTER INSERT OR UPDATE ON suppression_rules
    FOR EACH ROW
    EXECUTE FUNCTION suppression_audit_on_change();
