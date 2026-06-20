-- Dashboard user accounts (RBAC) — extends the existing V28 auth schema.
--
-- V28 already created dashboard_users (uuid id, totp_secret, role check) plus
-- dashboard_sessions / auth_events, but the code shipped a JSON-in-settings
-- auth store, leaving those tables unused. This migration completes the
-- table-based design by adding the RBAC columns the new implementation needs,
-- and a single-use invitation-token table. The id stays UUID; totp_secret is
-- kept for the future MFA phase. Sessions remain in the settings store for now.
ALTER TABLE dashboard_users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS granted_permissions TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS denied_permissions TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS created_by TEXT;

-- Invitation / password-reset tokens (hashed, single-use, expirable).
CREATE TABLE IF NOT EXISTS dashboard_invitations (
    token_hash   TEXT PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
    purpose      TEXT NOT NULL DEFAULT 'invite',         -- invite|reset
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
