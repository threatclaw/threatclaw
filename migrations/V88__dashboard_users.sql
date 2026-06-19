-- Dashboard user accounts (RBAC). Replaces the JSON-in-settings auth store.
-- The single existing admin is migrated at boot by an idempotent routine
-- that reads _auth/user_<email> from settings and inserts it here.
CREATE TABLE IF NOT EXISTS dashboard_users (
    id                    TEXT PRIMARY KEY,
    email                 TEXT NOT NULL UNIQUE,
    display_name          TEXT NOT NULL DEFAULT '',
    password_hash         TEXT,                          -- NULL while status='invited'
    role                  TEXT NOT NULL DEFAULT 'viewer',
    status                TEXT NOT NULL DEFAULT 'active', -- active|disabled|invited
    must_change_password  BOOLEAN NOT NULL DEFAULT false,
    granted_permissions   TEXT[] NOT NULL DEFAULT '{}',
    denied_permissions    TEXT[] NOT NULL DEFAULT '{}',
    failed_attempts       INTEGER NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    created_by            TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Invitation / password-reset tokens (hashed, single-use, expirable).
CREATE TABLE IF NOT EXISTS dashboard_invitations (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
    purpose      TEXT NOT NULL DEFAULT 'invite',         -- invite|reset
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
