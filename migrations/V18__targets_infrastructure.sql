-- ThreatClaw V2 — Infrastructure multi-cibles
-- Chaque serveur/firewall du parc est une cible configurable.

CREATE TABLE IF NOT EXISTS targets (
    id              TEXT PRIMARY KEY,           -- nom unique (e.g., "srv-prod-01")
    host            TEXT NOT NULL,
    target_type     TEXT NOT NULL,              -- linux, windows, firewall, network, local
    access_type     TEXT NOT NULL,              -- ssh, winrm, api, local
    port            INTEGER NOT NULL DEFAULT 22,
    mode            TEXT NOT NULL DEFAULT 'investigator',
    credential_name TEXT,                       -- référence vers secrets
    ssh_host_key    TEXT,                       -- fingerprint SSH TOFU
    driver          TEXT,                       -- pfsense, stormshield, etc.
    allowed_actions TEXT[] DEFAULT '{}',
    tags            TEXT[] DEFAULT '{}',
    last_scan       TIMESTAMPTZ,
    last_scan_ok    BOOLEAN,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_targets_type ON targets (target_type);
CREATE INDEX idx_targets_mode ON targets (mode);
CREATE INDEX idx_targets_tags ON targets USING GIN (tags);
