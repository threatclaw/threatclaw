-- V52: scan_schedules — recurring scan configurations.
--
-- Each row is a "recurring scan request" the operator created via the
-- /scans Planifiés tab. A dedicated tick (see src/scans/scheduler.rs)
-- runs every 60 s, finds rows where next_run_at <= now() AND enabled,
-- enqueues a scan_queue row, then bumps next_run_at to the next slot.
--
-- We deliberately avoid full cron expressions (too easy to mess up for
-- a non-sysadmin user). Frequency is one of: hourly / daily / weekly /
-- monthly with simple hour/minute/day knobs.

CREATE TABLE IF NOT EXISTS scan_schedules (
    id              BIGSERIAL PRIMARY KEY,
    scan_type       TEXT NOT NULL,                  -- nmap_fingerprint | trivy_image | ...
    target          TEXT NOT NULL,
    name            TEXT,                           -- human label "Scan hebdo /24 LAN"
    frequency       TEXT NOT NULL,                  -- hourly | daily | weekly | monthly
    minute          INT NOT NULL DEFAULT 0,         -- 0..59
    hour            INT,                            -- 0..23 (daily/weekly/monthly)
    day_of_week     INT,                            -- 0=Monday..6=Sunday (weekly)
    day_of_month    INT,                            -- 1..28 (monthly, capped at 28 to avoid Feb 29 nonsense)
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT NOT NULL DEFAULT 'rssi'
);

-- Tick query — "give me everything due"
CREATE INDEX IF NOT EXISTS scan_schedules_due_idx
    ON scan_schedules (next_run_at)
    WHERE enabled = true;

COMMENT ON TABLE scan_schedules IS
    'Recurring scan plans created by the operator. Tick at src/scans/scheduler.rs polls due rows and enqueues scan_queue jobs.';
COMMENT ON COLUMN scan_schedules.frequency IS
    'hourly | daily | weekly | monthly — simple knobs, no full cron.';
