-- V51: Scan queue for the passive enrichment pipeline.
--
-- Connectors (Wazuh, AD, Velociraptor, ...) sync data on schedule and
-- we ingest. When new assets / findings land, we want to *automatically*
-- enrich them with active scans (Nmap fingerprint, Trivy CVE check,
-- etc.) without blocking the L2 forensic loop.
--
-- The queue holds scan jobs. A worker pool in the scheduler picks rows
-- with status='queued', runs them via docker_executor (or the dedicated
-- nmap_discovery handler), writes the result back, and updates status.
--
-- Read path: L2 calls `get_asset_info(ip)` and reads `assets.properties`
-- which the scan worker keeps fresh. The scan queue is invisible to L2.

CREATE TABLE IF NOT EXISTS scan_queue (
    id              BIGSERIAL PRIMARY KEY,
    target          TEXT NOT NULL,                  -- IP, image:tag, URL, repo path
    scan_type       TEXT NOT NULL,                  -- nmap_fingerprint | trivy_image | ...
    status          TEXT NOT NULL DEFAULT 'queued', -- queued | running | done | error | skipped
    asset_id        TEXT,                           -- assets.id when applicable
    requested_by    TEXT NOT NULL,                  -- 'auto:asset_merge' | 'manual:rssi:<userid>' | 'schedule:<cron_id>'
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    duration_ms     INTEGER,
    result_json     JSONB,                          -- structured output (ports, findings, ...)
    error_msg       TEXT,
    ttl_seconds     INTEGER NOT NULL DEFAULT 3600,  -- skip if a `done` row exists for same (target, scan_type) within this window
    worker_id       TEXT                            -- which worker picked it up (for SELECT FOR UPDATE SKIP LOCKED tracing)
);

-- Hot path: workers pull queued rows, oldest first.
CREATE INDEX IF NOT EXISTS scan_queue_pull_idx
    ON scan_queue (status, requested_at)
    WHERE status = 'queued';

-- Dedup query: "is there a recent done row for this target+type?"
CREATE INDEX IF NOT EXISTS scan_queue_dedup_idx
    ON scan_queue (target, scan_type, finished_at DESC)
    WHERE status = 'done';

-- Per-asset history (used by /assets/[id] surface card).
CREATE INDEX IF NOT EXISTS scan_queue_asset_idx
    ON scan_queue (asset_id, finished_at DESC)
    WHERE asset_id IS NOT NULL;

-- Ongoing scans for incident-card "scan en cours" badge.
CREATE INDEX IF NOT EXISTS scan_queue_running_asset_idx
    ON scan_queue (asset_id, status)
    WHERE status IN ('queued', 'running');

COMMENT ON TABLE scan_queue IS
    'Active enrichment scan queue. Workers pull queued rows, run the scan, update status.';
COMMENT ON COLUMN scan_queue.requested_by IS
    'Origin marker: auto:* for hooks, manual:rssi:<id> for dashboard clicks, schedule:<id> for cron.';
COMMENT ON COLUMN scan_queue.ttl_seconds IS
    'Dedup window. enqueue() skips if a done row exists for (target, scan_type) within this many seconds.';
