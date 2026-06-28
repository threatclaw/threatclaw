-- V99__ingest_queue.sql
-- Write-ahead durable queue for webhook ingestion. The hot path writes the raw
-- (already gzip-decoded) payload here and returns 200; workers drain it via
-- FOR UPDATE SKIP LOCKED and run the existing process_webhook off the request
-- thread. LOGGED (not UNLOGGED) because the payload is forensic evidence that
-- must survive a crash. Deliberately NOT a hypertable: rows are short-lived
-- (claimed + deleted within ~300ms-seconds), so chunking/compression add no value.
CREATE TABLE IF NOT EXISTS ingest_queue (
    id          BIGSERIAL PRIMARY KEY,
    source      TEXT NOT NULL,
    body        BYTEA NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_by  TEXT,
    claimed_at  TIMESTAMPTZ
);

-- Claim index: unclaimed rows oldest-first. Partial index stays tiny because
-- claimed rows are deleted almost immediately after processing.
CREATE INDEX IF NOT EXISTS idx_ingest_queue_claim
    ON ingest_queue (received_at)
    WHERE claimed_at IS NULL;
