-- V100 — Dedup unique index on the logs hypertable (Phase 2b).
--
-- Phase 2a's ingest worker is at-least-once: a crash between processing a
-- claimed payload and deleting it re-runs that payload on the next claim, and
-- the worker explicitly relies on a server-side ON CONFLICT to absorb the
-- resulting duplicate. Phase 2b adds the batched writer (insert_logs_batch)
-- which uses ON CONFLICT DO NOTHING — this index is the conflict target.
--
-- The content key is (time, hostname, tag, md5(data::text)):
--   - `time` MUST be part of any unique index on a hypertable (it is the
--     partitioning column — see V76).
--   - jsonb `data::text` is canonical for equal values (keys are stored
--     sorted/normalised), so md5(data::text) is a stable content fingerprint.
-- A retried identical delta therefore lands on the same key and is dropped.
--
-- Pre-step: remove any pre-existing exact duplicates so the UNIQUE index can be
-- created on tables that predate it (e.g. a long-running staging box). Keeps the
-- lowest id of each duplicate group. NULL hostnames are treated as equal here
-- (IS NOT DISTINCT FROM); the going-forward index treats NULL hostnames as
-- distinct (standard SQL), which is fine — agent/NIDS telemetry always carries a
-- hostname, and exact NULL-hostname dup pairs are a negligible edge.

DELETE FROM logs a
    USING logs b
    WHERE a.id > b.id
      AND a.time = b.time
      AND a.hostname IS NOT DISTINCT FROM b.hostname
      AND a.tag = b.tag
      AND a.data = b.data;

CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_dedup
    ON logs (time, hostname, tag, md5(data::text));
