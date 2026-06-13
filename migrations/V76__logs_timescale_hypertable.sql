-- migrations/V76__logs_timescale_hypertable.sql
--
-- Convert `logs` and `logs_fluentbit` to TimescaleDB hypertables so the
-- ingestion pipeline keeps usable response times when a deployment scales
-- past a few thousand endpoints. Without partitioning, the logs table
-- crosses ~50 M rows after a few days of busy traffic and every query
-- starts paying a full scan cost; with hypertables, daily chunks are
-- pruned automatically based on the `time` filter the IE and dashboard
-- already pass on every read path.
--
-- Sized for ~10k hosts with mixed endpoint and forwarder profiles
-- (~440 GB/day raw projected). 90-day retention keeps disk usage
-- bounded; the compression policy folds chunks older than 7 days into
-- columnar storage with a typical 8-10x ratio, dropping 90-day footprint
-- from ~40 TB down to ~4 TB.

BEGIN;

-- ── Pre-flight ──────────────────────────────────────────────────────────────
-- Make absolutely sure the extension is on (it is on cyb06 but may not be
-- on a fresh install yet).
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ── logs ────────────────────────────────────────────────────────────────────
-- Drop the incoming foreign key from sigma_alerts → logs.id FIRST.
-- Postgres refuses to drop the PK index it depends on otherwise, and we
-- need to rebuild that PK to satisfy the hypertable contract. The FK
-- itself is also dropped permanently because TimescaleDB retention
-- cannot evict chunks that hold rows still referenced by sigma_alerts.
-- The log_id pointer becomes best-effort: it still points at the right
-- row while the chunk lives, and joins return NULL once the chunk has
-- rolled off retention — which is the desired behaviour for a forensic
-- trace pointer.
ALTER TABLE sigma_alerts DROP CONSTRAINT IF EXISTS sigma_alerts_log_id_fkey;

-- create_hypertable() requires the partitioning column to be part of every
-- unique constraint on the table. The current PRIMARY KEY is (id), which
-- excludes `time`; we expand it to (id, time) so the sequence-generated
-- id still gives effective uniqueness while satisfying the hypertable
-- contract.
ALTER TABLE logs DROP CONSTRAINT logs_pkey;
ALTER TABLE logs ADD PRIMARY KEY (id, "time");

-- Convert. `migrate_data => true` rewrites existing rows into per-day
-- chunks in-place; on the current staging volume (~400 MB) this completes
-- in a few seconds. For very large existing tables an operator should
-- schedule a maintenance window.
SELECT create_hypertable(
    'logs',
    'time',
    chunk_time_interval => INTERVAL '1 day',
    migrate_data        => true,
    if_not_exists       => true
);

-- ── logs_fluentbit ──────────────────────────────────────────────────────────
-- Staging table that the fluent-bit container writes to before the
-- AFTER-INSERT trigger folds rows into `logs`. Volume is high but
-- ephemeral; we partition it the same way and give it a much shorter
-- retention because the data is already mirrored into `logs`.
--
-- The table has no primary key (it's a write-only staging area), so the
-- only requirement is that `time` is the partitioning column. The
-- existing AFTER INSERT trigger keeps working — TimescaleDB attaches
-- triggers to every chunk automatically.
SELECT create_hypertable(
    'logs_fluentbit',
    'time',
    chunk_time_interval => INTERVAL '1 day',
    migrate_data        => true,
    if_not_exists       => true
);

-- ── Retention policies ──────────────────────────────────────────────────────
-- The background worker drops chunks whose latest time is older than the
-- interval. `if_not_exists => true` makes the migration idempotent.
SELECT add_retention_policy(
    'logs',
    INTERVAL '90 days',
    if_not_exists => true
);
SELECT add_retention_policy(
    'logs_fluentbit',
    INTERVAL '7 days',
    if_not_exists => true
);

-- ── Compression ─────────────────────────────────────────────────────────────
-- Columnar compression on chunks older than 7 days. `segmentby` picks the
-- columns the read queries filter on most often (hostname + tag); rows
-- inside a chunk are clustered by these segments so a filtered scan only
-- touches the relevant compressed blocks. `orderby` keeps the latest rows
-- first within a segment which matches how the dashboard renders log
-- panels.
ALTER TABLE logs SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'hostname, tag',
    timescaledb.compress_orderby   = '"time" DESC'
);
SELECT add_compression_policy(
    'logs',
    INTERVAL '7 days',
    if_not_exists => true
);

-- logs_fluentbit lives only 7 days so compression would buy nothing.

COMMIT;
