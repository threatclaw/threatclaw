-- One-time purge of the future-dated log backlog (companion to V90's trigger).
--
-- V90 installs a BEFORE INSERT trigger that clamps future timestamps, so NEW rows
-- are clean. But an install upgraded while a clock-drifted source had already
-- written hours-ahead rows keeps that backlog, and `ORDER BY time DESC` lets it
-- poison the Sigma cursor (clamp-to-now) for as long as it stays "ahead" of the
-- wall clock — up to a multi-hour blind window after the upgrade. Validated on
-- cyb06 (2026-06-20): a +2h syslog backlog kept real-time logs out of the cursor
-- batch until purged.
--
-- We DELETE rows whose `time` is more than 60s in the future: such a timestamp is
-- impossible for a real event (it is upstream clock drift / a TZ bug), so the rows
-- are already useless for time-based detection and only do harm. Forward-dated
-- rows never recur once V90's trigger is in place.
--
-- `logs` is a TimescaleDB hypertable: a host/time-scoped DELETE can decompress
-- chunks, so we lift the per-transaction decompression cap. The cap parameter
-- does not exist on a plain-PostgreSQL deployment, so the SET is wrapped in an
-- exception-swallowing block to keep the migration portable.
DO $$
BEGIN
    BEGIN
        SET LOCAL timescaledb.max_tuples_decompressed_per_dml_transaction = 0;
    EXCEPTION WHEN OTHERS THEN
        NULL; -- not a TimescaleDB deployment — a plain DELETE is fine
    END;
    DELETE FROM logs WHERE time > now() + INTERVAL '60 seconds';
END $$;
