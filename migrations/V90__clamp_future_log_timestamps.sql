-- Clamp future-dated log timestamps at the database layer (every ingestion path).
--
-- Some sources (rsyslog / fluent-bit with a TZ-naive template, or any clock-drifted
-- agent) emit a `time` hours ahead of wall-clock. fluent-bit writes to `logs`
-- directly via its PostgreSQL output, bypassing the Rust insert_log clamp, so
-- future-dated rows still land. With ORDER BY time DESC the Sigma cursor query
-- then sorts those rows first and saturates the batch while clamping the cursor
-- to now() — the real-time logs are skipped and detection silently degrades.
-- Observed on cyb06 (2026-06-20): syslog sources +2h, sysmon events never reached
-- the engine. See detection-chain audit.
--
-- A BEFORE INSERT/UPDATE row trigger clamps any `time` more than 60s ahead of the
-- server clock to now(), catching EVERY ingestion path. Cost is one comparison
-- per row. Modifying NEW.time in a BEFORE trigger is safe on the TimescaleDB
-- hypertable: chunk routing happens after BEFORE triggers run. A few seconds of
-- normal clock skew is tolerated; only meaningful drift triggers the clamp.
--
-- Pre-existing future-dated rows are left to age out of the cursor window
-- (updating the partitioning column in place is unsafe on compressed chunks).
CREATE OR REPLACE FUNCTION clamp_future_log_time() RETURNS trigger AS $$
BEGIN
    IF NEW.time > now() + INTERVAL '60 seconds' THEN
        NEW.time := now();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_clamp_future_log_time ON logs;
CREATE TRIGGER trg_clamp_future_log_time
    BEFORE INSERT OR UPDATE ON logs
    FOR EACH ROW EXECUTE FUNCTION clamp_future_log_time();
