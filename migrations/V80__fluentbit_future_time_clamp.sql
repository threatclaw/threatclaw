-- migrations/V80__fluentbit_future_time_clamp.sql
--
-- Clamp future-dated log timestamps at the fluent-bit ingest boundary.
--
-- The fluent-bit syslog-rfc3164 parser interprets the timestamp on the
-- incoming syslog line literally. Some producers (rsyslog with a
-- TZ-naïve template) emit a local-time string that is then re-tagged as
-- UTC, so each row lands an hour or two ahead of wall-clock on the
-- ingest side. The sigma cursor relies on monotonically-recent
-- timestamps to advance forward — a future row poisons it and the
-- engine starts silently skipping every log that arrives between now
-- and the bogus future timestamp.
--
-- The Rust insert_log path already has a future clamp, but the bulk of
-- the volume comes through the fluent-bit pgsql output plugin which
-- inserts straight into `logs_fluentbit` and triggers this function —
-- bypassing the Rust path entirely. Clamping here is the only place
-- that catches every row, regardless of the producer.
--
-- 60 s of tolerated drift covers reasonable NTP skew without mangling
-- a legitimately-tight clock. Anything past that is pinned to
-- `now()` so the cursor invariant is preserved.

CREATE OR REPLACE FUNCTION public.fn_fluentbit_to_logs()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    effective_time timestamptz;
BEGIN
    effective_time := COALESCE(NEW.time, NOW());
    IF effective_time > NOW() + INTERVAL '60 seconds' THEN
        -- Note in a NOTICE so the upstream TZ bug is greppable from PG logs.
        RAISE NOTICE 'fluentbit_to_logs: future time % clamped to now() (tag=%)', effective_time, NEW.tag;
        effective_time := NOW();
    END IF;
    INSERT INTO logs (tag, time, data, hostname, collector)
    VALUES (
        COALESCE(NEW.tag, 'unknown'),
        effective_time,
        COALESCE(NEW.data, '{}'::jsonb),
        COALESCE(NEW.data->>'host', NEW.data->>'hostname'),
        COALESCE(NEW.data->>'collector', 'fluent-bit')
    );
    RETURN NULL;
END;
$function$;
