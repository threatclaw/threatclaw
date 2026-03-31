-- V29: Fluent Bit staging table for log ingestion
-- The pgsql plugin expects a simple (tag, time, data) table.
-- This staging table + trigger inserts into the real 'logs' table with proper columns.

CREATE TABLE IF NOT EXISTS logs_fluentbit (
    tag TEXT,
    time TIMESTAMPTZ DEFAULT NOW(),
    data JSONB DEFAULT '{}'
);

-- Trigger function: extract hostname/collector from data and insert into real logs table
CREATE OR REPLACE FUNCTION fn_fluentbit_to_logs()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO logs (tag, time, data, hostname, collector)
    VALUES (
        COALESCE(NEW.tag, 'unknown'),
        COALESCE(NEW.time, NOW()),
        COALESCE(NEW.data, '{}'::jsonb),
        COALESCE(NEW.data->>'hostname', NEW.data->>'host', split_part(NEW.tag, '.', 3)),
        COALESCE(NEW.data->>'collector', 'fluent-bit')
    );
    -- Delete from staging (we don't keep data here)
    DELETE FROM logs_fluentbit WHERE ctid = NEW.ctid;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- After insert trigger on staging table
DROP TRIGGER IF EXISTS trg_fluentbit_ingest ON logs_fluentbit;
CREATE TRIGGER trg_fluentbit_ingest
    AFTER INSERT ON logs_fluentbit
    FOR EACH ROW
    EXECUTE FUNCTION fn_fluentbit_to_logs();
