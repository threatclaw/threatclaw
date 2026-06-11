-- migrations/V75__fix_fluentbit_hostname_priority.sql
--
-- Fix fn_fluentbit_to_logs to prefer the upstream syslog source hostname
-- over the fluent-bit container hostname.
--
-- The previous trigger used COALESCE(NEW.data->>'hostname', NEW.data->>'host').
-- fluent-bit sets data.hostname to its own container ID (e.g. bc130c79e5dd)
-- and stores the parsed syslog source in data.host (e.g. sd-98664). The old
-- order made every monitored host appear as the same fluent-bit container ID
-- in logs.hostname, which then cascaded into sigma_alerts.hostname,
-- findings.asset, and the asset inventory. Triage was effectively broken
-- because the SOC could not tell which real host had emitted the event.
--
-- This migration swaps the COALESCE order so the parsed syslog source wins.
-- The fluent-bit container hostname remains as the fallback for any future
-- shape where data.host is absent.

CREATE OR REPLACE FUNCTION public.fn_fluentbit_to_logs()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    INSERT INTO logs (tag, time, data, hostname, collector)
    VALUES (
        COALESCE(NEW.tag, 'unknown'),
        COALESCE(NEW.time, NOW()),
        COALESCE(NEW.data, '{}'::jsonb),
        COALESCE(NEW.data->>'host', NEW.data->>'hostname'),
        COALESCE(NEW.data->>'collector', 'fluent-bit')
    );
    RETURN NULL;
END;
$function$;
