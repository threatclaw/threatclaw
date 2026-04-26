-- V54: firewall_events — rolling buffer of pf log entries.
--
-- pfSense / OPNsense expose /api/diagnostics/firewall/log returning the
-- last N entries in pf format (block/pass with src/dst/port/proto).
-- We pull this every 5 min sync, ingest deltas, run pattern detection
-- on top (port scans, brute force, exfil), and keep a rolling 24 h
-- window for forensic context.
--
-- Volume: a busy firewall on a /24 LAN typically produces 100–1000
-- entries per minute. 24 h = ~1–10 M rows. The hot indexes (timestamp +
-- src/dst IP) keep the L2 lookup ("show me everything for asset X in
-- the last 10 min around incident Y") sub-second.

CREATE TABLE IF NOT EXISTS firewall_events (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    fw_source       TEXT NOT NULL,                 -- 'opnsense' | 'pfsense'
    interface       TEXT,
    action          TEXT NOT NULL,                 -- block | pass | match
    direction       TEXT,                          -- in | out
    proto           TEXT,                          -- tcp | udp | icmp ...
    src_ip          INET,
    src_port        INTEGER,
    dst_ip          INET,
    dst_port        INTEGER,
    rule_id         TEXT,
    raw_meta        JSONB,                         -- everything else from pf log
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hot path: forensic lookup by asset IP within a time window.
CREATE INDEX IF NOT EXISTS firewall_events_dst_ip_ts_idx
    ON firewall_events (dst_ip, timestamp DESC);

CREATE INDEX IF NOT EXISTS firewall_events_src_ip_ts_idx
    ON firewall_events (src_ip, timestamp DESC);

-- Pattern detection: blocks aggregated by src/dst over short windows.
CREATE INDEX IF NOT EXISTS firewall_events_action_ts_idx
    ON firewall_events (action, timestamp DESC);

-- Retention cleanup: delete WHERE timestamp < now() - interval '24 h'
-- runs at the end of every sync. The (timestamp) index serves both
-- this DELETE and the dashboard "last N hours" queries.
CREATE INDEX IF NOT EXISTS firewall_events_timestamp_idx
    ON firewall_events (timestamp DESC);

COMMENT ON TABLE firewall_events IS
    'Rolling pf log buffer. 24h retention enforced by the pfSense connector at end of each sync cycle.';
