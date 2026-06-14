-- V78 — Sigma rule statistics
--
-- Aggregated per-rule metrics surfaced on the new /sigma dashboard page:
-- fire counts over 7 / 30 days, last fire timestamp, false-positive rate,
-- distinct host count, top hostname. Without this, every list page load
-- would issue 4-5 aggregate queries per row against sigma_alerts. The
-- materialized view is refreshed every 5 minutes by the core, in lockstep
-- with the existing sigma cycle.

CREATE MATERIALIZED VIEW IF NOT EXISTS sigma_rule_stats AS
SELECT
    r.id AS rule_id,
    COALESCE(SUM(CASE WHEN a.matched_at >= NOW() - INTERVAL '7 days' THEN 1 ELSE 0 END), 0) AS fire_count_7d,
    COALESCE(SUM(CASE WHEN a.matched_at >= NOW() - INTERVAL '30 days' THEN 1 ELSE 0 END), 0) AS fire_count_30d,
    MAX(a.matched_at) AS last_fire_at,
    COALESCE(SUM(CASE
        WHEN a.matched_at >= NOW() - INTERVAL '7 days' AND a.status = 'false_positive'
        THEN 1 ELSE 0
    END), 0) AS fp_count_7d,
    COUNT(DISTINCT a.hostname) FILTER (
        WHERE a.matched_at >= NOW() - INTERVAL '7 days' AND a.hostname IS NOT NULL
    ) AS distinct_hosts_7d,
    (
        SELECT a2.hostname
        FROM sigma_alerts a2
        WHERE a2.rule_id = r.id
          AND a2.matched_at >= NOW() - INTERVAL '7 days'
          AND a2.hostname IS NOT NULL
        GROUP BY a2.hostname
        ORDER BY COUNT(*) DESC
        LIMIT 1
    ) AS top_hostname_7d
FROM sigma_rules r
LEFT JOIN sigma_alerts a ON a.rule_id = r.id
GROUP BY r.id;

CREATE UNIQUE INDEX IF NOT EXISTS sigma_rule_stats_rule_idx
    ON sigma_rule_stats (rule_id);

-- A nominal initial refresh so the view is not empty on the very first
-- page load right after the migration runs.
REFRESH MATERIALIZED VIEW sigma_rule_stats;
