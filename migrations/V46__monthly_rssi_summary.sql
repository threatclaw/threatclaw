-- Monthly RSSI summary. See roadmap §3.4.
--
-- Materialized view aggregeant les KPIs mensuels pour :
--   1. Widget dashboard home
--   2. Rapport PDF mensuel (skill-report-gen + Typst)
--   3. Export CSV audit NIS2
--
-- Refresh horaire via pg_cron si disponible, sinon manuellement.
-- Unique index sur `month` permet REFRESH CONCURRENTLY (pas de lock
-- bloquant sur la lecture pendant le refresh).
--
-- Backward-compatible : vue nouvelle, aucune table existante modifiée.

CREATE MATERIALIZED VIEW IF NOT EXISTS monthly_rssi_summary AS
SELECT
    date_trunc('month', created_at)::date AS month,

    COUNT(*)                                                        AS incidents_total,
    COUNT(*) FILTER (WHERE verdict = 'confirmed')                   AS incidents_confirmed,
    COUNT(*) FILTER (WHERE verdict = 'false_positive')              AS incidents_fp,
    COUNT(*) FILTER (WHERE verdict = 'inconclusive')                AS incidents_inconclusive,
    COUNT(*) FILTER (WHERE status IN ('resolved', 'closed'))        AS incidents_resolved,
    COUNT(*) FILTER (WHERE status = 'open')                         AS incidents_open,

    COUNT(*) FILTER (WHERE severity = 'CRITICAL')                   AS sev_critical,
    COUNT(*) FILTER (WHERE severity = 'HIGH')                       AS sev_high,
    COUNT(*) FILTER (WHERE severity = 'MEDIUM')                     AS sev_medium,
    COUNT(*) FILTER (WHERE severity = 'LOW')                        AS sev_low,

    COUNT(*) FILTER (WHERE blast_radius_snapshot IS NOT NULL)       AS incidents_with_blast,
    AVG(blast_radius_score)
      FILTER (WHERE blast_radius_score IS NOT NULL)::numeric(5,2)   AS blast_score_avg,
    MAX(blast_radius_score)                                         AS blast_score_max,

    -- MTTR is measured on resolved incidents only, in seconds.
    PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY
        EXTRACT(epoch FROM resolved_at - created_at))
        FILTER (WHERE resolved_at IS NOT NULL)                      AS mttr_p50_sec,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY
        EXTRACT(epoch FROM resolved_at - created_at))
        FILTER (WHERE resolved_at IS NOT NULL)                      AS mttr_p95_sec,

    MIN(created_at)                                                 AS first_incident_at,
    MAX(created_at)                                                 AS last_incident_at
FROM incidents
GROUP BY date_trunc('month', created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_monthly_rssi_month
    ON monthly_rssi_summary (month);

-- Helper : top 3 incidents par blast_radius_score sur un mois donné
-- (appelé depuis le rapport pour la section "Top 3 risques du mois").
CREATE OR REPLACE FUNCTION top_incidents_by_blast(month_start date, n int)
RETURNS TABLE (
    id int, title text, asset text, severity text,
    blast_radius_score smallint, created_at timestamptz
)
LANGUAGE sql STABLE AS $$
    SELECT id, title, asset, severity, blast_radius_score, created_at
    FROM incidents
    WHERE created_at >= month_start
      AND created_at < month_start + INTERVAL '1 month'
      AND blast_radius_score IS NOT NULL
    ORDER BY blast_radius_score DESC NULLS LAST
    LIMIT n;
$$;
