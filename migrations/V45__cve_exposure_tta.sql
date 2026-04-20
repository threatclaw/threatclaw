-- CISA KEV time-to-alert telemetry. See ADR (roadmap §3.5).
--
-- Tracks pour chaque CVE ajoutée au KEV catalog :
--   * quand CISA l'a publiée (date_added)
--   * quand TC l'a ingérée au prochain sync
--   * quand TC a produit une alerte matching un de nos assets scannés
--
-- Colonnes GENERATED pour le pipeline métrique (pas de calcul côté app).
-- Index sur observed_at DESC pour le widget dashboard.
--
-- Backward-compatible : table nouvelle, aucun changement existant.

CREATE TABLE IF NOT EXISTS cve_exposure_alerts (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id               TEXT NOT NULL,
    kev_published_at     TIMESTAMPTZ,
    first_observed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_asset_match_at TIMESTAMPTZ,
    incident_id          INTEGER,
    tta_ingest_sec       INTEGER GENERATED ALWAYS AS (
        CASE WHEN kev_published_at IS NULL THEN NULL
             ELSE EXTRACT(epoch FROM first_observed_at - kev_published_at)::int
        END
    ) STORED,
    tta_alert_sec        INTEGER GENERATED ALWAYS AS (
        CASE WHEN kev_published_at IS NULL OR first_asset_match_at IS NULL THEN NULL
             ELSE EXTRACT(epoch FROM first_asset_match_at - kev_published_at)::int
        END
    ) STORED,
    UNIQUE (cve_id)
);

CREATE INDEX IF NOT EXISTS idx_cve_expo_observed
    ON cve_exposure_alerts (first_observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_cve_expo_tta_alert
    ON cve_exposure_alerts (tta_alert_sec)
    WHERE tta_alert_sec IS NOT NULL;

-- Vue agrégée pour le widget dashboard (P50/P95 sur 30 derniers jours).
CREATE OR REPLACE VIEW kev_tta_metrics_30d AS
SELECT
    COUNT(*) FILTER (WHERE tta_alert_sec IS NOT NULL)                        AS matched_count,
    COUNT(*)                                                                  AS observed_count,
    PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY tta_alert_sec)               AS tta_alert_p50_sec,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY tta_alert_sec)               AS tta_alert_p95_sec,
    MAX(tta_alert_sec)                                                        AS tta_alert_max_sec,
    PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY tta_ingest_sec)              AS tta_ingest_p50_sec
FROM cve_exposure_alerts
WHERE first_observed_at > NOW() - INTERVAL '30 days';
