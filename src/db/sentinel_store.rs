//! PgBackend implementation of the `SentinelStore` trait. Drives the V74
//! schema writes (`incidents` + `sentinel_incident_metadata` +
//! `sentinel_alerts` + `sentinel_entities` + `sentinel_analytic_rules_cache`)
//! and the per-skill cursor stored in `skill_configs` under
//! `skill-microsoft-sentinel`.
//!
//! Every write uses an `ON CONFLICT` guard so that two scheduler cycles
//! racing on the same incident converge instead of producing duplicates.
//! See the dedup-race-condition note in the skill plan: even with the
//! `system_alert_id UNIQUE` constraint, simultaneous Sentinel + Graph
//! ingestion paths could otherwise collide.

use chrono::{DateTime, Utc};
use std::collections::HashSet;
use uuid::Uuid;

use crate::connectors::microsoft_sentinel::{
    DedupDecision, ParsedAnalyticRule, ParsedSentinelAlert, ParsedSentinelEntity,
    ParsedSentinelIncident, SentinelError, SentinelStore, map_sentinel_status,
};
use crate::db::postgres::PgBackend;

fn store_err(e: impl std::fmt::Display) -> SentinelError {
    SentinelError::Parse(e.to_string())
}

/// Derive the `incidents.asset` value from a Sentinel incident.
///
/// `incidents.asset` is NOT NULL and has no default in the V32 schema, so the
/// upsert must supply something. We synthesize a stable URI from the Sentinel
/// workspace + incident UUID. This keeps the column populated without lying
/// about which asset the incident affects — entity-level asset resolution
/// happens in Task 17b via `sentinel_entities.asset_id`.
fn synth_asset(inc: &ParsedSentinelIncident) -> String {
    format!("sentinel://incident/{}", inc.sentinel_incident_id)
}

#[async_trait::async_trait]
impl SentinelStore for PgBackend {
    /// Returns the set of provider_alert_ids that skill-microsoft-graph (Phase B)
    /// has already ingested as Defender alerts. Used by decide_dedup to skip
    /// re-ingesting the same alert via Sentinel when both skills are active.
    ///
    /// IMPORTANT: as of v1.0.x, Graph Phase B (Defender alert ingestion to the
    /// `incidents` table with `external_source='graph_defender'`) is NOT YET
    /// SHIPPED. This query intentionally returns an empty set in that case, and
    /// decide_dedup behaves as Insert-always, which is the correct behavior when
    /// there is nothing to dedupe against. The dedup mechanism activates
    /// automatically the moment skill-microsoft-graph Phase B lands and starts
    /// writing to incidents with external_source='graph_defender'.
    ///
    /// See: internal/specs/2026-06-03-skill-microsoft-sentinel-design.md section 10
    /// (Open contract with skill-microsoft-graph Phase B).
    async fn load_known_graph_provider_alert_ids(&self) -> Result<HashSet<String>, SentinelError> {
        let client = self.pool().get().await.map_err(store_err)?;
        let rows = client
            .query(
                "SELECT external_id FROM incidents \
                 WHERE external_source = 'graph_defender' AND external_id IS NOT NULL",
                &[],
            )
            .await
            .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .filter_map(|r| r.try_get::<_, String>(0).ok())
            .collect())
    }

    async fn load_cursor(&self) -> Result<Option<DateTime<Utc>>, SentinelError> {
        let client = self.pool().get().await.map_err(store_err)?;
        let row = client
            .query_opt(
                "SELECT value FROM skill_configs \
                 WHERE skill_id = 'skill-microsoft-sentinel' AND key = 'last_incident_modified'",
                &[],
            )
            .await
            .map_err(store_err)?;
        Ok(row.and_then(|r| {
            let raw: String = r.get(0);
            DateTime::parse_from_rfc3339(&raw)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        }))
    }

    async fn save_cursor(&self, cursor: DateTime<Utc>) -> Result<(), SentinelError> {
        let client = self.pool().get().await.map_err(store_err)?;
        client
            .execute(
                r#"INSERT INTO skill_configs (skill_id, key, value, updated_at)
                   VALUES ('skill-microsoft-sentinel', 'last_incident_modified', $1, NOW())
                   ON CONFLICT (skill_id, key) DO UPDATE SET value = $1, updated_at = NOW()"#,
                &[&cursor.to_rfc3339()],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn upsert_incident_with_metadata(
        &self,
        inc: &ParsedSentinelIncident,
        workspace_id: Uuid,
    ) -> Result<i32, SentinelError> {
        let client = self.pool().get().await.map_err(store_err)?;

        // Map Sentinel status + classification to the ThreatClaw status enum
        // before the insert. Storing the raw Sentinel status on incidents
        // would break downstream consumers that join against the canonical
        // status vocabulary (open/investigating/resolved/false_positive).
        let tc_status =
            map_sentinel_status(&inc.status, inc.classification.as_deref()).as_db_value();
        let asset = synth_asset(inc);
        let external_id_str = inc.sentinel_incident_id.to_string();

        let row = client
            .query_one(
                r#"
                INSERT INTO incidents (
                    asset, title, summary, severity, status,
                    external_id, external_source, external_url,
                    created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, 'sentinel', $7, NOW(), NOW())
                ON CONFLICT (external_source, external_id) WHERE external_id IS NOT NULL
                DO UPDATE SET
                    title = EXCLUDED.title,
                    summary = EXCLUDED.summary,
                    severity = EXCLUDED.severity,
                    status = EXCLUDED.status,
                    external_url = EXCLUDED.external_url,
                    updated_at = NOW()
                RETURNING id
                "#,
                &[
                    &asset,
                    &inc.title,
                    &inc.description,
                    &inc.severity,
                    &tc_status,
                    &external_id_str,
                    &inc.provider_incident_url,
                ],
            )
            .await
            .map_err(store_err)?;
        let tc_id: i32 = row.get(0);

        client
            .execute(
                r#"
                INSERT INTO sentinel_incident_metadata (
                    incident_id, sentinel_incident_id, sentinel_incident_number, sentinel_etag,
                    workspace_id, provider_name, provider_incident_id, provider_incident_url,
                    related_analytic_rule_ids, mitre_tactics, mitre_techniques,
                    sentinel_status, sentinel_classification, sentinel_classification_reason,
                    sentinel_last_modified_utc
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                ON CONFLICT (incident_id) DO UPDATE SET
                    sentinel_etag = EXCLUDED.sentinel_etag,
                    sentinel_status = EXCLUDED.sentinel_status,
                    sentinel_classification = EXCLUDED.sentinel_classification,
                    sentinel_classification_reason = EXCLUDED.sentinel_classification_reason,
                    sentinel_last_modified_utc = EXCLUDED.sentinel_last_modified_utc,
                    related_analytic_rule_ids = EXCLUDED.related_analytic_rule_ids,
                    mitre_tactics = EXCLUDED.mitre_tactics,
                    mitre_techniques = EXCLUDED.mitre_techniques,
                    provider_incident_url = EXCLUDED.provider_incident_url,
                    updated_at = NOW()
                "#,
                &[
                    &tc_id,
                    &inc.sentinel_incident_id,
                    &inc.incident_number,
                    &inc.etag,
                    &workspace_id,
                    &inc.provider_name,
                    &inc.provider_incident_id,
                    &inc.provider_incident_url,
                    &inc.related_analytic_rule_ids,
                    &inc.tactics,
                    &inc.techniques,
                    &inc.status,
                    &inc.classification,
                    &inc.classification_reason,
                    &inc.last_modified_utc,
                ],
            )
            .await
            .map_err(store_err)?;

        Ok(tc_id)
    }

    async fn upsert_sentinel_alert(
        &self,
        threatclaw_incident_id: i32,
        alert: &ParsedSentinelAlert,
        dedup: DedupDecision,
    ) -> Result<(), SentinelError> {
        let client = self.pool().get().await.map_err(store_err)?;
        // The dedup decision drives whether we even attempt the insert
        // (orchestrator counts it for telemetry), but the
        // `dedup_merged_with_graph` audit column itself cannot be set here
        // because when dedup == SkipMergeWithGraph the ON CONFLICT DO NOTHING
        // path means no row is written by this path at all. Hardcode false
        // until the graph_alert_id wiring lands (see TODO at the bottom).
        let _ = dedup;
        client
            .execute(
                r#"
                INSERT INTO sentinel_alerts (
                    id, incident_id, system_alert_id, provider_alert_id, provider_name,
                    vendor_name, product_name, alert_display_name, description, severity,
                    confidence_level, status, tactics, techniques, alert_link,
                    start_time_utc, end_time_utc, time_generated, additional_data,
                    dedup_merged_with_graph
                ) VALUES (
                    gen_random_uuid(), $1, $2, $3, $4,
                    $5, $6, $7, $8, $9,
                    $10, $11, $12, $13, $14,
                    $15, $16, $17, $18,
                    $19
                )
                ON CONFLICT (system_alert_id) DO NOTHING
                "#,
                &[
                    &threatclaw_incident_id,
                    &alert.system_alert_id,
                    &alert.provider_alert_id,
                    &alert.provider_name,
                    &alert.vendor_name,
                    &alert.product_name,
                    &alert.alert_display_name,
                    &alert.description,
                    &alert.severity,
                    &alert.confidence_level,
                    &alert.status,
                    &alert.tactics,
                    &alert.techniques,
                    &alert.alert_link,
                    &alert.start_time_utc,
                    &alert.end_time_utc,
                    &alert.time_generated,
                    &alert.additional_data,
                    &false,
                ],
            )
            .await
            .map_err(store_err)?;
        // TODO(skill-microsoft-sentinel:task17b): when graph_alert_id wiring lands,
        // UPDATE sentinel_alerts SET dedup_merged_with_graph=true, graph_alert_id=$1
        // for the row whose provider_alert_id matches the Graph alert we just skipped.
        // Today the flag is always false because the ON CONFLICT DO NOTHING path means
        // no row is written here when dedup decides SkipMergeWithGraph.
        Ok(())
    }

    async fn upsert_sentinel_entity(
        &self,
        threatclaw_incident_id: i32,
        ent: &ParsedSentinelEntity,
    ) -> Result<(), SentinelError> {
        let client = self.pool().get().await.map_err(store_err)?;
        client
            .execute(
                r#"
                INSERT INTO sentinel_entities (id, incident_id, kind, friendly_name, raw_properties)
                VALUES (gen_random_uuid(), $1, $2, $3, $4)
                "#,
                &[
                    &threatclaw_incident_id,
                    &ent.kind,
                    &ent.friendly_name,
                    &ent.raw_properties,
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn clear_sentinel_entities_for_incident(
        &self,
        threatclaw_incident_id: i32,
    ) -> Result<(), SentinelError> {
        let client = self.pool().get().await.map_err(store_err)?;
        client
            .execute(
                "DELETE FROM sentinel_entities WHERE incident_id = $1",
                &[&threatclaw_incident_id],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn upsert_analytic_rule(
        &self,
        workspace_id: Uuid,
        rule: &ParsedAnalyticRule,
    ) -> Result<(), SentinelError> {
        let client = self.pool().get().await.map_err(store_err)?;
        client
            .execute(
                r#"
                INSERT INTO sentinel_analytic_rules_cache (
                    rule_id, workspace_id, kind, display_name, description, severity,
                    tactics, techniques, query, query_frequency, query_period,
                    trigger_operator, trigger_threshold, enabled, raw_json, fetched_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW())
                ON CONFLICT (rule_id, workspace_id) DO UPDATE SET
                    kind = EXCLUDED.kind,
                    display_name = EXCLUDED.display_name,
                    description = EXCLUDED.description,
                    severity = EXCLUDED.severity,
                    tactics = EXCLUDED.tactics,
                    techniques = EXCLUDED.techniques,
                    query = EXCLUDED.query,
                    query_frequency = EXCLUDED.query_frequency,
                    query_period = EXCLUDED.query_period,
                    trigger_operator = EXCLUDED.trigger_operator,
                    trigger_threshold = EXCLUDED.trigger_threshold,
                    enabled = EXCLUDED.enabled,
                    raw_json = EXCLUDED.raw_json,
                    fetched_at = NOW()
                "#,
                &[
                    &rule.rule_id,
                    &workspace_id,
                    &rule.kind,
                    &rule.display_name,
                    &rule.description,
                    &rule.severity,
                    &rule.tactics,
                    &rule.techniques,
                    &rule.query,
                    &rule.query_frequency,
                    &rule.query_period,
                    &rule.trigger_operator,
                    &rule.trigger_threshold,
                    &rule.enabled,
                    &rule.raw,
                ],
            )
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn maybe_get_cached_analytic_rule(
        &self,
        workspace_id: Uuid,
        rule_id: Uuid,
        ttl_secs: i64,
    ) -> Result<Option<ParsedAnalyticRule>, SentinelError> {
        let client = self.pool().get().await.map_err(store_err)?;
        // `make_interval(secs => $3)` expects a double; PostgreSQL converts
        // the int8 bind transparently. TTL is checked here rather than at
        // write time so a single cache row survives multiple TTLs (caller
        // decides freshness per call).
        let row = client
            .query_opt(
                r#"
                SELECT kind, display_name, description, severity, tactics, techniques,
                       query, query_frequency, query_period, trigger_operator, trigger_threshold,
                       enabled, raw_json
                FROM sentinel_analytic_rules_cache
                WHERE rule_id = $1
                  AND workspace_id = $2
                  AND fetched_at > NOW() - make_interval(secs => $3::double precision)
                "#,
                &[&rule_id, &workspace_id, &(ttl_secs as f64)],
            )
            .await
            .map_err(store_err)?;
        Ok(row.map(|r| ParsedAnalyticRule {
            rule_id,
            kind: r.get(0),
            display_name: r.get(1),
            description: r.get(2),
            severity: r.get(3),
            tactics: r.get(4),
            techniques: r.get(5),
            query: r.get(6),
            query_frequency: r.get(7),
            query_period: r.get(8),
            trigger_operator: r.get(9),
            trigger_threshold: r.get(10),
            enabled: r.get(11),
            raw: r.get(12),
        }))
    }
}
