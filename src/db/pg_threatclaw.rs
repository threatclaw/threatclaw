//! PostgreSQL implementation of ThreatClawStore.

use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};

use super::postgres::PgBackend;
use super::threatclaw_store::*;
use crate::error::DatabaseError;

/// Track whether the threat_graph has been verified/created this session.
static GRAPH_ENSURED: AtomicBool = AtomicBool::new(false);

fn pool_err(e: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Pool(e.to_string())
}

fn query_err(e: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Query(e.to_string())
}

/// Map a scan_queue row to its struct. Centralises the column order so
/// every query above can rely on the same SELECT shape.
fn scan_job_from_row(r: tokio_postgres::Row) -> ScanJob {
    let ts_to_string = |opt: Option<chrono::DateTime<chrono::Utc>>| opt.map(|t| t.to_rfc3339());
    ScanJob {
        id: r.get(0),
        target: r.get(1),
        scan_type: r.get(2),
        status: r.get(3),
        asset_id: r.get(4),
        requested_by: r.get(5),
        requested_at: r.get::<_, chrono::DateTime<chrono::Utc>>(6).to_rfc3339(),
        started_at: ts_to_string(r.get(7)),
        finished_at: ts_to_string(r.get(8)),
        duration_ms: r.get(9),
        result_json: r.get(10),
        error_msg: r.get(11),
        ttl_seconds: r.get(12),
        worker_id: r.get(13),
    }
}

fn firewall_event_from_row(r: tokio_postgres::Row) -> FirewallEventRecord {
    FirewallEventRecord {
        id: r.get(0),
        timestamp: r.get::<_, chrono::DateTime<chrono::Utc>>(1).to_rfc3339(),
        fw_source: r.get(2),
        interface: r.get(3),
        action: r.get(4),
        direction: r.get(5),
        proto: r.get(6),
        src_ip: r.get(7),
        src_port: r.get(8),
        dst_ip: r.get(9),
        dst_port: r.get(10),
        rule_id: r.get(11),
        raw_meta: r.get(12),
    }
}

/// See ADR-047.
fn row_to_suppression_rule(r: tokio_postgres::Row) -> serde_json::Value {
    serde_json::json!({
        "id": r.get::<_, uuid::Uuid>("id").to_string(),
        "name": r.get::<_, String>("name"),
        "predicate": r.try_get::<_, serde_json::Value>("predicate").unwrap_or(serde_json::json!({})),
        "predicate_source": r.get::<_, String>("predicate_source"),
        "action": r.get::<_, String>("action"),
        "severity_cap": r.get::<_, Option<String>>("severity_cap"),
        "scope": r.get::<_, String>("scope"),
        "reason": r.get::<_, String>("reason"),
        "created_by": r.get::<_, String>("created_by"),
        "created_at": r.get::<_, chrono::DateTime<chrono::Utc>>("created_at").to_rfc3339(),
        "expires_at": r.get::<_, chrono::DateTime<chrono::Utc>>("expires_at").to_rfc3339(),
        "enabled": r.get::<_, bool>("enabled"),
        "match_count": r.get::<_, i64>("match_count"),
        "last_match_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("last_match_at").map(|t| t.to_rfc3339()),
        "source": r.get::<_, String>("source"),
    })
}

/// Strip extra quotes from agtype values.
/// AGE serializes strings as `"\"value\""` in JSON — this unwraps them to `"value"`.
/// Also handles numeric strings that should be numbers, and boolean strings.
fn strip_agtype_quotes(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let cleaned: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k, strip_agtype_quotes(v)))
                .collect();
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(strip_agtype_quotes).collect())
        }
        serde_json::Value::String(ref s) => {
            // agtype wraps strings in extra quotes: "\"value\"" → "value"
            if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                let inner = &s[1..s.len() - 1];
                // Try to parse as JSON value (number, bool, null, or cleaned string)
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(inner) {
                    return parsed;
                }
                return serde_json::Value::String(inner.to_string());
            }
            // Try to parse bare numbers/bools from agtype
            if let Ok(n) = s.parse::<i64>() {
                return serde_json::Value::Number(n.into());
            }
            if let Ok(n) = s.parse::<f64>() {
                if let Some(n) = serde_json::Number::from_f64(n) {
                    return serde_json::Value::Number(n);
                }
            }
            if s == "true" {
                return serde_json::Value::Bool(true);
            }
            if s == "false" {
                return serde_json::Value::Bool(false);
            }
            value
        }
        _ => value,
    }
}

/// Split RETURN clause into individual column expressions.
/// Handles nested function calls like `collect(DISTINCT a.hostname)`.
fn split_return_columns(return_clause: &str) -> Vec<String> {
    let trimmed = return_clause.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return vec!["result".to_string()];
    }
    let mut cols = vec![];
    let mut depth = 0;
    let mut current = String::new();
    for ch in trimmed.chars() {
        match ch {
            '(' | '[' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                cols.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        cols.push(current.trim().to_string());
    }
    if cols.is_empty() {
        cols.push("result".to_string());
    }
    cols
}

#[async_trait]
impl ThreatClawStore for PgBackend {
    async fn insert_finding(&self, f: &NewFinding) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let default_meta = serde_json::json!({});
        let meta = f.metadata.as_ref().unwrap_or(&default_meta);

        // Deduplicate: if a finding with same skill_id + title + asset already exists
        // and is still open, update it instead of creating a duplicate.
        let existing = conn
            .query_opt(
                r#"SELECT id, status FROM findings
               WHERE skill_id = $1 AND title = $2 AND COALESCE(asset, '') = COALESCE($3, '')
               ORDER BY id DESC LIMIT 1"#,
                &[&f.skill_id, &f.title, &f.asset],
            )
            .await
            .map_err(query_err)?;

        if let Some(row) = existing {
            let id: i64 = row.get(0);
            let status: String = row.get(1);
            // If still open or in_progress, just update detected_at + metadata (re-confirmed)
            if status == "open" || status == "in_progress" {
                conn.execute(
                    r#"UPDATE findings SET detected_at = NOW(), metadata = $1, severity = $2
                       WHERE id = $3"#,
                    &[meta, &f.severity, &id],
                )
                .await
                .map_err(query_err)?;
                return Ok(id);
            }
            // If resolved/false_positive but found again → reopen
            conn.execute(
                r#"UPDATE findings SET status = 'open', detected_at = NOW(), resolved_at = NULL,
                   resolved_by = NULL, metadata = $1, severity = $2
                   WHERE id = $3"#,
                &[meta, &f.severity, &id],
            )
            .await
            .map_err(query_err)?;
            return Ok(id);
        }

        // Cross-tool correlation: if metadata contains a CVE, check if another tool
        // already reported the same CVE on the same asset. If so, merge sources.
        let cve_id = meta.get("cve").and_then(|v| v.as_str()).unwrap_or("");
        if !cve_id.is_empty() {
            let cross = conn
                .query_opt(
                    r#"SELECT id, source, metadata FROM findings
                   WHERE metadata->>'cve' = $1
                   AND COALESCE(asset, '') = COALESCE($2, '')
                   AND skill_id != $3
                   ORDER BY id DESC LIMIT 1"#,
                    &[&cve_id, &f.asset, &f.skill_id],
                )
                .await
                .map_err(query_err)?;

            if let Some(row) = cross {
                let id: i64 = row.get(0);
                let existing_source: Option<String> = row.get(1);
                let mut existing_meta: serde_json::Value = row.get(2);
                // Add this tool to the sources list
                let new_source = f.source.as_deref().unwrap_or(&f.skill_id);
                let old_source = existing_source.as_deref().unwrap_or("unknown");
                let merged_source = if old_source.contains(new_source) {
                    old_source.to_string()
                } else {
                    format!("{}, {}", old_source, new_source)
                };
                // Merge metadata: add confirmed_by list
                if let Some(obj) = existing_meta.as_object_mut() {
                    let mut confirmed: Vec<String> = obj
                        .get("confirmed_by")
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                        .unwrap_or_default();
                    if !confirmed.contains(&new_source.to_string()) {
                        confirmed.push(new_source.to_string());
                    }
                    obj.insert("confirmed_by".into(), serde_json::json!(confirmed));
                }
                conn.execute(
                    r#"UPDATE findings SET source = $1, metadata = $2, detected_at = NOW(),
                       severity = CASE WHEN $3 = 'CRITICAL' THEN 'CRITICAL' ELSE severity END
                       WHERE id = $4"#,
                    &[&merged_source, &existing_meta, &f.severity, &id],
                )
                .await
                .map_err(query_err)?;
                return Ok(id);
            }
        }

        // No existing finding — insert new
        let row = conn
            .query_one(
                r#"INSERT INTO findings (skill_id, title, description, severity, category, asset, source, metadata)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   RETURNING id"#,
                &[&f.skill_id, &f.title, &f.description, &f.severity, &f.category, &f.asset, &f.source, meta],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get::<_, i64>(0))
    }

    async fn list_findings(
        &self,
        severity: Option<&str>,
        status: Option<&str>,
        skill_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<FindingRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                r#"SELECT id, skill_id, title, description, severity, status, category, asset, source,
                          metadata, detected_at::text, resolved_at::text, resolved_by
                   FROM findings
                   WHERE ($1::text IS NULL OR UPPER(severity) = UPPER($1))
                     AND ($2::text IS NULL OR status = $2)
                     AND ($3::text IS NULL OR skill_id = $3)
                   ORDER BY detected_at DESC
                   LIMIT $4 OFFSET $5"#,
                &[&severity, &status, &skill_id, &limit, &offset],
            )
            .await
            .map_err(query_err)?;

        Ok(rows
            .iter()
            .map(|r| FindingRecord {
                id: r.get(0),
                skill_id: r.get(1),
                title: r.get(2),
                description: r.get(3),
                severity: r.get(4),
                status: r.get(5),
                category: r.get(6),
                asset: r.get(7),
                source: r.get(8),
                metadata: r.get(9),
                detected_at: r.get(10),
                resolved_at: r.get(11),
                resolved_by: r.get(12),
            })
            .collect())
    }

    async fn count_findings_filtered(
        &self,
        severity: Option<&str>,
        status: Option<&str>,
        skill_id: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                r#"SELECT COUNT(*)::bigint FROM findings
               WHERE ($1::text IS NULL OR UPPER(severity) = UPPER($1))
                 AND ($2::text IS NULL OR status = $2)
                 AND ($3::text IS NULL OR skill_id = $3)"#,
                &[&severity, &status, &skill_id],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn get_finding(&self, id: i64) -> Result<Option<FindingRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                r#"SELECT id, skill_id, title, description, severity, status, category, asset, source,
                          metadata, detected_at::text, resolved_at::text, resolved_by
                   FROM findings WHERE id = $1"#,
                &[&id],
            )
            .await
            .map_err(query_err)?;

        Ok(row.map(|r| FindingRecord {
            id: r.get(0),
            skill_id: r.get(1),
            title: r.get(2),
            description: r.get(3),
            severity: r.get(4),
            status: r.get(5),
            category: r.get(6),
            asset: r.get(7),
            source: r.get(8),
            metadata: r.get(9),
            detected_at: r.get(10),
            resolved_at: r.get(11),
            resolved_by: r.get(12),
        }))
    }

    async fn update_finding_status(
        &self,
        id: i64,
        status: &str,
        resolved_by: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let resolved: Option<&str> = resolved_by;
        conn.execute(
            r#"UPDATE findings SET status = $1, resolved_by = $2,
                      resolved_at = CASE WHEN $1 = 'resolved' THEN NOW() ELSE resolved_at END
               WHERE id = $3"#,
            &[&status, &resolved, &id],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn list_audit_entries_between(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
        until: Option<chrono::DateTime<chrono::Utc>>,
        limit: i64,
    ) -> Result<Vec<super::threatclaw_store::AuditEntryRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let q = r#"
            SELECT id::text,
                   timestamp::text,
                   event_type,
                   agent_mode,
                   cmd_id,
                   approved_by,
                   success,
                   error_message,
                   skill_id,
                   row_hash,
                   previous_hash
            FROM agent_audit_log
            WHERE ($1::timestamptz IS NULL OR timestamp >= $1)
              AND ($2::timestamptz IS NULL OR timestamp <= $2)
            ORDER BY timestamp DESC
            LIMIT $3
        "#;
        let rows = conn
            .query(q, &[&since, &until, &limit])
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| super::threatclaw_store::AuditEntryRecord {
                id: r.get(0),
                timestamp: r.get(1),
                event_type: r.get(2),
                agent_mode: r.get(3),
                cmd_id: r.get(4),
                approved_by: r.get(5),
                success: r.get(6),
                error_message: r.get(7),
                skill_id: r.get(8),
                row_hash: r.get(9),
                previous_hash: r.get(10),
            })
            .collect())
    }

    async fn list_ai_systems(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<super::threatclaw_store::AiSystemRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let q = r#"
            SELECT id,
                   name,
                   category,
                   provider,
                   endpoint,
                   status,
                   risk_level,
                   assessment_status,
                   declared_by,
                   declared_at::text,
                   first_seen::text,
                   last_seen::text,
                   remediation,
                   metadata
            FROM ai_systems
            WHERE ($1::text IS NULL OR status = $1)
            ORDER BY last_seen DESC
            LIMIT $2
        "#;
        let rows = conn.query(q, &[&status, &limit]).await.map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| super::threatclaw_store::AiSystemRecord {
                id: r.get(0),
                name: r.get(1),
                category: r.get(2),
                provider: r.get(3),
                endpoint: r.get(4),
                status: r.get(5),
                risk_level: r.get(6),
                assessment_status: r.get(7),
                declared_by: r.get(8),
                declared_at: r.get(9),
                first_seen: r.get(10),
                last_seen: r.get(11),
                remediation: r.get(12),
                metadata: r.get(13),
            })
            .collect())
    }

    async fn upsert_ai_system(
        &self,
        system: &super::threatclaw_store::NewAiSystem,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Status promotion rule: keep the more "advanced" one on conflict
        //   detected < declared < assessed < retired
        // Handled by a CASE expression below. last_seen refreshed either way.
        let q = r#"
            INSERT INTO ai_systems (name, category, provider, endpoint, status, risk_level, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, '{}'::jsonb))
            ON CONFLICT (category, provider, endpoint) DO UPDATE SET
                name       = EXCLUDED.name,
                last_seen  = NOW(),
                status     = CASE
                    WHEN ai_systems.status = 'retired' THEN 'retired'
                    WHEN ai_systems.status = 'assessed' AND EXCLUDED.status IN ('detected','declared') THEN 'assessed'
                    WHEN ai_systems.status = 'declared' AND EXCLUDED.status = 'detected' THEN 'declared'
                    ELSE EXCLUDED.status
                END,
                risk_level = COALESCE(EXCLUDED.risk_level, ai_systems.risk_level),
                metadata   = ai_systems.metadata || EXCLUDED.metadata
            RETURNING id
        "#;
        let metadata = system.metadata.as_ref();
        let row = conn
            .query_one(
                q,
                &[
                    &system.name,
                    &system.category,
                    &system.provider,
                    &system.endpoint,
                    &system.status,
                    &system.risk_level,
                    &metadata,
                ],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn update_ai_system_status(
        &self,
        id: i64,
        status: &str,
        risk_level: Option<&str>,
        declared_by: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let q = r#"
            UPDATE ai_systems SET
                status      = $2,
                risk_level  = COALESCE($3, risk_level),
                declared_by = COALESCE($4, declared_by),
                declared_at = CASE WHEN $2 = 'declared' AND declared_at IS NULL THEN NOW() ELSE declared_at END,
                last_seen   = NOW()
            WHERE id = $1
        "#;
        conn.execute(q, &[&id, &status, &risk_level, &declared_by])
            .await
            .map_err(query_err)?;
        Ok(())
    }

    async fn count_ai_systems_by_status(&self) -> Result<Vec<(String, i64)>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT status, COUNT(*) FROM ai_systems GROUP BY status",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1)))
            .collect())
    }

    async fn auto_close_stale_findings(
        &self,
        skill_id: &str,
        since: &str,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn.query_one(
            r#"UPDATE findings SET status = 'resolved', resolved_by = 'auto-rescan', resolved_at = NOW()
               WHERE skill_id = $1 AND status IN ('open', 'in_progress')
               AND detected_at < $2::timestamptz
               RETURNING COUNT(*) OVER() AS total"#,
            &[&skill_id, &since],
        ).await;
        match row {
            Ok(r) => Ok(r.get::<_, i64>(0)),
            Err(_) => {
                // If no rows matched, the RETURNING fails — count directly
                let count = conn
                    .query_one(
                        r#"SELECT COUNT(*)::bigint FROM findings
                       WHERE skill_id = $1 AND status = 'resolved' AND resolved_by = 'auto-rescan'
                       AND resolved_at > NOW() - INTERVAL '1 minute'"#,
                        &[&skill_id],
                    )
                    .await
                    .map_err(query_err)?;
                Ok(count.get::<_, i64>(0))
            }
        }
    }

    async fn count_findings_by_severity(&self) -> Result<Vec<(String, i64)>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                r#"SELECT severity, COUNT(*)::bigint FROM findings WHERE status != 'resolved'
                   GROUP BY severity ORDER BY
                   CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                   WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"#,
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1)))
            .collect())
    }

    /// Count distinct signal sources on an asset within the last N minutes.
    /// Three independent tables contribute one signal each:
    ///   1. sigma_alerts on hostname=asset
    ///   2. findings with `asset` matching (case-insensitive)
    ///   3. firewall_events with src_ip / dst_ip matching the asset (when
    ///      the asset is referenced by IP) OR the firewall hostname for
    ///      asset-by-name. Uses raw_meta->>'hostname' as fallback.
    /// We don't double-count rows in the same table — the goal is to
    /// answer "is there any other independent signal on this asset?".
    async fn count_recent_signals_on_asset(
        &self,
        asset: &str,
        minutes: i64,
    ) -> Result<i64, DatabaseError> {
        if asset.is_empty() {
            return Ok(0);
        }
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                // findings.detected_at (pas created_at — la colonne ne
                // s'appelle pas pareil) ; firewall_events.timestamp ;
                // matching insensible à la casse sur findings et
                // sigma_alerts pour absorber les variations 'srv-01-dom'
                // / 'SRV-01-DOM' qui apparaissent selon la source.
                //
                // 2026-06-17: resolve the asset to its full alias set
                // (id, name, hostname, ip_addresses) before counting.
                // Without this the dispatcher's recent_count_5m /
                // recent_count_1h signals returned 0 for every
                // auto-enrolled asset (id = 'syslog-observed-sd-98664'
                // while sigma_alerts keyed on the bare hostname
                // 'sd-98664'). The graph CACAO then saw the asset as
                // perfectly quiet and delegated to the LLM on a void.
                // The same shape of mismatch silenced the sigma engine's
                // medium-rule promotion path that uses this count to
                // decide whether to escalate to an incident.
                "WITH asset_resolved AS ( \
                   SELECT id, name, hostname, COALESCE(ip_addresses, '{}'::text[]) AS ips \
                   FROM assets \
                   WHERE id = $1 OR name = $1 OR hostname = $1 \
                      OR LOWER(name) = LOWER($1) OR LOWER(hostname) = LOWER($1) \
                 ), asset_aliases AS ( \
                   SELECT id AS alias FROM asset_resolved \
                   UNION SELECT name FROM asset_resolved WHERE name IS NOT NULL \
                   UNION SELECT hostname FROM asset_resolved WHERE hostname IS NOT NULL \
                   UNION SELECT LOWER(name) FROM asset_resolved WHERE name IS NOT NULL \
                   UNION SELECT LOWER(hostname) FROM asset_resolved WHERE hostname IS NOT NULL \
                   UNION SELECT $1 \
                 ), asset_ips AS ( \
                   SELECT split_part(unnest(ips), ':', 1) AS ip FROM asset_resolved \
                 ) \
                 SELECT \
                   (SELECT COUNT(*) FROM sigma_alerts \
                      WHERE LOWER(hostname) IN (SELECT LOWER(alias) FROM asset_aliases) \
                        AND matched_at > NOW() - ($2::int * INTERVAL '1 minute'))::bigint \
                 + (SELECT COUNT(*) FROM findings \
                      WHERE LOWER(asset) IN (SELECT LOWER(alias) FROM asset_aliases) \
                        AND detected_at > NOW() - ($2::int * INTERVAL '1 minute'))::bigint \
                 + (SELECT COUNT(*) FROM firewall_events \
                      WHERE timestamp > NOW() - ($2::int * INTERVAL '1 minute') \
                        AND ( \
                          host(src_ip) IN (SELECT ip FROM asset_ips) \
                          OR host(dst_ip) IN (SELECT ip FROM asset_ips) \
                        ))::bigint \
                 AS total",
                &[&asset, &(minutes as i32)],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    // ── Shift Report queries ──

    async fn count_findings_since(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT COUNT(*)::bigint FROM findings WHERE detected_at >= $1",
                &[&since],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn count_alerts_since(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT COUNT(*)::bigint FROM sigma_alerts WHERE matched_at >= $1",
                &[&since],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn count_incidents_since(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT COUNT(*)::bigint FROM incidents WHERE created_at >= $1",
                &[&since],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn count_timeline_events_since(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT COUNT(*)::bigint FROM forensic_timeline WHERE created_at >= $1",
                &[&since],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn escalate_incident_severity(
        &self,
        incident_id: i32,
        new_severity: &str,
        reason: &str,
    ) -> Result<u64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let note = serde_json::json!([{
            "text": reason,
            "author": "dfir",
            "at": chrono::Utc::now().to_rfc3339(),
        }]);
        // Upgrade-only: the WHERE clause compares severity ranks (case-insensitive)
        // so we never downgrade and the update is a no-op if already >= new level.
        let n = conn
            .execute(
                "UPDATE incidents \
                 SET severity = $2, \
                     notes = COALESCE(notes, '[]'::jsonb) || $3::jsonb, \
                     updated_at = NOW() \
                 WHERE id = $1 \
                   AND (CASE upper(severity) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 \
                          WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) \
                     < (CASE upper($2) WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 \
                          WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END)",
                &[&incident_id, &new_severity, &note],
            )
            .await
            .map_err(query_err)?;
        Ok(n)
    }

    async fn list_finding_titles_since(
        &self,
        since: chrono::DateTime<chrono::Utc>,
        severity: &str,
        limit: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn.query(
            "SELECT title FROM findings WHERE detected_at >= $1 AND UPPER(severity) = UPPER($2) ORDER BY detected_at DESC LIMIT $3",
            &[&since, &severity, &limit],
        ).await.map_err(query_err)?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    async fn list_active_assets_since(
        &self,
        since: chrono::DateTime<chrono::Utc>,
        limit: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn.query(
            "SELECT DISTINCT COALESCE(asset, 'unknown') FROM findings WHERE detected_at >= $1 \
             UNION \
             SELECT DISTINCT COALESCE(hostname, 'unknown') FROM sigma_alerts WHERE matched_at >= $1 \
             LIMIT $2",
            &[&since, &limit],
        ).await.map_err(query_err)?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    async fn list_ml_anomalies(
        &self,
        threshold: f64,
        limit: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn.query(
            "SELECT asset_id || ' (score: ' || ROUND(score::numeric, 2) || ')' FROM ml_scores WHERE score >= $1 ORDER BY score DESC LIMIT $2",
            &[&threshold, &limit],
        ).await.map_err(query_err)?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    async fn list_alerts(
        &self,
        level: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AlertRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Exclude archived by default. Pass "include_archived" to bypass or
        // "archived" to filter only archived rows. Same semantics as list_incidents.
        let status_owned = status.map(String::from);
        let include_archived = status_owned.as_deref() == Some("include_archived");
        // Translate sentinel values — NULL or "all" both mean "default view"
        let effective_status: Option<String> = match status_owned.as_deref() {
            None | Some("all") | Some("include_archived") => None,
            Some(s) => Some(s.to_string()),
        };
        let archived_clause = if include_archived {
            ""
        } else {
            " AND status != 'archived'"
        };
        let q = format!(
            "SELECT id, rule_id, level, title, status, hostname, \
                    host(source_ip), username, matched_at::text, matched_fields \
             FROM sigma_alerts \
             WHERE ($1::text IS NULL OR UPPER(level) = UPPER($1)) \
               AND ($2::text IS NULL OR status = $2){} \
             ORDER BY matched_at DESC \
             LIMIT $3 OFFSET $4",
            archived_clause
        );
        let rows = conn
            .query(q.as_str(), &[&level, &effective_status, &limit, &offset])
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| AlertRecord {
                id: r.get(0),
                rule_id: r.get(1),
                level: r.get(2),
                title: r.get(3),
                status: r.get(4),
                hostname: r.get(5),
                source_ip: r.get(6),
                username: r.get(7),
                matched_at: r.get(8),
                matched_fields: r.get(9),
            })
            .collect())
    }

    async fn count_alerts_filtered(
        &self,
        level: Option<&str>,
        status: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                r#"SELECT COUNT(*)::bigint FROM sigma_alerts
               WHERE ($1::text IS NULL OR UPPER(level) = UPPER($1))
                 AND ($2::text IS NULL OR status = $2)"#,
                &[&level, &status],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn get_alert(&self, id: i64) -> Result<Option<AlertRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                r#"SELECT id, rule_id, level, title, status, hostname,
                          host(source_ip), username, matched_at::text, matched_fields
                   FROM sigma_alerts WHERE id = $1"#,
                &[&id],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(|r| AlertRecord {
            id: r.get(0),
            rule_id: r.get(1),
            level: r.get(2),
            title: r.get(3),
            status: r.get(4),
            hostname: r.get(5),
            source_ip: r.get(6),
            username: r.get(7),
            matched_at: r.get(8),
            matched_fields: r.get(9),
        }))
    }

    async fn update_alert_status(
        &self,
        id: i64,
        status: &str,
        notes: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            r#"UPDATE sigma_alerts SET status = $1, analyst_notes = COALESCE($2, analyst_notes),
                      resolved_at = CASE WHEN $1 = 'resolved' THEN NOW() ELSE resolved_at END
               WHERE id = $3"#,
            &[&status, &notes, &id],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn count_alerts_by_level(&self) -> Result<Vec<(String, i64)>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                r#"SELECT level, COUNT(*)::bigint FROM sigma_alerts WHERE status != 'resolved'
                   GROUP BY level ORDER BY
                   CASE level WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                   WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"#,
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1)))
            .collect())
    }

    // ── Scan queue (V51__scan_queue.sql) ──

    async fn enqueue_scan(&self, req: &NewScanRequest) -> Result<Option<i64>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let ttl = req.ttl_seconds.unwrap_or(3600);

        // Dedup: if a `done` row exists for (target, scan_type) within
        // the TTL window, don't enqueue a new one. Manual scans pass
        // ttl_seconds=0 which always falls through.
        if ttl > 0 {
            let interval_str = format!("{} seconds", ttl);
            let recent: Option<i64> = conn
                .query_opt(
                    "SELECT id FROM scan_queue \
                     WHERE target = $1 AND scan_type = $2 AND status = 'done' \
                       AND finished_at > now() - $3::interval \
                     ORDER BY finished_at DESC LIMIT 1",
                    &[&req.target, &req.scan_type, &interval_str],
                )
                .await
                .map_err(query_err)?
                .map(|r| r.get(0));
            if recent.is_some() {
                return Ok(None);
            }
        }

        let row = conn
            .query_one(
                "INSERT INTO scan_queue \
                 (target, scan_type, asset_id, requested_by, ttl_seconds) \
                 VALUES ($1, $2, $3, $4, $5) RETURNING id",
                &[
                    &req.target,
                    &req.scan_type,
                    &req.asset_id,
                    &req.requested_by,
                    &ttl,
                ],
            )
            .await
            .map_err(query_err)?;
        Ok(Some(row.get(0)))
    }

    async fn claim_next_scan(&self, worker_id: &str) -> Result<Option<ScanJob>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Atomic claim: SELECT FOR UPDATE SKIP LOCKED so concurrent
        // workers each grab a different row. UPDATE flips status to
        // running and stamps started_at + worker_id in the same tx.
        let row = conn
            .query_opt(
                "WITH claimed AS ( \
                    SELECT id FROM scan_queue \
                    WHERE status = 'queued' \
                    ORDER BY requested_at ASC \
                    LIMIT 1 \
                    FOR UPDATE SKIP LOCKED \
                 ) \
                 UPDATE scan_queue q \
                 SET status = 'running', started_at = now(), worker_id = $1 \
                 FROM claimed c \
                 WHERE q.id = c.id \
                 RETURNING q.id, q.target, q.scan_type, q.status, q.asset_id, \
                           q.requested_by, q.requested_at, q.started_at, q.finished_at, \
                           q.duration_ms, q.result_json, q.error_msg, q.ttl_seconds, q.worker_id",
                &[&worker_id],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(scan_job_from_row))
    }

    async fn complete_scan(
        &self,
        id: i64,
        result: &serde_json::Value,
        duration_ms: i32,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE scan_queue \
             SET status = 'done', finished_at = now(), duration_ms = $2, result_json = $3 \
             WHERE id = $1",
            &[&id, &duration_ms, &result],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn fail_scan(
        &self,
        id: i64,
        error_msg: &str,
        duration_ms: i32,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE scan_queue \
             SET status = 'error', finished_at = now(), duration_ms = $2, error_msg = $3 \
             WHERE id = $1",
            &[&id, &duration_ms, &error_msg],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn recent_scans_for_asset(
        &self,
        asset_id: &str,
        limit: i64,
    ) -> Result<Vec<ScanJob>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, target, scan_type, status, asset_id, requested_by, \
                        requested_at, started_at, finished_at, duration_ms, \
                        result_json, error_msg, ttl_seconds, worker_id \
                 FROM scan_queue \
                 WHERE asset_id = $1 \
                 ORDER BY requested_at DESC LIMIT $2",
                &[&asset_id, &limit],
            )
            .await
            .map_err(query_err)?;
        Ok(rows.into_iter().map(scan_job_from_row).collect())
    }

    async fn has_running_scan_for_asset(&self, asset_id: &str) -> Result<bool, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                "SELECT 1 FROM scan_queue \
                 WHERE asset_id = $1 AND status IN ('queued', 'running') LIMIT 1",
                &[&asset_id],
            )
            .await
            .map_err(query_err)?;
        Ok(row.is_some())
    }

    async fn list_scans(
        &self,
        status: Option<&str>,
        scan_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ScanJob>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, target, scan_type, status, asset_id, requested_by, \
                        requested_at, started_at, finished_at, duration_ms, \
                        result_json, error_msg, ttl_seconds, worker_id \
                 FROM scan_queue \
                 WHERE ($1::text IS NULL OR status = $1) \
                   AND ($2::text IS NULL OR scan_type = $2) \
                 ORDER BY requested_at DESC LIMIT $3 OFFSET $4",
                &[&status, &scan_type, &limit, &offset],
            )
            .await
            .map_err(query_err)?;
        Ok(rows.into_iter().map(scan_job_from_row).collect())
    }

    async fn count_scans(
        &self,
        status: Option<&str>,
        scan_type: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT COUNT(*)::bigint FROM scan_queue \
                 WHERE ($1::text IS NULL OR status = $1) \
                   AND ($2::text IS NULL OR scan_type = $2)",
                &[&status, &scan_type],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn get_skill_config(
        &self,
        skill_id: &str,
    ) -> Result<Vec<SkillConfigRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT skill_id, key, value FROM skill_configs WHERE skill_id = $1 ORDER BY key",
                &[&skill_id],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| SkillConfigRecord {
                skill_id: r.get(0),
                key: r.get(1),
                value: r.get(2),
            })
            .collect())
    }

    async fn set_skill_config(
        &self,
        skill_id: &str,
        key: &str,
        value: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            r#"INSERT INTO skill_configs (skill_id, key, value, updated_at)
               VALUES ($1, $2, $3, NOW())
               ON CONFLICT (skill_id, key) DO UPDATE SET value = $3, updated_at = NOW()"#,
            &[&skill_id, &key, &value],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn delete_skill_config(&self, skill_id: &str, key: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "DELETE FROM skill_configs WHERE skill_id = $1 AND key = $2",
            &[&skill_id, &key],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn record_metric(
        &self,
        name: &str,
        value: f64,
        labels: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "INSERT INTO metrics_snapshots (metric_name, metric_value, labels) VALUES ($1, $2, $3)",
            &[&name, &value, labels],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn get_dashboard_metrics(&self) -> Result<DashboardMetrics, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;

        let findings_row = conn.query_one(
            r#"SELECT
                COALESCE(SUM(CASE WHEN severity = 'critical' AND status != 'resolved' THEN 1 ELSE 0 END)::bigint, 0),
                COALESCE(SUM(CASE WHEN severity = 'high' AND status != 'resolved' THEN 1 ELSE 0 END)::bigint, 0),
                COALESCE(SUM(CASE WHEN severity = 'medium' AND status != 'resolved' THEN 1 ELSE 0 END)::bigint, 0),
                COALESCE(SUM(CASE WHEN severity = 'low' AND status != 'resolved' THEN 1 ELSE 0 END)::bigint, 0)
               FROM findings"#,
            &[],
        ).await.map_err(query_err)?;

        let alerts_row = conn.query_one(
            r#"SELECT COUNT(*)::bigint, COALESCE(SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END)::bigint, 0)
               FROM sigma_alerts WHERE matched_at > NOW() - INTERVAL '24 hours'"#,
            &[],
        ).await.map_err(query_err)?;

        let score: f64 = conn.query_opt(
            "SELECT metric_value FROM metrics_snapshots WHERE metric_name = 'security_score' ORDER BY recorded_at DESC LIMIT 1", &[],
        ).await.map_err(query_err)?.map(|r| r.get(0)).unwrap_or(0.0);

        let cloud: f64 = conn.query_opt(
            "SELECT metric_value FROM metrics_snapshots WHERE metric_name = 'cloud_score' ORDER BY recorded_at DESC LIMIT 1", &[],
        ).await.map_err(query_err)?.map(|r| r.get(0)).unwrap_or(0.0);

        let darkweb: f64 = conn.query_opt(
            "SELECT metric_value FROM metrics_snapshots WHERE metric_name = 'darkweb_leaks' ORDER BY recorded_at DESC LIMIT 1", &[],
        ).await.map_err(query_err)?.map(|r| r.get(0)).unwrap_or(0.0);

        Ok(DashboardMetrics {
            security_score: score,
            findings_critical: findings_row.get(0),
            findings_high: findings_row.get(1),
            findings_medium: findings_row.get(2),
            findings_low: findings_row.get(3),
            alerts_total: alerts_row.get(0),
            alerts_new: alerts_row.get(1),
            cloud_score: cloud,
            darkweb_leaks: darkweb as i64,
        })
    }

    async fn list_anonymizer_rules(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, label, pattern, token_prefix, capture_group, enabled
                 FROM anonymizer_rules WHERE enabled = true ORDER BY created_at",
                &[],
            )
            .await
            .map_err(query_err)?;

        let rules: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.get::<_, uuid::Uuid>(0).to_string(),
                    "label": r.get::<_, String>(1),
                    "pattern": r.get::<_, String>(2),
                    "token_prefix": r.get::<_, String>(3),
                    "capture_group": r.get::<_, i32>(4),
                    "enabled": r.get::<_, bool>(5),
                })
            })
            .collect();

        Ok(rules)
    }

    async fn create_anonymizer_rule(
        &self,
        label: &str,
        pattern: &str,
        token_prefix: &str,
        capture_group: i32,
    ) -> Result<String, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "INSERT INTO anonymizer_rules (label, pattern, token_prefix, capture_group)
                 VALUES ($1, $2, $3, $4) RETURNING id",
                &[&label, &pattern, &token_prefix, &capture_group],
            )
            .await
            .map_err(query_err)?;

        let id: uuid::Uuid = row.get(0);
        Ok(id.to_string())
    }

    async fn delete_anonymizer_rule(&self, id: &str) -> Result<(), DatabaseError> {
        let uuid = uuid::Uuid::parse_str(id)
            .map_err(|e| DatabaseError::Query(format!("Invalid UUID: {e}")))?;
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute("DELETE FROM anonymizer_rules WHERE id = $1", &[&uuid])
            .await
            .map_err(query_err)?;
        Ok(())
    }

    // ── Logs (raw log records from Fluent Bit) ──

    async fn query_logs(
        &self,
        minutes_back: i64,
        hostname: Option<&str>,
        tag: Option<&str>,
        limit: i64,
    ) -> Result<Vec<LogRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let interval_clause = format!("INTERVAL '{} minutes'", minutes_back);

        // Build query — interval is safe (i64), limit is safe (i64)
        // Hostname filtering uses an asset-alias CTE so the L1 LLM can
        // pass either the raw hostname it sees in the dossier (typical)
        // or the prefixed asset.id (`syslog-observed-X`) and still hit
        // the rows — log_search would otherwise miss any auto-enrolled
        // host whose id and hostname diverge.
        let rows = match (hostname, tag) {
            (Some(h), Some(t)) => {
                conn.query(
                    &format!("WITH asset_resolved AS ( \
                                SELECT id, name, hostname FROM assets \
                                WHERE id = $1 OR name = $1 OR hostname = $1 \
                                   OR LOWER(name) = LOWER($1) OR LOWER(hostname) = LOWER($1) \
                              ), asset_aliases AS ( \
                                SELECT id AS alias FROM asset_resolved \
                                UNION SELECT name FROM asset_resolved WHERE name IS NOT NULL \
                                UNION SELECT hostname FROM asset_resolved WHERE hostname IS NOT NULL \
                                UNION SELECT $1 \
                              ) \
                              SELECT id, tag, time::text, hostname, data FROM logs \
                              WHERE time >= NOW() - {} \
                                AND hostname IN (SELECT alias FROM asset_aliases) \
                                AND tag = $2 ORDER BY time DESC LIMIT {}", interval_clause, limit),
                    &[&h, &t],
                ).await.map_err(query_err)?
            }
            (Some(h), None) => {
                conn.query(
                    &format!("WITH asset_resolved AS ( \
                                SELECT id, name, hostname FROM assets \
                                WHERE id = $1 OR name = $1 OR hostname = $1 \
                                   OR LOWER(name) = LOWER($1) OR LOWER(hostname) = LOWER($1) \
                              ), asset_aliases AS ( \
                                SELECT id AS alias FROM asset_resolved \
                                UNION SELECT name FROM asset_resolved WHERE name IS NOT NULL \
                                UNION SELECT hostname FROM asset_resolved WHERE hostname IS NOT NULL \
                                UNION SELECT $1 \
                              ) \
                              SELECT id, tag, time::text, hostname, data FROM logs \
                              WHERE time >= NOW() - {} \
                                AND hostname IN (SELECT alias FROM asset_aliases) \
                              ORDER BY time DESC LIMIT {}", interval_clause, limit),
                    &[&h],
                ).await.map_err(query_err)?
            }
            (None, Some(t)) => {
                conn.query(
                    &format!("SELECT id, tag, time::text, hostname, data FROM logs WHERE time >= NOW() - {} AND tag = $1 ORDER BY time DESC LIMIT {}", interval_clause, limit),
                    &[&t],
                ).await.map_err(query_err)?
            }
            (None, None) => {
                // Per-tag quota via window function. Without it, a single
                // high-volume tag (typically syslog.tcp.*) eats the whole
                // LIMIT and starves every other source — on cyb06 a flat
                // `LIMIT 2000` returned 100 % syslog, and the sigma engine
                // never saw a single osquery.sysmon event despite ~3k/min
                // arriving. PARTITION BY tag with `rn <= per_tag` keeps a
                // fair slice for each ingestion channel.
                let per_tag = std::cmp::max(limit / 4, 200);
                conn.query(
                    &format!(
                        "SELECT id, tag, time, hostname, data \
                         FROM ( \
                            SELECT id, tag, time::text AS time, hostname, data, \
                                   ROW_NUMBER() OVER (PARTITION BY tag ORDER BY time DESC) AS rn \
                            FROM logs WHERE time >= NOW() - {} \
                         ) ranked \
                         WHERE rn <= {} \
                         ORDER BY time DESC \
                         LIMIT {}",
                        interval_clause, per_tag, limit
                    ),
                    &[],
                ).await.map_err(query_err)?
            }
        };

        Ok(rows
            .iter()
            .map(|r| LogRecord {
                id: r.get(0),
                tag: r.try_get(1).ok(),
                time: r.get(2),
                // Hunt-panel read does not scan via the cursor, so it does not
                // select created_at; the cursor never consults this LogRecord.
                created_at: String::new(),
                hostname: r.try_get(3).ok(),
                data: r.try_get::<_, serde_json::Value>(4).unwrap_or_default(),
            })
            .collect())
    }

    async fn query_logs_after_cursor(
        &self,
        after_time: Option<chrono::DateTime<chrono::Utc>>,
        after_id: i64,
        minutes_back_floor: i64,
        limit: i64,
    ) -> Result<Vec<LogRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Per-tag cap balances fairness (no one source can starve the
        // others) with throughput (the dominant source has to be able to
        // catch up). Setting it to 80 % of the total limit lets a single
        // tag burst through most of the batch when it is the only one
        // ingesting heavily, while still reserving ~20 % for the other
        // sources so a syslog flood cannot completely drown out osquery.
        // The previous limit/4 cap (1250 on a 5000-row batch) meant a
        // syslog spike of >5000 events per 5-min cycle never drained —
        // each cycle ate only 1250 rows from the front of the backlog
        // while ~10 k waited at the tail, so a real attack at the tail
        // never made it to the engine until the spike subsided.
        let per_tag = std::cmp::max((limit * 4) / 5, 1000);
        let interval_clause = format!("INTERVAL '{} minutes'", minutes_back_floor);

        // Resolve the effective floor: max of (cursor, now - minutes_back_floor).
        // The floor keeps a stale cursor from re-scanning days of history after
        // an outage — if the cursor's older than minutes_back_floor, we accept
        // the gap (a warn-once is logged by the caller) rather than melting the
        // database trying to catch up.
        //
        // The cursor advances on `created_at` (DB insert time, `DEFAULT now()`),
        // NOT the event `time`. `time` is attacker/source-controlled and routinely
        // drifts hours into the future (TZ-naïve syslog), which poisoned the old
        // `ORDER BY time` cursor: one future-dated row pinned the cursor ahead of
        // wall-clock and every real-time event landed *behind* it, invisible to
        // the engine until the wall clock caught up — a multi-hour blind window.
        // `created_at` is assigned by Postgres at INSERT, so it is monotonic and
        // immune to upstream clock drift on every ingest path (webhook insert_log
        // + the Fluent Bit staging trigger both leave it to the column default).
        let effective_after: chrono::DateTime<chrono::Utc> = match after_time {
            Some(t) => {
                let floor = chrono::Utc::now() - chrono::Duration::minutes(minutes_back_floor);
                if t < floor { floor } else { t }
            }
            None => chrono::Utc::now() - chrono::Duration::minutes(minutes_back_floor),
        };

        // Forward-paged read with the same fair-share per-tag quota as the
        // legacy `query_logs`. Order is ASC on (created_at, id) so the caller can
        // advance the cursor to the last row consumed without re-reading.
        // NOTE the parentheses around the keyset predicate: `A OR (B AND C)` (the
        // previous, unparenthesised form) bound as `A OR (B AND C)` only by luck
        // of AND-precedence — the intended floor `AND created_at >= NOW() - itv`
        // was actually swallowed into the second OR arm, so the `(created_at > $1)`
        // arm scanned with NO floor at all. Explicit grouping fixes that.
        let rows = conn
            .query(
                &format!(
                    "SELECT id, tag, time, created_at, hostname, data \
                     FROM ( \
                        SELECT id, tag, time::text AS time, created_at, hostname, data, \
                               ROW_NUMBER() OVER (PARTITION BY tag ORDER BY created_at ASC, id ASC) AS rn \
                        FROM logs WHERE \
                            ((created_at > $1) OR (created_at = $1 AND id > $2)) \
                            AND created_at >= NOW() - {} \
                     ) ranked \
                     WHERE rn <= {} \
                     ORDER BY created_at ASC, id ASC \
                     LIMIT {}",
                    interval_clause, per_tag, limit
                ),
                &[&effective_after, &after_id],
            )
            .await
            .map_err(query_err)?;

        Ok(rows
            .iter()
            .map(|r| LogRecord {
                id: r.get(0),
                tag: r.try_get(1).ok(),
                time: r.get(2),
                // Read created_at as a native timestamptz and re-serialise to
                // RFC 3339 (`...T...Z`), NOT `::text` (which yields Postgres'
                // space-separated form `2026-06-20 14:30:00+00` that
                // chrono::parse_from_rfc3339 rejects). The cursor round-trips
                // through this string, so the format must be parse-stable.
                created_at: r.get::<_, chrono::DateTime<chrono::Utc>>(3).to_rfc3339(),
                hostname: r.try_get(4).ok(),
                data: r.try_get::<_, serde_json::Value>(5).unwrap_or_default(),
            })
            .collect())
    }

    async fn insert_log(
        &self,
        tag: &str,
        hostname: &str,
        data: &serde_json::Value,
        time: &str,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Why pass `data` as `&Value` instead of a serialised string with a
        // `::jsonb` cast: tokio-postgres's `with-serde_json-1` feature binds
        // `serde_json::Value` natively with the right jsonb OID. Sending a
        // String + `::jsonb` cast looked fine in simple test cases but made
        // the prepared-statement type inference reject the param with
        // `error serializing parameter N` on production payloads (observed
        // on every Wazuh OpenCanary alert). insert_finding already used the
        // native-type pattern without issue — mirroring it here.
        //
        // Same reasoning for `time`: parse to DateTime<Utc> client-side so
        // tokio-postgres binds it as timestamptz without a cast.
        // Future-clamp: some syslog producers (rsyslog with a TZ-naïve
        // template piped through fluent-bit's syslog-rfc3164 parser) emit
        // a timestamp that has already been adjusted to a local timezone
        // and is then tagged as UTC at parse time, so the row lands an
        // hour or two ahead of wall-clock. The sigma cursor relies on
        // monotonically-recent timestamps to advance forward and a
        // future row poisons it for the rest of the day. We accept the
        // record but pin its time to `now()` when it would otherwise be
        // ahead — the upstream TZ bug is logged separately. Clock drift
        // of a few seconds is tolerated; only meaningful skew (> 60 s)
        // triggers the clamp.
        let parsed_time = chrono::DateTime::parse_from_rfc3339(time)
            .map(|d| d.with_timezone(&chrono::Utc))
            .map_err(|e| DatabaseError::Query(format!("invalid timestamp: {}", e)))?;
        let parsed_time = {
            let now = chrono::Utc::now();
            if parsed_time > now + chrono::Duration::seconds(60) {
                tracing::warn!(
                    "INSERT_LOG: tag={tag} time={time} is ahead of wall-clock by >60s, clamping to now (likely upstream TZ bug)"
                );
                now
            } else {
                parsed_time
            }
        };
        let row = conn
            .query_one(
                "INSERT INTO logs (tag, hostname, data, time) VALUES ($1, $2, $3, $4) RETURNING id",
                &[&tag, &hostname, data, &parsed_time],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn insert_sigma_alert(
        &self,
        rule_id: &str,
        level: &str,
        title: &str,
        hostname: &str,
        source_ip: Option<&str>,
        username: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Ensure the rule exists (create a stub if not)
        let rule_yaml = format!(
            "title: {}\nstatus: test\nlevel: {}\ndetection:\n  condition: test",
            title, level
        );
        let empty_json = serde_json::json!({});
        conn.execute(
            "INSERT INTO sigma_rules (id, title, level, rule_yaml, detection_json, enabled) VALUES ($1, $2, $3, $4, $5::jsonb, true) ON CONFLICT (id) DO NOTHING",
            &[&rule_id, &title, &level, &rule_yaml, &empty_json],
        ).await.map_err(query_err)?;

        let user_str = username.unwrap_or("");
        // Parse the IP client-side so tokio-postgres binds it as a native
        // inet param instead of routing through an `$N::inet` SQL cast —
        // the cast path was failing with `error serializing parameter N` on
        // production payloads for the same reason insert_log failed above.
        let parsed_ip: Option<std::net::IpAddr> = source_ip
            .filter(|ip| !ip.is_empty())
            .and_then(|ip| ip.parse().ok());

        let row = if let Some(ip) = parsed_ip {
            conn.query_one(
                "INSERT INTO sigma_alerts (rule_id, level, title, hostname, username, status, source_ip) VALUES ($1, $2, $3, $4, $5, 'new', $6) RETURNING id",
                &[&rule_id, &level, &title, &hostname, &user_str, &ip],
            ).await.map_err(query_err)?
        } else {
            conn.query_one(
                "INSERT INTO sigma_alerts (rule_id, level, title, hostname, username, status) VALUES ($1, $2, $3, $4, $5, 'new') RETURNING id",
                &[&rule_id, &level, &title, &hostname, &user_str],
            ).await.map_err(query_err)?
        };
        Ok(row.get(0))
    }

    async fn insert_sigma_alert_with_fields(
        &self,
        rule_id: &str,
        level: &str,
        title: &str,
        hostname: &str,
        source_ip: Option<&str>,
        username: Option<&str>,
        matched_fields: &serde_json::Value,
        log_id: Option<i64>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Stub rule (idempotent) — only created when the caller bypasses
        // the on-disk rule loader (legacy compat path: external IDS
        // connectors that ship findings under a rule_id we have not yet
        // declared). `status='auto-stub'` keeps the row out of the
        // dashboard's rule list and the `sigma_rule_stats` matview
        // refresh; `enabled=false` keeps it inert if the engine ever
        // tried to compile it (no detection body).
        let rule_yaml = format!(
            "title: {}\nstatus: auto-stub\nlevel: {}\ndetection:\n  condition: test",
            title, level
        );
        let empty_json = serde_json::json!({});
        conn.execute(
            "INSERT INTO sigma_rules (id, title, level, status, rule_yaml, detection_json, enabled) \
             VALUES ($1, $2, $3, 'auto-stub', $4, $5::jsonb, false) ON CONFLICT (id) DO NOTHING",
            &[&rule_id, &title, &level, &rule_yaml, &empty_json],
        )
        .await
        .map_err(query_err)?;

        let user_str = username.unwrap_or("");
        let parsed_ip: Option<std::net::IpAddr> = source_ip
            .filter(|ip| !ip.is_empty())
            .and_then(|ip| ip.parse().ok());

        // log_id wires the alert back to the source log line so the
        // operator can drill into the raw event from the alert detail
        // page. Without this every sigma_alert lands with log_id NULL
        // and the forensic view is broken (audit 2026-06-17).
        let row = match (parsed_ip, log_id) {
            (Some(ip), Some(lid)) => conn.query_one(
                "INSERT INTO sigma_alerts (rule_id, level, title, hostname, username, status, source_ip, matched_fields, log_id) \
                 VALUES ($1, $2, $3, $4, $5, 'new', $6, $7, $8) RETURNING id",
                &[&rule_id, &level, &title, &hostname, &user_str, &ip, matched_fields, &lid],
            ).await.map_err(query_err)?,
            (Some(ip), None) => conn.query_one(
                "INSERT INTO sigma_alerts (rule_id, level, title, hostname, username, status, source_ip, matched_fields) \
                 VALUES ($1, $2, $3, $4, $5, 'new', $6, $7) RETURNING id",
                &[&rule_id, &level, &title, &hostname, &user_str, &ip, matched_fields],
            ).await.map_err(query_err)?,
            (None, Some(lid)) => conn.query_one(
                "INSERT INTO sigma_alerts (rule_id, level, title, hostname, username, status, matched_fields, log_id) \
                 VALUES ($1, $2, $3, $4, $5, 'new', $6, $7) RETURNING id",
                &[&rule_id, &level, &title, &hostname, &user_str, matched_fields, &lid],
            ).await.map_err(query_err)?,
            (None, None) => conn.query_one(
                "INSERT INTO sigma_alerts (rule_id, level, title, hostname, username, status, matched_fields) \
                 VALUES ($1, $2, $3, $4, $5, 'new', $6) RETURNING id",
                &[&rule_id, &level, &title, &hostname, &user_str, matched_fields],
            ).await.map_err(query_err)?,
        };
        Ok(row.get(0))
    }

    async fn list_sigma_rules_enabled(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn.query(
            "SELECT id, title, level, logsource_category, logsource_product, logsource_service, tags, detection_json, disposition, tier, risk_score FROM sigma_rules WHERE enabled = true",
            &[],
        ).await.map_err(query_err)?;
        let mut results = Vec::new();
        for row in &rows {
            let tags: Vec<String> = row.try_get::<_, Vec<String>>(6).unwrap_or_default();
            let detection: serde_json::Value = row.try_get(7).unwrap_or(serde_json::Value::Null);
            results.push(serde_json::json!({
                "id": row.get::<_, &str>(0),
                "title": row.get::<_, &str>(1),
                "level": row.get::<_, &str>(2),
                "logsource_category": row.try_get::<_, &str>(3).ok(),
                "logsource_product": row.try_get::<_, &str>(4).ok(),
                "logsource_service": row.try_get::<_, &str>(5).ok(),
                "tags": tags,
                "detection_json": detection,
                "disposition": row.try_get::<_, &str>(8).unwrap_or("detect"),
                "tier": row.try_get::<_, &str>(9).unwrap_or("queue"),
                "risk_score": row.try_get::<_, i32>(10).ok(),
            }));
        }
        Ok(results)
    }

    async fn list_sigma_rules_with_stats(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Left join — a rule with zero matches still shows up with 0 counts
        // and NULL last_fire_at; the dashboard renders that as "no fire yet".
        let rows = conn
            .query(
                "SELECT r.id, r.title, r.description, r.level, r.status, r.enabled, \
                        r.logsource_category, r.logsource_product, r.logsource_service, \
                        r.tags, r.author, r.updated_at::text, \
                        COALESCE(s.fire_count_7d, 0), COALESCE(s.fire_count_30d, 0), \
                        s.last_fire_at::text, COALESCE(s.fp_count_7d, 0), \
                        COALESCE(s.distinct_hosts_7d, 0), s.top_hostname_7d, \
                        r.disposition, r.tier, r.promoted_at::text \
                 FROM sigma_rules r \
                 LEFT JOIN sigma_rule_stats s ON s.rule_id = r.id \
                 ORDER BY r.id",
                &[],
            )
            .await
            .map_err(query_err)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let tags: Vec<String> = row.try_get::<_, Vec<String>>(9).unwrap_or_default();
            out.push(serde_json::json!({
                "id": row.get::<_, &str>(0),
                "title": row.get::<_, &str>(1),
                "description": row.try_get::<_, &str>(2).ok(),
                "level": row.get::<_, &str>(3),
                "status": row.try_get::<_, &str>(4).ok(),
                "enabled": row.get::<_, bool>(5),
                "logsource_category": row.try_get::<_, &str>(6).ok(),
                "logsource_product": row.try_get::<_, &str>(7).ok(),
                "logsource_service": row.try_get::<_, &str>(8).ok(),
                "tags": tags,
                "author": row.try_get::<_, &str>(10).ok(),
                "updated_at": row.try_get::<_, &str>(11).ok(),
                "fire_count_7d": row.get::<_, i64>(12),
                "fire_count_30d": row.get::<_, i64>(13),
                "last_fire_at": row.try_get::<_, &str>(14).ok(),
                "fp_count_7d": row.get::<_, i64>(15),
                "distinct_hosts_7d": row.get::<_, i64>(16),
                "top_hostname_7d": row.try_get::<_, &str>(17).ok(),
                "disposition": row.try_get::<_, &str>(18).unwrap_or("detect"),
                "tier": row.try_get::<_, &str>(19).unwrap_or("queue"),
                "promoted_at": row.try_get::<_, &str>(20).ok(),
            }));
        }
        Ok(out)
    }

    async fn get_sigma_rule_detail(
        &self,
        id: &str,
        recent_limit: i64,
    ) -> Result<Option<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let limit = recent_limit.clamp(1, 200);

        let row_opt = conn
            .query_opt(
                "SELECT r.id, r.title, r.description, r.level, r.status, r.enabled, \
                        r.logsource_category, r.logsource_product, r.logsource_service, \
                        r.tags, r.author, r.rule_yaml, r.detection_json, r.updated_at::text, \
                        COALESCE(s.fire_count_7d, 0), COALESCE(s.fire_count_30d, 0), \
                        s.last_fire_at::text, COALESCE(s.fp_count_7d, 0), \
                        COALESCE(s.distinct_hosts_7d, 0), s.top_hostname_7d, \
                        r.disposition, r.tier, r.promoted_at::text \
                 FROM sigma_rules r \
                 LEFT JOIN sigma_rule_stats s ON s.rule_id = r.id \
                 WHERE r.id = $1",
                &[&id],
            )
            .await
            .map_err(query_err)?;

        let row = match row_opt {
            Some(r) => r,
            None => return Ok(None),
        };

        let recent_rows = conn
            .query(
                "SELECT matched_at::text, level, hostname, host(source_ip), username, status \
                 FROM sigma_alerts WHERE rule_id = $1 \
                 ORDER BY matched_at DESC LIMIT $2",
                &[&id, &limit],
            )
            .await
            .map_err(query_err)?;

        let recent: Vec<serde_json::Value> = recent_rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "matched_at": r.try_get::<_, &str>(0).ok(),
                    "level": r.try_get::<_, &str>(1).ok(),
                    "hostname": r.try_get::<_, &str>(2).ok(),
                    "source_ip": r.try_get::<_, &str>(3).ok(),
                    "username": r.try_get::<_, &str>(4).ok(),
                    "status": r.try_get::<_, &str>(5).ok(),
                })
            })
            .collect();

        // Top 5 hostnames by fire count over last 7 days — drives the
        // "where is this rule actually firing" snippet on the detail page.
        let top_rows = conn
            .query(
                "SELECT hostname, COUNT(*)::bigint FROM sigma_alerts \
                 WHERE rule_id = $1 AND hostname IS NOT NULL \
                   AND matched_at >= NOW() - INTERVAL '7 days' \
                 GROUP BY hostname ORDER BY 2 DESC LIMIT 5",
                &[&id],
            )
            .await
            .map_err(query_err)?;
        let top_hosts: Vec<serde_json::Value> = top_rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "hostname": r.get::<_, &str>(0),
                    "count": r.get::<_, i64>(1),
                })
            })
            .collect();

        let tags: Vec<String> = row.try_get::<_, Vec<String>>(9).unwrap_or_default();
        Ok(Some(serde_json::json!({
            "id": row.get::<_, &str>(0),
            "title": row.get::<_, &str>(1),
            "description": row.try_get::<_, &str>(2).ok(),
            "level": row.get::<_, &str>(3),
            "status": row.try_get::<_, &str>(4).ok(),
            "enabled": row.get::<_, bool>(5),
            "logsource_category": row.try_get::<_, &str>(6).ok(),
            "logsource_product": row.try_get::<_, &str>(7).ok(),
            "logsource_service": row.try_get::<_, &str>(8).ok(),
            "tags": tags,
            "author": row.try_get::<_, &str>(10).ok(),
            "rule_yaml": row.try_get::<_, &str>(11).ok(),
            "detection_json": row.try_get::<_, serde_json::Value>(12).unwrap_or(serde_json::Value::Null),
            "updated_at": row.try_get::<_, &str>(13).ok(),
            "fire_count_7d": row.get::<_, i64>(14),
            "fire_count_30d": row.get::<_, i64>(15),
            "last_fire_at": row.try_get::<_, &str>(16).ok(),
            "fp_count_7d": row.get::<_, i64>(17),
            "distinct_hosts_7d": row.get::<_, i64>(18),
            "top_hostname_7d": row.try_get::<_, &str>(19).ok(),
            "disposition": row.try_get::<_, &str>(20).unwrap_or("detect"),
            "tier": row.try_get::<_, &str>(21).unwrap_or("queue"),
            "promoted_at": row.try_get::<_, &str>(22).ok(),
            "recent_alerts": recent,
            "top_hostnames_7d": top_hosts,
        })))
    }

    async fn refresh_sigma_rule_stats(&self) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "REFRESH MATERIALIZED VIEW CONCURRENTLY sigma_rule_stats",
            &[],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn set_sigma_rule_enabled(&self, id: &str, enabled: bool) -> Result<bool, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let n = conn
            .execute(
                "UPDATE sigma_rules SET enabled = $2, updated_at = NOW() WHERE id = $1",
                &[&id, &enabled],
            )
            .await
            .map_err(query_err)?;
        Ok(n > 0)
    }

    async fn set_sigma_rule_promotion(
        &self,
        id: &str,
        disposition: Option<&str>,
        tier: Option<&str>,
        status: Option<&str>,
    ) -> Result<bool, DatabaseError> {
        // Validate against the enums the CHECK constraints enforce, so
        // the SQL fails before tripping a constraint round-trip.
        if let Some(d) = disposition {
            if !matches!(d, "monitor" | "detect" | "block") {
                return Err(DatabaseError::Query(format!("invalid disposition {d}")));
            }
        }
        if let Some(t) = tier {
            if !matches!(t, "page" | "queue" | "rba_only") {
                return Err(DatabaseError::Query(format!("invalid tier {t}")));
            }
        }
        if let Some(s) = status {
            if !matches!(s, "experimental" | "test" | "stable" | "deprecated") {
                return Err(DatabaseError::Query(format!("invalid status {s}")));
            }
        }

        let conn = self.pool().get().await.map_err(pool_err)?;
        // Build the UPDATE dynamically so unset fields aren't overwritten.
        let mut sets: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(id.to_string())];
        let mut idx = 2;
        if let Some(d) = disposition {
            sets.push(format!("disposition = ${idx}"));
            params.push(Box::new(d.to_string()));
            idx += 1;
        }
        if let Some(t) = tier {
            sets.push(format!("tier = ${idx}"));
            params.push(Box::new(t.to_string()));
            idx += 1;
        }
        if let Some(s) = status {
            sets.push(format!("status = ${idx}, promoted_at = NOW()"));
            params.push(Box::new(s.to_string()));
            idx += 1;
        }
        let _ = idx;
        if sets.is_empty() {
            return Ok(false);
        }
        sets.push("updated_at = NOW()".to_string());
        let sql = format!("UPDATE sigma_rules SET {} WHERE id = $1", sets.join(", "));
        let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let n = conn.execute(&sql, &refs[..]).await.map_err(query_err)?;
        Ok(n > 0)
    }

    async fn list_sigma_rule_exceptions(
        &self,
        rule_id: &str,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, rule_id, scope_field, scope_value, reason, owner, \
                        created_at::text, expires_at::text \
                 FROM sigma_rule_exceptions \
                 WHERE rule_id = $1 \
                   AND (expires_at IS NULL OR expires_at > NOW()) \
                 ORDER BY created_at DESC",
                &[&rule_id],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.get::<_, i64>(0),
                    "rule_id": r.get::<_, &str>(1),
                    "scope_field": r.get::<_, &str>(2),
                    "scope_value": r.get::<_, &str>(3),
                    "reason": r.try_get::<_, &str>(4).ok(),
                    "owner": r.try_get::<_, &str>(5).ok(),
                    "created_at": r.try_get::<_, &str>(6).ok(),
                    "expires_at": r.try_get::<_, &str>(7).ok(),
                })
            })
            .collect())
    }

    async fn list_sigma_exceptions_all(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT e.id, e.rule_id, r.title, e.scope_field, e.scope_value, \
                        e.reason, e.owner, e.created_at::text, e.expires_at::text \
                 FROM sigma_rule_exceptions e \
                 JOIN sigma_rules r ON r.id = e.rule_id \
                 WHERE e.expires_at IS NULL OR e.expires_at > NOW() \
                 ORDER BY e.created_at DESC LIMIT 500",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.get::<_, i64>(0),
                    "rule_id": r.get::<_, &str>(1),
                    "rule_title": r.get::<_, &str>(2),
                    "scope_field": r.get::<_, &str>(3),
                    "scope_value": r.get::<_, &str>(4),
                    "reason": r.try_get::<_, &str>(5).ok(),
                    "owner": r.try_get::<_, &str>(6).ok(),
                    "created_at": r.try_get::<_, &str>(7).ok(),
                    "expires_at": r.try_get::<_, &str>(8).ok(),
                })
            })
            .collect())
    }

    async fn insert_sigma_rule_exception(
        &self,
        rule_id: &str,
        scope_field: &str,
        scope_value: &str,
        reason: Option<&str>,
        owner: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<i64, DatabaseError> {
        if !matches!(scope_field, "hostname" | "source_ip" | "username" | "tag") {
            return Err(DatabaseError::Query(format!(
                "invalid scope_field {scope_field}"
            )));
        }
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "INSERT INTO sigma_rule_exceptions \
                    (rule_id, scope_field, scope_value, reason, owner, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                &[
                    &rule_id,
                    &scope_field,
                    &scope_value,
                    &reason,
                    &owner,
                    &expires_at,
                ],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn delete_sigma_rule_exception(&self, id: i64) -> Result<u64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute("DELETE FROM sigma_rule_exceptions WHERE id = $1", &[&id])
            .await
            .map_err(query_err)
    }

    async fn load_active_sigma_exceptions(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT rule_id, scope_field, scope_value FROM sigma_rule_exceptions \
                 WHERE expires_at IS NULL OR expires_at > NOW()",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "rule_id": r.get::<_, &str>(0),
                    "scope_field": r.get::<_, &str>(1),
                    "scope_value": r.get::<_, &str>(2),
                })
            })
            .collect())
    }

    async fn upsert_sigma_rule_from_file(
        &self,
        id: &str,
        title: &str,
        description: Option<&str>,
        level: &str,
        status: Option<&str>,
        logsource_category: Option<&str>,
        logsource_product: Option<&str>,
        logsource_service: Option<&str>,
        tags: &[String],
        author: Option<&str>,
        rule_yaml: &str,
        detection_json: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let tags_vec: Vec<String> = tags.to_vec();
        // INSERT with the file content; on conflict, overwrite only the
        // content-derived columns and leave the operator-managed ones
        // (enabled, disposition, tier, owner, promoted_at) intact.
        conn.execute(
            "INSERT INTO sigma_rules \
                (id, title, description, level, status, \
                 logsource_category, logsource_product, logsource_service, \
                 tags, author, rule_yaml, detection_json, enabled) \
             VALUES ($1, $2, $3, $4, COALESCE($5, 'experimental'), \
                     $6, $7, $8, $9, $10, $11, $12, true) \
             ON CONFLICT (id) DO UPDATE SET \
                title = EXCLUDED.title, \
                description = EXCLUDED.description, \
                level = EXCLUDED.level, \
                status = COALESCE(EXCLUDED.status, sigma_rules.status), \
                logsource_category = EXCLUDED.logsource_category, \
                logsource_product  = EXCLUDED.logsource_product, \
                logsource_service  = EXCLUDED.logsource_service, \
                tags = EXCLUDED.tags, \
                author = EXCLUDED.author, \
                rule_yaml = EXCLUDED.rule_yaml, \
                detection_json = EXCLUDED.detection_json, \
                updated_at = NOW()",
            &[
                &id,
                &title,
                &description,
                &level,
                &status,
                &logsource_category,
                &logsource_product,
                &logsource_service,
                &tags_vec,
                &author,
                &rule_yaml,
                detection_json,
            ],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn count_logs(&self, minutes_back: i64) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Use direct interval interpolation — safe because minutes_back is i64, not user input
        let query = format!(
            "SELECT COUNT(*) FROM logs WHERE time >= NOW() - INTERVAL '{} minutes'",
            minutes_back
        );
        let row = conn.query_one(&query, &[]).await.map_err(query_err)?;
        Ok(row.get::<_, i64>(0))
    }

    async fn search_logs(
        &self,
        filters: &crate::db::threatclaw_store::LogSearchFilters,
    ) -> Result<crate::db::threatclaw_store::LogSearchResult, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;

        // Clamp limit to a sane range. The dashboard typically asks for
        // 100; the cap of 1000 prevents an over-eager caller from pulling
        // entire chunks into memory in one shot.
        let limit = filters.limit.clamp(1, 1000);

        // Default time window: last 24 hours when caller didn't specify.
        // Without this the absent-filter case would scan the whole
        // hypertable; daily chunks make that bearable but not pleasant.
        let to_ts = filters.to.unwrap_or_else(chrono::Utc::now);
        let from_ts = filters
            .from
            .unwrap_or_else(|| to_ts - chrono::Duration::hours(24));

        // Parse the keyset cursor (`<rfc3339_time>|<id>`). Anything we
        // can't parse falls back to "no cursor" so a corrupt token doesn't
        // 500 the request.
        let cursor: Option<(chrono::DateTime<chrono::Utc>, i64)> = filters
            .cursor
            .as_deref()
            .and_then(|s| s.split_once('|'))
            .and_then(|(t, id)| {
                let parsed_time = chrono::DateTime::parse_from_rfc3339(t)
                    .ok()
                    .map(|d| d.with_timezone(&chrono::Utc))?;
                let parsed_id = id.parse::<i64>().ok()?;
                Some((parsed_time, parsed_id))
            });

        // Build the WHERE clause and the parameter list together so the
        // indexes are dollar-numbered consistently. tokio-postgres needs
        // owned values living long enough — collect everything into
        // `Box<dyn ToSql + Sync>` to keep the borrow checker happy.
        let mut clauses: Vec<String> = vec!["time >= $1".into(), "time <= $2".into()];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(from_ts), Box::new(to_ts)];
        let mut next_idx = 3;

        if let Some(h) = filters.hostname.as_deref().filter(|s| !s.is_empty()) {
            clauses.push(format!("hostname = ${}", next_idx));
            params.push(Box::new(h.to_string()));
            next_idx += 1;
        }
        if let Some(t) = filters.tag.as_deref().filter(|s| !s.is_empty()) {
            // SQL LIKE; caller pre-escapes literal %/_. tag is also
            // indexed individually so a prefix pattern stays fast.
            clauses.push(format!("tag LIKE ${}", next_idx));
            params.push(Box::new(t.to_string()));
            next_idx += 1;
        }
        if let Some(q) = filters.q.as_deref().filter(|s| !s.is_empty()) {
            // Substring search across the JSON payload — looks at the
            // three common message fields and falls back to the whole
            // stringified payload so the operator can find an indicator
            // without knowing the exact key name.
            let needle = format!("%{}%", q);
            clauses.push(format!(
                "(data->>'message' ILIKE ${} OR data->>'analysis' ILIKE ${} OR data->>'msg' ILIKE ${} OR data::text ILIKE ${})",
                next_idx, next_idx, next_idx, next_idx
            ));
            params.push(Box::new(needle));
            next_idx += 1;
        }
        if let Some((c_time, c_id)) = cursor {
            // Keyset pagination: continue from (c_time, c_id). The ORDER
            // BY below is time DESC, id DESC; the cursor condition matches.
            clauses.push(format!("(time, id) < (${}, ${})", next_idx, next_idx + 1));
            params.push(Box::new(c_time));
            params.push(Box::new(c_id));
            next_idx += 2;
        }
        let _ = next_idx; // silence "value assigned but never read" warning

        let where_clause = clauses.join(" AND ");
        let query = format!(
            "SELECT id, tag, time::text AS time_text, hostname, data, time AS time_raw \
             FROM logs \
             WHERE {} \
             ORDER BY time_raw DESC, id DESC \
             LIMIT {}",
            where_clause,
            limit + 1 // fetch one extra so we know whether to emit next_cursor
        );

        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = conn
            .query(&query, &params_refs[..])
            .await
            .map_err(query_err)?;

        // Materialise the page, then drop the +1 row and compute the cursor.
        let mut logs: Vec<crate::db::threatclaw_store::LogRecord> = rows
            .iter()
            .map(|r| crate::db::threatclaw_store::LogRecord {
                id: r.get(0),
                tag: r.try_get(1).ok(),
                time: r.get(2),
                // search_logs paginates on (time, id), not the Sigma cursor.
                created_at: String::new(),
                hostname: r.try_get(3).ok(),
                data: r.try_get::<_, serde_json::Value>(4).unwrap_or_default(),
            })
            .collect();

        let next_cursor = if rows.len() > limit as usize {
            // We fetched limit+1; drop the extra and use the last KEPT row
            // as the next cursor.
            logs.truncate(limit as usize);
            let last_row = &rows[limit as usize - 1];
            let last_time: chrono::DateTime<chrono::Utc> = last_row.get(5);
            let last_id: i64 = last_row.get(0);
            Some(format!("{}|{}", last_time.to_rfc3339(), last_id))
        } else {
            None
        };

        // Count touched hypertable chunks so the dashboard can hint at a
        // too-wide time range. We need "chunks that OVERLAP the window",
        // not "chunks strictly contained" — the timescaledb show_chunks()
        // helper returns the latter and reports 0 for the common case of a
        // window narrower than the chunk interval. Querying the metadata
        // view directly with an explicit overlap predicate is both clearer
        // and cheap (the view is in-memory catalog).
        let scanned_chunks: i64 = conn
            .query_one(
                "SELECT COUNT(*)::bigint FROM timescaledb_information.chunks \
                 WHERE hypertable_name = 'logs' \
                   AND range_start <= $2::timestamptz \
                   AND range_end   >= $1::timestamptz",
                &[&from_ts, &to_ts],
            )
            .await
            .map(|r| r.get::<_, i64>(0))
            .unwrap_or(0);

        Ok(crate::db::threatclaw_store::LogSearchResult {
            logs,
            next_cursor,
            scanned_chunks,
        })
    }

    async fn list_saved_hunt_queries(
        &self,
        user_id: Option<&str>,
    ) -> Result<Vec<crate::db::threatclaw_store::SavedHuntQuery>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;

        // Match by user when given, else return global presets (those stored
        // without a user). Newest-first so the sidebar reads top→bottom.
        let rows = if let Some(uid) = user_id {
            conn.query(
                "SELECT id, user_id, name, params, created_at::text \
                 FROM hunt_saved_queries WHERE user_id = $1 \
                 ORDER BY created_at DESC LIMIT 200",
                &[&uid],
            )
            .await
            .map_err(query_err)?
        } else {
            conn.query(
                "SELECT id, user_id, name, params, created_at::text \
                 FROM hunt_saved_queries WHERE user_id IS NULL \
                 ORDER BY created_at DESC LIMIT 200",
                &[],
            )
            .await
            .map_err(query_err)?
        };

        Ok(rows
            .into_iter()
            .map(|r| crate::db::threatclaw_store::SavedHuntQuery {
                id: r.get(0),
                user_id: r.try_get(1).ok(),
                name: r.get(2),
                params: r.try_get(3).unwrap_or_default(),
                created_at: r.get(4),
            })
            .collect())
    }

    async fn insert_saved_hunt_query(
        &self,
        user_id: Option<&str>,
        name: &str,
        params: &serde_json::Value,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "INSERT INTO hunt_saved_queries (user_id, name, params) \
                 VALUES ($1, $2, $3) RETURNING id",
                &[&user_id, &name, params],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn delete_saved_hunt_query(&self, id: i64) -> Result<u64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute("DELETE FROM hunt_saved_queries WHERE id = $1", &[&id])
            .await
            .map_err(query_err)
    }

    async fn execute_cypher(&self, cypher: &str) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;

        // AGE requires loading + search_path set per session
        conn.execute("LOAD 'age'", &[]).await.map_err(query_err)?;
        conn.execute("SET search_path = ag_catalog, \"$user\", public", &[])
            .await
            .map_err(query_err)?;

        // Auto-create graph if it doesn't exist (first run or fresh DB)
        if !GRAPH_ENSURED.load(Ordering::Relaxed) {
            let graph_exists = conn
                .query_opt(
                    "SELECT 1 FROM ag_catalog.ag_graph WHERE name = 'threat_graph'",
                    &[],
                )
                .await
                .map_err(query_err)?;
            if graph_exists.is_none() {
                tracing::info!("GRAPH: Creating 'threat_graph' (first run)");
                conn.execute("SELECT * FROM ag_catalog.create_graph('threat_graph')", &[])
                    .await
                    .map_err(query_err)?;
            }
            GRAPH_ENSURED.store(true, Ordering::Relaxed);
        }

        // No SQL escaping needed — we use $$ dollar quoting
        let escaped = cypher;

        // Detect if the query has a RETURN clause (read) or not (mutation)
        let upper = cypher.to_uppercase();
        let has_return = upper.contains("RETURN ");

        if !has_return {
            // Mutation (CREATE/MERGE/DELETE without RETURN) — use void return
            let sql = format!(
                "SELECT * FROM ag_catalog.cypher('threat_graph', $$ {} $$) AS (result agtype)",
                escaped,
            );
            // Mutations may return 0 rows — that's fine
            let _ = conn.query(&*sql, &[]).await.map_err(query_err)?;
            return Ok(vec![]);
        }

        // Parse RETURN clause to extract column names for the AS (...) declaration.
        let return_clause = if let Some(pos) = upper.rfind("RETURN ") {
            &cypher[pos + 7..]
        } else {
            "result"
        };

        // Strip DISTINCT keyword if present
        let return_fields = return_clause.trim();
        let return_fields = if return_fields.to_uppercase().starts_with("DISTINCT ") {
            &return_fields[9..]
        } else {
            return_fields
        };

        // Strip ORDER BY, LIMIT from the return clause for column extraction
        let return_fields = if let Some(pos) = return_fields.to_uppercase().find(" ORDER BY") {
            &return_fields[..pos]
        } else {
            return_fields
        };
        let return_fields = if let Some(pos) = return_fields.to_uppercase().find(" LIMIT") {
            &return_fields[..pos]
        } else {
            return_fields
        };

        // Split by commas at depth 0 (respecting nested parens/brackets)
        let col_names = split_return_columns(return_fields);

        // Build column aliases using the original expression names (quoted for dots)
        let cols: String = col_names
            .iter()
            .map(|name| {
                let alias = name.trim();
                let display = if let Some(pos) = alias.to_uppercase().rfind(" AS ") {
                    alias[pos + 4..].trim()
                } else {
                    alias
                };
                format!("\"{}\" agtype", display.replace('"', ""))
            })
            .collect::<Vec<_>>()
            .join(", ");

        let sql = format!(
            "SELECT row_to_json(r) FROM (SELECT * FROM ag_catalog.cypher('threat_graph', $$ {} $$) AS ({})) r",
            escaped, cols,
        );

        match conn.query(&*sql, &[]).await {
            Ok(rows) => {
                let results: Vec<serde_json::Value> = rows
                    .iter()
                    .filter_map(|r| r.try_get::<_, serde_json::Value>(0).ok())
                    .map(|v| strip_agtype_quotes(v))
                    .collect();
                Ok(results)
            }
            Err(e) => {
                tracing::debug!(
                    "CYPHER SQL failed: {} | SQL: {}",
                    e,
                    &sql[..sql.len().min(200)]
                );
                Err(query_err(e))
            }
        }
    }

    async fn log_llm_call(
        &self,
        model: &str,
        prompt_hash: &str,
        prompt_length: i32,
        response_json: Option<&serde_json::Value>,
        raw_response: Option<&str>,
        parsing_ok: bool,
        parsing_method: &str,
        severity: Option<&str>,
        confidence: Option<f64>,
        actions_count: i32,
        escalation: &str,
        cycle_duration_ms: i32,
        observations_count: i32,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let response_str = response_json.map(|v| serde_json::to_string(v).unwrap_or_default());
        let response_jsonb = response_str.as_deref().unwrap_or("null");
        let raw: String = raw_response
            .map(|r| r.chars().take(2000).collect::<String>())
            .unwrap_or_default();
        let sev = severity.unwrap_or("");
        let conf = confidence.unwrap_or(0.0);

        conn.execute(
            "INSERT INTO llm_training_data (model, prompt_hash, prompt_length, response_json, raw_response, parsing_ok, parsing_method, severity, confidence, actions_count, escalation, cycle_duration_ms, observations_count) \
             VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            &[&model, &prompt_hash, &prompt_length, &response_jsonb, &raw, &parsing_ok, &parsing_method, &sev, &conf, &actions_count, &escalation, &cycle_duration_ms, &observations_count],
        ).await.map_err(query_err)?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════
    // ASSETS MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    async fn list_assets(
        &self,
        category: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AssetRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let category_owned = category.map(|s| s.to_string());
        let status_owned = status.map(|s| s.to_string());
        // Hide merged aliases from the default inventory: merge_assets sets the
        // alias row to status='merged' so findings/alerts still resolve, but the
        // operator must not see it as a live asset. Without this filter a manual
        // merge "did nothing" — the alias kept showing after the list reloaded.
        // An explicit status='merged' filter still surfaces them on demand.
        // Hide both merge aliases (status='merged') and soft-deleted assets
        // (status='deleted') from the default inventory. An explicit status
        // filter still surfaces either — that's how the trash/Corbeille view
        // lists status='deleted'.
        let sql = "SELECT * FROM assets WHERE ($1::text IS NULL OR category = $1) AND ($2::text IS NULL OR status = $2) AND ($2::text = 'merged' OR status IS DISTINCT FROM 'merged') AND ($2::text = 'deleted' OR status IS DISTINCT FROM 'deleted') ORDER BY criticality DESC, last_seen DESC LIMIT $3 OFFSET $4";
        let rows = conn
            .query(sql, &[&category_owned, &status_owned, &limit, &offset])
            .await
            .map_err(query_err)?;
        Ok(rows.iter().map(|r| parse_asset_row(r)).collect())
    }

    async fn count_assets_filtered(
        &self,
        category: Option<&str>,
        status: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let category_owned = category.map(|s| s.to_string());
        let status_owned = status.map(|s| s.to_string());
        let row = conn.query_one(
            // Match list_assets: exclude merged aliases so the tab counts agree
            // with the rows actually shown (otherwise the count stays inflated).
            "SELECT COUNT(*)::bigint FROM assets WHERE ($1::text IS NULL OR category = $1) AND ($2::text IS NULL OR status = $2) AND ($2::text = 'merged' OR status IS DISTINCT FROM 'merged') AND ($2::text = 'deleted' OR status IS DISTINCT FROM 'deleted')",
            &[&category_owned, &status_owned],
        ).await.map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn get_asset(&self, id: &str) -> Result<Option<AssetRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query("SELECT * FROM assets WHERE id = $1", &[&id])
            .await
            .map_err(query_err)?;
        Ok(rows.first().map(parse_asset_row))
    }

    async fn upsert_asset(&self, a: &NewAsset) -> Result<String, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Phase 11d — normalise IPs at write-time so the in-DB array stays
        // canonical: strip `:port` (ephemeral source-port logs were polluting
        // assets with `10.77.0.174:51788` etc.), strip `/mask`, drop empties,
        // dedup. Without this the UPSERT's UNION DISTINCT keeps every
        // variant because they're treated as opaque strings.
        let ips_owned: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            a.ip_addresses
                .iter()
                .filter_map(|raw| {
                    let no_port = raw.split(':').next().unwrap_or(raw);
                    let no_mask = no_port.split('/').next().unwrap_or(no_port);
                    let trimmed = no_mask.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        let s = trimmed.to_string();
                        if seen.insert(s.clone()) {
                            Some(s)
                        } else {
                            None
                        }
                    }
                })
                .collect()
        };
        let ips: Vec<&str> = ips_owned.iter().map(|s| s.as_str()).collect();
        let tags: Vec<&str> = a.tags.iter().map(|s| s.as_str()).collect();
        let source_arr = vec![a.source.as_str()];
        // V67 — classify the incoming source to map onto inventory_status.
        // Precedence in the UPDATE clause makes sure we never demote a
        // 'declared' asset to 'observed_persistent' just because a passive
        // sighting arrived from a weaker source afterward.
        let new_inventory_status = crate::agent::billing::inventory_status_for(&a.source);
        conn.execute(
            r#"INSERT INTO assets (id, name, category, subcategory, role, criticality,
                ip_addresses, mac_address, hostname, fqdn, url, os, mac_vendor,
                services, source, sources, owner, location, tags, last_seen, inventory_status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, NOW(), $20)
            ON CONFLICT (id) DO UPDATE SET
                -- Protect user-edited fields from auto-discovery overwrite
                name = CASE WHEN 'name' = ANY(assets.user_modified) THEN assets.name
                            ELSE COALESCE(EXCLUDED.name, assets.name) END,
                category = CASE WHEN 'category' = ANY(assets.user_modified) THEN assets.category
                                ELSE EXCLUDED.category END,
                subcategory = COALESCE(EXCLUDED.subcategory, assets.subcategory),
                role = COALESCE(EXCLUDED.role, assets.role),
                criticality = CASE WHEN 'criticality' = ANY(assets.user_modified) THEN assets.criticality
                                   ELSE EXCLUDED.criticality END,
                -- IPs: union of existing + new (never lose an IP)
                ip_addresses = CASE
                    WHEN EXCLUDED.ip_addresses = '{}' THEN assets.ip_addresses
                    ELSE (SELECT ARRAY(SELECT DISTINCT unnest(assets.ip_addresses || EXCLUDED.ip_addresses)))
                END,
                mac_address = COALESCE(EXCLUDED.mac_address, assets.mac_address),
                hostname = CASE WHEN 'hostname' = ANY(assets.user_modified) THEN assets.hostname
                                ELSE COALESCE(EXCLUDED.hostname, assets.hostname) END,
                fqdn = COALESCE(EXCLUDED.fqdn, assets.fqdn),
                url = COALESCE(EXCLUDED.url, assets.url),
                os = COALESCE(EXCLUDED.os, assets.os),
                mac_vendor = COALESCE(EXCLUDED.mac_vendor, assets.mac_vendor),
                services = CASE WHEN EXCLUDED.services != '[]'::jsonb THEN EXCLUDED.services ELSE assets.services END,
                -- Sources: union (track all discovery origins)
                sources = (SELECT ARRAY(SELECT DISTINCT unnest(assets.sources || EXCLUDED.sources))),
                owner = CASE WHEN 'owner' = ANY(assets.user_modified) THEN assets.owner
                             ELSE COALESCE(EXCLUDED.owner, assets.owner) END,
                location = CASE WHEN 'location' = ANY(assets.user_modified) THEN assets.location
                                ELSE COALESCE(EXCLUDED.location, assets.location) END,
                -- Tags: union (never lose a tag)
                tags = (SELECT ARRAY(SELECT DISTINCT unnest(assets.tags || EXCLUDED.tags))),
                last_seen = NOW(),
                updated_at = NOW(),
                -- inventory_status precedence (V67):
                --   declared  > observed_persistent > observed_transient > inactive
                -- Never demote, only promote. inactive → whatever the new signal
                -- says (asset is back online).
                inventory_status = CASE
                    WHEN assets.inventory_status = 'declared'
                        THEN 'declared'
                    WHEN assets.inventory_status = 'observed_persistent'
                         AND EXCLUDED.inventory_status != 'declared'
                        THEN 'observed_persistent'
                    ELSE EXCLUDED.inventory_status
                END"#,
            &[&a.id, &a.name, &a.category, &a.subcategory, &a.role, &a.criticality,
              &ips, &a.mac_address, &a.hostname, &a.fqdn, &a.url, &a.os, &a.mac_vendor,
              &a.services, &a.source, &source_arr, &a.owner, &a.location, &tags,
              &new_inventory_status],
        ).await.map_err(query_err)?;
        Ok(a.id.clone())
    }

    async fn delete_asset(&self, id: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute("DELETE FROM assets WHERE id = $1", &[&id])
            .await
            .map_err(query_err)?;
        Ok(())
    }

    async fn asset_impact(&self, id: &str) -> Result<serde_json::Value, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Resolve the asset's identifiers first — tables reference an asset
        // inconsistently: findings.asset / incidents.asset hold the id OR the
        // name, sigma_alerts/logs key on hostname, ml_scores on asset_id. We
        // match against all of them so the preview is honest.
        let asset = match self.get_asset(id).await? {
            Some(a) => a,
            None => {
                return Ok(serde_json::json!({
                    "incidents": 0, "findings": 0, "alerts": 0, "logs": 0, "ml_scores": 0
                }));
            }
        };
        let host = asset.hostname.clone().unwrap_or_default();
        // id + name cover the `asset`/`asset_id` text columns; host covers the
        // hostname-keyed tables (case-insensitive).
        let names: Vec<String> = vec![asset.id.clone(), asset.name.clone()];
        let row = conn
            .query_one(
                "SELECT \
                   (SELECT COUNT(*) FROM incidents   WHERE asset = ANY($1) OR ($2 <> '' AND LOWER(asset) = LOWER($2)))::bigint, \
                   (SELECT COUNT(*) FROM findings    WHERE asset = ANY($1) OR ($2 <> '' AND LOWER(asset) = LOWER($2)))::bigint, \
                   (SELECT COUNT(*) FROM sigma_alerts WHERE $2 <> '' AND LOWER(hostname) = LOWER($2))::bigint, \
                   (SELECT COUNT(*) FROM logs        WHERE $2 <> '' AND LOWER(hostname) = LOWER($2))::bigint, \
                   (SELECT COUNT(*) FROM ml_scores   WHERE asset_id = ANY($1) OR ($2 <> '' AND asset_id = $2))::bigint",
                &[&names, &host],
            )
            .await
            .map_err(query_err)?;
        Ok(serde_json::json!({
            "incidents": row.get::<_, i64>(0),
            "findings": row.get::<_, i64>(1),
            "alerts": row.get::<_, i64>(2),
            "logs": row.get::<_, i64>(3),
            "ml_scores": row.get::<_, i64>(4),
        }))
    }

    async fn purge_asset(
        &self,
        id: &str,
        scope: &str,
        block_reenrol: bool,
    ) -> Result<serde_json::Value, DatabaseError> {
        if !matches!(scope, "reset" | "delete" | "purge") {
            return Ok(serde_json::json!({ "ok": false, "error": "invalid scope" }));
        }
        let asset = match self.get_asset(id).await? {
            Some(a) => a,
            None => return Ok(serde_json::json!({ "ok": false, "error": "asset not found" })),
        };
        let host = asset.hostname.clone().unwrap_or_default();
        let names: Vec<String> = vec![asset.id.clone(), asset.name.clone()];
        let del_incidents = matches!(scope, "delete" | "purge");
        let del_logs = scope == "purge";
        let hard = scope == "purge";

        let mut conn = self.pool().get().await.map_err(pool_err)?;
        let tx = conn.transaction().await.map_err(query_err)?;

        // Always — scrub analysis artifacts. Findings/incidents reference the
        // asset by id-or-name; sigma_alerts/ml_scores/logs key on hostname. The
        // `$host <> ''` guard stops an asset with no hostname from matching the
        // empty-hostname rows of unrelated sources.
        tx.execute(
            "DELETE FROM findings WHERE asset = ANY($1) OR ($2 <> '' AND LOWER(asset) = LOWER($2))",
            &[&names, &host],
        )
        .await
        .map_err(query_err)?;
        tx.execute(
            "DELETE FROM sigma_alerts WHERE $1 <> '' AND LOWER(hostname) = LOWER($1)",
            &[&host],
        )
        .await
        .map_err(query_err)?;
        tx.execute(
            "DELETE FROM ml_scores WHERE asset_id = ANY($1) OR ($2 <> '' AND asset_id = $2)",
            &[&names, &host],
        )
        .await
        .map_err(query_err)?;

        if del_incidents {
            // Incident child rows (ai_analyses, investigation_steps, sentinel_*)
            // are FK ON DELETE CASCADE, so they go with the parent incident.
            tx.execute(
                "DELETE FROM incidents WHERE asset = ANY($1) OR ($2 <> '' AND LOWER(asset) = LOWER($2))",
                &[&names, &host],
            ).await.map_err(query_err)?;
        }
        if del_logs && !host.is_empty() {
            // `logs` is a TimescaleDB compressed hypertable: a host-scoped delete
            // decompresses whole chunks and trips
            // max_tuples_decompressed_per_dml_transaction (observed live on a
            // 34k-row host). Lift the limit for THIS transaction when TimescaleDB
            // is present; plain-Postgres deployments (no hypertable) delete fine
            // without it, so the SET is skipped there to stay portable.
            let has_ts: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')",
                    &[],
                )
                .await
                .map_err(query_err)?
                .get(0);
            if has_ts {
                tx.batch_execute(
                    "SET LOCAL timescaledb.max_tuples_decompressed_per_dml_transaction = 0",
                )
                .await
                .map_err(query_err)?;
            }
            tx.execute(
                "DELETE FROM logs WHERE LOWER(hostname) = LOWER($1)",
                &[&host],
            )
            .await
            .map_err(query_err)?;
        }

        if hard {
            tx.execute("DELETE FROM assets WHERE id = $1", &[&asset.id])
                .await
                .map_err(query_err)?;
        } else if scope == "delete" {
            // Soft delete: kept for the trash view, hidden from inventory, and
            // optionally tombstoned so resolve_asset won't resurrect it.
            tx.execute(
                "UPDATE assets SET status = 'deleted', reenrol_blocked = $2, updated_at = NOW() WHERE id = $1",
                &[&asset.id, &block_reenrol],
            ).await.map_err(query_err)?;
        }
        // "reset" leaves the asset row untouched (stays active → re-accumulates).

        tx.commit().await.map_err(query_err)?;
        Ok(serde_json::json!({
            "ok": true,
            "scope": scope,
            "soft": !hard,
            "reenrol_blocked": scope == "delete" && block_reenrol,
        }))
    }

    async fn reactivate_asset(&self, id: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE assets SET status = 'active', reenrol_blocked = false, updated_at = NOW() WHERE id = $1",
            &[&id],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn count_assets_by_category(&self) -> Result<Vec<(String, i64)>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn.query(
            "SELECT category, COUNT(*) as cnt FROM assets WHERE status = 'active' GROUP BY category ORDER BY cnt DESC",
            &[],
        ).await.map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1)))
            .collect())
    }

    async fn find_asset_by_ip(&self, ip: &str) -> Result<Option<AssetRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT * FROM assets WHERE $1 = ANY(ip_addresses) LIMIT 1",
                &[&ip],
            )
            .await
            .map_err(query_err)?;
        Ok(rows.first().map(parse_asset_row))
    }

    async fn find_asset_by_mac(&self, mac: &str) -> Result<Option<AssetRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT * FROM assets WHERE mac_address = $1 LIMIT 1",
                &[&mac],
            )
            .await
            .map_err(query_err)?;
        Ok(rows.first().map(parse_asset_row))
    }

    async fn find_asset_by_hostname(
        &self,
        hostname: &str,
    ) -> Result<Option<AssetRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Normalize on both sides so the two enrolment paths converge on
        // the same asset row. fluent-bit / rsyslog ship the hostname
        // verbatim from the sender, which is often a FQDN
        // (`web-01.dexun.internal`). The osquery agent ships the short
        // hostname (`web-01`). Before this normalization those two paths
        // created two separate assets for the same machine, leaving the
        // operator with a duplicate inventory entry that wouldn't merge.
        //
        // Match order, most specific first:
        //   0. exact hostname (lower-cased) — preferred
        //   1. exact name (legacy match)
        //   2. short-hostname match (segment before the first `.`)
        //   3. short-name match
        // Two machines that happen to share the same short hostname but
        // live in different domains will collide; this is rare in
        // practice and the operator can override by setting an explicit
        // hostname on the asset record.
        let lower = hostname.to_lowercase();
        let rows = conn
            .query(
                "WITH n AS (SELECT $1::text AS h, SPLIT_PART($1::text, '.', 1) AS hs) \
             SELECT a.* FROM assets a, n \
             WHERE LOWER(a.hostname) = n.h \
                OR LOWER(a.name) = n.h \
                OR LOWER(SPLIT_PART(a.hostname, '.', 1)) = n.hs \
                OR LOWER(SPLIT_PART(a.name, '.', 1)) = n.hs \
             ORDER BY \
               CASE \
                 WHEN LOWER(a.hostname) = n.h THEN 0 \
                 WHEN LOWER(a.name) = n.h THEN 1 \
                 WHEN LOWER(SPLIT_PART(a.hostname, '.', 1)) = n.hs THEN 2 \
                 ELSE 3 \
               END, \
               a.created_at ASC \
             LIMIT 1",
                &[&lower],
            )
            .await
            .map_err(query_err)?;
        Ok(rows.first().map(parse_asset_row))
    }

    async fn mark_asset_user_modified(
        &self,
        id: &str,
        fields: &[&str],
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let fields_vec: Vec<String> = fields.iter().map(|f| f.to_string()).collect();
        conn.execute(
            "UPDATE assets SET user_modified = (SELECT ARRAY(SELECT DISTINCT unnest(user_modified || $2::text[]))) WHERE id = $1",
            &[&id, &fields_vec],
        ).await.map_err(query_err)?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════
    // INTERNAL NETWORKS
    // ═══════════════════════════════════════════════════════════

    async fn update_asset_software(
        &self,
        id: &str,
        software: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        // De-duplicate by (name, version). The previous version relied on
        // `jsonb_agg(DISTINCT elem)` which compares whole objects byte-for-
        // byte; osquery re-sends packages with a path or timestamp that
        // varies between scans, so distinct never collapsed the duplicates.
        // Result on the field: `debian` ended up with 165k software entries
        // for ~500 real packages and the asset detail page locked up.
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            r#"UPDATE assets SET software = (
                SELECT COALESCE(jsonb_agg(elem ORDER BY elem->>'name', elem->>'version'), '[]'::jsonb)
                FROM (
                    SELECT DISTINCT ON (elem->>'name', COALESCE(elem->>'version', '')) elem
                    FROM (
                        SELECT elem FROM jsonb_array_elements(COALESCE(assets.software, '[]'::jsonb)) AS elem
                        UNION ALL
                        SELECT elem FROM jsonb_array_elements($2::jsonb) AS elem
                    ) merged
                    ORDER BY elem->>'name', COALESCE(elem->>'version', ''), elem
                ) dedup
            ), updated_at = NOW() WHERE id = $1"#,
            &[&id, software],
        ).await.map_err(query_err)?;
        Ok(())
    }

    async fn set_asset_criticality(
        &self,
        id: &str,
        criticality: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE assets SET criticality = $2, updated_at = NOW() WHERE id = $1",
            &[&id, &criticality],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn add_asset_tag(&self, id: &str, tag: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE assets SET tags = array_append(tags, $2), updated_at = NOW() \
             WHERE id = $1 AND NOT ($2 = ANY(tags))",
            &[&id, &tag],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn remove_asset_tag(&self, id: &str, tag: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE assets SET tags = array_remove(tags, $2), updated_at = NOW() WHERE id = $1",
            &[&id, &tag],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn set_asset_dedup_confidence(
        &self,
        id: &str,
        dedup_confidence: &str,
    ) -> Result<(), DatabaseError> {
        // Validate against a fixed enum so a misbehaving caller can't
        // poison the column. Anything outside the set falls back to
        // 'medium' (the safe default — won't be excluded by the
        // billable filter, won't be marked authoritative either).
        let safe = match dedup_confidence {
            "high" | "medium" | "uncertain" => dedup_confidence.to_string(),
            _ => "medium".to_string(),
        };
        // Upgrade-only: once an asset is marked `high` (matched by MAC
        // = physical id), a later partial sync that only carries an IP
        // must NOT regress it to `uncertain`. Same logic for `medium`
        // vs `uncertain`. The SQL CASE encodes the lattice
        // uncertain < medium < high.
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE assets \
                SET dedup_confidence = CASE \
                    WHEN $2 = 'high' THEN 'high' \
                    WHEN $2 = 'medium' AND dedup_confidence != 'high' THEN 'medium' \
                    WHEN $2 = 'uncertain' AND COALESCE(dedup_confidence, 'uncertain') = 'uncertain' THEN 'uncertain' \
                    ELSE dedup_confidence \
                END \
              WHERE id = $1",
            &[&id, &safe],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    // ── V68 — manual merge (alias) ──

    async fn merge_assets(
        &self,
        alias_id: &str,
        canonical_id: &str,
        merged_by: &str,
        reason: &str,
    ) -> Result<(), DatabaseError> {
        if alias_id == canonical_id {
            return Err(DatabaseError::Constraint(
                "alias_id == canonical_id, refusing self-merge".into(),
            ));
        }
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Insert the alias mapping. `unmerged_at` stays NULL = active.
        // Conflict on (alias_id) means the row is already merged — we
        // accept that as idempotent and just refresh the canonical /
        // reason. This lets a re-merge after an unmerge succeed.
        conn.execute(
            "INSERT INTO merge_aliases (alias_id, canonical_id, merged_by, reason) \
                 VALUES ($1, $2, $3, $4) \
             ON CONFLICT (alias_id) DO UPDATE \
                 SET canonical_id = EXCLUDED.canonical_id, \
                     merged_by    = EXCLUDED.merged_by, \
                     reason       = EXCLUDED.reason, \
                     merged_at    = NOW(), \
                     unmerged_at  = NULL",
            &[&alias_id, &canonical_id, &merged_by, &reason],
        )
        .await
        .map_err(query_err)?;
        // Hide the alias from the default /assets listing. We use the
        // status='merged' marker rather than DELETE so findings/alerts
        // that reference the alias still resolve.
        conn.execute(
            "UPDATE assets SET status = 'merged' WHERE id = $1",
            &[&alias_id],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn unmerge_asset(&self, alias_id: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE merge_aliases SET unmerged_at = NOW() \
              WHERE alias_id = $1 AND unmerged_at IS NULL",
            &[&alias_id],
        )
        .await
        .map_err(query_err)?;
        conn.execute(
            "UPDATE assets SET status = 'active' WHERE id = $1 AND status = 'merged'",
            &[&alias_id],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn resolve_canonical_id(&self, id: &str) -> Result<String, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                "SELECT canonical_id FROM merge_aliases \
                  WHERE alias_id = $1 AND unmerged_at IS NULL",
                &[&id],
            )
            .await
            .map_err(query_err)?;
        Ok(row
            .map(|r| r.get::<_, String>("canonical_id"))
            .unwrap_or_else(|| id.to_string()))
    }

    // ── V68 — single-toggle exclusion (billing + monitoring) ──

    async fn set_asset_excluded(
        &self,
        id: &str,
        excluded: bool,
        reason: &str,
        until: Option<chrono::DateTime<chrono::Utc>>,
        by: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        if excluded {
            // Setting → require a non-empty reason (api also enforces but
            // belt-and-braces).
            if reason.trim().is_empty() {
                return Err(DatabaseError::Constraint(
                    "exclusion requires a non-empty reason".into(),
                ));
            }
            conn.execute(
                "UPDATE assets \
                    SET excluded         = true, \
                        exclusion_reason = $2, \
                        exclusion_until  = $3, \
                        exclusion_by     = $4, \
                        updated_at       = NOW() \
                  WHERE id = $1",
                &[&id, &reason, &until, &by],
            )
            .await
            .map_err(query_err)?;
        } else {
            conn.execute(
                "UPDATE assets \
                    SET excluded         = false, \
                        exclusion_reason = '', \
                        exclusion_until  = NULL, \
                        exclusion_by     = '', \
                        updated_at       = NOW() \
                  WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(query_err)?;
        }
        Ok(())
    }

    async fn expire_asset_exclusions(&self) -> Result<u64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let n = conn
            .execute(
                "UPDATE assets \
                    SET excluded         = false, \
                        exclusion_reason = '', \
                        exclusion_until  = NULL, \
                        exclusion_by     = '', \
                        updated_at       = NOW() \
                  WHERE excluded = true \
                    AND exclusion_until IS NOT NULL \
                    AND exclusion_until < NOW()",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(n)
    }

    async fn list_internal_networks(&self) -> Result<Vec<InternalNetwork>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, cidr, label, zone FROM internal_networks ORDER BY id",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| InternalNetwork {
                id: r.get::<_, i32>(0) as i64,
                cidr: r.get(1),
                label: r.try_get(2).ok(),
                zone: r.try_get::<_, String>(3).unwrap_or_else(|_| "lan".into()),
            })
            .collect())
    }

    async fn add_internal_network(
        &self,
        cidr: &str,
        label: Option<&str>,
        zone: Option<&str>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let z = zone.unwrap_or("lan");
        let row = conn.query_one(
            "INSERT INTO internal_networks (cidr, label, zone) VALUES ($1, $2, $3) ON CONFLICT (cidr) DO UPDATE SET label = EXCLUDED.label RETURNING id",
            &[&cidr, &label, &z],
        ).await.map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn delete_internal_network(&self, id: i64) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute("DELETE FROM internal_networks WHERE id = $1", &[&id])
            .await
            .map_err(query_err)?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════
    // COMPANY PROFILE
    // ═══════════════════════════════════════════════════════════

    async fn get_company_profile(&self) -> Result<CompanyProfile, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query("SELECT * FROM company_profile WHERE id = 1", &[])
            .await
            .map_err(query_err)?;
        if let Some(r) = rows.first() {
            Ok(CompanyProfile {
                company_name: r.try_get("company_name").ok(),
                nace_code: r.try_get("nace_code").ok(),
                sector: r
                    .try_get::<_, String>("sector")
                    .unwrap_or_else(|_| "other".into()),
                company_size: r
                    .try_get::<_, String>("company_size")
                    .unwrap_or_else(|_| "small".into()),
                employee_count: r.try_get("employee_count").ok(),
                country: r
                    .try_get::<_, String>("country")
                    .unwrap_or_else(|_| "FR".into()),
                business_hours: r
                    .try_get::<_, String>("business_hours")
                    .unwrap_or_else(|_| "office".into()),
                business_hours_start: r
                    .try_get::<_, String>("business_hours_start")
                    .unwrap_or_else(|_| "08:00".into()),
                business_hours_end: r
                    .try_get::<_, String>("business_hours_end")
                    .unwrap_or_else(|_| "18:00".into()),
                work_days: r
                    .try_get::<_, Vec<String>>("work_days")
                    .unwrap_or_else(|_| {
                        vec![
                            "mon".into(),
                            "tue".into(),
                            "wed".into(),
                            "thu".into(),
                            "fri".into(),
                        ]
                    }),
                geo_scope: r
                    .try_get::<_, String>("geo_scope")
                    .unwrap_or_else(|_| "france".into()),
                allowed_countries: r
                    .try_get::<_, Vec<String>>("allowed_countries")
                    .unwrap_or_else(|_| vec!["FR".into()]),
                blocked_countries: r
                    .try_get::<_, Vec<String>>("blocked_countries")
                    .unwrap_or_default(),
                critical_systems: r
                    .try_get::<_, Vec<String>>("critical_systems")
                    .unwrap_or_default(),
                compliance_frameworks: r
                    .try_get::<_, Vec<String>>("compliance_frameworks")
                    .unwrap_or_default(),
                anomaly_sensitivity: r
                    .try_get::<_, String>("anomaly_sensitivity")
                    .unwrap_or_else(|_| "medium".into()),
            })
        } else {
            Ok(CompanyProfile::default())
        }
    }

    async fn update_company_profile(&self, p: &CompanyProfile) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let work_days: Vec<&str> = p.work_days.iter().map(|s| s.as_str()).collect();
        let allowed: Vec<&str> = p.allowed_countries.iter().map(|s| s.as_str()).collect();
        let blocked: Vec<&str> = p.blocked_countries.iter().map(|s| s.as_str()).collect();
        let critical: Vec<&str> = p.critical_systems.iter().map(|s| s.as_str()).collect();
        let compliance: Vec<&str> = p.compliance_frameworks.iter().map(|s| s.as_str()).collect();
        conn.execute(
            r#"UPDATE company_profile SET
                company_name = $1, nace_code = $2, sector = $3, company_size = $4,
                employee_count = $5, country = $6, business_hours = $7,
                business_hours_start = $8, business_hours_end = $9, work_days = $10,
                geo_scope = $11, allowed_countries = $12, blocked_countries = $13,
                critical_systems = $14, compliance_frameworks = $15, anomaly_sensitivity = $16,
                updated_at = NOW()
            WHERE id = 1"#,
            &[
                &p.company_name,
                &p.nace_code,
                &p.sector,
                &p.company_size,
                &p.employee_count,
                &p.country,
                &p.business_hours,
                &p.business_hours_start,
                &p.business_hours_end,
                &work_days,
                &p.geo_scope,
                &allowed,
                &blocked,
                &critical,
                &compliance,
                &p.anomaly_sensitivity,
            ],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════
    // ASSET CATEGORIES
    // ═══════════════════════════════════════════════════════════

    async fn list_asset_categories(&self) -> Result<Vec<AssetCategory>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn.query(
            "SELECT id, label, label_en, icon, color, subcategories, is_builtin FROM asset_categories ORDER BY sort_order, label",
            &[],
        ).await.map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| AssetCategory {
                id: r.get(0),
                label: r.get(1),
                label_en: r.get(2),
                icon: r.get(3),
                color: r.get(4),
                subcategories: r.get(5),
                is_builtin: r.get(6),
            })
            .collect())
    }

    async fn upsert_asset_category(&self, c: &AssetCategory) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let subs: Vec<&str> = c.subcategories.iter().map(|s| s.as_str()).collect();
        conn.execute(
            r#"INSERT INTO asset_categories (id, label, label_en, icon, color, subcategories, is_builtin)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (id) DO UPDATE SET
                label = EXCLUDED.label, label_en = EXCLUDED.label_en,
                icon = EXCLUDED.icon, color = EXCLUDED.color,
                subcategories = EXCLUDED.subcategories"#,
            &[&c.id, &c.label, &c.label_en, &c.icon, &c.color, &subs, &c.is_builtin],
        ).await.map_err(query_err)?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════
    // ENRICHMENT CACHE
    // ═══════════════════════════════════════════════════════════

    async fn get_enrichment_cache(
        &self,
        source: &str,
        key: &str,
    ) -> Result<Option<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn.query(
            "SELECT value FROM enrichment_cache WHERE source = $1 AND key = $2 AND expires_at > NOW()",
            &[&source, &key],
        ).await.map_err(query_err)?;
        Ok(rows.first().map(|r| r.get::<_, serde_json::Value>(0)))
    }

    async fn set_enrichment_cache(
        &self,
        source: &str,
        key: &str,
        value: &serde_json::Value,
        ttl_hours: i64,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "INSERT INTO enrichment_cache (source, key, value, expires_at) VALUES ($1, $2, $3, NOW() + $4 * INTERVAL '1 hour') ON CONFLICT (source, key) DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at, created_at = NOW()",
            &[&source, &key, value, &ttl_hours],
        ).await.map_err(query_err)?;
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════
    // ML SCORES (dedicated table)
    // ═══════════════════════════════════════════════════════════

    async fn get_ml_score(&self, asset_id: &str) -> Result<Option<(f64, String)>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT score, COALESCE(reason, '') FROM ml_scores WHERE asset_id = $1",
                &[&asset_id],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .first()
            .map(|r| (r.get::<_, f32>(0) as f64, r.get::<_, String>(1))))
    }

    async fn get_all_ml_scores(
        &self,
    ) -> Result<std::collections::HashMap<String, (f64, String)>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Freshness gate: the ML engine re-scores every active asset each cycle
        // (~5 min). A row whose `computed_at` is older than a handful of cycles
        // means the asset dropped out of the ML feature window (no recent
        // activity) or the engine is down — either way the score is stale and
        // must NOT keep boosting/penalising the incident score. Without this the
        // Intelligence Engine applied month-old anomaly scores as if current.
        // 30 min = 6 cycles of tolerance. See detection-chain audit 2026-06-20.
        let rows = conn
            .query(
                "SELECT asset_id, score, COALESCE(reason, '') FROM ml_scores \
                 WHERE computed_at > NOW() - INTERVAL '30 minutes'",
                &[],
            )
            .await
            .map_err(query_err)?;
        let mut map = std::collections::HashMap::new();
        for r in &rows {
            let id: String = r.get(0);
            let score: f32 = r.get(1);
            let reason: String = r.get(2);
            map.insert(id, (score as f64, reason));
        }
        Ok(map)
    }

    async fn set_ml_score(
        &self,
        asset_id: &str,
        score: f64,
        reason: &str,
        features: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let score_f32 = score as f32;
        conn.execute(
            "INSERT INTO ml_scores (asset_id, score, reason, features, computed_at) VALUES ($1, $2, $3, $4, NOW()) ON CONFLICT (asset_id) DO UPDATE SET score = EXCLUDED.score, reason = EXCLUDED.reason, features = EXCLUDED.features, computed_at = NOW()",
            &[&asset_id, &score_f32, &reason, features],
        ).await.map_err(query_err)?;
        Ok(())
    }

    // ── Incidents (See ADR-043) ──

    async fn create_incident(
        &self,
        asset: &str,
        title: &str,
        severity: &str,
        alert_ids: &[i32],
        finding_ids: &[i32],
        alert_count: i32,
    ) -> Result<i32, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn.query_one(
            "INSERT INTO incidents (asset, title, severity, alert_ids, finding_ids, alert_count) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            &[&asset, &title, &severity, &alert_ids, &finding_ids, &alert_count],
        ).await.map_err(query_err)?;
        Ok(row.get("id"))
    }

    async fn set_incident_correlation(
        &self,
        id: i32,
        related_assets: &[String],
        campaign_id: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let related_json = serde_json::json!(related_assets);
        let campaign_owned = campaign_id.map(String::from);
        conn.execute(
            "UPDATE incidents SET related_assets = $2, campaign_id = $3, updated_at = NOW() WHERE id = $1",
            &[&id, &related_json, &campaign_owned],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn update_incident_verdict(
        &self,
        id: i32,
        verdict: &str,
        confidence: f64,
        summary: &str,
        mitre: &[String],
        proposed_actions: &serde_json::Value,
        investigation_log: &serde_json::Value,
        evidence_citations: &serde_json::Value,
        verdict_source: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let conf_f32 = confidence as f32;
        // Phase B — `error` is no longer a terminal status: an L2 failure
        // shouldn't bury the incident in a "broken" bucket no one revisits.
        // The incident stays `open` with verdict='error' so the RSSI sees
        // it in the regular queue and can act on the rules-based fallback
        // title; an audit note (added by the caller) explains the L2 fail.
        //
        // Sprint 1 #2 — verdict_source: COALESCE preserves the prior value
        // when the caller passes None (re-investigate path doesn't change
        // who originally decided this incident).
        let source_owned = verdict_source.map(String::from);
        conn.execute(
            "UPDATE incidents SET verdict = $2, confidence = $3, summary = $4, mitre_techniques = $5, proposed_actions = $6, investigation_log = $7, evidence_citations = $8, verdict_source = COALESCE($9, verdict_source), status = CASE WHEN $2 = 'false_positive' THEN 'closed' WHEN $2 = 'confirmed' THEN 'open' WHEN $2 = 'informational' THEN 'closed' ELSE 'open' END, updated_at = NOW() WHERE id = $1",
            &[&id, &verdict, &conf_f32, &summary, &mitre, proposed_actions, investigation_log, evidence_citations, &source_owned],
        ).await.map_err(query_err)?;
        Ok(())
    }

    async fn update_incident_hitl(
        &self,
        id: i32,
        status: &str,
        responded_by: &str,
        response: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE incidents SET hitl_status = $2, hitl_responded_by = $3, hitl_response = $4, hitl_responded_at = NOW(), updated_at = NOW() WHERE id = $1",
            &[&id, &status, &responded_by, &response],
        ).await.map_err(query_err)?;
        Ok(())
    }

    async fn attach_blast_radius_snapshot(
        &self,
        id: i32,
        score: u8,
        snapshot: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE incidents
                SET blast_radius_snapshot    = $2,
                    blast_radius_score       = $3,
                    blast_radius_computed_at = NOW(),
                    updated_at               = NOW()
              WHERE id = $1",
            &[&id, snapshot, &(score as i16)],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn update_incident_status(&self, id: i32, status: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let resolved = if status == "resolved" || status == "closed" {
            "NOW()"
        } else {
            "NULL"
        };
        conn.execute(
            &format!("UPDATE incidents SET status = $2, resolved_at = {}, updated_at = NOW() WHERE id = $1", resolved),
            &[&id, &status],
        ).await.map_err(query_err)?;
        Ok(())
    }

    async fn apply_operator_decision(
        &self,
        id: i32,
        decision: &str,
        actor: &str,
        reason: Option<&str>,
        snoozed_until: Option<chrono::DateTime<chrono::Utc>>,
        exception_scope: Option<&serde_json::Value>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Decision → (status, verdict, label written into notes).
        let (status, verdict, label) = match decision {
            "resolve" => ("resolved", "confirmed", "Resolve"),
            "false_positive" => ("resolved", "false_positive", "False Positive"),
            "accept_risk" => ("resolved", "risk_accepted", "Accept Risk"),
            "snooze" => ("snoozed", "pending", "Snooze"),
            other => {
                return Err(DatabaseError::Query(format!(
                    "apply_operator_decision: unknown decision {other:?}"
                )));
            }
        };
        let resolved_at_clause = if status == "resolved" {
            "NOW()"
        } else {
            "NULL"
        };
        let snooze_owned = snoozed_until;
        let reason_owned = reason.map(String::from);
        let scope_owned = exception_scope.cloned();
        let note_payload = serde_json::json!({
            "at": chrono::Utc::now().to_rfc3339(),
            "by": actor,
            "decision": label,
            "reason": reason.unwrap_or(""),
            "snoozed_until": snoozed_until.map(|t| t.to_rfc3339()),
            "exception_scope": exception_scope,
        });
        let sql = format!(
            "UPDATE incidents \
             SET status = $2, \
                 verdict = $3, \
                 resolved_at = {resolved_at_clause}, \
                 snoozed_until = $4, \
                 decision_reason = COALESCE($5, decision_reason), \
                 exception_scope = COALESCE($6, exception_scope), \
                 notes = COALESCE(notes, '[]'::jsonb) || jsonb_build_array($7::jsonb), \
                 updated_at = NOW() \
             WHERE id = $1"
        );
        conn.execute(
            &sql,
            &[
                &id,
                &status,
                &verdict,
                &snooze_owned,
                &reason_owned,
                &scope_owned,
                &note_payload,
            ],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn wake_expired_snoozes(&self) -> Result<Vec<i32>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "UPDATE incidents \
                 SET status = 'open', \
                     snoozed_until = NULL, \
                     notes = COALESCE(notes, '[]'::jsonb) || jsonb_build_array(jsonb_build_object( \
                         'at', NOW()::text, \
                         'by', 'system:snooze-scheduler', \
                         'decision', 'Snooze expired', \
                         'reason', 'Returning to active queue' \
                     )), \
                     updated_at = NOW() \
                 WHERE status = 'snoozed' \
                   AND snoozed_until IS NOT NULL \
                   AND snoozed_until <= NOW() \
                 RETURNING id",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    async fn admin_delete_incident(
        &self,
        id: i32,
        actor: &str,
    ) -> Result<serde_json::Value, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Capture a snapshot of the row before delete so the caller
        // can persist it in the audit log. We return id / asset /
        // title / verdict / status / created_at — enough to
        // reconstruct what was wiped without re-reading the row.
        let row = conn
            .query_one(
                "DELETE FROM incidents WHERE id = $1 \
                 RETURNING jsonb_build_object( \
                    'id', id, \
                    'asset', asset, \
                    'title', title, \
                    'status', status, \
                    'verdict', verdict, \
                    'created_at', created_at::text, \
                    'deleted_at', NOW()::text, \
                    'deleted_by', $2::text \
                 )",
                &[&id, &actor],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn update_incident_title(&self, id: i32, title: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE incidents SET title = $2, updated_at = NOW() WHERE id = $1",
            &[&id, &title],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn list_suppression_rules(
        &self,
        enabled_only: bool,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = if enabled_only {
            conn.query(
                "SELECT id, name, predicate, predicate_source, action, severity_cap,
                        scope, reason, created_by, created_at, expires_at, enabled,
                        match_count, last_match_at, source
                   FROM suppression_rules
                  WHERE enabled = TRUE AND expires_at > NOW()
                  ORDER BY created_at DESC",
                &[],
            )
            .await
            .map_err(query_err)?
        } else {
            conn.query(
                "SELECT id, name, predicate, predicate_source, action, severity_cap,
                        scope, reason, created_by, created_at, expires_at, enabled,
                        match_count, last_match_at, source
                   FROM suppression_rules
                  ORDER BY created_at DESC",
                &[],
            )
            .await
            .map_err(query_err)?
        };
        Ok(rows.into_iter().map(row_to_suppression_rule).collect())
    }

    async fn get_suppression_rule(
        &self,
        id: uuid::Uuid,
    ) -> Result<Option<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                "SELECT id, name, predicate, predicate_source, action, severity_cap,
                    scope, reason, created_by, created_at, expires_at, enabled,
                    match_count, last_match_at, source
               FROM suppression_rules WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(row_to_suppression_rule))
    }

    async fn create_suppression_rule(
        &self,
        name: &str,
        predicate: &serde_json::Value,
        predicate_source: &str,
        action: &str,
        severity_cap: Option<&str>,
        scope: &str,
        reason: &str,
        created_by: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        source: &str,
    ) -> Result<uuid::Uuid, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "INSERT INTO suppression_rules
                     (name, predicate, predicate_source, action, severity_cap,
                      scope, reason, created_by, expires_at, source)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                         COALESCE($9, NOW() + INTERVAL '90 days'), $10)
                 RETURNING id",
                &[
                    &name,
                    predicate,
                    &predicate_source,
                    &action,
                    &severity_cap,
                    &scope,
                    &reason,
                    &created_by,
                    &expires_at,
                    &source,
                ],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get("id"))
    }

    async fn disable_suppression_rule(&self, id: uuid::Uuid) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE suppression_rules SET enabled = FALSE WHERE id = $1",
            &[&id],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn load_active_suppression_rules(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        self.list_suppression_rules(true).await
    }

    async fn bump_suppression_match(&self, id: uuid::Uuid) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE suppression_rules
                SET match_count = match_count + 1,
                    last_match_at = NOW()
              WHERE id = $1",
            &[&id],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn list_incidents_for_preview(
        &self,
        lookback_days: i32,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, asset, title, severity, verdict, status,
                        mitre_techniques, alert_count, created_at
                   FROM incidents
                  WHERE created_at > NOW() - ($1::int || ' days')::interval
                  ORDER BY created_at DESC
                  LIMIT $2",
                &[&lookback_days, &limit],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.get::<_, i32>("id"),
                    "asset": r.get::<_, String>("asset"),
                    "title": r.get::<_, String>("title"),
                    "severity": r.get::<_, Option<String>>("severity"),
                    "verdict": r.get::<_, String>("verdict"),
                    "status": r.get::<_, String>("status"),
                    "mitre_techniques": r.get::<_, Option<Vec<String>>>("mitre_techniques"),
                    "alert_count": r.get::<_, Option<i32>>("alert_count"),
                    "created_at": r.get::<_, chrono::DateTime<chrono::Utc>>("created_at").to_rfc3339(),
                })
            })
            .collect())
    }

    async fn record_kev_observation(
        &self,
        cve_id: &str,
        kev_published_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<bool, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .execute(
                "INSERT INTO cve_exposure_alerts (cve_id, kev_published_at)
                 VALUES ($1, $2)
                 ON CONFLICT (cve_id) DO NOTHING",
                &[&cve_id, &kev_published_at],
            )
            .await
            .map_err(query_err)?;
        Ok(rows > 0)
    }

    async fn record_kev_first_match(
        &self,
        cve_id: &str,
        incident_id: Option<i32>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE cve_exposure_alerts
                SET first_asset_match_at = COALESCE(first_asset_match_at, NOW()),
                    incident_id = COALESCE(incident_id, $2)
              WHERE cve_id = $1",
            &[&cve_id, &incident_id],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn monthly_rssi_summary(
        &self,
        month: chrono::NaiveDate,
    ) -> Result<Option<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                "SELECT month, incidents_total, incidents_confirmed, incidents_fp,
                        incidents_inconclusive, incidents_resolved, incidents_open,
                        sev_critical, sev_high, sev_medium, sev_low,
                        incidents_with_blast, blast_score_avg, blast_score_max,
                        mttr_p50_sec, mttr_p95_sec,
                        first_incident_at, last_incident_at
                   FROM monthly_rssi_summary
                  WHERE month = $1",
                &[&month],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(|r| {
            serde_json::json!({
                "month": r.get::<_, chrono::NaiveDate>("month").to_string(),
                "incidents_total": r.get::<_, i64>("incidents_total"),
                "incidents_confirmed": r.get::<_, i64>("incidents_confirmed"),
                "incidents_fp": r.get::<_, i64>("incidents_fp"),
                "incidents_inconclusive": r.get::<_, i64>("incidents_inconclusive"),
                "incidents_resolved": r.get::<_, i64>("incidents_resolved"),
                "incidents_open": r.get::<_, i64>("incidents_open"),
                "sev_critical": r.get::<_, i64>("sev_critical"),
                "sev_high": r.get::<_, i64>("sev_high"),
                "sev_medium": r.get::<_, i64>("sev_medium"),
                "sev_low": r.get::<_, i64>("sev_low"),
                "incidents_with_blast": r.get::<_, i64>("incidents_with_blast"),
                "blast_score_avg": r.try_get::<_, Option<rust_decimal::Decimal>>("blast_score_avg").ok().flatten().map(|d| d.to_string()),
                "blast_score_max": r.get::<_, Option<i16>>("blast_score_max"),
                "mttr_p50_sec": r.try_get::<_, Option<f64>>("mttr_p50_sec").ok().flatten(),
                "mttr_p95_sec": r.try_get::<_, Option<f64>>("mttr_p95_sec").ok().flatten(),
                "first_incident_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("first_incident_at").map(|t| t.to_rfc3339()),
                "last_incident_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("last_incident_at").map(|t| t.to_rfc3339()),
            })
        }))
    }

    async fn top_incidents_by_blast(
        &self,
        month: chrono::NaiveDate,
        limit: i32,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, title, asset, severity, blast_radius_score, created_at
                   FROM top_incidents_by_blast($1, $2)",
                &[&month, &limit],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.get::<_, i32>("id"),
                    "title": r.get::<_, String>("title"),
                    "asset": r.get::<_, String>("asset"),
                    "severity": r.get::<_, Option<String>>("severity"),
                    "blast_radius_score": r.get::<_, Option<i16>>("blast_radius_score"),
                    "created_at": r.get::<_, chrono::DateTime<chrono::Utc>>("created_at").to_rfc3339(),
                })
            })
            .collect())
    }

    async fn refresh_monthly_rssi_summary(&self) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "REFRESH MATERIALIZED VIEW CONCURRENTLY monthly_rssi_summary",
            &[],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn kev_tta_metrics(&self) -> Result<serde_json::Value, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT matched_count, observed_count,
                        tta_alert_p50_sec, tta_alert_p95_sec, tta_alert_max_sec,
                        tta_ingest_p50_sec
                   FROM kev_tta_metrics_30d",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(serde_json::json!({
            "matched_count":   row.get::<_, Option<i64>>("matched_count").unwrap_or(0),
            "observed_count":  row.get::<_, Option<i64>>("observed_count").unwrap_or(0),
            "tta_alert_p50_sec": row.try_get::<_, Option<f64>>("tta_alert_p50_sec").ok().flatten(),
            "tta_alert_p95_sec": row.try_get::<_, Option<f64>>("tta_alert_p95_sec").ok().flatten(),
            "tta_alert_max_sec": row.get::<_, Option<i32>>("tta_alert_max_sec"),
            "tta_ingest_p50_sec": row.try_get::<_, Option<f64>>("tta_ingest_p50_sec").ok().flatten(),
        }))
    }

    async fn list_incidents(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Status filter semantics:
        //   None or "all"     → default view, excludes 'archived'
        //   "archived"        → only archived rows (for the dashboard toggle)
        //   "include_archived" → everything including archived
        //   anything else     → exact match
        let status_owned = status.map(String::from);
        let rows = match status_owned.as_deref() {
            None | Some("all") => {
                let q = format!(
                    "SELECT id, asset, title, summary, verdict, verdict_source, confidence, severity, alert_count, status, hitl_status, hitl_response, proposed_actions, mitre_techniques, notes, created_at, updated_at, resolved_at FROM incidents WHERE status != 'archived' ORDER BY created_at DESC LIMIT {} OFFSET {}",
                    limit, offset
                );
                conn.query(&q, &[]).await.map_err(query_err)?
            }
            Some("include_archived") => {
                let q = format!(
                    "SELECT id, asset, title, summary, verdict, verdict_source, confidence, severity, alert_count, status, hitl_status, hitl_response, proposed_actions, mitre_techniques, notes, created_at, updated_at, resolved_at FROM incidents ORDER BY created_at DESC LIMIT {} OFFSET {}",
                    limit, offset
                );
                conn.query(&q, &[]).await.map_err(query_err)?
            }
            Some(s) => {
                let q = format!(
                    "SELECT id, asset, title, summary, verdict, verdict_source, confidence, severity, alert_count, status, hitl_status, hitl_response, proposed_actions, mitre_techniques, notes, created_at, updated_at, resolved_at FROM incidents WHERE status = $1 ORDER BY created_at DESC LIMIT {} OFFSET {}",
                    limit, offset
                );
                conn.query(&q, &[&s.to_string()]).await.map_err(query_err)?
            }
        };
        let results: Vec<serde_json::Value> = rows.iter().map(|r| {
            serde_json::json!({
                "id": r.get::<_, i32>("id"),
                "asset": r.get::<_, String>("asset"),
                "title": r.get::<_, String>("title"),
                "summary": r.get::<_, Option<String>>("summary"),
                "verdict": r.get::<_, String>("verdict"),
                "verdict_source": r.get::<_, Option<String>>("verdict_source"),
                "confidence": r.get::<_, Option<f32>>("confidence"),
                "severity": r.get::<_, Option<String>>("severity"),
                "alert_count": r.get::<_, Option<i32>>("alert_count"),
                "status": r.get::<_, String>("status"),
                "hitl_status": r.get::<_, Option<String>>("hitl_status"),
                "hitl_response": r.get::<_, Option<String>>("hitl_response"),
                "proposed_actions": r.try_get::<_, serde_json::Value>("proposed_actions").unwrap_or(serde_json::json!([])),
                "mitre_techniques": r.get::<_, Option<Vec<String>>>("mitre_techniques"),
                "notes": r.try_get::<_, serde_json::Value>("notes").unwrap_or(serde_json::json!([])),
                "created_at": r.get::<_, chrono::DateTime<chrono::Utc>>("created_at").to_rfc3339(),
                "updated_at": r.get::<_, chrono::DateTime<chrono::Utc>>("updated_at").to_rfc3339(),
                "resolved_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("resolved_at").map(|t| t.to_rfc3339()),
            })
        }).collect();
        Ok(results)
    }

    async fn insert_risk_event(&self, ev: &NewRiskEvent) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "INSERT INTO risk_events \
                (risk_object, object_type, score, source_rule, mitre_tactic, mitre_technique, log_id, message) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &ev.risk_object,
                &ev.object_type,
                &ev.score,
                &ev.source_rule,
                &ev.mitre_tactic,
                &ev.mitre_technique,
                &ev.log_id,
                &ev.message,
            ],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn list_recent_risk_events(
        &self,
        since_hours: i64,
    ) -> Result<Vec<RiskEvent>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // since_hours is an internal i64 (never user input) — safe to interpolate,
        // same pattern as the interval clauses in query_logs_after_cursor.
        let interval = format!("INTERVAL '{} hours'", since_hours.max(1));
        let rows = conn
            .query(
                &format!(
                    "SELECT id, risk_object, object_type, score, source_rule, \
                            mitre_tactic, mitre_technique, log_id, message, created_at \
                     FROM risk_events \
                     WHERE created_at > NOW() - {} AND consumed_at IS NULL \
                     ORDER BY created_at DESC",
                    interval
                ),
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| RiskEvent {
                id: r.get(0),
                risk_object: r.get(1),
                object_type: r.get(2),
                score: r.get(3),
                source_rule: r.get(4),
                mitre_tactic: r.get::<_, Option<String>>(5),
                mitre_technique: r.get::<_, Option<String>>(6),
                log_id: r.get::<_, Option<i64>>(7),
                message: r.get::<_, Option<String>>(8),
                // RFC 3339 (not ::text) so the aggregator can parse_from_rfc3339
                // reliably for the 24h/7d windowing.
                created_at: r.get::<_, chrono::DateTime<chrono::Utc>>(9).to_rfc3339(),
            })
            .collect())
    }

    async fn mark_risk_events_consumed(
        &self,
        event_ids: &[i64],
        incident_id: i32,
    ) -> Result<u64, DatabaseError> {
        if event_ids.is_empty() {
            return Ok(0);
        }
        let conn = self.pool().get().await.map_err(pool_err)?;
        let n = conn
            .execute(
                "UPDATE risk_events SET consumed_at = NOW(), incident_id = $1 \
                 WHERE id = ANY($2) AND consumed_at IS NULL",
                &[&incident_id, &event_ids],
            )
            .await
            .map_err(query_err)?;
        Ok(n)
    }

    async fn insert_timeline_events(
        &self,
        incident_id: i32,
        events: &[NewTimelineEvent],
    ) -> Result<u64, DatabaseError> {
        if events.is_empty() {
            return Ok(0);
        }
        let mut conn = self.pool().get().await.map_err(pool_err)?;
        let tx = conn.transaction().await.map_err(query_err)?;
        let mut n: u64 = 0;
        for e in events {
            let related = serde_json::to_value(&e.related_artifacts)
                .unwrap_or_else(|_| serde_json::json!([]));
            let ts = chrono::DateTime::parse_from_rfc3339(&e.ts)
                .map(|d| d.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            tx.execute(
                "INSERT INTO forensic_timeline \
                    (incident_id, ts, tz_origin, event_type, asset, actor, description, \
                     severity, mitre_tactic, mitre_technique, ioc, related_artifacts, \
                     source_artifact, collected_hash) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
                &[
                    &incident_id,
                    &ts,
                    &e.tz_origin,
                    &e.event_type,
                    &e.asset,
                    &e.actor,
                    &e.description,
                    &e.severity,
                    &e.mitre_tactic,
                    &e.mitre_technique,
                    &e.ioc,
                    &related,
                    &e.source_artifact,
                    &e.collected_hash,
                ],
            )
            .await
            .map_err(query_err)?;
            n += 1;
        }
        tx.commit().await.map_err(query_err)?;
        Ok(n)
    }

    async fn list_timeline_for_incident(
        &self,
        incident_id: i32,
    ) -> Result<Vec<TimelineEvent>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, incident_id, ts, event_type, asset, actor, description, severity, \
                        mitre_tactic, mitre_technique, ioc, source_artifact, created_at \
                 FROM forensic_timeline WHERE incident_id = $1 ORDER BY ts ASC, id ASC",
                &[&incident_id],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| TimelineEvent {
                id: r.get(0),
                incident_id: r.get(1),
                ts: r.get::<_, chrono::DateTime<chrono::Utc>>(2).to_rfc3339(),
                event_type: r.get(3),
                asset: r.get(4),
                actor: r.get::<_, Option<String>>(5),
                description: r.get(6),
                severity: r.get(7),
                mitre_tactic: r.get::<_, Option<String>>(8),
                mitre_technique: r.get::<_, Option<String>>(9),
                ioc: r.get::<_, Option<String>>(10),
                source_artifact: r.get::<_, Option<String>>(11),
                created_at: r.get::<_, chrono::DateTime<chrono::Utc>>(12).to_rfc3339(),
            })
            .collect())
    }

    async fn mark_dfir_collected(&self, incident_id: i32) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE incidents SET dfir_collected_at = NOW() WHERE id = $1",
            &[&incident_id],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn list_incidents_needing_dfir(
        &self,
        limit: i64,
    ) -> Result<Vec<(i32, String)>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, asset FROM incidents \
                 WHERE dfir_collected_at IS NULL \
                   AND status NOT IN ('closed', 'archived', 'resolved', 'dismissed') \
                 ORDER BY created_at DESC LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<_, i32>(0), r.get::<_, String>(1)))
            .collect())
    }

    async fn get_incident(&self, id: i32) -> Result<Option<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn.query_opt(
            "SELECT id, asset, title, summary, verdict, verdict_source, confidence, severity, alert_ids, finding_ids, alert_count, investigation_log, mitre_techniques, proposed_actions, executed_actions, status, hitl_status, hitl_nonce, hitl_responded_at, hitl_responded_by, hitl_response, notified_channels, notes, evidence_citations, forensic_enriched_at, blast_radius_snapshot, blast_radius_score, blast_radius_computed_at, enrichment, created_at, updated_at, resolved_at FROM incidents WHERE id = $1",
            &[&id],
        ).await.map_err(query_err)?;
        Ok(row.map(|r| serde_json::json!({
            "id": r.get::<_, i32>("id"),
            "asset": r.get::<_, String>("asset"),
            "title": r.get::<_, String>("title"),
            "summary": r.get::<_, Option<String>>("summary"),
            "verdict": r.get::<_, String>("verdict"),
            "verdict_source": r.get::<_, Option<String>>("verdict_source"),
            "confidence": r.get::<_, Option<f32>>("confidence"),
            "severity": r.get::<_, Option<String>>("severity"),
            "alert_ids": r.get::<_, Option<Vec<i32>>>("alert_ids"),
            "finding_ids": r.get::<_, Option<Vec<i32>>>("finding_ids"),
            "alert_count": r.get::<_, Option<i32>>("alert_count"),
            "investigation_log": r.try_get::<_, serde_json::Value>("investigation_log").unwrap_or(serde_json::json!([])),
            "mitre_techniques": r.get::<_, Option<Vec<String>>>("mitre_techniques"),
            "proposed_actions": r.try_get::<_, serde_json::Value>("proposed_actions").unwrap_or(serde_json::json!([])),
            "executed_actions": r.try_get::<_, serde_json::Value>("executed_actions").unwrap_or(serde_json::json!([])),
            "status": r.get::<_, String>("status"),
            "hitl_status": r.get::<_, Option<String>>("hitl_status"),
            "hitl_responded_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("hitl_responded_at").map(|t| t.to_rfc3339()),
            "hitl_responded_by": r.get::<_, Option<String>>("hitl_responded_by"),
            "hitl_response": r.get::<_, Option<String>>("hitl_response"),
            "notified_channels": r.get::<_, Option<Vec<String>>>("notified_channels"),
            "notes": r.try_get::<_, serde_json::Value>("notes").unwrap_or(serde_json::json!([])),
            "evidence_citations": r.try_get::<_, serde_json::Value>("evidence_citations").unwrap_or(serde_json::json!([])),
            "forensic_enriched_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("forensic_enriched_at").map(|t| t.to_rfc3339()),
            "blast_radius_snapshot": r.try_get::<_, Option<serde_json::Value>>("blast_radius_snapshot").unwrap_or(None),
            "blast_radius_score": r.get::<_, Option<i16>>("blast_radius_score"),
            "blast_radius_computed_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("blast_radius_computed_at").map(|t| t.to_rfc3339()),
            "enrichment": r.try_get::<_, serde_json::Value>("enrichment").unwrap_or(serde_json::json!({})),
            "created_at": r.get::<_, chrono::DateTime<chrono::Utc>>("created_at").to_rfc3339(),
            "updated_at": r.get::<_, chrono::DateTime<chrono::Utc>>("updated_at").to_rfc3339(),
            "resolved_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("resolved_at").map(|t| t.to_rfc3339()),
        })))
    }

    async fn try_claim_incident_action(
        &self,
        incident_id: i32,
        subject: &str,
    ) -> Result<bool, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Append an in_progress marker for `subject` iff no LIVE marker exists:
        // - a `done` tombstone (action already executed), or
        // - a fresh `in_progress` claim (younger than the 10-minute window —
        //   an older one is treated as abandoned, e.g. a crash mid-execution,
        //   so the operator is never permanently locked out).
        // The whole thing is one conditional UPDATE: two concurrent approvals
        // (dashboard + chat) race on the same row and exactly one appends.
        let rows = conn
            .execute(
                "UPDATE incidents \
                 SET executed_actions = executed_actions || jsonb_build_array( \
                         jsonb_build_object('subject', $2::text, 'status', 'in_progress', 'at', now()::text)), \
                     updated_at = now() \
                 WHERE id = $1 \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM jsonb_array_elements(executed_actions) e \
                     WHERE e->>'subject' = $2 \
                       AND ( e->>'status' = 'done' \
                          OR (e->>'status' = 'in_progress' \
                              AND (e->>'at')::timestamptz > now() - interval '10 minutes') ) \
                   )",
                &[&incident_id, &subject],
            )
            .await
            .map_err(query_err)?;
        Ok(rows > 0)
    }

    async fn finalize_incident_action(
        &self,
        incident_id: i32,
        subject: &str,
        success: bool,
        message: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        if success {
            // Promote the in_progress marker for `subject` to a permanent done
            // tombstone (carries the outcome message for the dashboard).
            conn.execute(
                "UPDATE incidents SET executed_actions = ( \
                     SELECT coalesce(jsonb_agg( \
                         CASE WHEN e->>'subject' = $2 AND e->>'status' = 'in_progress' \
                              THEN jsonb_build_object('subject', $2::text, 'status', 'done', \
                                                      'success', true, 'message', $3::text, 'at', now()::text) \
                              ELSE e END), '[]'::jsonb) \
                     FROM jsonb_array_elements(executed_actions) e \
                 ), updated_at = now() WHERE id = $1",
                &[&incident_id, &subject, &message],
            )
            .await
            .map_err(query_err)?;
        } else {
            // Release the in_progress marker so the operator can retry.
            conn.execute(
                "UPDATE incidents SET executed_actions = ( \
                     SELECT coalesce(jsonb_agg(e), '[]'::jsonb) \
                     FROM jsonb_array_elements(executed_actions) e \
                     WHERE NOT (e->>'subject' = $2 AND e->>'status' = 'in_progress') \
                 ), updated_at = now() WHERE id = $1",
                &[&incident_id, &subject],
            )
            .await
            .map_err(query_err)?;
        }
        Ok(())
    }

    async fn find_open_incident_for_asset_with_pattern(
        &self,
        asset: &str,
        pattern_key: Option<&str>,
    ) -> Result<Option<i32>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let key_owned = pattern_key.map(String::from);
        // Pattern-aware dedup. The asset-only fallback (key IS NULL ⇒
        // legacy semantics) is preserved for callers that have not
        // extracted a pattern_key. Otherwise: only merge into an
        // existing incident when the pattern matches, OR when the
        // existing incident has not yet been stamped with a pattern at
        // all. A different pattern on the same asset escalates as a
        // new incident, so the title and timeline reflect the new
        // attack instead of being absorbed by an older one.
        //
        // The asset column is matched against the full alias set
        // (id / name / hostname / lower variants) for the same reason
        // recent_sigma_alerts_for_asset does: when an operator creates
        // an incident manually under the bare hostname while the IE
        // creates one under the auto-enrol id (or vice versa), the
        // dedup needs to recognise both shapes as the same machine.
        let row = conn
            .query_opt(
                "WITH asset_resolved AS ( \
                   SELECT id, name, hostname FROM assets \
                   WHERE id = $1 OR name = $1 OR hostname = $1 \
                      OR LOWER(name) = LOWER($1) OR LOWER(hostname) = LOWER($1) \
                 ), asset_aliases AS ( \
                   SELECT LOWER(id) AS alias FROM asset_resolved \
                   UNION SELECT LOWER(name) FROM asset_resolved WHERE name IS NOT NULL \
                   UNION SELECT LOWER(hostname) FROM asset_resolved WHERE hostname IS NOT NULL \
                   UNION SELECT LOWER($1) \
                 ) \
                 SELECT id FROM incidents \
                 WHERE LOWER(asset) IN (SELECT alias FROM asset_aliases) \
                   AND status IN ('open', 'investigating') \
                   AND updated_at > NOW() - INTERVAL '4 hours' \
                   AND ($2::text IS NULL \
                        OR last_pattern_key IS NULL \
                        OR last_pattern_key = $2) \
                 ORDER BY created_at DESC LIMIT 1",
                &[&asset, &key_owned],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(|r| r.get("id")))
    }

    async fn find_recently_dispositioned_incident_for_asset_with_pattern(
        &self,
        asset: &str,
        pattern_key: Option<&str>,
    ) -> Result<Option<i32>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let key_owned = pattern_key.map(String::from);
        // Same window as the open-incident lookup, but on rows the
        // operator has already triaged out (resolved) or paused
        // (snoozed). Used to rate-limit incident creation so a flapping
        // signal does not recreate a fresh incident every 5-minute
        // cycle on a pattern that the operator already decided to
        // close. The caller treats a Some(_) hit as "skip create".
        // Asset-alias-aware match — see find_open_incident_for_asset_with_pattern.
        let row = conn
            .query_opt(
                "WITH asset_resolved AS ( \
                   SELECT id, name, hostname FROM assets \
                   WHERE id = $1 OR name = $1 OR hostname = $1 \
                      OR LOWER(name) = LOWER($1) OR LOWER(hostname) = LOWER($1) \
                 ), asset_aliases AS ( \
                   SELECT LOWER(id) AS alias FROM asset_resolved \
                   UNION SELECT LOWER(name) FROM asset_resolved WHERE name IS NOT NULL \
                   UNION SELECT LOWER(hostname) FROM asset_resolved WHERE hostname IS NOT NULL \
                   UNION SELECT LOWER($1) \
                 ) \
                 SELECT id FROM incidents \
                 WHERE LOWER(asset) IN (SELECT alias FROM asset_aliases) \
                   AND status IN ('resolved', 'snoozed') \
                   AND updated_at > NOW() - INTERVAL '4 hours' \
                   AND ($2::text IS NULL \
                        OR last_pattern_key IS NULL \
                        OR last_pattern_key = $2) \
                 ORDER BY updated_at DESC LIMIT 1",
                &[&asset, &key_owned],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(|r| r.get("id")))
    }

    async fn find_open_incident_for_asset(
        &self,
        asset: &str,
    ) -> Result<Option<i32>, DatabaseError> {
        // Only match incidents from the last 4 hours to allow "fresh" recurring
        // incidents to merge, but don't resurrect old ones that were never closed.
        // Match insensible à la casse (LOWER des deux côtés) parce que les
        // sources d'asset_id varient — Wazuh écrit en uppercase, l'asset
        // ID en DB peut être lowercase, mes injects de test peuvent
        // utiliser l'un ou l'autre. Sans LOWER, la dedup rate et on crée
        // un doublon (#114bis pour SRV-01-DOM alors que #114 srv-01-dom
        // existe déjà).
        // Asset-alias-aware match — see find_open_incident_for_asset_with_pattern.
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                "WITH asset_resolved AS ( \
                   SELECT id, name, hostname FROM assets \
                   WHERE id = $1 OR name = $1 OR hostname = $1 \
                      OR LOWER(name) = LOWER($1) OR LOWER(hostname) = LOWER($1) \
                 ), asset_aliases AS ( \
                   SELECT LOWER(id) AS alias FROM asset_resolved \
                   UNION SELECT LOWER(name) FROM asset_resolved WHERE name IS NOT NULL \
                   UNION SELECT LOWER(hostname) FROM asset_resolved WHERE hostname IS NOT NULL \
                   UNION SELECT LOWER($1) \
                 ) \
                 SELECT id FROM incidents \
                 WHERE LOWER(asset) IN (SELECT alias FROM asset_aliases) \
                   AND status IN ('open', 'investigating') \
                   AND updated_at > NOW() - INTERVAL '4 hours' \
                 ORDER BY created_at DESC LIMIT 1",
                &[&asset],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(|r| r.get("id")))
    }

    async fn touch_incident(
        &self,
        id: i32,
        alert_count_delta: i32,
        pattern_key: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Sprint 5 #2 — bump `alert_count` only when the pattern key
        // actually changed. `pattern_key = NULL` means "legacy caller,
        // always bump" (preserves prior semantics).
        let key_owned = pattern_key.map(String::from);
        conn.execute(
            "UPDATE incidents \
             SET alert_count = alert_count + CASE \
                 WHEN $3::text IS NULL THEN $2 \
                 WHEN last_pattern_key IS DISTINCT FROM $3 THEN $2 \
                 ELSE 0 \
               END, \
                 last_pattern_key = COALESCE($3, last_pattern_key), \
                 updated_at = NOW() \
             WHERE id = $1",
            &[&id, &alert_count_delta, &key_owned],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn set_incident_enrichment(
        &self,
        id: i32,
        enrichment: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE incidents SET enrichment = $2, updated_at = NOW() WHERE id = $1",
            &[&id, enrichment],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn set_incident_proposed_actions(
        &self,
        id: i32,
        proposed_actions: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE incidents SET proposed_actions = $2, updated_at = NOW() WHERE id = $1",
            &[&id, proposed_actions],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn billable_breakdown(
        &self,
        billable_categories: &[String],
    ) -> Result<crate::agent::billing::BillableCount, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let cats: Vec<&str> = billable_categories.iter().map(|s| s.as_str()).collect();

        // V67 model — see src/agent/billing.rs for the rationale.
        // The "discovered" / "inactive" counts on the widget now read
        // inventory_status (the V66 billable_status column is left
        // populated for backward-compat but no longer the source of
        // truth for the widget breakdown).
        let row = conn
            .query_one(
                "WITH all_counts AS ( \
                    SELECT \
                        COUNT(*) FILTER (WHERE TRUE)                                                                               AS total, \
                        COUNT(*) FILTER (WHERE inventory_status = 'observed_transient' AND distinct_days_seen_30d < 3)             AS discovered, \
                        COUNT(*) FILTER (WHERE inventory_status = 'inactive' OR last_seen <= NOW() - INTERVAL '30 days')           AS inactive, \
                        COUNT(*) FILTER (WHERE dedup_confidence = 'uncertain')                                                     AS uncertain, \
                        COUNT(*) FILTER (WHERE demo = true)                                                                        AS demo \
                    FROM assets \
                ), billable_count AS ( \
                    SELECT COUNT(*) AS billable \
                      FROM assets \
                     WHERE demo = false \
                       AND excluded = false \
                       AND status = 'active' \
                       AND dedup_confidence != 'uncertain' \
                       AND last_seen > NOW() - INTERVAL '30 days' \
                       AND ( \
                            ( \
                                inventory_status IN ('declared','observed_persistent') \
                                AND category NOT IN ('website','cloud','container','pod','lambda','function') \
                            ) \
                            OR ( \
                                inventory_status = 'observed_transient' \
                                AND distinct_days_seen_30d >= 3 \
                                AND category = ANY($1) \
                            ) \
                       ) \
                ) \
                SELECT a.total, a.discovered, a.inactive, a.uncertain, a.demo, b.billable \
                  FROM all_counts a CROSS JOIN billable_count b",
                &[&cats],
            )
            .await
            .map_err(query_err)?;

        let total: i64 = row.get("total");
        let discovered: i64 = row.get("discovered");
        let inactive: i64 = row.get("inactive");
        let uncertain: i64 = row.get("uncertain");
        let demo: i64 = row.get("demo");
        let billable: i64 = row.get("billable");

        // Per-category breakdown (only the billable subset).
        let cat_rows = conn
            .query(
                "SELECT category, COUNT(*) AS n \
                   FROM assets \
                  WHERE demo = false \
                    AND excluded = false \
                    AND status = 'active' \
                    AND dedup_confidence != 'uncertain' \
                    AND last_seen > NOW() - INTERVAL '30 days' \
                    AND ( \
                         ( \
                             inventory_status IN ('declared','observed_persistent') \
                             AND category NOT IN ('website','cloud','container','pod','lambda','function') \
                         ) \
                         OR ( \
                             inventory_status = 'observed_transient' \
                             AND distinct_days_seen_30d >= 3 \
                             AND category = ANY($1) \
                         ) \
                    ) \
                  GROUP BY category \
                  ORDER BY n DESC",
                &[&cats],
            )
            .await
            .map_err(query_err)?;
        let by_category: Vec<(String, i64)> = cat_rows
            .iter()
            .map(|r| (r.get::<_, String>("category"), r.get::<_, i64>("n")))
            .collect();

        Ok(crate::agent::billing::BillableCount {
            billable,
            total,
            by_category,
            discovered,
            inactive,
            uncertain,
            demo,
        })
    }

    async fn reclassify_inactive_assets(&self, idle_days: i32) -> Result<u64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Bounded statement — clamp idle_days to a sane range to avoid
        // accidentally setting the cutoff in the future.
        let days = idle_days.clamp(1, 365);
        // V67 — flip both inventory_status AND legacy billable_status.
        // last_seen is the inventory connector's heartbeat for the asset
        // (set at every resolve), so it's the right anchor for "is this
        // asset still in the parc".
        let n = conn
            .execute(
                &format!(
                    "UPDATE assets \
                        SET inventory_status = 'inactive', \
                            billable_status = 'inactive' \
                      WHERE inventory_status != 'inactive' \
                        AND last_seen < NOW() - INTERVAL '{} days'",
                    days
                ),
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(n)
    }

    async fn phase_g_acceptance_stats(
        &self,
        lookback_days: i32,
    ) -> Result<(i64, i64, Vec<i32>), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // total incidents in window (excluding archived)
        let q_total = format!(
            "SELECT COUNT(*)::bigint AS n FROM incidents \
             WHERE created_at > NOW() - INTERVAL '{} days' \
               AND status != 'archived'",
            lookback_days.max(1)
        );
        let total_row = conn
            .query_one(q_total.as_str(), &[])
            .await
            .map_err(query_err)?;
        let total: i64 = total_row.get("n");

        // incidents in window without any proposed_actions.actions
        let q_missing = format!(
            "SELECT id, COUNT(*) OVER ()::bigint AS n FROM incidents \
             WHERE created_at > NOW() - INTERVAL '{} days' \
               AND status != 'archived' \
               AND ( \
                    proposed_actions IS NULL \
                 OR proposed_actions = '[]'::jsonb \
                 OR (proposed_actions->'actions') IS NULL \
                 OR jsonb_typeof(proposed_actions->'actions') != 'array' \
                 OR jsonb_array_length(proposed_actions->'actions') = 0 \
               ) \
             ORDER BY created_at DESC \
             LIMIT 20",
            lookback_days.max(1)
        );
        let rows = conn
            .query(q_missing.as_str(), &[])
            .await
            .map_err(query_err)?;
        let missing: i64 = rows.first().map(|r| r.get::<_, i64>("n")).unwrap_or(0);
        let ids: Vec<i32> = rows.iter().map(|r| r.get::<_, i32>("id")).collect();
        Ok((total, missing, ids))
    }

    async fn cleanup_old_sigma_alerts(&self, days_old: i32) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Delete only acknowledged/resolved alerts to avoid losing actionable ones.
        // 'new' alerts are kept regardless of age (they may still be relevant).
        let q = format!(
            "DELETE FROM sigma_alerts \
             WHERE status IN ('acknowledged', 'resolved') \
               AND matched_at < NOW() - INTERVAL '{} days'",
            days_old.max(1)
        );
        let count = conn.execute(q.as_str(), &[]).await.map_err(query_err)?;
        Ok(count as i64)
    }

    async fn recent_sigma_alerts_for_asset(
        &self,
        asset: &str,
        hours: i64,
    ) -> Result<Vec<crate::agent::incident_dossier::DossierAlert>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let since = chrono::Utc::now() - chrono::Duration::hours(hours);
        let rows = conn
            .query(
                // Select rule_id for Investigation Graph matching (CACAO trigger.sigma_rule),
                // title as human-readable rule_name for prompts and logs,
                // matched_fields + username for CEL signal computation.
                // The WHERE clause covers both hostname-based and IP-based assets
                // so that assets identified by source IP (e.g. "198.177.125.117")
                // still get their sigma alerts loaded.
                // Match sigma alerts via :
                //   - hostname = asset_id / name / hostname (canonical)
                //   - hostname IN asset.ip_addresses (sigma alert keyed par IP au lieu du hostname)
                //   - source_ip = asset_id (asset identifié par IP brute)
                //   - source_ip IN asset.ip_addresses (IDS alert où source_ip = une IP de l'asset)
                //
                // Le `$1` peut être l'asset.id, .name ou .hostname selon la source —
                // on les teste tous via OR. Ensuite on dérive `ip_addresses` par
                // unnest() puisque le strip des ports (`10.77.0.174:51788` → `10.77.0.174`)
                // se fait côté SQL via split_part. Sans cette résolution, asset
                // 'debian' (id=asset-bc24..., ip=[10.77.0.136]) manque les
                // sigma_alerts hostname='10.77.0.136'. Voir #1577 cas d'école.
                // Exclude alerts the analyst has already triaged out — without
                // this filter the IE keeps re-picking false_positive and
                // resolved rows in the next cycle, regenerating the very
                // incident the analyst just closed. Surfaced during the
                // 2026-06 cleanup when INC-64 closed-as-FP came back as
                // INC-65 immediately on the next 5-min tick because the
                // historical lnx-acct-002 alerts marked false_positive were
                // still considered active context.
                // 2026-06-17 — resolve the asset to its full hostname set
                // (id, name, hostname) BEFORE matching sigma_alerts. The old
                // version compared sigma_alerts.hostname only against `$1`,
                // which is the asset.id passed by the IE — so for assets
                // auto-enrolled as `syslog-observed-sd-98664` (id) whose real
                // hostname is `sd-98664`, the lookup returned 0 rows even
                // though dozens of alerts had hostname='sd-98664'. The
                // empty result then drove the dossier to L1 ReAct on no
                // evidence, and the LLM hallucinated CRITICAL "behavioral
                // anomalies" verdicts (incidents #47/48/51/56/62/84/89/122).
                // We now broaden the match to every alias the assets table
                // knows for this entity (id, name, hostname) plus its IP
                // addresses, both case-sensitive and lower-cased so a sigma
                // alert keyed on `SRV-CYBE06-001` aligns with an asset
                // declared as `srv-cybe06-001` after V84.
                "WITH asset_resolved AS ( \
                   SELECT id, name, hostname, COALESCE(ip_addresses, '{}'::text[]) AS ips \
                   FROM assets \
                   WHERE id = $1 OR name = $1 OR hostname = $1 \
                      OR LOWER(name) = LOWER($1) OR LOWER(hostname) = LOWER($1) \
                 ), asset_aliases AS ( \
                   SELECT id AS alias FROM asset_resolved \
                   UNION SELECT name FROM asset_resolved WHERE name IS NOT NULL \
                   UNION SELECT hostname FROM asset_resolved WHERE hostname IS NOT NULL \
                   UNION SELECT LOWER(name) FROM asset_resolved WHERE name IS NOT NULL \
                   UNION SELECT LOWER(hostname) FROM asset_resolved WHERE hostname IS NOT NULL \
                   UNION SELECT UPPER(name) FROM asset_resolved WHERE name IS NOT NULL \
                   UNION SELECT UPPER(hostname) FROM asset_resolved WHERE hostname IS NOT NULL \
                   UNION SELECT $1 \
                 ), asset_ips AS ( \
                   SELECT split_part(unnest(ips), ':', 1) AS ip FROM asset_resolved \
                 ) \
                 SELECT id, rule_id, COALESCE(title, rule_id, 'unknown'), level, \
                        matched_at, COALESCE(matched_fields, '{}'), username, \
                        source_ip::text \
                 FROM sigma_alerts \
                 WHERE ( \
                     hostname IN (SELECT alias FROM asset_aliases) \
                     OR source_ip::text IN (SELECT alias FROM asset_aliases) \
                     OR hostname IN (SELECT ip FROM asset_ips) \
                     OR source_ip::text IN (SELECT ip FROM asset_ips) \
                 ) AND matched_at >= $2 \
                   AND status NOT IN ('false_positive', 'resolved') \
                 ORDER BY \
                   CASE WHEN level = 'critical' THEN 0 \
                        WHEN level = 'high'     THEN 1 \
                        WHEN level = 'medium'   THEN 2 \
                        ELSE 3 END, \
                   matched_at DESC \
                 LIMIT 20",
                &[&asset, &since],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .iter()
            .map(|r| {
                let id: i64 = r.get(0);
                crate::agent::incident_dossier::DossierAlert {
                    id,
                    rule_id: r.get(1),
                    rule_name: r.get(2),
                    level: r.get(3),
                    source_ip: r.get::<_, Option<String>>(7),
                    matched_fields: r.get::<_, serde_json::Value>(5),
                    created_at: r.get(4),
                    username: r.get(6),
                }
            })
            .collect())
    }

    async fn count_attack_paths_for_asset(&self, asset: &str) -> Result<u32, DatabaseError> {
        // 2026-06-17 — same alias-resolution treatment as
        // recent_sigma_alerts_for_asset and count_recent_signals_on_asset.
        // attack_paths_predicted may key on the asset.id, name or hostname
        // depending on which graph populated the run (path_risk vs.
        // CACAO graphs), so we test every alias the assets table knows
        // for this entity.
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                "WITH asset_resolved AS ( \
                   SELECT id, name, hostname FROM assets \
                   WHERE id = $1 OR name = $1 OR hostname = $1 \
                      OR LOWER(name) = LOWER($1) OR LOWER(hostname) = LOWER($1) \
                 ), asset_aliases AS ( \
                   SELECT id AS alias FROM asset_resolved \
                   UNION SELECT name FROM asset_resolved WHERE name IS NOT NULL \
                   UNION SELECT hostname FROM asset_resolved WHERE hostname IS NOT NULL \
                   UNION SELECT $1 \
                 ), last_run AS ( \
                    SELECT run_id FROM attack_paths_predicted \
                    ORDER BY computed_at DESC LIMIT 1 \
                 ) \
                 SELECT COUNT(*)::bigint \
                 FROM attack_paths_predicted \
                 WHERE run_id = (SELECT run_id FROM last_run) \
                   AND ( \
                     src_asset IN (SELECT alias FROM asset_aliases) \
                     OR dst_asset IN (SELECT alias FROM asset_aliases) \
                     OR EXISTS ( \
                       SELECT 1 FROM unnest(path_assets) AS p \
                       WHERE p IN (SELECT alias FROM asset_aliases) \
                     ) \
                   )",
                &[&asset],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(|r| r.get::<_, i64>(0) as u32).unwrap_or(0))
    }

    async fn count_mitre_techniques(&self) -> Result<i64, DatabaseError> {
        // MITRE techniques are stored as settings rows under user_id='_mitre',
        // not in the legacy mitre_techniques table (which exists from migration
        // V21 but is unused — see enrichment/mitre_attack.rs).
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT COUNT(*) AS cnt FROM settings WHERE user_id = '_mitre'",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get("cnt"))
    }

    async fn archive_resolved_incidents(&self) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Also archive incidents that have been closed for at least 1 hour
        // (gives the RSSI a short window to see the closure before it disappears).
        let count = conn
            .execute(
                "UPDATE incidents SET status = 'archived', updated_at = NOW() \
             WHERE status IN ('resolved', 'closed', 'false_positive')",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(count as i64)
    }

    async fn archive_resolved_alerts(&self) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let count = conn
            .execute(
                "UPDATE sigma_alerts SET status = 'archived' \
             WHERE status IN ('resolved', 'acknowledged')",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(count as i64)
    }

    async fn bulk_archive_perimeter_mitigated(&self, dry_run: bool) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Cross-reference incident assets with src_ip values extracted from
        // any linked Suricata IDS finding's `matched_fields[*][1]` JSON line.
        // For each candidate (open, no sigma alerts), build a set of
        // "related IPs": the asset itself when it's an IPv4, plus any src_ip
        // pulled out of a Suricata payload. An incident is perimeter-
        // mitigated iff one of those IPs has at least one firewall block
        // event (action ∈ {block, blocked}) AND no firewall pass event
        // (action ∈ {pass, allow}) anywhere in the last 7 days.
        let select_ids = r#"
            WITH candidate AS (
                SELECT i.id, i.asset, i.finding_ids
                FROM incidents i
                WHERE i.status = 'open'
                  AND (i.alert_ids IS NULL
                       OR array_length(i.alert_ids, 1) IS NULL
                       OR array_length(i.alert_ids, 1) = 0)
                  AND i.asset IS NOT NULL
            ),
            incident_ips AS (
                SELECT c.id AS incident_id, c.asset AS ip
                FROM candidate c
                WHERE c.asset ~ '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
                UNION
                SELECT DISTINCT c.id,
                       (regexp_match(pair->>1, '"src_ip":"([^"]+)"'))[1]
                FROM candidate c
                JOIN findings cf ON cf.id = ANY(c.finding_ids::bigint[])
                CROSS JOIN LATERAL jsonb_array_elements(cf.metadata::jsonb->'matched_fields') AS pair
                WHERE jsonb_typeof(cf.metadata::jsonb->'matched_fields') = 'array'
                  AND pair->>0 = 'line'
                  AND pair->>1 ~ '"src_ip":"([^"]+)"'
            ),
            analysis AS (
                SELECT ii.incident_id,
                       BOOL_OR(
                           jsonb_typeof(f.metadata::jsonb->'matched_fields') = 'array'
                           AND EXISTS (
                               SELECT 1 FROM jsonb_array_elements(f.metadata::jsonb->'matched_fields') p
                               WHERE p->>0 = 'action' AND p->>1 IN ('block', 'blocked')
                           )
                       ) AS has_block,
                       BOOL_OR(
                           jsonb_typeof(f.metadata::jsonb->'matched_fields') = 'array'
                           AND EXISTS (
                               SELECT 1 FROM jsonb_array_elements(f.metadata::jsonb->'matched_fields') p
                               WHERE p->>0 = 'action' AND p->>1 IN ('pass', 'allow')
                           )
                       ) AS has_pass
                FROM incident_ips ii
                JOIN findings f
                  ON f.asset = ii.ip
                 AND f.detected_at > NOW() - INTERVAL '7 days'
                GROUP BY ii.incident_id
            )
            SELECT incident_id AS id FROM analysis
            WHERE has_block = TRUE AND has_pass = FALSE
        "#;
        if dry_run {
            let row = conn
                .query_one(
                    &format!("SELECT COUNT(*)::BIGINT AS n FROM ({}) m", select_ids),
                    &[],
                )
                .await
                .map_err(query_err)?;
            return Ok(row.get("n"));
        }
        let updated = conn
            .execute(
                &format!(
                    "UPDATE incidents SET status='archived', verdict='false_positive', \
                     updated_at = NOW() WHERE id IN ({})",
                    select_ids
                ),
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(updated as i64)
    }

    async fn bulk_archive_stale_pending(&self, hours: i64) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let hours_i32 = hours.clamp(1, 24 * 365 * 10) as i32;
        let count = conn
            .execute(
                "UPDATE incidents SET status = 'archived', updated_at = NOW() \
                 WHERE status = 'open' \
                   AND verdict = 'pending' \
                   AND created_at < NOW() - make_interval(hours => $1)",
                &[&hours_i32],
            )
            .await
            .map_err(query_err)?;
        Ok(count as i64)
    }

    async fn list_confirmed_unenriched_incidents(
        &self,
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, asset, title, summary, mitre_techniques, severity, alert_count, \
                        proposed_actions, evidence_citations, created_at, \
                        alert_ids, finding_ids \
                 FROM incidents \
                 WHERE verdict = 'confirmed' \
                   AND forensic_enriched_at IS NULL \
                   AND status != 'archived' \
                 ORDER BY created_at DESC \
                 LIMIT 1",
                &[],
            )
            .await
            .map_err(query_err)?;
        let results = rows.iter().map(|r| {
            serde_json::json!({
                "id": r.get::<_, i32>("id"),
                "asset": r.get::<_, String>("asset"),
                "title": r.get::<_, String>("title"),
                "summary": r.get::<_, Option<String>>("summary"),
                "mitre_techniques": r.get::<_, Option<Vec<String>>>("mitre_techniques"),
                "severity": r.get::<_, Option<String>>("severity"),
                "alert_count": r.get::<_, Option<i32>>("alert_count"),
                "proposed_actions": r.try_get::<_, serde_json::Value>("proposed_actions").unwrap_or(serde_json::json!([])),
                "evidence_citations": r.try_get::<_, serde_json::Value>("evidence_citations").unwrap_or(serde_json::json!([])),
                "created_at": r.get::<_, chrono::DateTime<chrono::Utc>>("created_at").to_rfc3339(),
                // Phase 2a — re-fetch findings/alerts in forensic_enricher to build a rich
                // grounded prompt (avoids the L2 hallucinating from a bare title+summary)
                "alert_ids": r.try_get::<_, Vec<i32>>("alert_ids").unwrap_or_default(),
                "finding_ids": r.try_get::<_, Vec<i32>>("finding_ids").unwrap_or_default(),
            })
        }).collect();
        Ok(results)
    }

    async fn mark_forensic_enriched(
        &self,
        id: i32,
        summary: Option<&str>,
        mitre_techniques: Option<&[String]>,
        evidence_citations: Option<&serde_json::Value>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        if let (Some(s), Some(m), Some(e)) = (summary, mitre_techniques, evidence_citations) {
            conn.execute(
                "UPDATE incidents SET \
                    summary = $1, \
                    mitre_techniques = $2, \
                    evidence_citations = $3, \
                    forensic_enriched_at = NOW(), \
                    updated_at = NOW() \
                 WHERE id = $4",
                &[&s, &m.to_vec(), e, &id],
            )
            .await
            .map_err(query_err)?;
        } else {
            conn.execute(
                "UPDATE incidents SET forensic_enriched_at = NOW(), updated_at = NOW() WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(query_err)?;
        }
        Ok(())
    }

    async fn purge_old_archived(&self, days_old: i32) -> Result<(i64, i64), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let days = days_old.max(1);
        // Incidents
        let inc_q = format!(
            "DELETE FROM incidents \
             WHERE status = 'archived' \
               AND updated_at < NOW() - INTERVAL '{} days'",
            days
        );
        let incidents = conn.execute(inc_q.as_str(), &[]).await.map_err(query_err)? as i64;
        // Sigma alerts
        let alert_q = format!(
            "DELETE FROM sigma_alerts \
             WHERE status = 'archived' \
               AND matched_at < NOW() - INTERVAL '{} days'",
            days
        );
        let alerts = conn
            .execute(alert_q.as_str(), &[])
            .await
            .map_err(query_err)? as i64;
        Ok((incidents, alerts))
    }

    async fn add_incident_note(
        &self,
        id: i32,
        text: &str,
        author: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let note = serde_json::json!({
            "text": text,
            "author": author,
            "at": chrono::Utc::now().to_rfc3339(),
        });
        // Append to the notes JSONB array
        conn.execute(
            "UPDATE incidents \
             SET notes = COALESCE(notes, '[]'::jsonb) || $2::jsonb, \
                 updated_at = NOW() \
             WHERE id = $1",
            &[&id, &note],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    // ── Demo data management ──

    async fn count_demo_findings(&self) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT COUNT(*)::bigint FROM findings WHERE metadata->>'demo' = 'true'",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn count_demo_alerts(&self) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT COUNT(*)::bigint FROM sigma_alerts WHERE title LIKE '[DEMO]%'",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn delete_demo_findings(&self) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "WITH deleted AS (DELETE FROM findings WHERE metadata->>'demo' = 'true' RETURNING 1) SELECT COUNT(*)::bigint FROM deleted",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn delete_demo_alerts(&self) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "WITH deleted AS (DELETE FROM sigma_alerts WHERE title LIKE '[DEMO]%' RETURNING 1) SELECT COUNT(*)::bigint FROM deleted",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn delete_demo_logs(&self) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "WITH deleted AS (DELETE FROM logs WHERE data->>'demo' = 'true' RETURNING 1) SELECT COUNT(*)::bigint FROM deleted",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn delete_demo_data_older_than(&self, ttl_minutes: i64) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let interval = format!("{} minutes", ttl_minutes);
        let r1 = conn
            .execute(
                &format!("DELETE FROM findings WHERE metadata->>'demo' = 'true' AND detected_at < NOW() - INTERVAL '{}'", interval),
                &[],
            )
            .await
            .unwrap_or(0);
        let r2 = conn
            .execute(
                &format!("DELETE FROM sigma_alerts WHERE title LIKE '[DEMO]%' AND detected_at < NOW() - INTERVAL '{}'", interval),
                &[],
            )
            .await
            .unwrap_or(0);
        let r3 = conn
            .execute(
                &format!("DELETE FROM logs WHERE data->>'demo' = 'true' AND time < NOW() - INTERVAL '{}'", interval),
                &[],
            )
            .await
            .unwrap_or(0);
        Ok((r1 + r2 + r3) as i64)
    }

    // ── V54__firewall_events ──

    async fn insert_firewall_events(
        &self,
        events: &[crate::db::threatclaw_store::NewFirewallEvent],
    ) -> Result<usize, DatabaseError> {
        if events.is_empty() {
            return Ok(0);
        }
        let conn = self.pool().get().await.map_err(pool_err)?;
        let mut inserted = 0usize;
        for ev in events {
            // INET cast happens server-side via $5/$7::inet — pass strings.
            let n = conn
                .execute(
                    r#"INSERT INTO firewall_events
                       (timestamp, fw_source, interface, action, direction, proto,
                        src_ip, src_port, dst_ip, dst_port, rule_id, raw_meta)
                       VALUES ($1, $2, $3, $4, $5, $6,
                               $7::inet, $8, $9::inet, $10, $11, $12)"#,
                    &[
                        &ev.timestamp,
                        &ev.fw_source,
                        &ev.interface,
                        &ev.action,
                        &ev.direction,
                        &ev.proto,
                        &ev.src_ip,
                        &ev.src_port,
                        &ev.dst_ip,
                        &ev.dst_port,
                        &ev.rule_id,
                        &ev.raw_meta,
                    ],
                )
                .await
                .map_err(query_err)?;
            inserted += n as usize;
        }
        Ok(inserted)
    }

    async fn prune_firewall_events(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let n = conn
            .execute(
                "DELETE FROM firewall_events WHERE timestamp < $1",
                &[&cutoff],
            )
            .await
            .map_err(query_err)?;
        Ok(n as i64)
    }

    async fn firewall_events_for_ip(
        &self,
        ip: &str,
        since: chrono::DateTime<chrono::Utc>,
        limit: i64,
    ) -> Result<Vec<FirewallEventRecord>, DatabaseError> {
        // 2026-06-17 — accept an asset id (textual) in addition to a raw IP.
        // The IE dispatcher passes `dossier.primary_asset`, which for
        // auto-enrolled hosts is something like `syslog-observed-sd-98664`.
        // The previous body cast `$1::inet`, which throws
        // `invalid input syntax for type inet` on any non-IP string —
        // the call site swallowed that as `Err → false`, so the
        // ml-anomaly-perimeter-blocked graph signal `all_fw_blocked` was
        // permanently false for every non-IP asset on the platform.
        // We now resolve the input through the assets table first: if a
        // row matches by id/name/hostname, we use its declared
        // ip_addresses to drive the firewall lookup; otherwise we treat
        // the input as a literal IP. The `inet`-typed comparison only
        // sees values that have already been validated as IPs by the
        // CTE filter.
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                r#"WITH asset_ips AS (
                       SELECT split_part(unnest(ip_addresses), ':', 1) AS ip
                       FROM assets
                       WHERE id = $1 OR name = $1 OR hostname = $1
                          OR LOWER(name) = LOWER($1) OR LOWER(hostname) = LOWER($1)
                   ), candidates AS (
                       SELECT ip FROM asset_ips
                       UNION SELECT $1 WHERE $1 ~ '^[0-9a-fA-F:.]+$'
                   ), valid_ips AS (
                       SELECT ip::inet AS ip
                       FROM candidates
                       WHERE ip ~ '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
                          OR ip ~ ':'
                   )
                   SELECT id, timestamp, fw_source, interface, action, direction, proto,
                          src_ip, src_port, dst_ip, dst_port, rule_id, raw_meta
                   FROM firewall_events
                   WHERE (src_ip IN (SELECT ip FROM valid_ips)
                          OR dst_ip IN (SELECT ip FROM valid_ips))
                     AND timestamp >= $2
                   ORDER BY timestamp DESC
                   LIMIT $3"#,
                &[&ip, &since, &limit],
            )
            .await
            .map_err(query_err)?;
        Ok(rows.into_iter().map(firewall_event_from_row).collect())
    }

    async fn firewall_blocked_aggregates(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::db::threatclaw_store::FirewallBlockedAggregate>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                r#"SELECT
                       host(src_ip)            AS src_ip,
                       COUNT(*)::BIGINT        AS blocked_count,
                       COUNT(DISTINCT dst_ip)::BIGINT  AS distinct_dst_ips,
                       COUNT(DISTINCT dst_port)::BIGINT AS distinct_dst_ports,
                       COUNT(*) FILTER (WHERE dst_port = 22)::BIGINT  AS hits_ssh,
                       COUNT(*) FILTER (WHERE dst_port = 3389)::BIGINT AS hits_rdp,
                       COUNT(*) FILTER (WHERE dst_port = 445)::BIGINT  AS hits_smb,
                       (array_agg(DISTINCT host(dst_ip)))[1:5] AS sample_dst_ips
                   FROM firewall_events
                   WHERE action = 'block'
                     AND src_ip IS NOT NULL
                     AND timestamp >= $1
                   GROUP BY src_ip
                   HAVING COUNT(*) >= 5
                   ORDER BY blocked_count DESC
                   LIMIT 200"#,
                &[&since],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| crate::db::threatclaw_store::FirewallBlockedAggregate {
                src_ip: r.get(0),
                blocked_count: r.get(1),
                distinct_dst_ips: r.get(2),
                distinct_dst_ports: r.get(3),
                hits_ssh: r.get(4),
                hits_rdp: r.get(5),
                hits_smb: r.get(6),
                sample_dst_ips: r.try_get::<_, Vec<String>>(7).unwrap_or_default(),
            })
            .collect())
    }

    // ── Phase G1b — task_queue + graph_executions (V62) ──

    async fn enqueue_task(
        &self,
        task: &crate::agent::task_queue::NewTask,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let kind_str = task.kind.as_str();
        let row = conn
            .query_one(
                "INSERT INTO task_queue (kind, graph_run_id, payload, priority, max_attempts) \
                 VALUES ($1, $2, $3, $4, $5) RETURNING id",
                &[
                    &kind_str,
                    &task.graph_run_id,
                    &task.payload,
                    &task.priority,
                    &task.max_attempts,
                ],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn claim_next_task(
        &self,
        kind: crate::agent::task_queue::TaskKind,
        worker_id: &str,
    ) -> Result<Option<crate::agent::task_queue::Task>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let kind_str = kind.as_str();
        // Atomic claim : SELECT FOR UPDATE SKIP LOCKED garantit que deux
        // workers n'attrapent jamais la même row, et UPDATE flips status
        // + bumpe attempts dans la même tx.
        let row = conn
            .query_opt(
                "WITH claimed AS ( \
                    SELECT id FROM task_queue \
                    WHERE status = 'queued' AND kind = $1 \
                    ORDER BY priority ASC, created_at ASC \
                    LIMIT 1 \
                    FOR UPDATE SKIP LOCKED \
                 ) \
                 UPDATE task_queue q \
                 SET status = 'running', \
                     started_at = now(), \
                     worker_id = $2, \
                     attempts = q.attempts + 1 \
                 FROM claimed c \
                 WHERE q.id = c.id \
                 RETURNING q.id, q.kind, q.graph_run_id, q.payload, q.status, \
                           q.priority, q.attempts, q.max_attempts, q.created_at, \
                           q.started_at, q.completed_at, q.worker_id, q.result, q.error",
                &[&kind_str, &worker_id],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(parse_task_row))
    }

    async fn complete_task(
        &self,
        id: i64,
        result: &serde_json::Value,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE task_queue \
             SET status = 'done', completed_at = now(), result = $2 \
             WHERE id = $1",
            &[&id, &result],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn fail_task(&self, id: i64, error: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE task_queue \
             SET status = 'error', completed_at = now(), error = $2 \
             WHERE id = $1",
            &[&id, &error],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn recover_stale_tasks(&self, older_than_secs: i64) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Postgres `make_interval(secs)` expects a double precision
        // argument. Passing an integer triggers tokio-postgres
        // serialization errors — keep the rust-side type as f64.
        let secs: f64 = older_than_secs.max(0) as f64;
        let row = conn
            .query_one(
                "WITH recovered AS ( \
                    UPDATE task_queue \
                    SET status = 'queued', worker_id = NULL, started_at = NULL \
                    WHERE status = 'running' \
                      AND started_at < now() - make_interval(secs => $1) \
                    RETURNING 1 \
                 ) SELECT COUNT(*)::bigint FROM recovered",
                &[&secs],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn count_tasks_by_status(
        &self,
    ) -> Result<crate::agent::task_queue::QueueDepths, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT status, COUNT(*)::bigint FROM task_queue \
                 WHERE status IN ('queued', 'running') \
                 GROUP BY status",
                &[],
            )
            .await
            .map_err(query_err)?;
        let mut depths = crate::agent::task_queue::QueueDepths::default();
        for r in rows {
            let status: String = r.get(0);
            let count: i64 = r.get(1);
            match status.as_str() {
                "queued" => depths.queued = count,
                "running" => depths.running = count,
                _ => {}
            }
        }
        Ok(depths)
    }

    async fn create_graph_execution(
        &self,
        exec: &crate::agent::task_queue::NewGraphExecution,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "INSERT INTO graph_executions (graph_name, sigma_alert_id, asset_id) \
                 VALUES ($1, $2, $3) RETURNING id",
                &[&exec.graph_name, &exec.sigma_alert_id, &exec.asset_id],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn insert_attack_paths(
        &self,
        paths: &[crate::agent::path_risk::AttackPath],
    ) -> Result<i64, DatabaseError> {
        if paths.is_empty() {
            return Ok(0);
        }
        let conn = self.pool().get().await.map_err(pool_err)?;
        let mut count = 0i64;
        for p in paths {
            let hops_i16: i16 = p.hops;
            let epss = p.epss_max;
            conn.execute(
                "INSERT INTO attack_paths_predicted \
                 (run_id, src_asset, dst_asset, path_assets, hops, score, \
                  epss_max, has_kev, cves_chain, mitre_techniques, explanation) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                &[
                    &p.run_id,
                    &p.src_asset,
                    &p.dst_asset,
                    &p.path_assets,
                    &hops_i16,
                    &p.score,
                    &epss,
                    &p.has_kev,
                    &p.cves_chain,
                    &p.mitre_techniques,
                    &p.explanation,
                ],
            )
            .await
            .map_err(query_err)?;
            count += 1;
        }
        Ok(count)
    }

    async fn latest_attack_paths(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::agent::path_risk::AttackPath>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Le run le plus récent (= computed_at max) puis Top-N par score.
        let rows = conn
            .query(
                "WITH last_run AS ( \
                    SELECT run_id FROM attack_paths_predicted \
                    ORDER BY computed_at DESC LIMIT 1 \
                 ) \
                 SELECT id, run_id, src_asset, dst_asset, path_assets, hops, \
                        score, epss_max, has_kev, cves_chain, mitre_techniques, \
                        explanation, computed_at \
                 FROM attack_paths_predicted \
                 WHERE run_id = (SELECT run_id FROM last_run) \
                 ORDER BY score DESC LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| crate::agent::path_risk::AttackPath {
                run_id: r.get(1),
                src_asset: r.get(2),
                dst_asset: r.get(3),
                path_assets: r.get(4),
                hops: r.get(5),
                score: r.get(6),
                epss_max: r.try_get(7).ok(),
                has_kev: r.get(8),
                cves_chain: r.try_get(9).unwrap_or_default(),
                mitre_techniques: r.try_get(10).unwrap_or_default(),
                explanation: r.try_get(11).ok(),
                computed_at: r.get(12),
            })
            .collect())
    }

    async fn list_graph_executions(
        &self,
        filter: &crate::db::threatclaw_store::GraphExecutionsFilter,
    ) -> Result<Vec<crate::agent::task_queue::GraphExecutionRecord>, DatabaseError> {
        use crate::agent::task_queue::{GraphExecutionRecord, GraphExecutionStatus};

        let conn = self.pool().get().await.map_err(pool_err)?;

        // Build dynamic WHERE — petit nombre de paramètres, on accumule
        // un Vec<&(dyn ToSql + Sync)> et on construit la SQL en
        // remplaçant $N au fur et à mesure.
        let mut sql = String::from(
            "SELECT id, graph_name, sigma_alert_id, asset_id, status, archive_reason, \
                    incident_id, trace, started_at, finished_at, duration_ms, error \
             FROM graph_executions WHERE 1=1",
        );
        let mut idx = 1;
        let limit = filter.limit.clamp(1, 500);

        let status_owned: Option<String> = filter.status.clone();
        let asset_owned: Option<String> = filter.asset_id.clone();
        let reason_owned: Option<String> = filter.archive_reason.clone();
        // tokio-postgres ne sérialise pas un String en `interval` malgré
        // le cast `::interval` côté SQL. On passe les heures en i32 et on
        // construit l'interval avec `make_interval(hours => $N)` qui
        // attend bien un int4.
        let since_hours_owned: Option<i32> = filter
            .since_hours
            .map(|h| h.clamp(0, i32::MAX as i64) as i32);

        if status_owned.is_some() {
            sql.push_str(&format!(" AND status = ${}", idx));
            idx += 1;
        }
        if asset_owned.is_some() {
            sql.push_str(&format!(" AND asset_id = ${}", idx));
            idx += 1;
        }
        if reason_owned.is_some() {
            sql.push_str(&format!(" AND archive_reason = ${}", idx));
            idx += 1;
        }
        if since_hours_owned.is_some() {
            sql.push_str(&format!(
                " AND started_at > now() - make_interval(hours => ${})",
                idx
            ));
            idx += 1;
        }
        sql.push_str(&format!(" ORDER BY started_at DESC LIMIT ${}", idx));

        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
        if let Some(s) = status_owned.as_ref() {
            params.push(s);
        }
        if let Some(a) = asset_owned.as_ref() {
            params.push(a);
        }
        if let Some(r) = reason_owned.as_ref() {
            params.push(r);
        }
        if let Some(i) = since_hours_owned.as_ref() {
            params.push(i);
        }
        params.push(&limit);

        let rows = conn
            .query(sql.as_str(), &params[..])
            .await
            .map_err(query_err)?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let status_str: String = r.get(4);
                let status = GraphExecutionStatus::from_str(&status_str)
                    .unwrap_or(GraphExecutionStatus::Failed);
                GraphExecutionRecord {
                    id: r.get(0),
                    graph_name: r.get(1),
                    sigma_alert_id: r.try_get(2).ok(),
                    asset_id: r.try_get(3).ok(),
                    status,
                    archive_reason: r.try_get(5).ok(),
                    incident_id: r.try_get(6).ok(),
                    trace: r.try_get(7).ok(),
                    started_at: r.get(8),
                    finished_at: r.try_get(9).ok(),
                    duration_ms: r.try_get(10).ok(),
                    error: r.try_get(11).ok(),
                }
            })
            .collect())
    }

    async fn latest_choke_points(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::db::threatclaw_store::ChokePoint>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        // Du dernier run, on UNNEST les path_assets en excluant le
        // src_asset (pas un choke point — c'est l'entrée externe) et
        // le dst_asset (la cible elle-même), puis on agrège.
        let rows = conn
            .query(
                "WITH last_run AS ( \
                    SELECT run_id FROM attack_paths_predicted \
                    ORDER BY computed_at DESC LIMIT 1 \
                 ), \
                 hops AS ( \
                    SELECT \
                      unnest(p.path_assets) AS asset, \
                      p.score, \
                      p.dst_asset \
                    FROM attack_paths_predicted p \
                    WHERE p.run_id = (SELECT run_id FROM last_run) \
                 ), \
                 mid_only AS ( \
                    SELECT h.asset, h.score, h.dst_asset \
                    FROM hops h \
                    JOIN attack_paths_predicted p ON p.run_id = (SELECT run_id FROM last_run) \
                    WHERE h.asset != p.src_asset AND h.asset != p.dst_asset \
                 ) \
                 SELECT \
                    asset, \
                    COUNT(*)::bigint AS paths_through, \
                    COALESCE(SUM(score), 0)::double precision AS weighted_score, \
                    array_agg(DISTINCT dst_asset) FILTER (WHERE dst_asset IS NOT NULL) AS top_targets \
                 FROM mid_only \
                 GROUP BY asset \
                 ORDER BY weighted_score DESC \
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let mut targets: Vec<String> = r.try_get(3).unwrap_or_default();
                targets.truncate(3);
                crate::db::threatclaw_store::ChokePoint {
                    asset: r.get(0),
                    paths_through: r.get(1),
                    weighted_score: r.get(2),
                    top_targets: targets,
                }
            })
            .collect())
    }

    // ── Phase G4b — incident_ai_analyses (V69) ──

    async fn insert_ai_analysis(
        &self,
        analysis: &crate::db::threatclaw_store::NewAiAnalysis,
    ) -> Result<i32, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "INSERT INTO incident_ai_analyses \
                 (incident_id, source, confidence, summary, skills_used, mitre_added, raw_output) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
                &[
                    &analysis.incident_id,
                    &analysis.source,
                    &analysis.confidence,
                    &analysis.summary,
                    &analysis.skills_used,
                    &analysis.mitre_added,
                    &analysis.raw_output,
                ],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get::<_, i32>("id"))
    }

    async fn get_ai_analyses(
        &self,
        incident_id: i32,
    ) -> Result<Vec<crate::db::threatclaw_store::AiAnalysis>, DatabaseError> {
        use crate::db::threatclaw_store::AiAnalysis;
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, incident_id, source, confidence, summary, \
                 skills_used, mitre_added, raw_output, created_at \
                 FROM incident_ai_analyses \
                 WHERE incident_id = $1 ORDER BY created_at DESC",
                &[&incident_id],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| AiAnalysis {
                id: r.get("id"),
                incident_id: r.get("incident_id"),
                source: r.get("source"),
                confidence: r.get("confidence"),
                summary: r.get("summary"),
                skills_used: r
                    .get::<_, Option<Vec<String>>>("skills_used")
                    .unwrap_or_default(),
                mitre_added: r
                    .get::<_, Option<Vec<String>>>("mitre_added")
                    .unwrap_or_default(),
                raw_output: r.get("raw_output"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    // ── Phase 9o — incident_investigation_steps (V72) ──

    async fn append_investigation_step(
        &self,
        step: &crate::db::threatclaw_store::NewInvestigationStep,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let kind = step.kind.as_str();
        let status = step.status.as_str();
        let row = conn
            .query_one(
                "INSERT INTO incident_investigation_steps \
                 (incident_id, kind, skill_id, summary, payload, duration_ms, status) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
                &[
                    &step.incident_id,
                    &kind,
                    &step.skill_id,
                    &step.summary,
                    &step.payload,
                    &step.duration_ms,
                    &status,
                ],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get::<_, i64>("id"))
    }

    async fn list_investigation_steps(
        &self,
        incident_id: i32,
    ) -> Result<Vec<crate::db::threatclaw_store::InvestigationStepRecord>, DatabaseError> {
        use crate::db::threatclaw_store::{InvestigationStepRecord, StepKind, StepStatus};
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, incident_id, kind, skill_id, summary, payload, \
                 duration_ms, status, created_at \
                 FROM incident_investigation_steps \
                 WHERE incident_id = $1 \
                 ORDER BY created_at ASC, id ASC",
                &[&incident_id],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let kind_str: String = r.get("kind");
                let status_str: String = r.get("status");
                InvestigationStepRecord {
                    id: r.get("id"),
                    incident_id: r.get("incident_id"),
                    // serde_json indirection lets us reuse the StepKind /
                    // StepStatus #[serde(rename_all)] mapping rather than
                    // duplicate it here. `Other` covers any future db
                    // value the binary doesn't know yet.
                    kind: serde_json::from_value(serde_json::Value::String(kind_str))
                        .unwrap_or(StepKind::Other),
                    skill_id: r.get("skill_id"),
                    summary: r.get("summary"),
                    payload: r.get("payload"),
                    duration_ms: r.get("duration_ms"),
                    status: serde_json::from_value(serde_json::Value::String(status_str))
                        .unwrap_or(StepStatus::Other),
                    created_at: r.get("created_at"),
                }
            })
            .collect())
    }

    async fn get_sigma_alerts_by_ids(
        &self,
        ids: &[i64],
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, title, level, hostname, username, host(source_ip)::text, \
                 matched_at, matched_fields \
                 FROM sigma_alerts WHERE id = ANY($1) ORDER BY matched_at ASC",
                &[&ids],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let matched_at: chrono::DateTime<chrono::Utc> = r.get(6);
                serde_json::json!({
                    "kind": "alert",
                    "id": r.get::<_, i64>(0),
                    "title": r.get::<_, String>(1),
                    "level": r.get::<_, String>(2),
                    "hostname": r.get::<_, Option<String>>(3),
                    "username": r.get::<_, Option<String>>(4),
                    "source_ip": r.get::<_, Option<String>>(5),
                    "ts": matched_at.to_rfc3339(),
                    "matched_fields": r.try_get::<_, serde_json::Value>(7).unwrap_or(serde_json::json!({})),
                })
            })
            .collect())
    }

    async fn get_findings_by_ids(
        &self,
        ids: &[i64],
    ) -> Result<Vec<serde_json::Value>, DatabaseError> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                "SELECT id, title, severity, asset, description, detected_at, metadata \
                 FROM findings WHERE id = ANY($1) ORDER BY detected_at ASC",
                &[&ids],
            )
            .await
            .map_err(query_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                let detected_at: chrono::DateTime<chrono::Utc> = r.get(5);
                serde_json::json!({
                    "kind": "finding",
                    "id": r.get::<_, i64>(0),
                    "title": r.get::<_, String>(1),
                    "level": r.get::<_, String>(2),
                    "hostname": r.get::<_, Option<String>>(3),
                    "username": Option::<String>::None,
                    "source_ip": Option::<String>::None,
                    "ts": detected_at.to_rfc3339(),
                    "matched_fields": r.try_get::<_, serde_json::Value>(6).unwrap_or(serde_json::json!({})),
                })
            })
            .collect())
    }

    async fn finalize_graph_execution(
        &self,
        id: i64,
        status: crate::agent::task_queue::GraphExecutionStatus,
        archive_reason: Option<&str>,
        incident_id: Option<i32>,
        trace: &serde_json::Value,
        error: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let status_str = status.as_str();
        conn.execute(
            "UPDATE graph_executions \
             SET status = $2, \
                 archive_reason = $3, \
                 incident_id = $4, \
                 trace = $5, \
                 error = $6, \
                 finished_at = now(), \
                 duration_ms = (EXTRACT(EPOCH FROM (now() - started_at)) * 1000)::int \
             WHERE id = $1",
            &[
                &id,
                &status_str,
                &archive_reason,
                &incident_id,
                trace,
                &error,
            ],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }
}

// ── Helper: parse task_queue row ──

fn parse_task_row(r: tokio_postgres::Row) -> crate::agent::task_queue::Task {
    use crate::agent::task_queue::{Task, TaskKind, TaskStatus};
    let kind_str: String = r.get(1);
    let status_str: String = r.get(4);
    Task {
        id: r.get(0),
        kind: TaskKind::from_str(&kind_str).unwrap_or(TaskKind::SkillCall),
        graph_run_id: r.get(2),
        payload: r.get(3),
        status: TaskStatus::from_str(&status_str).unwrap_or(TaskStatus::Queued),
        priority: r.get(5),
        attempts: r.get(6),
        max_attempts: r.get(7),
        created_at: r.get(8),
        started_at: r.get(9),
        completed_at: r.get(10),
        worker_id: r.get(11),
        result: r.get(12),
        error: r.get(13),
    }
}

// ── Helper: parse asset row ──

fn parse_asset_row(r: &tokio_postgres::Row) -> AssetRecord {
    AssetRecord {
        id: r.get("id"),
        name: r.get("name"),
        category: r.get("category"),
        subcategory: r.try_get("subcategory").ok(),
        role: r.try_get("role").ok(),
        criticality: r.get("criticality"),
        ip_addresses: r
            .try_get::<_, Vec<String>>("ip_addresses")
            .unwrap_or_default(),
        mac_address: r.try_get("mac_address").ok(),
        hostname: r.try_get("hostname").ok(),
        fqdn: r.try_get("fqdn").ok(),
        url: r.try_get("url").ok(),
        os: r.try_get("os").ok(),
        os_confidence: r.try_get::<_, f32>("os_confidence").unwrap_or(0.0),
        mac_vendor: r.try_get("mac_vendor").ok(),
        services: r
            .try_get::<_, serde_json::Value>("services")
            .unwrap_or(serde_json::json!([])),
        source: r.get("source"),
        first_seen: r
            .try_get::<_, chrono::DateTime<chrono::Utc>>("first_seen")
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
        last_seen: r
            .try_get::<_, chrono::DateTime<chrono::Utc>>("last_seen")
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
        owner: r.try_get("owner").ok(),
        location: r.try_get("location").ok(),
        tags: r.try_get::<_, Vec<String>>("tags").unwrap_or_default(),
        notes: r.try_get("notes").ok(),
        classification_method: r
            .try_get::<_, String>("classification_method")
            .unwrap_or_else(|_| "manual".into()),
        classification_confidence: r
            .try_get::<_, f32>("classification_confidence")
            .unwrap_or(1.0),
        status: r.get("status"),
        reenrol_blocked: r.try_get("reenrol_blocked").unwrap_or(false),
        sources: r.try_get::<_, Vec<String>>("sources").unwrap_or_default(),
        software: r
            .try_get::<_, serde_json::Value>("software")
            .unwrap_or(serde_json::json!([])),
        user_modified: r
            .try_get::<_, Vec<String>>("user_modified")
            .unwrap_or_default(),
        // V67 — surface the persistence bucket + distinct-days counter
        // to the dashboard so /assets can filter by billable state.
        // Defaults match the migration: brand-new rows are transient,
        // billable_status from V66 is 'discovered'.
        inventory_status: r
            .try_get::<_, String>("inventory_status")
            .unwrap_or_else(|_| "observed_transient".into()),
        distinct_days_seen_30d: r.try_get::<_, i32>("distinct_days_seen_30d").unwrap_or(0),
        billable_status: r
            .try_get::<_, String>("billable_status")
            .unwrap_or_else(|_| "discovered".into()),
        demo: r.try_get::<_, bool>("demo").unwrap_or(false),
        // V68 — exclusion toggle (billing + monitoring at once).
        excluded: r.try_get::<_, bool>("excluded").unwrap_or(false),
        exclusion_reason: r
            .try_get::<_, String>("exclusion_reason")
            .unwrap_or_default(),
        exclusion_until: r
            .try_get::<_, chrono::DateTime<chrono::Utc>>("exclusion_until")
            .ok()
            .map(|dt| dt.to_rfc3339()),
        exclusion_by: r.try_get::<_, String>("exclusion_by").unwrap_or_default(),
    }
}
