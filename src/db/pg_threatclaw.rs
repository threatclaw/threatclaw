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
        let rows = match (hostname, tag) {
            (Some(h), Some(t)) => {
                conn.query(
                    &format!("SELECT id, tag, time::text, hostname, data FROM logs WHERE time >= NOW() - {} AND hostname = $1 AND tag = $2 ORDER BY time DESC LIMIT {}", interval_clause, limit),
                    &[&h, &t],
                ).await.map_err(query_err)?
            }
            (Some(h), None) => {
                conn.query(
                    &format!("SELECT id, tag, time::text, hostname, data FROM logs WHERE time >= NOW() - {} AND hostname = $1 ORDER BY time DESC LIMIT {}", interval_clause, limit),
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
                conn.query(
                    &format!("SELECT id, tag, time::text, hostname, data FROM logs WHERE time >= NOW() - {} ORDER BY time DESC LIMIT {}", interval_clause, limit),
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
                hostname: r.try_get(3).ok(),
                data: r.try_get::<_, serde_json::Value>(4).unwrap_or_default(),
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
        let parsed_time = chrono::DateTime::parse_from_rfc3339(time)
            .map(|d| d.with_timezone(&chrono::Utc))
            .map_err(|e| DatabaseError::Query(format!("invalid timestamp: {}", e)))?;
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

    async fn list_sigma_rules_enabled(&self) -> Result<Vec<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn.query(
            "SELECT id, title, level, logsource_category, logsource_product, logsource_service, tags, detection_json FROM sigma_rules WHERE enabled = true",
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
            }));
        }
        Ok(results)
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
        let sql = "SELECT * FROM assets WHERE ($1::text IS NULL OR category = $1) AND ($2::text IS NULL OR status = $2) ORDER BY criticality DESC, last_seen DESC LIMIT $3 OFFSET $4";
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
            "SELECT COUNT(*)::bigint FROM assets WHERE ($1::text IS NULL OR category = $1) AND ($2::text IS NULL OR status = $2)",
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
        let ips: Vec<&str> = a.ip_addresses.iter().map(|s| s.as_str()).collect();
        let tags: Vec<&str> = a.tags.iter().map(|s| s.as_str()).collect();
        let source_arr = vec![a.source.as_str()];
        conn.execute(
            r#"INSERT INTO assets (id, name, category, subcategory, role, criticality,
                ip_addresses, mac_address, hostname, fqdn, url, os, mac_vendor,
                services, source, sources, owner, location, tags, last_seen)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, NOW())
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
                updated_at = NOW()"#,
            &[&a.id, &a.name, &a.category, &a.subcategory, &a.role, &a.criticality,
              &ips, &a.mac_address, &a.hostname, &a.fqdn, &a.url, &a.os, &a.mac_vendor,
              &a.services, &a.source, &source_arr, &a.owner, &a.location, &tags],
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
        let lower = hostname.to_lowercase();
        let rows = conn.query(
            "SELECT * FROM assets WHERE LOWER(hostname) = $1 OR LOWER(name) = $1 ORDER BY CASE WHEN LOWER(hostname) = $1 THEN 0 ELSE 1 END LIMIT 1",
            &[&lower],
        ).await.map_err(query_err)?;
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
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            r#"UPDATE assets SET software = (
                SELECT COALESCE(jsonb_agg(DISTINCT elem), '[]'::jsonb)
                FROM (
                    SELECT elem FROM jsonb_array_elements(COALESCE(assets.software, '[]'::jsonb)) AS elem
                    UNION
                    SELECT elem FROM jsonb_array_elements($2::jsonb) AS elem
                ) sub
            ), updated_at = NOW() WHERE id = $1"#,
            &[&id, software],
        ).await.map_err(query_err)?;
        Ok(())
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
        let rows = conn
            .query(
                "SELECT asset_id, score, COALESCE(reason, '') FROM ml_scores",
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
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let conf_f32 = confidence as f32;
        conn.execute(
            "UPDATE incidents SET verdict = $2, confidence = $3, summary = $4, mitre_techniques = $5, proposed_actions = $6, investigation_log = $7, evidence_citations = $8, status = CASE WHEN $2 = 'false_positive' THEN 'closed' WHEN $2 = 'error' THEN 'error' WHEN $2 = 'confirmed' THEN 'open' WHEN $2 = 'informational' THEN 'closed' ELSE 'open' END, updated_at = NOW() WHERE id = $1",
            &[&id, &verdict, &conf_f32, &summary, &mitre, proposed_actions, investigation_log, evidence_citations],
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
                    "SELECT id, asset, title, summary, verdict, confidence, severity, alert_count, status, hitl_status, hitl_response, proposed_actions, mitre_techniques, notes, created_at, updated_at, resolved_at FROM incidents WHERE status != 'archived' ORDER BY created_at DESC LIMIT {} OFFSET {}",
                    limit, offset
                );
                conn.query(&q, &[]).await.map_err(query_err)?
            }
            Some("include_archived") => {
                let q = format!(
                    "SELECT id, asset, title, summary, verdict, confidence, severity, alert_count, status, hitl_status, hitl_response, proposed_actions, mitre_techniques, notes, created_at, updated_at, resolved_at FROM incidents ORDER BY created_at DESC LIMIT {} OFFSET {}",
                    limit, offset
                );
                conn.query(&q, &[]).await.map_err(query_err)?
            }
            Some(s) => {
                let q = format!(
                    "SELECT id, asset, title, summary, verdict, confidence, severity, alert_count, status, hitl_status, hitl_response, proposed_actions, mitre_techniques, notes, created_at, updated_at, resolved_at FROM incidents WHERE status = $1 ORDER BY created_at DESC LIMIT {} OFFSET {}",
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

    async fn get_incident(&self, id: i32) -> Result<Option<serde_json::Value>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn.query_opt(
            "SELECT id, asset, title, summary, verdict, confidence, severity, alert_ids, finding_ids, alert_count, investigation_log, mitre_techniques, proposed_actions, executed_actions, status, hitl_status, hitl_nonce, hitl_responded_at, hitl_responded_by, hitl_response, notified_channels, notes, evidence_citations, blast_radius_snapshot, blast_radius_score, blast_radius_computed_at, created_at, updated_at, resolved_at FROM incidents WHERE id = $1",
            &[&id],
        ).await.map_err(query_err)?;
        Ok(row.map(|r| serde_json::json!({
            "id": r.get::<_, i32>("id"),
            "asset": r.get::<_, String>("asset"),
            "title": r.get::<_, String>("title"),
            "summary": r.get::<_, Option<String>>("summary"),
            "verdict": r.get::<_, String>("verdict"),
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
            "blast_radius_snapshot": r.try_get::<_, Option<serde_json::Value>>("blast_radius_snapshot").unwrap_or(None),
            "blast_radius_score": r.get::<_, Option<i16>>("blast_radius_score"),
            "blast_radius_computed_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("blast_radius_computed_at").map(|t| t.to_rfc3339()),
            "created_at": r.get::<_, chrono::DateTime<chrono::Utc>>("created_at").to_rfc3339(),
            "updated_at": r.get::<_, chrono::DateTime<chrono::Utc>>("updated_at").to_rfc3339(),
            "resolved_at": r.get::<_, Option<chrono::DateTime<chrono::Utc>>>("resolved_at").map(|t| t.to_rfc3339()),
        })))
    }

    async fn find_open_incident_for_asset(
        &self,
        asset: &str,
    ) -> Result<Option<i32>, DatabaseError> {
        // Only match incidents from the last 4 hours to allow "fresh" recurring
        // incidents to merge, but don't resurrect old ones that were never closed.
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                "SELECT id FROM incidents \
             WHERE asset = $1 \
               AND status IN ('open', 'investigating') \
               AND updated_at > NOW() - INTERVAL '4 hours' \
             ORDER BY created_at DESC LIMIT 1",
                &[&asset],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(|r| r.get("id")))
    }

    async fn touch_incident(&self, id: i32, alert_count_delta: i32) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "UPDATE incidents SET alert_count = alert_count + $2, updated_at = NOW() WHERE id = $1",
            &[&id, &alert_count_delta],
        )
        .await
        .map_err(query_err)?;
        Ok(())
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
        sources: r.try_get::<_, Vec<String>>("sources").unwrap_or_default(),
        software: r
            .try_get::<_, serde_json::Value>("software")
            .unwrap_or(serde_json::json!([])),
        user_modified: r
            .try_get::<_, Vec<String>>("user_modified")
            .unwrap_or_default(),
    }
}
