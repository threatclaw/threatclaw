//! PostgreSQL implementation of ThreatClawStore.

use async_trait::async_trait;

use super::postgres::PgBackend;
use super::threatclaw_store::*;
use crate::error::DatabaseError;

fn pool_err(e: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Pool(e.to_string())
}

fn query_err(e: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Query(e.to_string())
}

#[async_trait]
impl ThreatClawStore for PgBackend {
    async fn insert_finding(&self, f: &NewFinding) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let default_meta = serde_json::json!({});
        let meta = f.metadata.as_ref().unwrap_or(&default_meta);
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
    ) -> Result<Vec<FindingRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                r#"SELECT id, skill_id, title, description, severity, status, category, asset, source,
                          metadata, detected_at::text, resolved_at::text, resolved_by
                   FROM findings
                   WHERE ($1::text IS NULL OR severity = $1)
                     AND ($2::text IS NULL OR status = $2)
                     AND ($3::text IS NULL OR skill_id = $3)
                   ORDER BY detected_at DESC
                   LIMIT $4"#,
                &[&severity, &status, &skill_id, &limit],
            )
            .await
            .map_err(query_err)?;

        Ok(rows.iter().map(|r| FindingRecord {
            id: r.get(0), skill_id: r.get(1), title: r.get(2), description: r.get(3),
            severity: r.get(4), status: r.get(5), category: r.get(6), asset: r.get(7),
            source: r.get(8), metadata: r.get(9), detected_at: r.get(10),
            resolved_at: r.get(11), resolved_by: r.get(12),
        }).collect())
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
            id: r.get(0), skill_id: r.get(1), title: r.get(2), description: r.get(3),
            severity: r.get(4), status: r.get(5), category: r.get(6), asset: r.get(7),
            source: r.get(8), metadata: r.get(9), detected_at: r.get(10),
            resolved_at: r.get(11), resolved_by: r.get(12),
        }))
    }

    async fn update_finding_status(
        &self, id: i64, status: &str, resolved_by: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let resolved: Option<&str> = resolved_by;
        conn.execute(
            r#"UPDATE findings SET status = $1, resolved_by = $2,
                      resolved_at = CASE WHEN $1 = 'resolved' THEN NOW() ELSE resolved_at END
               WHERE id = $3"#,
            &[&status, &resolved, &id],
        ).await.map_err(query_err)?;
        Ok(())
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
            ).await.map_err(query_err)?;
        Ok(rows.iter().map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1))).collect())
    }

    async fn list_alerts(
        &self, level: Option<&str>, status: Option<&str>, limit: i64,
    ) -> Result<Vec<AlertRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                r#"SELECT id, rule_id, level, title, status, hostname,
                          host(source_ip), username, matched_at::text, matched_fields
                   FROM sigma_alerts
                   WHERE ($1::text IS NULL OR level = $1)
                     AND ($2::text IS NULL OR status = $2)
                   ORDER BY matched_at DESC
                   LIMIT $3"#,
                &[&level, &status, &limit],
            ).await.map_err(query_err)?;
        Ok(rows.iter().map(|r| AlertRecord {
            id: r.get(0), rule_id: r.get(1), level: r.get(2), title: r.get(3),
            status: r.get(4), hostname: r.get(5), source_ip: r.get(6),
            username: r.get(7), matched_at: r.get(8), matched_fields: r.get(9),
        }).collect())
    }

    async fn get_alert(&self, id: i64) -> Result<Option<AlertRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                r#"SELECT id, rule_id, level, title, status, hostname,
                          host(source_ip), username, matched_at::text, matched_fields
                   FROM sigma_alerts WHERE id = $1"#,
                &[&id],
            ).await.map_err(query_err)?;
        Ok(row.map(|r| AlertRecord {
            id: r.get(0), rule_id: r.get(1), level: r.get(2), title: r.get(3),
            status: r.get(4), hostname: r.get(5), source_ip: r.get(6),
            username: r.get(7), matched_at: r.get(8), matched_fields: r.get(9),
        }))
    }

    async fn update_alert_status(
        &self, id: i64, status: &str, notes: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            r#"UPDATE sigma_alerts SET status = $1, analyst_notes = COALESCE($2, analyst_notes),
                      resolved_at = CASE WHEN $1 = 'resolved' THEN NOW() ELSE resolved_at END
               WHERE id = $3"#,
            &[&status, &notes, &id],
        ).await.map_err(query_err)?;
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
            ).await.map_err(query_err)?;
        Ok(rows.iter().map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1))).collect())
    }

    async fn get_skill_config(&self, skill_id: &str) -> Result<Vec<SkillConfigRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query("SELECT skill_id, key, value FROM skill_configs WHERE skill_id = $1 ORDER BY key", &[&skill_id])
            .await.map_err(query_err)?;
        Ok(rows.iter().map(|r| SkillConfigRecord {
            skill_id: r.get(0), key: r.get(1), value: r.get(2),
        }).collect())
    }

    async fn set_skill_config(&self, skill_id: &str, key: &str, value: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            r#"INSERT INTO skill_configs (skill_id, key, value, updated_at)
               VALUES ($1, $2, $3, NOW())
               ON CONFLICT (skill_id, key) DO UPDATE SET value = $3, updated_at = NOW()"#,
            &[&skill_id, &key, &value],
        ).await.map_err(query_err)?;
        Ok(())
    }

    async fn delete_skill_config(&self, skill_id: &str, key: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute("DELETE FROM skill_configs WHERE skill_id = $1 AND key = $2", &[&skill_id, &key])
            .await.map_err(query_err)?;
        Ok(())
    }

    async fn record_metric(&self, name: &str, value: f64, labels: &serde_json::Value) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute(
            "INSERT INTO metrics_snapshots (metric_name, metric_value, labels) VALUES ($1, $2, $3)",
            &[&name, &value, labels],
        ).await.map_err(query_err)?;
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

        let rules: Vec<serde_json::Value> = rows.iter().map(|r| {
            serde_json::json!({
                "id": r.get::<_, uuid::Uuid>(0).to_string(),
                "label": r.get::<_, String>(1),
                "pattern": r.get::<_, String>(2),
                "token_prefix": r.get::<_, String>(3),
                "capture_group": r.get::<_, i32>(4),
                "enabled": r.get::<_, bool>(5),
            })
        }).collect();

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
        conn
            .execute("DELETE FROM anonymizer_rules WHERE id = $1", &[&uuid])
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
        let interval = format!("{} minutes", minutes_back);

        // Build query with static params to avoid Send issues with dynamic Box<dyn>
        let rows = match (hostname, tag) {
            (Some(h), Some(t)) => {
                conn.query(
                    &format!("SELECT id, tag, time::text, hostname, data FROM logs WHERE time >= NOW() - $1::interval AND hostname = $2 AND tag = $3 ORDER BY time DESC LIMIT {}", limit),
                    &[&interval, &h, &t],
                ).await.map_err(query_err)?
            }
            (Some(h), None) => {
                conn.query(
                    &format!("SELECT id, tag, time::text, hostname, data FROM logs WHERE time >= NOW() - $1::interval AND hostname = $2 ORDER BY time DESC LIMIT {}", limit),
                    &[&interval, &h],
                ).await.map_err(query_err)?
            }
            (None, Some(t)) => {
                conn.query(
                    &format!("SELECT id, tag, time::text, hostname, data FROM logs WHERE time >= NOW() - $1::interval AND tag = $2 ORDER BY time DESC LIMIT {}", limit),
                    &[&interval, &t],
                ).await.map_err(query_err)?
            }
            (None, None) => {
                conn.query(
                    &format!("SELECT id, tag, time::text, hostname, data FROM logs WHERE time >= NOW() - $1::interval ORDER BY time DESC LIMIT {}", limit),
                    &[&interval],
                ).await.map_err(query_err)?
            }
        };

        Ok(rows.iter().map(|r| LogRecord {
            id: r.get(0),
            tag: r.try_get(1).ok(),
            time: r.get(2),
            hostname: r.try_get(3).ok(),
            data: r.try_get::<_, serde_json::Value>(4).unwrap_or_default(),
        }).collect())
    }

    async fn insert_log(
        &self,
        tag: &str,
        hostname: &str,
        data: &serde_json::Value,
        time: &str,
    ) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let data_str = serde_json::to_string(data).unwrap_or_else(|_| "{}".to_string());
        // Full raw SQL — avoid all parameter serialization issues
        let sql = format!(
            "INSERT INTO logs (tag, hostname, data, time) VALUES ('{}', '{}', '{}'::jsonb, '{}'::timestamptz) RETURNING id",
            tag.replace('\'', "''"),
            hostname.replace('\'', "''"),
            data_str.replace('\'', "''"),
            time.replace('\'', "''"),
        );
        let row = conn.query_one(&*sql, &[]).await.map_err(query_err)?;
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
        let esc = |s: &str| s.replace('\'', "''");
        let rule_sql = format!(
            "INSERT INTO sigma_rules (id, title, level, rule_yaml, detection_json, enabled) VALUES ('{}', '{}', '{}', 'title: {}\nstatus: test\nlevel: {}\ndetection:\n  condition: test', '{{}}'::jsonb, true) ON CONFLICT (id) DO NOTHING",
            esc(rule_id), esc(title), esc(level), esc(title), esc(level),
        );
        conn.execute(&*rule_sql, &[]).await.map_err(query_err)?;

        // Full raw SQL to avoid parameter serialization issues
        let esc = |s: &str| s.replace('\'', "''");
        let ip_part = match source_ip {
            Some(ip) if !ip.is_empty() => format!(", source_ip") ,
            _ => String::new(),
        };
        let ip_val = match source_ip {
            Some(ip) if !ip.is_empty() => format!(", '{}'::inet", esc(ip)),
            _ => String::new(),
        };
        let user_str = username.unwrap_or("");
        let sql = format!(
            "INSERT INTO sigma_alerts (rule_id, level, title, hostname, username, status{}) VALUES ('{}', '{}', '{}', '{}', '{}', 'new'{}) RETURNING id",
            ip_part, esc(rule_id), esc(level), esc(title), esc(hostname), esc(user_str), ip_val,
        );
        let row = conn.query_one(&*sql, &[]).await.map_err(query_err)?;
        Ok(row.get(0))
    }

    async fn count_logs(&self, minutes_back: i64) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let interval = format!("{} minutes", minutes_back);
        let row = conn.query_one(
            "SELECT COUNT(*) FROM logs WHERE time >= NOW() - $1::interval",
            &[&interval],
        ).await.map_err(query_err)?;
        Ok(row.get::<_, i64>(0))
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
        let esc = |s: &str| s.replace('\'', "''");

        let response_jsonb = response_str.as_deref().unwrap_or("null");
        let raw = raw_response.map(|r| esc(&r.chars().take(2000).collect::<String>())).unwrap_or_default();
        let sev = severity.unwrap_or("");
        let conf = confidence.unwrap_or(0.0);

        let sql = format!(
            "INSERT INTO llm_training_data (model, prompt_hash, prompt_length, response_json, raw_response, parsing_ok, parsing_method, severity, confidence, actions_count, escalation, cycle_duration_ms, observations_count) \
             VALUES ('{}', '{}', {}, '{}'::jsonb, '{}', {}, '{}', '{}', {}, {}, '{}', {}, {})",
            esc(model), esc(prompt_hash), prompt_length,
            esc(response_jsonb), raw,
            parsing_ok, esc(parsing_method), esc(sev), conf,
            actions_count, esc(escalation), cycle_duration_ms, observations_count,
        );

        conn.execute(&*sql, &[]).await.map_err(query_err)?;
        Ok(())
    }
}
