//! PostgreSQL implementation of `DashboardUserStore` (dashboard accounts +
//! invitation tokens). Mirrors the SQL schema in `migrations/V88__dashboard_users.sql`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::dashboard_user_store::*;
use super::postgres::PgBackend;
use crate::error::DatabaseError;

fn pool_err(e: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Pool(e.to_string())
}

fn query_err(e: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Query(e.to_string())
}

const COLS: &str = "id, email, display_name, password_hash, role, status, \
    must_change_password, granted_permissions, denied_permissions, \
    failed_attempts, locked_until, created_by, created_at";

fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn parse_ts_opt(s: &Option<String>) -> Option<DateTime<Utc>> {
    s.as_ref()
        .and_then(|x| DateTime::parse_from_rfc3339(x).ok())
        .map(|d| d.with_timezone(&Utc))
}

fn dbu_row(r: &tokio_postgres::Row) -> DashboardUserRecord {
    DashboardUserRecord {
        id: r.get("id"),
        email: r.get("email"),
        display_name: r.get("display_name"),
        password_hash: r.get("password_hash"),
        role: r.get("role"),
        status: r.get("status"),
        must_change_password: r.get("must_change_password"),
        granted_permissions: r.get("granted_permissions"),
        denied_permissions: r.get("denied_permissions"),
        failed_attempts: r.get("failed_attempts"),
        locked_until: r
            .get::<_, Option<DateTime<Utc>>>("locked_until")
            .map(|t| t.to_rfc3339()),
        created_by: r.get("created_by"),
        created_at: r.get::<_, DateTime<Utc>>("created_at").to_rfc3339(),
    }
}

#[async_trait]
impl DashboardUserStore for PgBackend {
    async fn dbu_create(&self, u: &NewDashboardUser) -> Result<String, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            r#"INSERT INTO dashboard_users
               (id, email, display_name, role, status,
                granted_permissions, denied_permissions, created_by)
               VALUES ($1, $2, $3, $4, 'invited', $5, $6, $7)"#,
            &[
                &id,
                &u.email,
                &u.display_name,
                &u.role,
                &u.granted,
                &u.denied,
                &u.created_by,
            ],
        )
        .await
        .map_err(query_err)?;
        Ok(id)
    }

    async fn dbu_upsert_full(&self, r: &DashboardUserRecord) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let created = parse_ts(&r.created_at);
        let locked = parse_ts_opt(&r.locked_until);
        conn.execute(
            r#"INSERT INTO dashboard_users
               (id, email, display_name, password_hash, role, status,
                must_change_password, granted_permissions, denied_permissions,
                failed_attempts, locked_until, created_by, created_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
               ON CONFLICT (id) DO UPDATE SET
                 email = EXCLUDED.email,
                 display_name = EXCLUDED.display_name,
                 password_hash = EXCLUDED.password_hash,
                 role = EXCLUDED.role,
                 status = EXCLUDED.status,
                 must_change_password = EXCLUDED.must_change_password,
                 granted_permissions = EXCLUDED.granted_permissions,
                 denied_permissions = EXCLUDED.denied_permissions,
                 failed_attempts = EXCLUDED.failed_attempts,
                 locked_until = EXCLUDED.locked_until,
                 created_by = EXCLUDED.created_by"#,
            &[
                &r.id,
                &r.email,
                &r.display_name,
                &r.password_hash,
                &r.role,
                &r.status,
                &r.must_change_password,
                &r.granted_permissions,
                &r.denied_permissions,
                &r.failed_attempts,
                &locked,
                &r.created_by,
                &created,
            ],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn dbu_get(&self, id: &str) -> Result<Option<DashboardUserRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                &format!("SELECT {COLS} FROM dashboard_users WHERE id = $1"),
                &[&id],
            )
            .await
            .map_err(query_err)?;
        Ok(row.as_ref().map(dbu_row))
    }

    async fn dbu_get_by_email(
        &self,
        email: &str,
    ) -> Result<Option<DashboardUserRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                &format!("SELECT {COLS} FROM dashboard_users WHERE email = $1"),
                &[&email],
            )
            .await
            .map_err(query_err)?;
        Ok(row.as_ref().map(dbu_row))
    }

    async fn dbu_list(&self) -> Result<Vec<DashboardUserRecord>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let rows = conn
            .query(
                &format!("SELECT {COLS} FROM dashboard_users ORDER BY created_at"),
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(rows.iter().map(dbu_row).collect())
    }

    async fn dbu_count_active_admins(&self) -> Result<i64, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_one(
                "SELECT COUNT(*)::int8 AS n FROM dashboard_users \
                 WHERE role = 'admin' AND status = 'active'",
                &[],
            )
            .await
            .map_err(query_err)?;
        Ok(row.get::<_, i64>("n"))
    }

    async fn dbu_patch(&self, id: &str, patch: &UserPatch) -> Result<(), DatabaseError> {
        let Some(mut rec) = self.dbu_get(id).await? else {
            return Ok(());
        };
        rec.apply_patch(patch);
        self.dbu_upsert_full(&rec).await
    }

    async fn dbu_delete(&self, id: &str) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        conn.execute("DELETE FROM dashboard_users WHERE id = $1", &[&id])
            .await
            .map_err(query_err)?;
        Ok(())
    }

    async fn dbu_create_invitation(
        &self,
        token_hash: &str,
        user_id: &str,
        purpose: &str,
        expires_at: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let exp = parse_ts(expires_at);
        conn.execute(
            r#"INSERT INTO dashboard_invitations (token_hash, user_id, purpose, expires_at)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (token_hash) DO UPDATE SET
                 user_id = EXCLUDED.user_id,
                 purpose = EXCLUDED.purpose,
                 expires_at = EXCLUDED.expires_at"#,
            &[&token_hash, &user_id, &purpose, &exp],
        )
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn dbu_take_invitation(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, String)>, DatabaseError> {
        let conn = self.pool().get().await.map_err(pool_err)?;
        let row = conn
            .query_opt(
                "DELETE FROM dashboard_invitations \
                 WHERE token_hash = $1 AND expires_at > NOW() \
                 RETURNING user_id, purpose",
                &[&token_hash],
            )
            .await
            .map_err(query_err)?;
        Ok(row.map(|r| (r.get("user_id"), r.get("purpose"))))
    }
}
