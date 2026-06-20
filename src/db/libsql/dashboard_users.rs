//! LibSQL implementation of `DashboardUserStore`. SQLite has no array type,
//! so granted/denied permissions are JSON TEXT and `must_change_password` is
//! INTEGER 0/1. Timestamps are RFC3339 TEXT, parsed in Rust for comparisons.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use libsql::params;

use super::{LibSqlBackend, get_i64, get_opt_text, get_text, opt_text};
use crate::db::dashboard_user_store::*;
use crate::error::DatabaseError;

fn qe(e: impl std::fmt::Display) -> DatabaseError {
    DatabaseError::Query(e.to_string())
}

const COLS: &str = "id, email, display_name, password_hash, role, status, \
    must_change_password, granted_permissions, denied_permissions, \
    failed_attempts, locked_until, created_by, created_at";

fn json_vec(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

fn dbu_row(row: &libsql::Row) -> DashboardUserRecord {
    DashboardUserRecord {
        id: get_text(row, 0),
        email: get_text(row, 1),
        display_name: get_text(row, 2),
        password_hash: get_opt_text(row, 3),
        role: get_text(row, 4),
        status: get_text(row, 5),
        must_change_password: get_i64(row, 6) != 0,
        granted_permissions: json_vec(&get_text(row, 7)),
        denied_permissions: json_vec(&get_text(row, 8)),
        failed_attempts: get_i64(row, 9) as i32,
        locked_until: get_opt_text(row, 10),
        created_by: get_opt_text(row, 11),
        created_at: get_text(row, 12),
    }
}

#[async_trait]
impl DashboardUserStore for LibSqlBackend {
    async fn dbu_create(&self, u: &NewDashboardUser) -> Result<String, DatabaseError> {
        let conn = self.connect().await?;
        let id = uuid::Uuid::new_v4().to_string();
        let granted = serde_json::to_string(&u.granted).unwrap_or_else(|_| "[]".into());
        let denied = serde_json::to_string(&u.denied).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "INSERT INTO dashboard_users \
             (id, email, display_name, role, status, granted_permissions, denied_permissions, created_by) \
             VALUES (?1, ?2, ?3, ?4, 'invited', ?5, ?6, ?7)",
            params![
                id.clone(),
                u.email.clone(),
                u.display_name.clone(),
                u.role.clone(),
                granted,
                denied,
                opt_text(u.created_by.as_deref())
            ],
        )
        .await
        .map_err(qe)?;
        Ok(id)
    }

    async fn dbu_upsert_full(&self, r: &DashboardUserRecord) -> Result<(), DatabaseError> {
        let conn = self.connect().await?;
        let granted = serde_json::to_string(&r.granted_permissions).unwrap_or_else(|_| "[]".into());
        let denied = serde_json::to_string(&r.denied_permissions).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "INSERT INTO dashboard_users \
             (id, email, display_name, password_hash, role, status, must_change_password, \
              granted_permissions, denied_permissions, failed_attempts, locked_until, created_by, created_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) \
             ON CONFLICT(id) DO UPDATE SET \
               email=excluded.email, display_name=excluded.display_name, \
               password_hash=excluded.password_hash, role=excluded.role, status=excluded.status, \
               must_change_password=excluded.must_change_password, \
               granted_permissions=excluded.granted_permissions, \
               denied_permissions=excluded.denied_permissions, \
               failed_attempts=excluded.failed_attempts, locked_until=excluded.locked_until, \
               created_by=excluded.created_by",
            params![
                r.id.clone(),
                r.email.clone(),
                r.display_name.clone(),
                opt_text(r.password_hash.as_deref()),
                r.role.clone(),
                r.status.clone(),
                r.must_change_password as i64,
                granted,
                denied,
                r.failed_attempts as i64,
                opt_text(r.locked_until.as_deref()),
                opt_text(r.created_by.as_deref()),
                r.created_at.clone()
            ],
        )
        .await
        .map_err(qe)?;
        Ok(())
    }

    async fn dbu_get(&self, id: &str) -> Result<Option<DashboardUserRecord>, DatabaseError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                &format!("SELECT {COLS} FROM dashboard_users WHERE id = ?1"),
                params![id],
            )
            .await
            .map_err(qe)?;
        match rows.next().await.map_err(qe)? {
            Some(row) => Ok(Some(dbu_row(&row))),
            None => Ok(None),
        }
    }

    async fn dbu_get_by_email(
        &self,
        email: &str,
    ) -> Result<Option<DashboardUserRecord>, DatabaseError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                &format!("SELECT {COLS} FROM dashboard_users WHERE email = ?1"),
                params![email],
            )
            .await
            .map_err(qe)?;
        match rows.next().await.map_err(qe)? {
            Some(row) => Ok(Some(dbu_row(&row))),
            None => Ok(None),
        }
    }

    async fn dbu_list(&self) -> Result<Vec<DashboardUserRecord>, DatabaseError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                &format!("SELECT {COLS} FROM dashboard_users ORDER BY created_at"),
                params![],
            )
            .await
            .map_err(qe)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(qe)? {
            out.push(dbu_row(&row));
        }
        Ok(out)
    }

    async fn dbu_count_active_admins(&self) -> Result<i64, DatabaseError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM dashboard_users WHERE role = 'admin' AND status = 'active'",
                params![],
            )
            .await
            .map_err(qe)?;
        let row = rows
            .next()
            .await
            .map_err(qe)?
            .ok_or_else(|| DatabaseError::Query("count returned no row".into()))?;
        Ok(get_i64(&row, 0))
    }

    async fn dbu_patch(&self, id: &str, patch: &UserPatch) -> Result<(), DatabaseError> {
        let Some(mut rec) = self.dbu_get(id).await? else {
            return Ok(());
        };
        rec.apply_patch(patch);
        self.dbu_upsert_full(&rec).await
    }

    async fn dbu_delete(&self, id: &str) -> Result<(), DatabaseError> {
        let conn = self.connect().await?;
        conn.execute("DELETE FROM dashboard_users WHERE id = ?1", params![id])
            .await
            .map_err(qe)?;
        Ok(())
    }

    async fn dbu_create_invitation(
        &self,
        token_hash: &str,
        user_id: &str,
        purpose: &str,
        expires_at: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.connect().await?;
        conn.execute(
            "INSERT INTO dashboard_invitations (token_hash, user_id, purpose, expires_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(token_hash) DO UPDATE SET \
               user_id=excluded.user_id, purpose=excluded.purpose, expires_at=excluded.expires_at",
            params![token_hash, user_id, purpose, expires_at],
        )
        .await
        .map_err(qe)?;
        Ok(())
    }

    async fn dbu_take_invitation(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, String)>, DatabaseError> {
        let conn = self.connect().await?;
        let mut rows = conn
            .query(
                "SELECT user_id, purpose, expires_at FROM dashboard_invitations WHERE token_hash = ?1",
                params![token_hash],
            )
            .await
            .map_err(qe)?;
        let Some(row) = rows.next().await.map_err(qe)? else {
            return Ok(None);
        };
        let user_id = get_text(&row, 0);
        let purpose = get_text(&row, 1);
        let expires = get_text(&row, 2);
        let valid = DateTime::parse_from_rfc3339(&expires)
            .map(|d| d.with_timezone(&Utc) > Utc::now())
            .unwrap_or(false);
        // Single-use: consume the token regardless of validity.
        conn.execute(
            "DELETE FROM dashboard_invitations WHERE token_hash = ?1",
            params![token_hash],
        )
        .await
        .map_err(qe)?;
        if valid {
            Ok(Some((user_id, purpose)))
        } else {
            Ok(None)
        }
    }
}
