//! Dashboard user accounts (RBAC) — backend-agnostic CRUD over the
//! `dashboard_users` table, plus single-use invitation tokens. Replaces the
//! legacy JSON-in-settings auth store (`_auth/user_<email>`). The role→
//! permission mapping lives in `crate::channels::web::permissions`, not here.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::DatabaseError;

/// A dashboard account row. `password_hash` is `None` while `status` is
/// `"invited"` (the user has not accepted yet). `granted_permissions` /
/// `denied_permissions` are per-user overrides on top of the role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DashboardUserRecord {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub password_hash: Option<String>,
    pub role: String,
    pub status: String,
    pub must_change_password: bool,
    #[serde(default)]
    pub granted_permissions: Vec<String>,
    #[serde(default)]
    pub denied_permissions: Vec<String>,
    pub failed_attempts: i32,
    pub locked_until: Option<String>,
    pub created_by: Option<String>,
    pub created_at: String,
}

/// Input for creating a new account. The account is created in `"invited"`
/// status with no password; the user sets it via the invitation flow.
#[derive(Debug, Clone)]
pub struct NewDashboardUser {
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub granted: Vec<String>,
    pub denied: Vec<String>,
    pub created_by: Option<String>,
}

/// Partial update. Only `Some(_)` fields are written. The doubly-wrapped
/// fields (`Option<Option<_>>`) distinguish "leave unchanged" (`None`) from
/// "set to NULL" (`Some(None)`).
#[derive(Debug, Clone, Default)]
pub struct UserPatch {
    pub display_name: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
    pub granted: Option<Vec<String>>,
    pub denied: Option<Vec<String>>,
    pub password_hash: Option<Option<String>>,
    pub must_change_password: Option<bool>,
    pub failed_attempts: Option<i32>,
    pub locked_until: Option<Option<String>>,
}

impl DashboardUserRecord {
    /// Apply a partial update in place. Shared by every backend so the merge
    /// logic lives in one place (`dbu_patch` = get + apply + upsert).
    pub fn apply_patch(&mut self, p: &UserPatch) {
        if let Some(v) = &p.display_name {
            self.display_name = v.clone();
        }
        if let Some(v) = &p.role {
            self.role = v.clone();
        }
        if let Some(v) = &p.status {
            self.status = v.clone();
        }
        if let Some(v) = &p.granted {
            self.granted_permissions = v.clone();
        }
        if let Some(v) = &p.denied {
            self.denied_permissions = v.clone();
        }
        if let Some(v) = &p.password_hash {
            self.password_hash = v.clone();
        }
        if let Some(v) = p.must_change_password {
            self.must_change_password = v;
        }
        if let Some(v) = p.failed_attempts {
            self.failed_attempts = v;
        }
        if let Some(v) = &p.locked_until {
            self.locked_until = v.clone();
        }
    }
}

#[async_trait]
pub trait DashboardUserStore: Send + Sync {
    /// Insert a new account in `"invited"` status. Returns the generated id.
    async fn dbu_create(&self, u: &NewDashboardUser) -> Result<String, DatabaseError>;
    /// Insert-or-replace a full record at a caller-controlled id. Used by the
    /// legacy-admin boot migration, which must preserve the existing id so
    /// active sessions (`session.user_id`) keep resolving.
    async fn dbu_upsert_full(&self, rec: &DashboardUserRecord) -> Result<(), DatabaseError>;
    async fn dbu_get(&self, id: &str) -> Result<Option<DashboardUserRecord>, DatabaseError>;
    async fn dbu_get_by_email(
        &self,
        email: &str,
    ) -> Result<Option<DashboardUserRecord>, DatabaseError>;
    async fn dbu_list(&self) -> Result<Vec<DashboardUserRecord>, DatabaseError>;
    /// Count accounts with `role='admin' AND status='active'` (last-admin guard).
    async fn dbu_count_active_admins(&self) -> Result<i64, DatabaseError>;
    async fn dbu_patch(&self, id: &str, patch: &UserPatch) -> Result<(), DatabaseError>;
    async fn dbu_delete(&self, id: &str) -> Result<(), DatabaseError>;

    // ── Invitation / reset tokens (hashed, single-use) ──
    async fn dbu_create_invitation(
        &self,
        token_hash: &str,
        user_id: &str,
        purpose: &str,
        expires_at: &str,
    ) -> Result<(), DatabaseError>;
    /// Atomically consume a non-expired invitation. Returns `(user_id, purpose)`
    /// or `None` if the token is unknown or expired.
    async fn dbu_take_invitation(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, String)>, DatabaseError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_roundtrips_json_with_defaults() {
        let json = serde_json::json!({
            "id": "u1", "email": "a@b.c", "display_name": "A", "password_hash": null,
            "role": "admin", "status": "active", "must_change_password": false,
            "failed_attempts": 0, "locked_until": null, "created_by": null,
            "created_at": "2026-06-19T00:00:00Z"
        });
        let r: DashboardUserRecord = serde_json::from_value(json).unwrap();
        assert_eq!(r.granted_permissions, Vec::<String>::new());
        assert_eq!(r.denied_permissions, Vec::<String>::new());
        assert_eq!(r.role, "admin");
        assert!(r.password_hash.is_none());
    }
}
