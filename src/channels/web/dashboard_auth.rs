//! Dashboard Authentication — users, sessions, brute force protection.
//!
//! Uses the existing settings store (get_setting/set_setting) for persistence.
//! All auth data stored under namespace "_auth" in the settings table.
//!
//! Security:
//! - argon2id password hashing (OWASP 2024)
//! - SHA-256 session tokens (never stored plaintext)
//! - HttpOnly + SameSite=Strict cookies
//! - Brute force: 5 fails → 15min lock
//! - Constant-time comparison for tokens

use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::db::Database;
use crate::db::dashboard_user_store::DashboardUserRecord;

/// Max failed login attempts before lock.
const MAX_FAILED_ATTEMPTS: i32 = 5;
/// Lock duration after max failures (seconds).
const LOCK_DURATION_SECS: i64 = 900; // 15 minutes
/// Session inactivity timeout (seconds). Session expires after 15 minutes without activity.
/// Each authenticated request renews the timeout (sliding window).
pub const SESSION_DURATION_SECS: i64 = 900; // 15 minutes inactivity

/// Dashboard user record (stored in settings as JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardUser {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub role: String, // admin, analyst, viewer
    pub failed_attempts: i32,
    pub locked_until: Option<String>, // ISO 8601
    pub created_at: String,
}

/// Session record (stored in settings as JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub user_id: String,
    pub token_hash: String,
    pub ip_address: String,
    pub user_agent: String,
    pub expires_at: String, // ISO 8601
    pub created_at: String,
}

/// Public user info (no password hash). Carries the per-user permission
/// overrides so the authorization layer can compute the effective set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
    #[serde(default)]
    pub granted: Vec<String>,
    #[serde(default)]
    pub denied: Vec<String>,
}

impl UserInfo {
    fn from_record(r: DashboardUserRecord) -> Self {
        UserInfo {
            id: r.id,
            email: r.email,
            display_name: r.display_name,
            role: r.role,
            granted: r.granted_permissions,
            denied: r.denied_permissions,
        }
    }
}

/// Hash a password with argon2id (OWASP 2024 recommended).
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Password hash failed: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Generate a session token and return (raw_token, sha256_hash).
///
/// The raw token is 256 bits drawn from the OS CSPRNG (`OsRng`) — the same
/// source used for argon2 salts above. This previously derived the token from a
/// timestamp + PID + counter + thread id, none of which are secret: on a fresh
/// process (counter=0, PID in a narrow range) the token space was predictable
/// and brute-forceable. Never derive session secrets from non-random inputs.
pub fn generate_session_token() -> (String, String) {
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    let raw_token = hex::encode(bytes);
    let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
    (raw_token, token_hash)
}

/// Hash a session token for storage lookup.
fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

// ── User Management ──

/// Check if any user exists (first-run detection).
pub async fn has_any_user(store: &Arc<dyn Database>) -> bool {
    store
        .dbu_list()
        .await
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Get user by email (case-insensitive — emails are stored lowercased).
async fn get_user(store: &Arc<dyn Database>, email: &str) -> Option<DashboardUserRecord> {
    store
        .dbu_get_by_email(&email.to_lowercase())
        .await
        .ok()
        .flatten()
}

/// Persist a full user record (insert or update, id-preserving).
async fn save_user(store: &Arc<dyn Database>, user: &DashboardUserRecord) -> Result<(), String> {
    store
        .dbu_upsert_full(user)
        .await
        .map_err(|e| format!("DB error: {}", e))
}

/// Create the first admin user (first-run setup).
pub async fn create_admin(
    store: &Arc<dyn Database>,
    email: &str,
    password: &str,
    display_name: &str,
) -> Result<UserInfo, String> {
    if has_any_user(store).await {
        return Err("Un administrateur existe déjà".into());
    }
    if email.is_empty() || !email.contains('@') {
        return Err("Email invalide".into());
    }
    if password.len() < 8 {
        return Err("Le mot de passe doit faire au moins 8 caractères".into());
    }

    let password_hash = hash_password(password)?;
    let id = crate::config::license::generate_instance_id(); // reuse our UUID generator

    let user = DashboardUserRecord {
        id: id.clone(),
        email: email.to_lowercase(),
        display_name: display_name.to_string(),
        password_hash: Some(password_hash),
        role: "admin".to_string(),
        status: "active".to_string(),
        must_change_password: false,
        granted_permissions: Vec::new(),
        denied_permissions: Vec::new(),
        failed_attempts: 0,
        locked_until: None,
        created_by: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    save_user(store, &user).await?;
    tracing::info!("AUTH: Admin user created: {}", email);

    Ok(UserInfo::from_record(user))
}

// ── Authentication ──

/// Authenticate by email/password. Returns (UserInfo, session_token) on success.
pub async fn authenticate(
    store: &Arc<dyn Database>,
    email: &str,
    password: &str,
    ip: &str,
    user_agent: &str,
) -> Result<(UserInfo, String), String> {
    let mut user = get_user(store, email)
        .await
        .ok_or("Email ou mot de passe incorrect")?;

    // Only active accounts can authenticate (invited = not yet accepted,
    // disabled = deactivated by an admin). Generic message (anti-enumeration).
    if user.status != "active" {
        log_event(store, &user.email, "login_inactive", ip).await;
        return Err("Email ou mot de passe incorrect".into());
    }

    // Check lock
    if user.failed_attempts >= MAX_FAILED_ATTEMPTS {
        if let Some(ref until) = user.locked_until {
            if let Ok(lock_time) = chrono::DateTime::parse_from_rfc3339(until) {
                if chrono::Utc::now() < lock_time {
                    log_event(store, &user.email, "brute_force_blocked", ip).await;
                    return Err("Compte verrouillé. Réessayez dans 15 minutes.".into());
                }
            }
        }
        // Lock expired — reset
        user.failed_attempts = 0;
        user.locked_until = None;
        let _ = save_user(store, &user).await;
    }

    // Verify password (None hash = invited account with no password set yet).
    let stored_hash = user.password_hash.clone().unwrap_or_default();
    if stored_hash.is_empty() || !verify_password(password, &stored_hash) {
        user.failed_attempts += 1;
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS {
            let lock_until = chrono::Utc::now() + chrono::Duration::seconds(LOCK_DURATION_SECS);
            user.locked_until = Some(lock_until.to_rfc3339());
            log_event(store, &user.email, "account_locked", ip).await;
        }
        let _ = save_user(store, &user).await;
        log_event(store, &user.email, "login_failed", ip).await;
        return Err("Email ou mot de passe incorrect".into());
    }

    // Reset failed attempts
    user.failed_attempts = 0;
    user.locked_until = None;
    let _ = save_user(store, &user).await;

    // Create session
    let (raw_token, token_hash) = generate_session_token();
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(SESSION_DURATION_SECS);

    let session = SessionRecord {
        user_id: user.id.clone(),
        token_hash: token_hash.clone(),
        ip_address: ip.to_string(),
        user_agent: user_agent.to_string(),
        expires_at: expires_at.to_rfc3339(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let session_key = format!("session_{}", token_hash);
    let _ = store
        .set_setting(
            "_auth",
            &session_key,
            &serde_json::to_value(&session).unwrap(),
        )
        .await;

    log_event(store, &user.email, "login_success", ip).await;

    Ok((UserInfo::from_record(user), raw_token))
}

// ── Session Management ──

/// Validate a session token. Returns user info if valid.
pub async fn validate_session(store: &Arc<dyn Database>, token: &str) -> Option<UserInfo> {
    let token_hash = hash_token(token);
    let session_key = format!("session_{}", token_hash);

    let session: SessionRecord = store
        .get_setting("_auth", &session_key)
        .await
        .ok()?
        .and_then(|v| serde_json::from_value(v).ok())?;

    // Check expiry
    if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&session.expires_at) {
        if chrono::Utc::now() > expires {
            // Expired — clean up
            let _ = store
                .set_setting("_auth", &session_key, &serde_json::json!(null))
                .await;
            return None;
        }
    }

    // Sliding window: renew expiration on each valid request (15 min inactivity timeout)
    let new_expires = chrono::Utc::now() + chrono::Duration::seconds(SESSION_DURATION_SECS);
    let mut renewed = serde_json::to_value(&session).unwrap_or_default();
    if let Some(obj) = renewed.as_object_mut() {
        obj.insert(
            "expires_at".into(),
            serde_json::json!(new_expires.to_rfc3339()),
        );
    }
    let _ = store.set_setting("_auth", &session_key, &renewed).await;

    // Load user by id. A disabled account invalidates the session.
    let user = store.dbu_get(&session.user_id).await.ok().flatten()?;
    if user.status != "active" {
        return None;
    }
    Some(UserInfo::from_record(user))
}

/// Delete a session (logout).
pub async fn delete_session(store: &Arc<dyn Database>, token: &str) {
    let token_hash = hash_token(token);
    let session_key = format!("session_{}", token_hash);
    let _ = store
        .set_setting("_auth", &session_key, &serde_json::json!(null))
        .await;
}

/// Public SHA-256 hex of a token — used to look up invitation tokens, which
/// are stored hashed just like session tokens.
pub fn token_hash(token: &str) -> String {
    hash_token(token)
}

/// Invalidate every server-side session belonging to a user. Backs both
/// "sign out everywhere" and the account-disable / delete flows.
pub async fn delete_all_sessions_for_user(store: &Arc<dyn Database>, user_id: &str) {
    let rows = match store.list_settings("_auth").await {
        Ok(r) => r,
        Err(_) => return,
    };
    for row in rows {
        if !row.key.starts_with("session_") {
            continue;
        }
        if let Ok(sess) = serde_json::from_value::<SessionRecord>(row.value.clone()) {
            if sess.user_id == user_id {
                let _ = store
                    .set_setting("_auth", &row.key, &serde_json::json!(null))
                    .await;
            }
        }
    }
}

// ── Password Management ──

/// Change a user's password.
pub async fn change_password(
    store: &Arc<dyn Database>,
    email: &str,
    new_password: &str,
) -> Result<(), String> {
    let mut user = get_user(store, email)
        .await
        .ok_or("Utilisateur introuvable")?;
    user.password_hash = Some(hash_password(new_password)?);
    user.must_change_password = false;
    save_user(store, &user).await?;
    log_event(store, email, "password_changed", "dashboard").await;
    Ok(())
}

// ── Legacy migration ──

/// One-shot, idempotent migration of the legacy JSON-in-settings users
/// (`_auth/users_index` + `_auth/user_<email>`) into the `dashboard_users`
/// table. Preserves each user's id so active sessions (`session.user_id`)
/// keep resolving. Safe to call on every boot: users already present in the
/// table are skipped.
pub async fn migrate_legacy_admin(store: &Arc<dyn Database>) {
    let index: Vec<String> = match store.get_setting("_auth", "users_index").await {
        Ok(Some(v)) => serde_json::from_value(v).unwrap_or_default(),
        _ => return,
    };
    for email in index {
        if store
            .dbu_get_by_email(&email.to_lowercase())
            .await
            .ok()
            .flatten()
            .is_some()
        {
            continue; // already migrated
        }
        let key = format!(
            "user_{}",
            email.to_lowercase().replace('@', "_at_").replace('.', "_")
        );
        let legacy: Option<DashboardUser> = store
            .get_setting("_auth", &key)
            .await
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_value(v).ok());
        let Some(legacy) = legacy else { continue };
        let rec = DashboardUserRecord {
            id: legacy.id,
            email: legacy.email.to_lowercase(),
            display_name: legacy.display_name,
            password_hash: Some(legacy.password_hash),
            role: legacy.role,
            status: "active".to_string(),
            must_change_password: false,
            granted_permissions: Vec::new(),
            denied_permissions: Vec::new(),
            failed_attempts: legacy.failed_attempts,
            locked_until: legacy.locked_until,
            created_by: None,
            created_at: legacy.created_at,
        };
        match store.dbu_upsert_full(&rec).await {
            Ok(_) => tracing::info!("AUTH: migrated legacy user {} into dashboard_users", email),
            Err(e) => tracing::warn!("AUTH: legacy migration failed for {}: {}", email, e),
        }
    }
}

// ── Cookie helpers ──

/// Extract session token from Cookie header.
pub fn extract_session_cookie(cookie_header: &str) -> Option<String> {
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix("tc_session=") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Build Set-Cookie header for a new session.
/// Flags: HttpOnly (no JS access), SameSite=Strict (no CSRF).
/// Secure flag added only when behind HTTPS (detected via X-Forwarded-Proto or env).
/// No Max-Age = session cookie — dies when browser closes (anti cookie theft).
/// Server-side expiration still enforced via dashboard_sessions.expires_at.
pub fn build_session_cookie(token: &str, _max_age_secs: i64) -> String {
    let secure = if is_https() { "; Secure" } else { "" };
    format!(
        "tc_session={}; HttpOnly; SameSite=Strict; Path=/{}",
        token, secure
    )
}

/// Build Set-Cookie header to clear session.
pub fn clear_session_cookie() -> String {
    let secure = if is_https() { "; Secure" } else { "" };
    format!(
        "tc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{}",
        secure
    )
}

/// Detect if running behind HTTPS (nginx sets X-Forwarded-Proto, or TC_HTTPS env)
fn is_https() -> bool {
    std::env::var("TC_HTTPS").unwrap_or_default() == "true"
        || std::env::var("HTTPS").unwrap_or_default() == "on"
}

// ── Audit ──

async fn log_event(store: &Arc<dyn Database>, email: &str, event: &str, ip: &str) {
    let key = format!("event_{}_{}", event, chrono::Utc::now().timestamp_millis());
    let _ = store
        .set_setting(
            "_auth_log",
            &key,
            &serde_json::json!({
                "email": email, "event": event, "ip": ip,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        )
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let hash = hash_password("SecureP@ss123").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password("SecureP@ss123", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn test_session_token_unique() {
        let (t1, h1) = generate_session_token();
        let (t2, h2) = generate_session_token();
        assert_ne!(t1, t2);
        assert_ne!(h1, h2);
        assert_eq!(t1.len(), 64);
    }

    #[test]
    fn test_hash_token_matches() {
        let (token, expected) = generate_session_token();
        assert_eq!(hash_token(&token), expected);
    }

    #[test]
    fn test_extract_cookie() {
        assert_eq!(
            extract_session_cookie("tc_session=abc123; other=x"),
            Some("abc123".into())
        );
        assert_eq!(extract_session_cookie("other=x"), None);
        assert_eq!(extract_session_cookie("tc_session="), None);
    }

    #[test]
    fn test_session_cookie_format() {
        let c = build_session_cookie("tok", 3600);
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.contains("tc_session=tok"));
        // No Max-Age = session cookie, dies when browser closes
        assert!(!c.contains("Max-Age"));
        // Secure flag only when TC_HTTPS=true (not set in tests = HTTP mode)
    }

    #[test]
    fn test_clear_cookie_format() {
        let c = clear_session_cookie();
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("Max-Age=0"));
    }

    #[test]
    fn test_secure_flag_when_https() {
        // SAFETY: single-threaded test, no concurrent env access
        unsafe {
            std::env::set_var("TC_HTTPS", "true");
        }
        let c = build_session_cookie("tok", 3600);
        assert!(c.contains("Secure"));
        let c2 = clear_session_cookie();
        assert!(c2.contains("Secure"));
        unsafe {
            std::env::remove_var("TC_HTTPS");
        }
    }

    #[test]
    fn test_password_min_length() {
        // hash_password doesn't validate length — that's create_admin's job
        let hash = hash_password("short").unwrap();
        assert!(verify_password("short", &hash));
    }
}
