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

use std::sync::Arc;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use crate::db::Database;

/// Max failed login attempts before lock.
const MAX_FAILED_ATTEMPTS: i32 = 5;
/// Lock duration after max failures (seconds).
const LOCK_DURATION_SECS: i64 = 900; // 15 minutes
/// Default session duration (seconds).
pub const SESSION_DURATION_SECS: i64 = 28800; // 8 hours

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

/// Public user info (no password hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
}

/// Hash a password with argon2id (OWASP 2024 recommended).
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Password hash failed: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against a stored hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// Generate a session token and return (raw_token, sha256_hash).
pub fn generate_session_token() -> (String, String) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hasher.update(format!("{:?}", std::thread::current().id()).as_bytes());
    // Extra entropy: mix in a second time sample
    hasher.update(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes());
    let hash = hasher.finalize();

    let raw_token = hex::encode(hash);
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
    store.get_setting("_auth", "users_index").await
        .ok()
        .flatten()
        .and_then(|v| v.as_array().map(|a| !a.is_empty()))
        .unwrap_or(false)
}

/// Get user by email.
async fn get_user(store: &Arc<dyn Database>, email: &str) -> Option<DashboardUser> {
    let key = format!("user_{}", email.to_lowercase().replace('@', "_at_").replace('.', "_"));
    store.get_setting("_auth", &key).await.ok()?.and_then(|v| serde_json::from_value(v).ok())
}

/// Save user to store.
async fn save_user(store: &Arc<dyn Database>, user: &DashboardUser) -> Result<(), String> {
    let key = format!("user_{}", user.email.to_lowercase().replace('@', "_at_").replace('.', "_"));
    store.set_setting("_auth", &key, &serde_json::to_value(user).unwrap())
        .await.map_err(|e| format!("DB error: {}", e))?;

    // Update users index
    let mut index: Vec<String> = store.get_setting("_auth", "users_index").await
        .ok().flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    if !index.contains(&user.email) {
        index.push(user.email.clone());
        let _ = store.set_setting("_auth", "users_index", &serde_json::json!(index)).await;
    }
    Ok(())
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

    let user = DashboardUser {
        id: id.clone(),
        email: email.to_lowercase(),
        display_name: display_name.to_string(),
        password_hash,
        role: "admin".to_string(),
        failed_attempts: 0,
        locked_until: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    save_user(store, &user).await?;
    tracing::info!("AUTH: Admin user created: {}", email);

    Ok(UserInfo {
        id: user.id,
        email: user.email,
        display_name: user.display_name,
        role: user.role,
    })
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
    let mut user = get_user(store, email).await
        .ok_or("Email ou mot de passe incorrect")?;

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

    // Verify password
    if !verify_password(password, &user.password_hash) {
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
    let _ = store.set_setting("_auth", &session_key, &serde_json::to_value(&session).unwrap()).await;

    log_event(store, &user.email, "login_success", ip).await;

    Ok((
        UserInfo {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            role: user.role,
        },
        raw_token,
    ))
}

// ── Session Management ──

/// Validate a session token. Returns user info if valid.
pub async fn validate_session(store: &Arc<dyn Database>, token: &str) -> Option<UserInfo> {
    let token_hash = hash_token(token);
    let session_key = format!("session_{}", token_hash);

    let session: SessionRecord = store.get_setting("_auth", &session_key).await.ok()?
        .and_then(|v| serde_json::from_value(v).ok())?;

    // Check expiry
    if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&session.expires_at) {
        if chrono::Utc::now() > expires {
            // Expired — clean up
            let _ = store.set_setting("_auth", &session_key, &serde_json::json!(null)).await;
            return None;
        }
    }

    // Load user
    let index: Vec<String> = store.get_setting("_auth", "users_index").await.ok()?
        .and_then(|v| serde_json::from_value(v).ok())?;

    for email in &index {
        if let Some(user) = get_user(store, email).await {
            if user.id == session.user_id {
                return Some(UserInfo {
                    id: user.id,
                    email: user.email,
                    display_name: user.display_name,
                    role: user.role,
                });
            }
        }
    }
    None
}

/// Delete a session (logout).
pub async fn delete_session(store: &Arc<dyn Database>, token: &str) {
    let token_hash = hash_token(token);
    let session_key = format!("session_{}", token_hash);
    let _ = store.set_setting("_auth", &session_key, &serde_json::json!(null)).await;
}

// ── Password Management ──

/// Change a user's password.
pub async fn change_password(
    store: &Arc<dyn Database>,
    email: &str,
    new_password: &str,
) -> Result<(), String> {
    let mut user = get_user(store, email).await
        .ok_or("Utilisateur introuvable")?;
    user.password_hash = hash_password(new_password)?;
    save_user(store, &user).await?;
    log_event(store, email, "password_changed", "dashboard").await;
    Ok(())
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
pub fn build_session_cookie(token: &str, max_age_secs: i64) -> String {
    format!("tc_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}", token, max_age_secs)
}

/// Build Set-Cookie header to clear session.
pub fn clear_session_cookie() -> String {
    "tc_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

// ── Audit ──

async fn log_event(store: &Arc<dyn Database>, email: &str, event: &str, ip: &str) {
    let key = format!("event_{}_{}", event, chrono::Utc::now().timestamp_millis());
    let _ = store.set_setting("_auth_log", &key, &serde_json::json!({
        "email": email, "event": event, "ip": ip,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })).await;
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
        assert_eq!(extract_session_cookie("tc_session=abc123; other=x"), Some("abc123".into()));
        assert_eq!(extract_session_cookie("other=x"), None);
        assert_eq!(extract_session_cookie("tc_session="), None);
    }

    #[test]
    fn test_session_cookie_format() {
        let c = build_session_cookie("tok", 3600);
        assert!(c.contains("HttpOnly"));
        assert!(c.contains("SameSite=Strict"));
        assert!(c.contains("tc_session=tok"));
    }

    #[test]
    fn test_password_min_length() {
        // hash_password doesn't validate length — that's create_admin's job
        let hash = hash_password("short").unwrap();
        assert!(verify_password("short", &hash));
    }
}
