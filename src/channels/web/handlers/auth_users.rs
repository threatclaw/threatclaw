//! Dashboard user management (admin-only CRUD), the invitation/accept flow,
//! and "sign out everywhere". All admin actions require `users:manage` plus a
//! step-up (re-entry of the caller's own password). Guards protect the last
//! active admin from removal/demotion.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use crate::agent::notification_router;
use crate::channels::web::dashboard_auth as auth;
use crate::channels::web::permissions::effective_permissions;
use crate::channels::web::server::GatewayState;
use crate::db::Database;
use crate::db::dashboard_user_store::{NewDashboardUser, UserPatch};

/// Minimum password length (matches create_admin / change_password). A fuller
/// password policy is Phase D.
const MIN_PASSWORD_LEN: usize = 8;
/// Invitation / reset token lifetime.
const INVITE_TTL_DAYS: i64 = 7;

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "ok": false, "error": msg }))).into_response()
}

/// Resolve the caller's session, or return a 401/503 response.
async fn require_session(
    state: &Arc<GatewayState>,
    headers: &HeaderMap,
) -> Result<(Arc<dyn Database>, auth::UserInfo), Response> {
    let store = state
        .store
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "DB unavailable"))?
        .clone();
    let cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth::extract_session_cookie(cookie)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Non authentifié"))?;
    let user = auth::validate_session(&store, &token)
        .await
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Session invalide"))?;
    Ok((store, user))
}

/// Require the caller to hold `users:manage`.
fn require_admin(user: &auth::UserInfo) -> Result<(), Response> {
    let perms = effective_permissions(&user.role, &user.granted, &user.denied);
    if perms.contains("users:manage") {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "Réservé aux administrateurs"))
    }
}

/// Step-up: re-verify the caller's own password (no new session created).
async fn step_up(
    store: &Arc<dyn Database>,
    user: &auth::UserInfo,
    body: &Value,
) -> Result<(), Response> {
    let pw = body["currentPassword"].as_str().unwrap_or("");
    let rec = store
        .dbu_get(&user.id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "Mot de passe administrateur requis"))?;
    let hash = rec.password_hash.unwrap_or_default();
    if !hash.is_empty() && auth::verify_password(pw, &hash) {
        Ok(())
    } else {
        Err(err(
            StatusCode::FORBIDDEN,
            "Mot de passe administrateur requis",
        ))
    }
}

fn valid_role(role: &str) -> bool {
    matches!(role, "admin" | "analyst" | "viewer")
}

/// True if `can_remediate` is unset for this user (i.e. remediation NOT denied).
fn can_remediate(denied: &[String]) -> bool {
    !denied.iter().any(|p| p == "incidents:remediate")
}

// ── GET /api/auth/users ──

pub async fn list_users(State(state): State<Arc<GatewayState>>, headers: HeaderMap) -> Response {
    let (store, user) = match require_session(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&user) {
        return r;
    }
    let users = store.dbu_list().await.unwrap_or_default();
    let out: Vec<Value> = users
        .iter()
        .map(|u| {
            json!({
                "id": u.id,
                "email": u.email,
                "display_name": u.display_name,
                "role": u.role,
                "status": u.status,
                "can_remediate": can_remediate(&u.denied_permissions),
                "must_change_password": u.must_change_password,
                "created_by": u.created_by,
                "created_at": u.created_at,
            })
        })
        .collect();
    Json(json!({ "ok": true, "users": out })).into_response()
}

// ── POST /api/auth/users ── (create + invitation)

pub async fn create_user(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let (store, user) = match require_session(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&user) {
        return r;
    }
    if let Err(r) = step_up(&store, &user, &body).await {
        return r;
    }

    let email = body["email"].as_str().unwrap_or("").trim().to_lowercase();
    let display_name = body["displayName"].as_str().unwrap_or(&email).to_string();
    let role = body["role"].as_str().unwrap_or("viewer").to_string();
    let allow_remediate = body["canRemediate"].as_bool().unwrap_or(true);

    if email.is_empty() || !email.contains('@') {
        return err(StatusCode::BAD_REQUEST, "Email invalide");
    }
    if !valid_role(&role) {
        return err(StatusCode::BAD_REQUEST, "Rôle invalide");
    }
    if store
        .dbu_get_by_email(&email)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return err(StatusCode::CONFLICT, "Un compte existe déjà pour cet email");
    }

    // Only analysts carry the remediation override; admins always can, viewers never.
    let denied = if role == "analyst" && !allow_remediate {
        vec!["incidents:remediate".to_string()]
    } else {
        vec![]
    };

    let new = NewDashboardUser {
        email: email.clone(),
        display_name,
        role,
        granted: vec![],
        denied,
        created_by: Some(user.email.clone()),
    };
    let id = match store.dbu_create(&new).await {
        Ok(id) => id,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")),
    };

    match issue_invitation(&store, &id, "invite", &email, "Invitation ThreatClaw").await {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

// ── POST /api/auth/invitations/accept ── (public + token)

pub async fn accept_invitation(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<Value>,
) -> Response {
    let store = match state.store.as_ref() {
        Some(s) => s.clone(),
        None => return err(StatusCode::SERVICE_UNAVAILABLE, "DB unavailable"),
    };
    let token = body["token"].as_str().unwrap_or("");
    let new_password = body["newPassword"].as_str().unwrap_or("");

    if new_password.len() < MIN_PASSWORD_LEN {
        return err(
            StatusCode::BAD_REQUEST,
            "Le mot de passe doit faire au moins 8 caractères",
        );
    }
    // Generic message on any failure (anti-enumeration).
    let invalid = || err(StatusCode::BAD_REQUEST, "Lien invalide ou expiré");
    if token.is_empty() {
        return invalid();
    }
    let hash = auth::token_hash(token);
    let user_id = match store.dbu_take_invitation(&hash).await {
        Ok(Some((uid, _purpose))) => uid,
        _ => return invalid(),
    };

    let password_hash = match auth::hash_password(new_password) {
        Ok(h) => h,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let patch = UserPatch {
        password_hash: Some(Some(password_hash)),
        status: Some("active".to_string()),
        must_change_password: Some(false),
        ..Default::default()
    };
    match store.dbu_patch(&user_id, &patch).await {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")),
    }
}

// ── PATCH /api/auth/users/{id} ──

pub async fn patch_user(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let (store, user) = match require_session(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&user) {
        return r;
    }
    if let Err(r) = step_up(&store, &user, &body).await {
        return r;
    }

    let target = match store.dbu_get(&id).await.ok().flatten() {
        Some(t) => t,
        None => return err(StatusCode::NOT_FOUND, "Utilisateur introuvable"),
    };

    let new_role = body["role"].as_str().map(|s| s.to_string());
    let new_status = body["status"].as_str().map(|s| s.to_string());
    if let Some(r) = &new_role {
        if !valid_role(r) {
            return err(StatusCode::BAD_REQUEST, "Rôle invalide");
        }
    }

    // Last-admin guard: refuse to demote or disable the final active admin.
    let demoting = new_role.as_deref().is_some_and(|r| r != "admin");
    let disabling = new_status.as_deref() == Some("disabled");
    if target.role == "admin" && target.status == "active" && (demoting || disabling) {
        let admins = store.dbu_count_active_admins().await.unwrap_or(0);
        if admins <= 1 {
            return err(
                StatusCode::CONFLICT,
                "Impossible: c'est le dernier administrateur actif",
            );
        }
    }

    // can_remediate override (only meaningful for analysts).
    let denied = match body["canRemediate"].as_bool() {
        Some(false) => Some(vec!["incidents:remediate".to_string()]),
        Some(true) => Some(vec![]),
        None => None,
    };

    let patch = UserPatch {
        display_name: body["displayName"].as_str().map(|s| s.to_string()),
        role: new_role,
        status: new_status.clone(),
        denied,
        ..Default::default()
    };
    if let Err(e) = store.dbu_patch(&id, &patch).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}"));
    }

    // Disabling an account kills its live sessions immediately.
    if disabling {
        auth::delete_all_sessions_for_user(&store, &id).await;
    }
    Json(json!({ "ok": true })).into_response()
}

// ── DELETE /api/auth/users/{id} ──

pub async fn delete_user(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let (store, user) = match require_session(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&user) {
        return r;
    }
    if let Err(r) = step_up(&store, &user, &body).await {
        return r;
    }

    let target = match store.dbu_get(&id).await.ok().flatten() {
        Some(t) => t,
        None => return err(StatusCode::NOT_FOUND, "Utilisateur introuvable"),
    };
    if target.role == "admin" && target.status == "active" {
        let admins = store.dbu_count_active_admins().await.unwrap_or(0);
        if admins <= 1 {
            return err(
                StatusCode::CONFLICT,
                "Impossible: c'est le dernier administrateur actif",
            );
        }
    }
    if let Err(e) = store.dbu_delete(&id).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}"));
    }
    auth::delete_all_sessions_for_user(&store, &id).await;
    Json(json!({ "ok": true })).into_response()
}

// ── POST /api/auth/users/{id}/reinvite and /reset-password ──

pub async fn reinvite_user(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    regenerate_link(state, headers, id, "invite", "Invitation ThreatClaw").await
}

pub async fn reset_password_user(
    State(state): State<Arc<GatewayState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    regenerate_link(
        state,
        headers,
        id,
        "reset",
        "Réinitialisation du mot de passe ThreatClaw",
    )
    .await
}

async fn regenerate_link(
    state: Arc<GatewayState>,
    headers: HeaderMap,
    id: String,
    purpose: &str,
    subject: &str,
) -> Response {
    let (store, user) = match require_session(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Err(r) = require_admin(&user) {
        return r;
    }
    let target = match store.dbu_get(&id).await.ok().flatten() {
        Some(t) => t,
        None => return err(StatusCode::NOT_FOUND, "Utilisateur introuvable"),
    };
    match issue_invitation(&store, &id, purpose, &target.email, subject).await {
        Ok(resp) => resp,
        Err(r) => r,
    }
}

// ── POST /api/auth/logout-all ──

pub async fn logout_all(State(state): State<Arc<GatewayState>>, headers: HeaderMap) -> Response {
    let (store, user) = match require_session(&state, &headers).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    auth::delete_all_sessions_for_user(&store, &user.id).await;
    let mut response = Json(json!({ "ok": true })).into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&auth::clear_session_cookie())
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("")),
    );
    response
}

// ── Shared invitation issuance ──

/// Create a single-use token for `user_id`, then either email the link (if the
/// SMTP channel is configured) or return it for the admin to deliver manually.
async fn issue_invitation(
    store: &Arc<dyn Database>,
    user_id: &str,
    purpose: &str,
    email: &str,
    subject: &str,
) -> Result<Response, Response> {
    let (raw, hash) = auth::generate_session_token();
    let expires = (Utc::now() + Duration::days(INVITE_TTL_DAYS)).to_rfc3339();
    if let Err(e) = store
        .dbu_create_invitation(&hash, user_id, purpose, &expires)
        .await
    {
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")));
    }
    let link = format!("/invite?token={raw}");

    if notification_router::is_email_configured(store.as_ref()).await {
        let bodytext = format!(
            "Bonjour,\n\nUn compte ThreatClaw vous est ouvert. Pour definir votre mot de passe, ouvrez ce lien depuis le tableau de bord:\n\n{link}\n\nCe lien expire dans {INVITE_TTL_DAYS} jours.\n"
        );
        let _ =
            notification_router::send_smtp_email(store.as_ref(), Some(email), subject, &bodytext)
                .await;
        Ok(Json(json!({ "ok": true, "emailed": true })).into_response())
    } else {
        Ok(Json(json!({ "ok": true, "emailed": false, "invite_link": link })).into_response())
    }
}
