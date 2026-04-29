//! HTTP handlers for premium-skill licensing.
//!
//! Sit under `/api/tc/licensing/*`. Mirror the same `ApiResult<T>`
//! conventions as the rest of `/api/tc/*`. All write endpoints require
//! the `LicenseManager` to be present in `GatewayState` — when absent
//! (e.g. in tests, dispatcher), they respond with 503.
//!
//! Server endpoints:
//!
//! | Path                                | Verb | Purpose                                     |
//! |-------------------------------------|------|---------------------------------------------|
//! | `/api/tc/licensing/status`          | GET  | Read current license state                  |
//! | `/api/tc/licensing/activate`        | POST | Bind an existing license_key to this site   |
//! | `/api/tc/licensing/trial/start`     | POST | Request a 60-day evaluation                 |
//! | `/api/tc/licensing/heartbeat`       | POST | Manual cert refresh ("Refresh now" button)  |
//! | `/api/tc/licensing/deactivate`      | POST | Release this site's activation slot         |

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::channels::web::server::GatewayState;
use crate::licensing::{ApiError, ApiRejection, LicenseManager, LicenseStatus, ManagerError};

type ApiResult<T> = Result<Json<T>, (StatusCode, String)>;

fn no_manager() -> (StatusCode, String) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "licensing manager not initialised in this build".into(),
    )
}

fn manager_err(e: ManagerError) -> (StatusCode, String) {
    match e {
        ManagerError::NotProvisioned => (
            StatusCode::SERVICE_UNAVAILABLE,
            "premium licensing is not provisioned in this build".into(),
        ),
        ManagerError::Api(api) => api_err(api),
        ManagerError::Verify(msg) => (StatusCode::BAD_GATEWAY, format!("cert verify: {msg}")),
        ManagerError::Storage(io) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("local storage: {io}"),
        ),
        ManagerError::UnknownLocalLicense(key) => (
            StatusCode::NOT_FOUND,
            format!("not_found:license `{key}` is not active on this install"),
        ),
    }
}

fn api_err(e: ApiError) -> (StatusCode, String) {
    match e {
        ApiError::Network(m) => (StatusCode::BAD_GATEWAY, format!("network: {m}")),
        ApiError::Transient { status, message } => (
            StatusCode::BAD_GATEWAY,
            format!("license server transient ({status}): {message}"),
        ),
        ApiError::BadResponse(m) => (
            StatusCode::BAD_GATEWAY,
            format!("malformed license server response: {m}"),
        ),
        ApiError::Rejected { kind, message } => {
            let status = match kind {
                ApiRejection::Unauthenticated | ApiRejection::NotFound => StatusCode::NOT_FOUND,
                ApiRejection::SubscriptionInactive => StatusCode::PAYMENT_REQUIRED,
                ApiRejection::Revoked => StatusCode::GONE,
                ApiRejection::ActivationLimit => StatusCode::CONFLICT,
                ApiRejection::TrialAlreadyUsed => StatusCode::CONFLICT,
                ApiRejection::BadRequest => StatusCode::BAD_REQUEST,
                ApiRejection::RateLimit => StatusCode::TOO_MANY_REQUESTS,
                ApiRejection::Unknown => StatusCode::BAD_REQUEST,
            };
            // Surface the machine-readable kind to the dashboard so it
            // can pick the right banner ("subscription_inactive" → renew
            // CTA, "trial_already_used" → switch to purchase, etc.).
            (status, format!("{kind}:{message}"))
        }
    }
}

fn manager(state: &Arc<GatewayState>) -> Result<Arc<LicenseManager>, (StatusCode, String)> {
    state.license_manager.clone().ok_or_else(no_manager)
}

// ── Status ──────────────────────────────────────────────────────────

pub async fn status_handler(State(state): State<Arc<GatewayState>>) -> ApiResult<LicenseStatus> {
    // Status is readable even when the manager is absent — degrade
    // gracefully instead of returning 503.
    if let Some(mgr) = state.license_manager.clone() {
        return Ok(Json(mgr.status().await));
    }
    Ok(Json(LicenseStatus {
        provisioned: crate::licensing::is_provisioned(),
        licenses: vec![],
        trial_consumed: false,
    }))
}

// ── Activate (paste license key) ────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ActivateRequest {
    pub license_key: String,
    /// Optional — when omitted the server resolves the skill set from
    /// the license_key on its end. Useful for "I just want to bind this
    /// key to this site" without specifying which skill.
    #[serde(default)]
    pub requested_skills: Vec<String>,
}

pub async fn activate_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<ActivateRequest>,
) -> ApiResult<LicenseStatus> {
    let key = req.license_key.trim();
    if key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "license_key is required".into()));
    }
    let mgr = manager(&state)?;
    let skills_owned: Vec<String> = req.requested_skills.into_iter().collect();
    let skills_ref: Vec<&str> = skills_owned.iter().map(String::as_str).collect();
    let status = mgr.activate(key, &skills_ref).await.map_err(manager_err)?;
    Ok(Json(status))
}

// ── Trial start (60-day free evaluation) ────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TrialStartRequest {
    pub email: String,
    #[serde(default)]
    pub org: String,
    pub skill: String,
}

pub async fn trial_start_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<TrialStartRequest>,
) -> ApiResult<LicenseStatus> {
    let email = req.email.trim();
    let skill = req.skill.trim();
    if email.is_empty() || !email.contains('@') {
        return Err((StatusCode::BAD_REQUEST, "valid email is required".into()));
    }
    if skill.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "skill id is required".into()));
    }
    let mgr = manager(&state)?;
    let status = mgr
        .start_trial(email, req.org.trim(), skill)
        .await
        .map_err(manager_err)?;
    Ok(Json(status))
}

// ── Heartbeat (manual refresh button) ───────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct HeartbeatRequest {
    /// Optional — when omitted, heartbeats every active license at once.
    #[serde(default)]
    pub license_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub status: LicenseStatus,
    pub message: String,
}

pub async fn heartbeat_handler(
    State(state): State<Arc<GatewayState>>,
    body: Option<Json<HeartbeatRequest>>,
) -> ApiResult<HeartbeatResponse> {
    let mgr = manager(&state)?;
    let key_opt = body.and_then(|Json(b)| b.license_key);
    mgr.heartbeat(key_opt.as_deref())
        .await
        .map_err(manager_err)?;
    Ok(Json(HeartbeatResponse {
        status: mgr.status().await,
        message: "license certificate refreshed".into(),
    }))
}

// ── Portal session (Stripe billing portal URL) ──────────────────────

#[derive(Debug, Deserialize, Default)]
pub struct PortalSessionRequest {
    pub license_key: String,
    /// Where Stripe should redirect after the customer closes the
    /// portal. Defaults server-side to the agent's own /license page
    /// when empty.
    #[serde(default)]
    pub return_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PortalSessionResponse {
    pub url: String,
}

pub async fn portal_session_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<PortalSessionRequest>,
) -> ApiResult<PortalSessionResponse> {
    let key = req.license_key.trim();
    if key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "license_key is required".into()));
    }
    let mgr = manager(&state)?;
    let response = mgr
        .portal_session(key, req.return_url.as_deref())
        .await
        .map_err(manager_err)?;
    Ok(Json(PortalSessionResponse { url: response.url }))
}

// ── Deactivate (release activation slot for one license) ────────────

#[derive(Debug, Deserialize)]
pub struct DeactivateRequest {
    pub license_key: String,
}

#[derive(Debug, Serialize)]
pub struct DeactivateResponse {
    pub message: String,
    pub status: LicenseStatus,
}

pub async fn deactivate_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<DeactivateRequest>,
) -> ApiResult<DeactivateResponse> {
    let key = req.license_key.trim();
    if key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "license_key is required".into()));
    }
    let mgr = manager(&state)?;
    mgr.deactivate(key).await.map_err(manager_err)?;
    Ok(Json(DeactivateResponse {
        message: format!(
            "license {key} deactivated locally — activation slot released on the license server"
        ),
        status: mgr.status().await,
    }))
}
