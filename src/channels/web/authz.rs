//! Server-side authorization middleware for `/api/tc/*`.
//!
//! Runs after the bearer `auth_middleware` (which authenticates the proxy).
//! This layer authenticates the *user*: it resolves the `tc_session` cookie
//! (forwarded by the proxy), computes the caller's effective permissions, and
//! enforces the route's required permission. Deny-by-default — a mutating route
//! that escapes the mapping is locked to admin (see `permissions::route_permission`).

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::dashboard_auth::{extract_session_cookie, validate_session};
use super::permissions::{RoutePolicy, effective_permissions, route_permission};
use super::server::GatewayState;

pub async fn require_permission_middleware(
    State(state): State<Arc<GatewayState>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    match route_permission(&method, &path) {
        // Not an /api/tc route, or machine ingress validated by webhook_token in
        // the handler — no dashboard session required here.
        RoutePolicy::Public | RoutePolicy::MachineToken => next.run(request).await,
        RoutePolicy::Require(perm) => {
            let Some(store) = state.store.as_ref() else {
                return (StatusCode::INTERNAL_SERVER_ERROR, "db not initialised").into_response();
            };
            let cookie = request
                .headers()
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let Some(token) = extract_session_cookie(cookie) else {
                return (StatusCode::UNAUTHORIZED, "not authenticated").into_response();
            };
            let Some(user) = validate_session(store, &token).await else {
                return (StatusCode::UNAUTHORIZED, "invalid session").into_response();
            };
            let perms = effective_permissions(&user.role, &user.granted, &user.denied);
            if !perms.contains(perm) {
                return (StatusCode::FORBIDDEN, "insufficient permissions").into_response();
            }
            next.run(request).await
        }
    }
}
