//! HTTP client for `license.threatclaw.io`.
//!
//! Strict request/response typing, network errors classified into
//! retryable vs terminal, and a fixed timeout. Verifies TLS by default —
//! never relax this in production builds.
//!
//! Only the agent uses this. The license server itself is implemented
//! out-of-tree (Cloudflare Worker in the `threatclaw-premium` repo) and
//! its source is the contract for the wire format below.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Default endpoint. Overridable via the `THREATCLAW_LICENSE_API_URL`
/// environment variable for staging / e2e tests.
pub const DEFAULT_LICENSE_API_URL: &str = "https://license.threatclaw.io";

/// Bound on every HTTP call. The license server is on Cloudflare Workers
/// edge — this should comfortably cover the worst-case TLS handshake +
/// D1 query + Ed25519 sign anywhere on the planet.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// User-Agent string. Lets the operator distinguish agent versions in
/// the Worker access logs without leaking client identity.
fn user_agent() -> String {
    format!("threatclaw/{} (licensing; rust)", env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// Network error — DNS, TCP, TLS, timeout. Retryable.
    #[error("network error contacting license server: {0}")]
    Network(String),
    /// Server returned an unexpected status (5xx, malformed body, etc.).
    /// Retryable in most cases.
    #[error("license server transient error (status {status}): {message}")]
    Transient { status: u16, message: String },
    /// Server explicitly rejected the request — no retry will help.
    #[error("license server rejected the request: {kind} ({message})")]
    Rejected { kind: ApiRejection, message: String },
    /// Couldn't deserialize the response body. Treat as a server bug.
    #[error("malformed response from license server: {0}")]
    BadResponse(String),
}

/// Machine-readable rejection categories. The Worker returns one of these
/// in the JSON body's `error` field on 4xx responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiRejection {
    /// 401 — license key missing or unknown.
    Unauthenticated,
    /// 402 — subscription not active (cancelled, past_due past grace).
    SubscriptionInactive,
    /// 403 — license revoked.
    Revoked,
    /// 404 — license_key does not exist.
    NotFound,
    /// 409 — activation slot limit reached for this license.
    ActivationLimit,
    /// 409 — trial already consumed for this email or fingerprint.
    TrialAlreadyUsed,
    /// 422 — input validation (malformed email, bad UUID, etc.).
    BadRequest,
    /// 429 — rate limit hit.
    RateLimit,
    /// Anything else — server returned an unrecognized `error` code.
    Unknown,
}

impl ApiRejection {
    fn from_code(code: &str) -> Self {
        match code {
            "unauthenticated" => Self::Unauthenticated,
            "subscription_inactive" => Self::SubscriptionInactive,
            "revoked" => Self::Revoked,
            "not_found" => Self::NotFound,
            "activation_limit" => Self::ActivationLimit,
            "trial_already_used" => Self::TrialAlreadyUsed,
            "bad_request" => Self::BadRequest,
            "rate_limit" => Self::RateLimit,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for ApiRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Unauthenticated => "unauthenticated",
            Self::SubscriptionInactive => "subscription_inactive",
            Self::Revoked => "revoked",
            Self::NotFound => "not_found",
            Self::ActivationLimit => "activation_limit",
            Self::TrialAlreadyUsed => "trial_already_used",
            Self::BadRequest => "bad_request",
            Self::RateLimit => "rate_limit",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Common error envelope returned by the Worker on 4xx responses.
#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: String,
    #[serde(default)]
    message: String,
}

#[derive(Debug, Serialize)]
pub struct ActivateRequest<'a> {
    pub license_key: &'a str,
    pub install_id: &'a str,
    pub hostname: &'a str,
    pub site_fingerprint: &'a str,
    pub agent_version: &'a str,
    pub requested_skills: Vec<&'a str>,
}

#[derive(Debug, Serialize)]
pub struct TrialStartRequest<'a> {
    pub email: &'a str,
    pub org: &'a str,
    pub install_id: &'a str,
    pub hostname: &'a str,
    pub site_fingerprint: &'a str,
    pub agent_version: &'a str,
    pub requested_skill: &'a str,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatRequest<'a> {
    pub license_key: &'a str,
    pub install_id: &'a str,
    pub site_fingerprint: &'a str,
    pub agent_version: &'a str,
}

#[derive(Debug, Serialize)]
pub struct DeactivateRequest<'a> {
    pub license_key: &'a str,
    pub install_id: &'a str,
}

/// Returned by `/api/activate`, `/api/trial/start`, `/api/heartbeat`.
/// The `cert` is the base64-encoded `.tcl` envelope ready to feed to
/// [`crate::licensing::SignedLicense::decode`].
#[derive(Debug, Deserialize)]
pub struct CertResponse {
    pub cert: String,
    pub license_key: String,
    pub expires_at: u64,
    #[serde(default)]
    pub trial: bool,
}

#[derive(Debug, Deserialize)]
pub struct RevocationStatus {
    pub revoked: bool,
    #[serde(default)]
    pub reason: String,
}

/// Thin client over `reqwest::Client`. Cheap to clone (the underlying
/// connection pool is shared), so callers may keep a single instance
/// in the application state.
#[derive(Clone)]
pub struct LicenseClient {
    base_url: String,
    http: reqwest::Client,
}

impl LicenseClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .user_agent(user_agent())
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url: base_url.into(),
            http,
        }
    }

    /// Construct from environment, falling back to [`DEFAULT_LICENSE_API_URL`].
    pub fn from_env() -> Self {
        let url = std::env::var("THREATCLAW_LICENSE_API_URL")
            .unwrap_or_else(|_| DEFAULT_LICENSE_API_URL.to_string());
        Self::new(url)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn activate(&self, req: &ActivateRequest<'_>) -> Result<CertResponse, ApiError> {
        self.post_json("/api/activate", req).await
    }

    pub async fn start_trial(&self, req: &TrialStartRequest<'_>) -> Result<CertResponse, ApiError> {
        self.post_json("/api/trial/start", req).await
    }

    pub async fn heartbeat(&self, req: &HeartbeatRequest<'_>) -> Result<CertResponse, ApiError> {
        self.post_json("/api/heartbeat", req).await
    }

    pub async fn deactivate(&self, req: &DeactivateRequest<'_>) -> Result<(), ApiError> {
        let _: serde_json::Value = self.post_json("/api/deactivate", req).await?;
        Ok(())
    }

    pub async fn check_revocation(&self, license_key: &str) -> Result<RevocationStatus, ApiError> {
        let url = format!("{}/api/check-revocation", self.base_url);
        let resp = self
            .http
            .get(&url)
            .query(&[("license_key", license_key)])
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        self.parse_response(resp).await
    }

    async fn post_json<Req, Resp>(&self, path: &str, body: &Req) -> Result<Resp, ApiError>
    where
        Req: Serialize + ?Sized,
        Resp: for<'de> Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?;
        self.parse_response(resp).await
    }

    async fn parse_response<Resp>(&self, resp: reqwest::Response) -> Result<Resp, ApiError>
    where
        Resp: for<'de> Deserialize<'de>,
    {
        let status = resp.status();
        if status.is_success() {
            return resp
                .json::<Resp>()
                .await
                .map_err(|e| ApiError::BadResponse(e.to_string()));
        }

        let code = status.as_u16();
        let body_text = resp.text().await.unwrap_or_default();

        // Try to parse a structured error envelope first.
        if let Ok(env) = serde_json::from_str::<ErrorEnvelope>(&body_text) {
            if (400..500).contains(&code) {
                return Err(ApiError::Rejected {
                    kind: ApiRejection::from_code(&env.error),
                    message: if env.message.is_empty() {
                        env.error
                    } else {
                        env.message
                    },
                });
            }
            return Err(ApiError::Transient {
                status: code,
                message: env.message,
            });
        }

        if (400..500).contains(&code) {
            Err(ApiError::Rejected {
                kind: ApiRejection::Unknown,
                message: body_text,
            })
        } else {
            Err(ApiError::Transient {
                status: code,
                message: body_text,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_codes_round_trip() {
        for (code, expected) in [
            ("unauthenticated", ApiRejection::Unauthenticated),
            ("subscription_inactive", ApiRejection::SubscriptionInactive),
            ("revoked", ApiRejection::Revoked),
            ("not_found", ApiRejection::NotFound),
            ("activation_limit", ApiRejection::ActivationLimit),
            ("trial_already_used", ApiRejection::TrialAlreadyUsed),
            ("bad_request", ApiRejection::BadRequest),
            ("rate_limit", ApiRejection::RateLimit),
            ("flux-capacitor-down", ApiRejection::Unknown),
        ] {
            assert_eq!(ApiRejection::from_code(code), expected, "code {code}");
        }
    }

    #[test]
    fn user_agent_includes_crate_version() {
        let ua = user_agent();
        assert!(ua.starts_with("threatclaw/"));
        assert!(ua.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn from_env_respects_override() {
        // SAFETY: tests run in single-threaded context for env vars
        unsafe {
            std::env::set_var("THREATCLAW_LICENSE_API_URL", "https://staging.example.com");
        }
        let c = LicenseClient::from_env();
        assert_eq!(c.base_url(), "https://staging.example.com");
        unsafe {
            std::env::remove_var("THREATCLAW_LICENSE_API_URL");
        }
        let c2 = LicenseClient::from_env();
        assert_eq!(c2.base_url(), DEFAULT_LICENSE_API_URL);
    }
}
