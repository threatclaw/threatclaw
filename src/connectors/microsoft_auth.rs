//! Shared Microsoft OAuth client-credentials auth for Graph and Sentinel connectors.
//!
//! Both `microsoft_graph` and `microsoft_sentinel` use the same App Registration
//! against the v2.0 token endpoint, with different scopes:
//! - Graph:    `https://graph.microsoft.com/.default`
//! - Sentinel: `https://management.azure.com/.default`
//! - LogAnalytics (phase 2 Hunt Tool): `https://api.loganalytics.io/.default`
//!
//! This module owns: `AuthMethod` parsing, a token cache keyed by
//! `(tenant, client, scope)`, token acquisition with both certificate
//! (PS256) and secret flows, and a shared `reqwest::Client` builder plus a
//! retry helper that honours `Retry-After` on 429 and exponential backoff
//! with jitter on 5xx.
//!
//! The JWT client-assertion builder was moved verbatim out of
//! `microsoft_graph.rs` (function-body kept identical, only the return
//! type was rebadged to `AuthError`). The graph connector re-exports the
//! builder via a thin wrapper so its existing call sites and tests remain
//! green until Task 4 rewires it to consume this module end-to-end.

use reqwest::{Client, Request, Response};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// AuthMethod
// ---------------------------------------------------------------------------

/// Auth method selected by the operator in the skill config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Certificate,
    Secret,
}

impl AuthMethod {
    /// Parse the raw string stored in `skill_configs`.
    ///
    /// Defaults to `Certificate` for any unrecognised value — that matches
    /// the recommended production path in the plan and avoids accidentally
    /// falling back to the weaker credential type on a typo.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "secret" | "client_secret" => Self::Secret,
            _ => Self::Certificate,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed error returned by token acquisition. Mapped by callers
/// (microsoft_graph maps it into `GraphError::Jwt`/`GraphError::AuthRejected`,
/// microsoft_sentinel will map it into its own error type) for the
/// dashboard.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("token endpoint HTTP {0}: {1}")]
    TokenEndpoint(u16, String),
    #[error("token response parse failed: {0}")]
    Parse(String),
    #[error("client assertion JWT signing failed: {0}")]
    JwtSigning(String),
    #[error("transport: {0}")]
    Transport(String),
}

impl From<reqwest::Error> for AuthError {
    fn from(e: reqwest::Error) -> Self {
        AuthError::Transport(e.to_string())
    }
}

/// Typed error for the shared HTTP retry helper.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("retries exhausted: last status {0}")]
    RetriesExhausted(u16),
    #[error("transport: {0}")]
    Transport(String),
}

impl From<reqwest::Error> for HttpError {
    fn from(e: reqwest::Error) -> Self {
        HttpError::Transport(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Token cache
// ---------------------------------------------------------------------------

#[derive(Clone, Eq, PartialEq, Hash)]
struct TokenKey {
    tenant_id: String,
    client_id: String,
    scope: String,
}

struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Per-tenant per-scope in-memory token cache.
///
/// Keyed by `(tenant_id, client_id, scope)` so Graph and Sentinel tokens
/// coexist for the same App Registration without invalidating each other.
/// Refresh happens at 80% of `expires_in`, giving the scheduler ~10 min of
/// slack on a 60 min token.
#[derive(Default, Clone)]
pub struct MicrosoftAuthCache {
    inner: Arc<Mutex<HashMap<TokenKey, CachedToken>>>,
}

impl MicrosoftAuthCache {
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Token acquisition
// ---------------------------------------------------------------------------

/// Acquire (or return cached) access token for `scope` on `tenant`.
///
/// `credential` is interpreted according to `auth`:
/// - `Secret`: the raw `client_secret` value
/// - `Certificate`: a single PEM block containing both the leaf X.509
///   certificate (`-----BEGIN CERTIFICATE-----`) AND the matching RSA
///   private key (`-----BEGIN PRIVATE KEY-----` or
///   `-----BEGIN RSA PRIVATE KEY-----`). The function splits them
///   internally; both must be present.
pub async fn acquire_token(
    cache: &MicrosoftAuthCache,
    client: &Client,
    tenant: &str,
    client_id: &str,
    auth: AuthMethod,
    credential: &SecretString,
    scope: &str,
) -> Result<String, AuthError> {
    let key = TokenKey {
        tenant_id: tenant.to_string(),
        client_id: client_id.to_string(),
        scope: scope.to_string(),
    };

    // Fast path — still fresh.
    {
        let cache_guard = cache.inner.lock().await;
        if let Some(cached) = cache_guard.get(&key) {
            if cached.expires_at > Instant::now() {
                return Ok(cached.token.clone());
            }
        }
    }

    let token_endpoint = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");

    let mut form: Vec<(&str, String)> = vec![
        ("client_id", client_id.to_string()),
        ("scope", scope.to_string()),
        ("grant_type", "client_credentials".to_string()),
    ];

    match auth {
        AuthMethod::Secret => {
            form.push(("client_secret", credential.expose_secret().to_string()));
        }
        AuthMethod::Certificate => {
            let assertion = build_client_assertion_from_combined_pem(
                tenant,
                client_id,
                credential.expose_secret(),
            )?;
            form.push((
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
            ));
            form.push(("client_assertion", assertion));
        }
    }

    let issued_at = Instant::now();
    let resp = client.post(&token_endpoint).form(&form).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AuthError::TokenEndpoint(status.as_u16(), body));
    }

    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
        expires_in: u64,
    }
    let parsed: TokenResp = resp
        .json()
        .await
        .map_err(|e| AuthError::Parse(e.to_string()))?;

    // Refresh at 80% of expiry to avoid edge-of-window misses.
    let refresh_after = Duration::from_secs(parsed.expires_in.saturating_mul(80) / 100);
    let expires_at = issued_at + refresh_after;

    {
        let mut cache_guard = cache.inner.lock().await;
        cache_guard.insert(
            key,
            CachedToken {
                token: parsed.access_token.clone(),
                expires_at,
            },
        );
    }

    Ok(parsed.access_token)
}

/// Helper for `acquire_token`'s certificate path: the credential carries a
/// concatenated PEM bundle (cert + key) and we feed it to the canonical
/// `build_client_assertion` builder after splitting on its label markers.
fn build_client_assertion_from_combined_pem(
    tenant: &str,
    client_id: &str,
    combined_pem: &str,
) -> Result<String, AuthError> {
    let now_unix = current_unix_secs();
    build_client_assertion(tenant, client_id, combined_pem, combined_pem, now_unix)
}

// ---------------------------------------------------------------------------
// HTTP client + retry helper
// ---------------------------------------------------------------------------

/// Build the shared `reqwest::Client` used by both connectors.
///
/// Mirrors the options previously used in microsoft_graph.rs: rustls
/// native roots (already wired via the workspace `reqwest` features),
/// 30 s overall timeout, 10 s connect timeout, 90 s idle pool window.
pub fn build_http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_idle_timeout(Some(Duration::from_secs(90)))
        .user_agent("ThreatClaw/0.1 (microsoft-auth)")
        .build()
        .expect("microsoft_auth http client build")
}

/// Execute `req` with up to 3 retries on 429 and 5xx.
///
/// - On 429 we wait the exact `Retry-After` value (seconds). If absent,
///   we fall back to exponential backoff capped at 16 s.
/// - On 5xx we apply exponential backoff with a small deterministic
///   jitter (no `rand` dependency here — the helper is called from
///   shared code that should stay free of randomness for reproducibility).
/// - Anything else (success, client errors) returns the response so the
///   caller can interpret it.
pub async fn do_request_with_retry(client: &Client, req: Request) -> Result<Response, HttpError> {
    const MAX_RETRIES: u32 = 3;
    let mut attempt: u32 = 0;
    loop {
        let cloned = req
            .try_clone()
            .expect("Request must be cloneable for retry");
        let resp = client.execute(cloned).await?;
        let status = resp.status();

        if status.as_u16() == 429 {
            let wait = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| 2u64.pow(attempt.min(4)));
            tokio::time::sleep(Duration::from_secs(wait)).await;
        } else if status.is_server_error() && attempt < MAX_RETRIES {
            let base = 2u64.pow(attempt);
            let jitter = (base * 20) / 100; // 20% jitter
            let wait = base + (uniform_pseudo_random(attempt) % (jitter.max(1)));
            tokio::time::sleep(Duration::from_secs(wait)).await;
        } else {
            return Ok(resp);
        }
        attempt += 1;
        if attempt > MAX_RETRIES {
            return Err(HttpError::RetriesExhausted(status.as_u16()));
        }
    }
}

// Deterministic pseudo-jitter for retries (avoids extra rand dep here).
fn uniform_pseudo_random(seed: u32) -> u64 {
    (seed as u64).wrapping_mul(2654435761) & 0x7
}

// ---------------------------------------------------------------------------
// JWT client assertion (certificate auth) — MOVED VERBATIM from microsoft_graph.rs
// ---------------------------------------------------------------------------

/// Header that jsonwebtoken will serialise for our client-assertion JWT.
/// We cannot use `jsonwebtoken::Header` directly because it emits `alg`
/// but we also need `typ=JWT` and `x5t#S256` — the library handles all of
/// them via its struct fields, so this helper just wires them.
fn build_assertion_header(x5t_s256: &str) -> jsonwebtoken::Header {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
    header.typ = Some("JWT".into());
    header.x5t_s256 = Some(x5t_s256.to_string());
    header
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssertionClaims {
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub jti: String,
    pub nbf: u64,
    pub exp: u64,
    pub iat: u64,
}

/// Build the signed client-assertion JWT required by certificate auth.
///
/// `now_unix` is injected so unit tests can assert the exact payload
/// without clock-dependent flakiness. Production callers pass
/// `current_unix_secs()`.
///
/// The body of this function was MOVED VERBATIM from
/// `microsoft_graph.rs::build_client_assertion` — only the error type
/// changed (`GraphError::Jwt` → `AuthError::JwtSigning`) so the helper
/// can be reused across connectors. `microsoft_graph.rs` re-exports it
/// behind a thin adapter that re-wraps the error into `GraphError`.
pub fn build_client_assertion(
    tenant_id: &str,
    client_id: &str,
    cert_pem: &str,
    key_pem: &str,
    now_unix: u64,
) -> Result<String, AuthError> {
    use base64::Engine;

    // 1. Thumbprint — base64url(SHA-256(cert DER)). Microsoft docs (2025-10)
    //    require x5t#S256, not the legacy SHA-1 `x5t`.
    let cert_der = pem_body_decode(cert_pem, "CERTIFICATE")
        .map_err(|e| AuthError::JwtSigning(format!("cert pem: {e}")))?;
    let digest = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&cert_der);
        hasher.finalize()
    };
    let x5t_s256 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);

    // 2. Claims — 10 min max lifetime per Microsoft recommendation.
    let claims = AssertionClaims {
        aud: format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"),
        iss: client_id.into(),
        sub: client_id.into(),
        jti: uuid::Uuid::new_v4().to_string(),
        nbf: now_unix,
        exp: now_unix + 600,
        iat: now_unix,
    };

    // 3. Sign with PS256 (RSA-PSS / SHA-256). EncodingKey::from_rsa_pem
    //    accepts both PKCS#1 (BEGIN RSA PRIVATE KEY) and PKCS#8 (BEGIN
    //    PRIVATE KEY) — Entra's portal exports PKCS#8 by default.
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(key_pem.as_bytes())
        .map_err(|e| AuthError::JwtSigning(format!("private key pem: {e}")))?;
    let header = build_assertion_header(&x5t_s256);

    jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| AuthError::JwtSigning(format!("sign: {e}")))
}

/// Extract the base64-encoded body of a PEM block and decode it to bytes.
///
/// Handles CRLF/LF line endings, leading/trailing whitespace, and ignores
/// any content outside the BEGIN/END markers so multi-block PEMs (for
/// instance a cert followed by its issuer chain) degrade gracefully to
/// returning the first block — which is the leaf cert, the one we need.
pub(crate) fn pem_body_decode(pem: &str, label: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;

    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");

    let start = pem
        .find(&begin)
        .ok_or_else(|| format!("missing '{begin}'"))?;
    let after_begin = start + begin.len();
    let stop = pem[after_begin..]
        .find(&end)
        .ok_or_else(|| format!("missing '{end}'"))?
        + after_begin;

    let body: String = pem[after_begin..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| format!("base64: {e}"))
}

pub(crate) fn current_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_method_parse_certificate_default() {
        assert_eq!(AuthMethod::parse(""), AuthMethod::Certificate);
        assert_eq!(AuthMethod::parse("unknown"), AuthMethod::Certificate);
        assert_eq!(AuthMethod::parse("certificate"), AuthMethod::Certificate);
        assert_eq!(AuthMethod::parse("Certificate"), AuthMethod::Certificate);
    }

    #[test]
    fn auth_method_parse_secret_variants() {
        assert_eq!(AuthMethod::parse("secret"), AuthMethod::Secret);
        assert_eq!(AuthMethod::parse("client_secret"), AuthMethod::Secret);
        assert_eq!(AuthMethod::parse("SECRET"), AuthMethod::Secret);
        assert_eq!(AuthMethod::parse("  secret  "), AuthMethod::Secret);
    }
}
