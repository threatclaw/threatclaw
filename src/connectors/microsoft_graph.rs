//! Microsoft Graph connector — Microsoft 365 / Entra ID ingestion.
//!
//! Read-only connector targeting the biggest detection gap for SMBs: M365.
//! Pulls sign-in logs, directory audits, users, devices, Defender alerts and
//! surfaces the top compromise indicators (mail auto-forward rules, illicit
//! OAuth consent grants, impossible travel, MFA fatigue, Global Admin
//! escalation).
//!
//! This file is Phase A only: it implements the foundation (auth, token
//! cache, retry-aware HTTP client, test_connection, probe_features). The
//! actual ingestion pullers land in Phase B in a separate commit.
//!
//! ## Authentication
//!
//! App-only OAuth 2.0 `client_credentials` flow against the v2.0 token
//! endpoint. Both authentication methods are supported:
//!
//! - **Certificate** (recommended). A client-assertion JWT is signed with
//!   the app's private key and sent as `client_assertion`. Conforms to the
//!   2025 Microsoft guidance: `alg=PS256`, `x5t#S256` header carrying the
//!   base64url-encoded SHA-256 thumbprint of the certificate's DER form.
//!   See: <https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials>
//!
//! - **Secret**. Plain `client_secret` in the POST body. Simpler, max 24
//!   months lifetime, easier to leak. Provided for quick testing only.
//!
//! Tokens are cached in memory per-tenant and refreshed at 80% of
//! `expires_in`. They are never logged and never persisted to disk.
//!
//! ## Throttling
//!
//! Microsoft Graph enforces a global 130k requests / 10 s per app across all
//! tenants. On HTTP 429 the server returns a `Retry-After` header which
//! this client respects exactly — no earlier retry, no backoff override.
//! For 5xx responses we fall back to exponential backoff with jitter.

use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Configuration
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

/// Configuration for a single Microsoft 365 tenant.
///
/// Built by `sync_scheduler` from the rows stored in `skill_configs` under
/// the `skill-microsoft-graph` skill id. Credentials never leave this
/// struct — in particular we do not implement `Debug` manually so that a
/// careless `{:?}` print would still serialize the fields; we rely on the
/// caller never logging this value. `validate()` enforces the minimum set
/// of fields for the chosen auth method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrosoftGraphConfig {
    /// Directory (tenant) ID — GUID.
    pub tenant_id: String,
    /// Application (client) ID — GUID.
    pub client_id: String,
    pub auth_method: AuthMethod,

    /// Client secret value. Required when `auth_method == Secret`.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// PEM-encoded X.509 certificate. Required when `auth_method ==
    /// Certificate`. Must include the `-----BEGIN CERTIFICATE-----`
    /// header; multi-cert bundles are not accepted.
    #[serde(default)]
    pub client_cert_pem: Option<String>,

    /// PEM-encoded RSA private key matching `client_cert_pem`. PKCS#1
    /// (`-----BEGIN RSA PRIVATE KEY-----`) and PKCS#8 (`-----BEGIN PRIVATE
    /// KEY-----`) are both accepted by `jsonwebtoken::EncodingKey`.
    #[serde(default)]
    pub client_key_pem: Option<String>,
}

impl MicrosoftGraphConfig {
    /// Check that the minimum set of fields is present for the selected
    /// auth method. Returns a message suitable for surfacing in the
    /// dashboard.
    pub fn validate(&self) -> Result<(), String> {
        if self.tenant_id.trim().is_empty() {
            return Err("tenant_id is required".into());
        }
        if self.client_id.trim().is_empty() {
            return Err("client_id is required".into());
        }
        match self.auth_method {
            AuthMethod::Secret => {
                if self
                    .client_secret
                    .as_deref()
                    .map(|s| s.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err("client_secret is required when auth_method=secret".into());
                }
            }
            AuthMethod::Certificate => {
                if self
                    .client_cert_pem
                    .as_deref()
                    .map(|s| s.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err("client_cert_pem is required when auth_method=certificate".into());
                }
                if self
                    .client_key_pem
                    .as_deref()
                    .map(|s| s.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err("client_key_pem is required when auth_method=certificate".into());
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed error returned by the Graph client. Callers (the sync scheduler,
/// the test-connection handler) pattern-match on this to produce
/// actionable messages in the dashboard.
#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    /// Config is missing or malformed — surfaces immediately, no call made.
    #[error("config: {0}")]
    Config(String),

    /// Failed to build a client-assertion JWT. Typically a bad PEM.
    #[error("jwt: {0}")]
    Jwt(String),

    /// AAD rejected the credentials (401) or the token endpoint returned a
    /// specific OAuth error body.
    #[error("auth rejected: {0}")]
    AuthRejected(String),

    /// Admin consent has not been granted on the tenant — the token was
    /// issued but the API call came back with `Authorization_RequestDenied`.
    #[error("admin consent missing for tenant")]
    ConsentMissing,

    /// Returned by a probe call when a scope is not covered by the
    /// tenant's licences (e.g. P2 features without P2).
    #[error("licence limitation: {0}")]
    LicenceLimited(String),

    /// 403 that is neither of the above — returned so the caller can
    /// surface the raw Graph message.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// 429 after all retries exhausted. The field is the last
    /// `Retry-After` value in seconds.
    #[error("throttled, retry-after {0}s")]
    Throttled(u64),

    /// Any 5xx or network-level failure after retries.
    #[error("upstream: {0}")]
    Upstream(String),

    /// Transport-level failure (DNS, TLS, connection reset, …).
    #[error("http: {0}")]
    Http(String),

    /// Response body did not match the expected schema.
    #[error("parse: {0}")]
    Parse(String),
}

impl From<reqwest::Error> for GraphError {
    fn from(e: reqwest::Error) -> Self {
        GraphError::Http(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Token acquisition + cache
// ---------------------------------------------------------------------------

/// A live Graph access token with its expiry wall-clock deadline.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    /// Refresh moment — 80% of `expires_in` past the issue instant, not the
    /// raw `exp`. Gives the scheduler ~10 min of slack on a 60 min token.
    refresh_at: Instant,
}

/// Per-tenant in-memory token cache.
///
/// The cache is keyed by `(tenant_id, client_id, auth_method)` so that
/// switching credentials (rotating a secret to a cert) invalidates the old
/// entry automatically. In the single-tenant ThreatClaw deployment model
/// (rule absolue #1), the cache has exactly one entry most of the time.
#[derive(Default)]
pub struct TokenCache {
    entries: Mutex<HashMap<String, CachedToken>>,
}

impl TokenCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(config: &MicrosoftGraphConfig) -> String {
        format!(
            "{}|{}|{:?}",
            config.tenant_id, config.client_id, config.auth_method
        )
    }

    /// Return the cached token if it is still within its refresh window,
    /// otherwise acquire a new one.
    pub async fn get_or_refresh(
        &self,
        http: &Client,
        config: &MicrosoftGraphConfig,
    ) -> Result<String, GraphError> {
        let key = Self::key(config);

        // Fast path — still fresh.
        {
            let guard = self.entries.lock().await;
            if let Some(tok) = guard.get(&key) {
                if Instant::now() < tok.refresh_at {
                    return Ok(tok.access_token.clone());
                }
            }
        }

        // Slow path — acquire a new token. We release the lock during the
        // network call so concurrent callers don't serialise on the mutex;
        // worst case we acquire twice on first boot, which AAD tolerates.
        let fresh = acquire_token(http, config).await?;
        let mut guard = self.entries.lock().await;
        guard.insert(key, fresh.clone());
        Ok(fresh.access_token)
    }

    /// Force the cached entry to be re-acquired on the next call. Useful
    /// for test hooks and for responding to an `invalid_token` 401 from a
    /// downstream call that was served from a stale cache.
    pub async fn invalidate(&self, config: &MicrosoftGraphConfig) {
        let key = Self::key(config);
        let mut guard = self.entries.lock().await;
        guard.remove(&key);
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: String,
}

/// Raw token acquisition — talks to
/// `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`.
async fn acquire_token(
    http: &Client,
    config: &MicrosoftGraphConfig,
) -> Result<CachedToken, GraphError> {
    config.validate().map_err(GraphError::Config)?;

    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        config.tenant_id
    );

    let mut form: Vec<(&str, String)> = vec![
        ("client_id", config.client_id.clone()),
        ("grant_type", "client_credentials".into()),
        ("scope", "https://graph.microsoft.com/.default".into()),
    ];

    match config.auth_method {
        AuthMethod::Secret => {
            let secret = config
                .client_secret
                .as_ref()
                .expect("validate() enforces presence");
            form.push(("client_secret", secret.clone()));
        }
        AuthMethod::Certificate => {
            let cert_pem = config
                .client_cert_pem
                .as_ref()
                .expect("validate() enforces presence");
            let key_pem = config
                .client_key_pem
                .as_ref()
                .expect("validate() enforces presence");
            let assertion = build_client_assertion(
                &config.tenant_id,
                &config.client_id,
                cert_pem,
                key_pem,
                current_unix_secs(),
            )?;
            form.push((
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            ));
            form.push(("client_assertion", assertion));
        }
    }

    let issued_at = Instant::now();
    let res = http
        .post(&token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| GraphError::Http(format!("token endpoint: {e}")))?;

    let status = res.status();
    let body = res
        .text()
        .await
        .map_err(|e| GraphError::Http(format!("token body: {e}")))?;

    if !status.is_success() {
        // AAD error envelope is well-defined: {"error":"...","error_description":"..."}.
        // We strip the correlation IDs from the description so it is safe
        // to surface but we keep the error code for the dashboard mapping.
        let (code, desc) = match serde_json::from_str::<TokenErrorResponse>(&body) {
            Ok(err) => (err.error, err.error_description),
            Err(_) => (status.as_str().into(), body.clone()),
        };
        return Err(GraphError::AuthRejected(format!(
            "{code} — {}",
            scrub_correlation(&desc)
        )));
    }

    let parsed: TokenResponse = serde_json::from_str(&body)
        .map_err(|e| GraphError::Parse(format!("token response: {e}")))?;

    // Refresh at 80% of expires_in. A typical Graph token is 3600s, so
    // that gives ~720s of headroom between the client-side refresh and
    // the server-side expiry — enough to survive a stalled sync cycle
    // without hitting a mid-request 401.
    let refresh_window = Duration::from_secs(parsed.expires_in.saturating_mul(80) / 100);
    Ok(CachedToken {
        access_token: parsed.access_token,
        refresh_at: issued_at + refresh_window,
    })
}

/// Drop AAD `Trace ID` / `Correlation ID` blobs from an error description.
/// These are not secrets but they include customer-specific IDs we would
/// rather not surface to the dashboard UI. The kept portion is the human
/// sentence that describes the failure.
fn scrub_correlation(desc: &str) -> String {
    // Typical format: "AADSTS70011: The provided value for scope is not
    // valid.\r\nTrace ID: abc\r\nCorrelation ID: xyz\r\nTimestamp: ..."
    desc.split("Trace ID:")
        .next()
        .unwrap_or(desc)
        .trim()
        .to_string()
}

fn current_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// JWT client assertion (certificate auth)
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
struct AssertionClaims {
    aud: String,
    iss: String,
    sub: String,
    jti: String,
    nbf: u64,
    exp: u64,
    iat: u64,
}

/// Build the signed client-assertion JWT required by certificate auth.
///
/// `now_unix` is injected so unit tests can assert the exact payload
/// without clock-dependent flakiness. Production callers pass
/// `current_unix_secs()`.
pub fn build_client_assertion(
    tenant_id: &str,
    client_id: &str,
    cert_pem: &str,
    key_pem: &str,
    now_unix: u64,
) -> Result<String, GraphError> {
    use base64::Engine;

    // 1. Thumbprint — base64url(SHA-256(cert DER)). Microsoft docs (2025-10)
    //    require x5t#S256, not the legacy SHA-1 `x5t`.
    let cert_der = pem_body_decode(cert_pem, "CERTIFICATE")
        .map_err(|e| GraphError::Jwt(format!("cert pem: {e}")))?;
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
        .map_err(|e| GraphError::Jwt(format!("private key pem: {e}")))?;
    let header = build_assertion_header(&x5t_s256);

    jsonwebtoken::encode(&header, &claims, &key).map_err(|e| GraphError::Jwt(format!("sign: {e}")))
}

/// Extract the base64-encoded body of a PEM block and decode it to bytes.
///
/// Handles CRLF/LF line endings, leading/trailing whitespace, and ignores
/// any content outside the BEGIN/END markers so multi-block PEMs (for
/// instance a cert followed by its issuer chain) degrade gracefully to
/// returning the first block — which is the leaf cert, the one we need.
fn pem_body_decode(pem: &str, label: &str) -> Result<Vec<u8>, String> {
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

// ---------------------------------------------------------------------------
// Graph HTTP client with retry logic
// ---------------------------------------------------------------------------

const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";

/// Graph client — a reqwest client plus a token cache plus retry logic.
///
/// One instance can be reused across all Phase-B pullers for the same
/// tenant. Token acquisition is lazy, done on the first request and
/// transparently refreshed afterwards.
pub struct GraphClient {
    http: Client,
    config: MicrosoftGraphConfig,
    tokens: Arc<TokenCache>,
    /// Max retry attempts on 429 / 5xx before giving up. 4 is enough to
    /// survive a typical AAD maintenance blip (~30 s) without turning a
    /// transient blip into a sync-blocking hang.
    max_retries: u32,
}

impl GraphClient {
    pub fn new(config: MicrosoftGraphConfig) -> Result<Self, GraphError> {
        config.validate().map_err(GraphError::Config)?;
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ThreatClaw/0.1 (skill-microsoft-graph)")
            .build()
            .map_err(|e| GraphError::Http(format!("build client: {e}")))?;
        Ok(Self {
            http,
            config,
            tokens: Arc::new(TokenCache::new()),
            max_retries: 4,
        })
    }

    /// Override the retry cap — tests use a lower value.
    #[doc(hidden)]
    pub fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Issue a GET to `{GRAPH_BASE}{path}` and deserialise the JSON body.
    /// Handles token refresh, 401 retry after token invalidate, 429 with
    /// exact `Retry-After`, and 5xx with exponential backoff + jitter.
    pub async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, GraphError> {
        let raw = self.get_raw(path).await?;
        serde_json::from_slice(&raw).map_err(|e| GraphError::Parse(format!("{path}: {e}")))
    }

    /// Raw bytes of a GET response body. Useful when the caller wants to
    /// process the body incrementally (large signIns page, for example).
    pub async fn get_raw(&self, path: &str) -> Result<Vec<u8>, GraphError> {
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{GRAPH_BASE}{path}")
        };

        let mut attempt = 0u32;
        let mut tried_refresh = false;

        loop {
            let token = self.tokens.get_or_refresh(&self.http, &self.config).await?;
            let res = self
                .http
                .get(&url)
                .bearer_auth(&token)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| GraphError::Http(format!("GET {url}: {e}")))?;

            let status = res.status();

            // 401 — stale cached token. Force refresh exactly once, then retry.
            if status == StatusCode::UNAUTHORIZED && !tried_refresh {
                tried_refresh = true;
                self.tokens.invalidate(&self.config).await;
                continue;
            }

            // 429 — Retry-After is mandatory. We wait exactly what MS asks,
            // no earlier (throttling doc is explicit on this).
            if status == StatusCode::TOO_MANY_REQUESTS {
                let wait = retry_after_secs(&res).unwrap_or(30);
                if attempt >= self.max_retries {
                    return Err(GraphError::Throttled(wait));
                }
                attempt += 1;
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }

            // 5xx — transient. Backoff + jitter, cap at 60 s per attempt.
            if status.is_server_error() {
                if attempt >= self.max_retries {
                    let body = res.text().await.unwrap_or_default();
                    return Err(GraphError::Upstream(format!(
                        "{status} after {} retries: {}",
                        self.max_retries,
                        truncate(&body, 200)
                    )));
                }
                attempt += 1;
                tokio::time::sleep(backoff_delay(attempt)).await;
                continue;
            }

            if !status.is_success() {
                return Err(map_client_error(status, res).await);
            }

            return res
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| GraphError::Http(format!("read body {url}: {e}")));
        }
    }
}

/// Parse `Retry-After`. Microsoft always sends an integer number of
/// seconds on 429 so we only handle that form — HTTP-date is legal but
/// the Graph docs don't use it.
fn retry_after_secs(res: &Response) -> Option<u64> {
    res.headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// Exponential backoff with jitter. attempt 1 → ~1s, 2 → ~2s, 3 → ~4s…
/// capped at 60s. The jitter is ±25% so N concurrent pullers hitting the
/// same 5xx do not synchronise their retries.
fn backoff_delay(attempt: u32) -> Duration {
    use rand::Rng;
    let base = 1u64 << attempt.min(6); // 2, 4, 8, 16, 32, 64
    let capped = base.min(60);
    let jitter = rand::thread_rng().gen_range(-(capped as i64) / 4..=(capped as i64) / 4);
    Duration::from_secs((capped as i64 + jitter).max(1) as u64)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.into()
    } else {
        format!("{}…", &s[..max])
    }
}

/// Map a non-2xx, non-429, non-5xx response into the typed error. We
/// consume the body here so the caller doesn't have to juggle Response
/// ownership.
async fn map_client_error(status: StatusCode, res: Response) -> GraphError {
    let body = res.text().await.unwrap_or_default();
    let code = parse_graph_error_code(&body);

    match (status, code.as_deref()) {
        (StatusCode::UNAUTHORIZED, _) => GraphError::AuthRejected(truncate(&body, 200)),
        (StatusCode::FORBIDDEN, Some("Authorization_RequestDenied")) => GraphError::ConsentMissing,
        // Both identityProtection endpoints return 403 with this code on a
        // tenant without P2. We map it to a distinct variant so the
        // dashboard can render "P2 required" instead of a scary red cross.
        (StatusCode::FORBIDDEN, Some(c))
            if c.contains("License") || c.contains("Tenant") || c.contains("Sku") =>
        {
            GraphError::LicenceLimited(truncate(&body, 200))
        }
        (StatusCode::FORBIDDEN, _) => GraphError::Forbidden(truncate(&body, 200)),
        _ => GraphError::Upstream(format!("{status}: {}", truncate(&body, 200))),
    }
}

/// Extract the `error.code` field from a Microsoft Graph error body. The
/// shape is always `{"error":{"code":"...","message":"..."}}`.
fn parse_graph_error_code(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("error")?.get("code")?.as_str().map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Test connection — the canary call
// ---------------------------------------------------------------------------

/// Response from `test_connection`. Serialised directly to the dashboard
/// via the handler in `threatclaw_api.rs`, so field names are UI-facing.
#[derive(Debug, Clone, Serialize)]
pub struct TestConnectionResult {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Plans detected from `assignedPlans.servicePlanName`. Empty if the
    /// `/organization` endpoint didn't return any — unusual but possible
    /// on brand-new tenants before licence assignment.
    pub plans: Vec<String>,
    /// Whether the tenant has at least one P1/P2/Defender licence — used
    /// by the UI to decide which advanced modules to enable by default.
    pub has_p1: bool,
    pub has_p2: bool,
    pub has_defender: bool,
}

/// Call `GET /organization` and interpret the response.
///
/// This is the single canary call exposed to the dashboard: it proves the
/// entire chain (creds → token → authorised Graph call) in one round-trip
/// and returns enough licence info for the UI to auto-configure the
/// feature probe matrix afterwards.
pub async fn test_connection(client: &GraphClient) -> Result<TestConnectionResult, GraphError> {
    #[derive(Deserialize)]
    struct OrgResponse {
        value: Vec<Org>,
    }
    #[derive(Deserialize)]
    struct Org {
        id: String,
        #[serde(rename = "displayName")]
        display_name: Option<String>,
        #[serde(default, rename = "assignedPlans")]
        assigned_plans: Vec<AssignedPlan>,
    }
    #[derive(Deserialize)]
    struct AssignedPlan {
        /// The service family name (e.g. "exchange", "YammerEnterprise").
        /// Present on every plan entry; human-readable but coarse.
        #[serde(default)]
        service: Option<String>,
        /// Stable GUID that identifies the exact service plan (e.g. the
        /// Entra ID P1 plan has its own GUID). This is what Microsoft's
        /// licensing-service-plan-reference documents as the stable key.
        /// The `servicePlanName` field the previous version of this code
        /// parsed does NOT appear on `/organization/assignedPlans` —
        /// only `/subscribedSkus/servicePlans` carries it. Regression
        /// caught live against a real E5 trial tenant on 2026-04-23.
        #[serde(rename = "servicePlanId")]
        service_plan_id: Option<String>,
        #[serde(rename = "capabilityStatus")]
        capability_status: Option<String>,
    }

    let r: OrgResponse = client.get_json("/organization").await?;
    let org = r
        .value
        .into_iter()
        .next()
        .ok_or_else(|| GraphError::Parse("/organization returned empty value".into()))?;

    // Keep only plans with capabilityStatus == Enabled — MS leaves
    // expired/disabled plans in the list with other statuses. The
    // "plans" list exposed to the dashboard carries the `service`
    // family name (useful to humans), while SKU detection keys off
    // the stable `servicePlanId` GUID (robust to localisation /
    // rename across tenants).
    let (plan_ids, plans): (Vec<String>, Vec<String>) = org
        .assigned_plans
        .into_iter()
        .filter(|p| {
            p.capability_status
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case("Enabled"))
                .unwrap_or(false)
        })
        .map(|p| {
            (
                p.service_plan_id.unwrap_or_default(),
                p.service.unwrap_or_default(),
            )
        })
        .filter(|(id, _)| !id.is_empty())
        .unzip();

    // SKU detection — GUIDs from
    // <https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference>
    // and cross-checked against real /organization responses. These
    // are stable across every tenant worldwide.
    const PLAN_AAD_PREMIUM_P1: &str = "41781fb2-bc02-4b7c-bd55-b576c07bb09d";
    const PLAN_AAD_PREMIUM_P2: &str = "eec0eb4f-6444-4f95-aba0-50c24d67f998";
    const PLAN_DEFENDER_FOR_ENDPOINT_P1: &str = "292cc034-7b7c-4950-aaf5-943befd3f1d4";
    const PLAN_DEFENDER_FOR_ENDPOINT_P2: &str = "871d91ec-ec1a-452b-a83f-bd76c7d770ef";
    // Several SKUs expose DfE under different GUIDs depending on the
    // suite (E5 standalone vs MDE-Lite via Business Premium); list the
    // major ones so the UI can light up Defender without the customer
    // having to know which flavour they bought.
    const PLAN_MDE_LITE: &str = "292cc034-7b7c-4950-aaf5-943befd3f1d4";
    const PLAN_ATP_ENTERPRISE: &str = "8e0c0a52-6a6c-4d40-8370-dd62790dcd70";

    let has_plan = |target: &str| plan_ids.iter().any(|id| id.eq_ignore_ascii_case(target));
    let has_p1 = has_plan(PLAN_AAD_PREMIUM_P1) || has_plan(PLAN_AAD_PREMIUM_P2);
    let has_p2 = has_plan(PLAN_AAD_PREMIUM_P2);
    let has_defender = has_plan(PLAN_DEFENDER_FOR_ENDPOINT_P1)
        || has_plan(PLAN_DEFENDER_FOR_ENDPOINT_P2)
        || has_plan(PLAN_MDE_LITE)
        || has_plan(PLAN_ATP_ENTERPRISE);

    let message = {
        let name = org.display_name.as_deref().unwrap_or("<unknown>");
        let mut tags = vec![];
        if has_p1 {
            tags.push("P1");
        }
        if has_p2 {
            tags.push("P2");
        }
        if has_defender {
            tags.push("Defender");
        }
        if tags.is_empty() {
            format!("Connected to {name} (no premium plans detected)")
        } else {
            format!("Connected to {name} — {}", tags.join(", "))
        }
    };

    Ok(TestConnectionResult {
        ok: true,
        message,
        tenant_display_name: org.display_name,
        tenant_id: Some(org.id),
        plans,
        has_p1,
        has_p2,
        has_defender,
    })
}

// ---------------------------------------------------------------------------
// Probe matrix — per-feature permission detection
// ---------------------------------------------------------------------------

/// Outcome for a single feature probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    /// API call succeeded — feature is active.
    Ok,
    /// 403 with `Authorization_RequestDenied` — admin consent is missing
    /// for this scope.
    ConsentMissing,
    /// 403 citing a licence/Sku/Tenant restriction — tenant doesn't have
    /// the required plan (typically P2 / E5).
    Unlicensed,
    /// 403 with any other reason.
    Forbidden,
    /// Other failure — network, 5xx, or unexpected parse error.
    Error,
}

/// Probe one feature of the Graph API — summary of what is reachable on
/// this tenant.
#[derive(Debug, Clone, Serialize)]
pub struct FeatureProbe {
    pub feature: &'static str,
    pub status: ProbeStatus,
    /// Short operator-facing hint. Empty when `status == Ok`.
    pub detail: String,
}

/// Full probe report. Returned to the dashboard so it can colour the
/// feature list green / yellow / red at setup time.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeReport {
    pub probes: Vec<FeatureProbe>,
}

/// Run one lightweight call per feature. Top=1 everywhere so the total
/// cost of the probe is bounded (~8 requests, <10 s in the common case).
pub async fn probe_features(client: &GraphClient) -> ProbeReport {
    // (feature label, path). Ordering matches the matrix in M365_PLAN.md so
    // the UI can render them in a stable, meaningful order.
    const FEATURES: &[(&str, &str)] = &[
        ("signIns", "/auditLogs/signIns?$top=1"),
        ("directoryAudits", "/auditLogs/directoryAudits?$top=1"),
        ("users", "/users?$top=1&$select=id"),
        ("groups", "/groups?$top=1&$select=id"),
        ("devices", "/devices?$top=1&$select=id"),
        (
            "managedDevices",
            "/deviceManagement/managedDevices?$top=1&$select=id",
        ),
        (
            "conditionalAccess",
            "/policies/conditionalAccessPolicies?$top=1",
        ),
        ("securityAlerts", "/security/alerts_v2?$top=1"),
        ("riskyUsers", "/identityProtection/riskyUsers?$top=1"),
        (
            "riskDetections",
            "/identityProtection/riskDetections?$top=1",
        ),
    ];

    let mut probes = Vec::with_capacity(FEATURES.len());
    for (feature, path) in FEATURES {
        let status_and_detail = match client.get_raw(path).await {
            Ok(_) => (ProbeStatus::Ok, String::new()),
            Err(GraphError::ConsentMissing) => (
                ProbeStatus::ConsentMissing,
                "admin consent missing for required scope".into(),
            ),
            Err(GraphError::LicenceLimited(m)) => (ProbeStatus::Unlicensed, m),
            Err(GraphError::Forbidden(m)) => (ProbeStatus::Forbidden, m),
            Err(e) => (ProbeStatus::Error, e.to_string()),
        };
        probes.push(FeatureProbe {
            feature,
            status: status_and_detail.0,
            detail: status_and_detail.1,
        });
    }
    ProbeReport { probes }
}

// ---------------------------------------------------------------------------
// Ingestion — Phase B pullers
// ---------------------------------------------------------------------------

/// Graph audit log entry — only the fields we care about for detection.
/// Schema reference: <https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit>.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    #[serde(rename = "activityDateTime")]
    pub activity_date_time: String,
    #[serde(rename = "activityDisplayName")]
    pub activity_display_name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub result: String,
    #[serde(default, rename = "initiatedBy")]
    pub initiated_by: serde_json::Value,
    #[serde(default, rename = "targetResources")]
    pub target_resources: Vec<serde_json::Value>,
    #[serde(default, rename = "additionalDetails")]
    pub additional_details: Vec<serde_json::Value>,
}

impl AuditEvent {
    /// UPN (user principal name) of whoever triggered the action, when
    /// available. App-initiated events return `None`.
    pub fn actor_upn(&self) -> Option<&str> {
        self.initiated_by
            .get("user")
            .and_then(|u| u.get("userPrincipalName"))
            .and_then(|v| v.as_str())
    }

    /// UPN of the first user-typed target resource. Returns `None` when
    /// the target is a role, an app, or a group.
    pub fn target_upn(&self) -> Option<&str> {
        self.target_resources
            .iter()
            .find(|r| {
                r.get("type")
                    .and_then(|t| t.as_str())
                    .map(|t| t == "User")
                    .unwrap_or(false)
            })
            .and_then(|r| r.get("userPrincipalName"))
            .and_then(|v| v.as_str())
    }
}

/// Graph sign-in entry — same idea, only the fields we need.
/// Schema: <https://learn.microsoft.com/en-us/graph/api/resources/signin>.
#[derive(Debug, Clone, Deserialize)]
pub struct SignInEvent {
    pub id: String,
    #[serde(rename = "createdDateTime")]
    pub created_date_time: String,
    #[serde(default, rename = "userPrincipalName")]
    pub user_principal_name: String,
    #[serde(default, rename = "ipAddress")]
    pub ip_address: String,
    #[serde(default, rename = "appDisplayName")]
    pub app_display_name: String,
    #[serde(default)]
    pub status: serde_json::Value,
    #[serde(default, rename = "location")]
    pub location: serde_json::Value,
}

impl SignInEvent {
    pub fn error_code(&self) -> Option<i64> {
        self.status.get("errorCode").and_then(|v| v.as_i64())
    }
    pub fn country(&self) -> Option<&str> {
        self.location
            .get("countryOrRegion")
            .and_then(|v| v.as_str())
    }
}

/// Generic Graph collection response — `value` plus optional next/delta
/// link. Delta endpoints return `@odata.deltaLink` on the final page
/// instead of `@odata.nextLink`; we capture both so `fetch_delta`
/// can persist the cursor cleanly.
#[derive(Debug, Deserialize)]
struct GraphPage<T> {
    value: Vec<T>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
    #[serde(default, rename = "@odata.deltaLink")]
    delta_link: Option<String>,
}

/// Paginated GET over a Graph collection. Follows `@odata.nextLink` until
/// exhaustion or until `max_pages` is hit. The cap protects the scheduler
/// against a runaway backlog — anything past the cap comes back on the
/// next cycle thanks to the cursor.
async fn fetch_collection<T: for<'de> Deserialize<'de>>(
    client: &GraphClient,
    first_path: &str,
    max_pages: usize,
) -> Result<Vec<T>, GraphError> {
    let mut out: Vec<T> = Vec::new();
    let mut url = first_path.to_string();
    for _ in 0..max_pages {
        let page: GraphPage<T> = client.get_json(&url).await?;
        out.extend(page.value);
        match page.next_link {
            Some(next) => url = next,
            None => return Ok(out),
        }
    }
    Ok(out)
}

/// Percent-encode an ISO-8601 timestamp for safe inclusion in a `$filter`
/// URL. Only the characters that actually appear in ISO-8601 need escaping
/// (`:` and `+`), so we do not pull in a full urlencoding crate.
fn enc_iso(ts: &str) -> String {
    ts.replace('+', "%2B").replace(':', "%3A")
}

/// Page size for audit + signIn pulls. 250 is a good middle ground — it
/// fits in a single round-trip for typical SMB volume while staying well
/// under Graph's hard limit of 1000 per page for these endpoints.
const PAGE_SIZE: u32 = 250;
/// Maximum pages to follow before giving up on the cursor — 20 * 250 =
/// 5000 events per sync cycle per resource. Anything past that resumes
/// on the next cycle.
const MAX_PAGES: usize = 20;

/// Pull directoryAudits newer than `cursor` (exclusive). Returns events
/// sorted oldest-first so cursor advancement is deterministic.
pub async fn pull_directory_audits(
    client: &GraphClient,
    cursor: Option<&str>,
) -> Result<Vec<AuditEvent>, GraphError> {
    // `ge` would risk re-ingesting the boundary event every cycle; MS
    // Graph timestamps are millisecond-precise so `gt` is safe here.
    let filter = match cursor {
        Some(c) if !c.is_empty() => {
            format!("&$filter=activityDateTime gt {}", enc_iso(c))
        }
        _ => String::new(),
    };
    let path = format!(
        "/auditLogs/directoryAudits?$top={PAGE_SIZE}&$orderby=activityDateTime asc{filter}"
    );
    fetch_collection(client, &path, MAX_PAGES).await
}

/// Pull signIns newer than `cursor`. Requires AAD P1 for the $filter to
/// succeed; tenants without P1 will get a 403 which we bubble up.
pub async fn pull_sign_ins(
    client: &GraphClient,
    cursor: Option<&str>,
) -> Result<Vec<SignInEvent>, GraphError> {
    let filter = match cursor {
        Some(c) if !c.is_empty() => {
            format!("&$filter=createdDateTime gt {}", enc_iso(c))
        }
        _ => String::new(),
    };
    let path = format!("/auditLogs/signIns?$top={PAGE_SIZE}&$orderby=createdDateTime asc{filter}");
    fetch_collection(client, &path, MAX_PAGES).await
}

/// Paginated GET following `@odata.nextLink` that ALSO captures the final
/// `@odata.deltaLink` so the caller can persist it as a cursor. Used for
/// the delta-capable endpoints (users, groups, devices). If `first_path`
/// is an absolute URL (e.g. a deltaLink from a prior cycle), we use it
/// unchanged; otherwise it is treated as a path relative to the Graph
/// v1.0 base.
async fn fetch_delta<T: for<'de> Deserialize<'de>>(
    client: &GraphClient,
    first_path_or_url: &str,
    max_pages: usize,
) -> Result<(Vec<T>, Option<String>), GraphError> {
    let mut out: Vec<T> = Vec::new();
    let mut url = first_path_or_url.to_string();
    let mut delta_link = None;
    // `get_json` delegates to `get_raw`, which already normalises `http://`
    // prefixes to be used verbatim — so we can pass either a relative path
    // or an absolute deltaLink without branching here.
    for _ in 0..max_pages {
        let page: GraphPage<T> = client.get_json(&url).await?;
        out.extend(page.value);
        if let Some(d) = page.delta_link {
            delta_link = Some(d);
            return Ok((out, delta_link));
        }
        match page.next_link {
            Some(next) => url = next,
            None => return Ok((out, delta_link)),
        }
    }
    Ok((out, delta_link))
}

// ---------------------------------------------------------------------------
// Phase C: users, devices, managedDevices, conditional access
// ---------------------------------------------------------------------------

/// Distilled view of a `/users` row. Graph returns 30+ fields by default
/// — we read only what the identity_graph cares about.
#[derive(Debug, Clone, Deserialize)]
pub struct UserRow {
    pub id: String,
    #[serde(default, rename = "userPrincipalName")]
    pub user_principal_name: Option<String>,
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default, rename = "jobTitle")]
    pub job_title: Option<String>,
    /// Entra's deletion marker. Present only on delta payloads when a
    /// user has been removed since the last cursor — we downgrade them
    /// to `accountEnabled=false` in the identity graph.
    #[serde(default, rename = "@removed")]
    pub removed: Option<serde_json::Value>,
    #[serde(default, rename = "accountEnabled")]
    pub account_enabled: Option<bool>,
}

/// Entra-joined device (Azure AD device, not Intune-managed per se).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceRow {
    pub id: String,
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(default, rename = "deviceId")]
    pub device_id: Option<String>,
    #[serde(default, rename = "operatingSystem")]
    pub operating_system: Option<String>,
    #[serde(default, rename = "operatingSystemVersion")]
    pub operating_system_version: Option<String>,
    #[serde(default, rename = "accountEnabled")]
    pub account_enabled: Option<bool>,
    #[serde(default, rename = "approximateLastSignInDateTime")]
    pub approximate_last_signin: Option<String>,
    #[serde(default, rename = "@removed")]
    pub removed: Option<serde_json::Value>,
}

/// Intune-managed device — carries more ops-relevant fields (compliance,
/// serial number) than the plain Entra device row.
#[derive(Debug, Clone, Deserialize)]
pub struct ManagedDeviceRow {
    pub id: String,
    #[serde(default, rename = "deviceName")]
    pub device_name: Option<String>,
    #[serde(default, rename = "operatingSystem")]
    pub operating_system: Option<String>,
    #[serde(default, rename = "osVersion")]
    pub os_version: Option<String>,
    #[serde(default, rename = "serialNumber")]
    pub serial_number: Option<String>,
    #[serde(default)]
    pub manufacturer: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default, rename = "userPrincipalName")]
    pub user_principal_name: Option<String>,
    #[serde(default, rename = "complianceState")]
    pub compliance_state: Option<String>,
    #[serde(default, rename = "jailBroken")]
    pub jail_broken: Option<String>,
    #[serde(default, rename = "lastSyncDateTime")]
    pub last_sync_date_time: Option<String>,
    #[serde(default, rename = "emailAddress")]
    pub email_address: Option<String>,
}

/// Conditional Access policy summary. Stored as a finding when the
/// policy is disabled or in report-only — both are compliance gaps.
#[derive(Debug, Clone, Deserialize)]
pub struct ConditionalAccessPolicy {
    pub id: String,
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

/// Pull users via `/users/delta`. Accepts either an absolute deltaLink
/// from a prior cycle or falls back to a fresh `/users/delta` with the
/// `$select` we actually need.
pub async fn pull_users_delta(
    client: &GraphClient,
    delta_link: Option<&str>,
) -> Result<(Vec<UserRow>, Option<String>), GraphError> {
    let path = match delta_link {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => "/users/delta?$select=id,userPrincipalName,displayName,department,jobTitle,accountEnabled"
            .to_string(),
    };
    fetch_delta(client, &path, MAX_PAGES).await
}

/// Pull Entra-joined devices via `/devices/delta`.
pub async fn pull_devices_delta(
    client: &GraphClient,
    delta_link: Option<&str>,
) -> Result<(Vec<DeviceRow>, Option<String>), GraphError> {
    let path = match delta_link {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => "/devices/delta?$select=id,deviceId,displayName,operatingSystem,\
              operatingSystemVersion,accountEnabled,approximateLastSignInDateTime"
            .to_string(),
    };
    fetch_delta(client, &path, MAX_PAGES).await
}

/// Pull Intune managed devices. No delta support — timestamp filter on
/// `lastSyncDateTime` cursor.
pub async fn pull_managed_devices(
    client: &GraphClient,
    cursor: Option<&str>,
) -> Result<Vec<ManagedDeviceRow>, GraphError> {
    let filter = match cursor {
        Some(c) if !c.is_empty() => {
            format!("&$filter=lastSyncDateTime gt {}", enc_iso(c))
        }
        _ => String::new(),
    };
    let path = format!(
        "/deviceManagement/managedDevices?$top={PAGE_SIZE}\
         &$orderby=lastSyncDateTime asc{filter}"
    );
    fetch_collection(client, &path, MAX_PAGES).await
}

/// Pull conditional access policies. Small list, full refresh every cycle.
pub async fn pull_conditional_access_policies(
    client: &GraphClient,
) -> Result<Vec<ConditionalAccessPolicy>, GraphError> {
    fetch_collection(
        client,
        "/identity/conditionalAccess/policies?$select=id,displayName,state",
        MAX_PAGES,
    )
    .await
}

// ---------------------------------------------------------------------------
// Phase D: security/alerts_v2 + identityProtection
// ---------------------------------------------------------------------------

/// Defender-unified alert from `/security/alerts_v2`. We retain only
/// what we put in the finding — the full Graph schema is ~40 fields.
#[derive(Debug, Clone, Deserialize)]
pub struct AlertV2 {
    pub id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default, rename = "createdDateTime")]
    pub created_date_time: Option<String>,
    #[serde(default, rename = "lastUpdateDateTime")]
    pub last_update_date_time: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub classification: Option<String>,
    #[serde(default)]
    pub determination: Option<String>,
    #[serde(default, rename = "incidentId")]
    pub incident_id: Option<String>,
    #[serde(default, rename = "alertWebUrl")]
    pub alert_web_url: Option<String>,
    #[serde(default, rename = "providerAlertId")]
    pub provider_alert_id: Option<String>,
}

/// Entra ID Identity Protection — the P2-gated "this user is risky" view.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskyUser {
    pub id: String,
    #[serde(default, rename = "userPrincipalName")]
    pub user_principal_name: Option<String>,
    #[serde(default, rename = "riskLevel")]
    pub risk_level: Option<String>,
    #[serde(default, rename = "riskState")]
    pub risk_state: Option<String>,
    #[serde(default, rename = "riskDetail")]
    pub risk_detail: Option<String>,
    #[serde(default, rename = "riskLastUpdatedDateTime")]
    pub risk_last_updated: Option<String>,
}

/// Single risk detection event — impossible travel, anonymous IP,
/// unfamiliar sign-in features, etc.
#[derive(Debug, Clone, Deserialize)]
pub struct RiskDetection {
    pub id: String,
    #[serde(default, rename = "userPrincipalName")]
    pub user_principal_name: Option<String>,
    #[serde(default, rename = "riskEventType")]
    pub risk_event_type: Option<String>,
    #[serde(default, rename = "riskLevel")]
    pub risk_level: Option<String>,
    #[serde(default, rename = "ipAddress")]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub location: Option<serde_json::Value>,
    #[serde(default)]
    pub activity: Option<String>,
    #[serde(default, rename = "detectedDateTime")]
    pub detected_date_time: Option<String>,
}

/// Pull Defender unified alerts. Requires E5 / Defender standalone.
pub async fn pull_security_alerts_v2(
    client: &GraphClient,
    cursor: Option<&str>,
) -> Result<Vec<AlertV2>, GraphError> {
    let filter = match cursor {
        Some(c) if !c.is_empty() => {
            format!("&$filter=createdDateTime gt {}", enc_iso(c))
        }
        _ => String::new(),
    };
    let path = format!("/security/alerts_v2?$top={PAGE_SIZE}&$orderby=createdDateTime asc{filter}");
    fetch_collection(client, &path, MAX_PAGES).await
}

/// Pull Entra ID Identity Protection risky users (P2 only). Risk state
/// changes push the `riskLastUpdatedDateTime` forward, so we cursor on
/// that — dedup is then by (user_id, risk_level) at finding level.
pub async fn pull_risky_users(
    client: &GraphClient,
    cursor: Option<&str>,
) -> Result<Vec<RiskyUser>, GraphError> {
    let filter = match cursor {
        Some(c) if !c.is_empty() => {
            format!("&$filter=riskLastUpdatedDateTime gt {}", enc_iso(c))
        }
        _ => String::new(),
    };
    let path = format!(
        "/identityProtection/riskyUsers?$top={PAGE_SIZE}\
         &$orderby=riskLastUpdatedDateTime asc{filter}"
    );
    fetch_collection(client, &path, MAX_PAGES).await
}

/// Pull individual risk-detection events — impossible travel and friends.
pub async fn pull_risk_detections(
    client: &GraphClient,
    cursor: Option<&str>,
) -> Result<Vec<RiskDetection>, GraphError> {
    let filter = match cursor {
        Some(c) if !c.is_empty() => {
            format!("&$filter=detectedDateTime gt {}", enc_iso(c))
        }
        _ => String::new(),
    };
    let path = format!(
        "/identityProtection/riskDetections?$top={PAGE_SIZE}\
         &$orderby=detectedDateTime asc{filter}"
    );
    fetch_collection(client, &path, MAX_PAGES).await
}

// ---------------------------------------------------------------------------
// Detections — map Graph events to Sigma-style alerts
// ---------------------------------------------------------------------------

/// A detection candidate ready to be inserted as a sigma_alert. Built by
/// `detect_from_audit` / `detect_from_signin`; consumed by
/// `sync_microsoft_graph` which does the DB write.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub rule_id: &'static str,
    pub level: &'static str, // critical | high | medium | low
    pub title: String,
    pub username: Option<String>,
    pub source_ip: Option<String>,
}

/// The synthetic hostname used for every M365 alert. Graph events are
/// tenant-wide, not endpoint-bound, so we tag them with a stable key the
/// dashboard can filter on.
fn m365_hostname(tenant_id: &str) -> String {
    format!("m365:{tenant_id}")
}

/// Check a single audit event against our catalog of high-value patterns.
/// Returns `None` for events we do not care about — the vast majority.
pub fn detect_from_audit(event: &AuditEvent) -> Option<Detection> {
    // Only alert on successful actions — failed attempts are noise unless
    // we are looking at brute force, which lives in the signIn path.
    if !event.result.eq_ignore_ascii_case("success") {
        return None;
    }

    let activity = event.activity_display_name.as_str();
    let category = event.category.as_str();

    // 1. Mail auto-forward rule — the single strongest indicator of a
    //    compromised mailbox. Entra surfaces Exchange's mailbox-rule
    //    changes via Graph audit under distinct activity names depending
    //    on whether the change came from OWA (`Update inbox rules`) or
    //    PowerShell (`New-InboxRule` / `Set-InboxRule`).
    if activity == "Update inbox rules"
        || activity == "New-InboxRule"
        || activity == "Set-InboxRule"
    {
        return Some(Detection {
            rule_id: "tc-m365-mail-forward-rule",
            level: "high",
            title: format!(
                "M365 inbox rule modified (activity: {activity}) — possible mailbox compromise"
            ),
            username: event
                .actor_upn()
                .or_else(|| event.target_upn())
                .map(String::from),
            source_ip: None,
        });
    }

    // 2. Illicit OAuth consent grant. `Consent to application` fires on
    //    both admin and user consents; the risky one is the user consent
    //    to a non-verified app. We emit `medium` for admin consent
    //    (legitimate most of the time, still worth logging), `high` for
    //    user consent (common illicit-consent attack pattern).
    if category.eq_ignore_ascii_case("ApplicationManagement")
        && activity == "Consent to application"
    {
        let is_admin_consent = event
            .additional_details
            .iter()
            .filter_map(|d| d.get("key").and_then(|k| k.as_str()))
            .any(|k| k.eq_ignore_ascii_case("ConsentType"))
            && event.additional_details.iter().any(|d| {
                d.get("value")
                    .and_then(|v| v.as_str())
                    .map(|v| v.contains("AllPrincipals") || v.eq_ignore_ascii_case("Admin"))
                    .unwrap_or(false)
            });
        let level = if is_admin_consent { "medium" } else { "high" };
        return Some(Detection {
            rule_id: "tc-m365-oauth-consent",
            level,
            title: format!(
                "OAuth application consent granted ({}) — verify app legitimacy",
                if is_admin_consent { "admin" } else { "user" }
            ),
            username: event.actor_upn().map(String::from),
            source_ip: None,
        });
    }

    // 3. Global Admin (or any other directory role) added to a user. We
    //    scan every targetResource and every modifiedProperty to catch
    //    the role display name — it can appear either at the resource
    //    level or in the property diff.
    if activity == "Add member to role" || activity == "Add member to role in bulk" {
        if let Some(role) = audit_extract_role_name(event) {
            let critical = role.eq_ignore_ascii_case("Global Administrator")
                || role.eq_ignore_ascii_case("Privileged Role Administrator")
                || role.eq_ignore_ascii_case("Privileged Authentication Administrator");
            return Some(Detection {
                rule_id: "tc-m365-role-assignment",
                level: if critical { "critical" } else { "medium" },
                title: format!(
                    "Directory role '{role}' assigned — {}",
                    if critical {
                        "high-impact privilege escalation"
                    } else {
                        "privileged role change"
                    }
                ),
                username: event.target_upn().map(String::from),
                source_ip: None,
            });
        }
    }

    None
}

/// Dig the role display name out of a `Add member to role` event. The
/// role name lives in a `modifiedProperties` entry with `displayName =
/// "Role.DisplayName"` on the target role resource.
fn audit_extract_role_name(event: &AuditEvent) -> Option<String> {
    for target in &event.target_resources {
        let t_type = target.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if t_type != "Role" {
            continue;
        }

        // Prefer modifiedProperties[].newValue — that's where the role
        // name lives in practice. Fall back to displayName on the target
        // resource itself when the property diff is absent.
        if let Some(props) = target.get("modifiedProperties").and_then(|p| p.as_array()) {
            for p in props {
                let name = p.get("displayName").and_then(|n| n.as_str()).unwrap_or("");
                if name.eq_ignore_ascii_case("Role.DisplayName") {
                    if let Some(v) = p.get("newValue").and_then(|v| v.as_str()) {
                        // MS Graph wraps the value in double quotes —
                        // `"\"Global Administrator\""`. Strip them so
                        // downstream comparisons are clean.
                        return Some(v.trim_matches('"').to_string());
                    }
                }
            }
        }
        if let Some(n) = target.get("displayName").and_then(|n| n.as_str()) {
            return Some(n.to_string());
        }
    }
    None
}

/// Check a single sign-in against the current catalog. Phase B only
/// surfaces individual signals — MFA fatigue clustering and impossible
/// travel land in the next patch once we have a time-window accumulator.
pub fn detect_from_signin(event: &SignInEvent) -> Option<Detection> {
    // Riskiest single-event indicator we can emit today: a successful
    // sign-in from an anonymous proxy / Tor exit, which Entra flags via
    // riskState/riskLevelDuringSignIn. We only look at high-risk here
    // because the low/medium tiers are too noisy without a trained
    // baseline.
    let risk_level = event
        .status
        .get("additionalDetails")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if risk_level.to_ascii_lowercase().contains("high") {
        let ip = if event.ip_address.is_empty() {
            None
        } else {
            Some(event.ip_address.clone())
        };
        return Some(Detection {
            rule_id: "tc-m365-high-risk-signin",
            level: "high",
            title: format!(
                "High-risk sign-in by {} from {}",
                event.user_principal_name,
                event.country().unwrap_or("unknown location")
            ),
            username: Some(event.user_principal_name.clone()),
            source_ip: ip,
        });
    }
    None
}

// ---------------------------------------------------------------------------
// Sync entrypoint
// ---------------------------------------------------------------------------

/// Cursors carried from one sync cycle to the next. Persisted in
/// `skill_configs` by the scheduler so a restart resumes where it
/// stopped.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncCursors {
    pub signins_created_datetime: Option<String>,
    pub audit_activity_datetime: Option<String>,

    /// Graph deltaLink for `/users/delta`. Opaque URL, not a timestamp.
    pub users_delta_link: Option<String>,
    /// Graph deltaLink for `/devices/delta`.
    pub devices_delta_link: Option<String>,
    /// `lastSyncDateTime` of the newest managedDevice we have seen.
    pub managed_devices_last_sync: Option<String>,
    /// `createdDateTime` of the newest alerts_v2 we have emitted.
    pub alerts_v2_created_datetime: Option<String>,
    /// `riskLastUpdatedDateTime` of the newest riskyUser we have seen.
    pub risky_users_last_updated: Option<String>,
    /// `detectedDateTime` of the newest riskDetection we have seen.
    pub risk_detections_detected_datetime: Option<String>,
}

/// Per-cycle counters + advanced cursors. Returned to the scheduler.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MicrosoftGraphSyncResult {
    pub connection_ok: bool,
    pub tenant_display_name: Option<String>,
    pub plans: Vec<String>,

    pub audits_fetched: usize,
    pub signins_fetched: usize,
    pub users_upserted: usize,
    pub devices_upserted: usize,
    pub managed_devices_upserted: usize,
    pub ca_policies_checked: usize,
    pub alerts_v2_fetched: usize,
    pub risky_users_fetched: usize,
    pub risk_detections_fetched: usize,
    pub alerts_inserted: usize,
    pub insert_errors: usize,

    pub errors: Vec<String>,

    /// Cursors to persist — only overwrites when the corresponding puller
    /// succeeded, so a transient 403 (licence drop) doesn't lose the old
    /// cursor for unrelated resources.
    pub new_cursors: SyncCursors,
}

/// Normalise a Graph `alerts_v2.severity` string ("informational", "low",
/// "medium", "high") to the sigma level vocabulary the dashboard uses.
/// Unknown values degrade to `"medium"` so we still surface them.
pub fn map_alert_v2_severity(s: Option<&str>) -> &'static str {
    match s.unwrap_or("").to_ascii_lowercase().as_str() {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        "informational" | "info" => "low",
        _ => "medium",
    }
}

/// Normalise a Graph `riskLevel` value ("low", "medium", "high", "hidden",
/// "none", "unknownFutureValue") to sigma level. `high` maps to `critical`
/// for riskyUsers because Identity Protection only flags `high` when the
/// user is near-certainly compromised — that warrants waking the RSSI up.
pub fn map_risk_level_user(s: Option<&str>) -> Option<&'static str> {
    match s.unwrap_or("").to_ascii_lowercase().as_str() {
        "high" => Some("critical"),
        "medium" => Some("high"),
        "low" => Some("medium"),
        // `none`, `hidden`, `unknownFutureValue` — don't emit.
        _ => None,
    }
}

/// Same mapping as [`map_risk_level_user`] but for single `riskDetection`
/// events. One level lower because detections are candidates, not
/// confirmed compromises — false-positive rate is higher.
pub fn map_risk_level_detection(s: Option<&str>) -> Option<&'static str> {
    match s.unwrap_or("").to_ascii_lowercase().as_str() {
        "high" => Some("high"),
        "medium" => Some("medium"),
        "low" => Some("low"),
        _ => None,
    }
}

/// One sync cycle — connection check, audit pull, signIn pull, detection
/// + sigma_alert writes, cursor advancement.
pub async fn sync_microsoft_graph(
    store: &dyn crate::db::Database,
    config: &MicrosoftGraphConfig,
    cursors: SyncCursors,
) -> MicrosoftGraphSyncResult {
    let mut result = MicrosoftGraphSyncResult::default();
    result.new_cursors = cursors.clone();

    let client = match GraphClient::new(config.clone()) {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(e.to_string());
            return result;
        }
    };

    // Canary — proves creds + consent are still valid this cycle. Bail
    // out on failure: pulling audits / signIns with broken auth would
    // return N identical 401s and pollute the error log for nothing.
    match test_connection(&client).await {
        Ok(tc) => {
            result.connection_ok = tc.ok;
            result.tenant_display_name = tc.tenant_display_name.clone();
            result.plans = tc.plans.clone();
        }
        Err(e) => {
            result.errors.push(format!("test_connection: {e}"));
            tracing::warn!("MS-GRAPH: abort cycle — {}", e);
            return result;
        }
    }

    let hostname = m365_hostname(&config.tenant_id);

    // ── directoryAudits ────────────────────────────────────────────────
    match pull_directory_audits(&client, cursors.audit_activity_datetime.as_deref()).await {
        Ok(events) => {
            result.audits_fetched = events.len();
            for ev in &events {
                // Advance the cursor unconditionally — even events we
                // don't detect on should not come back next cycle.
                if result
                    .new_cursors
                    .audit_activity_datetime
                    .as_deref()
                    .map(|c| c < ev.activity_date_time.as_str())
                    .unwrap_or(true)
                {
                    result.new_cursors.audit_activity_datetime =
                        Some(ev.activity_date_time.clone());
                }

                if let Some(det) = detect_from_audit(ev) {
                    match store
                        .insert_sigma_alert(
                            det.rule_id,
                            det.level,
                            &det.title,
                            &hostname,
                            det.source_ip.as_deref(),
                            det.username.as_deref(),
                        )
                        .await
                    {
                        Ok(_) => result.alerts_inserted += 1,
                        Err(e) => {
                            result.insert_errors += 1;
                            tracing::warn!("MS-GRAPH: insert_sigma_alert (audit) failed: {}", e);
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("MS-GRAPH: directoryAudits pull failed: {}", e);
            result.errors.push(format!("directoryAudits: {e}"));
        }
    }

    // ── signIns ────────────────────────────────────────────────────────
    match pull_sign_ins(&client, cursors.signins_created_datetime.as_deref()).await {
        Ok(events) => {
            result.signins_fetched = events.len();
            for ev in &events {
                if result
                    .new_cursors
                    .signins_created_datetime
                    .as_deref()
                    .map(|c| c < ev.created_date_time.as_str())
                    .unwrap_or(true)
                {
                    result.new_cursors.signins_created_datetime =
                        Some(ev.created_date_time.clone());
                }

                // Record the login edge in the identity graph so UBA
                // (fan-out, impossible travel cross-source) can see it.
                // Only record successful sign-ins with a valid UPN —
                // failures pollute the LOGGED_IN edge count and we don't
                // want to MATCH on missing users.
                if !ev.user_principal_name.is_empty() && ev.error_code() == Some(0) {
                    crate::graph::identity_graph::record_login(
                        store,
                        &ev.user_principal_name,
                        &hostname,
                        &ev.ip_address,
                        "entra",
                        true,
                    )
                    .await;
                }

                if let Some(det) = detect_from_signin(ev) {
                    match store
                        .insert_sigma_alert(
                            det.rule_id,
                            det.level,
                            &det.title,
                            &hostname,
                            det.source_ip.as_deref(),
                            det.username.as_deref(),
                        )
                        .await
                    {
                        Ok(_) => result.alerts_inserted += 1,
                        Err(e) => {
                            result.insert_errors += 1;
                            tracing::warn!("MS-GRAPH: insert_sigma_alert (signin) failed: {}", e);
                        }
                    }
                }
            }
        }
        Err(GraphError::Forbidden(_)) | Err(GraphError::LicenceLimited(_)) => {
            // signIns needs P1 — tenant without P1 cannot query this
            // endpoint. Silent degrade; audit path still works.
            tracing::info!("MS-GRAPH: signIns skipped (tenant lacks P1)");
        }
        Err(e) => {
            tracing::warn!("MS-GRAPH: signIns pull failed: {}", e);
            result.errors.push(format!("signIns: {e}"));
        }
    }

    // ── users (delta) ──────────────────────────────────────────────────
    // Feeds the identity graph so downstream UBA (fan-out, escalation
    // chains) can bind Entra accounts to on-prem events.
    match pull_users_delta(&client, cursors.users_delta_link.as_deref()).await {
        Ok((users, delta)) => {
            for u in &users {
                // Skip @removed markers — accountEnabled=false + tombstone
                // is more useful written as one op than two.
                if u.removed.is_some() {
                    if let Some(upn) = u.user_principal_name.as_deref() {
                        if !upn.is_empty() {
                            crate::graph::identity_graph::upsert_user(
                                store, upn, false, false, None,
                            )
                            .await;
                        }
                    }
                    continue;
                }
                let upn = match u.user_principal_name.as_deref() {
                    Some(s) if !s.is_empty() => s,
                    _ => continue,
                };
                // `is_admin` on /users is not directly exposed — we flip
                // it elsewhere via the role-assignment audit path. Here
                // we only seed the node with the UPN + department.
                crate::graph::identity_graph::upsert_user(
                    store,
                    upn,
                    false,
                    false,
                    u.department.as_deref(),
                )
                .await;
                result.users_upserted += 1;
            }
            if delta.is_some() {
                result.new_cursors.users_delta_link = delta;
            }
        }
        Err(GraphError::Forbidden(_)) | Err(GraphError::LicenceLimited(_)) => {
            tracing::info!("MS-GRAPH: users/delta skipped (consent missing or licence)");
        }
        Err(e) => {
            tracing::warn!("MS-GRAPH: users/delta pull failed: {}", e);
            result.errors.push(format!("users/delta: {e}"));
        }
    }

    // ── devices (delta) ────────────────────────────────────────────────
    // Entra-joined devices become Asset nodes. MAC is not exposed by
    // /devices so resolution falls back to hostname+source, which is
    // exactly what asset_resolution does when MAC is None.
    match pull_devices_delta(&client, cursors.devices_delta_link.as_deref()).await {
        Ok((devices, delta)) => {
            for d in &devices {
                if d.removed.is_some() {
                    continue;
                }
                let hostname_dev = match d.display_name.as_deref() {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => continue,
                };
                let os_string = match (&d.operating_system, &d.operating_system_version) {
                    (Some(os), Some(v)) => Some(format!("{os} {v}")),
                    (Some(os), None) => Some(os.clone()),
                    _ => None,
                };
                let discovered = crate::graph::asset_resolution::DiscoveredAsset {
                    mac: None,
                    hostname: Some(hostname_dev),
                    fqdn: None,
                    ip: None,
                    os: os_string,
                    ports: None,
                    services: serde_json::Value::Null,
                    ou: None,
                    vlan: None,
                    vm_id: None,
                    criticality: None,
                    source: "m365-entra".into(),
                };
                let _ = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
                result.devices_upserted += 1;
            }
            if delta.is_some() {
                result.new_cursors.devices_delta_link = delta;
            }
        }
        Err(GraphError::Forbidden(_)) | Err(GraphError::LicenceLimited(_)) => {
            tracing::info!("MS-GRAPH: devices/delta skipped (consent missing or licence)");
        }
        Err(e) => {
            tracing::warn!("MS-GRAPH: devices/delta pull failed: {}", e);
            result.errors.push(format!("devices/delta: {e}"));
        }
    }

    // ── managed devices (Intune) ───────────────────────────────────────
    // Carries richer ops fields — serial number, compliance state,
    // manufacturer/model. Emit a finding when a device falls out of
    // compliance: that's the signal the RSSI needs.
    match pull_managed_devices(&client, cursors.managed_devices_last_sync.as_deref()).await {
        Ok(devices) => {
            for d in &devices {
                // Advance cursor on every row, detection or not.
                if let Some(ts) = &d.last_sync_date_time {
                    if result
                        .new_cursors
                        .managed_devices_last_sync
                        .as_deref()
                        .map(|c| c < ts.as_str())
                        .unwrap_or(true)
                    {
                        result.new_cursors.managed_devices_last_sync = Some(ts.clone());
                    }
                }

                let hostname_dev = match d.device_name.as_deref() {
                    Some(s) if !s.is_empty() => s.to_string(),
                    _ => continue,
                };
                let os_string = match (&d.operating_system, &d.os_version) {
                    (Some(os), Some(v)) => Some(format!("{os} {v}")),
                    (Some(os), None) => Some(os.clone()),
                    _ => None,
                };
                let discovered = crate::graph::asset_resolution::DiscoveredAsset {
                    mac: None,
                    hostname: Some(hostname_dev.clone()),
                    fqdn: None,
                    ip: None,
                    os: os_string,
                    ports: None,
                    services: serde_json::Value::Null,
                    ou: None,
                    vlan: None,
                    vm_id: None,
                    criticality: None,
                    source: "m365-intune".into(),
                };
                let _ = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
                result.managed_devices_upserted += 1;

                // Compliance states per MS docs: unknown, compliant,
                // noncompliant, conflict, error, inGracePeriod, configManager.
                // `noncompliant` + `error` are worth a sigma_alert; the
                // others are either transient or OK.
                let compliance = d.compliance_state.as_deref().unwrap_or("").to_lowercase();
                if compliance == "noncompliant" || compliance == "error" {
                    let level = if compliance == "noncompliant" {
                        "medium"
                    } else {
                        "low"
                    };
                    let title = format!(
                        "Intune: device '{}' is {} (Intune compliance gap)",
                        hostname_dev, compliance
                    );
                    match store
                        .insert_sigma_alert(
                            "tc-m365-intune-noncompliant",
                            level,
                            &title,
                            &hostname_dev,
                            None,
                            d.user_principal_name.as_deref(),
                        )
                        .await
                    {
                        Ok(_) => result.alerts_inserted += 1,
                        Err(e) => {
                            result.insert_errors += 1;
                            tracing::warn!("MS-GRAPH: insert_sigma_alert (intune) failed: {}", e);
                        }
                    }
                }
            }
        }
        Err(GraphError::Forbidden(_)) | Err(GraphError::LicenceLimited(_)) => {
            tracing::info!("MS-GRAPH: managedDevices skipped (no Intune licence)");
        }
        Err(e) => {
            tracing::warn!("MS-GRAPH: managedDevices pull failed: {}", e);
            result.errors.push(format!("managedDevices: {e}"));
        }
    }

    // ── conditional access policies ────────────────────────────────────
    // Small list, full refresh. Policies in "disabled" or "enabledForReportingButNotEnforced"
    // are compliance gaps (CA in report-only is not protecting anyone).
    match pull_conditional_access_policies(&client).await {
        Ok(policies) => {
            result.ca_policies_checked = policies.len();
            for p in &policies {
                let state = p.state.as_deref().unwrap_or("").to_lowercase();
                let (should_alert, level) = match state.as_str() {
                    "disabled" => (true, "medium"),
                    "enabledforreportingbutnotenforced" => (true, "low"),
                    _ => (false, ""),
                };
                if !should_alert {
                    continue;
                }
                let name = p.display_name.as_deref().unwrap_or(&p.id);
                let title =
                    format!("Conditional Access policy '{name}' is {state} — not enforcing");
                match store
                    .insert_sigma_alert(
                        "tc-m365-ca-policy-inactive",
                        level,
                        &title,
                        &hostname,
                        None,
                        None,
                    )
                    .await
                {
                    Ok(_) => result.alerts_inserted += 1,
                    Err(e) => {
                        result.insert_errors += 1;
                        tracing::warn!("MS-GRAPH: insert_sigma_alert (CA) failed: {}", e);
                    }
                }
            }
        }
        Err(GraphError::Forbidden(_)) | Err(GraphError::LicenceLimited(_)) => {
            tracing::info!("MS-GRAPH: conditionalAccess skipped (consent missing or licence)");
        }
        Err(e) => {
            tracing::warn!("MS-GRAPH: conditionalAccess pull failed: {}", e);
            result.errors.push(format!("conditionalAccess: {e}"));
        }
    }

    // ── Phase D: security/alerts_v2 (Defender unified) ─────────────────
    match pull_security_alerts_v2(&client, cursors.alerts_v2_created_datetime.as_deref()).await {
        Ok(alerts) => {
            result.alerts_v2_fetched = alerts.len();
            for a in &alerts {
                if let Some(ts) = &a.created_date_time {
                    if result
                        .new_cursors
                        .alerts_v2_created_datetime
                        .as_deref()
                        .map(|c| c < ts.as_str())
                        .unwrap_or(true)
                    {
                        result.new_cursors.alerts_v2_created_datetime = Some(ts.clone());
                    }
                }

                // Only emit for non-resolved alerts — resolved / FP
                // should not re-page the RSSI.
                let status = a.status.as_deref().unwrap_or("").to_lowercase();
                if status == "resolved" {
                    continue;
                }

                let level = map_alert_v2_severity(a.severity.as_deref());
                let title = format!(
                    "Defender: {} ({})",
                    a.title.as_deref().unwrap_or("Unnamed alert"),
                    a.category.as_deref().unwrap_or("uncategorised"),
                );
                let rule_id = format!(
                    "tc-m365-defender-{}",
                    a.category
                        .as_deref()
                        .unwrap_or("alert")
                        .to_lowercase()
                        .replace(|c: char| !c.is_ascii_alphanumeric(), "-")
                );
                match store
                    .insert_sigma_alert(&rule_id, level, &title, &hostname, None, None)
                    .await
                {
                    Ok(_) => result.alerts_inserted += 1,
                    Err(e) => {
                        result.insert_errors += 1;
                        tracing::warn!("MS-GRAPH: insert_sigma_alert (alerts_v2) failed: {}", e);
                    }
                }
            }
        }
        Err(GraphError::Forbidden(_)) | Err(GraphError::LicenceLimited(_)) => {
            tracing::info!("MS-GRAPH: alerts_v2 skipped (no Defender licence)");
        }
        Err(e) => {
            tracing::warn!("MS-GRAPH: alerts_v2 pull failed: {}", e);
            result.errors.push(format!("alerts_v2: {e}"));
        }
    }

    // ── Phase D: identityProtection/riskyUsers (P2) ────────────────────
    match pull_risky_users(&client, cursors.risky_users_last_updated.as_deref()).await {
        Ok(users) => {
            result.risky_users_fetched = users.len();
            for u in &users {
                if let Some(ts) = &u.risk_last_updated {
                    if result
                        .new_cursors
                        .risky_users_last_updated
                        .as_deref()
                        .map(|c| c < ts.as_str())
                        .unwrap_or(true)
                    {
                        result.new_cursors.risky_users_last_updated = Some(ts.clone());
                    }
                }

                // Only alert on active risk states — "remediated",
                // "dismissed", "confirmedSafe" are historical.
                let state = u.risk_state.as_deref().unwrap_or("").to_lowercase();
                if !matches!(state.as_str(), "atrisk" | "confirmedcompromised") {
                    continue;
                }

                let level = match map_risk_level_user(u.risk_level.as_deref()) {
                    Some(l) => l,
                    None => continue,
                };
                let title = format!(
                    "Entra ID: risky user {} — riskLevel={} state={}",
                    u.user_principal_name.as_deref().unwrap_or("?"),
                    u.risk_level.as_deref().unwrap_or("?"),
                    state
                );
                match store
                    .insert_sigma_alert(
                        "tc-m365-risky-user",
                        level,
                        &title,
                        &hostname,
                        None,
                        u.user_principal_name.as_deref(),
                    )
                    .await
                {
                    Ok(_) => result.alerts_inserted += 1,
                    Err(e) => {
                        result.insert_errors += 1;
                        tracing::warn!("MS-GRAPH: insert_sigma_alert (risky_user) failed: {}", e);
                    }
                }
            }
        }
        Err(GraphError::Forbidden(_)) | Err(GraphError::LicenceLimited(_)) => {
            tracing::info!("MS-GRAPH: riskyUsers skipped (no P2 licence)");
        }
        Err(e) => {
            tracing::warn!("MS-GRAPH: riskyUsers pull failed: {}", e);
            result.errors.push(format!("riskyUsers: {e}"));
        }
    }

    // ── Phase D: identityProtection/riskDetections ─────────────────────
    match pull_risk_detections(
        &client,
        cursors.risk_detections_detected_datetime.as_deref(),
    )
    .await
    {
        Ok(detections) => {
            result.risk_detections_fetched = detections.len();
            for d in &detections {
                if let Some(ts) = &d.detected_date_time {
                    if result
                        .new_cursors
                        .risk_detections_detected_datetime
                        .as_deref()
                        .map(|c| c < ts.as_str())
                        .unwrap_or(true)
                    {
                        result.new_cursors.risk_detections_detected_datetime = Some(ts.clone());
                    }
                }

                let level = match map_risk_level_detection(d.risk_level.as_deref()) {
                    Some(l) => l,
                    None => continue,
                };
                let event_type = d.risk_event_type.as_deref().unwrap_or("unknown");
                let title = format!(
                    "Entra ID risk detection: {} (user={})",
                    event_type,
                    d.user_principal_name.as_deref().unwrap_or("?"),
                );
                let rule_id = format!(
                    "tc-m365-risk-{}",
                    event_type
                        .to_lowercase()
                        .replace(|c: char| !c.is_ascii_alphanumeric(), "-")
                );
                match store
                    .insert_sigma_alert(
                        &rule_id,
                        level,
                        &title,
                        &hostname,
                        d.ip_address.as_deref(),
                        d.user_principal_name.as_deref(),
                    )
                    .await
                {
                    Ok(_) => result.alerts_inserted += 1,
                    Err(e) => {
                        result.insert_errors += 1;
                        tracing::warn!(
                            "MS-GRAPH: insert_sigma_alert (risk_detection) failed: {}",
                            e
                        );
                    }
                }
            }
        }
        Err(GraphError::Forbidden(_)) | Err(GraphError::LicenceLimited(_)) => {
            tracing::info!("MS-GRAPH: riskDetections skipped (no P2 licence)");
        }
        Err(e) => {
            tracing::warn!("MS-GRAPH: riskDetections pull failed: {}", e);
            result.errors.push(format!("riskDetections: {e}"));
        }
    }

    tracing::info!(
        "MS-GRAPH: cycle done — tenant='{}' audits={} signIns={} users={} devices={} managed={} \
         ca_policies={} alerts_v2={} risky_users={} risk_det={} alerts_out={} errors={}",
        result.tenant_display_name.as_deref().unwrap_or("?"),
        result.audits_fetched,
        result.signins_fetched,
        result.users_upserted,
        result.devices_upserted,
        result.managed_devices_upserted,
        result.ca_policies_checked,
        result.alerts_v2_fetched,
        result.risky_users_fetched,
        result.risk_detections_fetched,
        result.alerts_inserted,
        result.errors.len()
    );

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_from_json(j: serde_json::Value) -> AuditEvent {
        serde_json::from_value(j).expect("audit fixture must deserialize")
    }

    fn signin_from_json(j: serde_json::Value) -> SignInEvent {
        serde_json::from_value(j).expect("signin fixture must deserialize")
    }

    #[test]
    fn enc_iso_escapes_colon_and_plus() {
        assert_eq!(
            enc_iso("2026-04-23T10:30:00+00:00"),
            "2026-04-23T10%3A30%3A00%2B00%3A00"
        );
        // 'Z' suffix (the form MS Graph emits) — no change needed.
        assert_eq!(
            enc_iso("2026-04-23T10:30:00.123Z"),
            "2026-04-23T10%3A30%3A00.123Z"
        );
    }

    #[test]
    fn detect_mail_forward_rule_from_owa() {
        // Shape captured from a real Graph response — OWA-initiated inbox
        // rule update.
        let ev = audit_from_json(serde_json::json!({
            "id": "abc",
            "activityDateTime": "2026-04-23T10:00:00Z",
            "activityDisplayName": "Update inbox rules",
            "category": "ApplicationManagement",
            "result": "success",
            "initiatedBy": {
                "user": { "userPrincipalName": "jean@contoso.com" }
            },
            "targetResources": [{
                "type": "User",
                "userPrincipalName": "jean@contoso.com"
            }]
        }));
        let det = detect_from_audit(&ev).expect("should detect");
        assert_eq!(det.rule_id, "tc-m365-mail-forward-rule");
        assert_eq!(det.level, "high");
        assert_eq!(det.username.as_deref(), Some("jean@contoso.com"));
    }

    #[test]
    fn detect_mail_forward_rule_from_powershell() {
        let ev = audit_from_json(serde_json::json!({
            "id": "abc",
            "activityDateTime": "2026-04-23T10:00:00Z",
            "activityDisplayName": "New-InboxRule",
            "category": "Exchange",
            "result": "success",
            "initiatedBy": {
                "user": { "userPrincipalName": "jean@contoso.com" }
            }
        }));
        let det = detect_from_audit(&ev).expect("should detect");
        assert_eq!(det.rule_id, "tc-m365-mail-forward-rule");
    }

    #[test]
    fn detect_skips_failed_audit_events() {
        let ev = audit_from_json(serde_json::json!({
            "id": "abc",
            "activityDateTime": "2026-04-23T10:00:00Z",
            "activityDisplayName": "Update inbox rules",
            "category": "ApplicationManagement",
            "result": "failure",
            "initiatedBy": {}
        }));
        assert!(detect_from_audit(&ev).is_none());
    }

    #[test]
    fn detect_oauth_user_consent_is_high() {
        let ev = audit_from_json(serde_json::json!({
            "id": "abc",
            "activityDateTime": "2026-04-23T10:00:00Z",
            "activityDisplayName": "Consent to application",
            "category": "ApplicationManagement",
            "result": "success",
            "initiatedBy": {
                "user": { "userPrincipalName": "jean@contoso.com" }
            },
            "additionalDetails": [
                { "key": "ConsentType", "value": "Principal" }
            ]
        }));
        let det = detect_from_audit(&ev).expect("should detect");
        assert_eq!(det.rule_id, "tc-m365-oauth-consent");
        assert_eq!(det.level, "high"); // user consent — higher risk
    }

    #[test]
    fn detect_oauth_admin_consent_is_medium() {
        let ev = audit_from_json(serde_json::json!({
            "id": "abc",
            "activityDateTime": "2026-04-23T10:00:00Z",
            "activityDisplayName": "Consent to application",
            "category": "ApplicationManagement",
            "result": "success",
            "initiatedBy": { "user": { "userPrincipalName": "admin@contoso.com" } },
            "additionalDetails": [
                { "key": "ConsentType", "value": "AllPrincipals" }
            ]
        }));
        let det = detect_from_audit(&ev).expect("should detect");
        assert_eq!(det.level, "medium");
    }

    #[test]
    fn detect_global_admin_added_is_critical() {
        let ev = audit_from_json(serde_json::json!({
            "id": "abc",
            "activityDateTime": "2026-04-23T10:00:00Z",
            "activityDisplayName": "Add member to role",
            "category": "RoleManagement",
            "result": "success",
            "initiatedBy": { "user": { "userPrincipalName": "rogue@contoso.com" } },
            "targetResources": [
                {
                    "type": "User",
                    "userPrincipalName": "victim@contoso.com"
                },
                {
                    "type": "Role",
                    "displayName": "Global Administrator",
                    "modifiedProperties": [
                        {
                            "displayName": "Role.DisplayName",
                            "newValue": "\"Global Administrator\""
                        }
                    ]
                }
            ]
        }));
        let det = detect_from_audit(&ev).expect("should detect");
        assert_eq!(det.rule_id, "tc-m365-role-assignment");
        assert_eq!(det.level, "critical");
        assert_eq!(det.username.as_deref(), Some("victim@contoso.com"));
    }

    #[test]
    fn detect_non_critical_role_is_medium() {
        let ev = audit_from_json(serde_json::json!({
            "id": "abc",
            "activityDateTime": "2026-04-23T10:00:00Z",
            "activityDisplayName": "Add member to role",
            "category": "RoleManagement",
            "result": "success",
            "initiatedBy": { "user": { "userPrincipalName": "admin@contoso.com" } },
            "targetResources": [
                { "type": "User", "userPrincipalName": "new@contoso.com" },
                {
                    "type": "Role",
                    "displayName": "Message Center Reader",
                    "modifiedProperties": [
                        {
                            "displayName": "Role.DisplayName",
                            "newValue": "\"Message Center Reader\""
                        }
                    ]
                }
            ]
        }));
        let det = detect_from_audit(&ev).expect("should detect");
        assert_eq!(det.level, "medium");
    }

    #[test]
    fn detect_ignores_uninteresting_activity() {
        let ev = audit_from_json(serde_json::json!({
            "id": "abc",
            "activityDateTime": "2026-04-23T10:00:00Z",
            "activityDisplayName": "Update user",
            "category": "UserManagement",
            "result": "success",
            "initiatedBy": {}
        }));
        assert!(detect_from_audit(&ev).is_none());
    }

    #[test]
    fn detect_high_risk_signin() {
        let ev = signin_from_json(serde_json::json!({
            "id": "s1",
            "createdDateTime": "2026-04-23T10:00:00Z",
            "userPrincipalName": "jean@contoso.com",
            "ipAddress": "185.220.101.42",
            "status": {
                "errorCode": 0,
                "additionalDetails": "High risk detected"
            },
            "location": { "countryOrRegion": "RU" }
        }));
        let det = detect_from_signin(&ev).expect("should detect");
        assert_eq!(det.rule_id, "tc-m365-high-risk-signin");
        assert_eq!(det.source_ip.as_deref(), Some("185.220.101.42"));
        assert!(det.title.contains("RU"));
    }

    #[test]
    fn detect_normal_signin_is_silent() {
        let ev = signin_from_json(serde_json::json!({
            "id": "s2",
            "createdDateTime": "2026-04-23T10:00:00Z",
            "userPrincipalName": "jean@contoso.com",
            "ipAddress": "10.0.0.1",
            "status": { "errorCode": 0, "additionalDetails": "None" }
        }));
        assert!(detect_from_signin(&ev).is_none());
    }

    #[test]
    fn auth_method_parse() {
        assert_eq!(AuthMethod::parse("secret"), AuthMethod::Secret);
        assert_eq!(AuthMethod::parse("SECRET"), AuthMethod::Secret);
        assert_eq!(AuthMethod::parse("client_secret"), AuthMethod::Secret);
        assert_eq!(AuthMethod::parse("certificate"), AuthMethod::Certificate);
        assert_eq!(AuthMethod::parse(""), AuthMethod::Certificate);
        assert_eq!(AuthMethod::parse("bogus"), AuthMethod::Certificate);
    }

    #[test]
    fn config_validate_rejects_missing_tenant() {
        let c = MicrosoftGraphConfig {
            tenant_id: "".into(),
            client_id: "cid".into(),
            auth_method: AuthMethod::Secret,
            client_secret: Some("s".into()),
            client_cert_pem: None,
            client_key_pem: None,
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_missing_secret() {
        let c = MicrosoftGraphConfig {
            tenant_id: "tid".into(),
            client_id: "cid".into(),
            auth_method: AuthMethod::Secret,
            client_secret: None,
            client_cert_pem: None,
            client_key_pem: None,
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_missing_cert_pair() {
        let c = MicrosoftGraphConfig {
            tenant_id: "tid".into(),
            client_id: "cid".into(),
            auth_method: AuthMethod::Certificate,
            client_secret: None,
            client_cert_pem: Some("cert".into()),
            client_key_pem: None, // missing
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_validate_accepts_secret_minimal() {
        let c = MicrosoftGraphConfig {
            tenant_id: "tid".into(),
            client_id: "cid".into(),
            auth_method: AuthMethod::Secret,
            client_secret: Some("value".into()),
            client_cert_pem: None,
            client_key_pem: None,
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn pem_body_decode_strips_whitespace_and_wraps() {
        // 8 bytes of 0xFF encoded in base64 is "////////".
        let pem = "random preamble\n\
                   -----BEGIN TEST-----\n\
                   //\t//\r\n///\r\n/\r\n\
                   -----END TEST-----\n\
                   trailing\n";
        let out = pem_body_decode(pem, "TEST").expect("decode ok");
        assert_eq!(out, vec![0xFFu8; 6]);
    }

    #[test]
    fn pem_body_decode_reports_missing_label() {
        let err = pem_body_decode("no headers here", "CERTIFICATE").unwrap_err();
        assert!(err.contains("missing"));
    }

    #[test]
    fn retry_after_backoff_is_positive_and_capped() {
        // backoff_delay can never exceed ~75s (60 + 25% jitter) and is
        // always >= 1s. Run the randomised function many times to catch
        // any edge in the jitter arithmetic.
        for attempt in 1u32..8 {
            for _ in 0..50 {
                let d = backoff_delay(attempt);
                assert!(d.as_secs() >= 1, "attempt {attempt} produced 0s");
                assert!(d.as_secs() <= 75, "attempt {attempt} produced {d:?}");
            }
        }
    }

    #[test]
    fn scrub_correlation_drops_trace_id_block() {
        let msg = "AADSTS70011: Scope not valid.\r\nTrace ID: abc\r\nCorrelation ID: xyz\r\nTimestamp: 2026-04-23";
        assert_eq!(scrub_correlation(msg), "AADSTS70011: Scope not valid.");
    }

    #[test]
    fn parse_graph_error_code_extracts_code() {
        let body = r#"{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}"#;
        assert_eq!(
            parse_graph_error_code(body).as_deref(),
            Some("Authorization_RequestDenied")
        );
    }

    #[test]
    fn parse_graph_error_code_returns_none_on_garbage() {
        assert_eq!(parse_graph_error_code("not json at all"), None);
        assert_eq!(parse_graph_error_code("{}"), None);
    }

    #[test]
    fn map_alert_v2_severity_all_cases() {
        assert_eq!(map_alert_v2_severity(Some("high")), "high");
        assert_eq!(map_alert_v2_severity(Some("HIGH")), "high");
        assert_eq!(map_alert_v2_severity(Some("medium")), "medium");
        assert_eq!(map_alert_v2_severity(Some("low")), "low");
        assert_eq!(map_alert_v2_severity(Some("informational")), "low");
        assert_eq!(map_alert_v2_severity(Some("info")), "low");
        assert_eq!(map_alert_v2_severity(None), "medium");
        assert_eq!(map_alert_v2_severity(Some("")), "medium");
        assert_eq!(
            map_alert_v2_severity(Some("something-new-ms-added")),
            "medium"
        );
    }

    #[test]
    fn map_risk_level_user_escalates_high_to_critical() {
        assert_eq!(map_risk_level_user(Some("high")), Some("critical"));
        assert_eq!(map_risk_level_user(Some("HIGH")), Some("critical"));
        assert_eq!(map_risk_level_user(Some("medium")), Some("high"));
        assert_eq!(map_risk_level_user(Some("low")), Some("medium"));
        assert_eq!(map_risk_level_user(Some("none")), None);
        assert_eq!(map_risk_level_user(Some("hidden")), None);
        assert_eq!(map_risk_level_user(Some("unknownFutureValue")), None);
        assert_eq!(map_risk_level_user(None), None);
    }

    #[test]
    fn map_risk_level_detection_is_one_notch_lower() {
        assert_eq!(map_risk_level_detection(Some("high")), Some("high"));
        assert_eq!(map_risk_level_detection(Some("medium")), Some("medium"));
        assert_eq!(map_risk_level_detection(Some("low")), Some("low"));
        assert_eq!(map_risk_level_detection(Some("none")), None);
    }

    #[test]
    fn graph_page_parses_delta_and_next_links() {
        let payload = serde_json::json!({
            "value": [{"id": "u1"}, {"id": "u2"}],
            "@odata.deltaLink": "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=xyz"
        });
        let page: GraphPage<serde_json::Value> = serde_json::from_value(payload).unwrap();
        assert_eq!(page.value.len(), 2);
        assert!(page.delta_link.is_some());
        assert!(page.next_link.is_none());
    }

    #[test]
    fn graph_page_parses_next_link_without_delta() {
        let payload = serde_json::json!({
            "value": [],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users/delta?$skiptoken=abc"
        });
        let page: GraphPage<serde_json::Value> = serde_json::from_value(payload).unwrap();
        assert!(page.next_link.is_some());
        assert!(page.delta_link.is_none());
    }

    #[test]
    fn user_row_parses_removed_marker() {
        let ur: UserRow = serde_json::from_value(serde_json::json!({
            "id": "abc",
            "@removed": { "reason": "changed" }
        }))
        .unwrap();
        assert!(ur.removed.is_some());
    }

    #[test]
    fn device_row_parses_full_shape() {
        let d: DeviceRow = serde_json::from_value(serde_json::json!({
            "id": "d1",
            "displayName": "PC-COMPTA-01",
            "deviceId": "dev-guid",
            "operatingSystem": "Windows",
            "operatingSystemVersion": "10.0.19045",
            "accountEnabled": true
        }))
        .unwrap();
        assert_eq!(d.display_name.as_deref(), Some("PC-COMPTA-01"));
        assert_eq!(d.operating_system.as_deref(), Some("Windows"));
    }

    #[test]
    fn managed_device_compliance_states_are_deserialisable() {
        for state in &[
            "unknown",
            "compliant",
            "noncompliant",
            "conflict",
            "error",
            "inGracePeriod",
        ] {
            let md: ManagedDeviceRow = serde_json::from_value(serde_json::json!({
                "id": "x",
                "complianceState": state
            }))
            .unwrap();
            assert_eq!(md.compliance_state.as_deref(), Some(*state));
        }
    }

    #[test]
    fn alert_v2_parses_minimal() {
        let a: AlertV2 = serde_json::from_value(serde_json::json!({
            "id": "a1",
            "title": "Suspicious sign-in",
            "severity": "high",
            "status": "new",
            "createdDateTime": "2026-04-23T10:00:00Z"
        }))
        .unwrap();
        assert_eq!(a.title.as_deref(), Some("Suspicious sign-in"));
        assert_eq!(map_alert_v2_severity(a.severity.as_deref()), "high");
    }

    #[test]
    fn risky_user_parses_graph_shape() {
        let r: RiskyUser = serde_json::from_value(serde_json::json!({
            "id": "u1",
            "userPrincipalName": "jean@contoso.com",
            "riskLevel": "high",
            "riskState": "atRisk",
            "riskLastUpdatedDateTime": "2026-04-23T10:00:00Z"
        }))
        .unwrap();
        assert_eq!(r.user_principal_name.as_deref(), Some("jean@contoso.com"));
        assert_eq!(
            map_risk_level_user(r.risk_level.as_deref()),
            Some("critical")
        );
    }

    #[test]
    fn risk_detection_parses_graph_shape() {
        let r: RiskDetection = serde_json::from_value(serde_json::json!({
            "id": "rd1",
            "userPrincipalName": "jean@contoso.com",
            "riskEventType": "impossibleTravel",
            "riskLevel": "high",
            "ipAddress": "185.220.101.42",
            "detectedDateTime": "2026-04-23T10:00:00Z"
        }))
        .unwrap();
        assert_eq!(r.risk_event_type.as_deref(), Some("impossibleTravel"));
        assert_eq!(r.ip_address.as_deref(), Some("185.220.101.42"));
    }

    #[test]
    fn conditional_access_policy_parses() {
        let p: ConditionalAccessPolicy = serde_json::from_value(serde_json::json!({
            "id": "p1",
            "displayName": "Require MFA for admins",
            "state": "enabled"
        }))
        .unwrap();
        assert_eq!(p.state.as_deref(), Some("enabled"));
    }

    /// Full round-trip: generate an ephemeral RSA key, build the
    /// assertion, then verify its signature and claims with the
    /// matching public key. Proves the JWT is well-formed end-to-end.
    ///
    /// Uses a fresh key per run rather than a checked-in test vector —
    /// simpler and removes the risk of shipping secrets in the repo.
    #[test]
    fn build_client_assertion_round_trip() {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

        // Build a self-signed cert + matching RSA-2048 key in one
        // openssl call. We shell out because adding `rcgen` as a
        // test-only dep just for this would be overkill.
        let tmp = tempfile::tempdir().expect("tmpdir");
        let key_path = tmp.path().join("k.pem");
        let cert_path = tmp.path().join("c.pem");

        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "30",
                "-nodes",
                "-subj",
                "/CN=threatclaw-test",
            ])
            .output()
            .expect("openssl must be on PATH to run this test");
        assert!(
            status.status.success(),
            "openssl failed: {}",
            String::from_utf8_lossy(&status.stderr)
        );

        let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
        let key_pem = std::fs::read_to_string(&key_path).unwrap();

        let tenant = "00000000-0000-0000-0000-000000000001";
        let client = "00000000-0000-0000-0000-000000000002";
        let now: u64 = 1_700_000_000;

        let jwt = build_client_assertion(tenant, client, &cert_pem, &key_pem, now)
            .expect("assertion must build");

        // Decode header manually to check x5t#S256 + alg.
        let header = jsonwebtoken::decode_header(&jwt).expect("header parse");
        assert_eq!(header.alg, Algorithm::PS256);
        assert_eq!(header.typ.as_deref(), Some("JWT"));
        let x5t = header.x5t_s256.expect("x5t#S256 present");
        // 32-byte SHA-256 encoded in base64url without padding is always
        // exactly 43 chars. This is a cheap structural check that the
        // thumbprint was not accidentally hex or SHA-1.
        assert_eq!(x5t.len(), 43);

        // Verify signature + claims with the public key extracted from
        // the cert. jsonwebtoken can read the public key straight from
        // a PEM-encoded X.509 cert.
        let pub_key = DecodingKey::from_rsa_pem(cert_pem.as_bytes()).expect("pub key from cert");
        let mut validation = Validation::new(Algorithm::PS256);
        validation.set_audience(&[format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        )]);
        validation.set_issuer(&[client]);
        // nbf is `now`; the default Validation.leeway (60s) covers
        // clock-skew but not us sending now=1.7G with the verifier's
        // real clock. Disable time checks and verify the numeric
        // claims by hand below.
        validation.validate_exp = false;
        validation.validate_nbf = false;

        let decoded = decode::<AssertionClaims>(&jwt, &pub_key, &validation)
            .expect("signature + claims verify");

        assert_eq!(decoded.claims.iss, client);
        assert_eq!(decoded.claims.sub, client);
        assert_eq!(decoded.claims.iat, now);
        assert_eq!(decoded.claims.nbf, now);
        assert_eq!(decoded.claims.exp, now + 600);
        assert!(!decoded.claims.jti.is_empty());
    }
}
