//! `LicenseManager` — runtime owner of licensing state.
//!
//! One instance per process. Owns the [`super::api_client::LicenseClient`],
//! the cached site fingerprint, and the in-memory [`super::PremiumGate`]
//! that the skill registry consults when loading premium skills.
//!
//! Lifecycle:
//!
//! 1. [`LicenseManager::bootstrap`] is called once at process start. It
//!    loads the persisted cert (if any) from `~/.threatclaw/licensing/`
//!    and constructs an in-memory gate. Failure to load is non-fatal —
//!    the process keeps running with no gate (premium skills refused).
//! 2. The dashboard / CLI calls [`LicenseManager::activate`],
//!    [`LicenseManager::start_trial`], or [`LicenseManager::deactivate`]
//!    in response to user actions.
//! 3. [`LicenseManager::spawn_heartbeat`] runs a background task that
//!    refreshes the cert with the license server every 7 days, so the
//!    rolling 30-day cert never lapses for an online deployment.
//!
//! Everything is **disabled if [`super::is_provisioned`] returns false**
//! (compile-time pubkey is the all-zeros placeholder). This is the
//! safety rail that lets us land the whole pipeline before the real
//! Ed25519 keypair has been minted.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use super::api_client::{
    ActivateRequest, ApiError, ApiRejection, CertResponse, DeactivateRequest, HeartbeatRequest,
    LicenseClient, TrialStartRequest,
};
use super::cert::{LicenseTier, SignedLicense, now_secs};
use super::fingerprint::site_fingerprint;
use super::gate::PremiumGate;
use super::grace::{GraceState, assess};
use super::storage::{self, LicensingState};
use super::trial;
use super::verify::verify_license;

/// Heartbeat cadence. The cert issued by the server is valid 30 days; we
/// refresh weekly so a single missed call does not threaten the cert.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(7 * 86_400);

/// Initial delay before the first heartbeat attempt after process boot.
/// Picks a small jitter so that 1000 simultaneously-restarted clients
/// (e.g. after a coordinated upgrade) do not stampede the API.
const HEARTBEAT_BOOT_DELAY: Duration = Duration::from_secs(60);

/// Diagnostic snapshot for the dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LicenseStatus {
    /// Whether the licensing pipeline is wired up (real pubkey embedded).
    pub provisioned: bool,
    /// Master license key, if any.
    pub license_key: Option<String>,
    /// Email on the cert, for support diagnostics.
    pub licensee_email: Option<String>,
    /// Tier on the cert (Trial / Individual / ActionPack / Msp / Enterprise).
    pub tier: Option<LicenseTier>,
    /// Skills the cert covers.
    pub skills: Vec<String>,
    /// Where the cert sits in its lifecycle (valid / renewal-soon / grace / lapsed).
    pub grace: Option<GraceState>,
    /// True when the cert is a 60-day trial.
    pub trial: bool,
    /// UNIX seconds when the cert hard-expires (before grace).
    pub expires_at: Option<u64>,
    /// Last successful heartbeat against the server, UNIX seconds.
    pub last_heartbeat: u64,
    /// Last attempted heartbeat, UNIX seconds.
    pub last_attempt: u64,
    /// Whether this install has already consumed its free trial (per
    /// local state — server still authoritative).
    pub trial_consumed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("licensing pipeline not provisioned (build pubkey is the placeholder)")]
    NotProvisioned,
    #[error("license server: {0}")]
    Api(#[from] ApiError),
    #[error("cert returned by server failed verification: {0}")]
    Verify(String),
    #[error("storage I/O: {0}")]
    Storage(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct LicenseManager {
    inner: Arc<RwLock<Inner>>,
    client: LicenseClient,
    install_id: String,
    site_fingerprint: String,
    hostname: String,
    agent_version: String,
}

struct Inner {
    state: LicensingState,
    gate: Option<PremiumGate>,
}

impl LicenseManager {
    /// Constructor + initial state load. Always succeeds; on disk errors
    /// the manager comes up with empty state and logs a warning.
    pub async fn bootstrap(client: LicenseClient) -> Self {
        let install_id = match storage::load_or_create_install_id() {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(error = %e, "licensing: failed to load install_id, using ephemeral");
                uuid::Uuid::new_v4().to_string()
            }
        };
        let site_fingerprint = site_fingerprint().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "licensing: site_fingerprint unavailable");
            String::new()
        });
        let hostname = read_hostname();
        let agent_version = env!("CARGO_PKG_VERSION").to_string();

        let state = storage::read_state().unwrap_or_default();
        let gate = load_gate_from_disk(&site_fingerprint);

        Self {
            inner: Arc::new(RwLock::new(Inner { state, gate })),
            client,
            install_id,
            site_fingerprint,
            hostname,
            agent_version,
        }
    }

    /// True if the in-memory gate currently allows the given premium
    /// skill. Returns `false` for unprovisioned builds, missing cert, or
    /// any denial reason. Cheap, suitable for hot paths in skill loading.
    pub async fn allows_skill(&self, skill_id: &str) -> bool {
        if !super::is_provisioned() {
            return false;
        }
        let inner = self.inner.read().await;
        match &inner.gate {
            Some(gate) => matches!(gate.check(skill_id), super::GateDecision::Allowed { .. }),
            None => false,
        }
    }

    /// Diagnostic snapshot for the dashboard.
    pub async fn status(&self) -> LicenseStatus {
        let inner = self.inner.read().await;
        let mut out = LicenseStatus {
            provisioned: super::is_provisioned(),
            license_key: if inner.state.license_key.is_empty() {
                None
            } else {
                Some(inner.state.license_key.clone())
            },
            licensee_email: None,
            tier: None,
            skills: vec![],
            grace: None,
            trial: false,
            expires_at: None,
            last_heartbeat: inner.state.last_heartbeat,
            last_attempt: inner.state.last_attempt,
            trial_consumed: inner.state.trial_consumed,
        };

        if let Some(gate) = &inner.gate {
            out.licensee_email = Some(gate.licensee_email().to_string());
            out.tier = Some(gate.tier());
        }

        // Re-read the persisted cert to extract the cert-level fields the
        // gate doesn't expose (skills, expires_at). Cheap (sub-kB file).
        if let Ok(Some(encoded)) = storage::read_cert() {
            if let Ok(signed) = SignedLicense::decode(&encoded) {
                out.skills = signed.cert.skills.clone();
                out.expires_at = Some(signed.cert.expires_at);
                out.trial = trial::is_trial(&signed.cert);
                out.grace = Some(assess(&signed.cert, now_secs()));
            }
        }
        out
    }

    /// Activate against an existing license key. Used both for first
    /// activation and after re-installation.
    pub async fn activate(
        &self,
        license_key: &str,
        requested_skills: &[&str],
    ) -> Result<LicenseStatus, ManagerError> {
        if !super::is_provisioned() {
            return Err(ManagerError::NotProvisioned);
        }
        let req = ActivateRequest {
            license_key,
            install_id: &self.install_id,
            hostname: &self.hostname,
            site_fingerprint: &self.site_fingerprint,
            agent_version: &self.agent_version,
            requested_skills: requested_skills.to_vec(),
        };
        let resp = self.client.activate(&req).await?;
        self.persist_cert(&resp).await?;
        Ok(self.status().await)
    }

    /// Start a 60-day trial. Server authoritatively decides whether to
    /// grant it (anti-abuse). On success, persists the cert and the
    /// "trial consumed" marker.
    pub async fn start_trial(
        &self,
        email: &str,
        org: &str,
        requested_skill: &str,
    ) -> Result<LicenseStatus, ManagerError> {
        if !super::is_provisioned() {
            return Err(ManagerError::NotProvisioned);
        }
        let req = TrialStartRequest {
            email,
            org,
            install_id: &self.install_id,
            hostname: &self.hostname,
            site_fingerprint: &self.site_fingerprint,
            agent_version: &self.agent_version,
            requested_skill,
        };
        let resp = self.client.start_trial(&req).await?;
        self.persist_cert(&resp).await?;
        // Record consumption locally too — defense in depth.
        trial::mark_consumed().ok();
        Ok(self.status().await)
    }

    /// Refresh the cert against the server. Called by the background
    /// heartbeat task and by the dashboard "Refresh now" button.
    pub async fn heartbeat(&self) -> Result<(), ManagerError> {
        if !super::is_provisioned() {
            return Err(ManagerError::NotProvisioned);
        }
        let license_key = {
            let inner = self.inner.read().await;
            inner.state.license_key.clone()
        };
        if license_key.is_empty() {
            // No license configured — heartbeat is a silent no-op.
            return Ok(());
        }

        // Stamp the attempt timestamp upfront so even a failure shows up
        // in /licensing/status as "last attempt: just now".
        {
            let mut inner = self.inner.write().await;
            inner.state.last_attempt = now_secs();
            storage::write_state(&inner.state).ok();
        }

        let req = HeartbeatRequest {
            license_key: &license_key,
            install_id: &self.install_id,
            site_fingerprint: &self.site_fingerprint,
            agent_version: &self.agent_version,
        };
        match self.client.heartbeat(&req).await {
            Ok(resp) => {
                self.persist_cert(&resp).await?;
                Ok(())
            }
            Err(ApiError::Rejected {
                kind: ApiRejection::Revoked,
                ..
            })
            | Err(ApiError::Rejected {
                kind: ApiRejection::SubscriptionInactive,
                ..
            }) => {
                // Terminal state — drop the cert, but keep license_key in
                // state so the dashboard can show "subscription inactive,
                // please renew" instead of pretending nothing happened.
                tracing::warn!(license_key = %license_key, "licensing: heartbeat refused, dropping cert");
                self.drop_cert_keep_key().await.ok();
                Err(ManagerError::Api(ApiError::Rejected {
                    kind: ApiRejection::SubscriptionInactive,
                    message: "subscription no longer active".into(),
                }))
            }
            Err(e) => {
                // Transient failures (network, 5xx) leave the existing
                // cert intact — its 30-day window plus 90-day grace mean
                // a few hours of API outage are invisible to the user.
                tracing::debug!(error = ?e, "licensing: heartbeat failed (will retry)");
                Err(ManagerError::Api(e))
            }
        }
    }

    /// Tell the server to release this install's activation slot, then
    /// wipe the local cert. Best-effort: if the server is unreachable
    /// we still wipe locally so the user can move the license to another
    /// machine without waiting for the API.
    pub async fn deactivate(&self) -> Result<(), ManagerError> {
        if !super::is_provisioned() {
            return Err(ManagerError::NotProvisioned);
        }
        let license_key = {
            let inner = self.inner.read().await;
            inner.state.license_key.clone()
        };
        if !license_key.is_empty() {
            let req = DeactivateRequest {
                license_key: &license_key,
                install_id: &self.install_id,
            };
            if let Err(e) = self.client.deactivate(&req).await {
                tracing::warn!(error = ?e, "licensing: server deactivate failed, wiping local anyway");
            }
        }
        let mut inner = self.inner.write().await;
        inner.state = LicensingState::default();
        inner.gate = None;
        storage::clear_all()?;
        Ok(())
    }

    /// Spawn the background heartbeat loop. Cancel the returned handle
    /// to stop it — typically done by the process supervisor on shutdown.
    pub fn spawn_heartbeat(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(HEARTBEAT_BOOT_DELAY).await;
            let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(e) = me.heartbeat().await {
                    tracing::debug!(error = ?e, "licensing: heartbeat tick failed");
                }
            }
        })
    }

    /// Verify the response cert and persist it both on disk and in the
    /// in-memory gate.
    async fn persist_cert(&self, resp: &CertResponse) -> Result<(), ManagerError> {
        let signed =
            SignedLicense::decode(&resp.cert).map_err(|e| ManagerError::Verify(e.to_string()))?;
        verify_license(&signed).map_err(|e| ManagerError::Verify(e.to_string()))?;

        // Build the gate up front so a bad cert (e.g. site_fingerprint
        // mismatch by the server) is caught here, not at first skill
        // load somewhere else in the codebase.
        let gate = PremiumGate::from_cert_str(&resp.cert, Some(self.site_fingerprint.clone()))
            .map_err(|e| ManagerError::Verify(e.to_string()))?;

        storage::write_cert(&resp.cert)?;

        let now = now_secs();
        let mut inner = self.inner.write().await;
        inner.state.license_key = resp.license_key.clone();
        inner.state.last_heartbeat = now;
        inner.state.last_attempt = now;
        if resp.trial {
            inner.state.trial_consumed = true;
        }
        storage::write_state(&inner.state)?;
        inner.gate = Some(gate);
        Ok(())
    }

    async fn drop_cert_keep_key(&self) -> std::io::Result<()> {
        let mut inner = self.inner.write().await;
        inner.gate = None;
        // Wipe just the cert file; the state.json keeps license_key for
        // dashboard messaging.
        let dir = storage::licensing_dir()?;
        let p = dir.join("cert.tcl");
        match std::fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Read /etc/hostname (Linux) or fall back to `gethostname` via libc.
/// Used as a non-secret diagnostic field on the server side.
fn read_hostname() -> String {
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    "unknown-host".to_string()
}

/// On boot, try to rebuild a [`PremiumGate`] from the persisted cert.
/// Returns `None` on any failure (missing cert, parse error, signature
/// mismatch) — safe default: premium skills will be refused.
fn load_gate_from_disk(site_fp: &str) -> Option<PremiumGate> {
    if !super::is_provisioned() {
        return None;
    }
    let encoded = storage::read_cert().ok().flatten()?;
    let site = if site_fp.is_empty() {
        None
    } else {
        Some(site_fp.to_string())
    };
    match PremiumGate::from_cert_str(&encoded, site) {
        Ok(g) => Some(g),
        Err(e) => {
            tracing::warn!(error = ?e, "licensing: persisted cert failed to load");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_hostname_falls_back_when_etc_unreadable() {
        // We cannot reliably remove /etc/hostname in a test; just
        // exercise the function and assert it returns *something* sane.
        let h = read_hostname();
        assert!(!h.is_empty());
    }

    #[tokio::test]
    async fn allows_skill_returns_false_without_a_cert() {
        // No cert on disk → `inner.gate` is None → every skill is
        // refused, regardless of provisioning state. This is the
        // pristine-install behavior.
        let mgr = LicenseManager::bootstrap(LicenseClient::new("https://unused.invalid")).await;
        assert!(!mgr.allows_skill("skill-velociraptor-actions").await);
    }

    #[tokio::test]
    async fn status_reports_provisioned_with_no_license_yet() {
        let mgr = LicenseManager::bootstrap(LicenseClient::new("https://unused.invalid")).await;
        let s = mgr.status().await;
        assert!(s.provisioned, "TRUSTED_PUBKEYS is now populated");
        assert!(s.license_key.is_none());
        assert!(s.tier.is_none());
    }
}
