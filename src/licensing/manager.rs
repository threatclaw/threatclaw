//! `LicenseManager` — runtime owner of licensing state.
//!
//! One instance per process. Owns the [`super::api_client::LicenseClient`],
//! the cached site fingerprint, and one [`super::PremiumGate`] per active
//! license. The skill registry consults this manager when loading premium
//! skills; a skill is allowed if **any** of the active gates covers it.
//!
//! Multi-license rationale: a customer can buy multiple skills over time
//! through separate Stripe transactions (e.g. velociraptor today,
//! opnsense in three months). Each purchase produces its own
//! `license_key` + cert, so the manager has to OR-compose decisions
//! across all of them rather than holding a single "current" license.
//!
//! Lifecycle:
//!
//! 1. [`LicenseManager::bootstrap`] is called once at process start. It
//!    loads every persisted cert (via [`storage::read_all_certs`]) and
//!    constructs one gate per validated cert. Failure to load any single
//!    cert is non-fatal — the others continue to work.
//! 2. The dashboard / CLI calls [`LicenseManager::activate`],
//!    [`LicenseManager::start_trial`], or [`LicenseManager::deactivate`]
//!    in response to user actions. Activation appends a new license;
//!    deactivation removes one specific license.
//! 3. [`LicenseManager::spawn_heartbeat`] runs a background task that
//!    refreshes every active license's cert with the license server
//!    every 7 days, so the rolling 30-day cert never lapses for an
//!    online deployment.

use std::collections::HashMap;
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
use super::storage::{self, LicenseEntry, LicensingState};
use super::trial;
use super::verify::verify_license;

/// Heartbeat cadence. The cert issued by the server is valid 30 days; we
/// refresh weekly so a single missed call does not threaten the cert.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(7 * 86_400);

/// Initial delay before the first heartbeat attempt after process boot.
/// Picks a small jitter so that 1000 simultaneously-restarted clients
/// (e.g. after a coordinated upgrade) do not stampede the API.
const HEARTBEAT_BOOT_DELAY: Duration = Duration::from_secs(60);

// ────────────────────────────────────────────────────────────────────
// Status types — what the dashboard renders
// ────────────────────────────────────────────────────────────────────

/// Per-license snapshot for the dashboard.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActiveLicense {
    pub license_key: String,
    pub licensee_email: String,
    pub tier: LicenseTier,
    pub skills: Vec<String>,
    pub grace: GraceState,
    pub trial: bool,
    pub expires_at: u64,
    pub last_heartbeat: u64,
    pub last_attempt: u64,
    /// True if this license currently has the right to run HITL
    /// destructive actions. Set in [`LicenseManager::status`] from the
    /// in-memory gate, not derived from the cert payload alone — so
    /// expired / revoked / not-yet-active licenses report `false`
    /// even though their cert advertises HITL skills.
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub allows_hitl: bool,
}

/// Aggregate diagnostic snapshot. Composed of per-license entries plus
/// install-wide flags.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LicenseStatus {
    /// Whether the licensing pipeline is wired up (real pubkey embedded).
    pub provisioned: bool,
    /// One entry per active license_key on this install.
    pub licenses: Vec<ActiveLicense>,
    /// Whether this install has already consumed its free trial (per
    /// local state — server still authoritative).
    pub trial_consumed: bool,
}

impl LicenseStatus {
    /// True when at least one active license is present.
    pub fn has_any_license(&self) -> bool {
        !self.licenses.is_empty()
    }
}

// ────────────────────────────────────────────────────────────────────
// Errors
// ────────────────────────────────────────────────────────────────────

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
    #[error("license `{0}` not found locally — paste it via /api/tc/licensing/activate first")]
    UnknownLocalLicense(String),
}

// ────────────────────────────────────────────────────────────────────
// Manager
// ────────────────────────────────────────────────────────────────────

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
    /// Per-license active gate. Keyed by `license_key` for O(1) lookup
    /// when refreshing or deactivating one specific license.
    gates: HashMap<String, PremiumGate>,
}

impl Inner {
    fn allows_skill_now(&self, skill_id: &str) -> bool {
        self.gates
            .values()
            .any(|g| matches!(g.check(skill_id), super::GateDecision::Allowed { .. }))
    }
}

impl LicenseManager {
    /// Constructor + initial state load. Always succeeds; on disk errors
    /// the manager comes up with empty state and logs a warning. Reads
    /// every cert under `licensing/certs/` and rebuilds one gate per
    /// successfully-verified file.
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
        let gates = load_gates_from_disk(&site_fingerprint);

        Self {
            inner: Arc::new(RwLock::new(Inner { state, gates })),
            client,
            install_id,
            site_fingerprint,
            hostname,
            agent_version,
        }
    }

    /// True if at least one in-memory gate currently allows the given
    /// premium skill. Returns `false` for unprovisioned builds, missing
    /// certs, or any denial reason. Cheap, suitable for hot paths in
    /// skill loading. Kept around for any callers still asking by skill
    /// id; new code should use [`Self::allows_hitl`] which expresses the
    /// post-2026-04-26 doctrine pivot.
    pub async fn allows_skill(&self, skill_id: &str) -> bool {
        if !super::is_provisioned() {
            return false;
        }
        let inner = self.inner.read().await;
        inner.allows_skill_now(skill_id)
    }

    /// True if any active license unlocks the global "Action Pack" —
    /// the single SKU that gates every HITL destructive flow (firewall
    /// block, AD disable, EDR isolate, ...).
    ///
    /// Phase A.1 (2026-04-28 pricing pivot) — HITL is now free for every
    /// tier including the unlicensed Free instance. The pricing moat is
    /// the asset-count tier (see `allows_assets_count`), not the ability
    /// to act on threats: gating an emergency response button behind a
    /// paywall creates moral friction at the worst possible time.
    ///
    /// Function kept (not deleted) so the call sites at
    /// `tool_calling.rs`, the API handlers, and the frontend manifest
    /// loader continue to work unchanged. If we ever decide to gate a
    /// specific destructive action, this is the surgical lever.
    pub async fn allows_hitl(&self) -> bool {
        true
    }

    /// Diagnostic snapshot for the dashboard.
    pub async fn status(&self) -> LicenseStatus {
        let inner = self.inner.read().await;
        let mut licenses = Vec::with_capacity(inner.state.licenses.len());
        let now = now_secs();

        for entry in &inner.state.licenses {
            let mut active = ActiveLicense {
                license_key: entry.license_key.clone(),
                licensee_email: String::new(),
                tier: LicenseTier::Individual, // overwritten below if cert present
                skills: vec![],
                grace: GraceState::Lapsed,
                trial: false,
                expires_at: 0,
                last_heartbeat: entry.last_heartbeat,
                last_attempt: entry.last_attempt,
                active: false,
                // A.1 pricing pivot — HITL is unconditionally available;
                // the status snapshot reflects this so the dashboard
                // doesn't keep showing a per-license HITL gate.
                allows_hitl: true,
            };
            if let Ok(Some(encoded)) = storage::read_cert(&entry.license_key) {
                if let Ok(signed) = SignedLicense::decode(&encoded) {
                    active.licensee_email = signed.cert.licensee.email.clone();
                    active.tier = signed.cert.tier;
                    active.skills = signed.cert.skills.clone();
                    active.expires_at = signed.cert.expires_at;
                    active.trial = trial::is_trial(&signed.cert);
                    active.grace = assess(&signed.cert, now);
                    active.active = matches!(
                        active.grace,
                        GraceState::Valid
                            | GraceState::RenewalSoon { .. }
                            | GraceState::InGrace { .. }
                    );
                }
            }
            licenses.push(active);
        }

        LicenseStatus {
            provisioned: super::is_provisioned(),
            licenses,
            trial_consumed: inner.state.trial_consumed,
        }
    }

    /// Activate a new license_key on this install, **adding** it to any
    /// pre-existing licenses. Re-activating a key already present
    /// behaves as a heartbeat refresh (idempotent).
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
        // Defense-in-depth: also flag the install as trial-consumed.
        let mut inner = self.inner.write().await;
        inner.state.trial_consumed = true;
        storage::write_state(&inner.state).ok();
        drop(inner);
        Ok(self.status().await)
    }

    /// Refresh **one** license's cert against the server. If
    /// `license_key` is `None`, refresh **every** active license (used
    /// by the background heartbeat task). Per-license errors are
    /// swallowed in the broadcast variant so one stale license doesn't
    /// block the others.
    pub async fn heartbeat(&self, license_key: Option<&str>) -> Result<(), ManagerError> {
        if !super::is_provisioned() {
            return Err(ManagerError::NotProvisioned);
        }

        let targets: Vec<String> = {
            let inner = self.inner.read().await;
            match license_key {
                Some(k) if inner.state.find(k).is_some() => vec![k.to_string()],
                Some(k) => return Err(ManagerError::UnknownLocalLicense(k.to_string())),
                None => inner
                    .state
                    .licenses
                    .iter()
                    .map(|l| l.license_key.clone())
                    .collect(),
            }
        };

        if targets.is_empty() {
            return Ok(());
        }

        let mut last_err: Option<ManagerError> = None;
        for key in &targets {
            // Stamp the attempt upfront, even before the call.
            {
                let mut inner = self.inner.write().await;
                if let Some(entry) = inner.state.find_mut(key) {
                    entry.last_attempt = now_secs();
                }
                storage::write_state(&inner.state).ok();
            }

            let req = HeartbeatRequest {
                license_key: key,
                install_id: &self.install_id,
                site_fingerprint: &self.site_fingerprint,
                agent_version: &self.agent_version,
            };
            match self.client.heartbeat(&req).await {
                Ok(resp) => {
                    if let Err(e) = self.persist_cert(&resp).await {
                        tracing::warn!(license_key = %key, error = ?e, "heartbeat persist failed");
                        last_err = Some(e);
                    }
                }
                Err(ApiError::Rejected {
                    kind: ApiRejection::Revoked,
                    ..
                })
                | Err(ApiError::Rejected {
                    kind: ApiRejection::SubscriptionInactive,
                    ..
                }) => {
                    tracing::warn!(license_key = %key, "heartbeat refused, dropping cert");
                    self.drop_cert_keep_entry(key).await.ok();
                    last_err = Some(ManagerError::Api(ApiError::Rejected {
                        kind: ApiRejection::SubscriptionInactive,
                        message: format!("subscription no longer active for {key}"),
                    }));
                }
                Err(e) => {
                    tracing::debug!(license_key = %key, error = ?e, "heartbeat transient failure");
                    if license_key.is_some() {
                        // Caller asked for one specific license — surface
                        // the error directly instead of swallowing.
                        return Err(ManagerError::Api(e));
                    }
                    last_err = Some(ManagerError::Api(e));
                }
            }
        }
        // For batch (None) heartbeats, don't fail the whole call if one
        // license errored — others may have succeeded.
        if license_key.is_some() {
            return last_err.map(Err).unwrap_or(Ok(()));
        }
        Ok(())
    }

    /// Tell the server to release **one** install/license slot, then
    /// remove that license from local state. Best-effort: if the server
    /// is unreachable we still wipe locally so the user can move the
    /// license to another machine without waiting for the API.
    pub async fn deactivate(&self, license_key: &str) -> Result<(), ManagerError> {
        if !super::is_provisioned() {
            return Err(ManagerError::NotProvisioned);
        }
        {
            let inner = self.inner.read().await;
            if inner.state.find(license_key).is_none() {
                return Err(ManagerError::UnknownLocalLicense(license_key.to_string()));
            }
        }

        let req = DeactivateRequest {
            license_key,
            install_id: &self.install_id,
        };
        if let Err(e) = self.client.deactivate(&req).await {
            tracing::warn!(license_key = %license_key, error = ?e, "server deactivate failed, wiping local anyway");
        }

        let mut inner = self.inner.write().await;
        inner.state.remove(license_key);
        inner.gates.remove(license_key);
        storage::write_state(&inner.state)?;
        storage::remove_cert(license_key)?;
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
                if let Err(e) = me.heartbeat(None).await {
                    tracing::debug!(error = ?e, "licensing: heartbeat tick failed");
                }
            }
        })
    }

    /// Verify the cert returned by the server, persist it on disk
    /// (under its license_key), and update the in-memory gate map.
    async fn persist_cert(&self, resp: &CertResponse) -> Result<(), ManagerError> {
        let signed =
            SignedLicense::decode(&resp.cert).map_err(|e| ManagerError::Verify(e.to_string()))?;
        verify_license(&signed).map_err(|e| ManagerError::Verify(e.to_string()))?;

        // Build the gate up front so a bad cert (e.g. site_fingerprint
        // mismatch by the server) is caught here, not at first skill
        // load somewhere else in the codebase.
        let gate = PremiumGate::from_cert_str(&resp.cert, Some(self.site_fingerprint.clone()))
            .map_err(|e| ManagerError::Verify(e.to_string()))?;

        storage::write_cert(&resp.license_key, &resp.cert)?;

        let now = now_secs();
        let mut inner = self.inner.write().await;
        let entry = inner.state.upsert(&resp.license_key, now);
        entry.last_heartbeat = now;
        entry.last_attempt = now;
        if resp.trial {
            inner.state.trial_consumed = true;
        }
        storage::write_state(&inner.state)?;
        inner.gates.insert(resp.license_key.clone(), gate);
        Ok(())
    }

    /// Drop the in-memory gate + on-disk cert for one license, but keep
    /// the entry in `state.licenses` so the dashboard can show
    /// "subscription inactive, please renew" instead of pretending the
    /// license never existed.
    async fn drop_cert_keep_entry(&self, license_key: &str) -> std::io::Result<()> {
        let mut inner = self.inner.write().await;
        inner.gates.remove(license_key);
        storage::remove_cert(license_key)
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

/// On boot, scan `licensing/certs/` and rebuild one gate per cert that
/// successfully verifies. Failures (corrupted file, signature mismatch,
/// site-fingerprint mismatch) are logged and skipped — we do not want
/// one bad cert to deny every other valid license on the machine.
fn load_gates_from_disk(site_fp: &str) -> HashMap<String, PremiumGate> {
    let mut out = HashMap::new();
    if !super::is_provisioned() {
        return out;
    }
    let site = if site_fp.is_empty() {
        None
    } else {
        Some(site_fp.to_string())
    };
    let certs = match storage::read_all_certs() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = ?e, "licensing: failed to enumerate certs");
            return out;
        }
    };
    for (key, encoded) in certs {
        match PremiumGate::from_cert_str(&encoded, site.clone()) {
            Ok(g) => {
                out.insert(key, g);
            }
            Err(e) => {
                tracing::warn!(license_key = %key, error = ?e, "licensing: persisted cert failed to load");
            }
        }
    }
    out
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
        // No certs on disk → no gates → every skill is refused, regardless
        // of provisioning state. This is the pristine-install behavior.
        let mgr = LicenseManager::bootstrap(LicenseClient::new("https://unused.invalid")).await;
        assert!(!mgr.allows_skill("skill-velociraptor-actions").await);
        // A.1 pricing pivot — HITL is unconditionally true now (no longer
        // gated). The asset count is the new pricing lever.
        assert!(mgr.allows_hitl().await);
    }

    #[tokio::test]
    async fn status_reports_provisioned_with_no_license_yet() {
        let mgr = LicenseManager::bootstrap(LicenseClient::new("https://unused.invalid")).await;
        let s = mgr.status().await;
        assert!(s.provisioned, "TRUSTED_PUBKEYS is now populated");
        assert!(s.licenses.is_empty());
        assert!(!s.has_any_license());
    }

    #[tokio::test]
    async fn deactivate_unknown_license_returns_typed_error() {
        let mgr = LicenseManager::bootstrap(LicenseClient::new("https://unused.invalid")).await;
        let r = mgr.deactivate("TC-NEVER-SEEN-XXXX-XXXX").await;
        assert!(matches!(r, Err(ManagerError::UnknownLocalLicense(_))));
    }

    #[tokio::test]
    async fn heartbeat_for_unknown_license_returns_typed_error() {
        let mgr = LicenseManager::bootstrap(LicenseClient::new("https://unused.invalid")).await;
        let r = mgr.heartbeat(Some("TC-NEVER-SEEN-XXXX-XXXX")).await;
        assert!(matches!(r, Err(ManagerError::UnknownLocalLicense(_))));
    }

    #[tokio::test]
    async fn heartbeat_with_no_licenses_is_a_noop() {
        let mgr = LicenseManager::bootstrap(LicenseClient::new("https://unused.invalid")).await;
        // Empty state → no targets → nothing to do, nothing to fail.
        assert!(mgr.heartbeat(None).await.is_ok());
    }
}
