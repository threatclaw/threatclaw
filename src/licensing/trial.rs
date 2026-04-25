//! Trial-specific helpers.
//!
//! A trial license is a regular signed [`super::cert::LicenseCert`] with
//! `tier == LicenseTier::Trial` and a 60-day `expires_at`. The licensing
//! pipeline treats it like any other cert; this module just exposes
//! ergonomics for the dashboard ("trial expires in 7 days") and for
//! abuse-prevention bookkeeping.
//!
//! The authoritative anti-abuse check lives on the server: it correlates
//! `(email, install_id, ip block)` to refuse a second trial on the same
//! identity. We additionally persist `trial_consumed = true` locally
//! after a successful trial start, so that a casual `state.json` reset
//! does not lure the user into expecting a fresh trial — defense in
//! depth, not the primary control.

use super::cert::LicenseCert;
use super::storage::{self, LicensingState};

/// Default trial length. Changing this requires a coordinated change on
/// the license server (the cert it issues sets `expires_at`).
pub const TRIAL_DAYS: u32 = 60;

/// True if a cert is a trial cert (tier `Trial`).
pub fn is_trial(cert: &LicenseCert) -> bool {
    cert.tier.is_trial()
}

/// Days remaining on a trial. Returns 0 once expired.
pub fn days_remaining(cert: &LicenseCert, now_secs: u64) -> u32 {
    const DAY: u64 = 86_400;
    if now_secs >= cert.expires_at {
        return 0;
    }
    ((cert.expires_at - now_secs) / DAY) as u32
}

/// Mark the local install as having consumed its trial. Idempotent —
/// safe to call repeatedly.
pub fn mark_consumed() -> std::io::Result<()> {
    let mut state = storage::read_state().unwrap_or_default();
    if state.trial_consumed {
        return Ok(());
    }
    state.trial_consumed = true;
    storage::write_state(&state)
}

/// True if local state already records a consumed trial. The server is
/// still the source of truth — this just lets the dashboard avoid
/// offering "Start trial" when we already know it would be rejected.
pub fn locally_consumed() -> bool {
    storage::read_state()
        .map(|s| s.trial_consumed)
        .unwrap_or(false)
}

/// Bookkeeping after a trial start succeeds with the server.
///
/// Appends the new `license_key` to the multi-license state, marks the
/// trial as consumed, and stamps the heartbeat clock so the background
/// renewal task does not immediately fire a duplicate call.
pub fn record_trial_started(license_key: &str, now_secs: u64) -> std::io::Result<()> {
    let mut state = storage::read_state().unwrap_or_default();
    let entry = state.upsert(license_key, now_secs);
    entry.last_heartbeat = now_secs;
    entry.last_attempt = now_secs;
    state.trial_consumed = true;
    storage::write_state(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::licensing::cert::{LicenseTier, Licensee};

    fn cert_with(tier: LicenseTier, expires_at: u64) -> LicenseCert {
        LicenseCert {
            v: 1,
            licensee: Licensee {
                id: "x".into(),
                email: "x@y.fr".into(),
                org: String::new(),
            },
            tier,
            skills: vec!["skill-velociraptor-actions".into()],
            site_fingerprint: None,
            issued_at: 0,
            expires_at,
            grace_period_days: 0,
            revocation_check_url: String::new(),
        }
    }

    #[test]
    fn is_trial_detects_tier() {
        assert!(is_trial(&cert_with(LicenseTier::Trial, 100)));
        assert!(!is_trial(&cert_with(LicenseTier::Individual, 100)));
        assert!(!is_trial(&cert_with(LicenseTier::ActionPack, 100)));
    }

    #[test]
    fn days_remaining_clamps_to_zero_after_expiry() {
        let c = cert_with(LicenseTier::Trial, 100 * 86_400);
        assert_eq!(days_remaining(&c, 100 * 86_400 + 1), 0);
        assert_eq!(days_remaining(&c, 200 * 86_400), 0);
    }

    #[test]
    fn days_remaining_floors_correctly() {
        let c = cert_with(LicenseTier::Trial, 60 * 86_400);
        assert_eq!(days_remaining(&c, 0), 60);
        assert_eq!(days_remaining(&c, 30 * 86_400), 30);
        // 12 hours before expiry is < 1 full day, must floor to 0.
        assert_eq!(days_remaining(&c, 60 * 86_400 - 12 * 3600), 0);
    }
}
