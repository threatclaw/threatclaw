//! Grace-period state machine for license renewal.
//!
//! A license cert carries a hard `expires_at` plus a `grace_period_days`
//! window during which premium skills continue to work even if the Licensee
//! cannot reach the issuer to renew. This buys time for real situations:
//! expired credit card, accounting approval lag, outage of
//! `license.threatclaw.io`, air-gapped site with a lapsed courier delivery.
//!
//! The goal is to **never silently brick a production deployment** because
//! of a payment-provider hiccup. Warnings escalate over the grace window,
//! and only after full expiry does enforcement kick in.

use super::cert::LicenseCert;

/// Where a license stands relative to its lifecycle at a given moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraceState {
    /// Cert is valid, no action needed.
    Valid,
    /// Cert approaches expiry — nudge the licensee.
    /// `days_remaining` is how many full days until `expires_at`.
    RenewalSoon { days_remaining: u32 },
    /// Cert has expired but is within the grace window.
    /// `days_into_grace` is elapsed, `days_left_in_grace` is remaining.
    InGrace {
        days_into_grace: u32,
        days_left_in_grace: u32,
    },
    /// Cert + grace fully lapsed. Premium skills must refuse to load.
    Lapsed,
}

impl GraceState {
    /// How urgent is this state? Used by the dashboard to pick a UI banner.
    pub fn urgency(&self) -> Urgency {
        match self {
            GraceState::Valid => Urgency::None,
            GraceState::RenewalSoon { days_remaining } if *days_remaining <= 7 => Urgency::Warning,
            GraceState::RenewalSoon { .. } => Urgency::Info,
            GraceState::InGrace { .. } => Urgency::Critical,
            GraceState::Lapsed => Urgency::Blocking,
        }
    }

    /// True if premium skills are still permitted to run.
    pub fn permits_premium(&self) -> bool {
        !matches!(self, GraceState::Lapsed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    None,
    Info,
    Warning,
    Critical,
    Blocking,
}

/// Threshold in seconds below which we raise a `RenewalSoon` warning.
/// 14 days — enough to get an invoice processed in a typical French SMB
/// accounting cycle.
pub const RENEWAL_WARNING_WINDOW_DAYS: u32 = 14;

/// Compute the grace state of a cert at wall-clock `now_secs`.
pub fn assess(cert: &LicenseCert, now_secs: u64) -> GraceState {
    const DAY: u64 = 86_400;

    if cert.is_fully_lapsed(now_secs) {
        return GraceState::Lapsed;
    }

    if let Some(expired_secs) = cert.seconds_expired(now_secs) {
        let grace_total_secs = cert.grace_period_days as u64 * DAY;
        let grace_left_secs = grace_total_secs.saturating_sub(expired_secs);
        return GraceState::InGrace {
            days_into_grace: (expired_secs / DAY) as u32,
            days_left_in_grace: (grace_left_secs / DAY) as u32,
        };
    }

    // Still valid — check whether we should nudge.
    let until_expiry_secs = cert.expires_at.saturating_sub(now_secs);
    let days_remaining = (until_expiry_secs / DAY) as u32;
    if days_remaining <= RENEWAL_WARNING_WINDOW_DAYS {
        return GraceState::RenewalSoon { days_remaining };
    }

    GraceState::Valid
}

/// Stateful tracker that can detect transitions between states across
/// polls — useful for emitting exactly one notification per transition
/// (avoids daily nag loops).
#[derive(Debug, Default, Clone)]
pub struct GraceTracker {
    last_state: Option<GraceState>,
}

impl GraceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns Some(new_state) if the state has changed since last poll,
    /// None otherwise. The tracker records the new state.
    pub fn poll(&mut self, cert: &LicenseCert, now_secs: u64) -> Option<GraceState> {
        let new_state = assess(cert, now_secs);
        if self.last_state != Some(new_state) {
            self.last_state = Some(new_state);
            Some(new_state)
        } else {
            None
        }
    }

    pub fn current(&self) -> Option<GraceState> {
        self.last_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::licensing::cert::{LicenseCert, LicenseTier, Licensee};

    const DAY: u64 = 86_400;

    fn cert_expiring_at(expires_at: u64) -> LicenseCert {
        LicenseCert {
            v: 1,
            licensee: Licensee {
                id: "t".into(),
                email: "t@t.fr".into(),
                org: String::new(),
            },
            tier: LicenseTier::Individual,
            skills: vec!["skill-test".into()],
            site_fingerprint: None,
            issued_at: 0,
            expires_at,
            grace_period_days: 90,
            revocation_check_url: String::new(),
        }
    }

    #[test]
    fn valid_state_when_far_from_expiry() {
        let cert = cert_expiring_at(100 * DAY);
        assert_eq!(assess(&cert, 10 * DAY), GraceState::Valid);
    }

    #[test]
    fn renewal_soon_within_14d() {
        let cert = cert_expiring_at(100 * DAY);
        let now = 100 * DAY - 3 * DAY; // 3 days left
        match assess(&cert, now) {
            GraceState::RenewalSoon { days_remaining } => assert_eq!(days_remaining, 3),
            s => panic!("expected RenewalSoon, got {:?}", s),
        }
    }

    #[test]
    fn in_grace_after_expiry() {
        let cert = cert_expiring_at(100 * DAY);
        let now = 100 * DAY + 10 * DAY;
        match assess(&cert, now) {
            GraceState::InGrace {
                days_into_grace,
                days_left_in_grace,
            } => {
                assert_eq!(days_into_grace, 10);
                assert_eq!(days_left_in_grace, 80);
            }
            s => panic!("expected InGrace, got {:?}", s),
        }
    }

    #[test]
    fn lapsed_after_full_grace() {
        let cert = cert_expiring_at(100 * DAY);
        let now = 100 * DAY + 91 * DAY;
        assert_eq!(assess(&cert, now), GraceState::Lapsed);
    }

    #[test]
    fn tracker_emits_once_per_transition() {
        let cert = cert_expiring_at(100 * DAY);
        let mut t = GraceTracker::new();

        // First poll: transition None -> Valid, emits.
        assert!(t.poll(&cert, 10 * DAY).is_some());
        // Same state again: no emission.
        assert!(t.poll(&cert, 20 * DAY).is_none());
        // Transition to RenewalSoon: emits.
        assert!(t.poll(&cert, 100 * DAY - 5 * DAY).is_some());
        // Same window: no emission.
        let s = t.poll(&cert, 100 * DAY - 5 * DAY + 60); // 1 minute later, still same "days_remaining"
        assert!(s.is_none());
    }

    #[test]
    fn permits_premium_until_lapsed() {
        assert!(GraceState::Valid.permits_premium());
        assert!(GraceState::RenewalSoon { days_remaining: 3 }.permits_premium());
        assert!(GraceState::InGrace {
            days_into_grace: 30,
            days_left_in_grace: 60
        }
        .permits_premium());
        assert!(!GraceState::Lapsed.permits_premium());
    }
}
