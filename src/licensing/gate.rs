//! Gate that decides whether a given premium skill is allowed to load.
//!
//! Called at skill-registry load time. The gate composes cert parsing,
//! Ed25519 verification, grace-period assessment, and optional
//! site-fingerprint pinning into a single boolean decision with an
//! attached reason (for audit logging and dashboard banners).

use super::cert::{now_secs, LicenseCertError, SignedLicense};
use super::grace::{assess, GraceState};
use super::verify::{verify_license, VerifyError};

/// Outcome of gating a premium skill load.
#[derive(Debug, Clone)]
pub enum GateDecision {
    /// Skill allowed. Includes the current grace state so callers can
    /// surface a dashboard banner (e.g. "license expires in 9 days").
    Allowed { state: GraceState },
    /// Skill refused. `reason` is safe to log and display.
    Denied { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("no license certificate configured for this install")]
    NoLicense,
    #[error("cert parse error: {0}")]
    Parse(#[from] LicenseCertError),
    #[error("cert verification failed: {0}")]
    Verify(#[from] VerifyError),
}

/// The gate itself. Holds one parsed + verified license plus the site
/// fingerprint computed for this installation.
///
/// Typical usage:
///
/// ```ignore
/// let gate = PremiumGate::from_cert_str(cert_b64, site_fp)?;
/// match gate.check("skill-opnsense-actions") {
///     GateDecision::Allowed { state } => load_skill(...),
///     GateDecision::Denied { reason } => {
///         tracing::warn!(reason = %reason, "premium skill refused");
///     }
/// }
/// ```
pub struct PremiumGate {
    signed: SignedLicense,
    site_fingerprint: Option<String>,
}

impl PremiumGate {
    /// Construct a gate from an encoded license string. Verifies the
    /// signature eagerly so a bogus cert fails at startup rather than at
    /// first skill load.
    pub fn from_cert_str(encoded: &str, site_fingerprint: Option<String>) -> Result<Self, GateError> {
        if encoded.trim().is_empty() {
            return Err(GateError::NoLicense);
        }
        let signed = SignedLicense::decode(encoded)?;
        verify_license(&signed)?;
        Ok(Self {
            signed,
            site_fingerprint,
        })
    }

    /// Check whether a specific skill is allowed at the current wall-clock
    /// time. Never panics — denial paths always return a `Denied` with
    /// a human-readable reason.
    pub fn check(&self, skill_id: &str) -> GateDecision {
        self.check_at(skill_id, now_secs())
    }

    /// Same as [`check`], but with injectable time for tests.
    pub fn check_at(&self, skill_id: &str, now_secs: u64) -> GateDecision {
        let cert = &self.signed.cert;

        if !cert.covers_skill(skill_id) {
            return GateDecision::Denied {
                reason: format!(
                    "license does not cover skill `{}` (covered: {})",
                    skill_id,
                    cert.skills.join(", ")
                ),
            };
        }

        if let (Some(site), Some(expected)) =
            (cert.site_fingerprint.as_deref(), self.site_fingerprint.as_deref())
        {
            if site != expected {
                return GateDecision::Denied {
                    reason: "license is pinned to a different site fingerprint".into(),
                };
            }
        }

        let state = assess(cert, now_secs);
        if !state.permits_premium() {
            return GateDecision::Denied {
                reason: format!(
                    "license fully lapsed (expired + {}-day grace elapsed)",
                    cert.grace_period_days
                ),
            };
        }

        GateDecision::Allowed { state }
    }

    pub fn licensee_email(&self) -> &str {
        &self.signed.cert.licensee.email
    }

    pub fn tier(&self) -> super::cert::LicenseTier {
        self.signed.cert.tier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::licensing::cert::{LicenseCert, LicenseTier, Licensee, SignedLicense};

    const DAY: u64 = 86_400;

    fn fake_signed(cert: LicenseCert) -> SignedLicense {
        SignedLicense {
            cert_bytes: serde_json::to_vec(&cert).unwrap(),
            cert,
            signature: [0u8; 64],
        }
    }

    /// Sidesteps `from_cert_str` (which requires a valid signature) to
    /// unit-test the gate logic independently. Verification is covered
    /// by `verify.rs`.
    fn gate_with(cert: LicenseCert, site: Option<String>) -> PremiumGate {
        PremiumGate {
            signed: fake_signed(cert),
            site_fingerprint: site,
        }
    }

    fn base_cert() -> LicenseCert {
        LicenseCert {
            v: 1,
            licensee: Licensee {
                id: "x".into(),
                email: "x@y.fr".into(),
                org: String::new(),
            },
            tier: LicenseTier::ActionPack,
            skills: vec!["skill-opnsense-actions".into()],
            site_fingerprint: None,
            issued_at: 0,
            expires_at: 100 * DAY,
            grace_period_days: 90,
            revocation_check_url: String::new(),
        }
    }

    #[test]
    fn allowed_on_valid_cert() {
        let gate = gate_with(base_cert(), None);
        matches!(
            gate.check_at("skill-opnsense-actions", 10 * DAY),
            GateDecision::Allowed { .. }
        );
    }

    #[test]
    fn denied_when_skill_not_covered() {
        let gate = gate_with(base_cert(), None);
        match gate.check_at("skill-fortinet-actions", 10 * DAY) {
            GateDecision::Denied { reason } => assert!(reason.contains("does not cover")),
            _ => panic!("expected denial"),
        }
    }

    #[test]
    fn wildcard_skill_covers_any() {
        let mut c = base_cert();
        c.skills = vec!["*".into()];
        let gate = gate_with(c, None);
        matches!(
            gate.check_at("skill-anything", 10 * DAY),
            GateDecision::Allowed { .. }
        );
    }

    #[test]
    fn denied_on_site_mismatch() {
        let mut c = base_cert();
        c.site_fingerprint = Some("sha256:aaa".into());
        let gate = gate_with(c, Some("sha256:bbb".into()));
        match gate.check_at("skill-opnsense-actions", 10 * DAY) {
            GateDecision::Denied { reason } => assert!(reason.contains("site")),
            _ => panic!("expected site denial"),
        }
    }

    #[test]
    fn allowed_on_site_match() {
        let mut c = base_cert();
        c.site_fingerprint = Some("sha256:aaa".into());
        let gate = gate_with(c, Some("sha256:aaa".into()));
        matches!(
            gate.check_at("skill-opnsense-actions", 10 * DAY),
            GateDecision::Allowed { .. }
        );
    }

    #[test]
    fn denied_after_full_grace() {
        let gate = gate_with(base_cert(), None);
        let now = 100 * DAY + 91 * DAY;
        match gate.check_at("skill-opnsense-actions", now) {
            GateDecision::Denied { reason } => assert!(reason.contains("lapsed")),
            _ => panic!("expected denial"),
        }
    }

    #[test]
    fn allowed_inside_grace_window() {
        let gate = gate_with(base_cert(), None);
        let now = 100 * DAY + 30 * DAY;
        matches!(
            gate.check_at("skill-opnsense-actions", now),
            GateDecision::Allowed {
                state: GraceState::InGrace { .. }
            }
        );
    }
}
