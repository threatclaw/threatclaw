//! License certificate structure and serialization.
//!
//! A license cert is a small JSON document. For distribution we wrap it
//! with a detached Ed25519 signature into a single base64-encoded file
//! (extension `.tcl` — ThreatClaw License).
//!
//! The wire format is:
//!
//! ```text
//! base64(
//!   u32_le(json_len)
//!   json_bytes
//!   64_signature_bytes
//! )
//! ```
//!
//! This keeps parsing trivial (no framing library, no PKIX complexity) and
//! keeps certs short enough to paste into a support email if needed
//! (typically 600-900 bytes base64).

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Commercial tier of a license. Informational — the actual skills
/// unlocked are in `LicenseCert::skills`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseTier {
    /// One specific premium skill, single site.
    Individual,
    /// All premium skills, single site.
    ActionPack,
    /// All premium skills, unlimited client deployments (MSPs).
    Msp,
    /// Custom enterprise terms (SLA, support, source escrow, ...).
    Enterprise,
}

/// Identity of the party holding the license. Email is the primary key for
/// support and revocation lookups; `org` is for display only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Licensee {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub org: String,
}

/// The license payload — what the Licensor signs.
///
/// All timestamps are UNIX seconds. Field names are short to keep the cert
/// compact enough to round-trip through email / QR / support channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseCert {
    /// Format version, must match [`super::LICENSE_FORMAT_VERSION`] at verify time.
    pub v: u32,
    /// Who this license belongs to.
    pub licensee: Licensee,
    /// Commercial tier (display only).
    pub tier: LicenseTier,
    /// Skill IDs unlocked by this cert. For MSP/Enterprise tiers this is
    /// typically `["*"]` (wildcard, all premium skills).
    pub skills: Vec<String>,
    /// Optional site pin — sha256 of `machine_id + install_path`. When
    /// present, a skill will only load on a matching site. Absent for
    /// MSP/Enterprise tiers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_fingerprint: Option<String>,
    /// When the cert was issued.
    pub issued_at: u64,
    /// When the cert expires (hard stop, modulo grace period).
    pub expires_at: u64,
    /// How many days after `expires_at` the skills remain functional if
    /// renewal cannot reach the issuer. Defaults to [`super::DEFAULT_GRACE_DAYS`].
    #[serde(default = "default_grace")]
    pub grace_period_days: u32,
    /// Endpoint to query for revocation status. May be empty for fully
    /// air-gapped deployments.
    #[serde(default)]
    pub revocation_check_url: String,
}

fn default_grace() -> u32 {
    super::DEFAULT_GRACE_DAYS
}

impl LicenseCert {
    /// True if the cert covers the given skill id. Wildcards (`*`) match
    /// any premium skill.
    pub fn covers_skill(&self, skill_id: &str) -> bool {
        self.skills.iter().any(|s| s == "*" || s == skill_id)
    }

    /// Returns (now - expires_at) in seconds, or None if still valid.
    pub fn seconds_expired(&self, now_secs: u64) -> Option<u64> {
        if now_secs > self.expires_at {
            Some(now_secs - self.expires_at)
        } else {
            None
        }
    }

    /// Returns true if the cert, including its grace period, has fully lapsed.
    pub fn is_fully_lapsed(&self, now_secs: u64) -> bool {
        let grace_secs = self.grace_period_days as u64 * 86400;
        now_secs > self.expires_at.saturating_add(grace_secs)
    }
}

/// A license cert packaged with its detached Ed25519 signature.
///
/// This is the on-disk / on-wire form. To verify, use
/// [`super::verify_license`].
#[derive(Debug, Clone)]
pub struct SignedLicense {
    pub cert: LicenseCert,
    /// Canonical JSON bytes that were signed. Keeping the exact bytes
    /// avoids any round-trip ambiguity with serde's JSON formatting.
    pub cert_bytes: Vec<u8>,
    /// Raw Ed25519 signature (64 bytes).
    pub signature: [u8; 64],
}

#[derive(Debug, thiserror::Error)]
pub enum LicenseCertError {
    #[error("invalid base64: {0}")]
    Base64(String),
    #[error("malformed cert envelope: {0}")]
    Envelope(&'static str),
    #[error("cert JSON could not be parsed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported license format version {got}, this build supports {supported}")]
    UnsupportedVersion { got: u32, supported: u32 },
}

impl SignedLicense {
    /// Parse a base64-encoded `.tcl` file. Does **not** verify the signature
    /// — that is the job of [`super::verify_license`].
    pub fn decode(encoded: &str) -> Result<Self, LicenseCertError> {
        // Strip whitespace (emails often insert line breaks).
        let clean: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
        let raw = B64
            .decode(clean.as_bytes())
            .map_err(|e| LicenseCertError::Base64(e.to_string()))?;

        if raw.len() < 4 + 64 {
            return Err(LicenseCertError::Envelope("envelope too short"));
        }

        let json_len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        let sig_start = 4 + json_len;

        if raw.len() != sig_start + 64 {
            return Err(LicenseCertError::Envelope("envelope length mismatch"));
        }

        let cert_bytes = raw[4..sig_start].to_vec();
        let cert: LicenseCert = serde_json::from_slice(&cert_bytes)?;

        if cert.v > super::LICENSE_FORMAT_VERSION {
            return Err(LicenseCertError::UnsupportedVersion {
                got: cert.v,
                supported: super::LICENSE_FORMAT_VERSION,
            });
        }

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw[sig_start..]);

        Ok(SignedLicense {
            cert,
            cert_bytes,
            signature,
        })
    }

    /// Encode into the on-wire format. Typically only called by the
    /// license issuance service, but exposed for test parity.
    pub fn encode(cert_bytes: &[u8], signature: &[u8; 64]) -> Result<String, LicenseCertError> {
        if cert_bytes.len() > u32::MAX as usize {
            return Err(LicenseCertError::Envelope("cert too large"));
        }
        let mut buf = Vec::with_capacity(4 + cert_bytes.len() + 64);
        buf.extend_from_slice(&(cert_bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(cert_bytes);
        buf.extend_from_slice(signature);
        Ok(B64.encode(&buf))
    }
}

/// Current wall-clock time in UNIX seconds. Separate helper so tests can
/// inject a fixed time via the `_at` functions below.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert() -> LicenseCert {
        LicenseCert {
            v: 1,
            licensee: Licensee {
                id: "test-uuid".into(),
                email: "alice@example.fr".into(),
                org: "Example SARL".into(),
            },
            tier: LicenseTier::ActionPack,
            skills: vec!["skill-opnsense-actions".into()],
            site_fingerprint: None,
            issued_at: 1_715_000_000,
            expires_at: 1_746_536_000,
            grace_period_days: 90,
            revocation_check_url: String::new(),
        }
    }

    #[test]
    fn covers_skill_exact() {
        let c = sample_cert();
        assert!(c.covers_skill("skill-opnsense-actions"));
        assert!(!c.covers_skill("skill-fortinet-actions"));
    }

    #[test]
    fn covers_skill_wildcard() {
        let mut c = sample_cert();
        c.skills = vec!["*".into()];
        assert!(c.covers_skill("skill-anything"));
    }

    #[test]
    fn envelope_roundtrip() {
        let cert = sample_cert();
        let json = serde_json::to_vec(&cert).unwrap();
        let sig = [7u8; 64];
        let encoded = SignedLicense::encode(&json, &sig).unwrap();
        let parsed = SignedLicense::decode(&encoded).unwrap();

        assert_eq!(parsed.cert.licensee.email, cert.licensee.email);
        assert_eq!(parsed.signature, sig);
        assert_eq!(parsed.cert_bytes, json);
    }

    #[test]
    fn envelope_rejects_short() {
        let r = SignedLicense::decode("YWJj"); // 3 bytes decoded, too short
        assert!(matches!(r, Err(LicenseCertError::Envelope(_))));
    }

    #[test]
    fn seconds_expired_and_lapsed() {
        let c = sample_cert();
        assert!(c.seconds_expired(c.expires_at - 1).is_none());
        assert_eq!(c.seconds_expired(c.expires_at + 5), Some(5));

        let grace_secs = c.grace_period_days as u64 * 86400;
        assert!(!c.is_fully_lapsed(c.expires_at + grace_secs - 1));
        assert!(c.is_fully_lapsed(c.expires_at + grace_secs + 1));
    }
}
