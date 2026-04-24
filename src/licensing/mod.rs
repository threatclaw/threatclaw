//! Licensing for ThreatClaw premium skills.
//!
//! This module provides offline verification of license certificates for
//! premium skills distributed through `hub.threatclaw.io`. The ThreatClaw
//! core itself remains AGPL v3 and never requires a license; this
//! infrastructure only gates skills whose catalog manifest declares
//! `"tier": "premium"`.
//!
//! # Design
//!
//! - A **license certificate** is a short JSON document signed with Ed25519
//!   by the Licensor's offline-stored private key. The matching public key
//!   is embedded in this module at compile time (see `TRUSTED_PUBKEY`).
//! - Verification is **offline by default** — a cert carries its own
//!   `expires_at` and `grace_period_days`. No network call is required
//!   to load premium skills under a valid cert, which keeps air-gapped
//!   deployments fully functional.
//! - Optional **revocation check** against `license.threatclaw.io` runs in
//!   the background if reachable; a revocation takes effect only after the
//!   grace period, to protect against accidental outages.
//! - The license cert optionally pins to a **site fingerprint** (sha256 of
//!   machine id + install path) to discourage casual cert copying between
//!   deployments.
//!
//! # What this module does NOT do
//!
//! - It does not download premium skills. Distribution is a separate
//!   concern handled by the marketplace client (to be added later).
//! - It does not enforce payment — that is Stripe's job, out-of-band.
//! - It does not generate licenses. That is the Licensor's responsibility,
//!   performed by the license issuance service that signs with the matching
//!   Ed25519 private key.

pub mod cert;
pub mod gate;
pub mod grace;
pub mod verify;

pub use cert::{LicenseCert, LicenseCertError, LicenseTier, SignedLicense};
pub use gate::{GateDecision, GateError, PremiumGate};
pub use grace::{GraceState, GraceTracker};
pub use verify::{verify_license, VerifyError};

/// Default grace period applied when a cert does not specify one.
pub const DEFAULT_GRACE_DAYS: u32 = 90;

/// Current license format version. Increment on breaking changes to the
/// cert schema. Verifiers reject certs with a higher version than they
/// support.
pub const LICENSE_FORMAT_VERSION: u32 = 1;

/// Ed25519 public key trusted to sign valid license certificates.
///
/// This is embedded at compile time. It is the *public* half of a keypair
/// whose private half is held offline by the Licensor (CyberConsulting.fr)
/// and never touches any ThreatClaw installation.
///
/// Rotation: if the private key is ever compromised, a new public key is
/// shipped in a ThreatClaw core update, and all existing certs must be
/// re-issued. There is intentionally no "key trust store" mechanism —
/// replacing the compiled-in key is a deliberate, auditable event.
///
/// **The placeholder value below is a known-dummy key (32 zero bytes).**
/// Before the first premium skill ships, a real keypair MUST be generated
/// offline (see `docs/operations/premium-key-rotation.md`) and this
/// constant replaced.
pub const TRUSTED_PUBKEY: [u8; 32] = [0u8; 32];

/// Returns true once a non-placeholder public key has been provisioned.
/// Premium-skill gating is disabled as long as this returns false — this
/// is a safety rail so that development builds never accidentally enforce
/// against a dummy key.
pub fn is_provisioned() -> bool {
    TRUSTED_PUBKEY != [0u8; 32]
}
