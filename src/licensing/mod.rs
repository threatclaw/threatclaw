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
//!   by the Licensor's offline-stored private key. The matching public keys
//!   are embedded in this module at compile time (see [`TRUSTED_PUBKEYS`]).
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

pub mod api_client;
pub mod cert;
pub mod fingerprint;
pub mod gate;
pub mod grace;
pub mod manager;
pub mod storage;
pub mod trial;
pub mod verify;

pub use api_client::{
    ActivateRequest, ApiError, ApiRejection, CertResponse, DeactivateRequest, HeartbeatRequest,
    LicenseClient, RevocationStatus, TrialStartRequest,
};
pub use cert::{LicenseCert, LicenseCertError, LicenseTier, SignedLicense};
pub use fingerprint::{hash_install_id, site_fingerprint};
pub use gate::{GateDecision, GateError, PremiumGate};
pub use grace::{GraceState, GraceTracker};
pub use manager::{ActiveLicense, LicenseManager, LicenseStatus, ManagerError};
pub use storage::{LicenseEntry, LicensingState, licensing_dir, load_or_create_install_id};
pub use verify::{VerifyError, verify_license};

/// Default grace period applied when a cert does not specify one.
pub const DEFAULT_GRACE_DAYS: u32 = 90;

/// Current license format version. Increment on breaking changes to the
/// cert schema. Verifiers reject certs with a higher version than they
/// support.
pub const LICENSE_FORMAT_VERSION: u32 = 1;

/// Ed25519 public keys trusted to sign valid license certificates.
///
/// Embedded at compile time. The matching private keys are held offline
/// by the Licensor (CyberConsulting.fr) and never touch any ThreatClaw
/// installation. [`verify_license`] accepts any cert signed by any of
/// these keys — this is the **multi-trust-anchor** pattern that makes
/// emergency rotation a no-op for clients.
///
/// # Slot semantics
///
/// - Slot **PRIMARY** (`TRUSTED_PUBKEYS[0]`) — privkey actively signs
///   every cert today.
/// - Slot **EMERGENCY** (`TRUSTED_PUBKEYS[1]`) — privkey kept offline,
///   never used until rotation. If PRIMARY is lost or compromised, the
///   issuance server immediately switches to signing with the EMERGENCY
///   privkey. Existing clients accept the new certs without any update,
///   because they already trust this pubkey.
/// - Additional slots (3+) may appear temporarily during a planned
///   transition (e.g. introducing a new PRIMARY in a TC update while
///   keeping the previous PRIMARY trusted for stragglers).
///
/// # Rotation runbook (summary)
///
/// 1. Detect compromise / loss of PRIMARY.
/// 2. Server flips signing to the EMERGENCY privkey — clients keep
///    working unchanged.
/// 3. Generate a fresh keypair offline (call it NEW). Build a TC update
///    that adds `NEW` to this slice — keep both EMERGENCY (now signing)
///    and NEW (next-EMERGENCY).
/// 4. Push the update; clients adopt it over the following weeks.
/// 5. Once adoption is acceptable, build another TC update that swaps
///    EMERGENCY → NEW as the active signing target, and adds yet another
///    fresh emergency slot.
///
/// # Provisioning
///
/// All-zero entries are placeholder slots; they are skipped during
/// verification and never accept signatures. [`is_provisioned`] returns
/// true as soon as **any** slot holds a real key — so a build with only
/// the PRIMARY filled in (EMERGENCY still zero) is functional but not
/// disaster-resilient. Always provision both before the first paid
/// release.
///
/// **The placeholder value below is a known-dummy state (two zero-byte
/// slots).** Before the first premium skill ships, a real keypair MUST
/// be generated offline (see `docs/operations/premium-key-rotation.md`)
/// and the constants below replaced.
pub const TRUSTED_PUBKEYS: &[[u8; 32]] = &[
    // PRIMARY — privkey signs new certs (CyberConsulting.fr, generated 2026-04-25).
    // hex: c0d2eb890ad52c14892071ba77fba6ec0f08b6ea52ac53c3e12a338698cb28a9
    [
        0xc0, 0xd2, 0xeb, 0x89, 0x0a, 0xd5, 0x2c, 0x14, 0x89, 0x20, 0x71, 0xba, 0x77, 0xfb, 0xa6,
        0xec, 0x0f, 0x08, 0xb6, 0xea, 0x52, 0xac, 0x53, 0xc3, 0xe1, 0x2a, 0x33, 0x86, 0x98, 0xcb,
        0x28, 0xa9,
    ],
    // EMERGENCY — pre-generated standby. Privkey in cold storage (USB + paper),
    // never used until rotation. Generated 2026-04-25.
    // hex: 9f154a81ae8fe1f3206b4c77a83a012823dea35649a06198d759257852008e10
    [
        0x9f, 0x15, 0x4a, 0x81, 0xae, 0x8f, 0xe1, 0xf3, 0x20, 0x6b, 0x4c, 0x77, 0xa8, 0x3a, 0x01,
        0x28, 0x23, 0xde, 0xa3, 0x56, 0x49, 0xa0, 0x61, 0x98, 0xd7, 0x59, 0x25, 0x78, 0x52, 0x00,
        0x8e, 0x10,
    ],
];

/// Convenience view: the active signing pubkey (PRIMARY slot). Used by
/// the dashboard to surface a fingerprint for support / audit purposes.
pub fn primary_pubkey() -> &'static [u8; 32] {
    &TRUSTED_PUBKEYS[0]
}

/// Returns true once at least one non-placeholder public key has been
/// provisioned. Premium-skill gating is disabled as long as this returns
/// false — a safety rail so that development builds never accidentally
/// enforce against a dummy key.
pub fn is_provisioned() -> bool {
    TRUSTED_PUBKEYS.iter().any(|k| k != &[0u8; 32])
}
