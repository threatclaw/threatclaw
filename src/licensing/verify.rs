//! Ed25519 signature verification for license certificates.
//!
//! Iterates over [`super::TRUSTED_PUBKEYS`] and accepts the cert if any
//! provisioned slot validates the signature. Placeholder (all-zero) slots
//! are skipped — they never match real signatures.
//!
//! Uses the already-present `ed25519-dalek` dependency — no new crates
//! pulled in for the licensing layer.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::TRUSTED_PUBKEYS;
use super::cert::SignedLicense;

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("trusted public key has not been provisioned in this build")]
    NotProvisioned,
    #[error("public key is malformed")]
    BadPubkey,
    #[error("signature rejected by Ed25519 verifier")]
    BadSignature,
}

/// Verify a signed license against the compiled-in trusted key set.
///
/// Succeeds if the signature is a valid Ed25519 signature over
/// `signed.cert_bytes` by **any** non-placeholder pubkey in
/// [`TRUSTED_PUBKEYS`]. Does not check expiry, skill coverage, or
/// site fingerprint — that is the gate's responsibility.
pub fn verify_license(signed: &SignedLicense) -> Result<(), VerifyError> {
    if !super::is_provisioned() {
        return Err(VerifyError::NotProvisioned);
    }
    verify_against(signed, TRUSTED_PUBKEYS)
}

/// Pure verification helper — exposed at crate level so unit tests can
/// inject ephemeral pubkey sets without mutating the global constant.
pub(crate) fn verify_against(
    signed: &SignedLicense,
    pubkeys: &[[u8; 32]],
) -> Result<(), VerifyError> {
    let sig = Signature::from_bytes(&signed.signature);
    let mut tried_any = false;
    for pubkey in pubkeys {
        if pubkey == &[0u8; 32] {
            continue;
        }
        tried_any = true;
        let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
            // Malformed slot — log-worthy but don't bail; later slots may
            // still validate the signature legitimately.
            continue;
        };
        if vk.verify(&signed.cert_bytes, &sig).is_ok() {
            return Ok(());
        }
    }
    if !tried_any {
        Err(VerifyError::NotProvisioned)
    } else {
        Err(VerifyError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::licensing::cert::{LicenseCert, LicenseTier, Licensee, SignedLicense};
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_signed(sk: &SigningKey) -> SignedLicense {
        let cert = LicenseCert {
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
            expires_at: 1_000_000,
            grace_period_days: 90,
            revocation_check_url: String::new(),
        };
        let json = serde_json::to_vec(&cert).unwrap();
        let sig = sk.sign(&json).to_bytes();
        SignedLicense {
            cert,
            cert_bytes: json,
            signature: sig,
        }
    }

    #[test]
    fn signature_verifies_against_matching_key() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let signed = sample_signed(&sk);

        let trust_set = [pk, [0u8; 32]];
        assert!(verify_against(&signed, &trust_set).is_ok());
    }

    #[test]
    fn signature_verifies_when_any_slot_matches() {
        // PRIMARY is unrelated, EMERGENCY is the actual signer — verifier
        // must still accept (the whole point of multi-pubkey).
        let other = SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes();
        let real = SigningKey::from_bytes(&[2u8; 32]);
        let real_pk = real.verifying_key().to_bytes();

        let trust_set = [other, real_pk];
        let signed = sample_signed(&real);
        assert!(verify_against(&signed, &trust_set).is_ok());
    }

    #[test]
    fn signature_rejected_when_no_slot_matches() {
        let issuer = SigningKey::from_bytes(&[3u8; 32]);
        let signed = sample_signed(&issuer);

        let unrelated_a = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        let unrelated_b = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();

        let trust_set = [unrelated_a, unrelated_b];
        assert!(matches!(
            verify_against(&signed, &trust_set),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn placeholder_only_returns_not_provisioned() {
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let signed = sample_signed(&sk);
        let trust_set = [[0u8; 32], [0u8; 32]];
        assert!(matches!(
            verify_against(&signed, &trust_set),
            Err(VerifyError::NotProvisioned)
        ));
    }

    #[test]
    fn tampered_cert_bytes_are_rejected() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let mut signed = sample_signed(&sk);
        signed.cert_bytes[0] ^= 0xFF;

        assert!(matches!(
            verify_against(&signed, &[pk, [0u8; 32]]),
            Err(VerifyError::BadSignature)
        ));
    }

    #[test]
    fn verify_license_rejects_signature_from_unrelated_key() {
        // Once `TRUSTED_PUBKEYS` is provisioned, a cert signed by an
        // unrelated key must be rejected with `BadSignature` (not
        // `NotProvisioned`). This exercises the `verify_license` glue
        // against the real compiled-in trust set.
        let sk = SigningKey::from_bytes(&[6u8; 32]);
        let signed = sample_signed(&sk);
        assert!(matches!(
            verify_license(&signed),
            Err(VerifyError::BadSignature)
        ));
    }
}
