//! Ed25519 signature verification for license certificates.
//!
//! Uses the already-present `ed25519-dalek` dependency — no new crates
//! pulled in for the licensing layer.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::TRUSTED_PUBKEY;
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

/// Verify a signed license against the compiled-in trusted public key.
///
/// Succeeds only if the signature is a valid Ed25519 signature by
/// [`TRUSTED_PUBKEY`] over `signed.cert_bytes`. Does not check expiry or
/// skill coverage — that is the gate's responsibility.
pub fn verify_license(signed: &SignedLicense) -> Result<(), VerifyError> {
    if !super::is_provisioned() {
        return Err(VerifyError::NotProvisioned);
    }

    let vk = VerifyingKey::from_bytes(&TRUSTED_PUBKEY).map_err(|_| VerifyError::BadPubkey)?;
    let sig = Signature::from_bytes(&signed.signature);

    vk.verify(&signed.cert_bytes, &sig)
        .map_err(|_| VerifyError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::licensing::cert::{LicenseCert, LicenseTier, Licensee, SignedLicense};
    use ed25519_dalek::{Signer, SigningKey};

    /// End-to-end signature round-trip using an ephemeral keypair. Does
    /// not exercise the compile-time trusted key (which is all-zeros in
    /// development builds) — that code path is covered by the
    /// `NotProvisioned` test below.
    ///
    /// Uses a deterministic 32-byte seed to avoid needing the
    /// `rand_core` feature on `ed25519-dalek` just for one test.
    #[test]
    fn signature_roundtrip_with_ephemeral_key() {
        let seed: [u8; 32] = [
            0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1A,
        ];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();

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

        let signed = SignedLicense {
            cert,
            cert_bytes: json.clone(),
            signature: sig,
        };

        // Verify with the matching key succeeds.
        let signature = Signature::from_bytes(&signed.signature);
        assert!(vk.verify(&signed.cert_bytes, &signature).is_ok());

        // Tamper with the cert bytes -> verification fails.
        let mut tampered = signed.cert_bytes.clone();
        tampered[0] ^= 0xFF;
        assert!(vk.verify(&tampered, &signature).is_err());
    }

    #[test]
    fn verify_refuses_dummy_pubkey() {
        // With the placeholder all-zeros key, `is_provisioned()` is false
        // and `verify_license` must bail out rather than silently accept
        // or reject random signatures.
        assert!(!super::super::is_provisioned());

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
        let signed = SignedLicense {
            cert_bytes: serde_json::to_vec(&cert).unwrap(),
            cert,
            signature: [0u8; 64],
        };

        assert!(matches!(
            verify_license(&signed),
            Err(VerifyError::NotProvisioned)
        ));
    }
}
