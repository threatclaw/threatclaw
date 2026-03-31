//! Master Password — Argon2id key derivation for human-memorable passwords.
//!
//! Instead of a raw hex key in an env var, the RSSI can set a master password
//! in the wizard. The password is derived into a 256-bit key via Argon2id.
//!
//! Flow:
//! 1. First setup: RSSI enters password → derive key → encrypt canary → store salt+canary
//! 2. Restart: RSSI enters password → derive key → decrypt canary → verify → unlock vault
//! 3. Password change: re-derive → re-encrypt all secrets with new key

use argon2::{Argon2, Algorithm, Params, Version};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::secrets::types::SecretError;

/// Argon2id parameters (OWASP recommended: m=64MiB, t=3, p=1)
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;     // 3 iterations
const ARGON2_P_COST: u32 = 1;     // 1 thread
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// Canary value encrypted with the derived key to verify correct password.
const CANARY_PLAINTEXT: &[u8] = b"threatclaw-vault-canary-v1";

/// Result of master password setup.
#[derive(Debug, Clone)]
pub struct MasterPasswordSetup {
    /// Argon2id salt (store in DB/config — NOT secret).
    pub salt: Vec<u8>,
    /// Encrypted canary (store in DB/config — used to verify password).
    pub encrypted_canary: Vec<u8>,
    /// Canary encryption salt (for HKDF derivation of canary key).
    pub canary_salt: Vec<u8>,
}

/// Derive a 256-bit master key from a password using Argon2id.
pub fn derive_master_key(
    password: &SecretString,
    salt: &[u8],
) -> Result<SecretString, SecretError> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_LEN))
            .map_err(|e| SecretError::InvalidMasterKey)?,
    );

    let mut key = vec![0u8; KEY_LEN];
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|_| SecretError::InvalidMasterKey)?;

    // Convert to hex string for compatibility with existing SecretsCrypto
    let hex_key = hex::encode(&key);

    // Zero the raw key bytes
    key.fill(0);

    Ok(SecretString::from(hex_key))
}

/// Generate a random salt for Argon2id.
pub fn generate_salt() -> Vec<u8> {
    use aes_gcm::aead::{AeadCore, OsRng};
    let mut salt = vec![0u8; SALT_LEN];
    rand::RngCore::fill_bytes(&mut OsRng, &mut salt);
    salt
}

/// Setup a new master password: derive key, encrypt canary, return setup data.
pub fn setup_master_password(
    password: &SecretString,
) -> Result<(SecretString, MasterPasswordSetup), SecretError> {
    let salt = generate_salt();
    let master_key = derive_master_key(password, &salt)?;

    // Encrypt canary with the derived key to verify on next unlock
    let crypto = crate::secrets::crypto::SecretsCrypto::new(master_key.clone())?;
    let (encrypted_canary, canary_salt) = crypto.encrypt(CANARY_PLAINTEXT)?;

    Ok((
        master_key,
        MasterPasswordSetup {
            salt,
            encrypted_canary,
            canary_salt,
        },
    ))
}

/// Verify a master password against stored setup data.
pub fn verify_master_password(
    password: &SecretString,
    setup: &MasterPasswordSetup,
) -> Result<SecretString, SecretError> {
    let master_key = derive_master_key(password, &setup.salt)?;

    // Try to decrypt the canary
    let crypto = crate::secrets::crypto::SecretsCrypto::new(master_key.clone())?;
    let decrypted = crypto.decrypt(&setup.encrypted_canary, &setup.canary_salt)?;

    // Compare with expected canary
    if decrypted.expose().as_bytes() != CANARY_PLAINTEXT {
        return Err(SecretError::DecryptionFailed(
            "Master password incorrect — canary mismatch".to_string(),
        ));
    }

    Ok(master_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let password = SecretString::from("test-password-123");
        let salt = vec![1u8; SALT_LEN];
        let key1 = derive_master_key(&password, &salt).unwrap();
        let key2 = derive_master_key(&password, &salt).unwrap();
        assert_eq!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_derive_key_different_salt() {
        let password = SecretString::from("test-password-123");
        let salt1 = vec![1u8; SALT_LEN];
        let salt2 = vec![2u8; SALT_LEN];
        let key1 = derive_master_key(&password, &salt1).unwrap();
        let key2 = derive_master_key(&password, &salt2).unwrap();
        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_derive_key_different_password() {
        let salt = vec![1u8; SALT_LEN];
        let key1 = derive_master_key(&SecretString::from("password-A"), &salt).unwrap();
        let key2 = derive_master_key(&SecretString::from("password-B"), &salt).unwrap();
        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_setup_and_verify() {
        let password = SecretString::from("my-secure-master-password");
        let (key, setup) = setup_master_password(&password).unwrap();
        assert_eq!(key.expose_secret().len(), 64); // 32 bytes hex

        let verified_key = verify_master_password(&password, &setup).unwrap();
        assert_eq!(key.expose_secret(), verified_key.expose_secret());
    }

    #[test]
    fn test_verify_wrong_password() {
        let password = SecretString::from("correct-password");
        let (_, setup) = setup_master_password(&password).unwrap();

        let result = verify_master_password(&SecretString::from("wrong-password"), &setup);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_salt_unique() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, s2);
        assert_eq!(s1.len(), SALT_LEN);
    }

    #[test]
    fn test_key_length() {
        let password = SecretString::from("test");
        let salt = generate_salt();
        let key = derive_master_key(&password, &salt).unwrap();
        // Hex-encoded 32 bytes = 64 chars
        assert_eq!(key.expose_secret().len(), 64);
    }
}
