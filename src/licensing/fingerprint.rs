//! Site fingerprint — a stable, opaque identifier for this install.
//!
//! Used as the `site_fingerprint` field of a [`super::cert::LicenseCert`]
//! so that a license issued for install A cannot be transparently used on
//! install B. The fingerprint is sha256 of the install id (a random UUID
//! v4 minted at first activation) — it intentionally does not depend on
//! hardware, so the same TC binary running in a different VM derived from
//! the same disk image gets distinct fingerprints once each VM has booted
//! and generated its own install id.
//!
//! ## Design notes
//!
//! - **Privacy**: nothing in the fingerprint identifies the user, the
//!   employer, or the hardware. It is a one-way hash of a random UUID.
//! - **Stability**: as long as `~/.threatclaw/licensing/install_id` is
//!   not deleted, the fingerprint never changes. Backups that preserve
//!   the dotfile preserve the activation.
//! - **Re-installation**: a clean install starts with no `install_id`
//!   and generates one — this is the trigger for re-activation against
//!   the license server.

use sha2::{Digest, Sha256};

use super::storage::load_or_create_install_id;

/// Compute the site fingerprint for this install. Lazily writes the
/// install id on first call.
pub fn site_fingerprint() -> std::io::Result<String> {
    let install_id = load_or_create_install_id()?;
    Ok(hash_install_id(&install_id))
}

/// Pure helper for testing. Returns a 64-char hex string.
pub fn hash_install_id(install_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(install_id.as_bytes());
    let digest = h.finalize();
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let fp = hash_install_id("11111111-2222-3333-4444-555555555555");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_install_ids_yield_different_fingerprints() {
        let a = hash_install_id("a");
        let b = hash_install_id("b");
        assert_ne!(a, b);
    }

    #[test]
    fn same_install_id_yields_same_fingerprint() {
        let id = "deadbeef-cafe-1234-5678-abcdefabcdef";
        assert_eq!(hash_install_id(id), hash_install_id(id));
    }
}
