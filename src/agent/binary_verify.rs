//! Binary Integrity Verification.
//!
//! Verifies that the running ThreatClaw binary has not been tampered with.
//! Uses SHA-256 hash comparison against a known-good hash.

use std::path::Path;

/// Result of a binary verification check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyResult {
    pub verified: bool,
    pub binary_path: String,
    pub binary_hash: String,
    pub expected_hash: Option<String>,
    pub binary_size: u64,
    pub error: Option<String>,
}

/// Compute SHA-256 hash of the running binary.
pub fn hash_current_binary() -> Result<(String, String, u64), String> {
    // Get path to current executable
    let exe_path =
        std::env::current_exe().map_err(|e| format!("Cannot determine binary path: {e}"))?;

    let path_str = exe_path.to_string_lossy().to_string();

    let metadata = std::fs::metadata(&exe_path).map_err(|e| format!("Cannot stat binary: {e}"))?;

    let contents = std::fs::read(&exe_path).map_err(|e| format!("Cannot read binary: {e}"))?;

    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&contents);
    let hash_hex = hex::encode(hash);

    Ok((path_str, hash_hex, metadata.len()))
}

/// Verify binary integrity against a stored hash.
/// If no expected hash is stored, just computes and returns the current hash.
pub async fn verify_binary(store: &dyn crate::db::Database) -> VerifyResult {
    let (path, hash, size) = match hash_current_binary() {
        Ok(v) => v,
        Err(e) => {
            return VerifyResult {
                verified: false,
                binary_path: "unknown".into(),
                binary_hash: "".into(),
                expected_hash: None,
                binary_size: 0,
                error: Some(e),
            };
        }
    };

    // Check against stored hash
    let expected = store
        .get_setting("_system", "binary_hash")
        .await
        .ok()
        .flatten()
        .and_then(|v| v.as_str().map(String::from));

    let verified = match &expected {
        Some(exp) => exp == &hash,
        None => {
            // First run — store the hash
            let _ = store
                .set_setting("_system", "binary_hash", &serde_json::json!(hash))
                .await;
            true
        }
    };

    if !verified {
        tracing::error!(
            "BINARY INTEGRITY FAILED: expected={} actual={}",
            expected.as_deref().unwrap_or("?"),
            hash
        );
    }

    VerifyResult {
        verified,
        binary_path: path,
        binary_hash: hash,
        expected_hash: expected,
        binary_size: size,
        error: if verified {
            None
        } else {
            Some("Hash mismatch — binary may have been tampered".into())
        },
    }
}
