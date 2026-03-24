//! ThreatClaw License System — asset-based, offline verification.
//!
//! Serial format: TC-{TIER}-{16 hex chars}
//! Payload: "tier:max_assets:expires:client_name"
//! Signed with HMAC-SHA256, verified locally (no network call).
//!
//! Community = no serial needed, 150 assets max.
//! Pro/Enterprise/MSSP = serial required.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};

/// HMAC key for serial verification.
///
/// SECURITY MODEL:
/// - This key is in the open-source code (visible to everyone)
/// - It CAN technically be used to generate serials
/// - Protection against abuse is LEGAL (AGPL v3), not technical
/// - Someone who forks and removes the limit must publish under AGPL
/// - The serial system is for honest users, not a DRM
/// - For production: replace with Ed25519 asymmetric signatures
///   (private key on server, public key in binary)
const VERIFY_KEY: &[u8] = b"tc-license-verify-2026-v1-threatclaw";

/// Default max assets for Community tier.
const COMMUNITY_MAX_ASSETS: usize = 150;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    Community,
    Pro,
    Enterprise,
    Mssp,
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Community => write!(f, "Community"),
            Self::Pro => write!(f, "Pro"),
            Self::Enterprise => write!(f, "Enterprise"),
            Self::Mssp => write!(f, "MSSP"),
        }
    }
}

/// Parsed and verified license.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseConfig {
    pub tier: LicenseTier,
    pub max_assets: usize,
    pub client_name: String,
    pub expires: String,
    pub serial: String,
    pub valid: bool,
    pub days_remaining: Option<i64>,
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            tier: LicenseTier::Community,
            max_assets: COMMUNITY_MAX_ASSETS,
            client_name: String::new(),
            expires: String::new(),
            serial: String::new(),
            valid: true,
            days_remaining: None,
        }
    }
}

impl LicenseConfig {
    /// Community tier (no serial).
    pub fn community() -> Self {
        Self::default()
    }

    /// Check if the asset count exceeds the license limit.
    pub fn is_over_limit(&self, asset_count: usize) -> bool {
        asset_count > self.max_assets
    }

    /// Usage percentage (0-100+).
    pub fn usage_percent(&self, asset_count: usize) -> u8 {
        if self.max_assets == 0 { return 100; }
        ((asset_count as f64 / self.max_assets as f64) * 100.0).min(255.0) as u8
    }

    /// Human-readable status message.
    pub fn status_message(&self, asset_count: usize) -> String {
        let pct = self.usage_percent(asset_count);
        if pct >= 100 {
            format!("Limite atteinte ({}/{}) — ThreatClaw Pro des 49EUR/mois", asset_count, self.max_assets)
        } else if pct >= 80 {
            format!("{}/{} assets ({}%) — vous approchez de la limite", asset_count, self.max_assets, pct)
        } else {
            format!("{}/{} assets", asset_count, self.max_assets)
        }
    }
}

/// Verify a serial and return the license config.
/// Returns Community if serial is empty, invalid, or expired.
pub fn verify_serial(serial: &str) -> LicenseConfig {
    let serial = serial.trim();
    if serial.is_empty() {
        return LicenseConfig::community();
    }

    // Parse: TC-{TIER}-{PAYLOAD_HEX}-{SIGNATURE_HEX}
    let parts: Vec<&str> = serial.split('-').collect();
    if parts.len() < 4 || parts[0] != "TC" {
        tracing::warn!("LICENSE: Invalid serial format");
        return LicenseConfig::community();
    }

    let tier_str = parts[1];
    let payload_hex = parts[2];
    let sig_hex = parts[3];

    // Decode payload
    let payload_bytes = match hex::decode(payload_hex) {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("LICENSE: Invalid payload hex");
            return LicenseConfig::community();
        }
    };

    let payload_str = match String::from_utf8(payload_bytes) {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!("LICENSE: Invalid payload UTF-8");
            return LicenseConfig::community();
        }
    };

    // Verify HMAC signature
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("LICENSE: Invalid signature hex");
            return LicenseConfig::community();
        }
    };

    let mut mac = match Hmac::<Sha256>::new_from_slice(VERIFY_KEY) {
        Ok(m) => m,
        Err(_) => return LicenseConfig::community(),
    };
    mac.update(payload_str.as_bytes());
    let expected_sig = mac.finalize().into_bytes();

    // Compare first 16 bytes (serial only stores truncated signature for readability)
    if sig_bytes.len() < 16 || expected_sig[..16] != sig_bytes[..16] {
        tracing::warn!("LICENSE: Invalid signature — serial rejected");
        return LicenseConfig::community();
    }

    // Parse payload: "tier:max_assets:expires:client_name"
    let fields: Vec<&str> = payload_str.splitn(4, ':').collect();
    if fields.len() < 4 {
        tracing::warn!("LICENSE: Invalid payload format");
        return LicenseConfig::community();
    }

    let tier = match fields[0] {
        "pro" => LicenseTier::Pro,
        "enterprise" => LicenseTier::Enterprise,
        "mssp" => LicenseTier::Mssp,
        _ => LicenseTier::Community,
    };

    let max_assets = fields[1].parse::<usize>().unwrap_or(COMMUNITY_MAX_ASSETS);
    let expires = fields[2].to_string();
    let client_name = fields[3].to_string();

    // Check expiration
    let days_remaining = chrono::NaiveDate::parse_from_str(&expires, "%Y-%m-%d")
        .ok()
        .map(|exp| {
            let today = chrono::Utc::now().date_naive();
            (exp - today).num_days()
        });

    let expired = days_remaining.map(|d| d < 0).unwrap_or(false);
    if expired {
        tracing::warn!("LICENSE: Serial expired on {} — reverting to Community", expires);
        return LicenseConfig {
            tier: LicenseTier::Community,
            max_assets: COMMUNITY_MAX_ASSETS,
            client_name,
            expires,
            serial: serial.to_string(),
            valid: false,
            days_remaining,
        };
    }

    tracing::info!("LICENSE: {} tier verified for '{}' — {} assets, expires {}",
        tier, client_name, max_assets, expires);

    LicenseConfig {
        tier,
        max_assets,
        client_name,
        expires,
        serial: serial.to_string(),
        valid: true,
        days_remaining,
    }
}

/// Generate a serial (SERVER-SIDE ONLY — this function uses the same key for demo).
/// In production, use a separate generation key on your server.
pub fn generate_serial(tier: &str, max_assets: usize, expires: &str, client_name: &str) -> String {
    let payload = format!("{}:{}:{}:{}", tier, max_assets, expires, client_name);

    let mut mac = Hmac::<Sha256>::new_from_slice(VERIFY_KEY).expect("HMAC key");
    mac.update(payload.as_bytes());
    let signature = mac.finalize().into_bytes();

    let payload_hex = hex::encode(payload.as_bytes());
    // Use first 16 bytes of signature (32 hex chars) for readability
    let sig_hex = hex::encode(&signature[..16]);

    let tier_code = match tier {
        "pro" => "PRO",
        "enterprise" => "ENT",
        "mssp" => "MSSP",
        _ => "COM",
    };

    format!("TC-{}-{}-{}", tier_code, payload_hex, sig_hex)
}

/// Get the current community asset limit (for display).
pub fn community_limit() -> usize {
    COMMUNITY_MAX_ASSETS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_default() {
        let lic = LicenseConfig::community();
        assert_eq!(lic.tier, LicenseTier::Community);
        assert_eq!(lic.max_assets, 150);
        assert!(lic.valid);
    }

    #[test]
    fn test_generate_and_verify() {
        let serial = generate_serial("pro", 500, "2027-12-31", "TestCorp SAS");
        assert!(serial.starts_with("TC-PRO-"));

        let lic = verify_serial(&serial);
        assert_eq!(lic.tier, LicenseTier::Pro);
        assert_eq!(lic.max_assets, 500);
        assert_eq!(lic.client_name, "TestCorp SAS");
        assert_eq!(lic.expires, "2027-12-31");
        assert!(lic.valid);
    }

    #[test]
    fn test_invalid_serial() {
        let lic = verify_serial("TC-PRO-invalid-data");
        assert_eq!(lic.tier, LicenseTier::Community);
    }

    #[test]
    fn test_empty_serial() {
        let lic = verify_serial("");
        assert_eq!(lic.tier, LicenseTier::Community);
        assert_eq!(lic.max_assets, 150);
    }

    #[test]
    fn test_expired_serial() {
        let serial = generate_serial("pro", 500, "2020-01-01", "Expired Corp");
        let lic = verify_serial(&serial);
        assert_eq!(lic.tier, LicenseTier::Community); // Expired = Community
        assert!(!lic.valid);
    }

    #[test]
    fn test_usage_percent() {
        let lic = LicenseConfig::community();
        assert_eq!(lic.usage_percent(75), 50);
        assert_eq!(lic.usage_percent(150), 100);
        assert_eq!(lic.usage_percent(0), 0);
    }

    #[test]
    fn test_over_limit() {
        let lic = LicenseConfig::community();
        assert!(!lic.is_over_limit(100));
        assert!(!lic.is_over_limit(150));
        assert!(lic.is_over_limit(151));
    }

    #[test]
    fn test_enterprise_serial() {
        let serial = generate_serial("enterprise", 999999, "2028-06-30", "BigCorp SA");
        let lic = verify_serial(&serial);
        assert_eq!(lic.tier, LicenseTier::Enterprise);
        assert_eq!(lic.max_assets, 999999);
    }

    #[test]
    fn test_mssp_serial() {
        let serial = generate_serial("mssp", 999999, "2027-03-24", "CyberConsulting.fr");
        let lic = verify_serial(&serial);
        assert_eq!(lic.tier, LicenseTier::Mssp);
        assert_eq!(lic.client_name, "CyberConsulting.fr");
    }

    #[test]
    fn test_tampered_serial() {
        let serial = generate_serial("pro", 500, "2027-12-31", "TestCorp");
        // Tamper with the serial
        let tampered = serial.replace("PRO", "ENT");
        let lic = verify_serial(&tampered);
        // Should fail or return community (tier code doesn't match payload)
        // The payload still says "pro" so it'll be Pro if sig validates
        // But changing PRO→ENT in prefix doesn't change the payload hex
        // So it'll still verify as Pro — the prefix is just cosmetic
        assert!(lic.valid); // Payload unchanged = still valid
        assert_eq!(lic.tier, LicenseTier::Pro); // Payload says pro
    }
}
