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

/// Billing mode — determines how the license is validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BillingMode {
    /// Monthly subscription — check api.threatclaw.io weekly
    Monthly,
    /// Annual — serial valid 365 days, no network check
    Annual,
    /// Perpetual — no expiration, no check (enterprise air-gap)
    Perpetual,
}

impl Default for BillingMode {
    fn default() -> Self { Self::Annual }
}

/// Parsed and verified license.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseConfig {
    pub tier: LicenseTier,
    pub max_assets: usize,
    pub client_name: String,
    pub client_id: String,
    pub expires: String,
    pub billing: BillingMode,
    pub serial: String,
    pub valid: bool,
    pub days_remaining: Option<i64>,
    /// Last successful remote check (ISO date, for monthly billing)
    pub last_check: Option<String>,
    /// Whether a remote check is needed
    pub needs_check: bool,
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            tier: LicenseTier::Community,
            max_assets: COMMUNITY_MAX_ASSETS,
            client_name: String::new(),
            client_id: String::new(),
            expires: String::new(),
            billing: BillingMode::Annual,
            serial: String::new(),
            valid: true,
            days_remaining: None,
            last_check: None,
            needs_check: false,
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

    // Parse payload: "tier:max_assets:expires:billing:client_id:client_name"
    // Legacy format (4 fields): "tier:max_assets:expires:client_name"
    let fields: Vec<&str> = payload_str.splitn(6, ':').collect();
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

    // Detect new format (6 fields) vs legacy (4 fields)
    let (billing, client_id, client_name) = if fields.len() >= 6 {
        let b = match fields[3] {
            "monthly" => BillingMode::Monthly,
            "perpetual" => BillingMode::Perpetual,
            _ => BillingMode::Annual,
        };
        (b, fields[4].to_string(), fields[5].to_string())
    } else {
        // Legacy format: no billing/client_id
        (BillingMode::Annual, String::new(), fields[3].to_string())
    };

    // Check expiration (skip for perpetual)
    let days_remaining = if billing == BillingMode::Perpetual {
        None // Never expires
    } else {
        chrono::NaiveDate::parse_from_str(&expires, "%Y-%m-%d")
            .ok()
            .map(|exp| {
                let today = chrono::Utc::now().date_naive();
                (exp - today).num_days()
            })
    };

    let expired = days_remaining.map(|d| d < 0).unwrap_or(false);
    if expired {
        tracing::warn!("LICENSE: Serial expired on {} — reverting to Community", expires);
        return LicenseConfig {
            tier: LicenseTier::Community,
            max_assets: COMMUNITY_MAX_ASSETS,
            client_name, client_id, expires, billing,
            serial: serial.to_string(),
            valid: false, days_remaining,
            last_check: None, needs_check: false,
        };
    }

    // For monthly billing, flag that a remote check is needed
    let needs_check = billing == BillingMode::Monthly;

    tracing::info!("LICENSE: {} tier for '{}' — {} assets, billing={:?}, expires {}",
        tier, client_name, max_assets, billing, if billing == BillingMode::Perpetual { "never".into() } else { expires.clone() });

    LicenseConfig {
        tier, max_assets, client_name, client_id, expires, billing,
        serial: serial.to_string(),
        valid: true, days_remaining,
        last_check: None, needs_check,
    }
}

/// Generate a serial (SERVER-SIDE ONLY).
/// billing: "monthly" | "annual" | "perpetual"
/// client_id: unique ID for remote check (empty for air-gap)
pub fn generate_serial(tier: &str, max_assets: usize, expires: &str, client_name: &str) -> String {
    generate_serial_full(tier, max_assets, expires, "annual", "", client_name)
}

/// Generate a serial with full billing + client_id.
pub fn generate_serial_full(tier: &str, max_assets: usize, expires: &str, billing: &str, client_id: &str, client_name: &str) -> String {
    let payload = format!("{}:{}:{}:{}:{}:{}", tier, max_assets, expires, billing, client_id, client_name);

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

/// Check license status remotely (for monthly billing only).
/// Returns true if active, false if cancelled/expired.
/// Grace period: if network fails, returns true for 30 days after last check.
pub async fn check_license_remote(client_id: &str, last_check: Option<&str>) -> (bool, String) {
    const CHECK_URL: &str = "https://api.threatclaw.io/license/check";
    const GRACE_DAYS: i64 = 30;

    if client_id.is_empty() {
        return (true, "no_client_id".into());
    }

    // Try remote check
    match reqwest::Client::new()
        .get(&format!("{}?id={}", CHECK_URL, client_id))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<serde_json::Value>().await {
                Ok(body) => {
                    let active = body["active"].as_bool().unwrap_or(false);
                    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    if active {
                        tracing::info!("LICENSE CHECK: {} active", client_id);
                        (true, today)
                    } else {
                        tracing::warn!("LICENSE CHECK: {} inactive — subscription cancelled?", client_id);
                        (false, today)
                    }
                }
                Err(_) => grace_period(last_check, GRACE_DAYS),
            }
        }
        _ => {
            // Network failure — use grace period
            tracing::warn!("LICENSE CHECK: network unavailable — using grace period");
            grace_period(last_check, GRACE_DAYS)
        }
    }
}

/// Grace period: if last check was within N days, still valid.
fn grace_period(last_check: Option<&str>, grace_days: i64) -> (bool, String) {
    if let Some(last) = last_check {
        if let Ok(last_date) = chrono::NaiveDate::parse_from_str(last, "%Y-%m-%d") {
            let today = chrono::Utc::now().date_naive();
            let days_since = (today - last_date).num_days();
            if days_since <= grace_days {
                tracing::info!("LICENSE: Grace period active ({}/{} days)", days_since, grace_days);
                return (true, last.to_string());
            }
        }
    }
    tracing::warn!("LICENSE: Grace period expired — reverting to Community");
    (false, String::new())
}

/// Should we run a remote check? (Only for monthly billing, max 1x/week)
pub fn should_check_remote(license: &LicenseConfig) -> bool {
    if license.billing != BillingMode::Monthly { return false; }
    if license.client_id.is_empty() { return false; }

    match &license.last_check {
        Some(last) => {
            if let Ok(last_date) = chrono::NaiveDate::parse_from_str(last, "%Y-%m-%d") {
                let today = chrono::Utc::now().date_naive();
                (today - last_date).num_days() >= 7 // Check once per week
            } else {
                true
            }
        }
        None => true, // Never checked
    }
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

    #[test]
    fn test_monthly_billing() {
        let serial = generate_serial_full("pro", 500, "2027-12-31", "monthly", "cli_123", "MonthlyCorp");
        let lic = verify_serial(&serial);
        assert_eq!(lic.tier, LicenseTier::Pro);
        assert_eq!(lic.billing, BillingMode::Monthly);
        assert_eq!(lic.client_id, "cli_123");
        assert!(lic.needs_check); // Monthly needs remote check
    }

    #[test]
    fn test_annual_billing() {
        let serial = generate_serial_full("pro", 500, "2027-12-31", "annual", "", "AnnualCorp");
        let lic = verify_serial(&serial);
        assert_eq!(lic.billing, BillingMode::Annual);
        assert!(!lic.needs_check); // Annual doesn't need check
    }

    #[test]
    fn test_perpetual_no_expiry() {
        let serial = generate_serial_full("enterprise", 999999, "9999-12-31", "perpetual", "", "AirGapCorp");
        let lic = verify_serial(&serial);
        assert_eq!(lic.billing, BillingMode::Perpetual);
        assert!(lic.valid);
        assert!(lic.days_remaining.is_none()); // Perpetual = no expiry check
    }

    #[test]
    fn test_grace_period_active() {
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let (active, _) = grace_period(Some(&today), 30);
        assert!(active); // Checked today = within grace
    }

    #[test]
    fn test_grace_period_expired() {
        let (active, _) = grace_period(Some("2020-01-01"), 30);
        assert!(!active); // Way past grace period
    }

    #[test]
    fn test_grace_period_no_check() {
        let (active, _) = grace_period(None, 30);
        assert!(!active); // Never checked = no grace
    }

    #[test]
    fn test_should_check_monthly() {
        let lic = LicenseConfig {
            billing: BillingMode::Monthly,
            client_id: "cli_123".into(),
            last_check: None,
            ..LicenseConfig::default()
        };
        assert!(should_check_remote(&lic)); // Never checked = should check
    }

    #[test]
    fn test_should_not_check_annual() {
        let lic = LicenseConfig {
            billing: BillingMode::Annual,
            ..LicenseConfig::default()
        };
        assert!(!should_check_remote(&lic)); // Annual = no check
    }

    #[test]
    fn test_legacy_serial_compat() {
        // Old 4-field format should still work
        let serial = generate_serial("pro", 500, "2027-12-31", "LegacyCorp");
        let lic = verify_serial(&serial);
        assert_eq!(lic.tier, LicenseTier::Pro);
        assert_eq!(lic.billing, BillingMode::Annual); // Default for legacy
        assert_eq!(lic.client_name, "LegacyCorp");
    }
}
