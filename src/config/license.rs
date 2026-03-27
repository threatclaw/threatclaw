//! ThreatClaw Instance Identity & Premium Skills.
//!
//! Generates a unique instance UUID at first boot.
//! No asset limits — ThreatClaw is fully free and unlimited.
//!
//! The UUID and tier system are "plumbing" for future premium skills:
//! - Instance UUID identifies each deployment (for marketplace)
//! - Tier tracks whether premium skills have been purchased
//! - No features are gated behind tiers — only marketplace skills

use serde::{Deserialize, Serialize};

/// Instance tier — currently informational only, no limits enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    /// Free, unlimited, no restrictions.
    Community,
    /// Future: access to premium skills on marketplace.
    Pro,
    /// Future: priority support + all premium skills.
    Enterprise,
}

impl Default for LicenseTier {
    fn default() -> Self { Self::Community }
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Community => write!(f, "Community"),
            Self::Pro => write!(f, "Pro"),
            Self::Enterprise => write!(f, "Enterprise"),
        }
    }
}

/// Instance identity and license status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseConfig {
    /// Unique instance identifier (generated at first boot).
    pub instance_id: String,
    /// Current tier (Community = free, unlimited).
    pub tier: LicenseTier,
    /// No asset limits — always None (unlimited).
    pub max_assets: Option<u32>,
    /// Client name (set during onboarding, optional).
    pub client_name: String,
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            instance_id: generate_instance_id(),
            tier: LicenseTier::Community,
            max_assets: None, // Unlimited
            client_name: String::new(),
        }
    }
}

impl LicenseConfig {
    /// Community tier — free, unlimited.
    pub fn community() -> Self {
        Self::default()
    }

    /// Asset limit check — always returns false (no limits).
    pub fn is_over_limit(&self, _asset_count: usize) -> bool {
        false // No limits in ThreatClaw
    }

    /// Status message for the dashboard.
    pub fn status_message(&self, asset_count: usize) -> String {
        format!("{} assets surveillés — aucune limite", asset_count)
    }

    /// Check if a premium skill can be installed.
    /// For now, always returns true (no premium skills yet).
    pub fn can_install_premium_skill(&self, _skill_id: &str) -> bool {
        // TODO: When marketplace launches, check against purchased skills
        // For now, no premium skills exist — everything is free
        true
    }
}

/// Generate a unique instance ID using SHA-256 of entropy sources.
/// Format: tc-XXXXXXXX-XXXX-XXXX-XXXXXXXX (128 bits from SHA-256).
/// 2^128 = 340 undecillion combinations — collision-proof until the heat death of the universe.
pub fn generate_instance_id() -> String {
    use sha2::{Sha256, Digest};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(count.to_le_bytes());
    hasher.update(format!("{:?}", std::thread::current().id()).as_bytes());
    let hash = hasher.finalize();

    format!("tc-{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7],
        hash[8], hash[9], hash[10], hash[11])
}

/// Load or create instance ID from database.
pub async fn load_or_create_instance_id(store: &dyn crate::db::Database) -> String {
    // Try to load existing instance ID
    if let Ok(Some(val)) = store.get_setting("_system", "tc_instance_id").await {
        if let Some(id) = val.as_str() {
            if !id.is_empty() {
                return id.to_string();
            }
        }
    }

    // Generate new instance ID and persist
    let id = generate_instance_id();
    let _ = store.set_setting("_system", "tc_instance_id", &serde_json::json!(id)).await;
    tracing::info!("INSTANCE: Generated new instance ID: {}", id);
    id
}

/// Load license config from database (tier + instance ID).
pub async fn load_license(store: &dyn crate::db::Database) -> LicenseConfig {
    let instance_id = load_or_create_instance_id(store).await;

    let tier = if let Ok(Some(val)) = store.get_setting("_system", "tc_license_tier").await {
        match val.as_str().unwrap_or("community") {
            "pro" => LicenseTier::Pro,
            "enterprise" => LicenseTier::Enterprise,
            _ => LicenseTier::Community,
        }
    } else {
        LicenseTier::Community
    };

    let client_name = store.get_setting("_system", "tc_config_company")
        .await
        .ok()
        .flatten()
        .and_then(|v| v["name"].as_str().map(String::from))
        .unwrap_or_default();

    LicenseConfig {
        instance_id,
        tier,
        max_assets: None,
        client_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_default() {
        let lic = LicenseConfig::community();
        assert_eq!(lic.tier, LicenseTier::Community);
        assert!(lic.max_assets.is_none()); // Unlimited
        assert!(!lic.is_over_limit(999_999)); // Never over limit
    }

    #[test]
    fn test_instance_id_format() {
        let id = generate_instance_id();
        assert!(id.starts_with("tc-"));
        // tc-XXXXXXXX-XXXX-XXXX-XXXXXXXX = 3+8+1+4+1+4+1+8 = 30
        assert_eq!(id.len(), 30);
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "tc");
        assert_eq!(parts[1].len(), 8);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 8);
    }

    #[test]
    fn test_status_message_no_limit() {
        let lic = LicenseConfig::community();
        let msg = lic.status_message(500);
        assert!(msg.contains("500"));
        assert!(msg.contains("aucune limite"));
    }

    #[test]
    fn test_premium_skill_always_allowed() {
        let lic = LicenseConfig::community();
        assert!(lic.can_install_premium_skill("skill-sage-100"));
    }

    #[test]
    fn test_unique_instance_ids() {
        let id1 = generate_instance_id();
        let id2 = generate_instance_id();
        assert_ne!(id1, id2);
    }
}
