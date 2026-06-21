//! `FirewallSkill` implementation for Stormshield SNS.
//!
//! The serverd/NSRPC client and the HITL remediation actions live in
//! [`crate::connectors::stormshield_sns`]. This skill wires the SNS into the
//! enrichment side (`lookup_logs_for_ip`).
//!
//! NOTE: SNS gates log retrieval (`LOG DOWNLIMIT` / `LOG DOWNLOAD`) behind an
//! explicit personal-data-access acquisition (RGPD): the command returns
//! `ret=205 "Private data access right required"` until the ThreatClaw account
//! is granted unrestricted log access on the appliance (documented in the
//! connector setup guide). Until that access is configured — and the serverd
//! download sub-protocol grounded — log lookup returns empty rather than
//! fabricating entries.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::agent::skills::firewall::{FirewallError, FirewallLogEntry, FirewallSkill};
use crate::connectors::stormshield_sns::SnsConfig;

pub struct StormshieldFirewall {
    pub url: String,
    pub auth_user: String,
    pub auth_secret: String,
    pub no_tls_verify: bool,
}

impl StormshieldFirewall {
    pub fn sns_config(&self) -> SnsConfig {
        SnsConfig {
            url: self.url.clone(),
            user: self.auth_user.clone(),
            password: self.auth_secret.clone(),
            no_tls_verify: self.no_tls_verify,
        }
    }
}

#[async_trait]
impl FirewallSkill for StormshieldFirewall {
    fn skill_id(&self) -> &'static str {
        "skill-stormshield"
    }

    async fn lookup_logs_for_ip(
        &self,
        _ip: &str,
        _since: DateTime<Utc>,
        _until: DateTime<Utc>,
    ) -> Result<Vec<FirewallLogEntry>, FirewallError> {
        // Pending personal-data-access wiring (see module note). Build the
        // config so the connector path is exercised, then return no entries
        // rather than inventing them.
        let _cfg = self.sns_config();
        Ok(Vec::new())
    }
}
