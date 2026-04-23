//! Connectors — integrate with existing client infrastructure.
//!
//! Each connector speaks to a specific tool the client already has
//! (Active Directory, pfSense, Proxmox, etc.) and feeds discovered
//! assets/users into the ThreatClaw graph via the Asset Resolution Pipeline.

use crate::error::DatabaseError;

/// Log-and-swallow helper for connector DB writes.
///
/// Replaces the widespread `let _ = store.insert_*(...).await;` pattern
/// that silently dropped every database error — we only discovered in
/// v1.0.10 that insert_log and insert_sigma_alert had been failing for
/// weeks on OpenCanary payloads, invisible because callers discarded
/// the Result.
///
/// Usage:
/// ```ignore
/// log_db_write("skill-wazuh:sigma", store.insert_sigma_alert(...)).await;
/// ```
///
/// The `ctx` argument is logged on failure so the operator can tell
/// which connector + which call type hit the error, without having to
/// map it back to a line number.
pub async fn log_db_write<T, F>(ctx: &str, fut: F) -> Option<T>
where
    F: std::future::Future<Output = Result<T, DatabaseError>>,
{
    match fut.await {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(ctx = ctx, "connector DB write failed: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DatabaseError;

    #[tokio::test]
    async fn log_db_write_returns_some_on_ok() {
        let r = log_db_write("test:ok", async { Ok::<i64, DatabaseError>(42) }).await;
        assert_eq!(r, Some(42));
    }

    // Regression: the whole point of this helper is that an Err variant
    // no longer disappears silently. We can't observe the tracing output
    // here without wiring a subscriber, but we can prove the helper does
    // return None (i.e. the caller's `let _` correctly drops to nothing)
    // — which the previous pattern also did. What changed is that the
    // error is now logged, which is covered by the live staging soak.
    #[tokio::test]
    async fn log_db_write_returns_none_on_err() {
        let r: Option<i64> = log_db_write("test:err", async {
            Err(DatabaseError::Query("simulated".into()))
        })
        .await;
        assert_eq!(r, None);
    }
}

pub mod active_directory;
pub mod authentik;
pub mod cloudflare;
pub mod crowdsec;
pub mod defectdojo;
pub mod dfir_iris;
pub mod dhcp_parser;
pub mod docker_executor;
pub mod elastic_siem;
pub mod fortinet;
pub mod freebox;
pub mod glpi;
pub mod graylog;
pub mod keycloak;
pub mod mikrotik;
pub mod nmap_discovery;
pub mod olvid;
pub mod osquery;
pub mod pfsense;
pub mod pihole;
pub mod proxmox;
pub mod proxmox_backup;
pub mod remediation;
pub mod shuffle;
pub mod suricata;
pub mod sync_scheduler;
pub mod thehive;
pub mod unifi;
pub mod uptimerobot;
pub mod veeam;
pub mod velociraptor;
pub mod wazuh;
pub mod webhook_ingest;
pub mod zeek;
