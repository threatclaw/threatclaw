//! Connector Sync Scheduler — automatically syncs connectors at configured intervals.
//!
//! Each connector skill can have:
//!   - `auto_sync` = "true" (enable periodic sync)
//!   - `sync_interval` = "60" (minutes between syncs, default 60)
//!
//! The scheduler runs every 60s, checks which connectors are due, and runs them.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Connector definitions: skill_id → sync function name
const CONNECTORS: &[(&str, &str)] = &[
    ("skill-wazuh-connector", "wazuh"),
    ("skill-pihole", "pihole"),
    ("skill-glpi", "glpi"),
    ("skill-crowdsec-connector", "crowdsec"),
    ("skill-unifi", "unifi"),
    ("skill-active-directory", "ad"),
];

/// Spawn the connector sync scheduler.
pub fn spawn_sync_scheduler(store: Arc<dyn Database>) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(60));
        let mut last_sync: HashMap<String, std::time::Instant> = HashMap::new();

        tracing::info!("SYNC SCHEDULER: Started — checking connectors every 60s");

        loop {
            ticker.tick().await;

            for (skill_id, connector_type) in CONNECTORS {
                // Check if auto_sync is enabled for this skill
                let configs = match store.get_skill_config(skill_id).await {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                let config_map: HashMap<String, String> = configs.iter()
                    .map(|c| (c.key.clone(), c.value.clone()))
                    .collect();

                let auto_sync = config_map.get("auto_sync")
                    .map(|v| v == "true")
                    .unwrap_or(false);

                if !auto_sync { continue; }

                let interval_min: u64 = config_map.get("sync_interval")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60);

                // Check if enough time has passed since last sync
                let now = std::time::Instant::now();
                if let Some(last) = last_sync.get(*skill_id) {
                    if now.duration_since(*last) < Duration::from_secs(interval_min * 60) {
                        continue;
                    }
                }

                tracing::info!("SYNC SCHEDULER: Running {} (every {}min)", skill_id, interval_min);
                last_sync.insert(skill_id.to_string(), now);

                // Run the appropriate sync
                let store_ref = store.clone();
                let skill = skill_id.to_string();
                let conn_type = connector_type.to_string();
                let cfg = config_map.clone();

                tokio::spawn(async move {
                    match run_connector_sync(store_ref.as_ref(), &skill, &conn_type, &cfg).await {
                        Ok(summary) => tracing::info!("SYNC SCHEDULER: {} complete — {}", skill, summary),
                        Err(e) => tracing::warn!("SYNC SCHEDULER: {} failed — {}", skill, e),
                    }
                });
            }
        }
    });
}

/// Run a specific connector sync based on its type.
async fn run_connector_sync(
    store: &dyn Database,
    skill_id: &str,
    connector_type: &str,
    config: &HashMap<String, String>,
) -> Result<String, String> {
    match connector_type {
        "wazuh" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let username = config.get("username").cloned().unwrap_or("wazuh".into());
            let password = config.get("password").cloned().unwrap_or_default();
            let indexer_url = config.get("indexer_url").cloned().filter(|s| !s.is_empty());
            let indexer_username = config.get("indexer_username").cloned();
            let indexer_password = config.get("indexer_password").cloned();
            if url.is_empty() { return Err("url not configured".into()); }

            let wc = crate::connectors::wazuh::WazuhConfig {
                url, username, password,
                no_tls_verify: config.get("no_tls_verify").map(|v| v == "true").unwrap_or(true),
                max_alerts: config.get("max_alerts").and_then(|v| v.parse().ok()).unwrap_or(100),
                indexer_url, indexer_username, indexer_password,
            };
            let r = crate::connectors::wazuh::sync_wazuh(store, &wc).await;
            Ok(format!("{} alerts, {} findings, {} errors", r.alerts_imported, r.findings_created, r.errors.len()))
        }
        "pihole" => {
            let url = config.get("pihole_url").cloned().unwrap_or_default();
            let password = config.get("pihole_password").cloned().unwrap_or_default();
            if url.is_empty() { return Err("pihole_url not configured".into()); }

            let pc = crate::connectors::pihole::PiholeConfig { url, password };
            let r = crate::connectors::pihole::sync_pihole(store, &pc).await;
            Ok(format!("{} queries, {} findings", r.queries_analyzed, r.findings_created))
        }
        "glpi" => {
            let url = config.get("glpi_url").cloned().unwrap_or_default();
            let app_token = config.get("glpi_app_token").cloned().unwrap_or_default();
            let user_token = config.get("glpi_user_token").cloned().unwrap_or_default();
            if url.is_empty() || app_token.is_empty() { return Err("glpi_url or glpi_app_token not configured".into()); }

            let gc = crate::connectors::glpi::GlpiConfig {
                url, app_token, user_token, no_tls_verify: true,
            };
            let r = crate::connectors::glpi::sync_glpi(store, &gc).await;
            Ok(format!("{} computers, {} network, {} assets", r.computers, r.network_equipment, r.assets_resolved))
        }
        "crowdsec" => {
            let url = config.get("CROWDSEC_URL").cloned().unwrap_or_default();
            let key = config.get("CROWDSEC_BOUNCER_KEY").cloned().unwrap_or_default();
            if url.is_empty() || key.is_empty() { return Err("CROWDSEC_URL or key not configured".into()); }

            let cc = crate::connectors::crowdsec::CrowdSecConfig { url, bouncer_key: key };
            let r = crate::connectors::crowdsec::sync_crowdsec(store, &cc, false).await;
            Ok(format!("{} decisions, {} alerts", r.new_decisions, r.alerts_created))
        }
        "pihole" | "unifi" | "ad" => {
            // TODO: implement auto-sync for these
            Err(format!("{} auto-sync not yet implemented", connector_type))
        }
        _ => Err(format!("Unknown connector: {}", connector_type)),
    }
}
