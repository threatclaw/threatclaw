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
use tokio::time::{Duration, interval};

/// Connector definitions: skill_id → sync function name
const CONNECTORS: &[(&str, &str)] = &[
    ("skill-wazuh-connector", "wazuh"),
    ("skill-pihole", "pihole"),
    ("skill-glpi", "glpi"),
    ("skill-crowdsec-connector", "crowdsec"),
    ("skill-unifi", "unifi"),
    ("skill-active-directory", "ad"),
    ("skill-elastic-siem", "elastic_siem"),
    ("skill-graylog", "graylog"),
    ("skill-thehive", "thehive"),
    ("skill-dfir-iris", "dfir_iris"),
    ("skill-shuffle", "shuffle"),
    ("skill-keycloak", "keycloak"),
    ("skill-authentik", "authentik"),
    ("skill-proxmox", "proxmox"),
    ("skill-proxmox-backup", "proxmox_backup"),
    ("skill-veeam", "veeam"),
    ("skill-mikrotik", "mikrotik"),
    ("skill-fortinet", "fortinet"),
    ("skill-velociraptor", "velociraptor"),
    ("skill-microsoft-graph", "microsoft_graph"),
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

                let config_map: HashMap<String, String> = configs
                    .iter()
                    .map(|c| (c.key.clone(), c.value.clone()))
                    .collect();

                let auto_sync = config_map
                    .get("auto_sync")
                    .map(|v| v == "true")
                    .unwrap_or(false);

                if !auto_sync {
                    continue;
                }

                let interval_min: u64 = config_map
                    .get("sync_interval")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(60);

                // Check if enough time has passed since last sync
                let now = std::time::Instant::now();
                if let Some(last) = last_sync.get(*skill_id) {
                    if now.duration_since(*last) < Duration::from_secs(interval_min * 60) {
                        continue;
                    }
                }

                tracing::info!(
                    "SYNC SCHEDULER: Running {} (every {}min)",
                    skill_id,
                    interval_min
                );
                last_sync.insert(skill_id.to_string(), now);

                // Run the appropriate sync
                let store_ref = store.clone();
                let skill = skill_id.to_string();
                let conn_type = connector_type.to_string();
                let cfg = config_map.clone();

                tokio::spawn(async move {
                    match run_connector_sync(store_ref.as_ref(), &skill, &conn_type, &cfg).await {
                        Ok(summary) => {
                            tracing::info!("SYNC SCHEDULER: {} complete — {}", skill, summary)
                        }
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
            if url.is_empty() {
                return Err("url not configured".into());
            }

            // Cursor + user-supplied noise filters live in the same skill_configs
            // table as the connection credentials. Parsing is best-effort so a
            // malformed config field degrades to "ignore it" rather than failing
            // the whole sync.
            let cursor_last_timestamp = config
                .get("cursor_last_timestamp")
                .cloned()
                .filter(|s| !s.is_empty());
            let skip_rule_ids: Vec<String> = config
                .get("skip_rule_ids")
                .map(|s| {
                    s.split(|c: char| c == ',' || c.is_whitespace())
                        .filter(|p| !p.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let skip_if_log_contains: std::collections::HashMap<String, String> = config
                .get("skip_if_log_contains")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();

            let wc = crate::connectors::wazuh::WazuhConfig {
                url,
                username,
                password,
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                max_alerts: config
                    .get("max_alerts")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(500),
                indexer_url,
                indexer_username,
                indexer_password,
                min_level: config
                    .get("min_level")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(7),
                skip_rule_ids,
                skip_if_log_contains,
                cursor_last_timestamp,
            };
            let r = crate::connectors::wazuh::sync_wazuh(store, &wc).await;

            // Persist the advanced cursor so the next cycle resumes from the
            // right spot. Ignore persistence errors — they would only cause a
            // duplicate re-ingest on the next cycle (dedup is handled by the
            // insert being idempotent in practice via the cursor windowing).
            if let Some(new_cursor) = &r.cursor {
                if let Err(e) = store
                    .set_skill_config(skill_id, "cursor_last_timestamp", new_cursor)
                    .await
                {
                    tracing::warn!("SYNC SCHEDULER: failed to persist wazuh cursor: {}", e);
                }
            }

            Ok(format!(
                "fetched={} imported={} findings={} noise={} insert_errors={} errors={}",
                r.alerts_fetched,
                r.alerts_imported,
                r.findings_created,
                r.dropped_noise,
                r.insert_errors,
                r.errors.len()
            ))
        }
        "velociraptor" => {
            let api_url = config.get("api_url").cloned().unwrap_or_default();
            let ca_pem = config.get("ca_pem").cloned().unwrap_or_default();
            let client_cert_pem = config.get("client_cert_pem").cloned().unwrap_or_default();
            let client_key_pem = config.get("client_key_pem").cloned().unwrap_or_default();
            let username = config.get("username").cloned().unwrap_or_default();
            if api_url.is_empty()
                || ca_pem.is_empty()
                || client_cert_pem.is_empty()
                || client_key_pem.is_empty()
                || username.is_empty()
            {
                return Err(
                    "velociraptor needs api_url + ca_pem + client_cert_pem + client_key_pem + username".into()
                );
            }
            let cursor_last_hunt_completion = config
                .get("cursor_last_hunt_completion")
                .cloned()
                .filter(|s| !s.is_empty());
            let max_findings_per_cycle = config
                .get("max_findings_per_cycle")
                .and_then(|v| v.parse().ok())
                .unwrap_or(500);

            let vc = crate::connectors::velociraptor::VelociraptorConfig {
                api_url,
                ca_pem,
                client_cert_pem,
                client_key_pem,
                username,
                cursor_last_hunt_completion,
                max_findings_per_cycle,
                admin_client_cert_pem: None,
                admin_client_key_pem: None,
            };
            let r = crate::connectors::velociraptor::sync_velociraptor(store, &vc).await;

            // Persist cursor like the Wazuh connector does — next cycle
            // resumes from the newest hunt we have already emitted.
            if let Some(new_cursor) = &r.cursor {
                if let Err(e) = store
                    .set_skill_config(skill_id, "cursor_last_hunt_completion", new_cursor)
                    .await
                {
                    tracing::warn!(
                        "SYNC SCHEDULER: failed to persist velociraptor cursor: {}",
                        e
                    );
                }
            }

            Ok(format!(
                "clients={} hunts={} findings={} insert_errors={} errors={}",
                r.clients_imported,
                r.hunts_fetched,
                r.findings_created,
                r.insert_errors,
                r.errors.len()
            ))
        }
        "pihole" => {
            let url = config.get("pihole_url").cloned().unwrap_or_default();
            let password = config.get("pihole_password").cloned().unwrap_or_default();
            if url.is_empty() {
                return Err("pihole_url not configured".into());
            }

            let pc = crate::connectors::pihole::PiholeConfig { url, password };
            let r = crate::connectors::pihole::sync_pihole(store, &pc).await;
            Ok(format!(
                "{} queries, {} findings",
                r.queries_analyzed, r.findings_created
            ))
        }
        "glpi" => {
            let url = config.get("glpi_url").cloned().unwrap_or_default();
            let app_token = config.get("glpi_app_token").cloned().unwrap_or_default();
            let user_token = config.get("glpi_user_token").cloned().unwrap_or_default();
            if url.is_empty() || app_token.is_empty() {
                return Err("glpi_url or glpi_app_token not configured".into());
            }

            let gc = crate::connectors::glpi::GlpiConfig {
                url,
                app_token,
                user_token,
                no_tls_verify: true,
            };
            let r = crate::connectors::glpi::sync_glpi(store, &gc).await;
            Ok(format!(
                "{} computers, {} network, {} assets",
                r.computers, r.network_equipment, r.assets_resolved
            ))
        }
        "crowdsec" => {
            let url = config.get("CROWDSEC_URL").cloned().unwrap_or_default();
            let key = config
                .get("CROWDSEC_BOUNCER_KEY")
                .cloned()
                .unwrap_or_default();
            if url.is_empty() || key.is_empty() {
                return Err("CROWDSEC_URL or key not configured".into());
            }

            let cc = crate::connectors::crowdsec::CrowdSecConfig {
                url,
                bouncer_key: key,
            };
            let r = crate::connectors::crowdsec::sync_crowdsec(store, &cc, false).await;
            Ok(format!(
                "{} decisions, {} alerts",
                r.new_decisions, r.alerts_created
            ))
        }
        "elastic_siem" => {
            let url = config.get("url").cloned().unwrap_or_default();
            if url.is_empty() {
                return Err("url not configured".into());
            }
            let c = crate::connectors::elastic_siem::ElasticSiemConfig {
                url,
                api_key_id: config.get("api_key_id").cloned(),
                api_key_secret: config.get("api_key_secret").cloned(),
                username: config.get("username").cloned(),
                password: config.get("password").cloned(),
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                max_alerts: config
                    .get("max_alerts")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100),
            };
            let r = crate::connectors::elastic_siem::sync_elastic_siem(store, &c).await;
            Ok(format!(
                "{} alerts, {} findings, {} errors",
                r.alerts_imported,
                r.findings_created,
                r.errors.len()
            ))
        }
        "graylog" => {
            let url = config.get("url").cloned().unwrap_or_default();
            if url.is_empty() {
                return Err("url not configured".into());
            }
            let c = crate::connectors::graylog::GraylogConfig {
                url,
                token: config.get("token").cloned(),
                username: config.get("username").cloned(),
                password: config.get("password").cloned(),
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                max_events: config
                    .get("max_events")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100),
            };
            let r = crate::connectors::graylog::sync_graylog(store, &c).await;
            Ok(format!(
                "{} events, {} findings, {} errors",
                r.events_imported,
                r.findings_created,
                r.errors.len()
            ))
        }
        "thehive" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let api_key = config.get("api_key").cloned().unwrap_or_default();
            if url.is_empty() || api_key.is_empty() {
                return Err("url or api_key not configured".into());
            }
            let c = crate::connectors::thehive::TheHiveConfig {
                url,
                api_key,
                org: config.get("org").cloned(),
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                max_alerts: config
                    .get("max_alerts")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100),
            };
            let r = crate::connectors::thehive::sync_thehive(store, &c).await;
            Ok(format!(
                "{} alerts, {} observables, {} findings",
                r.alerts_imported, r.observables_imported, r.findings_created
            ))
        }
        "dfir_iris" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let api_key = config.get("api_key").cloned().unwrap_or_default();
            if url.is_empty() || api_key.is_empty() {
                return Err("url or api_key not configured".into());
            }
            let c = crate::connectors::dfir_iris::DfirIrisConfig {
                url,
                api_key,
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                max_cases: config
                    .get("max_cases")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(50),
            };
            let r = crate::connectors::dfir_iris::sync_dfir_iris(store, &c).await;
            Ok(format!(
                "{} cases, {} IOCs, {} findings",
                r.cases_imported, r.iocs_imported, r.findings_created
            ))
        }
        "shuffle" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let api_key = config.get("api_key").cloned().unwrap_or_default();
            if url.is_empty() || api_key.is_empty() {
                return Err("url or api_key not configured".into());
            }
            let c = crate::connectors::shuffle::ShuffleConfig {
                url,
                api_key,
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
            };
            let r = crate::connectors::shuffle::sync_shuffle(store, &c).await;
            Ok(format!(
                "{} workflows, {} failures, {} findings",
                r.workflows_checked, r.failures_found, r.findings_created
            ))
        }
        "keycloak" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let client_id = config.get("client_id").cloned().unwrap_or_default();
            let client_secret = config.get("client_secret").cloned().unwrap_or_default();
            if url.is_empty() || client_id.is_empty() {
                return Err("url or client_id not configured".into());
            }
            let c = crate::connectors::keycloak::KeycloakConfig {
                url,
                client_id,
                client_secret,
                realm: config
                    .get("realm")
                    .cloned()
                    .unwrap_or_else(|| "master".into()),
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                max_events: config
                    .get("max_events")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(200),
            };
            let r = crate::connectors::keycloak::sync_keycloak(store, &c).await;
            Ok(format!(
                "{} login, {} admin, {} findings",
                r.login_events, r.admin_events, r.findings_created
            ))
        }
        "authentik" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let token = config.get("token").cloned().unwrap_or_default();
            if url.is_empty() || token.is_empty() {
                return Err("url or token not configured".into());
            }
            let c = crate::connectors::authentik::AuthentikConfig {
                url,
                token,
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                max_events: config
                    .get("max_events")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(200),
            };
            let r = crate::connectors::authentik::sync_authentik(store, &c).await;
            Ok(format!(
                "{} events, {} findings",
                r.events_imported, r.findings_created
            ))
        }
        "proxmox" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let token_id = config.get("token_id").cloned().unwrap_or_default();
            let token_secret = config.get("token_secret").cloned().unwrap_or_default();
            if url.is_empty() || token_id.is_empty() || token_secret.is_empty() {
                return Err("url, token_id or token_secret not configured".into());
            }
            let c = crate::connectors::proxmox::ProxmoxConfig {
                url,
                token_id,
                token_secret,
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                cursor_last_log_time: config.get("cursor_last_log_time").cloned(),
            };
            let r = crate::connectors::proxmox::sync_proxmox(store, &c).await;
            // Persist cursor so the next cycle picks up only new audit log events.
            if let Some(ref ts) = r.cursor_last_log_time {
                if let Err(e) = store
                    .set_skill_config("skill-proxmox", "cursor_last_log_time", ts)
                    .await
                {
                    tracing::warn!("SYNC SCHEDULER: failed to persist proxmox cursor: {}", e);
                }
            }
            Ok(format!(
                "{} VMs, {} containers, {} nodes, {} audit events, {} findings",
                r.vms, r.containers, r.nodes, r.audit_events_ingested, r.findings_created
            ))
        }
        "proxmox_backup" => {
            let url = config.get("url").cloned().unwrap_or_default();
            if url.is_empty() {
                return Err("url not configured".into());
            }
            let c = crate::connectors::proxmox_backup::ProxmoxBackupConfig {
                url,
                username: config.get("username").cloned(),
                password: config.get("password").cloned(),
                token_name: config.get("token_name").cloned(),
                token_value: config.get("token_value").cloned(),
                datastore: config.get("datastore").cloned(),
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
            };
            let r = crate::connectors::proxmox_backup::sync_proxmox_backup(store, &c).await;
            Ok(format!(
                "{} tasks, {} findings",
                r.tasks_checked, r.findings_created
            ))
        }
        "veeam" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let username = config.get("username").cloned().unwrap_or_default();
            let password = config.get("password").cloned().unwrap_or_default();
            if url.is_empty() || username.is_empty() {
                return Err("url or username not configured".into());
            }
            let c = crate::connectors::veeam::VeeamConfig {
                url,
                username,
                password,
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                max_sessions: config
                    .get("max_sessions")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(100),
            };
            let r = crate::connectors::veeam::sync_veeam(store, &c).await;
            Ok(format!(
                "{} sessions, {} findings",
                r.sessions_checked, r.findings_created
            ))
        }
        "fortinet" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let api_key = config.get("api_key").cloned().unwrap_or_default();
            if url.is_empty() || api_key.is_empty() {
                return Err("url or api_key not configured".into());
            }
            let c = crate::connectors::fortinet::FortinetConfig {
                url,
                api_key,
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
                cursor_user_event: config.get("cursor_user_event").cloned(),
                cursor_system_event: config.get("cursor_system_event").cloned(),
                cursor_forward_traffic: config.get("cursor_forward_traffic").cloned(),
            };
            let r = crate::connectors::fortinet::sync_fortinet(store, &c).await;
            for (key, val) in [
                ("cursor_user_event", &r.cursor_user_event),
                ("cursor_system_event", &r.cursor_system_event),
                ("cursor_forward_traffic", &r.cursor_forward_traffic),
            ] {
                if let Some(v) = val {
                    if let Err(e) = store.set_skill_config("skill-fortinet", key, v).await {
                        tracing::warn!("SYNC SCHEDULER: failed to persist fortinet {key}: {e}");
                    }
                }
            }
            Ok(format!(
                "{} ARP, {} assets, {} ifaces, {} addr, {} pols, sslvpn={}, ipsec={}, events_u={} events_s={} fw_blocks={}",
                r.arp_entries,
                r.assets_resolved,
                r.interfaces,
                r.firewall_addresses,
                r.firewall_policies,
                r.ssl_vpn_sessions,
                r.ipsec_tunnels,
                r.user_events_ingested,
                r.system_events_ingested,
                r.forward_blocks_ingested
            ))
        }
        "mikrotik" => {
            let url = config.get("url").cloned().unwrap_or_default();
            let username = config.get("username").cloned().unwrap_or_default();
            let password = config.get("password").cloned().unwrap_or_default();
            if url.is_empty() || username.is_empty() {
                return Err("url or username not configured".into());
            }
            let c = crate::connectors::mikrotik::MikroTikConfig {
                url,
                username,
                password,
                no_tls_verify: config
                    .get("no_tls_verify")
                    .map(|v| v == "true")
                    .unwrap_or(true),
            };
            let r = crate::connectors::mikrotik::sync_mikrotik(store, &c).await;
            Ok(format!(
                "{} logs, {} leases, {} findings",
                r.log_entries, r.dhcp_leases, r.findings_created
            ))
        }
        "microsoft_graph" => {
            let tenant_id = config.get("tenant_id").cloned().unwrap_or_default();
            let client_id = config.get("client_id").cloned().unwrap_or_default();
            if tenant_id.is_empty() || client_id.is_empty() {
                return Err("tenant_id or client_id not configured".into());
            }
            let auth_method = crate::connectors::microsoft_graph::AuthMethod::parse(
                config
                    .get("auth_method")
                    .map(|s| s.as_str())
                    .unwrap_or("certificate"),
            );
            let mc = crate::connectors::microsoft_graph::MicrosoftGraphConfig {
                tenant_id,
                client_id,
                auth_method,
                client_secret: config
                    .get("client_secret")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                client_cert_pem: config
                    .get("client_cert_pem")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                client_key_pem: config
                    .get("client_key_pem")
                    .cloned()
                    .filter(|s| !s.is_empty()),
            };
            if let Err(e) = mc.validate() {
                return Err(e);
            }

            let cursors = crate::connectors::microsoft_graph::SyncCursors {
                signins_created_datetime: config
                    .get("cursor_signins_created_datetime")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                audit_activity_datetime: config
                    .get("cursor_audit_activity_datetime")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                users_delta_link: config
                    .get("cursor_users_delta_link")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                devices_delta_link: config
                    .get("cursor_devices_delta_link")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                managed_devices_last_sync: config
                    .get("cursor_managed_devices_last_sync")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                alerts_v2_created_datetime: config
                    .get("cursor_alerts_v2_created_datetime")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                risky_users_last_updated: config
                    .get("cursor_risky_users_last_updated")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                risk_detections_detected_datetime: config
                    .get("cursor_risk_detections_detected_datetime")
                    .cloned()
                    .filter(|s| !s.is_empty()),
            };

            let r =
                crate::connectors::microsoft_graph::sync_microsoft_graph(store, &mc, cursors).await;

            // Persist cursors — same pattern as wazuh/velociraptor. We
            // write unconditionally because the sync fills new_cursors
            // from the input when a puller failed, so a successful cursor
            // is never overwritten by a later failure.
            let to_persist: [(&str, Option<&String>); 8] = [
                (
                    "cursor_signins_created_datetime",
                    r.new_cursors.signins_created_datetime.as_ref(),
                ),
                (
                    "cursor_audit_activity_datetime",
                    r.new_cursors.audit_activity_datetime.as_ref(),
                ),
                (
                    "cursor_users_delta_link",
                    r.new_cursors.users_delta_link.as_ref(),
                ),
                (
                    "cursor_devices_delta_link",
                    r.new_cursors.devices_delta_link.as_ref(),
                ),
                (
                    "cursor_managed_devices_last_sync",
                    r.new_cursors.managed_devices_last_sync.as_ref(),
                ),
                (
                    "cursor_alerts_v2_created_datetime",
                    r.new_cursors.alerts_v2_created_datetime.as_ref(),
                ),
                (
                    "cursor_risky_users_last_updated",
                    r.new_cursors.risky_users_last_updated.as_ref(),
                ),
                (
                    "cursor_risk_detections_detected_datetime",
                    r.new_cursors.risk_detections_detected_datetime.as_ref(),
                ),
            ];
            for (key, val) in to_persist {
                if let Some(v) = val {
                    if let Err(e) = store.set_skill_config(skill_id, key, v).await {
                        tracing::warn!("SYNC SCHEDULER: failed to persist m365 {}: {}", key, e);
                    }
                }
            }

            Ok(format!(
                "tenant='{}' audits={} signIns={} users={} devices={} managed={} ca={} \
                 alerts_v2={} risky_users={} risk_det={} alerts_out={} insert_errors={} errors={}",
                r.tenant_display_name.as_deref().unwrap_or("?"),
                r.audits_fetched,
                r.signins_fetched,
                r.users_upserted,
                r.devices_upserted,
                r.managed_devices_upserted,
                r.ca_policies_checked,
                r.alerts_v2_fetched,
                r.risky_users_fetched,
                r.risk_detections_fetched,
                r.alerts_inserted,
                r.insert_errors,
                r.errors.len()
            ))
        }
        "unifi" | "ad" => Err(format!("{} auto-sync not yet implemented", connector_type)),
        _ => Err(format!("Unknown connector: {}", connector_type)),
    }
}
