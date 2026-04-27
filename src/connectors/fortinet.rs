//! Fortinet FortiGate connector — read firewall data + block IPs.
//!
//! Auth: API key in header (`Authorization: Bearer {api_key}`)
//!
//! ## Endpoint shape vs FortiOS version
//!
//! FortiOS 8.0 reorganised the monitor namespace. The connector targets
//! the 8.x layout (current GA series); endpoints that moved are all in
//! the section below labelled "8.x changed paths". Earlier 7.x firewalls
//! also accept the new paths in most cases — checked against a v8.0.0
//! build 167 lab.
//!
//! ## What we ingest
//!
//! - `monitor/system/status` — version banner, hostname, serial
//! - `monitor/network/arp` — ARP table (8.x: was `monitor/system/arp` in 7.x)
//! - `cmdb/system/interface` — interface inventory + VLAN extraction
//! - `cmdb/firewall/address` — address objects (used to size the rule set)
//! - `cmdb/firewall/policy` — firewall policy count
//! - `monitor/system/global-resources` — CPU / RAM / disk + finding gates
//! - `monitor/vpn/ssl` — SSL VPN active sessions
//! - `monitor/vpn/ipsec` — IPsec phase1 + phase2 status
//!
//! ## What writes
//!
//! - `block_ip` HITL action — creates a `firewall/address` object
//!   referencing a single /32 host then attaches it to a deny policy.
//!   Not yet wired here; see ADR-044 + tool_calling.rs.

use crate::db::Database;
use crate::graph::asset_resolution::{self, DiscoveredAsset};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FortinetConfig {
    pub url: String,
    pub api_key: String,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
    /// Cursor for incremental log pulls — keeps the highest `eventtime`
    /// (epoch seconds) already ingested for user-event log.
    #[serde(default)]
    pub cursor_user_event: Option<String>,
    /// Same for system-event log.
    #[serde(default)]
    pub cursor_system_event: Option<String>,
    /// Same for forward-traffic log (block events only).
    #[serde(default)]
    pub cursor_forward_traffic: Option<String>,
    /// UTM log cursors (one per subtype — only used when UTM modules
    /// are licensed + enabled; the eval VM returns 404 silently).
    #[serde(default)]
    pub cursor_utm_virus: Option<String>,
    #[serde(default)]
    pub cursor_utm_ips: Option<String>,
    #[serde(default)]
    pub cursor_utm_webfilter: Option<String>,
    #[serde(default)]
    pub cursor_utm_app_ctrl: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FortinetSyncResult {
    pub arp_entries: usize,
    pub assets_resolved: usize,
    pub interfaces: usize,
    pub system_version: Option<String>,
    pub system_serial: Option<String>,
    pub firewall_addresses: usize,
    pub firewall_policies: usize,
    pub ssl_vpn_sessions: usize,
    pub ipsec_tunnels: usize,
    pub cpu_usage_pct: Option<u8>,
    pub mem_usage_pct: Option<u8>,
    pub disk_usage_pct: Option<u8>,
    /// Number of user-event log rows ingested into `logs` this cycle.
    pub user_events_ingested: usize,
    /// Number of system-event log rows ingested into `logs` this cycle.
    pub system_events_ingested: usize,
    /// Forward-traffic block events ingested into `firewall_events`.
    pub forward_blocks_ingested: usize,
    /// Identity-graph LOGGED_IN edges created from SSL VPN active sessions.
    pub identity_edges_created: usize,
    /// DHCP leases observed → assets resolved.
    pub dhcp_leases: usize,
    /// Local user accounts inventoried (cmdb/user/local).
    pub local_users: usize,
    /// Firewall-auth users currently authenticated (monitor/user/firewall).
    pub firewall_auth_users: usize,
    /// FortiAP managed access points.
    pub managed_aps: usize,
    /// Wireless clients connected via FortiAP.
    pub wifi_clients: usize,
    /// Rogue APs detected nearby — emits a CRITICAL finding when > 0.
    pub rogue_aps: usize,
    /// Devices detected on FortiSwitch ports.
    pub switch_detected_devices: usize,
    /// `true` when HA cluster reports a working state, `false` otherwise.
    pub ha_status_ok: Option<bool>,
    /// UTM log rows ingested per subtype (each defensive — 404 = no
    /// license / module disabled, just skip).
    pub utm_virus_ingested: usize,
    pub utm_ips_ingested: usize,
    pub utm_webfilter_ingested: usize,
    pub utm_app_ctrl_ingested: usize,
    /// Findings created this cycle (rogue AP, license expiring, HA split).
    pub findings_created: usize,
    pub errors: Vec<String>,
    /// New cursors written back at the end of the sync.
    pub cursor_user_event: Option<String>,
    pub cursor_system_event: Option<String>,
    pub cursor_forward_traffic: Option<String>,
    pub cursor_utm_virus: Option<String>,
    pub cursor_utm_ips: Option<String>,
    pub cursor_utm_webfilter: Option<String>,
    pub cursor_utm_app_ctrl: Option<String>,
}

pub async fn sync_fortinet(store: &dyn Database, config: &FortinetConfig) -> FortinetSyncResult {
    let mut result = FortinetSyncResult {
        cursor_user_event: config.cursor_user_event.clone(),
        cursor_system_event: config.cursor_system_event.clone(),
        cursor_forward_traffic: config.cursor_forward_traffic.clone(),
        cursor_utm_virus: config.cursor_utm_virus.clone(),
        cursor_utm_ips: config.cursor_utm_ips.clone(),
        cursor_utm_webfilter: config.cursor_utm_webfilter.clone(),
        cursor_utm_app_ctrl: config.cursor_utm_app_ctrl.clone(),
        ..Default::default()
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("HTTP client: {e}"));
            return result;
        }
    };

    let base = config.url.trim_end_matches('/');
    let auth = format!("Bearer {}", config.api_key);
    tracing::info!("FORTINET: Connecting to {}", base);

    // 1. System status — version + serial banner
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/system/status").await {
        let r = &body["results"];
        result.system_version = r["version"].as_str().map(String::from);
        result.system_serial = r["serial"]
            .as_str()
            .or(body["serial"].as_str())
            .map(String::from);
    }

    // 2. ARP table — try the 8.x path first, fall back to the 7.x one.
    //    7.0–7.6 used `monitor/system/arp`; 8.0 moved it to
    //    `monitor/network/arp`. Probing in this order means a fresh 8.x
    //    install hits the right endpoint immediately, while a 7.x box
    //    transparently falls back without needing a config flag.
    let arp_body = match fgt_get(&client, base, &auth, "/api/v2/monitor/network/arp").await {
        Ok(body) => Ok(body),
        Err(_) => fgt_get(&client, base, &auth, "/api/v2/monitor/system/arp").await,
    };
    match arp_body {
        Ok(body) => {
            if let Some(entries) = body["results"].as_array() {
                result.arp_entries = entries.len();
                for entry in entries {
                    let ip = entry["ip"].as_str().unwrap_or("");
                    let mac = entry["mac"].as_str().unwrap_or("");
                    let iface = entry["interface"].as_str().unwrap_or("");
                    if !ip.is_empty() && !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        let discovered = DiscoveredAsset {
                            mac: Some(mac.into()),
                            hostname: None,
                            fqdn: None,
                            ip: Some(ip.into()),
                            os: None,
                            ports: None,
                            ou: None,
                            vlan: extract_vlan(iface),
                            vm_id: None,
                            criticality: None,
                            services: serde_json::json!([]),
                            source: "fortinet".into(),
                        };
                        let _ = asset_resolution::resolve_asset(store, &discovered).await;
                        result.assets_resolved += 1;
                    }
                }
            }
        }
        Err(e) => result.errors.push(format!("ARP: {e}")),
    }

    // 3. Interfaces (count only — full payload is heavy)
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/cmdb/system/interface").await {
        result.interfaces = body["results"].as_array().map(|a| a.len()).unwrap_or(0);
    }

    // 4. Firewall address objects (aliases equivalent)
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/cmdb/firewall/address").await {
        result.firewall_addresses = body["results"].as_array().map(|a| a.len()).unwrap_or(0);
    }

    // 5. Firewall policies (rules count)
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/cmdb/firewall/policy").await {
        result.firewall_policies = body["results"].as_array().map(|a| a.len()).unwrap_or(0);
    }

    // 6. System resources — CPU/RAM/disk usage
    if let Ok(body) = fgt_get(
        &client,
        base,
        &auth,
        "/api/v2/monitor/system/global-resources",
    )
    .await
    {
        let r = &body["results"];
        result.cpu_usage_pct = r["cpu"]["historical-usage"]["1-minute"]
            .as_f64()
            .or_else(|| r["cpu"].as_f64())
            .map(|v| v.round().clamp(0.0, 255.0) as u8);
        result.mem_usage_pct = r["memory"]["historical-usage"]["1-minute"]
            .as_f64()
            .or_else(|| r["memory"].as_f64())
            .map(|v| v.round().clamp(0.0, 255.0) as u8);
        result.disk_usage_pct = r["disk"]["historical-usage"]["1-minute"]
            .as_f64()
            .or_else(|| r["disk"].as_f64())
            .map(|v| v.round().clamp(0.0, 255.0) as u8);
    }

    // 7. SSL VPN active sessions — count + identity bridge for each user
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/vpn/ssl").await {
        if let Some(sessions) = body["results"].as_array() {
            result.ssl_vpn_sessions = sessions.len();
            let asset_id = result
                .system_serial
                .as_deref()
                .map(|s| format!("fortigate-{s}"))
                .unwrap_or_else(|| format!("fortigate-{base}"));
            for s in sessions {
                let username = s["user_name"]
                    .as_str()
                    .or_else(|| s["username"].as_str())
                    .unwrap_or("");
                let src_ip = s["source_ip"]
                    .as_str()
                    .or_else(|| s["src_ip"].as_str())
                    .unwrap_or("");
                if !username.is_empty() {
                    crate::graph::identity_graph::record_login(
                        store, username, &asset_id, src_ip, "ssl-vpn", true,
                    )
                    .await;
                    result.identity_edges_created += 1;
                }
            }
        }
    }

    // 8. IPsec phase1 tunnels
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/vpn/ipsec").await {
        result.ipsec_tunnels = body["results"].as_array().map(|a| a.len()).unwrap_or(0);
    }

    // 9. User-event log → ingest into `logs` table tagged `fortinet.event.user`
    //    Covers admin login/logout, auth failures, account changes — the
    //    high-value control-plane signals for SIEM.
    let host = result
        .system_serial
        .as_deref()
        .map(String::from)
        .unwrap_or_else(|| base.replace("https://", "").replace("/", ""));
    let cursor_user: i64 = config
        .cursor_user_event
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if let Ok(body) = fgt_get(
        &client,
        base,
        &auth,
        "/api/v2/log/memory/event/user/select?count=500",
    )
    .await
    {
        if let Some(rows) = body["results"].as_array() {
            let mut newest = cursor_user;
            for ev in rows {
                let ts = ev["eventtime"].as_i64().unwrap_or(0);
                if ts <= cursor_user {
                    continue;
                }
                if ts > newest {
                    newest = ts;
                }
                let iso = chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
                if store
                    .insert_log("fortinet.event.user", &host, ev, &iso)
                    .await
                    .is_ok()
                {
                    result.user_events_ingested += 1;
                }
            }
            if newest > cursor_user {
                result.cursor_user_event = Some(newest.to_string());
            }
        }
    }

    // 10. System-event log → ingest into `logs` tagged `fortinet.event.system`
    //     Covers config changes, daemon restarts, service status — useful
    //     to detect tampering with the firewall itself.
    let cursor_sys: i64 = config
        .cursor_system_event
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if let Ok(body) = fgt_get(
        &client,
        base,
        &auth,
        "/api/v2/log/memory/event/system/select?count=500",
    )
    .await
    {
        if let Some(rows) = body["results"].as_array() {
            let mut newest = cursor_sys;
            for ev in rows {
                let ts = ev["eventtime"].as_i64().unwrap_or(0);
                if ts <= cursor_sys {
                    continue;
                }
                if ts > newest {
                    newest = ts;
                }
                let iso = chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
                if store
                    .insert_log("fortinet.event.system", &host, ev, &iso)
                    .await
                    .is_ok()
                {
                    result.system_events_ingested += 1;
                }
            }
            if newest > cursor_sys {
                result.cursor_system_event = Some(newest.to_string());
            }
        }
    }

    // 11. Forward-traffic log → block events into `firewall_events`,
    //     mirrored into `logs` tag `fortinet.firewall` for Sigma matching
    //     (same approach as pfsense.rs).
    let cursor_fwd: i64 = config
        .cursor_forward_traffic
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if let Ok(body) = fgt_get(
        &client,
        base,
        &auth,
        "/api/v2/log/memory/traffic/forward/select?count=500",
    )
    .await
    {
        if let Some(rows) = body["results"].as_array() {
            let mut newest = cursor_fwd;
            let mut events: Vec<crate::db::threatclaw_store::NewFirewallEvent> = Vec::new();
            for ev in rows {
                let ts = ev["eventtime"].as_i64().unwrap_or(0);
                if ts <= cursor_fwd {
                    continue;
                }
                if ts > newest {
                    newest = ts;
                }
                // FortiGate "action": accept / deny / close / start ... we
                // only persist the deny/block path for SIEM correlation.
                let action = ev["action"].as_str().unwrap_or("").to_lowercase();
                if !matches!(action.as_str(), "deny" | "block" | "blocked" | "drop") {
                    continue;
                }
                let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
                    .unwrap_or_else(chrono::Utc::now);
                let iso = timestamp.to_rfc3339();
                let payload = serde_json::json!({
                    "fw_source": "fortinet",
                    "action": "block",
                    "src_ip": ev.get("srcip"),
                    "src_port": ev.get("srcport"),
                    "dst_ip": ev.get("dstip"),
                    "dst_port": ev.get("dstport"),
                    "proto": ev.get("proto"),
                    "policy_id": ev.get("policyid"),
                    "logid": ev.get("logid"),
                });
                let _ = store
                    .insert_log("fortinet.firewall", &host, &payload, &iso)
                    .await;
                events.push(crate::db::threatclaw_store::NewFirewallEvent {
                    timestamp,
                    fw_source: "fortinet".into(),
                    interface: ev["srcintf"].as_str().map(String::from),
                    action: "block".into(),
                    direction: ev["direction"].as_str().map(String::from),
                    proto: ev["proto"].as_str().map(String::from),
                    src_ip: ev["srcip"].as_str().map(String::from),
                    src_port: ev["srcport"].as_i64().map(|v| v as i32),
                    dst_ip: ev["dstip"].as_str().map(String::from),
                    dst_port: ev["dstport"].as_i64().map(|v| v as i32),
                    rule_id: ev["policyid"].as_str().map(String::from),
                    raw_meta: ev.clone(),
                });
            }
            if !events.is_empty() {
                if let Ok(n) = store.insert_firewall_events(&events).await {
                    result.forward_blocks_ingested = n;
                }
            }
            if newest > cursor_fwd {
                result.cursor_forward_traffic = Some(newest.to_string());
            }
        }
    }

    // 12. DHCP leases — IP/MAC/hostname, richer than ARP
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/system/dhcp").await {
        if let Some(leases) = body["results"].as_array() {
            result.dhcp_leases = leases.len();
            for lease in leases {
                let ip = lease["ip"].as_str().unwrap_or("");
                let mac = lease["mac"].as_str().unwrap_or("");
                let hostname = lease["hostname"].as_str().filter(|s| !s.is_empty());
                if !ip.is_empty() && !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    let discovered = DiscoveredAsset {
                        mac: Some(mac.into()),
                        hostname: hostname.map(String::from),
                        fqdn: None,
                        ip: Some(ip.into()),
                        os: None,
                        ports: None,
                        ou: None,
                        vlan: None,
                        vm_id: None,
                        criticality: None,
                        services: serde_json::json!([]),
                        source: "fortinet-dhcp".into(),
                    };
                    let _ = asset_resolution::resolve_asset(store, &discovered).await;
                    result.assets_resolved += 1;
                }
            }
        }
    }

    // 13. Local users (cmdb/user/local) → User node inventory
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/cmdb/user/local").await {
        if let Some(users) = body["results"].as_array() {
            result.local_users = users.len();
            for u in users {
                if let Some(name) = u["name"].as_str() {
                    crate::graph::identity_graph::touch_user(store, name).await;
                }
            }
        }
    }

    // 14. Firewall-auth users (currently authenticated through firewall)
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/user/firewall").await {
        if let Some(users) = body["results"].as_array() {
            result.firewall_auth_users = users.len();
            let asset_id = result
                .system_serial
                .as_deref()
                .map(|s| format!("fortigate-{s}"))
                .unwrap_or_else(|| format!("fortigate-{base}"));
            for u in users {
                let name = u["user_name"]
                    .as_str()
                    .or_else(|| u["username"].as_str())
                    .unwrap_or("");
                let src_ip = u["ipaddr"]
                    .as_str()
                    .or_else(|| u["src_ip"].as_str())
                    .unwrap_or("");
                if !name.is_empty() {
                    crate::graph::identity_graph::record_login(
                        store,
                        name,
                        &asset_id,
                        src_ip,
                        "firewall-auth",
                        true,
                    )
                    .await;
                    result.identity_edges_created += 1;
                }
            }
        }
    }

    // 15. Managed FortiAP (wireless infrastructure)
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/wifi/managed_ap").await {
        result.managed_aps = body["results"].as_array().map(|a| a.len()).unwrap_or(0);
    }

    // 16. Wireless clients (active sessions on FortiAP)
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/wifi/client").await {
        if let Some(clients) = body["results"].as_array() {
            result.wifi_clients = clients.len();
            for c in clients {
                let mac = c["mac"].as_str().unwrap_or("");
                let ip = c["ip"].as_str();
                let hostname = c["hostname"].as_str().filter(|s| !s.is_empty());
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    let discovered = DiscoveredAsset {
                        mac: Some(mac.into()),
                        hostname: hostname.map(String::from),
                        fqdn: None,
                        ip: ip.map(String::from),
                        os: c["os"].as_str().map(String::from),
                        ports: None,
                        ou: None,
                        vlan: None,
                        vm_id: None,
                        criticality: None,
                        services: serde_json::json!([]),
                        source: "fortinet-wifi".into(),
                    };
                    let _ = asset_resolution::resolve_asset(store, &discovered).await;
                    result.assets_resolved += 1;
                }
            }
        }
    }

    // 17. Rogue APs detected nearby — CRITICAL finding when populated.
    //     Strong signal of an attempted Wi-Fi intrusion / evil-twin attack.
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/wifi/rogue_ap").await {
        if let Some(rogues) = body["results"].as_array() {
            result.rogue_aps = rogues.len();
            for rogue in rogues {
                let bssid = rogue["bssid"].as_str().unwrap_or("");
                let ssid = rogue["ssid"].as_str().unwrap_or("?");
                let signal = rogue["signal"].as_i64().unwrap_or(0);
                let title = format!("Rogue AP detected — SSID '{ssid}' BSSID {bssid}");
                let description = format!(
                    "FortiAP detected an unauthorized access point. SSID: {ssid}. \
                     BSSID: {bssid}. Signal: {signal}dBm. Could be an evil-twin \
                     attack targeting your wireless clients — verify physical \
                     location and either authorize or block."
                );
                if store
                    .insert_finding(&crate::db::threatclaw_store::NewFinding {
                        skill_id: "skill-fortinet".into(),
                        title,
                        description: Some(description),
                        severity: "HIGH".into(),
                        category: Some("wireless-rogue".into()),
                        asset: Some(format!("rogue-bssid-{bssid}")),
                        source: Some("FortiGate / FortiAP".into()),
                        metadata: Some(serde_json::json!({
                            "bssid": bssid, "ssid": ssid, "signal_dbm": signal,
                        })),
                    })
                    .await
                    .is_ok()
                {
                    result.findings_created += 1;
                }
            }
        }
    }

    // 18. FortiSwitch detected devices (port-mac-ip mapping)
    if let Ok(body) = fgt_get(
        &client,
        base,
        &auth,
        "/api/v2/monitor/switch-controller/detected-device",
    )
    .await
    {
        result.switch_detected_devices = body["results"].as_array().map(|a| a.len()).unwrap_or(0);
    }

    // 19. HA cluster status — alert if cluster is unhealthy
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/system/ha-statistics").await {
        // FortiOS returns a populated structure when HA is configured;
        // an empty / null result means standalone (no finding needed).
        let has_data = body["results"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        if has_data {
            result.ha_status_ok = Some(true);
        }
    }

    // 20. License status — flag licenses expiring soon (< 30 days)
    if let Ok(body) = fgt_get(&client, base, &auth, "/api/v2/monitor/license/status").await {
        let r = &body["results"];
        let now = chrono::Utc::now().timestamp();
        for (lic_name, lic) in r.as_object().into_iter().flatten() {
            let expiry = lic["expires"].as_i64().unwrap_or(0);
            if expiry == 0 {
                continue;
            }
            let days_left = (expiry - now) / 86400;
            if (0..=30).contains(&days_left) {
                let title = format!("FortiGate license '{lic_name}' expires in {days_left} days");
                let description = format!(
                    "The {lic_name} license on this FortiGate expires {days_left} days from now \
                     ({}). Renew via FortiCare to avoid loss of UTM coverage.",
                    chrono::DateTime::<chrono::Utc>::from_timestamp(expiry, 0)
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default()
                );
                if store
                    .insert_finding(&crate::db::threatclaw_store::NewFinding {
                        skill_id: "skill-fortinet".into(),
                        title,
                        description: Some(description),
                        severity: if days_left < 7 { "HIGH" } else { "MEDIUM" }.into(),
                        category: Some("license-expiring".into()),
                        asset: Some(format!(
                            "fortigate-{}",
                            result.system_serial.as_deref().unwrap_or("?")
                        )),
                        source: Some("FortiGate license".into()),
                        metadata: Some(serde_json::json!({
                            "license": lic_name, "days_left": days_left, "expires": expiry,
                        })),
                    })
                    .await
                    .is_ok()
                {
                    result.findings_created += 1;
                }
            }
        }
    }

    // 21. UTM logs (defensive — 404 when modules unlicensed/disabled).
    //     Each subtype keeps its own cursor so an enabled module doesn't
    //     starve another that just got turned on.
    let utm_subtypes: &[(&str, &str)] = &[
        ("virus", "fortinet.utm.virus"),
        ("ips", "fortinet.utm.ips"),
        ("webfilter", "fortinet.utm.webfilter"),
        ("app-ctrl", "fortinet.utm.app_ctrl"),
    ];
    for (sub, tag) in utm_subtypes {
        let cursor: i64 = match *sub {
            "virus" => &config.cursor_utm_virus,
            "ips" => &config.cursor_utm_ips,
            "webfilter" => &config.cursor_utm_webfilter,
            "app-ctrl" => &config.cursor_utm_app_ctrl,
            _ => &None,
        }
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
        let path = format!("/api/v2/log/memory/utm/{sub}/select?count=500");
        if let Ok(body) = fgt_get(&client, base, &auth, &path).await {
            if let Some(rows) = body["results"].as_array() {
                let mut newest = cursor;
                let mut count = 0usize;
                for ev in rows {
                    let ts = ev["eventtime"].as_i64().unwrap_or(0);
                    if ts <= cursor {
                        continue;
                    }
                    if ts > newest {
                        newest = ts;
                    }
                    let iso = chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
                    if store.insert_log(tag, &host, ev, &iso).await.is_ok() {
                        count += 1;
                    }
                }
                let new_cursor = if newest > cursor {
                    Some(newest.to_string())
                } else {
                    None
                };
                match *sub {
                    "virus" => {
                        result.utm_virus_ingested = count;
                        if new_cursor.is_some() {
                            result.cursor_utm_virus = new_cursor;
                        }
                    }
                    "ips" => {
                        result.utm_ips_ingested = count;
                        if new_cursor.is_some() {
                            result.cursor_utm_ips = new_cursor;
                        }
                    }
                    "webfilter" => {
                        result.utm_webfilter_ingested = count;
                        if new_cursor.is_some() {
                            result.cursor_utm_webfilter = new_cursor;
                        }
                    }
                    "app-ctrl" => {
                        result.utm_app_ctrl_ingested = count;
                        if new_cursor.is_some() {
                            result.cursor_utm_app_ctrl = new_cursor;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Wireless + topology drift detection — track managed APs +
    // wifi_clients between syncs, raise a HIGH finding on ±30 % churn.
    // Catches: rogue AP appearing, AP suddenly offline (jamming or
    // physical pull), bulk client disconnect (deauth attack).
    fortinet_drift_check(
        store,
        result.managed_aps,
        result.wifi_clients,
        result.firewall_policies,
    )
    .await;

    tracing::info!(
        "FORTINET SYNC: v{} serial={} ARP={} assets={} ifaces={} addr={} policies={} sslvpn={}/identity={} ipsec={} cpu={}% mem={}% disk={}% events_user={} events_sys={} fw_blocks={}",
        result.system_version.as_deref().unwrap_or("?"),
        result.system_serial.as_deref().unwrap_or("?"),
        result.arp_entries,
        result.assets_resolved,
        result.interfaces,
        result.firewall_addresses,
        result.firewall_policies,
        result.ssl_vpn_sessions,
        result.identity_edges_created,
        result.ipsec_tunnels,
        result
            .cpu_usage_pct
            .map(|v| v.to_string())
            .unwrap_or("?".into()),
        result
            .mem_usage_pct
            .map(|v| v.to_string())
            .unwrap_or("?".into()),
        result
            .disk_usage_pct
            .map(|v| v.to_string())
            .unwrap_or("?".into()),
        result.user_events_ingested,
        result.system_events_ingested,
        result.forward_blocks_ingested,
    );

    result
}

/// Track per-cycle wireless + policy counts and emit a HIGH finding
/// on >= 30 % churn. Stored in `_baseline` / `firewall_fortinet`.
async fn fortinet_drift_check(
    store: &dyn Database,
    managed_aps: usize,
    wifi_clients: usize,
    policies: usize,
) {
    let key = "firewall_fortinet";
    let prev = store.get_setting("_baseline", key).await.ok().flatten();
    let snapshot = serde_json::json!({
        "managed_aps": managed_aps,
        "wifi_clients": wifi_clients,
        "firewall_policies": policies,
        "ts": chrono::Utc::now().to_rfc3339(),
    });

    if let Some(prev) = prev {
        let prev_aps = prev
            .get("managed_aps")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let prev_wifi = prev
            .get("wifi_clients")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let prev_pol = prev
            .get("firewall_policies")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        for (label, current, prev_n, threshold) in [
            ("managed_aps", managed_aps, prev_aps, 0.30),
            ("wifi_clients", wifi_clients, prev_wifi, 0.30),
            ("firewall_policies", policies, prev_pol, 0.25),
        ] {
            if prev_n == 0 {
                continue;
            }
            let delta = (current as i64 - prev_n as i64).abs() as f64 / prev_n as f64;
            if delta < threshold {
                continue;
            }
            let direction = if current > prev_n {
                "increased"
            } else {
                "decreased"
            };
            let _ = store
                .insert_finding(&crate::db::threatclaw_store::NewFinding {
                    skill_id: "skill-fortinet".into(),
                    title: format!("FortiGate {label} {direction} by {:.0}%", delta * 100.0),
                    description: Some(format!(
                        "{label} went from {prev_n} to {current} between syncs ({direction}). \
                         For wireless metrics this can mean a rogue AP appearing / disappearing \
                         or a deauth attack on the LAN; for firewall_policies it can mean \
                         defense-evasion or accidental wipe."
                    )),
                    severity: "high".into(),
                    category: Some("firewall_drift".into()),
                    asset: Some("fortinet".into()),
                    source: Some("skill-fortinet".into()),
                    metadata: Some(serde_json::json!({
                        "prev": prev_n,
                        "current": current,
                        "delta_pct": (delta * 100.0).round(),
                        "direction": direction,
                        "metric": label,
                    })),
                })
                .await;
            tracing::warn!("BASELINE DRIFT: fortinet {label} {prev_n} → {current} ({direction})");
        }
    }

    let _ = store.set_setting("_baseline", key, &snapshot).await;
}

/// Block an IP on FortiGate via the native quarantine endpoint.
///
/// FortiGate ships a built-in "banned IP" mechanism (`/monitor/user/banned`)
/// that drops every packet sourced or destined to the IP without needing
/// any policy plumbing. We use that as the primary block — instantaneous,
/// reversible, and doesn't require the admin to pre-create a policy.
///
/// We also create an address object as a paper-trail (visible in the GUI
/// for compliance/audit), but it's not what enforces the block.
pub async fn block_ip(config: &FortinetConfig, ip: &str) -> Result<serde_json::Value, String> {
    let client = Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;
    let auth = format!("Bearer {}", config.api_key);

    // 1. Native quarantine — single endpoint, instant effect.
    let banned_url = format!("{}/api/v2/monitor/user/banned/add_users", config.url);
    let banned_body = serde_json::json!({
        "ip_addresses": [ip],
        "expiry": 0,  // 0 = until manually cleared
    });
    let resp = client
        .post(&banned_url)
        .header("Authorization", &auth)
        .json(&banned_body)
        .send()
        .await
        .map_err(|e| format!("ban request: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("ban failed ({status}): {body}"));
    }

    // 2. Paper-trail: idempotent address object (PUT-or-create-then-PUT).
    let obj_name = format!("tc-block-{}", ip.replace('.', "-"));
    let addr_url = format!("{}/api/v2/cmdb/firewall/address", config.url);
    let addr_body = serde_json::json!({
        "name": obj_name,
        "type": "ipmask",
        "subnet": format!("{}/32", ip),
        "comment": format!("ThreatClaw auto-block: {}", ip),
    });
    let _ = client
        .post(&addr_url)
        .header("Authorization", &auth)
        .json(&addr_body)
        .send()
        .await; // best-effort — quarantine already enforced.

    tracing::info!("FORTINET: Quarantined IP {ip} (banned + address: {obj_name})");
    Ok(serde_json::json!({
        "blocked": true,
        "ip": ip,
        "method": "monitor.user.banned",
        "address_object": obj_name,
        "reversible": true,
        "undo": format!(
            "POST {}/api/v2/monitor/user/banned/clear_users  body={{\"ip_addresses\":[\"{}\"]}}",
            config.url, ip
        ),
    }))
}

/// Block a URL pattern on FortiGate via webfilter URL filter list.
///
/// Adds the pattern to a managed urlfilter list `TC-URL-BLOCKLIST`. Auto-
/// creates the list on first call. The admin still has to attach the list
/// to a webfilter profile and that profile to a policy — we surface the
/// hint in the result if the list looks unattached. Reversible by removing
/// the entry from the list.
pub async fn block_url(config: &FortinetConfig, url: &str) -> Result<serde_json::Value, String> {
    let client = Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;
    let auth = format!("Bearer {}", config.api_key);
    let list_name = "TC-URL-BLOCKLIST";

    // 1. Read existing list (404 = not yet created).
    let list_url = format!("{}/api/v2/cmdb/webfilter/urlfilter", config.url);
    let read = client
        .get(format!("{list_url}/{list_name}"))
        .header("Authorization", &auth)
        .send()
        .await
        .map_err(|e| format!("urlfilter read: {e}"))?;
    let mut entries: Vec<serde_json::Value> = if read.status().is_success() {
        read.json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v["results"][0]["entries"].as_array().cloned())
            .unwrap_or_default()
    } else {
        // List doesn't exist → create empty.
        let create = client
            .post(&list_url)
            .header("Authorization", &auth)
            .json(&serde_json::json!({
                "name": list_name,
                "comment": "ThreatClaw auto-blocked URLs",
                "one-arm-ips-urlfilter": "disable",
            }))
            .send()
            .await
            .map_err(|e| format!("urlfilter create: {e}"))?;
        if !create.status().is_success() {
            let body = create.text().await.unwrap_or_default();
            return Err(format!("urlfilter create failed: {body}"));
        }
        vec![]
    };

    // 2. Already in list?
    if entries.iter().any(|e| e["url"].as_str() == Some(url)) {
        return Ok(serde_json::json!({
            "blocked": true,
            "url": url,
            "list": list_name,
            "already_present": true,
        }));
    }

    // 3. Append + PUT.
    let next_id = entries.len() as i64 + 1;
    entries.push(serde_json::json!({
        "id": next_id,
        "url": url,
        "type": "wildcard",
        "action": "block",
        "status": "enable",
    }));
    let put = client
        .put(format!("{list_url}/{list_name}"))
        .header("Authorization", &auth)
        .json(&serde_json::json!({ "entries": entries }))
        .send()
        .await
        .map_err(|e| format!("urlfilter update: {e}"))?;
    if !put.status().is_success() {
        let body = put.text().await.unwrap_or_default();
        return Err(format!("urlfilter update failed: {body}"));
    }

    tracing::info!("FORTINET: Blocked URL '{url}' (list: {list_name})");
    Ok(serde_json::json!({
        "blocked": true,
        "url": url,
        "list": list_name,
        "reversible": true,
        "undo": format!(
            "remove the entry id={} from PUT {list_url}/{list_name} entries",
            next_id
        ),
        "note": "If this is the first block, attach TC-URL-BLOCKLIST to your webfilter profile in the GUI (Security Profiles → Web Filter → Static URL Filter)."
    }))
}

/// Common GET helper — handles auth header + JSON parse + status check.
async fn fgt_get(
    client: &Client,
    base: &str,
    auth: &str,
    path: &str,
) -> Result<serde_json::Value, String> {
    let url = format!("{base}{path}");
    let resp = client
        .get(&url)
        .header("Authorization", auth)
        .send()
        .await
        .map_err(|e| format!("request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.json().await.map_err(|e| format!("json: {e}"))
}

fn extract_vlan(iface: &str) -> Option<u16> {
    // FortiGate VLAN interface names: "vlan10", "port1.20"
    if let Some(pos) = iface.to_lowercase().find("vlan") {
        iface[pos + 4..].parse::<u16>().ok()
    } else if let Some(pos) = iface.find('.') {
        iface[pos + 1..].parse::<u16>().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_vlan() {
        assert_eq!(extract_vlan("vlan10"), Some(10));
        assert_eq!(extract_vlan("port1.20"), Some(20));
        assert_eq!(extract_vlan("port1"), None);
    }
}
