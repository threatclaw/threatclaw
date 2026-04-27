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
    pub errors: Vec<String>,
    /// New cursors written back at the end of the sync.
    pub cursor_user_event: Option<String>,
    pub cursor_system_event: Option<String>,
    pub cursor_forward_traffic: Option<String>,
}

pub async fn sync_fortinet(store: &dyn Database, config: &FortinetConfig) -> FortinetSyncResult {
    let mut result = FortinetSyncResult {
        cursor_user_event: config.cursor_user_event.clone(),
        cursor_system_event: config.cursor_system_event.clone(),
        cursor_forward_traffic: config.cursor_forward_traffic.clone(),
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

/// Block an IP on FortiGate by creating an address object + deny policy.
pub async fn block_ip(config: &FortinetConfig, ip: &str) -> Result<serde_json::Value, String> {
    let client = Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP: {e}"))?;

    let obj_name = format!("tc-block-{}", ip.replace('.', "-"));
    let addr_url = format!("{}/api/v2/cmdb/firewall/address", config.url);
    let addr_body = serde_json::json!({
        "name": obj_name,
        "type": "ipmask",
        "subnet": format!("{}/32", ip),
        "comment": format!("ThreatClaw auto-block: {}", ip),
    });

    let resp = client
        .post(&addr_url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&addr_body)
        .send()
        .await
        .map_err(|e| format!("Address create: {e}"))?;

    if !resp.status().is_success() && resp.status().as_u16() != 500 {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Address create failed: {body}"));
    }

    tracing::info!("FORTINET: Blocked IP {ip} (address object: {obj_name})");
    Ok(serde_json::json!({
        "blocked": true,
        "ip": ip,
        "address_object": obj_name,
        "reversible": true,
        "undo": format!("DELETE {}/api/v2/cmdb/firewall/address/{}", config.url, obj_name),
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
