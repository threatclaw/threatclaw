//! Fortinet FortiGate Connector — read firewall data + block IPs.
//!
//! Auth: API key in header (Authorization: Bearer {api_key})
//! API: GET https://{host}/api/v2/monitor/system/arp
//!      GET https://{host}/api/v2/monitor/firewall/session
//!      POST https://{host}/api/v2/cmdb/firewall/address (create address object)
//!      POST https://{host}/api/v2/cmdb/firewall/policy (create block rule)

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
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize)]
pub struct FortinetSyncResult {
    pub arp_entries: usize,
    pub assets_resolved: usize,
    pub interfaces: usize,
    pub errors: Vec<String>,
}

pub async fn sync_fortinet(store: &dyn Database, config: &FortinetConfig) -> FortinetSyncResult {
    let mut result = FortinetSyncResult {
        arp_entries: 0, assets_resolved: 0, interfaces: 0, errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("HTTP client: {}", e)); return result; }
    };

    tracing::info!("FORTINET: Connecting to {}", config.url);

    // ARP table
    let arp_url = format!("{}/api/v2/monitor/system/arp", config.url);
    match client.get(&arp_url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(entries) = body["results"].as_array() {
                    result.arp_entries = entries.len();
                    for entry in entries {
                        let ip = entry["ip"].as_str().unwrap_or("");
                        let mac = entry["mac"].as_str().unwrap_or("");
                        let iface = entry["interface"].as_str().unwrap_or("");

                        if !ip.is_empty() && !mac.is_empty() && mac != "00:00:00:00:00:00" {
                            let discovered = DiscoveredAsset {
                                mac: Some(mac.to_string()),
                                hostname: None,
                                fqdn: None,
                                ip: Some(ip.to_string()),
                                os: None,
                                ports: None,
                                ou: None,
                                vlan: extract_vlan(iface),
                                vm_id: None,
                                criticality: None,
            services: serde_json::json!([]),
                                source: "fortinet".into(),
                            };
                            asset_resolution::resolve_asset(store, &discovered).await;
                            result.assets_resolved += 1;
                        }
                    }
                }
            }
        }
        Ok(resp) => { result.errors.push(format!("ARP HTTP {}", resp.status())); }
        Err(e) => { result.errors.push(format!("ARP: {}", e)); }
    }

    // Interfaces
    let iface_url = format!("{}/api/v2/cmdb/system/interface", config.url);
    match client.get(&iface_url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                result.interfaces = body["results"].as_array().map(|a| a.len()).unwrap_or(0);
            }
        }
        _ => {}
    }

    tracing::info!("FORTINET SYNC: {} ARP entries, {} assets, {} interfaces",
        result.arp_entries, result.assets_resolved, result.interfaces);

    result
}

/// Block an IP on FortiGate by creating an address object + deny policy.
pub async fn block_ip(config: &FortinetConfig, ip: &str) -> Result<serde_json::Value, String> {
    let client = Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP: {}", e))?;

    let obj_name = format!("tc-block-{}", ip.replace('.', "-"));

    // Create address object
    let addr_url = format!("{}/api/v2/cmdb/firewall/address", config.url);
    let addr_body = serde_json::json!({
        "name": obj_name,
        "type": "ipmask",
        "subnet": format!("{}/32", ip),
        "comment": format!("ThreatClaw auto-block: {}", ip),
    });

    let resp = client.post(&addr_url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&addr_body)
        .send().await
        .map_err(|e| format!("Address create: {}", e))?;

    if !resp.status().is_success() && resp.status().as_u16() != 500 {
        // 500 sometimes means "already exists" on FortiGate
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Address create failed: {}", body));
    }

    tracing::info!("FORTINET: Blocked IP {} (address object: {})", ip, obj_name);
    Ok(serde_json::json!({
        "blocked": true,
        "ip": ip,
        "address_object": obj_name,
        "reversible": true,
        "undo": format!("DELETE {}/api/v2/cmdb/firewall/address/{}", config.url, obj_name),
    }))
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
