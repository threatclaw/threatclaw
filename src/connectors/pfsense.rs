//! pfSense / OPNsense Connector — real REST API integration.
//!
//! Discovers network topology: ARP table, DHCP leases, firewall rules,
//! interfaces, and VLANs. Feeds assets into the graph via Asset Resolution.
//!
//! Supports both:
//! - pfSense (requires pfSense-pkg-RESTAPI v2 package)
//! - OPNsense (built-in API)
//!
//! Auth: Basic auth (pfSense) or API Key/Secret (OPNsense)

use crate::db::Database;
use crate::graph::asset_resolution::{self, DiscoveredAsset};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Firewall connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Firewall URL (e.g., "https://192.168.1.1")
    pub url: String,
    /// Firewall type
    pub fw_type: FirewallType,
    /// Auth: username (pfSense) or API key (OPNsense)
    pub auth_user: String,
    /// Auth: password (pfSense) or API secret (OPNsense)
    pub auth_secret: String,
    /// Skip TLS certificate verification (self-signed certs)
    pub no_tls_verify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallType {
    PfSense,
    OPNsense,
}

/// Result of a firewall sync operation.
#[derive(Debug, Clone, Serialize)]
pub struct FirewallSyncResult {
    pub arp_entries: usize,
    pub dhcp_leases: usize,
    pub interfaces: usize,
    pub vlans: usize,
    pub firewall_rules: usize,
    pub assets_resolved: usize,
    pub errors: Vec<String>,
}

/// ARP entry from the firewall.
#[derive(Debug, Clone, Deserialize)]
struct ArpEntry {
    ip: Option<String>,
    mac: Option<String>,
    hostname: Option<String>,
    #[serde(alias = "interface", alias = "intf")]
    interface: Option<String>,
    #[serde(alias = "intf_description")]
    interface_desc: Option<String>,
}

/// DHCP lease from the firewall.
#[derive(Debug, Clone, Deserialize)]
struct DhcpLease {
    #[serde(alias = "address")]
    ip: Option<String>,
    mac: Option<String>,
    hostname: Option<String>,
    #[serde(alias = "if")]
    interface: Option<String>,
    #[serde(alias = "if_descr")]
    interface_desc: Option<String>,
    #[serde(alias = "active_status", alias = "state")]
    status: Option<String>,
}

/// Sync firewall data into ThreatClaw graph.
pub async fn sync_firewall(store: &dyn Database, config: &FirewallConfig) -> FirewallSyncResult {
    let mut result = FirewallSyncResult {
        arp_entries: 0, dhcp_leases: 0, interfaces: 0, vlans: 0,
        firewall_rules: 0, assets_resolved: 0, errors: vec![],
    };

    let client = match build_client(config) {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("HTTP client error: {}", e));
            return result;
        }
    };

    tracing::info!("FIREWALL: Connecting to {} ({:?})", config.url, config.fw_type);

    // 1. Sync ARP table (all devices on network)
    match fetch_arp(&client, config).await {
        Ok(entries) => {
            result.arp_entries = entries.len();
            for entry in &entries {
                if let (Some(ip), Some(mac)) = (&entry.ip, &entry.mac) {
                    if !ip.is_empty() && !mac.is_empty() && mac != "(incomplete)" {
                        let vlan = extract_vlan_from_interface(entry.interface.as_deref());
                        let discovered = DiscoveredAsset {
                            mac: Some(mac.clone()),
                            hostname: entry.hostname.clone().filter(|h| !h.is_empty() && h != "?"),
                            fqdn: None,
                            ip: Some(ip.clone()),
                            os: None,
                            ports: None,
                            ou: None,
                            vlan,
                            vm_id: None,
                            criticality: None,
            services: serde_json::json!([]),
                            source: config.fw_type.source_name().into(),
                        };
                        asset_resolution::resolve_asset(store, &discovered).await;
                        result.assets_resolved += 1;
                    }
                }
            }
            tracing::info!("FIREWALL: {} ARP entries → {} assets resolved",
                result.arp_entries, result.assets_resolved);
        }
        Err(e) => {
            result.errors.push(format!("ARP fetch failed: {}", e));
            tracing::error!("FIREWALL: ARP fetch failed: {}", e);
        }
    }

    // 2. Sync DHCP leases (enrich with hostname)
    match fetch_dhcp_leases(&client, config).await {
        Ok(leases) => {
            result.dhcp_leases = leases.len();
            for lease in &leases {
                if let (Some(ip), Some(mac)) = (&lease.ip, &lease.mac) {
                    if !ip.is_empty() && !mac.is_empty() {
                        let vlan = extract_vlan_from_interface(lease.interface.as_deref());
                        let discovered = DiscoveredAsset {
                            mac: Some(mac.clone()),
                            hostname: lease.hostname.clone().filter(|h| !h.is_empty()),
                            fqdn: None,
                            ip: Some(ip.clone()),
                            os: None,
                            ports: None,
                            ou: None,
                            vlan,
                            vm_id: None,
                            criticality: None,
            services: serde_json::json!([]),
                            source: "dhcp".into(),
                        };
                        asset_resolution::resolve_asset(store, &discovered).await;
                        result.assets_resolved += 1;
                    }
                }
            }
            tracing::info!("FIREWALL: {} DHCP leases synced", result.dhcp_leases);
        }
        Err(e) => {
            result.errors.push(format!("DHCP fetch failed: {}", e));
            tracing::error!("FIREWALL: DHCP fetch failed: {}", e);
        }
    }

    // 3. Count interfaces and VLANs (for topology awareness)
    match fetch_interfaces(&client, config).await {
        Ok(count) => { result.interfaces = count; }
        Err(e) => { result.errors.push(format!("Interfaces fetch: {}", e)); }
    }

    match fetch_vlans(&client, config).await {
        Ok(count) => { result.vlans = count; }
        Err(e) => { result.errors.push(format!("VLANs fetch: {}", e)); }
    }

    match fetch_firewall_rules(&client, config).await {
        Ok(count) => { result.firewall_rules = count; }
        Err(e) => { result.errors.push(format!("Rules fetch: {}", e)); }
    }

    tracing::info!(
        "FIREWALL SYNC COMPLETE: {} ARP, {} DHCP, {} interfaces, {} VLANs, {} rules, {} assets",
        result.arp_entries, result.dhcp_leases, result.interfaces,
        result.vlans, result.firewall_rules, result.assets_resolved
    );

    result
}

impl FirewallType {
    fn source_name(&self) -> &str {
        match self {
            FirewallType::PfSense => "pfSense",
            FirewallType::OPNsense => "opnsense",
        }
    }
}

fn build_client(config: &FirewallConfig) -> Result<Client, String> {
    Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))
}

/// Fetch ARP table from firewall.
async fn fetch_arp(client: &Client, config: &FirewallConfig) -> Result<Vec<ArpEntry>, String> {
    let url = match config.fw_type {
        FirewallType::PfSense => format!("{}/api/v2/diagnostics/arp_table", config.url),
        FirewallType::OPNsense => format!("{}/api/diagnostics/interface/getArp", config.url),
    };

    let resp = client.get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("ARP request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("ARP: HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("ARP parse error: {}", e))?;

    // pfSense wraps in {data: [...]}, OPNsense returns array directly
    let entries_val = if config.fw_type == FirewallType::PfSense {
        body.get("data").cloned().unwrap_or(serde_json::Value::Array(vec![]))
    } else {
        body
    };

    let entries: Vec<ArpEntry> = serde_json::from_value(entries_val)
        .map_err(|e| format!("ARP deserialize error: {}", e))?;

    Ok(entries)
}

/// Fetch DHCP leases from firewall.
async fn fetch_dhcp_leases(client: &Client, config: &FirewallConfig) -> Result<Vec<DhcpLease>, String> {
    let url = match config.fw_type {
        FirewallType::PfSense => format!("{}/api/v2/services/dhcpd/lease", config.url),
        FirewallType::OPNsense => format!("{}/api/dhcpv4/leases/searchLease", config.url),
    };

    let resp = client.get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("DHCP request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("DHCP: HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("DHCP parse error: {}", e))?;

    // pfSense: {data: [...]}, OPNsense: {rows: [...]}
    let leases_val = if config.fw_type == FirewallType::PfSense {
        body.get("data").cloned().unwrap_or(serde_json::Value::Array(vec![]))
    } else {
        body.get("rows").cloned().unwrap_or(serde_json::Value::Array(vec![]))
    };

    let leases: Vec<DhcpLease> = serde_json::from_value(leases_val)
        .map_err(|e| format!("DHCP deserialize error: {}", e))?;

    Ok(leases)
}

/// Fetch interface count.
async fn fetch_interfaces(client: &Client, config: &FirewallConfig) -> Result<usize, String> {
    let url = match config.fw_type {
        FirewallType::PfSense => format!("{}/api/v2/interface", config.url),
        FirewallType::OPNsense => format!("{}/api/interfaces/overview/export", config.url),
    };

    let resp = client.get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("Interfaces request: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Interfaces: HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await
        .map_err(|e| format!("Interfaces parse: {}", e))?;

    let count = if config.fw_type == FirewallType::PfSense {
        body.get("data").and_then(|d| d.as_array()).map(|a| a.len()).unwrap_or(0)
    } else {
        body.as_array().map(|a| a.len()).unwrap_or(0)
    };

    tracing::info!("FIREWALL: {} interfaces found", count);
    Ok(count)
}

/// Fetch VLAN count.
async fn fetch_vlans(client: &Client, config: &FirewallConfig) -> Result<usize, String> {
    let url = match config.fw_type {
        FirewallType::PfSense => format!("{}/api/v2/interface/vlan", config.url),
        FirewallType::OPNsense => format!("{}/api/interfaces/vlan_settings/searchItem", config.url),
    };

    let resp = client.get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("VLANs request: {}", e))?;

    if !resp.status().is_success() { return Ok(0); }

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("VLANs parse: {}", e))?;

    let count = if config.fw_type == FirewallType::PfSense {
        body.get("data").and_then(|d| d.as_array()).map(|a| a.len()).unwrap_or(0)
    } else {
        body.get("rows").and_then(|d| d.as_array()).map(|a| a.len()).unwrap_or(0)
    };

    tracing::info!("FIREWALL: {} VLANs found", count);
    Ok(count)
}

/// Fetch firewall rule count.
async fn fetch_firewall_rules(client: &Client, config: &FirewallConfig) -> Result<usize, String> {
    let url = match config.fw_type {
        FirewallType::PfSense => format!("{}/api/v2/firewall/rule", config.url),
        FirewallType::OPNsense => format!("{}/api/firewall/filter/searchRule", config.url),
    };

    let resp = client.get(&url)
        .basic_auth(&config.auth_user, Some(&config.auth_secret))
        .send()
        .await
        .map_err(|e| format!("Rules request: {}", e))?;

    if !resp.status().is_success() { return Ok(0); }

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("Rules parse: {}", e))?;

    let count = if config.fw_type == FirewallType::PfSense {
        body.get("data").and_then(|d| d.as_array()).map(|a| a.len()).unwrap_or(0)
    } else {
        body.get("rows").and_then(|d| d.as_array()).map(|a| a.len()).unwrap_or(0)
    };

    tracing::info!("FIREWALL: {} firewall rules found", count);
    Ok(count)
}

/// Extract VLAN ID from interface name (e.g., "em1.10" → 10, "vtnet1_vlan20" → 20).
fn extract_vlan_from_interface(interface: Option<&str>) -> Option<u16> {
    let iface = interface?;

    // pfSense format: "em1.10"
    if let Some(pos) = iface.rfind('.') {
        if let Ok(vlan) = iface[pos + 1..].parse::<u16>() {
            return Some(vlan);
        }
    }

    // OPNsense format: "vtnet1_vlan10"
    if let Some(pos) = iface.find("vlan") {
        if let Ok(vlan) = iface[pos + 4..].parse::<u16>() {
            return Some(vlan);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_vlan_pfsense() {
        assert_eq!(extract_vlan_from_interface(Some("em1.10")), Some(10));
        assert_eq!(extract_vlan_from_interface(Some("igb0.20")), Some(20));
    }

    #[test]
    fn test_extract_vlan_opnsense() {
        assert_eq!(extract_vlan_from_interface(Some("vtnet1_vlan10")), Some(10));
        assert_eq!(extract_vlan_from_interface(Some("vtnet0_vlan30")), Some(30));
    }

    #[test]
    fn test_extract_vlan_no_vlan() {
        assert_eq!(extract_vlan_from_interface(Some("em0")), None);
        assert_eq!(extract_vlan_from_interface(Some("lan")), None);
        assert_eq!(extract_vlan_from_interface(None), None);
    }
}
