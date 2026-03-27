//! Proxmox VE Connector — discovers VMs and containers via REST API.
//!
//! Auth: API token (PVEAPIToken=user@realm!tokenid=secret)
//! Endpoint: https://proxmox:8006/api2/json/
//!
//! Feeds VMs into the Asset Resolution Pipeline with vm_id set.

use crate::db::Database;
use crate::graph::asset_resolution::{self, DiscoveredAsset};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Proxmox connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxmoxConfig {
    /// Proxmox URL (e.g., "https://192.168.10.10:8006")
    pub url: String,
    /// API token ID (e.g., "tc-audit@pam!tc-token")
    pub token_id: String,
    /// API token secret
    pub token_secret: String,
    /// Skip TLS verification
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
}

fn default_true() -> bool { true }

/// Proxmox sync result.
#[derive(Debug, Clone, Serialize)]
pub struct ProxmoxSyncResult {
    pub vms: usize,
    pub containers: usize,
    pub nodes: usize,
    pub assets_resolved: usize,
    pub errors: Vec<String>,
}

/// VM/container resource from Proxmox.
#[derive(Debug, Deserialize)]
struct PveResource {
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default)]
    res_type: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    node: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    vmid: u64,
    #[serde(default)]
    maxcpu: f64,
    #[serde(default)]
    maxmem: u64,
}

/// Sync Proxmox VMs/containers into ThreatClaw graph.
pub async fn sync_proxmox(store: &dyn Database, config: &ProxmoxConfig) -> ProxmoxSyncResult {
    let mut result = ProxmoxSyncResult {
        vms: 0, containers: 0, nodes: 0, assets_resolved: 0, errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("HTTP client error: {}", e));
            return result;
        }
    };

    let auth_header = format!("PVEAPIToken={}={}", config.token_id, config.token_secret);

    tracing::info!("PROXMOX: Connecting to {}", config.url);

    // Fetch all cluster resources
    let url = format!("{}/api2/json/cluster/resources", config.url);
    let resp = match client.get(&url)
        .header("Authorization", &auth_header)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("Proxmox API error: {}", e));
            tracing::error!("PROXMOX: API request failed: {}", e);
            return result;
        }
    };

    if !resp.status().is_success() {
        result.errors.push(format!("Proxmox API: HTTP {}", resp.status()));
        return result;
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(e) => {
            result.errors.push(format!("Proxmox JSON parse: {}", e));
            return result;
        }
    };

    let resources: Vec<PveResource> = body.get("data")
        .and_then(|d| serde_json::from_value(d.clone()).ok())
        .unwrap_or_default();

    for res in &resources {
        match res.res_type.as_str() {
            "qemu" => {
                result.vms += 1;
                let discovered = DiscoveredAsset {
                    mac: None,
                    hostname: Some(res.name.clone()),
                    fqdn: None,
                    ip: None, // Proxmox doesn't reliably expose guest IPs
                    os: None,
                    ports: None,
                    ou: None,
                    vlan: None,
                    vm_id: Some(format!("pve-{}-{}", res.node, res.vmid)),
                    criticality: None,
            services: serde_json::json!([]),
                    source: "proxmox".into(),
                };
                asset_resolution::resolve_asset(store, &discovered).await;
                result.assets_resolved += 1;
            }
            "lxc" => {
                result.containers += 1;
                let discovered = DiscoveredAsset {
                    mac: None,
                    hostname: Some(res.name.clone()),
                    fqdn: None,
                    ip: None,
                    os: Some("Linux (LXC)".into()),
                    ports: None,
                    ou: None,
                    vlan: None,
                    vm_id: Some(format!("pve-lxc-{}-{}", res.node, res.vmid)),
                    criticality: None,
            services: serde_json::json!([]),
                    source: "proxmox".into(),
                };
                asset_resolution::resolve_asset(store, &discovered).await;
                result.assets_resolved += 1;
            }
            "node" => {
                result.nodes += 1;
            }
            _ => {}
        }
    }

    tracing::info!(
        "PROXMOX SYNC: {} VMs, {} containers, {} nodes, {} assets",
        result.vms, result.containers, result.nodes, result.assets_resolved
    );

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_header_format() {
        let header = format!("PVEAPIToken={}={}", "tc@pam!token", "secret123");
        assert_eq!(header, "PVEAPIToken=tc@pam!token=secret123");
    }
}
