//! Proxmox VE Connector — full hypervisor visibility.
//!
//! Auth: API token (`PVEAPIToken=user@realm!tokenid=secret`)
//! Endpoint: `https://proxmox:8006/api2/json/`
//!
//! Beyond a basic VM/container inventory the connector pulls:
//!
//! - **cluster/log** — control-plane audit (admin login, VM destroy,
//!   user add, root su) → mirrored into `logs` with tag
//!   `proxmox.audit` so the Sigma engine can match attack patterns.
//! - **cluster/backup** — backup job inventory. Zero jobs configured
//!   on a populated cluster emits a CRITICAL finding (no backup =
//!   no recovery).
//! - **qemu-guest-agent network-get-interfaces** — when QGA is
//!   running, fetches the actual VM IPs to enrich the asset graph.
//!
//! Cursor: `cursor_last_log_time` keeps the audit log incremental.

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use crate::graph::asset_resolution::{self, DiscoveredAsset};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Proxmox connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxmoxConfig {
    pub url: String,
    pub token_id: String,
    pub token_secret: String,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
    /// Audit-log cursor (epoch seconds, persisted between sync cycles).
    #[serde(default)]
    pub cursor_last_log_time: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ProxmoxSyncResult {
    pub vms: usize,
    pub containers: usize,
    pub nodes: usize,
    pub assets_resolved: usize,
    pub audit_events_ingested: usize,
    pub backup_jobs: usize,
    pub findings_created: usize,
    pub ips_enriched: usize,
    pub errors: Vec<String>,
    /// Newest audit-log timestamp seen (epoch seconds as string).
    pub cursor_last_log_time: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PveResource {
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
}

pub async fn sync_proxmox(store: &dyn Database, config: &ProxmoxConfig) -> ProxmoxSyncResult {
    let mut result = ProxmoxSyncResult {
        cursor_last_log_time: config.cursor_last_log_time.clone(),
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

    let auth = format!("PVEAPIToken={}={}", config.token_id, config.token_secret);
    let base = config.url.trim_end_matches('/');

    tracing::info!("PROXMOX: Connecting to {}", base);

    // ── 1. Cluster resources (VMs, containers, nodes) ─────────────
    let resources = match pve_get(&client, base, &auth, "/api2/json/cluster/resources").await {
        Ok(v) => v,
        Err(e) => {
            result.errors.push(format!("cluster/resources: {e}"));
            return result;
        }
    };
    let parsed: Vec<PveResource> = resources
        .get("data")
        .and_then(|d| serde_json::from_value(d.clone()).ok())
        .unwrap_or_default();

    let mut running_vms: Vec<(String, u64)> = Vec::new(); // (node, vmid) for QGA enrichment
    for res in &parsed {
        match res.res_type.as_str() {
            "qemu" => {
                result.vms += 1;
                if res.status == "running" {
                    running_vms.push((res.node.clone(), res.vmid));
                }
                let discovered = DiscoveredAsset {
                    mac: None,
                    hostname: if res.name.is_empty() {
                        None
                    } else {
                        Some(res.name.clone())
                    },
                    fqdn: None,
                    ip: None,
                    os: None,
                    ports: None,
                    ou: None,
                    vlan: None,
                    vm_id: Some(format!("pve-{}-{}", res.node, res.vmid)),
                    criticality: None,
                    services: serde_json::json!([]),
                    source: "proxmox".into(),
                };
                let _ = asset_resolution::resolve_asset(store, &discovered).await;
                result.assets_resolved += 1;
            }
            "lxc" => {
                result.containers += 1;
                let discovered = DiscoveredAsset {
                    mac: None,
                    hostname: if res.name.is_empty() {
                        None
                    } else {
                        Some(res.name.clone())
                    },
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
                let _ = asset_resolution::resolve_asset(store, &discovered).await;
                result.assets_resolved += 1;
            }
            "node" => result.nodes += 1,
            _ => {}
        }
    }

    // ── 2. IP enrichment via qemu-guest-agent (best-effort) ──────
    // QGA is opt-in per VM; the call returns 500/404 when the VM
    // doesn't have it. We tolerate failures silently — they're the
    // common case (most VMs don't run QGA).
    for (node, vmid) in &running_vms {
        let path = format!("/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces");
        if let Ok(body) = pve_get(&client, base, &auth, &path).await {
            if let Some(ip) = first_routable_ip(&body) {
                let discovered = DiscoveredAsset {
                    mac: None,
                    hostname: parsed
                        .iter()
                        .find(|r| r.vmid == *vmid && r.res_type == "qemu")
                        .map(|r| r.name.clone()),
                    fqdn: None,
                    ip: Some(ip),
                    os: None,
                    ports: None,
                    ou: None,
                    vlan: None,
                    vm_id: Some(format!("pve-{node}-{vmid}")),
                    criticality: None,
                    services: serde_json::json!([]),
                    source: "proxmox-qga".into(),
                };
                let _ = asset_resolution::resolve_asset(store, &discovered).await;
                result.ips_enriched += 1;
            }
        }
    }

    // ── 3. Backup jobs status ────────────────────────────────────
    match pve_get(&client, base, &auth, "/api2/json/cluster/backup").await {
        Ok(body) => {
            let jobs = body
                .get("data")
                .and_then(|d| d.as_array())
                .cloned()
                .unwrap_or_default();
            result.backup_jobs = jobs.len();
            // Empty backup config on a cluster with VMs = critical.
            if jobs.is_empty() && result.vms + result.containers > 0 {
                let title = "Proxmox : aucun job de sauvegarde configuré".to_string();
                let description = format!(
                    "{} VMs et {} containers présents sur le cluster sans aucun job vzdump configuré. \
                     Aucune sauvegarde = aucune récupération possible en cas de ransomware ou de défaillance.",
                    result.vms, result.containers
                );
                if store
                    .insert_finding(&NewFinding {
                        skill_id: "skill-proxmox".into(),
                        title,
                        description: Some(description),
                        severity: "CRITICAL".into(),
                        category: Some("backup-coverage".into()),
                        asset: Some(format!("proxmox:{}", base)),
                        source: Some("Proxmox VE".into()),
                        metadata: Some(serde_json::json!({
                            "vms": result.vms,
                            "containers": result.containers,
                            "backup_jobs": 0,
                        })),
                    })
                    .await
                    .is_ok()
                {
                    result.findings_created += 1;
                }
            }
        }
        Err(e) => result.errors.push(format!("cluster/backup: {e}")),
    }

    // ── 4. Audit log → logs table (incremental) ──────────────────
    let cursor_epoch: i64 = config
        .cursor_last_log_time
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    match pve_get(&client, base, &auth, "/api2/json/cluster/log?max=500").await {
        Ok(body) => {
            let entries = body
                .get("data")
                .and_then(|d| d.as_array())
                .cloned()
                .unwrap_or_default();
            let mut newest = cursor_epoch;
            for ev in &entries {
                let ts = ev.get("time").and_then(|v| v.as_i64()).unwrap_or(0);
                if ts <= cursor_epoch {
                    continue;
                }
                if ts > newest {
                    newest = ts;
                }
                let host = ev.get("node").and_then(|v| v.as_str()).unwrap_or("proxmox");
                let iso = chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
                if store
                    .insert_log("proxmox.audit", host, ev, &iso)
                    .await
                    .is_ok()
                {
                    result.audit_events_ingested += 1;
                }
            }
            if newest > cursor_epoch {
                result.cursor_last_log_time = Some(newest.to_string());
            }
        }
        Err(e) => result.errors.push(format!("cluster/log: {e}")),
    }

    tracing::info!(
        "PROXMOX SYNC: {} VMs, {} containers, {} nodes, {} assets, {} IPs, {} audit, {} findings",
        result.vms,
        result.containers,
        result.nodes,
        result.assets_resolved,
        result.ips_enriched,
        result.audit_events_ingested,
        result.findings_created
    );

    result
}

async fn pve_get(
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

/// Extract the first routable (non-loopback, non-link-local) IPv4 from
/// a `network-get-interfaces` response. Returns None when only
/// 127.0.0.1, 169.254.x or fe80:: are reported (= QGA is up but VM has
/// no real network yet).
fn first_routable_ip(body: &serde_json::Value) -> Option<String> {
    let result = body.get("data").and_then(|d| d.get("result"))?;
    for iface in result.as_array()? {
        let name = iface.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name == "lo" || name.starts_with("docker") || name.starts_with("veth") {
            continue;
        }
        let addrs = iface
            .get("ip-addresses")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        for addr in &addrs {
            let ip = addr
                .get("ip-address")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ty = addr
                .get("ip-address-type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if ty != "ipv4" {
                continue;
            }
            if ip.starts_with("127.") || ip.starts_with("169.254.") || ip.is_empty() {
                continue;
            }
            return Some(ip.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_header_format() {
        let h = format!("PVEAPIToken={}={}", "tc@pam!token", "secret123");
        assert_eq!(h, "PVEAPIToken=tc@pam!token=secret123");
    }

    #[test]
    fn first_ip_skips_loopback_and_link_local() {
        let body = serde_json::json!({
            "data": {
                "result": [
                    {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
                    {"name": "eth0", "ip-addresses": [
                        {"ip-address": "169.254.1.5", "ip-address-type": "ipv4"},
                        {"ip-address": "10.77.0.42", "ip-address-type": "ipv4"}
                    ]}
                ]
            }
        });
        assert_eq!(first_routable_ip(&body).as_deref(), Some("10.77.0.42"));
    }

    #[test]
    fn first_ip_returns_none_when_no_real_network() {
        let body = serde_json::json!({
            "data": {
                "result": [
                    {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]}
                ]
            }
        });
        assert!(first_routable_ip(&body).is_none());
    }
}
