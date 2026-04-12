//! MikroTik RouterOS Connector — import firewall logs and system status via REST API.
//!
//! Auth: Basic auth
//! REST API: GET /rest/... (RouterOS 7.1+)
//! Port: 443 (HTTPS by default)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MikroTikConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize)]
pub struct MikroTikSyncResult {
    pub log_entries: usize,
    pub dhcp_leases: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_mikrotik(store: &dyn Database, config: &MikroTikConfig) -> MikroTikSyncResult {
    let mut result = MikroTikSyncResult {
        log_entries: 0, dhcp_leases: 0, findings_created: 0, errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("HTTP client: {}", e)); return result; }
    };

    let url = config.url.trim_end_matches('/');
    tracing::info!("MIKROTIK: Connecting to {}", url);

    // Test connectivity with system resource
    let resource_resp = match client.get(format!("{}/rest/system/resource", url))
        .basic_auth(&config.username, Some(&config.password))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Connection: {}", e)); return result; }
    };

    if !resource_resp.status().is_success() {
        let status = resource_resp.status();
        result.errors.push(format!("Auth HTTP {} — check credentials and REST API is enabled (RouterOS 7.1+)", status));
        return result;
    }

    let resource: serde_json::Value = match resource_resp.json().await {
        Ok(d) => d,
        Err(e) => { result.errors.push(format!("Parse resource: {}", e)); return result; }
    };

    let board = resource["board-name"].as_str().unwrap_or("unknown");
    let version = resource["version"].as_str().unwrap_or("?");
    let cpu_load = resource["cpu-load"].as_u64().unwrap_or(0);
    let free_mem = resource["free-memory"].as_u64().unwrap_or(0);
    let total_mem = resource["total-memory"].as_u64().unwrap_or(1);

    tracing::info!("MIKROTIK: {} v{} — CPU {}%, MEM {}/{} MB",
        board, version, cpu_load, free_mem / 1048576, total_mem / 1048576);

    // High resource usage alert
    let mem_pct = if total_mem > 0 { ((total_mem - free_mem) * 100 / total_mem) as u32 } else { 0 };
    if cpu_load > 80 || mem_pct > 90 {
        let _ = store.insert_finding(&NewFinding {
            skill_id: "skill-mikrotik".into(),
            title: format!("[MikroTik] {} resource pressure — CPU {}%, MEM {}%", board, cpu_load, mem_pct),
            description: Some(format!("Board: {} v{}", board, version)),
            severity: "MEDIUM".into(),
            category: Some("network".into()),
            asset: Some(board.to_string()),
            source: Some("MikroTik RouterOS".into()),
            metadata: Some(serde_json::json!({
                "board": board,
                "version": version,
                "cpu_load": cpu_load,
                "mem_pct": mem_pct,
            })),
        }).await;
        result.findings_created += 1;
    }

    // Fetch firewall logs (topic=firewall)
    match client.get(format!("{}/rest/log", url))
        .basic_auth(&config.username, Some(&config.password))
        .query(&[(".proplist", "time,topics,message"), ("topics", "firewall")])
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(logs) = resp.json::<Vec<serde_json::Value>>().await {
                tracing::info!("MIKROTIK: {} firewall log entries", logs.len());
                result.log_entries = logs.len();

                // Count drops per source IP
                let mut drops: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
                for log in &logs {
                    let msg = log["message"].as_str().unwrap_or("");
                    // MikroTik firewall logs: "input: in:ether1 out:(unknown 0), src-mac xx:xx, proto TCP (SYN), 1.2.3.4:12345->192.168.1.1:22, len 60"
                    if msg.contains("input:") || msg.contains("forward:") {
                        // Extract source IP from the log message
                        if let Some(ip_part) = msg.split("->").next() {
                            if let Some(src) = ip_part.rsplit(", ").next() {
                                let src_ip = src.split(':').next().unwrap_or("");
                                if !src_ip.is_empty() {
                                    *drops.entry(src_ip.to_string()).or_insert(0) += 1;
                                }
                            }
                        }
                    }
                }

                // Report IPs with many drops
                for (ip, count) in &drops {
                    if *count >= 10 {
                        let _ = store.insert_sigma_alert(
                            "mikrotik-fw-drop",
                            if *count >= 50 { "HIGH" } else { "MEDIUM" },
                            &format!("MikroTik: {} firewall drops from {}", count, ip),
                            board,
                            Some(ip.as_str()),
                            None,
                        ).await;

                        if *count >= 50 {
                            let _ = store.insert_finding(&NewFinding {
                                skill_id: "skill-mikrotik".into(),
                                title: format!("[MikroTik] {} drops from {}", count, ip),
                                description: Some(format!("Firewall dropped {} packets from IP {}", count, ip)),
                                severity: "HIGH".into(),
                                category: Some("network".into()),
                                asset: Some(board.to_string()),
                                source: Some("MikroTik Firewall".into()),
                                metadata: Some(serde_json::json!({
                                    "source_ip": ip,
                                    "drop_count": count,
                                })),
                            }).await;
                            result.findings_created += 1;
                        }
                    }
                }
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("MIKROTIK: Firewall logs: {}", e);
        }
    }

    // Fetch DHCP leases for network discovery
    match client.get(format!("{}/rest/ip/dhcp-server/lease", url))
        .basic_auth(&config.username, Some(&config.password))
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(leases) = resp.json::<Vec<serde_json::Value>>().await {
                tracing::info!("MIKROTIK: {} DHCP leases", leases.len());
                result.dhcp_leases = leases.len();

                for lease in &leases {
                    let address = lease["address"].as_str().unwrap_or("");
                    let mac = lease["mac-address"].as_str().unwrap_or("");
                    let hostname = lease["host-name"].as_str().unwrap_or("");
                    let status = lease["status"].as_str().unwrap_or("");

                    if !address.is_empty() && status == "bound" {
                        // Feed into asset resolution
                        let discovered = crate::graph::asset_resolution::DiscoveredAsset {
                            mac: if mac.is_empty() { None } else { Some(mac.to_string()) },
                            hostname: if hostname.is_empty() { None } else { Some(hostname.to_string()) },
                            fqdn: None,
                            ip: Some(address.to_string()),
                            os: None,
                            ports: None,
                            services: serde_json::json!([]),
                            ou: None,
                            vlan: None,
                            vm_id: None,
                            criticality: None,
                            source: "mikrotik-dhcp".into(),
                        };
                        let _ = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
                    }
                }
            }
        }
        _ => {}
    }

    // Check active connections count
    match client.get(format!("{}/rest/ip/firewall/connection", url))
        .basic_auth(&config.username, Some(&config.password))
        .query(&[(".proplist", ".id")])
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(conns) = resp.json::<Vec<serde_json::Value>>().await {
                let count = conns.len();
                if count > 5000 {
                    let _ = store.insert_finding(&NewFinding {
                        skill_id: "skill-mikrotik".into(),
                        title: format!("[MikroTik] {} active connections — possible DDoS/scan", count),
                        description: Some(format!("Router {} has {} active connections in the connection table", board, count)),
                        severity: "MEDIUM".into(),
                        category: Some("network".into()),
                        asset: Some(board.to_string()),
                        source: Some("MikroTik RouterOS".into()),
                        metadata: Some(serde_json::json!({
                            "connection_count": count,
                        })),
                    }).await;
                    result.findings_created += 1;
                }
            }
        }
        _ => {}
    }

    tracing::info!("MIKROTIK: Sync done — {} logs, {} leases, {} findings",
        result.log_entries, result.dhcp_leases, result.findings_created);
    result
}
