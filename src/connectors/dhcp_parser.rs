#![allow(unused_imports)]
//! DHCP Log Parser — extract MAC-IP-hostname mappings from DHCP logs.
//!
//! Parses ISC dhcpd syslog format (the most common DHCP server on Linux).
//! Also handles dnsmasq format (OpenWrt, Pi-hole).
//! Creates/updates assets from discovered devices.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLease {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DhcpSyncResult {
    pub leases_parsed: usize,
    pub assets_created: usize,
    pub errors: Vec<String>,
}

/// Parse DHCP leases from syslog entries and create/update assets.
/// Called when new logs with tag "syslog.*.dhcp" arrive.
pub async fn process_dhcp_logs(store: &dyn Database) -> DhcpSyncResult {
    let mut result = DhcpSyncResult {
        leases_parsed: 0, assets_created: 0, errors: vec![],
    };

    // Query recent DHCP logs (last 60 min)
    let logs = store.query_logs(60, None, Some("dhcp"), 500).await.unwrap_or_default();

    let mut seen_macs = std::collections::HashSet::new();

    for log in &logs {
        let msg = log.data["message"].as_str().unwrap_or("");

        // Parse ISC dhcpd format: "DHCPACK on 192.168.1.50 to 00:1a:2b:3c:4d:5e (hostname) via eth0"
        if let Some(lease) = parse_dhcpd_line(msg) {
            if seen_macs.contains(&lease.mac) { continue; }
            seen_macs.insert(lease.mac.clone());
            result.leases_parsed += 1;

            let discovered = crate::graph::asset_resolution::DiscoveredAsset {
                mac: Some(lease.mac.clone()),
                hostname: lease.hostname.clone(),
                fqdn: None,
                ip: Some(lease.ip.clone()),
                os: None,
                ports: None,
                services: serde_json::json!([]),
                ou: None,
                vlan: None,
                vm_id: None,
                criticality: Some("low".into()),
                source: "dhcp".into(),
            };
            let res = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
            tracing::debug!("DHCP ASSET: {} → {:?} ({})", lease.mac, res.action, res.asset_id);
            result.assets_created += 1;
        }

        // Parse dnsmasq format: "dnsmasq-dhcp: DHCPACK(eth0) 192.168.1.50 00:1a:2b:3c:4d:5e hostname"
        if let Some(lease) = parse_dnsmasq_line(msg) {
            if seen_macs.contains(&lease.mac) { continue; }
            seen_macs.insert(lease.mac.clone());
            result.leases_parsed += 1;

            let discovered = crate::graph::asset_resolution::DiscoveredAsset {
                mac: Some(lease.mac.clone()),
                hostname: lease.hostname.clone(),
                fqdn: None,
                ip: Some(lease.ip.clone()),
                os: None,
                ports: None,
                services: serde_json::json!([]),
                ou: None,
                vlan: None,
                vm_id: None,
                criticality: Some("low".into()),
                source: "dhcp".into(),
            };
            let res = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
            tracing::debug!("DHCP ASSET (dnsmasq): {} → {:?}", lease.mac, res.action);
            result.assets_created += 1;
        }
    }

    if result.leases_parsed > 0 {
        tracing::info!("DHCP: {} leases parsed, {} assets created", result.leases_parsed, result.assets_created);
    }

    result
}

/// Parse ISC dhcpd log line.
/// Format: "DHCPACK on 192.168.1.50 to 00:1a:2b:3c:4d:5e (hostname) via eth0"
fn parse_dhcpd_line(line: &str) -> Option<DhcpLease> {
    if !line.contains("DHCPACK") && !line.contains("DHCPOFFER") { return None; }

    // Extract IP (after "on " or after "DHCPACK ")
    let ip = line.split(" on ").nth(1)
        .or_else(|| line.split("DHCPACK ").nth(1))
        .and_then(|s| s.split_whitespace().next())
        .map(|s| s.trim().to_string())?;

    // Extract MAC (after "to ")
    let mac = line.split(" to ").nth(1)
        .and_then(|s| s.split_whitespace().next())
        .map(|s| s.trim().to_string())?;

    // Extract hostname (in parentheses)
    let hostname = line.split('(').nth(1)
        .and_then(|s| s.split(')').next())
        .filter(|s| !s.is_empty() && !s.contains("via"))
        .map(|s| s.to_string());

    Some(DhcpLease { mac, ip, hostname })
}

/// Parse dnsmasq DHCP log line.
/// Format: "dnsmasq-dhcp: DHCPACK(eth0) 192.168.1.50 00:1a:2b:3c:4d:5e hostname"
fn parse_dnsmasq_line(line: &str) -> Option<DhcpLease> {
    if !line.contains("dnsmasq-dhcp") || !line.contains("DHCPACK") { return None; }

    let after_ack = line.split("DHCPACK").nth(1)?;
    // Skip the (interface) part
    let after_iface = after_ack.split(')').nth(1)?;
    let parts: Vec<&str> = after_iface.split_whitespace().collect();
    if parts.len() < 2 { return None; }

    let ip = parts[0].to_string();
    let mac = parts[1].to_string();
    let hostname = parts.get(2).filter(|s| !s.is_empty() && **s != "*").map(|s| s.to_string());

    Some(DhcpLease { mac, ip, hostname })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dhcpd() {
        let line = "DHCPACK on 192.168.1.50 to 00:1a:2b:3c:4d:5e (laptop-jean) via eth0";
        let lease = parse_dhcpd_line(line).unwrap();
        assert_eq!(lease.ip, "192.168.1.50");
        assert_eq!(lease.mac, "00:1a:2b:3c:4d:5e");
        assert_eq!(lease.hostname, Some("laptop-jean".into()));
    }

    #[test]
    fn test_parse_dnsmasq() {
        let line = "dnsmasq-dhcp: DHCPACK(eth0) 192.168.1.50 00:1a:2b:3c:4d:5e PC-COMPTA";
        let lease = parse_dnsmasq_line(line).unwrap();
        assert_eq!(lease.ip, "192.168.1.50");
        assert_eq!(lease.mac, "00:1a:2b:3c:4d:5e");
        assert_eq!(lease.hostname, Some("PC-COMPTA".into()));
    }

    #[test]
    fn test_no_hostname() {
        let line = "DHCPACK on 10.0.0.5 to aa:bb:cc:dd:ee:ff via br0";
        let lease = parse_dhcpd_line(line).unwrap();
        assert_eq!(lease.ip, "10.0.0.5");
        assert!(lease.hostname.is_none());
    }
}
