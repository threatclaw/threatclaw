//! Nmap Network Discovery — runs nmap and feeds results into Asset Resolution.
//!
//! Executes nmap via tokio::process (or Docker), parses XML output,
//! and creates DiscoveredAsset entries for each host found.
//!
//! This is a "tool" skill — ThreatClaw runs nmap itself.

use crate::db::Database;
use crate::graph::asset_resolution::{self, DiscoveredAsset};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::process::Command;

/// Nmap scan configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapConfig {
    /// Target subnets (e.g., "192.168.1.0/24" or "10.0.0.0/24,192.168.2.0/24")
    pub targets: String,
    /// Number of top ports to scan (default: 1000)
    #[serde(default = "default_top_ports")]
    pub top_ports: u16,
    /// Timing template (T1-T5, default: T3)
    #[serde(default = "default_timing")]
    pub timing: String,
    /// Run via Docker instead of local nmap binary
    #[serde(default)]
    pub use_docker: bool,
}

fn default_top_ports() -> u16 { 1000 }
fn default_timing() -> String { "T3".into() }

/// Result of a nmap discovery scan.
#[derive(Debug, Clone, Serialize)]
pub struct NmapScanResult {
    pub hosts_discovered: usize,
    pub assets_resolved: usize,
    pub open_ports_total: usize,
    pub scan_duration_secs: u64,
    pub errors: Vec<String>,
}

/// Run nmap discovery scan and feed results into Asset Resolution Pipeline.
pub async fn run_discovery(store: &dyn Database, config: &NmapConfig) -> NmapScanResult {
    let start = std::time::Instant::now();
    let mut result = NmapScanResult {
        hosts_discovered: 0, assets_resolved: 0, open_ports_total: 0,
        scan_duration_secs: 0, errors: vec![],
    };

    tracing::info!("NMAP: Starting discovery scan on {}", config.targets);

    // Validate timing template (prevent injection via -T flag)
    let valid_timings = ["T0", "T1", "T2", "T3", "T4", "T5"];
    let timing = if valid_timings.contains(&config.timing.as_str()) {
        config.timing.clone()
    } else {
        tracing::warn!("NMAP: Invalid timing '{}', falling back to T3", config.timing);
        "T3".to_string()
    };

    // Validate targets (prevent injection)
    if !validate_targets(&config.targets) {
        result.errors.push("Invalid target format".into());
        return result;
    }

    // Build nmap command with validated timing
    let mut safe_config = config.clone();
    safe_config.timing = timing;
    let xml_output = if safe_config.use_docker {
        run_nmap_docker(&safe_config).await
    } else {
        run_nmap_local(&safe_config).await
    };

    let xml = match xml_output {
        Ok(xml) => xml,
        Err(e) => {
            result.errors.push(format!("Nmap execution failed: {}", e));
            tracing::error!("NMAP: Execution failed: {}", e);
            return result;
        }
    };

    // Parse XML output
    let hosts = parse_nmap_xml(&xml);
    result.hosts_discovered = hosts.len();

    tracing::info!("NMAP: {} hosts discovered, feeding into Asset Resolution", hosts.len());

    // Feed each host into the Asset Resolution Pipeline
    for host in &hosts {
        let ports: Vec<u16> = host.ports.iter().map(|p| p.port).collect();
        result.open_ports_total += ports.len();

        let discovered = DiscoveredAsset {
            mac: host.mac.clone(),
            hostname: host.hostname.clone(),
            fqdn: None,
            ip: Some(host.ip.clone()),
            os: host.os.clone(),
            ports: if ports.is_empty() { None } else { Some(ports) },
            ou: None,
            vlan: None,
            vm_id: None,
            criticality: None,
            source: "nmap".into(),
        };

        let resolution = asset_resolution::resolve_asset(store, &discovered).await;
        result.assets_resolved += 1;

        tracing::debug!("NMAP: {} → {} ({:?})", host.ip,
            resolution.asset_id, resolution.action);
    }

    result.scan_duration_secs = start.elapsed().as_secs();
    tracing::info!(
        "NMAP COMPLETE: {} hosts, {} assets resolved, {} open ports, {}s",
        result.hosts_discovered, result.assets_resolved,
        result.open_ports_total, result.scan_duration_secs
    );

    result
}

/// Run nmap locally (nmap must be installed).
async fn run_nmap_local(config: &NmapConfig) -> Result<String, String> {
    let output = Command::new("nmap")
        .args([
            "-sV",
            "--top-ports", &config.top_ports.to_string(),
            &format!("-{}", config.timing),
            "--open",
            "-oX", "-",  // XML output to stdout
        ])
        .args(config.targets.split(',').map(|t| t.trim()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Failed to execute nmap: {}. Is nmap installed?", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nmap exited with {}: {}", output.status, stderr));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| format!("nmap output is not valid UTF-8: {}", e))
}

/// Run nmap via Docker.
async fn run_nmap_docker(config: &NmapConfig) -> Result<String, String> {
    let output = Command::new("docker")
        .args([
            "run", "--rm", "--network", "host",
            "instrumentisto/nmap:latest",
            "-sV",
            "--top-ports", &config.top_ports.to_string(),
            &format!("-{}", config.timing),
            "--open",
            "-oX", "-",
        ])
        .args(config.targets.split(',').map(|t| t.trim()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("Docker nmap failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Docker nmap exited with {}: {}", output.status, stderr));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| format!("Docker nmap output not UTF-8: {}", e))
}

/// Validate target string to prevent command injection.
fn validate_targets(targets: &str) -> bool {
    // Only allow: digits, dots, slashes, commas, colons (IPv6), spaces, hyphens
    targets.chars().all(|c|
        c.is_ascii_digit() || c == '.' || c == '/' || c == ',' || c == ':' || c == ' ' || c == '-'
    ) && !targets.is_empty()
}

/// Parsed nmap host.
#[derive(Debug, Clone)]
struct NmapHost {
    ip: String,
    mac: Option<String>,
    hostname: Option<String>,
    os: Option<String>,
    ports: Vec<NmapPort>,
}

#[derive(Debug, Clone)]
struct NmapPort {
    port: u16,
    protocol: String,
    service: String,
}

/// Parse nmap XML output into structured hosts.
/// Handles the standard nmap -oX format.
fn parse_nmap_xml(xml: &str) -> Vec<NmapHost> {
    let mut hosts = vec![];
    let mut current_host: Option<NmapHost> = None;

    for line in xml.lines() {
        let trimmed = line.trim();

        // Host start — match <host ...> but NOT <hostname
        if (trimmed.starts_with("<host ") || trimmed.starts_with("<host>"))
            && !trimmed.starts_with("<hostname")
            && !trimmed.starts_with("<hostnames")
        {
            current_host = Some(NmapHost {
                ip: String::new(), mac: None, hostname: None, os: None, ports: vec![],
            });
        }

        // Skip down hosts
        if trimmed.contains("<status state=\"down\"") {
            current_host = None;
        }

        if let Some(ref mut host) = current_host {
            // IP address
            if trimmed.starts_with("<address ") && trimmed.contains("addrtype=\"ipv4\"") {
                if let Some(addr) = extract_attr(trimmed, "addr") {
                    host.ip = addr;
                }
            }

            // MAC address
            if trimmed.starts_with("<address ") && trimmed.contains("addrtype=\"mac\"") {
                host.mac = extract_attr(trimmed, "addr");
            }

            // Hostname (may be inside <hostnames> wrapper on same line)
            if trimmed.contains("<hostname ") {
                host.hostname = extract_attr(trimmed, "name");
            }

            // OS match (may be inside <os> wrapper on same line)
            if trimmed.contains("<osmatch ") {
                if host.os.is_none() {
                    host.os = extract_attr(
                        &trimmed[trimmed.find("<osmatch").unwrap_or(0)..],
                        "name",
                    );
                }
            }

            // Port (may have service on same line)
            if trimmed.contains("<port ") && trimmed.contains("portid=") {
                if let (Some(portid), Some(protocol)) = (extract_attr(trimmed, "portid"), extract_attr(trimmed, "protocol")) {
                    if let Ok(port_num) = portid.parse::<u16>() {
                        let service = if trimmed.contains("<service ") {
                            extract_attr(trimmed, "name").unwrap_or_default()
                        } else {
                            String::new()
                        };
                        host.ports.push(NmapPort { port: port_num, protocol, service });
                    }
                }
            } else if trimmed.contains("<service ") && !trimmed.contains("<port ") {
                // Service on separate line
                if let Some(name) = extract_attr(trimmed, "name") {
                    if let Some(last_port) = host.ports.last_mut() {
                        last_port.service = name;
                    }
                }
            }

            // Host end
            if trimmed == "</host>" {
                if !host.ip.is_empty() {
                    hosts.push(host.clone());
                }
                current_host = None;
            }
        }
    }

    hosts
}

/// Extract an XML attribute value from a tag line.
fn extract_attr(line: &str, attr: &str) -> Option<String> {
    let needle = format!("{}=\"", attr);
    if let Some(start) = line.find(&needle) {
        let value_start = start + needle.len();
        if let Some(end) = line[value_start..].find('"') {
            return Some(line[value_start..value_start + end].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_targets() {
        assert!(validate_targets("192.168.1.0/24"));
        assert!(validate_targets("10.0.0.0/8,192.168.1.0/24"));
        assert!(validate_targets("192.168.1.1-254"));
        assert!(!validate_targets(""));
        assert!(!validate_targets("192.168.1.0/24; rm -rf /"));
        assert!(!validate_targets("$(whoami)"));
    }

    #[test]
    fn test_extract_attr() {
        assert_eq!(extract_attr(r#"<address addr="192.168.1.1" addrtype="ipv4"/>"#, "addr"),
            Some("192.168.1.1".into()));
        assert_eq!(extract_attr(r#"<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>"#, "addr"),
            Some("AA:BB:CC:DD:EE:FF".into()));
        assert_eq!(extract_attr(r#"<hostname name="srv-web-01" type="PTR"/>"#, "name"),
            Some("srv-web-01".into()));
    }

    #[test]
    fn test_parse_nmap_xml() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
<host starttime="1711234567" endtime="1711234570"><status state="up"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Intel"/>
<hostnames><hostname name="srv-web-01" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports>
<os><osmatch name="Linux 5.x" accuracy="95"/></os>
</host>
<host starttime="1711234567" endtime="1711234570"><status state="up"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames><hostname name="gateway" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports>
</host>
</nmaprun>"#;

        let hosts = parse_nmap_xml(xml);
        assert_eq!(hosts.len(), 2);

        assert_eq!(hosts[0].ip, "192.168.1.10");
        assert_eq!(hosts[0].mac, Some("AA:BB:CC:DD:EE:FF".into()));
        assert_eq!(hosts[0].hostname, Some("srv-web-01".into()));
        assert_eq!(hosts[0].os, Some("Linux 5.x".into()));
        assert_eq!(hosts[0].ports.len(), 3);
        assert_eq!(hosts[0].ports[0].port, 22);
        assert_eq!(hosts[0].ports[0].service, "ssh");

        assert_eq!(hosts[1].ip, "192.168.1.1");
        assert_eq!(hosts[1].hostname, Some("gateway".into()));
        assert_eq!(hosts[1].mac, None); // Gateway didn't return MAC
    }
}
