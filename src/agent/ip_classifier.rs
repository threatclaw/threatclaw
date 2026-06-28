//! IP Classifier — determines if an IP is internal known, internal unknown, or external.
//!
//! Uses the client's declared internal networks to classify any IP seen in alerts/logs.
//! Internal unknown IPs get auto-created as "unknown" assets for investigation.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

// IPv6 helpers (prefix masks on the first 16-bit segment).
const V6_LINK_LOCAL_MASK: u16 = 0xffc0; // fe80::/10
const V6_LINK_LOCAL: u16 = 0xfe80;
const V6_ULA_MASK: u16 = 0xfe00; // fc00::/7 (unique local — the IPv6 "private")
const V6_ULA: u16 = 0xfc00;

/// Classification result for an IP address.
#[derive(Debug, Clone, PartialEq)]
pub enum IpClass {
    /// IP belongs to a known asset
    InternalKnown(String), // asset_id
    /// IP is in an internal network but not a known asset
    InternalUnknown,
    /// IP is external (internet)
    External,
    /// IP is a special address (loopback, multicast, etc.)
    Special,
}

/// A parsed CIDR network range.
#[derive(Debug, Clone)]
pub struct NetworkRange {
    pub addr: u32,
    pub mask: u32,
    pub label: String,
    pub zone: String,
}

impl NetworkRange {
    /// Parse a CIDR string like "192.168.1.0/24"
    pub fn from_cidr(cidr: &str, label: &str, zone: &str) -> Option<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        let addr = Ipv4Addr::from_str(parts[0]).ok()?;
        let prefix: u32 = parts[1].parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        let addr_u32 = u32::from(addr);
        Some(Self {
            addr: addr_u32 & mask,
            mask,
            label: label.to_string(),
            zone: zone.to_string(),
        })
    }

    /// Check if an IPv4 address is within this range.
    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        let ip_u32 = u32::from(*ip);
        (ip_u32 & self.mask) == self.addr
    }
}

/// Check if an IP is in any of the declared internal networks.
pub fn is_internal(ip: &str, networks: &[NetworkRange]) -> bool {
    if let Ok(IpAddr::V4(v4)) = IpAddr::from_str(ip) {
        networks.iter().any(|n| n.contains(&v4))
    } else {
        false
    }
}

/// Check if an IP is a private address (RFC 1918 for v4, ULA fc00::/7 for v6),
/// even if not in the declared networks.
pub fn is_private(ip: &str) -> bool {
    match IpAddr::from_str(ip) {
        Ok(IpAddr::V4(v4)) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            false
        }
        // IPv6 unique-local addresses fc00::/7 are the v6 equivalent of RFC1918.
        Ok(IpAddr::V6(v6)) => (v6.segments()[0] & V6_ULA_MASK) == V6_ULA,
        Err(_) => false,
    }
}

/// Check if an IP is special (loopback, multicast, link-local, unspecified).
pub fn is_special(ip: &str) -> bool {
    match IpAddr::from_str(ip) {
        Ok(IpAddr::V4(v4)) => {
            let octets = v4.octets();
            // Loopback 127.0.0.0/8
            if octets[0] == 127 {
                return true;
            }
            // Link-local 169.254.0.0/16
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // Multicast 224.0.0.0/4
            if octets[0] >= 224 {
                return true;
            }
            // Broadcast
            if v4 == Ipv4Addr::BROADCAST {
                return true;
            }
            false
        }
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback()       // ::1
                || v6.is_unspecified() // ::
                || v6.is_multicast()   // ff00::/8
                || (v6.segments()[0] & V6_LINK_LOCAL_MASK) == V6_LINK_LOCAL // fe80::/10
        }
        Err(_) => false,
    }
}

// See ADR-031: single source of truth for IP classification
pub fn is_non_routable(ip: &str) -> bool {
    is_private(ip) || is_special(ip)
}

/// Classify an IP address.
pub fn classify(ip: &str, networks: &[NetworkRange], known_asset_ips: &[String]) -> IpClass {
    if is_special(ip) {
        return IpClass::Special;
    }

    // Check if it matches a known asset
    if let Some(asset_ip) = known_asset_ips.iter().find(|a| a.as_str() == ip) {
        return IpClass::InternalKnown(asset_ip.clone());
    }

    // Check if it's in declared internal networks
    if is_internal(ip, networks) {
        return IpClass::InternalUnknown;
    }

    // Check if it's a private IP (even if not in declared networks — still internal)
    if is_private(ip) {
        return IpClass::InternalUnknown;
    }

    IpClass::External
}

/// Whether an IP observed as a syslog `host` value should be auto-enrolled as an
/// asset. A WAN-facing firewall logs thousands of public scanner IPs; enrolling
/// them creates billable junk assets (and they keep coming back every sigma
/// cycle). Only internal IPs (declared networks, RFC1918/ULA, or a known asset)
/// are enrollable — External and special addresses are dropped.
pub fn ip_is_enrollable(ip: &str, networks: &[NetworkRange], known_asset_ips: &[String]) -> bool {
    !matches!(
        classify(ip, networks, known_asset_ips),
        IpClass::External | IpClass::Special
    )
}

/// Extract source and destination IPs from a sigma alert or log entry.
/// Never falls back to `hostname` — hostname is a victim label, not an IP,
/// and coercing it into an IP slot produces invalid graph/classifier inputs.
pub fn extract_ips_from_alert(alert: &serde_json::Value) -> (Option<String>, Option<String>) {
    let source_ip = alert["source_ip"]
        .as_str()
        .or_else(|| alert["src_ip"].as_str())
        .or_else(|| alert["data"]["source_ip"].as_str())
        .map(|s| s.split('/').next().unwrap_or(s).to_string());

    let dest_ip = alert["dest_ip"]
        .as_str()
        .or_else(|| alert["dst_ip"].as_str())
        .or_else(|| alert["data"]["dest_ip"].as_str())
        .map(|s| s.split('/').next().unwrap_or(s).to_string());

    (source_ip, dest_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_range_parse() {
        let nr = NetworkRange::from_cidr("192.168.1.0/24", "LAN", "lan").unwrap();
        assert!(nr.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(nr.contains(&Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!nr.contains(&Ipv4Addr::new(192, 168, 2, 1)));
        assert!(!nr.contains(&Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_is_private() {
        assert!(is_private("192.168.1.1"));
        assert!(is_private("10.0.0.1"));
        assert!(is_private("172.16.0.1"));
        assert!(is_private("172.31.255.255"));
        assert!(!is_private("8.8.8.8"));
        assert!(!is_private("185.220.101.42"));
        assert!(!is_private("172.32.0.1"));
    }

    #[test]
    fn test_is_special() {
        assert!(is_special("127.0.0.1"));
        assert!(is_special("169.254.1.1"));
        assert!(is_special("224.0.0.1"));
        assert!(!is_special("192.168.1.1"));
    }

    #[test]
    fn test_classify() {
        let networks = vec![NetworkRange::from_cidr("192.168.1.0/24", "LAN", "lan").unwrap()];
        let known = vec!["192.168.1.10".to_string()];

        assert_eq!(
            classify("192.168.1.10", &networks, &known),
            IpClass::InternalKnown("192.168.1.10".into())
        );
        assert_eq!(
            classify("192.168.1.200", &networks, &known),
            IpClass::InternalUnknown
        );
        assert_eq!(
            classify("185.220.101.42", &networks, &known),
            IpClass::External
        );
        assert_eq!(classify("127.0.0.1", &networks, &known), IpClass::Special);
        // Private IP not in declared networks — still internal unknown
        assert_eq!(
            classify("10.0.0.50", &networks, &known),
            IpClass::InternalUnknown
        );
    }

    #[test]
    fn ipv6_special_and_private() {
        // special
        assert!(is_special("::1")); // loopback
        assert!(is_special("::")); // unspecified
        assert!(is_special("fe80::1")); // link-local
        assert!(is_special("ff02::1")); // multicast
        assert!(!is_special("2001:4860:4860::8888")); // public (Google DNS)
        // private (ULA)
        assert!(is_private("fc00::1"));
        assert!(is_private("fd12:3456:789a::1"));
        assert!(!is_private("2001:4860:4860::8888"));
        // classify
        let nets: Vec<NetworkRange> = vec![];
        assert_eq!(
            classify("2606:4700:4700::1111", &nets, &[]),
            IpClass::External
        );
        assert_eq!(classify("fc00::1", &nets, &[]), IpClass::InternalUnknown);
        assert_eq!(classify("::1", &nets, &[]), IpClass::Special);
    }

    #[test]
    fn enrollable_drops_public_and_special() {
        let nets: Vec<NetworkRange> = vec![];
        let known: Vec<String> = vec![];
        // public scanner IPs (the #9 billing-pollution case) — never enroll
        assert!(!ip_is_enrollable("185.220.101.42", &nets, &known));
        assert!(!ip_is_enrollable("2606:4700:4700::1111", &nets, &known));
        // special — never enroll
        assert!(!ip_is_enrollable("127.0.0.1", &nets, &known));
        assert!(!ip_is_enrollable("::1", &nets, &known));
        assert!(!ip_is_enrollable("ff02::1", &nets, &known));
        // genuinely internal — still enroll
        assert!(ip_is_enrollable("10.0.0.5", &nets, &known));
        assert!(ip_is_enrollable("fc00::5", &nets, &known));
        // declared-network IP — enroll
        let nets2 = vec![NetworkRange::from_cidr("203.0.113.0/24", "DMZ", "dmz").unwrap()];
        assert!(ip_is_enrollable("203.0.113.7", &nets2, &known));
    }
}
