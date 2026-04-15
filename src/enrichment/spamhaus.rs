//! Spamhaus DNSBL — check if an IP is blacklisted (spam, botnet, hijacked).
//!
//! Method: DNS A record query (NOT HTTP).
//! Query: reverse IP octets + ".zen.spamhaus.org"
//! Example: check 1.2.3.4 → query "4.3.2.1.zen.spamhaus.org"
//!
//! Response codes:
//!   NXDOMAIN = clean
//!   127.0.0.2 = SBL (spam source)
//!   127.0.0.3 = SBL CSS (snowshoe spam)
//!   127.0.0.4 = XBL CBL (exploited/botnet)
//!   127.0.0.9 = DROP/EDROP (hijacked IP space)
//!   127.0.0.10-11 = PBL (dynamic/residential)
//!   127.255.255.x = ERROR (resolver blocked)
//!
//! IMPORTANT: Public DNS resolvers (8.8.8.8, 1.1.1.1) are BLOCKED.
//! Must use the local system resolver.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamhausResult {
    pub ip: String,
    pub is_listed: bool,
    pub listings: Vec<SpamhausListing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamhausListing {
    pub code: String,
    pub list: String,
    pub description: String,
    pub severity: String,
}

/// Check an IP against Spamhaus ZEN (SBL + XBL + PBL combined).
pub async fn check_ip(ip: &str) -> Result<SpamhausResult, String> {
    let addr = Ipv4Addr::from_str(ip).map_err(|_| format!("Invalid IPv4 address: {}", ip))?;

    let octets = addr.octets();
    let reversed = format!(
        "{}.{}.{}.{}.zen.spamhaus.org",
        octets[3], octets[2], octets[1], octets[0]
    );

    // Use tokio DNS resolution (system resolver)
    let lookup = tokio::net::lookup_host(format!("{}:0", reversed)).await;

    match lookup {
        Err(_) => {
            // NXDOMAIN or resolution failure = not listed (clean)
            Ok(SpamhausResult {
                ip: ip.to_string(),
                is_listed: false,
                listings: vec![],
            })
        }
        Ok(addrs) => {
            let mut listings = Vec::new();

            for addr in addrs {
                if let std::net::SocketAddr::V4(v4) = addr {
                    let result_ip = v4.ip();
                    let octets = result_ip.octets();
                    let code = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);

                    // Check for error codes (resolver blocked)
                    if octets[0] == 127 && octets[1] == 255 {
                        return Err("Spamhaus: DNS resolver is blocked. Use a local resolver, not public DNS.".into());
                    }

                    if let Some(listing) = classify_code(octets[3]) {
                        listings.push(SpamhausListing {
                            code: code.clone(),
                            list: listing.0.to_string(),
                            description: listing.1.to_string(),
                            severity: listing.2.to_string(),
                        });
                    }
                }
            }

            Ok(SpamhausResult {
                ip: ip.to_string(),
                is_listed: !listings.is_empty(),
                listings,
            })
        }
    }
}

fn classify_code(last_octet: u8) -> Option<(&'static str, &'static str, &'static str)> {
    match last_octet {
        2 => Some(("SBL", "Known spam source", "high")),
        3 => Some(("SBL CSS", "Snowshoe spammer", "high")),
        4 => Some(("XBL CBL", "Exploited machine / botnet", "critical")),
        5 => Some(("XBL CBL", "Exploited machine / botnet", "critical")),
        6 => Some(("XBL CBL", "Exploited machine / botnet", "critical")),
        7 => Some(("XBL CBL", "Exploited machine / botnet", "critical")),
        9 => Some(("DROP", "Hijacked IP space", "critical")),
        10 => Some(("PBL ISP", "Dynamic / residential IP", "low")),
        11 => Some(("PBL Spamhaus", "Dynamic / residential IP", "low")),
        _ => None,
    }
}

/// Check if an IP is on a specific Spamhaus list (sbl, xbl, pbl).
pub async fn check_ip_list(ip: &str, list: &str) -> Result<bool, String> {
    let addr = Ipv4Addr::from_str(ip).map_err(|_| format!("Invalid IPv4 address: {}", ip))?;

    let octets = addr.octets();
    let query = format!(
        "{}.{}.{}.{}.{}.spamhaus.org",
        octets[3], octets[2], octets[1], octets[0], list
    );

    match tokio::net::lookup_host(format!("{}:0", query)).await {
        Err(_) => Ok(false), // Not listed
        Ok(mut addrs) => {
            // Listed if we get any valid response (not error codes)
            if let Some(std::net::SocketAddr::V4(v4)) = addrs.next() {
                let o = v4.ip().octets();
                if o[0] == 127 && o[1] == 255 {
                    return Err("Spamhaus: DNS resolver blocked".into());
                }
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_codes() {
        assert!(classify_code(2).is_some());
        assert_eq!(classify_code(2).unwrap().0, "SBL");
        assert_eq!(classify_code(4).unwrap().0, "XBL CBL");
        assert_eq!(classify_code(9).unwrap().0, "DROP");
        assert_eq!(classify_code(10).unwrap().0, "PBL ISP");
        assert!(classify_code(0).is_none());
        assert!(classify_code(255).is_none());
    }

    #[test]
    fn test_invalid_ip() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(check_ip("not-an-ip"));
        assert!(result.is_err());
    }
}
