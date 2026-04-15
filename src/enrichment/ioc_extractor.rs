//! IoC Extractor — extracts Indicators of Compromise from raw log data.
//!
//! Scans log JSONB fields for:
//! - IP addresses (IPv4)
//! - URLs (http/https)
//! - File hashes (SHA-256, MD5)
//! - Domain names
//!
//! Used by the Intelligence Engine to cross-reference with enrichment sources.

use std::collections::HashSet;

/// Extracted IoCs from a set of logs.
#[derive(Debug, Default)]
pub struct ExtractedIocs {
    pub ips: HashSet<String>,
    pub urls: HashSet<String>,
    pub hashes: HashSet<String>,
    pub domains: HashSet<String>,
}

/// Extract IoCs from a JSON log payload.
pub fn extract_from_json(data: &serde_json::Value) -> ExtractedIocs {
    let mut iocs = ExtractedIocs::default();
    let text = data.to_string();
    extract_from_text(&text, &mut iocs);
    iocs
}

/// Extract IoCs from a batch of log records.
pub fn extract_from_logs(logs: &[crate::db::threatclaw_store::LogRecord]) -> ExtractedIocs {
    let mut iocs = ExtractedIocs::default();
    for log in logs {
        let text = log.data.to_string();
        extract_from_text(&text, &mut iocs);
    }

    // Filter out private/local IPs
    iocs.ips.retain(|ip| !is_private_ip(ip));

    iocs
}

/// Extract IoCs from raw text.
fn extract_from_text(text: &str, iocs: &mut ExtractedIocs) {
    // Extract IPv4 addresses
    let mut i = 0;
    let chars: Vec<char> = text.chars().collect();
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            if let Some((ip, end)) = try_parse_ipv4(&chars, i) {
                iocs.ips.insert(ip);
                i = end;
                continue;
            }
        }
        i += 1;
    }

    // Extract URLs
    for prefix in &["http://", "https://"] {
        let mut pos = 0;
        while let Some(start) = text[pos..].find(prefix) {
            let abs_start = pos + start;
            let url_end = text[abs_start..]
                .find(|c: char| {
                    c.is_whitespace() || c == '"' || c == '\'' || c == '>' || c == ')' || c == ']'
                })
                .map(|e| abs_start + e)
                .unwrap_or(text.len());
            let url = &text[abs_start..url_end];
            if url.len() > 10 {
                // Minimum http://x.xx
                iocs.urls.insert(url.to_string());
                // Extract domain from URL
                if let Some(domain) = extract_domain_from_url(url) {
                    iocs.domains.insert(domain);
                }
            }
            pos = url_end;
        }
    }

    // Extract SHA-256 hashes (64 hex chars)
    for word in text.split(|c: char| !c.is_ascii_hexdigit()) {
        if word.len() == 64 && word.chars().all(|c| c.is_ascii_hexdigit()) {
            iocs.hashes.insert(word.to_lowercase());
        }
        // MD5 (32 hex chars)
        if word.len() == 32 && word.chars().all(|c| c.is_ascii_hexdigit()) {
            iocs.hashes.insert(word.to_lowercase());
        }
    }
}

/// Try to parse an IPv4 address starting at position i.
fn try_parse_ipv4(chars: &[char], start: usize) -> Option<(String, usize)> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut i = start;

    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            current.push(chars[i]);
            if current.len() > 3 {
                return None;
            }
        } else if chars[i] == '.' && !current.is_empty() {
            if let Ok(n) = current.parse::<u16>() {
                if n > 255 {
                    return None;
                }
                parts.push(n);
                current.clear();
            } else {
                return None;
            }
        } else {
            break;
        }
        i += 1;
    }

    if !current.is_empty() {
        if let Ok(n) = current.parse::<u16>() {
            if n <= 255 {
                parts.push(n);
            }
        }
    }

    if parts.len() == 4 {
        let ip = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], parts[3]);
        Some((ip, i))
    } else {
        None
    }
}

/// Extract domain from a URL.
fn extract_domain_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let domain = without_scheme.split('/').next()?;
    let domain = domain.split(':').next()?; // Remove port
    if domain.contains('.') && domain.len() > 3 {
        Some(domain.to_lowercase())
    } else {
        None
    }
}

/// Check if an IP is private/local (should not be enriched externally).
fn is_private_ip(ip: &str) -> bool {
    crate::agent::ip_classifier::is_non_routable(ip)
        || ip.starts_with("0.")
        || ip == "255.255.255.255"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ips() {
        let mut iocs = ExtractedIocs::default();
        extract_from_text(
            "Failed login from 185.220.101.42 to 192.168.1.107",
            &mut iocs,
        );
        assert!(iocs.ips.contains("185.220.101.42"));
        // 192.168.1.107 is private, will be filtered in extract_from_logs
    }

    #[test]
    fn test_extract_urls() {
        let mut iocs = ExtractedIocs::default();
        extract_from_text(
            "Downloading from https://evil.com/malware.exe and http://bad.org/payload",
            &mut iocs,
        );
        assert!(iocs.urls.contains("https://evil.com/malware.exe"));
        assert!(iocs.urls.contains("http://bad.org/payload"));
        assert!(iocs.domains.contains("evil.com"));
        assert!(iocs.domains.contains("bad.org"));
    }

    #[test]
    fn test_extract_hash() {
        let mut iocs = ExtractedIocs::default();
        extract_from_text(
            "Hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            &mut iocs,
        );
        assert_eq!(iocs.hashes.len(), 1);
    }

    #[test]
    fn test_private_ip_filter() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("185.220.101.42"));
    }
}
