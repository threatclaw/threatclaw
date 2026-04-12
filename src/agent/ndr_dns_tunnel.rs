//! DNS tunneling detection. See SESSION_2026-04-06.md P1.
//!
//! Detects data exfiltration and C2 communication over DNS by analyzing:
//! - Query volume per domain (>100 queries/h = suspect)
//! - Subdomain length (>50 chars = encoding likely)
//! - Subdomain entropy (high entropy = encoded data)
//! - TXT record abuse (bulk TXT = return channel)
//! - Fast flux (>10 IPs for same domain in <1h)
//!
//! Sources: zeek.dns and/or pihole logs.
//! MITRE: T1071.004 (Application Layer Protocol: DNS)

use std::collections::HashMap;
use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// Detection thresholds — tuned for PME (low traffic, high signal).
const VOLUME_THRESHOLD: usize = 100;        // >100 queries/h to same domain
const SUBDOMAIN_LEN_THRESHOLD: usize = 50;  // >50 chars = likely base32/base64 encoding
const ENTROPY_THRESHOLD: f64 = 3.5;         // Shannon entropy > 3.5 = encoded data
const TXT_VOLUME_THRESHOLD: usize = 20;     // >20 TXT queries to same domain/h
const FAST_FLUX_THRESHOLD: usize = 10;      // >10 distinct IPs for same domain
const MIN_SUBDOMAIN_LEN: usize = 8;         // Ignore short subdomains (normal)

/// Result of a DNS tunnel scan cycle.
#[derive(Debug)]
pub struct DnsTunnelResult {
    pub logs_checked: usize,
    pub tunnels_detected: usize,
    pub findings_created: usize,
}

/// A detected DNS tunnel candidate with evidence.
#[derive(Debug)]
struct TunnelCandidate {
    domain: String,
    src_ip: String,
    evidence: Vec<String>,
    severity: &'static str,
    query_count: usize,
    max_subdomain_len: usize,
    avg_entropy: f64,
    txt_count: usize,
    unique_ips: usize,
}

/// Scan recent DNS logs for tunneling indicators.
/// Sources: zeek.dns logs and pihole query logs.
pub async fn scan_dns_tunnels(
    store: std::sync::Arc<dyn Database>,
    minutes_back: i64,
) -> DnsTunnelResult {
    let mut result = DnsTunnelResult {
        logs_checked: 0, tunnels_detected: 0, findings_created: 0,
    };

    // Collect DNS logs from all available sources
    let mut all_queries: Vec<DnsQuery> = Vec::new();

    // Source 1: Zeek dns.log
    let zeek_logs = store.query_logs(minutes_back, None, Some("zeek.dns"), 5000)
        .await.unwrap_or_default();
    result.logs_checked += zeek_logs.len();

    for log in &zeek_logs {
        let query = log.data["query"].as_str().unwrap_or("");
        if query.is_empty() || query == "-" { continue; }
        let qtype = log.data["qtype_name"].as_str()
            .or_else(|| log.data["qtype"].as_str())
            .unwrap_or("");
        let src = log.data["id.orig_h"].as_str().unwrap_or("");
        // Answers can contain resolved IPs
        let answers = log.data["answers"].as_str().unwrap_or("")
            .split(',').filter(|s| !s.is_empty()).map(String::from).collect();

        all_queries.push(DnsQuery {
            domain: query.to_lowercase(),
            qtype: qtype.to_string(),
            src_ip: src.to_string(),
            answers,
        });
    }

    // Source 2: Pi-hole logs (if available)
    let pihole_logs = store.query_logs(minutes_back, None, Some("pihole"), 5000)
        .await.unwrap_or_default();
    result.logs_checked += pihole_logs.len();

    for log in &pihole_logs {
        let query = log.data["query"].as_str()
            .or_else(|| log.data["domain"].as_str())
            .unwrap_or("");
        if query.is_empty() { continue; }
        let src = log.data["client"].as_str()
            .or_else(|| log.data["src_ip"].as_str())
            .unwrap_or("");
        let qtype = log.data["type"].as_str().unwrap_or("");

        all_queries.push(DnsQuery {
            domain: query.to_lowercase(),
            qtype: qtype.to_string(),
            src_ip: src.to_string(),
            answers: Vec::new(),
        });
    }

    if all_queries.is_empty() { return result; }

    // Aggregate per (base_domain, src_ip)
    let mut domain_stats: HashMap<(String, String), DomainStats> = HashMap::new();

    for q in &all_queries {
        let base = extract_base_domain(&q.domain);
        if base.is_empty() { continue; }
        // Skip well-known high-volume domains (NTP, OCSP, CDN, etc.)
        if is_whitelisted_domain(&base) { continue; }

        let key = (base.clone(), q.src_ip.clone());
        let stats = domain_stats.entry(key).or_insert_with(|| DomainStats {
            base_domain: base,
            src_ip: q.src_ip.clone(),
            query_count: 0,
            txt_count: 0,
            subdomains: Vec::new(),
            resolved_ips: std::collections::HashSet::new(),
        });

        stats.query_count += 1;

        if q.qtype.eq_ignore_ascii_case("TXT") || q.qtype == "16" {
            stats.txt_count += 1;
        }

        // Extract subdomain part (before the base domain)
        let subdomain = extract_subdomain(&q.domain, &stats.base_domain);
        if subdomain.len() >= MIN_SUBDOMAIN_LEN {
            stats.subdomains.push(subdomain);
        }

        for ip in &q.answers {
            if looks_like_ip(ip) {
                stats.resolved_ips.insert(ip.clone());
            }
        }
    }

    // Analyze each domain for tunneling indicators
    for ((_base, _src), stats) in &domain_stats {
        let mut evidence: Vec<String> = Vec::new();
        let mut score: u32 = 0;

        // 1. Volume: many queries to same domain
        if stats.query_count >= VOLUME_THRESHOLD {
            evidence.push(format!("{} requêtes DNS (seuil: {})", stats.query_count, VOLUME_THRESHOLD));
            score += 30;
        }

        // 2. Long subdomains (base32/base64 encoding)
        let max_len = stats.subdomains.iter().map(|s| s.len()).max().unwrap_or(0);
        let long_count = stats.subdomains.iter().filter(|s| s.len() > SUBDOMAIN_LEN_THRESHOLD).count();
        if long_count > 0 {
            evidence.push(format!("{} sous-domaines > {} chars (max: {})",
                long_count, SUBDOMAIN_LEN_THRESHOLD, max_len));
            score += 40;
        }

        // 3. High entropy subdomains
        let entropies: Vec<f64> = stats.subdomains.iter()
            .filter(|s| s.len() >= MIN_SUBDOMAIN_LEN)
            .map(|s| shannon_entropy(s))
            .collect();
        let avg_entropy = if entropies.is_empty() { 0.0 }
            else { entropies.iter().sum::<f64>() / entropies.len() as f64 };
        let high_entropy_count = entropies.iter().filter(|&&e| e > ENTROPY_THRESHOLD).count();
        if high_entropy_count > 3 {
            evidence.push(format!("{} sous-domaines haute entropie (moy: {:.2}, seuil: {})",
                high_entropy_count, avg_entropy, ENTROPY_THRESHOLD));
            score += 30;
        }

        // 4. TXT record abuse (return channel for DNS tunnel)
        if stats.txt_count >= TXT_VOLUME_THRESHOLD {
            evidence.push(format!("{} requêtes TXT (seuil: {})", stats.txt_count, TXT_VOLUME_THRESHOLD));
            score += 25;
        }

        // 5. Fast flux (many IPs for same domain)
        if stats.resolved_ips.len() >= FAST_FLUX_THRESHOLD {
            evidence.push(format!("{} IPs distinctes (fast flux, seuil: {})",
                stats.resolved_ips.len(), FAST_FLUX_THRESHOLD));
            score += 20;
        }

        // Threshold: need at least 2 indicators or 1 strong one (score >= 40)
        if evidence.is_empty() || (evidence.len() < 2 && score < 40) { continue; }

        let severity = if score >= 70 { "CRITICAL" } else { "HIGH" };

        let candidate = TunnelCandidate {
            domain: stats.base_domain.clone(),
            src_ip: stats.src_ip.clone(),
            evidence,
            severity,
            query_count: stats.query_count,
            max_subdomain_len: max_len,
            avg_entropy,
            txt_count: stats.txt_count,
            unique_ips: stats.resolved_ips.len(),
        };

        create_tunnel_finding(store.as_ref(), &candidate).await;
        result.tunnels_detected += 1;
        result.findings_created += 1;
    }

    if result.tunnels_detected > 0 {
        tracing::warn!(
            "NDR-DNS-TUNNEL: {} DNS logs analyzed, {} tunnels detected",
            result.logs_checked, result.tunnels_detected
        );
    }

    result
}

/// Create a finding for a detected DNS tunnel.
async fn create_tunnel_finding(store: &dyn Database, tunnel: &TunnelCandidate) {
    let evidence_text = tunnel.evidence.join("\n- ");

    let title = format!(
        "DNS tunneling suspect: {} ({} requêtes depuis {})",
        tunnel.domain, tunnel.query_count, tunnel.src_ip
    );

    let description = format!(
        "Activité DNS suspecte détectée vers {}.\n\
         Source: {}\n\n\
         Indicateurs:\n- {}\n\n\
         Le DNS tunneling permet l'exfiltration de données ou la communication C2 \
         en encodant des données dans les sous-domaines DNS. Les outils courants \
         incluent iodine, dnscat2, dns2tcp, cobalt strike DNS beacon.\n\n\
         Action recommandée: vérifier les processus sur la machine source, \
         analyser le trafic DNS vers ce domaine, bloquer si confirmé.",
        tunnel.domain, tunnel.src_ip, evidence_text,
    );

    let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
        skill_id: "ndr-dns-tunnel".into(),
        title,
        description: Some(description),
        severity: tunnel.severity.into(),
        category: Some("c2-detection".into()),
        asset: Some(tunnel.src_ip.clone()),
        source: Some("DNS tunneling analysis".into()),
        metadata: Some(serde_json::json!({
            "domain": tunnel.domain,
            "src_ip": tunnel.src_ip,
            "query_count": tunnel.query_count,
            "max_subdomain_length": tunnel.max_subdomain_len,
            "avg_subdomain_entropy": tunnel.avg_entropy,
            "txt_query_count": tunnel.txt_count,
            "unique_resolved_ips": tunnel.unique_ips,
            "evidence": tunnel.evidence,
            "detection": "dns-tunnel-analysis",
            "mitre": ["T1071.004", "T1048.001"]
        })),
    }).await;
}

// ── Helper functions ──

struct DnsQuery {
    domain: String,
    qtype: String,
    src_ip: String,
    answers: Vec<String>,
}

struct DomainStats {
    base_domain: String,
    src_ip: String,
    query_count: usize,
    txt_count: usize,
    subdomains: Vec<String>,
    resolved_ips: std::collections::HashSet<String>,
}

/// Extract base domain (e.g., "evil.com" from "aGVsbG8.data.evil.com").
/// Returns the last 2 labels (or 3 for co.uk/com.br style TLDs).
fn extract_base_domain(fqdn: &str) -> String {
    let labels: Vec<&str> = fqdn.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return fqdn.trim_end_matches('.').to_string();
    }
    // Handle 2-part TLDs (co.uk, com.br, org.au, etc.)
    let last = *labels.last().unwrap_or(&"");
    let second = labels.get(labels.len() - 2).unwrap_or(&"");
    if matches!(*second, "co" | "com" | "org" | "net" | "edu" | "gov" | "ac" | "go") &&
       last.len() <= 3 && labels.len() > 3 {
        labels[labels.len() - 3..].join(".")
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

/// Extract subdomain part (everything before the base domain).
fn extract_subdomain(fqdn: &str, base: &str) -> String {
    let fqdn_clean = fqdn.trim_end_matches('.');
    if fqdn_clean.len() > base.len() + 1 && fqdn_clean.ends_with(base) {
        fqdn_clean[..fqdn_clean.len() - base.len() - 1].to_string()
    } else {
        String::new()
    }
}

/// Shannon entropy of a string (bits per character).
/// High entropy (>3.5) suggests encoded/encrypted data.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Check if a string looks like an IPv4 address.
fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Whitelist of high-volume domains that generate false positives.
/// These are NTP pools, CDNs, OS services, OCSP, etc.
fn is_whitelisted_domain(domain: &str) -> bool {
    const WHITELIST: &[&str] = &[
        // NTP
        "pool.ntp.org", "ntp.ubuntu.com", "time.windows.com", "time.apple.com",
        // OCSP / CRL
        "ocsp.digicert.com", "ocsp.pki.goog", "ocsp.sectigo.com",
        "crl.microsoft.com", "crl3.digicert.com",
        // OS updates
        "windowsupdate.com", "update.microsoft.com", "ubuntu.com",
        "debian.org", "download.docker.com",
        // CDN / Cloud infra
        "cloudflare.com", "amazonaws.com", "azure.com", "googleapis.com",
        "akamaiedge.net", "cloudfront.net", "fastly.net",
        // DNS providers
        "in-addr.arpa", "ip6.arpa",
        // Common services
        "google.com", "microsoft.com", "apple.com",
    ];
    WHITELIST.iter().any(|w| domain == *w || domain.ends_with(&format!(".{}", w)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("aGVsbG8.data.evil.com"), "evil.com");
        assert_eq!(extract_base_domain("sub.example.co.uk"), "example.co.uk");
        assert_eq!(extract_base_domain("evil.com"), "evil.com");
        assert_eq!(extract_base_domain("a.b.c.d.example.org"), "example.org");
    }

    #[test]
    fn test_extract_subdomain() {
        assert_eq!(extract_subdomain("aGVsbG8.data.evil.com", "evil.com"), "aGVsbG8.data");
        assert_eq!(extract_subdomain("evil.com", "evil.com"), "");
        assert_eq!(extract_subdomain("x.evil.com", "evil.com"), "x");
    }

    #[test]
    fn test_shannon_entropy() {
        // Random-looking string = high entropy
        let high = shannon_entropy("aGVsbG8gd29ybGQgZXhmaWx0cmF0aW9u");
        assert!(high > 3.0, "high entropy string: {}", high);

        // Repetitive string = low entropy
        let low = shannon_entropy("aaaaaaaaaa");
        assert!(low < 0.1, "low entropy string: {}", low);

        // Normal subdomain = moderate
        let normal = shannon_entropy("mail.server01");
        assert!(normal > 2.0 && normal < 4.0, "normal entropy: {}", normal);
    }

    #[test]
    fn test_looks_like_ip() {
        assert!(looks_like_ip("192.168.1.1"));
        assert!(looks_like_ip("8.8.8.8"));
        assert!(!looks_like_ip("not-an-ip"));
        assert!(!looks_like_ip("256.1.1.1")); // >255
        assert!(!looks_like_ip("1.2.3"));
    }

    #[test]
    fn test_whitelisted() {
        assert!(is_whitelisted_domain("pool.ntp.org"));
        assert!(is_whitelisted_domain("sub.pool.ntp.org"));
        assert!(is_whitelisted_domain("googleapis.com"));
        assert!(!is_whitelisted_domain("evil.com"));
        assert!(!is_whitelisted_domain("suspicious-tunnel.xyz"));
    }
}
