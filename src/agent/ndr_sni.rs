//! SNI typosquatting and suspicious domain detection.
//!
//! Detects phishing infrastructure and C2 domains by analyzing TLS SNI fields:
//! - Levenshtein distance against top legitimate domains (typosquatting)
//! - Exotic/free TLDs commonly used by attackers (.tk, .ml, .ga, .cf)
//! - SNI mismatch: SNI ≠ certificate CN/SAN
//! - IP-based SNI (no domain name — raw IP in SNI field)
//!
//! Source: Zeek ssl.log (server_name field).
//! MITRE: T1583.001 (Acquire Infrastructure: Domains)

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use std::collections::HashSet;

/// Levenshtein distance threshold for typosquatting.
/// Distance 1-2 from a top domain = likely typosquatting.
const TYPO_MAX_DISTANCE: usize = 2;

/// Result of an SNI scan cycle.
#[derive(Debug)]
pub struct SniScanResult {
    pub logs_checked: usize,
    pub suspects_found: usize,
    pub findings_created: usize,
}

/// Scan recent Zeek ssl.log for suspicious SNI values.
pub async fn scan_sni(store: std::sync::Arc<dyn Database>, minutes_back: i64) -> SniScanResult {
    let mut result = SniScanResult {
        logs_checked: 0,
        suspects_found: 0,
        findings_created: 0,
    };

    let logs = store
        .query_logs(minutes_back, None, Some("zeek.ssl"), 2000)
        .await
        .unwrap_or_default();
    result.logs_checked = logs.len();

    if logs.is_empty() {
        return result;
    }

    // Dedup: one finding per SNI per cycle
    let mut seen_snis: HashSet<String> = HashSet::new();

    for log in &logs {
        let sni = log.data["server_name"].as_str().unwrap_or("");
        if sni.is_empty() || sni == "-" {
            continue;
        }
        let sni_lower = sni.to_lowercase();

        if seen_snis.contains(&sni_lower) {
            continue;
        }

        let src = log.data["id.orig_h"].as_str().unwrap_or("unknown");
        let dst = log.data["id.resp_h"].as_str().unwrap_or("unknown");
        let port = log.data["id.resp_p"].as_u64().unwrap_or(0) as u16;
        let hostname = log.hostname.as_deref().unwrap_or(src);

        // Skip internal-to-internal
        if is_internal(src) && is_internal(dst) {
            continue;
        }

        let mut evidence: Vec<String> = Vec::new();
        let mut score: u32 = 0;

        // ── 1. Typosquatting: Levenshtein distance from top domains ──
        if let Some((legit, dist)) = check_typosquatting(&sni_lower) {
            evidence.push(format!(
                "Typosquatting probable: \"{}\" à distance {} de \"{}\"",
                sni_lower, dist, legit
            ));
            score += if dist == 1 { 50 } else { 35 };
        }

        // ── 2. Exotic/free TLDs ──
        if let Some(tld) = check_exotic_tld(&sni_lower) {
            evidence.push(format!("TLD suspect: .{} (fréquemment abusé)", tld));
            score += 15;
        }

        // ── 3. IP address as SNI (not a domain name) ──
        if looks_like_ip(&sni_lower) {
            evidence.push("SNI contient une adresse IP au lieu d'un domaine".into());
            score += 30;
        }

        // ── 4. SNI mismatch with certificate CN/SAN ──
        let cert_subject = log.data["subject"]
            .as_str()
            .or_else(|| log.data["certificate.subject"].as_str())
            .unwrap_or("");
        if !cert_subject.is_empty() && !sni_lower.is_empty() {
            if let Some(cn) = extract_cn(cert_subject) {
                let cn_lower = cn.to_lowercase();
                if !sni_matches_cn(&sni_lower, &cn_lower) {
                    evidence.push(format!(
                        "SNI mismatch: SNI=\"{}\" ≠ cert CN=\"{}\"",
                        sni_lower, cn_lower
                    ));
                    score += 25;
                }
            }
        }

        // Threshold: need evidence and reasonable score
        if evidence.is_empty() || score < 30 {
            continue;
        }

        seen_snis.insert(sni_lower.clone());
        result.suspects_found += 1;

        let severity = if score >= 50 { "HIGH" } else { "MEDIUM" };
        let evidence_text = evidence.join(", ");

        let title = format!("SNI suspect: {} (score {})", sni_lower, score);

        let description = format!(
            "Domaine TLS suspect détecté dans le SNI.\n\
             \n\
             - SNI: {}\n\
             - Source: {} → {}:{}\n\
             - Anomalies: {}\n\
             \n\
             Les domaines typosquattés et les TLD gratuits sont couramment utilisés \
             pour le phishing, les infrastructures C2 et le vol de credentials.\n\
             \n\
             Action recommandée: vérifier si ce domaine est légitime, \
             bloquer si phishing confirmé.",
            sni_lower, src, dst, port, evidence_text,
        );

        let _ = store
            .insert_finding(&crate::db::threatclaw_store::NewFinding {
                skill_id: "ndr-sni".into(),
                title,
                description: Some(description),
                severity: severity.into(),
                category: Some("phishing-detection".into()),
                asset: Some(hostname.to_string()),
                source: Some("SNI typosquatting analysis".into()),
                metadata: Some(serde_json::json!({
                    "sni": sni_lower,
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": port,
                    "anomaly_score": score,
                    "evidence": evidence,
                    "detection": "sni-typosquatting",
                    "mitre": ["T1583.001", "T1566.002"]
                })),
            })
            .await;
        result.findings_created += 1;
    }

    if result.suspects_found > 0 {
        tracing::warn!(
            "NDR-SNI: {} logs checked, {} suspicious SNIs detected",
            result.logs_checked,
            result.suspects_found
        );
    }

    result
}

// ── Typosquatting detection ──

/// Top domains to check against for typosquatting.
/// These are the most impersonated brands in phishing campaigns.
const TOP_DOMAINS: &[&str] = &[
    // Tech
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "linkedin.com",
    "netflix.com",
    "paypal.com",
    "dropbox.com",
    "github.com",
    "zoom.us",
    "slack.com",
    "teams.microsoft.com",
    // Enterprise
    "office365.com",
    "office.com",
    "outlook.com",
    "live.com",
    "onedrive.com",
    "sharepoint.com",
    "microsoftonline.com",
    // French specifics
    "orange.fr",
    "free.fr",
    "sfr.fr",
    "bouyguestelecom.fr",
    "laposte.net",
    "impots.gouv.fr",
    "ameli.fr",
    "caf.fr",
    "banquepopulaire.fr",
    "creditmutuel.fr",
    "societegenerale.fr",
    "bnpparibas.com",
    "labanquepostale.fr",
    // Cloud
    "aws.amazon.com",
    "cloud.google.com",
    "azure.microsoft.com",
    // Security
    "virustotal.com",
    "shodan.io",
];

/// Check if a domain is a typosquat of a known top domain.
/// Returns (legitimate_domain, distance) if match found.
fn check_typosquatting(sni: &str) -> Option<(String, usize)> {
    // Extract the domain part (remove subdomains for comparison)
    let sni_base = extract_registrable_domain(sni);
    if sni_base.is_empty() {
        return None;
    }

    for &legit in TOP_DOMAINS {
        let legit_base = extract_registrable_domain(legit);
        // Skip exact matches (legitimate traffic)
        if sni_base == legit_base {
            return None;
        }
        // Only compare domains of similar length (avoid noise)
        let len_diff = (sni_base.len() as i32 - legit_base.len() as i32).unsigned_abs() as usize;
        if len_diff > TYPO_MAX_DISTANCE {
            continue;
        }

        let dist = levenshtein(&sni_base, &legit_base);
        if dist > 0 && dist <= TYPO_MAX_DISTANCE {
            return Some((legit.to_string(), dist));
        }
    }
    None
}

/// Exotic/free TLDs commonly abused for phishing and C2.
const EXOTIC_TLDS: &[&str] = &[
    "tk", "ml", "ga", "cf", "gq", // Freenom (free, massively abused)
    "xyz", "top", "buzz", "club", "icu", // Cheap, high abuse ratio
    "work", "surf", "cam", "rest", "bar", // Low-cost, often malicious
    "cn", "ru", "su", // High phishing volume
    "pw", "cc", "ws", // Pacific islands (cheap, unregulated)
    "bid", "stream", "click", "link", // Spam TLDs
];

/// Check if domain uses an exotic/suspicious TLD.
fn check_exotic_tld(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.split('.').collect();
    if let Some(&tld) = parts.last() {
        if EXOTIC_TLDS.contains(&tld) {
            return Some(tld.to_string());
        }
    }
    None
}

/// Levenshtein distance between two strings.
/// Optimal O(min(m,n)) space implementation.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let m = a_bytes.len();
    let n = b_bytes.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    // Use the shorter string for the column (saves memory)
    let (short, long, short_len, long_len) = if m <= n {
        (a_bytes, b_bytes, m, n)
    } else {
        (b_bytes, a_bytes, n, m)
    };

    let mut prev: Vec<usize> = (0..=short_len).collect();
    let mut curr = vec![0usize; short_len + 1];

    for i in 1..=long_len {
        curr[0] = i;
        for j in 1..=short_len {
            let cost = if long[i - 1] == short[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1) // deletion
                .min(curr[j - 1] + 1) // insertion
                .min(prev[j - 1] + cost); // substitution
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[short_len]
}

/// Extract the registrable domain (e.g., "google.com" from "mail.google.com").
fn extract_registrable_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
    if parts.len() <= 2 {
        return domain.trim_end_matches('.').to_string();
    }
    // Handle 2-part TLDs
    let last = *parts.last().unwrap_or(&"");
    let second = parts.get(parts.len() - 2).unwrap_or(&"");
    if matches!(
        *second,
        "co" | "com" | "org" | "net" | "edu" | "gov" | "ac" | "go"
    ) && last.len() <= 3
        && parts.len() > 3
    {
        parts[parts.len() - 3..].join(".")
    } else {
        parts[parts.len() - 2..].join(".")
    }
}

/// Extract CN from X.509 subject string (e.g., "CN=example.com,O=...").
fn extract_cn(subject: &str) -> Option<String> {
    for part in subject.split(',') {
        let part = part.trim();
        if let Some(cn) = part.strip_prefix("CN=") {
            return Some(cn.to_string());
        }
    }
    None
}

/// Check if SNI matches certificate CN (including wildcard certs).
fn sni_matches_cn(sni: &str, cn: &str) -> bool {
    if sni == cn {
        return true;
    }
    // Wildcard cert: *.example.com matches sub.example.com
    if let Some(wildcard_base) = cn.strip_prefix("*.") {
        if sni.ends_with(wildcard_base) && sni.len() > wildcard_base.len() {
            return true;
        }
    }
    false
}

/// Check if a string looks like an IPv4 address.
fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn is_internal(ip: &str) -> bool {
    crate::agent::ip_classifier::is_non_routable(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("google", "gogle"), 1);
        assert_eq!(levenshtein("microsoft", "microsoftt"), 1);
        assert_eq!(levenshtein("microsoft", "micr0soft"), 1);
        assert_eq!(levenshtein("paypal", "paypa1"), 1);
        assert_eq!(levenshtein("same", "same"), 0);
        assert_eq!(levenshtein("", "abc"), 3);
    }

    #[test]
    fn test_typosquatting_detection() {
        // Distance 1 from google.com
        assert!(check_typosquatting("gogle.com").is_some());
        assert!(check_typosquatting("googl3.com").is_some());
        // Distance 1 from microsoft.com
        assert!(check_typosquatting("micr0soft.com").is_some());
        // Exact match = legitimate, not typosquatting
        assert!(check_typosquatting("google.com").is_none());
        // Completely different = not typosquatting
        assert!(check_typosquatting("randomsite.com").is_none());
    }

    #[test]
    fn test_exotic_tld() {
        assert!(check_exotic_tld("evil.tk").is_some());
        assert!(check_exotic_tld("phishing.ml").is_some());
        assert!(check_exotic_tld("legitimate.com").is_none());
        assert!(check_exotic_tld("company.fr").is_none());
    }

    #[test]
    fn test_extract_cn() {
        assert_eq!(
            extract_cn("CN=example.com,O=Org"),
            Some("example.com".into())
        );
        assert_eq!(extract_cn("O=Org, CN=test.com"), Some("test.com".into()));
        assert_eq!(extract_cn("O=NoCommonName"), None);
    }

    #[test]
    fn test_sni_matches_cn() {
        assert!(sni_matches_cn("example.com", "example.com"));
        assert!(sni_matches_cn("sub.example.com", "*.example.com"));
        assert!(!sni_matches_cn("other.com", "example.com"));
        assert!(!sni_matches_cn("example.com", "*.example.com")); // wildcard needs subdomain
    }

    #[test]
    fn test_registrable_domain() {
        assert_eq!(extract_registrable_domain("mail.google.com"), "google.com");
        assert_eq!(
            extract_registrable_domain("sub.example.co.uk"),
            "example.co.uk"
        );
        assert_eq!(extract_registrable_domain("example.com"), "example.com");
    }
}
