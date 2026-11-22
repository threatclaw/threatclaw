#![allow(unused_imports)]
//! AdGuard Home Connector — import DNS queries from the AdGuard Home API.
//!
//! Endpoint: GET http://{host}/control/querylog?limit=N
//! Auth: HTTP Basic (AdGuard Home admin username/password).
//! The `reason` field tells why a query was filtered; SafeBrowsing hits
//! (malware / phishing) are reported separately from plain blocklist hits.

use crate::db::Database;
use crate::db::threatclaw_store::{NewFinding, ThreatClawStore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdguardConfig {
    pub url: String,      // e.g. "http://192.168.1.1:3000"
    pub username: String, // AdGuard Home admin user
    pub password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdguardSyncResult {
    pub queries_analyzed: usize,
    pub blocked_domains: usize,
    pub malicious_domains: usize,
    pub clients_seen: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

/// Blocked = the answer was replaced by AdGuard (blocklist, blocked service,
/// SafeBrowsing, parental control). Rewrites and SafeSearch are not blocks.
fn is_blocked(reason: &str) -> bool {
    matches!(
        reason,
        "FilteredBlackList"
            | "FilteredBlockedService"
            | "FilteredSafeBrowsing"
            | "FilteredParental"
            | "FilteredInvalid"
    )
}

/// SafeBrowsing = AdGuard's malware / phishing reputation list.
fn is_malicious(reason: &str) -> bool {
    reason == "FilteredSafeBrowsing"
}

pub async fn sync_adguard(store: &dyn Database, config: &AdguardConfig) -> AdguardSyncResult {
    let mut result = AdguardSyncResult {
        queries_analyzed: 0,
        blocked_domains: 0,
        malicious_domains: 0,
        clients_seen: 0,
        findings_created: 0,
        errors: vec![],
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .no_proxy()
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("AdGuard HTTP client: {}", e));
            return result;
        }
    };
    let base = config.url.trim_end_matches('/');

    // Get recent queries
    let queries_resp = match client
        .get(&format!("{}/control/querylog?limit=200", base))
        .basic_auth(&config.username, Some(&config.password))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("AdGuard querylog: {}", e));
            return result;
        }
    };

    if !queries_resp.status().is_success() {
        result
            .errors
            .push(format!("AdGuard querylog HTTP {}", queries_resp.status()));
        return result;
    }

    let body: serde_json::Value = match queries_resp.json().await {
        Ok(b) => b,
        Err(e) => {
            result.errors.push(format!("AdGuard parse: {}", e));
            return result;
        }
    };

    let mut clients = std::collections::HashSet::new();
    let mut blocked = std::collections::HashSet::new();
    let mut malicious = std::collections::HashSet::new();
    let mut client_blocked_count: std::collections::HashMap<String, u32> =
        std::collections::HashMap::new();
    // client → malicious domains it tried to resolve
    let mut client_malicious: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    if let Some(arr) = body["data"].as_array() {
        for q in arr {
            result.queries_analyzed += 1;
            let client_ip = q["client"].as_str().unwrap_or("");
            let domain = q["question"]["name"].as_str().unwrap_or("");
            let reason = q["reason"].as_str().unwrap_or("");

            if !client_ip.is_empty() {
                clients.insert(client_ip.to_string());
            }

            if is_blocked(reason) {
                blocked.insert(domain.to_string());
                *client_blocked_count
                    .entry(client_ip.to_string())
                    .or_insert(0) += 1;
            }

            if is_malicious(reason) {
                malicious.insert(domain.to_string());
                let domains = client_malicious.entry(client_ip.to_string()).or_default();
                if !domains.iter().any(|d| d == domain) {
                    domains.push(domain.to_string());
                }
            }
        }
    }

    result.clients_seen = clients.len();
    result.blocked_domains = blocked.len();
    result.malicious_domains = malicious.len();

    // Malware / phishing lookups → HIGH, one finding per client
    for (ip, domains) in &client_malicious {
        let title = format!(
            "AdGuard: {} malicious domain(s) queried by {}",
            domains.len(),
            ip
        );
        if store
            .insert_finding(&NewFinding {
                skill_id: "skill-adguard".into(),
                title,
                description: Some(format!(
                    "Client {} resolved domains flagged by AdGuard SafeBrowsing (malware/phishing): {}",
                    ip,
                    domains.join(", ")
                )),
                severity: "HIGH".into(),
                category: Some("dns-malicious".into()),
                asset: Some(ip.clone()),
                source: Some("AdGuard Home".into()),
                metadata: Some(serde_json::json!({"domains": domains, "client": ip})),
            })
            .await
            .is_ok()
        {
            result.findings_created += 1;
        }
    }

    // Heavily blocked clients (>20 blocked queries = suspicious)
    for (ip, count) in &client_blocked_count {
        if *count >= 20 {
            let title = format!("AdGuard: {} blocked DNS queries from {}", count, ip);
            if store
                .insert_finding(&NewFinding {
                    skill_id: "skill-adguard".into(),
                    title,
                    description: Some(format!(
                        "Client {} has {} blocked DNS queries in recent history",
                        ip, count
                    )),
                    severity: "MEDIUM".into(),
                    category: Some("dns-suspicious".into()),
                    asset: Some(ip.clone()),
                    source: Some("AdGuard Home".into()),
                    metadata: Some(serde_json::json!({"blocked_count": count, "client": ip})),
                })
                .await
                .is_ok()
            {
                result.findings_created += 1;
            }
        }
    }

    tracing::info!(
        "ADGUARD: {} queries, {} blocked domains, {} malicious, {} clients, {} findings",
        result.queries_analyzed,
        result.blocked_domains,
        result.malicious_domains,
        result.clients_seen,
        result.findings_created
    );

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_and_safesearch_are_not_blocks() {
        assert!(is_blocked("FilteredBlackList"));
        assert!(is_blocked("FilteredSafeBrowsing"));
        assert!(!is_blocked("Rewrite"));
        assert!(!is_blocked("FilteredSafeSearch"));
        assert!(!is_blocked("NotFilteredNotFound"));
        assert!(!is_blocked("NotFilteredWhiteList"));
    }

    #[test]
    fn only_safebrowsing_is_malicious() {
        assert!(is_malicious("FilteredSafeBrowsing"));
        assert!(!is_malicious("FilteredBlackList"));
        assert!(!is_malicious("FilteredParental"));
    }
}
