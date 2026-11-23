#![allow(unused_imports)]
//! AdGuard Home Connector — import DNS queries from the AdGuard Home API.
//!
//! Endpoint: GET http://{host}/control/querylog?limit=N
//! Auth: HTTP Basic (AdGuard Home admin username/password).
//! The `reason` field tells why a query was filtered; SafeBrowsing hits
//! (malware / phishing) are reported separately from plain blocklist hits.
//!
//! Findings are grouped per client and per period (day or week, see
//! `adguard_alert_window`): the title carries the period, so `insert_finding`
//! updates the same finding all period long instead of creating one per sync.
//! A cursor (`adguard_cursor`, newest query time seen) keeps the running
//! totals from counting the same query twice across syncs.

use crate::db::Database;
use crate::db::threatclaw_store::{NewFinding, ThreatClawStore};
use chrono::{DateTime, Datelike, FixedOffset, Local};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const SKILL_ID: &str = "skill-adguard";
const CURSOR_KEY: &str = "adguard_cursor";
/// Blocked queries per client and period before a finding is raised.
const BLOCKED_THRESHOLD: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AlertWindow {
    #[default]
    Daily,
    Weekly,
}

impl AlertWindow {
    /// "weekly" → Weekly, anything else (empty, typo) → Daily.
    pub fn parse(s: &str) -> Self {
        if s.trim().eq_ignore_ascii_case("weekly") {
            AlertWindow::Weekly
        } else {
            AlertWindow::Daily
        }
    }

    /// Period label put in finding titles: "2026-11-23" or "2026-W48".
    fn label<Tz: chrono::TimeZone>(self, now: &DateTime<Tz>) -> String
    where
        Tz::Offset: std::fmt::Display,
    {
        match self {
            AlertWindow::Daily => now.format("%Y-%m-%d").to_string(),
            AlertWindow::Weekly => {
                let w = now.iso_week();
                format!("{}-W{:02}", w.year(), w.week())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdguardConfig {
    pub url: String,      // e.g. "http://192.168.1.1:3000"
    pub username: String, // AdGuard Home admin user
    pub password: String,
    #[serde(default)]
    pub alert_window: AlertWindow,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdguardSyncResult {
    pub queries_analyzed: usize,
    pub new_queries: usize,
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

/// What one querylog page adds on top of the cursor.
#[derive(Debug, Default)]
struct Tally {
    analyzed: usize,
    new_queries: usize,
    clients: HashSet<String>,
    blocked_domains: HashSet<String>,
    malicious_domains: HashSet<String>,
    /// client → blocked queries newer than the cursor
    blocked_per_client: HashMap<String, u64>,
    /// client → malicious domains newer than the cursor
    malicious_per_client: HashMap<String, Vec<String>>,
    newest: Option<DateTime<FixedOffset>>,
}

/// Count the queries strictly newer than `cursor`. Entries without a
/// parseable time are counted only on the first run (no cursor).
fn tally(entries: &[serde_json::Value], cursor: Option<DateTime<FixedOffset>>) -> Tally {
    let mut t = Tally::default();
    for q in entries {
        t.analyzed += 1;
        let time = q["time"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok());
        let is_new = match (time, cursor) {
            (Some(ts), Some(c)) => ts > c,
            (None, Some(_)) => false,
            (_, None) => true,
        };
        if let Some(ts) = time {
            if t.newest.map_or(true, |n| ts > n) {
                t.newest = Some(ts);
            }
        }
        if !is_new {
            continue;
        }
        t.new_queries += 1;

        let client_ip = q["client"].as_str().unwrap_or("");
        let domain = q["question"]["name"].as_str().unwrap_or("");
        let reason = q["reason"].as_str().unwrap_or("");

        if !client_ip.is_empty() {
            t.clients.insert(client_ip.to_string());
        }
        if is_blocked(reason) {
            t.blocked_domains.insert(domain.to_string());
            *t.blocked_per_client.entry(client_ip.to_string()).or_insert(0) += 1;
        }
        if is_malicious(reason) {
            t.malicious_domains.insert(domain.to_string());
            let domains = t.malicious_per_client.entry(client_ip.to_string()).or_default();
            if !domains.iter().any(|d| d == domain) {
                domains.push(domain.to_string());
            }
        }
    }
    t
}

fn blocked_title(ip: &str, period: &str) -> String {
    format!("AdGuard: blocked DNS queries from {} ({})", ip, period)
}

fn malicious_title(ip: &str, period: &str) -> String {
    format!("AdGuard: malicious domains queried by {} ({})", ip, period)
}

pub async fn sync_adguard(store: &dyn Database, config: &AdguardConfig) -> AdguardSyncResult {
    let mut result = AdguardSyncResult {
        queries_analyzed: 0,
        new_queries: 0,
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

    let cursor = store
        .get_skill_config(SKILL_ID)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|c| c.key == CURSOR_KEY)
        .and_then(|c| DateTime::parse_from_rfc3339(&c.value).ok());

    let entries = body["data"].as_array().cloned().unwrap_or_default();
    let t = tally(&entries, cursor);

    result.queries_analyzed = t.analyzed;
    result.new_queries = t.new_queries;
    result.clients_seen = t.clients.len();
    result.blocked_domains = t.blocked_domains.len();
    result.malicious_domains = t.malicious_domains.len();

    if cursor.is_some() && t.new_queries == entries.len() && !entries.is_empty() {
        tracing::warn!(
            "ADGUARD: all {} fetched queries are new — some may have been missed since the last sync, shorten the sync interval",
            entries.len()
        );
    }

    // Running totals of this period's findings, keyed by title
    let period = config.alert_window.label(&Local::now());
    let previous: HashMap<String, serde_json::Value> = store
        .list_findings(None, None, Some(SKILL_ID), 500, 0)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|f| f.title.ends_with(&format!("({})", period)))
        .map(|f| (f.title, f.metadata))
        .collect();

    // Malware / phishing lookups → HIGH, one finding per client and period
    for (ip, domains) in &t.malicious_per_client {
        let title = malicious_title(ip, &period);
        let mut all: Vec<String> = previous
            .get(&title)
            .and_then(|m| serde_json::from_value(m["domains"].clone()).ok())
            .unwrap_or_default();
        for d in domains {
            if !all.contains(d) {
                all.push(d.clone());
            }
        }
        if store
            .insert_finding(&NewFinding {
                skill_id: SKILL_ID.into(),
                title,
                description: Some(format!(
                    "Client {} resolved domains flagged by AdGuard SafeBrowsing (malware/phishing) during {}. The full list is in the finding metadata.",
                    ip, period
                )),
                severity: "HIGH".into(),
                category: Some("dns-malicious".into()),
                asset: Some(ip.clone()),
                source: Some("AdGuard Home".into()),
                metadata: Some(serde_json::json!({
                    "domains": all, "client": ip, "period": period,
                })),
            })
            .await
            .is_ok()
        {
            result.findings_created += 1;
        }
    }

    // Blocked queries → INFO, one finding per client and period, raised once
    // the period total reaches the threshold and then kept up to date
    for (ip, new_count) in &t.blocked_per_client {
        let title = blocked_title(ip, &period);
        let total = previous
            .get(&title)
            .and_then(|m| m["blocked_count"].as_u64())
            .unwrap_or(0)
            + new_count;
        if total < BLOCKED_THRESHOLD {
            continue;
        }
        if store
            .insert_finding(&NewFinding {
                skill_id: SKILL_ID.into(),
                title,
                description: Some(format!(
                    "Client {} had DNS queries blocked by AdGuard during {}. The running total is in the finding metadata (blocked_count).",
                    ip, period
                )),
                severity: "INFO".into(),
                category: Some("dns-blocked".into()),
                asset: Some(ip.clone()),
                source: Some("AdGuard Home".into()),
                metadata: Some(serde_json::json!({
                    "blocked_count": total, "client": ip, "period": period,
                })),
            })
            .await
            .is_ok()
        {
            result.findings_created += 1;
        }
    }

    if let Some(newest) = t.newest {
        if let Err(e) = store
            .set_skill_config(SKILL_ID, CURSOR_KEY, &newest.to_rfc3339())
            .await
        {
            result.errors.push(format!("AdGuard cursor: {}", e));
        }
    }

    tracing::info!(
        "ADGUARD: {} queries ({} new), {} blocked domains, {} malicious, {} clients, {} findings ({})",
        result.queries_analyzed,
        result.new_queries,
        result.blocked_domains,
        result.malicious_domains,
        result.clients_seen,
        result.findings_created,
        period
    );

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn q(time: &str, client: &str, domain: &str, reason: &str) -> serde_json::Value {
        json!({"time": time, "client": client, "question": {"name": domain}, "reason": reason})
    }

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

    #[test]
    fn cursor_skips_queries_already_counted() {
        let entries = vec![
            q("2026-11-23T10:00:03Z", "10.0.0.1", "a.com", "FilteredBlackList"),
            q("2026-11-23T10:00:02Z", "10.0.0.1", "b.com", "FilteredSafeBrowsing"),
            q("2026-11-23T10:00:01Z", "10.0.0.1", "c.com", "FilteredBlackList"),
        ];
        let first = tally(&entries, None);
        assert_eq!(first.new_queries, 3);
        assert_eq!(first.blocked_per_client["10.0.0.1"], 3);

        let cursor = DateTime::parse_from_rfc3339("2026-11-23T10:00:01Z").ok();
        let next = tally(&entries, cursor);
        assert_eq!(next.new_queries, 2);
        assert_eq!(next.blocked_per_client["10.0.0.1"], 2);
        assert_eq!(next.malicious_per_client["10.0.0.1"], vec!["b.com".to_string()]);
        assert_eq!(next.newest, DateTime::parse_from_rfc3339("2026-11-23T10:00:03Z").ok());
    }

    #[test]
    fn period_labels() {
        let d = DateTime::parse_from_rfc3339("2026-11-23T10:00:00Z").unwrap();
        assert_eq!(AlertWindow::Daily.label(&d), "2026-11-23");
        assert_eq!(AlertWindow::Weekly.label(&d), "2026-W48");
        assert_eq!(AlertWindow::parse("weekly"), AlertWindow::Weekly);
        assert_eq!(AlertWindow::parse(""), AlertWindow::Daily);
    }
}
