#![allow(unused_imports)]
//! AdGuard Home Connector — import DNS queries from the AdGuard Home API.
//!
//! Endpoint: GET http://{host}/control/querylog?limit=N[&older_than=T]
//! Auth: HTTP Basic (AdGuard Home admin username/password).
//! The `reason` field tells why a query was filtered; SafeBrowsing hits
//! (malware / phishing) are reported separately from plain blocklist hits.
//!
//! Findings are grouped per client and per period (day or week, see
//! `adguard_alert_window` and `dns_findings`). A cursor (`adguard_cursor`, newest query time seen) keeps the running
//! totals from counting the same query twice across syncs, and tells how far
//! back to page (`older_than`) so busy networks are not truncated.

use crate::connectors::dns_findings::{self, AlertWindow, DnsSource};
use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use chrono::{DateTime, FixedOffset, Local};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const SKILL_ID: &str = "skill-adguard";
const CURSOR_KEY: &str = "adguard_cursor";
/// Query log page size, and how many pages one sync may read back.
const PAGE_SIZE: usize = 500;
const MAX_PAGES: usize = 10;

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
            *t.blocked_per_client
                .entry(client_ip.to_string())
                .or_insert(0) += 1;
        }
        if is_malicious(reason) {
            t.malicious_domains.insert(domain.to_string());
            let domains = t
                .malicious_per_client
                .entry(client_ip.to_string())
                .or_default();
            if !domains.iter().any(|d| d == domain) {
                domains.push(domain.to_string());
            }
        }
    }
    t
}

/// True once a page holds a query at or before the cursor: everything older
/// was already counted by a previous sync.
fn reaches_cursor(entries: &[serde_json::Value], cursor: Option<DateTime<FixedOffset>>) -> bool {
    let Some(c) = cursor else { return false };
    entries.iter().any(|q| {
        q["time"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .is_some_and(|ts| ts <= c)
    })
}

/// GET one query log page; `older_than` is the previous page's `oldest`.
async fn fetch_page(
    client: &reqwest::Client,
    base: &str,
    config: &AdguardConfig,
    older_than: Option<&str>,
) -> Result<serde_json::Value, String> {
    let mut req = client
        .get(&format!("{}/control/querylog", base))
        .query(&[("limit", PAGE_SIZE.to_string())])
        .basic_auth(&config.username, Some(&config.password));
    if let Some(o) = older_than {
        req = req.query(&[("older_than", o)]);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("AdGuard querylog: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("AdGuard querylog HTTP {}", resp.status()));
    }
    resp.json()
        .await
        .map_err(|e| format!("AdGuard parse: {}", e))
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

    let cursor = dns_findings::read_cursor(store, SKILL_ID, CURSOR_KEY).await;

    // Page back through the query log (newest first) until the cursor is
    // reached. Without a cursor (first run) one page is enough: no backfill.
    let mut entries: Vec<serde_json::Value> = vec![];
    let mut older_than: Option<String> = None;
    let mut saturated = false;
    for page_no in 1..=MAX_PAGES {
        let page = match fetch_page(&client, base, config, older_than.as_deref()).await {
            Ok(p) => p,
            Err(e) => {
                result.errors.push(e);
                // Nothing counted yet: keep the cursor where it is and retry next sync
                if entries.is_empty() {
                    return result;
                }
                break;
            }
        };
        let data = page["data"].as_array().cloned().unwrap_or_default();
        let len = data.len();
        let done = cursor.is_none() || reaches_cursor(&data, cursor) || len < PAGE_SIZE;
        entries.extend(data);
        if done {
            break;
        }
        match page["oldest"].as_str().filter(|o| !o.is_empty()) {
            Some(o) => older_than = Some(o.to_string()),
            None => break,
        }
        saturated = page_no == MAX_PAGES;
    }

    let t = tally(&entries, cursor);

    result.queries_analyzed = t.analyzed;
    result.new_queries = t.new_queries;
    result.clients_seen = t.clients.len();
    result.blocked_domains = t.blocked_domains.len();
    result.malicious_domains = t.malicious_domains.len();

    if saturated {
        tracing::warn!(
            "ADGUARD: read {} queries ({} pages) without reaching the previous sync — older ones were skipped, shorten the sync interval",
            entries.len(),
            MAX_PAGES
        );
    }

    result.findings_created = dns_findings::upsert_period_findings(
        store,
        &DnsSource {
            skill_id: SKILL_ID,
            short_name: "AdGuard",
            source: "AdGuard Home",
        },
        config.alert_window,
        &t.blocked_per_client,
        &t.malicious_per_client,
    )
    .await;

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
        config.alert_window.label(&Local::now())
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
            q(
                "2026-11-23T10:00:03Z",
                "10.0.0.1",
                "a.com",
                "FilteredBlackList",
            ),
            q(
                "2026-11-23T10:00:02Z",
                "10.0.0.1",
                "b.com",
                "FilteredSafeBrowsing",
            ),
            q(
                "2026-11-23T10:00:01Z",
                "10.0.0.1",
                "c.com",
                "FilteredBlackList",
            ),
        ];
        let first = tally(&entries, None);
        assert_eq!(first.new_queries, 3);
        assert_eq!(first.blocked_per_client["10.0.0.1"], 3);

        let cursor = DateTime::parse_from_rfc3339("2026-11-23T10:00:01Z").ok();
        let next = tally(&entries, cursor);
        assert_eq!(next.new_queries, 2);
        assert_eq!(next.blocked_per_client["10.0.0.1"], 2);
        assert_eq!(
            next.malicious_per_client["10.0.0.1"],
            vec!["b.com".to_string()]
        );
        assert_eq!(
            next.newest,
            DateTime::parse_from_rfc3339("2026-11-23T10:00:03Z").ok()
        );
    }

    #[test]
    fn paging_stops_once_the_cursor_is_reached() {
        let page = vec![
            q(
                "2026-11-23T10:00:03Z",
                "10.0.0.1",
                "a.com",
                "FilteredBlackList",
            ),
            q(
                "2026-11-23T10:00:02Z",
                "10.0.0.1",
                "b.com",
                "NotFilteredNotFound",
            ),
        ];
        let before = DateTime::parse_from_rfc3339("2026-11-23T10:00:01Z").ok();
        let inside = DateTime::parse_from_rfc3339("2026-11-23T10:00:02Z").ok();
        assert!(!reaches_cursor(&page, before));
        assert!(reaches_cursor(&page, inside));
        assert!(!reaches_cursor(&page, None));
    }
}
