#![allow(unused_imports)]
//! Pi-hole Connector — import DNS queries from Pi-hole v6 API.
//!
//! Pi-hole v6 has a built-in REST API (no more lighttpd/PHP).
//! Endpoint: GET http://{host}/api/queries?length=N&start=K[&from=T&until=T]
//! Auth: requires session token from POST /api/auth (released with
//! DELETE /api/auth at the end, Pi-hole caps concurrent sessions).
//!
//! Findings are grouped per client and per period (day or week, see
//! `pihole_alert_window` and `dns_findings`). A cursor (`pihole_cursor`,
//! newest query time seen) bounds each sync to the queries since the last
//! one (`from`), paged within a window frozen at sync start (`until`).

use crate::connectors::dns_findings::{self, AlertWindow, DnsSource};
use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use chrono::{DateTime, FixedOffset, Local, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const SKILL_ID: &str = "skill-pihole";
const CURSOR_KEY: &str = "pihole_cursor";
/// Query page size, and how many pages one sync may read.
const PAGE_SIZE: usize = 500;
const MAX_PAGES: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiholeConfig {
    pub url: String,      // e.g. "http://192.168.1.1"
    pub password: String, // Pi-hole admin password
    #[serde(default)]
    pub alert_window: AlertWindow,
}

#[derive(Debug, Clone, Serialize)]
pub struct PiholeSyncResult {
    pub queries_analyzed: usize,
    pub new_queries: usize,
    pub blocked_domains: usize,
    pub suspicious_domains: usize,
    pub clients_seen: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

/// Blocked by Pi-hole itself (gravity, regex, denylist, incl. CNAME
/// inspection) or by the upstream server. v6 reports the status as a
/// string; older payloads used FTL's numeric codes (1 gravity, 4 regex,
/// 5 exact denylist).
fn is_blocked(status: &serde_json::Value) -> bool {
    match status {
        serde_json::Value::String(s) => matches!(
            s.as_str(),
            "GRAVITY"
                | "REGEX"
                | "DENYLIST"
                | "GRAVITY_CNAME"
                | "REGEX_CNAME"
                | "DENYLIST_CNAME"
                | "EXTERNAL_BLOCKED_IP"
                | "EXTERNAL_BLOCKED_NULL"
                | "EXTERNAL_BLOCKED_NXRA"
                | "EXTERNAL_BLOCKED_EDE15"
        ),
        v => matches!(v.as_i64(), Some(1 | 4 | 5)),
    }
}

/// v6: `client: {ip, name}`; older payloads: `client: "ip"`.
fn client_ip(q: &serde_json::Value) -> &str {
    q["client"]["ip"]
        .as_str()
        .or_else(|| q["client"].as_str())
        .unwrap_or("")
}

/// Query time: v6 sends a unix timestamp (float seconds).
fn query_time(q: &serde_json::Value) -> Option<DateTime<FixedOffset>> {
    let secs = q["time"].as_f64()?;
    DateTime::from_timestamp_micros((secs * 1_000_000.0) as i64).map(|d| d.fixed_offset())
}

/// What the fetched pages add on top of the cursor.
#[derive(Debug, Default)]
struct Tally {
    analyzed: usize,
    new_queries: usize,
    clients: HashSet<String>,
    blocked_domains: HashSet<String>,
    /// client → blocked queries newer than the cursor
    blocked_per_client: HashMap<String, u64>,
    newest: Option<DateTime<FixedOffset>>,
}

/// Count the queries strictly newer than `cursor`, once each (query ids
/// dedupe entries seen on two pages). Entries without a parseable time are
/// counted only on the first run (no cursor).
fn tally(entries: &[serde_json::Value], cursor: Option<DateTime<FixedOffset>>) -> Tally {
    let mut t = Tally::default();
    let mut seen_ids = HashSet::new();
    for q in entries {
        if let Some(id) = q["id"].as_i64() {
            if !seen_ids.insert(id) {
                continue;
            }
        }
        t.analyzed += 1;
        let time = query_time(q);
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

        let ip = client_ip(q);
        let domain = q["domain"].as_str().unwrap_or("");
        if !ip.is_empty() {
            t.clients.insert(ip.to_string());
        }
        if is_blocked(&q["status"]) {
            t.blocked_domains.insert(domain.to_string());
            *t.blocked_per_client.entry(ip.to_string()).or_insert(0) += 1;
        }
    }
    t
}

pub async fn sync_pihole(store: &dyn Database, config: &PiholeConfig) -> PiholeSyncResult {
    let mut result = PiholeSyncResult {
        queries_analyzed: 0,
        new_queries: 0,
        blocked_domains: 0,
        suspicious_domains: 0,
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
            result.errors.push(format!("Pi-hole HTTP client: {}", e));
            return result;
        }
    };
    let base = config.url.trim_end_matches('/');

    // Authenticate
    let auth_resp = match client
        .post(&format!("{}/api/auth", base))
        .json(&serde_json::json!({"password": config.password}))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("Pi-hole auth: {}", e));
            return result;
        }
    };

    if !auth_resp.status().is_success() {
        result
            .errors
            .push(format!("Pi-hole auth HTTP {}", auth_resp.status()));
        return result;
    }

    let auth_body: serde_json::Value = match auth_resp.json().await {
        Ok(b) => b,
        Err(e) => {
            result.errors.push(format!("Pi-hole auth parse: {}", e));
            return result;
        }
    };

    // No admin password set on the Pi-hole → valid session without a sid
    let session = auth_body["session"]["sid"]
        .as_str()
        .unwrap_or("")
        .to_string();
    if session.is_empty() && auth_body["session"]["valid"].as_bool() != Some(true) {
        result.errors.push("Pi-hole: no session token".into());
        return result;
    }

    let cursor = dns_findings::read_cursor(store, SKILL_ID, CURSOR_KEY).await;
    let until = Utc::now().timestamp();

    // Without a cursor (first run) one page is enough: no backfill
    let mut entries: Vec<serde_json::Value> = vec![];
    let mut saturated = false;
    for page_no in 0..MAX_PAGES {
        let mut params = vec![
            ("length", PAGE_SIZE.to_string()),
            ("start", (page_no * PAGE_SIZE).to_string()),
        ];
        if let Some(c) = cursor {
            params.push(("from", c.timestamp().to_string()));
            params.push(("until", until.to_string()));
        }
        let mut req = client.get(&format!("{}/api/queries", base)).query(&params);
        if !session.is_empty() {
            req = req.header("sid", session.as_str());
        }
        let page: serde_json::Value = match req.send().await {
            Ok(r) if r.status().is_success() => match r.json().await {
                Ok(b) => b,
                Err(e) => {
                    result.errors.push(format!("Pi-hole parse: {}", e));
                    break;
                }
            },
            Ok(r) => {
                result
                    .errors
                    .push(format!("Pi-hole queries HTTP {}", r.status()));
                break;
            }
            Err(e) => {
                result.errors.push(format!("Pi-hole queries: {}", e));
                break;
            }
        };
        let data = page["queries"].as_array().cloned().unwrap_or_default();
        let len = data.len();
        entries.extend(data);
        if cursor.is_none() || len < PAGE_SIZE {
            break;
        }
        saturated = page_no + 1 == MAX_PAGES;
    }

    // Free the session seat
    if !session.is_empty() {
        let _ = client
            .delete(&format!("{}/api/auth", base))
            .header("sid", session.as_str())
            .send()
            .await;
    }

    // Nothing counted: keep the cursor where it is and retry next sync
    if entries.is_empty() && !result.errors.is_empty() {
        return result;
    }

    let t = tally(&entries, cursor);
    result.queries_analyzed = t.analyzed;
    result.new_queries = t.new_queries;
    result.clients_seen = t.clients.len();
    result.blocked_domains = t.blocked_domains.len();

    if saturated {
        tracing::warn!(
            "PIHOLE: read {} queries ({} pages) without reaching the previous sync — older ones were skipped, shorten the sync interval",
            entries.len(),
            MAX_PAGES
        );
    }

    // Pi-hole has no malware/phishing verdict of its own: blocked only
    result.findings_created = dns_findings::upsert_period_findings(
        store,
        &DnsSource {
            skill_id: SKILL_ID,
            short_name: "Pi-hole",
            source: "Pi-hole",
        },
        config.alert_window,
        &t.blocked_per_client,
        &HashMap::new(),
    )
    .await;

    if let Some(newest) = t.newest {
        if let Err(e) = store
            .set_skill_config(SKILL_ID, CURSOR_KEY, &newest.to_rfc3339())
            .await
        {
            result.errors.push(format!("Pi-hole cursor: {}", e));
        }
    }

    tracing::info!(
        "PIHOLE: {} queries ({} new), {} blocked domains, {} clients, {} findings ({})",
        result.queries_analyzed,
        result.new_queries,
        result.blocked_domains,
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

    /// Shape of a Pi-hole v6 /api/queries entry.
    fn q(id: i64, time: f64, ip: &str, domain: &str, status: &str) -> serde_json::Value {
        json!({
            "id": id, "time": time, "type": "A", "status": status, "domain": domain,
            "client": {"ip": ip, "name": null}, "reply": {"type": "IP", "time": 0.1},
        })
    }

    #[test]
    fn v6_string_statuses() {
        assert!(is_blocked(&json!("GRAVITY")));
        assert!(is_blocked(&json!("DENYLIST_CNAME")));
        assert!(is_blocked(&json!("EXTERNAL_BLOCKED_NXRA")));
        assert!(!is_blocked(&json!("FORWARDED")));
        assert!(!is_blocked(&json!("CACHE")));
    }

    #[test]
    fn legacy_numeric_statuses_and_client() {
        assert!(is_blocked(&json!(1)));
        assert!(is_blocked(&json!(5)));
        assert!(!is_blocked(&json!(2)));
        assert_eq!(client_ip(&json!({"client": "10.0.0.9"})), "10.0.0.9");
    }

    #[test]
    fn cursor_and_ids_prevent_double_counting() {
        let t0 = 1_795_000_000.0;
        let entries = vec![
            q(3, t0 + 3.0, "10.0.0.1", "a.com", "GRAVITY"),
            q(2, t0 + 2.0, "10.0.0.1", "b.com", "FORWARDED"),
            q(1, t0 + 1.0, "10.0.0.1", "c.com", "REGEX"),
            // same query again on the next page
            q(3, t0 + 3.0, "10.0.0.1", "a.com", "GRAVITY"),
        ];
        let first = tally(&entries, None);
        assert_eq!(first.analyzed, 3);
        assert_eq!(first.blocked_per_client["10.0.0.1"], 2);

        let cursor = query_time(&entries[2]);
        let next = tally(&entries, cursor);
        assert_eq!(next.new_queries, 2);
        assert_eq!(next.blocked_per_client["10.0.0.1"], 1);
        assert_eq!(next.newest, query_time(&entries[0]));
    }
}
