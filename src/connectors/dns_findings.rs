//! Shared finding logic for the DNS filtering connectors (AdGuard Home, Pi-hole).
//!
//! Findings are grouped per client and per period (day or week): the title
//! carries the period, so `insert_finding`'s dedup on skill_id + title + asset
//! keeps updating the same finding all period long instead of creating one
//! per sync. Running totals live in the finding metadata; the connectors keep
//! a cursor (newest query time seen) so a query is never counted twice.

use crate::db::Database;
use crate::db::threatclaw_store::{NewFinding, ThreatClawStore};
use chrono::{DateTime, Datelike, FixedOffset, Local};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Blocked queries per client and period before a finding is raised.
pub const BLOCKED_THRESHOLD: u64 = 20;

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
    pub fn label<Tz: chrono::TimeZone>(self, now: &DateTime<Tz>) -> String
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

/// Which connector raises the findings.
pub struct DnsSource<'a> {
    pub skill_id: &'a str,
    /// Title prefix, e.g. "AdGuard".
    pub short_name: &'a str,
    /// `source` column, e.g. "AdGuard Home".
    pub source: &'a str,
}

/// Read the connector's cursor (RFC 3339) from its skill config.
pub async fn read_cursor(
    store: &dyn Database,
    skill_id: &str,
    key: &str,
) -> Option<DateTime<FixedOffset>> {
    store
        .get_skill_config(skill_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|c| c.key == key)
        .and_then(|c| DateTime::parse_from_rfc3339(&c.value).ok())
}

/// Raise or update this period's findings. `blocked` holds the blocked
/// queries per client since the cursor (→ INFO once the period total reaches
/// the threshold), `malicious` the malware/phishing domains per client
/// (→ HIGH). Returns how many findings were written.
pub async fn upsert_period_findings(
    store: &dyn Database,
    src: &DnsSource<'_>,
    window: AlertWindow,
    blocked: &HashMap<String, u64>,
    malicious: &HashMap<String, Vec<String>>,
) -> usize {
    let period = window.label(&Local::now());
    let suffix = format!("({})", period);
    let previous: HashMap<String, serde_json::Value> = store
        .list_findings(None, None, Some(src.skill_id), 500, 0)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|f| f.title.ends_with(&suffix))
        .map(|f| (f.title, f.metadata))
        .collect();
    let mut written = 0;

    for (ip, domains) in malicious {
        let title = format!(
            "{}: malicious domains queried by {} {}",
            src.short_name, ip, suffix
        );
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
                skill_id: src.skill_id.into(),
                title,
                description: Some(format!(
                    "Client {} resolved domains flagged as malware/phishing by {} during {}. The full list is in the finding metadata.",
                    ip, src.source, period
                )),
                severity: "HIGH".into(),
                category: Some("dns-malicious".into()),
                asset: Some(ip.clone()),
                source: Some(src.source.into()),
                metadata: Some(serde_json::json!({
                    "domains": all, "client": ip, "period": period,
                })),
            })
            .await
            .is_ok()
        {
            written += 1;
        }
    }

    for (ip, new_count) in blocked {
        let title = format!(
            "{}: blocked DNS queries from {} {}",
            src.short_name, ip, suffix
        );
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
                skill_id: src.skill_id.into(),
                title,
                description: Some(format!(
                    "Client {} had DNS queries blocked by {} during {}. The running total is in the finding metadata (blocked_count).",
                    ip, src.source, period
                )),
                severity: "INFO".into(),
                category: Some("dns-blocked".into()),
                asset: Some(ip.clone()),
                source: Some(src.source.into()),
                metadata: Some(serde_json::json!({
                    "blocked_count": total, "client": ip, "period": period,
                })),
            })
            .await
            .is_ok()
        {
            written += 1;
        }
    }

    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_labels() {
        let d = DateTime::parse_from_rfc3339("2026-11-23T10:00:00Z").unwrap();
        assert_eq!(AlertWindow::Daily.label(&d), "2026-11-23");
        assert_eq!(AlertWindow::Weekly.label(&d), "2026-W48");
        assert_eq!(AlertWindow::parse("weekly"), AlertWindow::Weekly);
        assert_eq!(AlertWindow::parse(""), AlertWindow::Daily);
    }
}
