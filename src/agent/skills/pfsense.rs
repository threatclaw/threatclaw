//! Implémentation `FirewallSkill` pour pfSense.
//!
//! pfSense (FreeBSD pf) partage le format de log filter avec OPNsense mais
//! l'API est différente : endpoints `/api/v1/diagnostics/log/...` (avec
//! l'API REST tierce de pfSense) ou syslog forward direct vers TC.
//!
//! Cette implémentation cible l'API REST pfSense-API (jaredhendrickson13/pfsense-api).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::agent::skills::firewall::{FirewallError, FirewallLogEntry, FirewallSkill};

const REQUEST_TIMEOUT_SECS: u64 = 10;
const MAX_ROWS: usize = 100;

pub struct PfsenseFirewall {
    pub url: String,
    pub api_key: String,
    pub no_tls_verify: bool,
}

#[async_trait]
impl FirewallSkill for PfsenseFirewall {
    fn skill_id(&self) -> &'static str {
        "skill-pfsense"
    }

    async fn lookup_logs_for_ip(
        &self,
        ip: &str,
        since: DateTime<Utc>,
        _until: DateTime<Utc>,
    ) -> Result<Vec<FirewallLogEntry>, FirewallError> {
        // pfsense-api endpoint : GET /api/v1/diagnostics/log/firewall
        let url = format!(
            "{}/api/v1/diagnostics/log/firewall",
            self.url.trim_end_matches('/')
        );

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.no_tls_verify)
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| FirewallError::Other(format!("client build: {e}")))?;

        let resp = client
            .get(&url)
            .header("Authorization", &self.api_key)
            .send()
            .await
            .map_err(|e| FirewallError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(vec![]);
        }
        let json: Value = resp
            .json()
            .await
            .map_err(|e| FirewallError::Parse(e.to_string()))?;

        let mut entries = Vec::new();
        if let Some(arr) = json["data"].as_array() {
            for r in arr {
                if let Some(e) = parse_pfsense_log(r, since, ip, self.skill_id()) {
                    entries.push(e);
                }
            }
        }
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries.truncate(MAX_ROWS);
        Ok(entries)
    }
}

fn parse_pfsense_log(
    row: &Value,
    since: DateTime<Utc>,
    filter_ip: &str,
    source_skill: &str,
) -> Option<FirewallLogEntry> {
    // pfsense-api retourne : {"time", "act" (block/pass), "interface", "src", "srcport",
    //                         "dst", "dstport", "proto", ...}
    let time_str = row["time"].as_str()?;
    // Format pfSense par défaut : "May 5 10:00:00" (RFC 3164 partial). On
    // assume year courante (best effort).
    let now = Utc::now();
    let with_year = format!("{} {}", time_str, now.format("%Y"));
    let timestamp = chrono::NaiveDateTime::parse_from_str(&with_year, "%b %e %H:%M:%S %Y")
        .ok()
        .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))?;
    if timestamp < since {
        return None;
    }

    let src = row["src"].as_str()?;
    let dst = row["dst"].as_str().unwrap_or("");
    if src != filter_ip && dst != filter_ip {
        return None;
    }

    Some(FirewallLogEntry {
        timestamp,
        action: row["act"].as_str().unwrap_or("logged").to_string(),
        source_ip: src.to_string(),
        source_port: row["srcport"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .or_else(|| row["srcport"].as_str().and_then(|s| s.parse::<u16>().ok())),
        dest_ip: row["dst"].as_str().map(String::from),
        dest_port: row["dstport"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .or_else(|| row["dstport"].as_str().and_then(|s| s.parse::<u16>().ok())),
        proto: row["proto"].as_str().map(String::from),
        signature: None,
        category: None,
        bytes_to_server: None,
        bytes_to_client: None,
        source_skill: source_skill.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_pfsense_block() {
        // Use current year so the parser doesn't reject as too old
        let year = chrono::Utc::now().format("%Y").to_string();
        let now = chrono::Utc::now();
        let time_str = now.format("%b %e %H:%M:%S").to_string();
        let row = json!({
            "time": time_str,
            "act": "block",
            "src": "203.0.113.5",
            "srcport": "44321",
            "dst": "10.0.0.10",
            "dstport": "22",
            "proto": "tcp",
        });
        let _ = year;
        let since = now - chrono::Duration::hours(1);
        let entry = parse_pfsense_log(&row, since, "203.0.113.5", "skill-pfsense").unwrap();
        assert_eq!(entry.action, "block");
        assert_eq!(entry.source_ip, "203.0.113.5");
        assert_eq!(entry.dest_port, Some(22));
    }

    #[test]
    fn parse_pfsense_filters_unrelated_ip() {
        let now = chrono::Utc::now();
        let time_str = now.format("%b %e %H:%M:%S").to_string();
        let row = json!({
            "time": time_str,
            "act": "block",
            "src": "1.2.3.4",
            "dst": "5.6.7.8",
        });
        let since = now - chrono::Duration::hours(1);
        // We're looking for 9.9.9.9 — neither src nor dst → filtered out
        assert!(parse_pfsense_log(&row, since, "9.9.9.9", "skill-pfsense").is_none());
    }
}
