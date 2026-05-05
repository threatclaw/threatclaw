//! Implémentation `FirewallSkill` pour Fortinet (FortiGate).
//!
//! Wrappe l'API REST FortiGate `/api/v2/log/...`. Stub-friendly : si les
//! collections de logs ne sont pas accessibles, retourne `Ok(vec![])` (ce
//! qui est valide pour l'enrichment opportuniste).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::agent::skills::firewall::{FirewallError, FirewallLogEntry, FirewallSkill};

const REQUEST_TIMEOUT_SECS: u64 = 10;

pub struct FortinetFirewall {
    pub url: String,
    pub api_key: String,
    pub no_tls_verify: bool,
}

#[async_trait]
impl FirewallSkill for FortinetFirewall {
    fn skill_id(&self) -> &'static str {
        "skill-fortinet"
    }

    async fn lookup_logs_for_ip(
        &self,
        ip: &str,
        since: DateTime<Utc>,
        _until: DateTime<Utc>,
    ) -> Result<Vec<FirewallLogEntry>, FirewallError> {
        // FortiGate REST API : /api/v2/log/forticloud-disk/traffic/forward
        // (ou /api/v2/log/disk/... selon la version). Filtre par srcip ou dstip.
        // Cette implémentation est volontairement minimale — elle pose le
        // pattern et les paramètres. Le filtrage temporel se fait côté Rust
        // après réception parce que le format de query log Fortinet varie selon
        // les versions (`?filter=`, `?freetext=`, etc.).
        let url = format!(
            "{}/api/v2/log/disk/traffic/forward?filter=srcip%3D{}&srcip={}",
            self.url.trim_end_matches('/'),
            urlencoding::encode(ip),
            ip,
        );

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.no_tls_verify)
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| FirewallError::Other(format!("client build: {e}")))?;

        let resp = client
            .get(&url)
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| FirewallError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            // Logs pas accessibles ou licence absente — opportuniste : pas
            // d'erreur fatale, juste pas d'entrée pour ce firewall.
            return Ok(vec![]);
        }

        let json: Value = resp
            .json()
            .await
            .map_err(|e| FirewallError::Parse(e.to_string()))?;

        let mut entries = Vec::new();
        if let Some(results) = json["results"].as_array() {
            for r in results {
                if let Some(entry) = parse_fortinet_log(r, since, self.skill_id()) {
                    entries.push(entry);
                }
            }
        }
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries.truncate(50);
        Ok(entries)
    }
}

fn parse_fortinet_log(
    row: &Value,
    since: DateTime<Utc>,
    source_skill: &str,
) -> Option<FirewallLogEntry> {
    // FortiGate timestamp format: epoch seconds (numeric) or "date=2026-05-05 time=10:00:00"
    let ts_secs = row["timestamp"].as_i64().or_else(|| {
        row["epoch_time"]
            .as_str()
            .and_then(|s| s.parse::<i64>().ok())
    })?;
    let timestamp = DateTime::<Utc>::from_timestamp(ts_secs, 0)?;
    if timestamp < since {
        return None;
    }

    Some(FirewallLogEntry {
        timestamp,
        action: row["action"].as_str().unwrap_or("logged").to_string(),
        source_ip: row["srcip"].as_str()?.to_string(),
        source_port: row["srcport"].as_u64().and_then(|n| u16::try_from(n).ok()),
        dest_ip: row["dstip"].as_str().map(String::from),
        dest_port: row["dstport"].as_u64().and_then(|n| u16::try_from(n).ok()),
        proto: row["proto"]
            .as_str()
            .or_else(|| row["service"].as_str())
            .map(String::from),
        signature: row["attack"].as_str().map(String::from),
        category: row["catdesc"]
            .as_str()
            .or_else(|| row["category"].as_str())
            .map(String::from),
        bytes_to_server: row["sentbyte"].as_u64(),
        bytes_to_client: row["rcvdbyte"].as_u64(),
        source_skill: source_skill.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_fortinet_traffic_log() {
        let row = json!({
            "timestamp": 1777881600i64,  // 2026-05-04T08:00:00Z
            "action": "deny",
            "srcip": "203.0.113.5",
            "srcport": 4444,
            "dstip": "10.0.0.10",
            "dstport": 22,
            "proto": "tcp",
            "sentbyte": 100,
            "rcvdbyte": 200,
            "catdesc": "Brute Force",
            "attack": "SSH.Brute.Force",
        });
        let since = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let entry = parse_fortinet_log(&row, since, "skill-fortinet").unwrap();
        assert_eq!(entry.action, "deny");
        assert_eq!(entry.source_ip, "203.0.113.5");
        assert_eq!(entry.dest_port, Some(22));
        assert_eq!(entry.signature.as_deref(), Some("SSH.Brute.Force"));
    }

    #[test]
    fn parse_fortinet_skips_old_event() {
        let row = json!({
            "timestamp": 1577836800i64,  // 2020-01-01
            "action": "deny",
            "srcip": "1.2.3.4",
        });
        let since = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(parse_fortinet_log(&row, since, "skill-fortinet").is_none());
    }
}
