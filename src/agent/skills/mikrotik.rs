//! Implémentation `FirewallSkill` pour Mikrotik RouterOS.
//!
//! RouterOS expose une REST API depuis v7 (port 80/443/8728/8729 selon config).
//! Les logs firewall sont accessibles via `/log` avec filter `topics`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::agent::skills::firewall::{FirewallError, FirewallLogEntry, FirewallSkill};

const REQUEST_TIMEOUT_SECS: u64 = 10;
const MAX_ROWS: usize = 100;

pub struct MikrotikFirewall {
    pub url: String,
    pub username: String,
    pub password: String,
    pub no_tls_verify: bool,
}

#[async_trait]
impl FirewallSkill for MikrotikFirewall {
    fn skill_id(&self) -> &'static str {
        "skill-mikrotik"
    }

    async fn lookup_logs_for_ip(
        &self,
        ip: &str,
        since: DateTime<Utc>,
        _until: DateTime<Utc>,
    ) -> Result<Vec<FirewallLogEntry>, FirewallError> {
        // RouterOS REST endpoint for logs : GET /rest/log
        // Filter via query string `?topics=firewall,info`. Pas de filter IP
        // côté API — on filtre côté Rust.
        let url = format!(
            "{}/rest/log?.proplist=time,topics,message",
            self.url.trim_end_matches('/')
        );

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.no_tls_verify)
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| FirewallError::Other(format!("client build: {e}")))?;

        let resp = client
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|e| FirewallError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Ok(vec![]);
        }
        let arr: Vec<Value> = resp
            .json()
            .await
            .map_err(|e| FirewallError::Parse(e.to_string()))?;

        let mut entries = Vec::new();
        for r in arr {
            if let Some(e) = parse_mikrotik_log(&r, since, ip, self.skill_id()) {
                entries.push(e);
            }
        }
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries.truncate(MAX_ROWS);
        Ok(entries)
    }
}

/// Mikrotik log message format est en texte libre dans `message`.
/// Exemple : `"input: in:ether1 out:(unknown 0), src-mac aa:bb..., proto TCP, 1.2.3.4:54321->5.6.7.8:443, len 60"`.
/// On extrait l'IP via regex simple, action via le premier mot avant `:`.
fn parse_mikrotik_log(
    row: &Value,
    since: DateTime<Utc>,
    filter_ip: &str,
    source_skill: &str,
) -> Option<FirewallLogEntry> {
    let time_str = row["time"].as_str()?;
    // Mikrotik format : "may/05 10:00:00" ou "10:00:00" pour today.
    // Best effort : si le format est juste l'heure, on assume aujourd'hui.
    let now = Utc::now();
    let timestamp = parse_mikrotik_time(time_str, now)?;
    if timestamp < since {
        return None;
    }

    let message = row["message"].as_str()?;
    if !message.contains(filter_ip) {
        return None;
    }

    let topics = row["topics"].as_str().unwrap_or("");
    let action = if topics.contains("drop") {
        "drop"
    } else if topics.contains("accept") {
        "accept"
    } else {
        "logged"
    };

    // Parse "src:port->dst:port" avec une regex simple
    let (src, src_port, dst, dst_port) = parse_flow_arrow(message);

    let proto = if message.contains("proto TCP") {
        Some("TCP".into())
    } else if message.contains("proto UDP") {
        Some("UDP".into())
    } else if message.contains("proto ICMP") {
        Some("ICMP".into())
    } else {
        None
    };

    Some(FirewallLogEntry {
        timestamp,
        action: action.to_string(),
        source_ip: src.unwrap_or_else(|| filter_ip.to_string()),
        source_port: src_port,
        dest_ip: dst,
        dest_port: dst_port,
        proto,
        signature: None,
        category: Some(topics.to_string()).filter(|s| !s.is_empty()),
        bytes_to_server: None,
        bytes_to_client: None,
        source_skill: source_skill.to_string(),
    })
}

fn parse_mikrotik_time(s: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    // Format complet : "may/05 10:00:00"
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(
        &format!("{} {}", s, now.format("%Y")),
        "%b/%d %H:%M:%S %Y",
    ) {
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }
    // Format heure seule : "10:00:00" → today
    if let Ok(time) = chrono::NaiveTime::parse_from_str(s, "%H:%M:%S") {
        let date = now.date_naive();
        let naive = chrono::NaiveDateTime::new(date, time);
        return Some(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }
    None
}

/// Extrait `src:port->dst:port` d'un message Mikrotik.
fn parse_flow_arrow(msg: &str) -> (Option<String>, Option<u16>, Option<String>, Option<u16>) {
    let arrow_pos = match msg.find("->") {
        Some(p) => p,
        None => return (None, None, None, None),
    };

    // Cherche le dernier "ip:port" avant "->"
    let prefix = &msg[..arrow_pos];
    let src_part = prefix
        .rsplit(' ')
        .next()
        .unwrap_or("")
        .trim_end_matches(',');
    let (src, src_port) = split_ip_port(src_part);

    // Et "ip:port" après "->" jusqu'au prochain espace/virgule
    let suffix = &msg[arrow_pos + 2..];
    let dst_end = suffix
        .find(|c: char| c == ' ' || c == ',')
        .unwrap_or(suffix.len());
    let dst_part = &suffix[..dst_end];
    let (dst, dst_port) = split_ip_port(dst_part);

    (src, src_port, dst, dst_port)
}

fn split_ip_port(s: &str) -> (Option<String>, Option<u16>) {
    if let Some(idx) = s.rfind(':') {
        let ip = &s[..idx];
        let port = s[idx + 1..].parse::<u16>().ok();
        return (Some(ip.to_string()), port);
    }
    (Some(s.to_string()).filter(|x| !x.is_empty()), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_mikrotik_drop_log() {
        let now = chrono::Utc::now();
        let time_str = now.format("%H:%M:%S").to_string();
        let row = json!({
            "time": time_str,
            "topics": "firewall,info,drop",
            "message": "input: in:ether1, src-mac aa:bb:cc:dd:ee:ff, proto TCP, 203.0.113.5:54321->10.0.0.10:22, len 60"
        });
        let since = now - chrono::Duration::hours(1);
        let entry = parse_mikrotik_log(&row, since, "203.0.113.5", "skill-mikrotik").unwrap();
        assert_eq!(entry.source_ip, "203.0.113.5");
        assert_eq!(entry.source_port, Some(54321));
        assert_eq!(entry.dest_ip.as_deref(), Some("10.0.0.10"));
        assert_eq!(entry.dest_port, Some(22));
        assert_eq!(entry.action, "drop");
        assert_eq!(entry.proto.as_deref(), Some("TCP"));
    }

    #[test]
    fn parse_flow_arrow_basic() {
        let (src, sp, dst, dp) = parse_flow_arrow("proto TCP, 1.2.3.4:1234->5.6.7.8:80, len 60");
        assert_eq!(src.as_deref(), Some("1.2.3.4"));
        assert_eq!(sp, Some(1234));
        assert_eq!(dst.as_deref(), Some("5.6.7.8"));
        assert_eq!(dp, Some(80));
    }
}
