//! Implémentation `FirewallSkill` pour OPNsense.
//!
//! Wrappe l'API REST `/api/diagnostics/log/core/<scope>` (POST) déjà connue.
//! Voir mémoire `infra_lab_opnsense.md` pour les endpoints validés en lab.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::agent::skills::firewall::{FirewallError, FirewallLogEntry, FirewallSkill};

const MAX_ROWS_PER_LOOKUP: i64 = 100;
const REQUEST_TIMEOUT_SECS: u64 = 8;

/// Configuration runtime de l'instance OPNsense connectée chez le client.
pub struct OpnsenseFirewall {
    pub url: String,
    pub auth_user: String,
    pub auth_secret: String,
    pub no_tls_verify: bool,
}

#[async_trait]
impl FirewallSkill for OpnsenseFirewall {
    fn skill_id(&self) -> &'static str {
        "skill-opnsense"
    }

    async fn lookup_logs_for_ip(
        &self,
        ip: &str,
        since: DateTime<Utc>,
        _until: DateTime<Utc>,
    ) -> Result<Vec<FirewallLogEntry>, FirewallError> {
        // OPNsense ne filtre pas par fenêtre dans l'API search — on retourne
        // les N dernières lignes matching `ip` puis on filtre côté Rust par
        // `>= since`. C'est suffisant pour les fenêtres courtes (1-4h)
        // qu'utilise dossier_enrichment.
        let mut entries = Vec::new();

        // 1) Suricata IDS alerts pour cette IP
        let suri = self
            .fetch_log_scope("suricata", ip)
            .await
            .unwrap_or_default();
        for ev in suri {
            if let Some(entry) = parse_suricata_event(&ev, since, self.skill_id()) {
                entries.push(entry);
            }
        }

        // 2) Filter logs (pf decisions) pour cette IP
        let filt = self.fetch_log_scope("filter", ip).await.unwrap_or_default();
        for ev in filt {
            if let Some(entry) = parse_filter_event(&ev, since, self.skill_id()) {
                entries.push(entry);
            }
        }

        // Tri descendant pour que les plus récents soient en tête
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries.truncate(MAX_ROWS_PER_LOOKUP as usize);
        Ok(entries)
    }
}

impl OpnsenseFirewall {
    /// Appelle `POST /api/diagnostics/log/core/<scope>` avec un searchPhrase
    /// sur l'IP. Retourne le array `rows` du payload OPNsense, ou erreur.
    async fn fetch_log_scope(&self, scope: &str, ip: &str) -> Result<Vec<Value>, FirewallError> {
        let url = format!("{}/api/diagnostics/log/core/{}", self.url, scope);
        let body = serde_json::json!({
            "current": 1,
            "rowCount": MAX_ROWS_PER_LOOKUP,
            "searchPhrase": ip,
            "severity": "",
            "validFrom": "0",
        });

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.no_tls_verify)
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| FirewallError::Other(format!("client build: {e}")))?;

        let resp = client
            .post(&url)
            .basic_auth(&self.auth_user, Some(&self.auth_secret))
            .json(&body)
            .send()
            .await
            .map_err(|e| FirewallError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(FirewallError::Network(format!(
                "HTTP {} on {}",
                resp.status(),
                url
            )));
        }

        let json: Value = resp
            .json()
            .await
            .map_err(|e| FirewallError::Parse(e.to_string()))?;

        Ok(json["rows"].as_array().cloned().unwrap_or_default())
    }
}

/// Parse une ligne de log Suricata (JSON ndjson dans le champ `line` selon la
/// version OPNsense). Schéma typique : `{"timestamp", "event_type", "src_ip",
/// "dest_ip", "src_port", "dest_port", "proto", "alert": {"signature",
/// "category", "severity", "action"}, "flow": {"bytes_toserver", "bytes_toclient"}}`.
fn parse_suricata_event(
    row: &Value,
    since: DateTime<Utc>,
    source_skill: &str,
) -> Option<FirewallLogEntry> {
    // Le champ `line` peut être soit déjà un object JSON, soit une string
    // contenant du JSON ndjson selon la version.
    let line = &row["line"];
    let event: Value = if line.is_object() {
        line.clone()
    } else if let Some(s) = line.as_str() {
        serde_json::from_str(s).ok()?
    } else {
        return None;
    };

    let ts_str = event["timestamp"].as_str()?;
    // Suricata utilise un offset sans colon (`+0200`) qui n'est pas RFC3339
    // strict. On tente RFC3339 d'abord, puis le format Suricata commun.
    let timestamp = DateTime::parse_from_rfc3339(ts_str)
        .or_else(|_| DateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S%.f%z"))
        .or_else(|_| DateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S%z"))
        .ok()
        .map(|dt| dt.with_timezone(&Utc))?;
    if timestamp < since {
        return None;
    }

    let alert = event.get("alert");
    let action = alert
        .and_then(|a| a["action"].as_str())
        .unwrap_or("logged")
        .to_string();
    let signature = alert
        .and_then(|a| a["signature"].as_str())
        .map(String::from);
    let category = alert.and_then(|a| a["category"].as_str()).map(String::from);

    Some(FirewallLogEntry {
        timestamp,
        action,
        source_ip: event["src_ip"].as_str()?.to_string(),
        source_port: event["src_port"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok()),
        dest_ip: event["dest_ip"].as_str().map(String::from),
        dest_port: event["dest_port"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok()),
        proto: event["proto"].as_str().map(String::from),
        signature,
        category,
        bytes_to_server: event["flow"]["bytes_toserver"].as_u64(),
        bytes_to_client: event["flow"]["bytes_toclient"].as_u64(),
        source_skill: source_skill.to_string(),
    })
}

/// Parse une ligne de log filter (pf). Schéma OPNsense :
/// `{"__timestamp__", "action", "interface", "src", "dst", "srcport", "dstport",
///   "proto", ...}`
fn parse_filter_event(
    row: &Value,
    since: DateTime<Utc>,
    source_skill: &str,
) -> Option<FirewallLogEntry> {
    // OPNsense renvoie `__timestamp__` en server-local naive ISO
    // ("2026-04-26T16:26:24" sans offset). On parse en NaiveDateTime puis
    // on assume UTC (ou le TZ du serveur si on l'a — pour l'instant best
    // effort, ce qui compte c'est l'ordering relatif).
    let ts_str = row["__timestamp__"].as_str()?;
    let naive = chrono::NaiveDateTime::parse_from_str(ts_str, "%Y-%m-%dT%H:%M:%S").ok()?;
    let timestamp = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
    if timestamp < since {
        return None;
    }

    let src = row["src"].as_str().or_else(|| row["src_ip"].as_str())?;

    Some(FirewallLogEntry {
        timestamp,
        action: row["action"].as_str().unwrap_or("logged").to_string(),
        source_ip: src.to_string(),
        source_port: row["srcport"]
            .as_str()
            .and_then(|s| s.parse::<u16>().ok())
            .or_else(|| row["src_port"].as_u64().and_then(|n| u16::try_from(n).ok())),
        dest_ip: row["dst"]
            .as_str()
            .or_else(|| row["dest_ip"].as_str())
            .map(String::from),
        dest_port: row["dstport"]
            .as_str()
            .and_then(|s| s.parse::<u16>().ok())
            .or_else(|| {
                row["dest_port"]
                    .as_u64()
                    .and_then(|n| u16::try_from(n).ok())
            }),
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
    fn parse_suricata_with_alert() {
        let row = json!({
            "line": json!({
                "timestamp": "2026-05-05T03:55:10.193989+0200",
                "event_type": "alert",
                "src_ip": "14.102.231.203",
                "src_port": 80,
                "dest_ip": "10.77.0.174",
                "dest_port": 55925,
                "proto": "TCP",
                "alert": {
                    "signature": "ET INFO Packed Executable Download",
                    "category": "Misc activity",
                    "severity": 3,
                    "action": "allowed"
                },
                "flow": {
                    "bytes_toserver": 707,
                    "bytes_toclient": 47054,
                }
            })
        });
        let since = DateTime::parse_from_rfc3339("2026-05-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let entry = parse_suricata_event(&row, since, "skill-opnsense").unwrap();
        assert_eq!(entry.source_ip, "14.102.231.203");
        assert_eq!(entry.dest_ip.as_deref(), Some("10.77.0.174"));
        assert_eq!(
            entry.signature.as_deref(),
            Some("ET INFO Packed Executable Download")
        );
        assert_eq!(entry.action, "allowed");
        assert_eq!(entry.bytes_to_client, Some(47054));
        assert_eq!(entry.source_skill, "skill-opnsense");
    }

    #[test]
    fn parse_suricata_skips_old_event() {
        let row = json!({
            "line": json!({
                "timestamp": "2026-04-01T00:00:00+0000",
                "src_ip": "1.2.3.4",
            })
        });
        let since = DateTime::parse_from_rfc3339("2026-05-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(parse_suricata_event(&row, since, "skill-opnsense").is_none());
    }

    #[test]
    fn parse_suricata_handles_string_line() {
        // Some OPNsense versions return `line` as a JSON-encoded string
        let row = json!({
            "line": "{\"timestamp\":\"2026-05-05T10:00:00+0000\",\"src_ip\":\"1.1.1.1\"}",
        });
        let since = DateTime::parse_from_rfc3339("2026-05-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let entry = parse_suricata_event(&row, since, "skill-opnsense").unwrap();
        assert_eq!(entry.source_ip, "1.1.1.1");
    }

    #[test]
    fn parse_filter_event_basic() {
        let row = json!({
            "__timestamp__": "2026-05-05T10:00:00",
            "action": "block",
            "src": "5.6.7.8",
            "dst": "10.0.0.1",
            "srcport": "44321",
            "dstport": "22",
            "proto": "tcp",
        });
        let since = DateTime::parse_from_rfc3339("2026-05-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let entry = parse_filter_event(&row, since, "skill-opnsense").unwrap();
        assert_eq!(entry.action, "block");
        assert_eq!(entry.source_ip, "5.6.7.8");
        assert_eq!(entry.dest_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(entry.source_port, Some(44321));
        assert_eq!(entry.dest_port, Some(22));
        assert_eq!(entry.signature, None);
    }
}
