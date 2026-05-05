//! Implémentation `SiemSkill` pour Graylog.
//!
//! Graylog expose `/api/search/universal/relative` et `/api/search/universal/absolute`.
//! On utilise absolute avec from/to et un query string standard `host:<asset>`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::agent::skills::siem::{SiemError, SiemLogEntry, SiemSkill};

const REQUEST_TIMEOUT_SECS: u64 = 10;
const MAX_HITS: usize = 50;

pub struct GraylogSkill {
    pub url: String,
    pub api_token: String,
    pub no_tls_verify: bool,
}

#[async_trait]
impl SiemSkill for GraylogSkill {
    fn skill_id(&self) -> &'static str {
        "skill-graylog"
    }

    async fn get_logs_around(
        &self,
        asset: &str,
        timestamp: DateTime<Utc>,
        window: chrono::Duration,
    ) -> Result<Vec<SiemLogEntry>, SiemError> {
        let from = timestamp - window;
        let to = timestamp + window;

        let url = format!(
            "{}/api/search/universal/absolute?query=source%3A{}&from={}&to={}&limit={}",
            self.url.trim_end_matches('/'),
            urlencoding::encode(asset),
            urlencoding::encode(&from.to_rfc3339()),
            urlencoding::encode(&to.to_rfc3339()),
            MAX_HITS
        );

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.no_tls_verify)
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| SiemError::Other(format!("client build: {e}")))?;

        // Graylog auth : token comme username + password literal "token"
        let resp = client
            .get(&url)
            .basic_auth(&self.api_token, Some("token"))
            .header("Accept", "application/json")
            .header("X-Requested-By", "ThreatClaw")
            .send()
            .await
            .map_err(|e| SiemError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SiemError::Network(format!("HTTP {}", resp.status())));
        }
        let json: Value = resp
            .json()
            .await
            .map_err(|e| SiemError::Parse(e.to_string()))?;

        let messages = json["messages"].as_array().cloned().unwrap_or_default();
        let mut entries = Vec::with_capacity(messages.len());
        for m in messages {
            if let Some(entry) = parse_graylog_message(&m, self.skill_id()) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

fn parse_graylog_message(wrapper: &Value, source_skill: &str) -> Option<SiemLogEntry> {
    // Graylog wrap chaque hit dans `{"message": {"timestamp", "source", "level", "message", ...}}`
    let m = &wrapper["message"];

    let ts_str = m["timestamp"].as_str()?;
    let timestamp = DateTime::parse_from_rfc3339(ts_str)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))?;

    let asset = m["source"].as_str().unwrap_or("").to_string();
    let level = m["level"]
        .as_u64()
        .map(|n| match n {
            0..=2 => "critical",
            3 => "error",
            4 => "warning",
            5 | 6 => "notice",
            _ => "info",
        })
        .unwrap_or("info")
        .to_string();
    let message = m["message"].as_str().unwrap_or("").to_string();

    let mut tags: Vec<String> = Vec::new();
    if let Some(facility) = m["facility"].as_str() {
        tags.push(facility.to_string());
    }
    if let Some(streams) = m["streams"].as_array() {
        for s in streams {
            if let Some(stream_str) = s.as_str() {
                tags.push(stream_str.to_string());
            }
        }
    }

    Some(SiemLogEntry {
        timestamp,
        asset,
        level,
        message,
        tags,
        source_skill: source_skill.to_string(),
        raw: Some(m.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_graylog_message_with_level() {
        let wrapper = json!({
            "message": {
                "timestamp": "2026-05-05T10:00:00.000Z",
                "source": "srv-01",
                "level": 4,
                "message": "Failed login for user foo",
                "facility": "auth",
            }
        });
        let entry = parse_graylog_message(&wrapper, "skill-graylog").unwrap();
        assert_eq!(entry.asset, "srv-01");
        assert_eq!(entry.level, "warning");
        assert_eq!(entry.message, "Failed login for user foo");
        assert!(entry.tags.iter().any(|t| t == "auth"));
    }

    #[test]
    fn parse_graylog_message_invalid_ts_returns_none() {
        let wrapper = json!({
            "message": {
                "timestamp": "not a date",
                "source": "x"
            }
        });
        assert!(parse_graylog_message(&wrapper, "skill-graylog").is_none());
    }
}
