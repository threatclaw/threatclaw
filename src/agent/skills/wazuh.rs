//! Implémentation `SiemSkill` pour Wazuh.
//!
//! Wazuh stocke les alerts dans son indexer (Elasticsearch/OpenSearch fork).
//! L'API Wazuh manager permet de query les alerts via `/security/user/authenticate`
//! puis `/cluster/alerts` ou directement via le wazuh-indexer (port 9200).
//!
//! Cette implémentation cible le wazuh-indexer (OpenSearch) parce que c'est
//! plus stable et propre que l'API manager pour les alerts.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::agent::skills::siem::{SiemError, SiemLogEntry, SiemSkill};

const REQUEST_TIMEOUT_SECS: u64 = 10;
const MAX_HITS: usize = 50;
const DEFAULT_INDEX: &str = "wazuh-alerts-*";

pub struct WazuhSkill {
    /// URL du wazuh-indexer (OpenSearch), pas de l'API manager.
    pub indexer_url: String,
    pub username: String,
    pub password: String,
    pub no_tls_verify: bool,
}

#[async_trait]
impl SiemSkill for WazuhSkill {
    fn skill_id(&self) -> &'static str {
        "skill-wazuh"
    }

    async fn get_logs_around(
        &self,
        asset: &str,
        timestamp: DateTime<Utc>,
        window: chrono::Duration,
    ) -> Result<Vec<SiemLogEntry>, SiemError> {
        let from = timestamp - window;
        let to = timestamp + window;

        let body = json!({
            "size": MAX_HITS,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"timestamp": {"gte": from.to_rfc3339(), "lte": to.to_rfc3339()}}},
                        {"bool": {"should": [
                            {"term": {"agent.name": asset}},
                            {"term": {"agent.ip": asset}},
                            {"term": {"data.srcip": asset}},
                            {"term": {"data.dstip": asset}},
                        ], "minimum_should_match": 1}}
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}]
        });

        let url = format!(
            "{}/{}/_search",
            self.indexer_url.trim_end_matches('/'),
            DEFAULT_INDEX
        );
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.no_tls_verify)
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| SiemError::Other(format!("client build: {e}")))?;

        let resp = client
            .post(&url)
            .basic_auth(&self.username, Some(&self.password))
            .json(&body)
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
        let hits = json["hits"]["hits"].as_array().cloned().unwrap_or_default();
        let mut entries = Vec::with_capacity(hits.len());
        for hit in hits {
            if let Some(e) = parse_wazuh_alert(&hit, self.skill_id()) {
                entries.push(e);
            }
        }
        Ok(entries)
    }
}

fn parse_wazuh_alert(hit: &Value, source_skill: &str) -> Option<SiemLogEntry> {
    let src = &hit["_source"];

    let ts_str = src["timestamp"].as_str()?;
    let timestamp = DateTime::parse_from_rfc3339(ts_str)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))?;

    let asset = src["agent"]["name"]
        .as_str()
        .or_else(|| src["agent"]["ip"].as_str())
        .unwrap_or("")
        .to_string();

    // Wazuh rule.level : 0-15. 0-3 informational, 4-7 normal, 8-12 warning,
    // 13-15 high/critical.
    let level_num = src["rule"]["level"].as_u64().unwrap_or(0);
    let level = match level_num {
        0..=3 => "info",
        4..=7 => "low",
        8..=11 => "medium",
        12..=14 => "high",
        _ => "critical",
    }
    .to_string();

    let message = src["rule"]["description"]
        .as_str()
        .or_else(|| src["full_log"].as_str())
        .unwrap_or("")
        .to_string();

    let mut tags: Vec<String> = Vec::new();
    if let Some(groups) = src["rule"]["groups"].as_array() {
        for g in groups {
            if let Some(s) = g.as_str() {
                tags.push(s.to_string());
            }
        }
    }
    if let Some(rule_id) = src["rule"]["id"].as_str() {
        tags.push(format!("rule:{}", rule_id));
    }

    Some(SiemLogEntry {
        timestamp,
        asset,
        level,
        message,
        tags,
        source_skill: source_skill.to_string(),
        raw: Some(src.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_wazuh_high_severity_alert() {
        let hit = json!({
            "_source": {
                "timestamp": "2026-05-05T10:00:00.000Z",
                "agent": {"name": "srv-01", "ip": "10.0.0.10"},
                "rule": {
                    "level": 13,
                    "id": "5710",
                    "description": "Multiple failed login attempts",
                    "groups": ["authentication_failed", "ssh", "syslog"]
                },
                "full_log": "sshd[1234]: Failed password for foo"
            }
        });
        let entry = parse_wazuh_alert(&hit, "skill-wazuh").unwrap();
        assert_eq!(entry.asset, "srv-01");
        assert_eq!(entry.level, "high");
        assert!(entry.message.contains("Multiple failed login"));
        assert!(entry.tags.contains(&"rule:5710".to_string()));
        assert!(entry.tags.contains(&"authentication_failed".to_string()));
    }

    #[test]
    fn parse_wazuh_critical_level() {
        let hit = json!({
            "_source": {
                "timestamp": "2026-05-05T10:00:00.000Z",
                "agent": {"name": "x"},
                "rule": {"level": 15, "description": "rootkit"}
            }
        });
        let entry = parse_wazuh_alert(&hit, "skill-wazuh").unwrap();
        assert_eq!(entry.level, "critical");
    }
}
