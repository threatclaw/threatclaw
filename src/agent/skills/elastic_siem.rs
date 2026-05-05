//! Implémentation `SiemSkill` pour Elasticsearch (Elastic SIEM).
//!
//! Wrappe l'endpoint `/_search` standard avec une query bool/range. Indexes
//! configurés via `skill-elastic-siem` skill_configs (par défaut "logs-*").

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::agent::skills::siem::{SiemError, SiemLogEntry, SiemSkill};

const MAX_HITS: usize = 50;
const REQUEST_TIMEOUT_SECS: u64 = 10;

pub struct ElasticSiemSkill {
    pub url: String,
    /// Pattern d'index (ex: "logs-*", "winlogbeat-*", "filebeat-*").
    pub index_pattern: String,
    pub api_key: Option<String>,
    /// Authentification basic alternative (si pas d'API key).
    pub username: Option<String>,
    pub password: Option<String>,
    pub no_tls_verify: bool,
}

#[async_trait]
impl SiemSkill for ElasticSiemSkill {
    fn skill_id(&self) -> &'static str {
        "skill-elastic-siem"
    }

    async fn get_logs_around(
        &self,
        asset: &str,
        timestamp: DateTime<Utc>,
        window: chrono::Duration,
    ) -> Result<Vec<SiemLogEntry>, SiemError> {
        let from = timestamp - window;
        let to = timestamp + window;

        // Query Elasticsearch standard : range sur @timestamp + match sur asset
        // (host.name OU agent.hostname OU host.hostname selon la version ECS).
        let body = json!({
            "size": MAX_HITS,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {
                            "gte": from.to_rfc3339(),
                            "lte": to.to_rfc3339(),
                        }}},
                        {"bool": {"should": [
                            {"term": {"host.name": asset}},
                            {"term": {"agent.hostname": asset}},
                            {"term": {"host.hostname": asset}},
                            {"term": {"hostname": asset}},
                        ], "minimum_should_match": 1}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        });

        let url = format!(
            "{}/{}/_search",
            self.url.trim_end_matches('/'),
            self.index_pattern
        );

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.no_tls_verify)
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|e| SiemError::Other(format!("client build: {e}")))?;

        let mut req = client.post(&url).json(&body);
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("ApiKey {}", key));
        } else if let (Some(u), Some(p)) = (&self.username, &self.password) {
            req = req.basic_auth(u, Some(p));
        }

        let resp = req
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
            if let Some(entry) = parse_elastic_hit(&hit, self.skill_id()) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }
}

fn parse_elastic_hit(hit: &Value, source_skill: &str) -> Option<SiemLogEntry> {
    let src = &hit["_source"];

    let ts_str = src["@timestamp"].as_str()?;
    let timestamp = DateTime::parse_from_rfc3339(ts_str)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))?;

    // Asset selon les champs ECS standards
    let asset = src["host"]["name"]
        .as_str()
        .or_else(|| src["agent"]["hostname"].as_str())
        .or_else(|| src["host"]["hostname"].as_str())
        .or_else(|| src["hostname"].as_str())
        .unwrap_or("")
        .to_string();

    let level = src["log"]["level"]
        .as_str()
        .or_else(|| src["level"].as_str())
        .unwrap_or("info")
        .to_string();

    let message = src["message"]
        .as_str()
        .or_else(|| src["event"]["original"].as_str())
        .unwrap_or("")
        .to_string();

    let tags: Vec<String> = src["tags"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

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
    fn parse_hit_with_ecs_fields() {
        let hit = json!({
            "_source": {
                "@timestamp": "2026-05-05T10:00:00Z",
                "host": {"name": "srv-01"},
                "log": {"level": "warning"},
                "message": "User foo logged in from 10.0.0.5",
                "tags": ["auth", "ssh"]
            }
        });
        let entry = parse_elastic_hit(&hit, "skill-elastic-siem").unwrap();
        assert_eq!(entry.asset, "srv-01");
        assert_eq!(entry.level, "warning");
        assert!(entry.message.contains("foo"));
        assert_eq!(entry.tags, vec!["auth", "ssh"]);
    }

    #[test]
    fn parse_hit_falls_back_to_agent_hostname() {
        let hit = json!({
            "_source": {
                "@timestamp": "2026-05-05T10:00:00Z",
                "agent": {"hostname": "client-42"},
                "message": "x"
            }
        });
        let entry = parse_elastic_hit(&hit, "skill-elastic-siem").unwrap();
        assert_eq!(entry.asset, "client-42");
    }

    #[test]
    fn parse_hit_with_invalid_timestamp_returns_none() {
        let hit = json!({
            "_source": {
                "@timestamp": "not-a-date",
                "host": {"name": "x"}
            }
        });
        assert!(parse_elastic_hit(&hit, "skill-elastic-siem").is_none());
    }
}
