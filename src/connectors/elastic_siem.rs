//! Elastic Security Connector — import detection alerts via Kibana API.
//!
//! Auth: API Key (base64(id:secret)) or Basic auth
//! Alerts: POST /api/detection_engine/signals/search
//! Port: 5601 (HTTPS by default)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElasticSiemConfig {
    pub url: String,
    #[serde(default)]
    pub api_key_id: Option<String>,
    #[serde(default)]
    pub api_key_secret: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
    #[serde(default = "default_limit")]
    pub max_alerts: u32,
}

fn default_true() -> bool { true }
fn default_limit() -> u32 { 100 }

#[derive(Debug, Clone, Serialize)]
pub struct ElasticSiemSyncResult {
    pub alerts_imported: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_elastic_siem(store: &dyn Database, config: &ElasticSiemConfig) -> ElasticSiemSyncResult {
    let mut result = ElasticSiemSyncResult {
        alerts_imported: 0, findings_created: 0, errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("HTTP client: {}", e)); return result; }
    };

    let url = config.url.trim_end_matches('/');
    tracing::info!("ELASTIC: Connecting to {}", url);

    // Build auth header
    let mut req_builder = client.post(format!("{}/api/detection_engine/signals/search", url));

    if let (Some(id), Some(secret)) = (&config.api_key_id, &config.api_key_secret) {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", id, secret));
        req_builder = req_builder.header("Authorization", format!("ApiKey {}", encoded));
    } else if let (Some(user), Some(pass)) = (&config.username, &config.password) {
        req_builder = req_builder.basic_auth(user, Some(pass));
    } else {
        result.errors.push("No auth configured: set api_key_id+api_key_secret or username+password".into());
        return result;
    }

    // Search for open alerts from last 24h
    let body = serde_json::json!({
        "query": {
            "bool": {
                "filter": [
                    { "range": { "@timestamp": { "gte": "now-24h" } } },
                    { "term": { "signal.status": "open" } }
                ]
            }
        },
        "size": config.max_alerts,
        "sort": [{ "@timestamp": { "order": "desc" } }]
    });

    let resp = match req_builder
        .header("kbn-xsrf", "true")
        .header("Content-Type", "application/json")
        .json(&body)
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Request failed: {}", e)); return result; }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        result.errors.push(format!("HTTP {}: {}", status, &body_text[..body_text.len().min(200)]));
        return result;
    }

    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(e) => { result.errors.push(format!("Parse response: {}", e)); return result; }
    };

    let hits = match data["hits"]["hits"].as_array() {
        Some(h) => h,
        None => {
            tracing::info!("ELASTIC: No alerts found");
            return result;
        }
    };

    tracing::info!("ELASTIC: {} alerts found", hits.len());

    for hit in hits {
        let source = &hit["_source"];
        let signal = &source["signal"];

        let rule_name = signal["rule"]["name"].as_str().unwrap_or("Unknown rule");
        let rule_id = signal["rule"]["id"].as_str().unwrap_or("elastic-unknown");
        let severity = signal["rule"]["severity"].as_str().unwrap_or("medium");
        let hostname = source["host"]["name"].as_str().or_else(|| source["agent"]["name"].as_str());
        let source_ip = source["source"]["ip"].as_str();
        let username = source["user"]["name"].as_str();

        let tc_severity = match severity.to_lowercase().as_str() {
            "critical" => "CRITICAL",
            "high" => "HIGH",
            "medium" => "MEDIUM",
            _ => "LOW",
        };

        // Insert as sigma alert
        let _ = store.insert_sigma_alert(
            rule_id,
            tc_severity,
            rule_name,
            hostname.unwrap_or(""),
            source_ip,
            username,
        ).await;
        result.alerts_imported += 1;

        // Create finding for HIGH/CRITICAL
        if tc_severity == "HIGH" || tc_severity == "CRITICAL" {
            let _ = store.insert_finding(&NewFinding {
                skill_id: "skill-elastic-siem".into(),
                title: format!("[Elastic] {}", rule_name),
                description: Some(signal["rule"]["description"].as_str().unwrap_or("").to_string()),
                severity: tc_severity.into(),
                category: Some("siem".into()),
                asset: hostname.map(|s| s.to_string()),
                source: Some("Elastic Security".into()),
                metadata: Some(serde_json::json!({
                    "rule_id": rule_id,
                    "source_ip": source_ip,
                    "username": username,
                    "risk_score": signal["rule"]["risk_score"],
                })),
            }).await;
            result.findings_created += 1;
        }
    }

    tracing::info!("ELASTIC: Sync done — {} alerts, {} findings", result.alerts_imported, result.findings_created);
    result
}
