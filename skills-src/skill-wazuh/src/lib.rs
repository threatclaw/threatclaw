//! skill-wazuh — Connexion Wazuh SIEM existant.
//!
//! Se connecte à un serveur Wazuh existant via son API REST.
//! Récupère les alertes et les injecte dans ThreatClaw pour corrélation.
//! API : GET https://<wazuh>:55000/security/user/authenticate → token
//!       GET https://<wazuh>:55000/alerts?limit=100&sort=-timestamp

wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::{Deserialize, Serialize};

struct SkillWazuh;
export!(SkillWazuh);

#[derive(Deserialize)]
struct Params {
    #[serde(default = "default_limit")]
    limit: u32,
    #[serde(default)]
    level_min: Option<u32>,
}

fn default_limit() -> u32 { 50 }

#[derive(Serialize)]
struct WazuhAlert {
    id: String,
    timestamp: String,
    rule_id: String,
    rule_description: String,
    rule_level: u32,
    agent_name: String,
    agent_ip: String,
}

impl Guest for SkillWazuh {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-wazuh: starting — connecting to Wazuh API");

        let params: Params = serde_json::from_str(&req.params).unwrap_or(Params { limit: 50, level_min: None });

        // Check if Wazuh credentials are configured
        if !host::secret_exists("wazuh_api_user") {
            return Response { output: None, error: Some("Wazuh API credentials not configured. Add wazuh_api_user and wazuh_api_password in Config > Skills.".to_string()) };
        }

        // Step 1: Authenticate to Wazuh API
        // The host will inject the credentials automatically via the allowlist
        let auth_resp = match host::http_request(
            "POST", "https://localhost:55000/security/user/authenticate",
            "{\"Content-Type\": \"application/json\"}", None, Some(10000),
        ) {
            Ok(r) => r,
            Err(e) => return Response { output: None, error: Some(format!("Wazuh auth failed: {e}")) },
        };

        let auth_body = String::from_utf8_lossy(&auth_resp.body);
        let auth_data: serde_json::Value = serde_json::from_str(&auth_body).unwrap_or_default();
        let token = auth_data["data"]["token"].as_str().unwrap_or("");

        if token.is_empty() {
            return Response { output: None, error: Some("Wazuh: empty token — check credentials".to_string()) };
        }

        // Step 2: Fetch alerts
        let level_filter = params.level_min.map(|l| format!("&level={l}..")).unwrap_or_default();
        let alerts_url = format!(
            "https://localhost:55000/alerts?limit={}&sort=-timestamp&pretty=false{level_filter}",
            params.limit
        );
        let headers = format!("{{\"Authorization\": \"Bearer {token}\"}}");

        let alerts_resp = match host::http_request("GET", &alerts_url, &headers, None, Some(15000)) {
            Ok(r) => r,
            Err(e) => return Response { output: None, error: Some(format!("Wazuh alerts fetch failed: {e}")) },
        };

        let alerts_body = String::from_utf8_lossy(&alerts_resp.body);
        let alerts_data: serde_json::Value = serde_json::from_str(&alerts_body).unwrap_or_default();

        let items = alerts_data["data"]["affected_items"].as_array().cloned().unwrap_or_default();
        let mut results = Vec::new();

        for item in &items {
            let rule_level = item["rule"]["level"].as_u64().unwrap_or(0) as u32;
            let rule_desc = item["rule"]["description"].as_str().unwrap_or("").to_string();
            let agent_name = item["agent"]["name"].as_str().unwrap_or("").to_string();
            let agent_ip = item["agent"]["ip"].as_str().unwrap_or("").to_string();
            let rule_id = item["rule"]["id"].as_str().unwrap_or("").to_string();
            let timestamp = item["timestamp"].as_str().unwrap_or("").to_string();
            let alert_id = item["id"].as_str().unwrap_or("").to_string();

            // Map Wazuh level to severity
            let severity = match rule_level {
                0..=5 => "low",
                6..=10 => "medium",
                11..=13 => "high",
                _ => "critical",
            };

            // Push finding to ThreatClaw
            let finding = serde_json::json!({
                "skill_id": "skill-wazuh", "source": "wazuh", "category": "monitoring",
                "title": format!("[Wazuh L{}] {}", rule_level, rule_desc),
                "severity": severity,
                "asset": format!("{} ({})", agent_name, agent_ip),
                "description": format!("Rule: {} | Agent: {} | Level: {}", rule_id, agent_name, rule_level),
                "metadata": { "wazuh_rule_id": rule_id, "wazuh_level": rule_level, "agent_ip": agent_ip },
            });
            let body_bytes = serde_json::to_vec(&finding).unwrap_or_default();
            let _ = host::http_request("POST", "http://localhost:3000/api/tc/findings", "{}", Some(&body_bytes), Some(10000));

            results.push(WazuhAlert {
                id: alert_id, timestamp, rule_id, rule_description: rule_desc,
                rule_level, agent_name, agent_ip,
            });
        }

        host::log(host::LogLevel::Info, &format!("skill-wazuh: {} alerts imported", results.len()));
        Response { output: Some(serde_json::to_string(&results).unwrap_or_default()), error: None }
    }

    fn schema() -> String {
        serde_json::json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "default": 50, "description": "Max alertes à récupérer" },
                "level_min": { "type": "integer", "description": "Niveau minimum Wazuh (1-15)" }
            }
        }).to_string()
    }

    fn description() -> String {
        "Connexion Wazuh SIEM — récupère les alertes du serveur Wazuh existant et les injecte pour corrélation IA.".to_string()
    }
}
