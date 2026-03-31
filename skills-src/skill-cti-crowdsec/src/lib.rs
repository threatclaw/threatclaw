//! skill-cti-crowdsec — Enrichissement IP via CrowdSec CTI API.
//!
//! Vérifie la réputation d'une IP suspecte dans la base CrowdSec communautaire.
//! API : GET https://cti.api.crowdsec.net/v2/smoke/{ip}
//! Limite : 50 req/jour (tier gratuit)

wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::{Deserialize, Serialize};

struct SkillCtiCrowdsec;
export!(SkillCtiCrowdsec);

#[derive(Deserialize)]
struct Params {
    ips: Vec<String>,
}

#[derive(Serialize)]
struct CtiResult {
    ip: String,
    reputation: String,
    confidence: f64,
    behaviors: Vec<String>,
    classifications: Vec<String>,
    error: Option<String>,
}

impl Guest for SkillCtiCrowdsec {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-cti-crowdsec: starting");

        let params: Params = match serde_json::from_str(&req.params) {
            Ok(p) => p,
            Err(e) => return Response { output: None, error: Some(format!("Invalid params: {e}")) },
        };

        let mut results = Vec::new();

        for ip in &params.ips {
            let url = format!("https://cti.api.crowdsec.net/v2/smoke/{ip}");

            let resp = match host::http_request("GET", &url, "{}", None, Some(10000)) {
                Ok(r) => r,
                Err(e) => {
                    results.push(CtiResult {
                        ip: ip.clone(), reputation: "unknown".into(), confidence: 0.0,
                        behaviors: vec![], classifications: vec![],
                        error: Some(format!("API error: {e}")),
                    });
                    continue;
                }
            };

            let body = String::from_utf8_lossy(&resp.body);
            let data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();

            let reputation = data["reputation"].as_str().unwrap_or("unknown").to_string();
            let confidence = data["scores"]["overall"]["total"].as_f64().unwrap_or(0.0);

            let behaviors: Vec<String> = data["behaviors"].as_array()
                .map(|arr| arr.iter().filter_map(|b| b["label"].as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            let classifications: Vec<String> = data["classifications"]["classifications"].as_array()
                .map(|arr| arr.iter().filter_map(|c| c["label"].as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            // If malicious → submit finding
            if reputation == "malicious" || confidence > 50.0 {
                let finding = serde_json::json!({
                    "skill_id": "skill-cti-crowdsec",
                    "title": format!("IP {ip} — réputation {reputation} (CrowdSec score: {confidence:.0})"),
                    "severity": if confidence > 80.0 { "critical" } else if confidence > 50.0 { "high" } else { "medium" },
                    "asset": ip, "source": "crowdsec-cti", "category": "monitoring",
                    "description": format!("Comportements: {}. Classifications: {}.", behaviors.join(", "), classifications.join(", ")),
                    "metadata": { "reputation": reputation, "score": confidence, "behaviors": behaviors, "classifications": classifications },
                });
                let body_bytes = serde_json::to_vec(&finding).unwrap_or_default();
                let _ = host::http_request("POST", "http://localhost:3000/api/tc/findings", "{}", Some(&body_bytes), Some(10000));
            }

            results.push(CtiResult { ip: ip.clone(), reputation, confidence, behaviors, classifications, error: None });
        }

        Response { output: Some(serde_json::to_string(&results).unwrap_or_default()), error: None }
    }

    fn schema() -> String {
        serde_json::json!({
            "type": "object",
            "properties": { "ips": { "type": "array", "items": { "type": "string" }, "description": "IPs à vérifier" } },
            "required": ["ips"]
        }).to_string()
    }

    fn description() -> String {
        "Enrichissement IP via CrowdSec CTI — vérifie la réputation, comportements et classifications des IPs suspectes.".to_string()
    }
}
