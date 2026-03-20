//! skill-abuseipdb — Vérification réputation IP via AbuseIPDB.
//!
//! API : GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}
//! Gratuit : 1000 req/jour

wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::{Deserialize, Serialize};

struct SkillAbuseIpdb;
export!(SkillAbuseIpdb);

#[derive(Deserialize)]
struct Params { ips: Vec<String> }

#[derive(Serialize)]
struct AbuseResult {
    ip: String,
    abuse_confidence_score: u32,
    total_reports: u32,
    country_code: String,
    isp: String,
    is_tor: bool,
    is_public: bool,
}

impl Guest for SkillAbuseIpdb {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-abuseipdb: starting");
        let params: Params = match serde_json::from_str(&req.params) {
            Ok(p) => p,
            Err(e) => return Response { output: None, error: Some(format!("Invalid params: {e}")) },
        };

        let mut results = Vec::new();
        for ip in &params.ips {
            let url = format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
            let resp = match host::http_request("GET", &url, "{\"Accept\": \"application/json\"}", None, Some(10000)) {
                Ok(r) => r,
                Err(e) => { host::log(host::LogLevel::Warn, &format!("AbuseIPDB error for {ip}: {e}")); continue; }
            };

            let body = String::from_utf8_lossy(&resp.body);
            let data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let d = &data["data"];

            let score = d["abuseConfidenceScore"].as_u64().unwrap_or(0) as u32;
            let reports = d["totalReports"].as_u64().unwrap_or(0) as u32;

            if score > 50 {
                let finding = serde_json::json!({
                    "skill_id": "skill-abuseipdb", "source": "abuseipdb", "category": "monitoring",
                    "title": format!("IP {ip} — score d'abus {score}% ({reports} signalements)"),
                    "severity": if score > 80 { "critical" } else { "high" },
                    "asset": ip,
                    "description": format!("ISP: {}, Pays: {}", d["isp"].as_str().unwrap_or("?"), d["countryCode"].as_str().unwrap_or("?")),
                });
                let body_bytes = serde_json::to_vec(&finding).unwrap_or_default();
                let _ = host::http_request("POST", "http://localhost:3000/api/tc/findings", "{}", Some(&body_bytes), Some(10000));
            }

            results.push(AbuseResult {
                ip: ip.clone(), abuse_confidence_score: score, total_reports: reports,
                country_code: d["countryCode"].as_str().unwrap_or("").to_string(),
                isp: d["isp"].as_str().unwrap_or("").to_string(),
                is_tor: d["isTor"].as_bool().unwrap_or(false),
                is_public: d["isPublic"].as_bool().unwrap_or(true),
            });
        }
        Response { output: Some(serde_json::to_string(&results).unwrap_or_default()), error: None }
    }

    fn schema() -> String {
        serde_json::json!({ "type": "object", "properties": { "ips": { "type": "array", "items": { "type": "string" } } }, "required": ["ips"] }).to_string()
    }

    fn description() -> String { "Vérification réputation IP via AbuseIPDB — score d'abus, signalements, ISP, pays.".to_string() }
}
