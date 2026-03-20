//! skill-darkweb-monitor — Surveillance fuites dark web via HIBP API.
//!
//! API : GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
//! Payant : ~$3.50/mois — clé API fournie par le client

wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::{Deserialize, Serialize};

struct SkillDarkwebMonitor;
export!(SkillDarkwebMonitor);

#[derive(Deserialize)]
struct Params { emails: Vec<String> }

#[derive(Serialize)]
struct BreachResult { email: String, breaches: Vec<BreachInfo>, total: usize }

#[derive(Serialize)]
struct BreachInfo { name: String, breach_date: String, data_classes: Vec<String>, is_verified: bool }

impl Guest for SkillDarkwebMonitor {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-darkweb-monitor: starting");
        let params: Params = match serde_json::from_str(&req.params) {
            Ok(p) => p, Err(e) => return Response { output: None, error: Some(format!("{e}")) },
        };

        let has_key = host::secret_exists("hibp_api_key");
        if !has_key {
            return Response { output: None, error: Some("Clé API HIBP non configurée. Abonnement requis (~$3.50/mois) sur haveibeenpwned.com/API/Key".to_string()) };
        }

        let mut results = Vec::new();
        for (i, email) in params.emails.iter().enumerate() {
            // Rate limit: 10 req/min — wait 6s between each (handled by host rate limiter)
            if i > 0 {
                host::log(host::LogLevel::Debug, "Waiting for rate limit...");
            }

            let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false");
            let resp = match host::http_request("GET", &url, "{\"user-agent\": \"ThreatClaw\"}", None, Some(15000)) {
                Ok(r) => r,
                Err(e) => {
                    host::log(host::LogLevel::Warn, &format!("HIBP error for {email}: {e}"));
                    results.push(BreachResult { email: email.clone(), breaches: vec![], total: 0 });
                    continue;
                }
            };

            if resp.status == 404 {
                results.push(BreachResult { email: email.clone(), breaches: vec![], total: 0 });
                continue;
            }

            let body = String::from_utf8_lossy(&resp.body);
            let data: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap_or_default();

            let breaches: Vec<BreachInfo> = data.iter().map(|b| BreachInfo {
                name: b["Name"].as_str().unwrap_or("").to_string(),
                breach_date: b["BreachDate"].as_str().unwrap_or("").to_string(),
                data_classes: b["DataClasses"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                is_verified: b["IsVerified"].as_bool().unwrap_or(false),
            }).collect();

            if !breaches.is_empty() {
                let critical = breaches.iter().any(|b| b.is_verified && b.data_classes.iter().any(|d| d.contains("Password")));
                let finding = serde_json::json!({
                    "skill_id": "skill-darkweb-monitor", "source": "hibp", "category": "monitoring",
                    "title": format!("{email} — {} fuite(s) détectée(s)", breaches.len()),
                    "severity": if critical { "critical" } else { "high" },
                    "asset": email,
                    "description": format!("Fuites: {}", breaches.iter().map(|b| b.name.as_str()).collect::<Vec<_>>().join(", ")),
                });
                let body_bytes = serde_json::to_vec(&finding).unwrap_or_default();
                let _ = host::http_request("POST", "http://localhost:3000/api/tc/findings", "{}", Some(&body_bytes), Some(10000));
            }

            let total = breaches.len();
            results.push(BreachResult { email: email.clone(), breaches, total });
        }

        Response { output: Some(serde_json::to_string(&results).unwrap_or_default()), error: None }
    }

    fn schema() -> String {
        serde_json::json!({ "type": "object", "properties": { "emails": { "type": "array", "items": { "type": "string" } } }, "required": ["emails"] }).to_string()
    }

    fn description() -> String { "Surveillance dark web — vérifie si les emails du client apparaissent dans des fuites de données (HIBP). Nécessite une clé API payante.".to_string() }
}
