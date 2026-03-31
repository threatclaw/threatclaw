//! skill-shodan — Surface d'attaque externe via Shodan API.
//!
//! Vérifie si les IPs/domaines du client sont exposés sur Internet.
//! API : GET https://api.shodan.io/shodan/host/{ip}?key={key}
//! Payant : $49/an pour l'API basique

wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::{Deserialize, Serialize};

struct SkillShodan;
export!(SkillShodan);

#[derive(Deserialize)]
struct Params { targets: Vec<String> }

#[derive(Serialize)]
struct ShodanResult {
    ip: String, ports: Vec<u16>, vulns: Vec<String>, os: String,
    org: String, hostnames: Vec<String>, last_update: String,
}

impl Guest for SkillShodan {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-shodan: starting");

        if !host::secret_exists("shodan_api_key") {
            return Response { output: None, error: Some("Clé API Shodan non configurée. Abonnement requis ($49/an) sur shodan.io.".to_string()) };
        }

        let params: Params = match serde_json::from_str(&req.params) {
            Ok(p) => p, Err(e) => return Response { output: None, error: Some(format!("{e}")) },
        };

        let mut results = Vec::new();
        for target in &params.targets {
            let url = format!("https://api.shodan.io/shodan/host/{target}");
            match host::http_request("GET", &url, "{}", None, Some(15000)) {
                Ok(r) => {
                    let body = String::from_utf8_lossy(&r.body);
                    let data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();

                    let ports: Vec<u16> = data["ports"].as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect())
                        .unwrap_or_default();

                    let vulns: Vec<String> = data["vulns"].as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default();

                    // Findings for exposed services
                    if !ports.is_empty() {
                        let severity = if vulns.iter().any(|v| v.starts_with("CVE-")) { "high" }
                            else if ports.len() > 5 { "medium" } else { "low" };

                        let finding = serde_json::json!({
                            "skill_id": "skill-shodan", "source": "shodan", "category": "scanning",
                            "title": format!("{target} — {} ports exposés sur Internet", ports.len()),
                            "severity": severity,
                            "asset": target,
                            "description": format!("Ports: {:?}. CVEs: {}.", ports, if vulns.is_empty() { "aucun".to_string() } else { vulns.join(", ") }),
                            "metadata": { "ports": ports, "vulns": vulns },
                        });
                        let bytes = serde_json::to_vec(&finding).unwrap_or_default();
                        let _ = host::http_request("POST", "http://localhost:3000/api/tc/findings", "{}", Some(&bytes), Some(10000));
                    }

                    results.push(ShodanResult {
                        ip: target.clone(), ports, vulns,
                        os: data["os"].as_str().unwrap_or("").to_string(),
                        org: data["org"].as_str().unwrap_or("").to_string(),
                        hostnames: data["hostnames"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default(),
                        last_update: data["last_update"].as_str().unwrap_or("").to_string(),
                    });
                }
                Err(e) => host::log(host::LogLevel::Warn, &format!("Shodan error for {target}: {e}")),
            }
        }

        Response { output: Some(serde_json::to_string(&results).unwrap_or_default()), error: None }
    }

    fn schema() -> String {
        serde_json::json!({ "type": "object", "properties": { "targets": { "type": "array", "items": { "type": "string" }, "description": "IPs ou domaines à vérifier" } }, "required": ["targets"] }).to_string()
    }

    fn description() -> String { "Surface d'attaque externe — vérifie si les IPs/domaines sont exposés sur Internet via Shodan. Clé API payante.".to_string() }
}
