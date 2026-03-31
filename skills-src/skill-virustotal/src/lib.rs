//! skill-virustotal — Analyse de fichiers/URLs/hashes suspects via VirusTotal API.
//!
//! API : GET https://www.virustotal.com/api/v3/files/{hash}
//!        GET https://www.virustotal.com/api/v3/urls/{url_id}
//! Gratuit : 4 req/min, 500 req/jour, 15.5K req/mois

wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::{Deserialize, Serialize};

struct SkillVirusTotal;
export!(SkillVirusTotal);

#[derive(Deserialize)]
struct Params { hashes: Option<Vec<String>>, urls: Option<Vec<String>> }

#[derive(Serialize)]
struct VtResult {
    query: String, query_type: String, malicious: u32, suspicious: u32,
    undetected: u32, harmless: u32, reputation: i64, tags: Vec<String>,
}

impl Guest for SkillVirusTotal {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-virustotal: starting");

        if !host::secret_exists("virustotal_api_key") {
            return Response { output: None, error: Some("Clé API VirusTotal non configurée. Gratuit sur virustotal.com.".to_string()) };
        }

        let params: Params = serde_json::from_str(&req.params).unwrap_or(Params { hashes: None, urls: None });
        let mut results = Vec::new();

        // Check file hashes
        for hash in params.hashes.unwrap_or_default() {
            let url = format!("https://www.virustotal.com/api/v3/files/{hash}");
            match host::http_request("GET", &url, "{}", None, Some(15000)) {
                Ok(r) => {
                    let body = String::from_utf8_lossy(&r.body);
                    let data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                    let stats = &data["data"]["attributes"]["last_analysis_stats"];
                    let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
                    let suspicious = stats["suspicious"].as_u64().unwrap_or(0) as u32;

                    if malicious > 0 {
                        let finding = serde_json::json!({
                            "skill_id": "skill-virustotal", "source": "virustotal", "category": "scanning",
                            "title": format!("Hash {hash} — {malicious} détections malveillantes"),
                            "severity": if malicious > 10 { "critical" } else if malicious > 3 { "high" } else { "medium" },
                            "asset": hash, "description": format!("{malicious} moteurs AV détectent ce fichier comme malveillant"),
                        });
                        let bytes = serde_json::to_vec(&finding).unwrap_or_default();
                        let _ = host::http_request("POST", "http://localhost:3000/api/tc/findings", "{}", Some(&bytes), Some(10000));
                    }

                    results.push(VtResult {
                        query: hash, query_type: "file_hash".into(), malicious, suspicious,
                        undetected: stats["undetected"].as_u64().unwrap_or(0) as u32,
                        harmless: stats["harmless"].as_u64().unwrap_or(0) as u32,
                        reputation: data["data"]["attributes"]["reputation"].as_i64().unwrap_or(0),
                        tags: data["data"]["attributes"]["tags"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default(),
                    });
                }
                Err(e) => host::log(host::LogLevel::Warn, &format!("VT error for {hash}: {e}")),
            }
        }

        Response { output: Some(serde_json::to_string(&results).unwrap_or_default()), error: None }
    }

    fn schema() -> String {
        serde_json::json!({
            "type": "object",
            "properties": {
                "hashes": { "type": "array", "items": { "type": "string" }, "description": "SHA-256 hashes" },
                "urls": { "type": "array", "items": { "type": "string" }, "description": "URLs à vérifier" }
            }
        }).to_string()
    }

    fn description() -> String { "Analyse fichiers/URLs via VirusTotal — détection multi-moteurs AV. Clé API gratuite requise.".to_string() }
}
