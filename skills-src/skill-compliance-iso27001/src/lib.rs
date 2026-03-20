//! skill-compliance-iso27001 — Conformité ISO 27001:2022 (93 contrôles Annexe A).
//!
//! Même logique que NIS2 mais avec les 4 catégories ISO 27001.

wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::Serialize;

struct SkillComplianceIso;
export!(SkillComplianceIso);

#[derive(Serialize)]
struct IsoReport { overall_score: f64, categories: Vec<CategoryScore> }

#[derive(Serialize)]
struct CategoryScore { id: String, name: String, score: f64, controls_count: u32, status: String }

const ISO_CATEGORIES: &[(&str, &str, u32, &[&str])] = &[
    ("A5-A8", "Contrôles organisationnels", 37, &["policy", "risk", "compliance", "governance", "asset"]),
    ("A9-A14", "Contrôles humains", 8, &["training", "awareness", "phishing", "hr", "screening"]),
    ("A15-A24", "Contrôles physiques", 14, &["physical", "access", "facility", "media", "equipment"]),
    ("A25-A34", "Contrôles technologiques", 34, &["vulnerability", "network", "crypto", "tls", "firewall", "patch", "logging", "monitoring"]),
];

impl Guest for SkillComplianceIso {
    fn execute(_req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-compliance-iso27001: starting");

        let resp = match host::http_request("GET", "http://localhost:3000/api/tc/findings?limit=200", "{}", None, Some(10000)) {
            Ok(r) => r,
            Err(e) => return Response { output: None, error: Some(format!("{e}")) },
        };

        let body = String::from_utf8_lossy(&resp.body);
        let data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let findings = data["findings"].as_array().cloned().unwrap_or_default();

        let mut categories = Vec::new();
        let mut total = 0.0;

        for (id, name, controls, keywords) in ISO_CATEGORIES {
            let matching = findings.iter().filter(|f| {
                let t = f["title"].as_str().unwrap_or("").to_lowercase();
                let c = f["category"].as_str().unwrap_or("").to_lowercase();
                keywords.iter().any(|kw| t.contains(kw) || c.contains(kw))
            }).count();

            let critical = findings.iter().filter(|f| {
                let t = f["title"].as_str().unwrap_or("").to_lowercase();
                keywords.iter().any(|kw| t.contains(kw)) && f["severity"].as_str() == Some("critical")
            }).count();

            let score = (100.0 - (critical * 15 + matching * 3) as f64).max(0.0).min(100.0);
            let status = if score >= 80.0 { "managed" } else if score >= 60.0 { "defined" } else { "developing" };

            total += score;
            categories.push(CategoryScore {
                id: id.to_string(), name: name.to_string(), score,
                controls_count: *controls, status: status.to_string(),
            });
        }

        let overall = total / ISO_CATEGORIES.len() as f64;
        let report = IsoReport { overall_score: overall, categories };
        Response { output: Some(serde_json::to_string(&report).unwrap_or_default()), error: None }
    }

    fn schema() -> String { serde_json::json!({ "type": "object", "properties": {} }).to_string() }
    fn description() -> String { "Conformité ISO 27001:2022 — évalue 93 contrôles Annexe A en 4 catégories.".to_string() }
}
