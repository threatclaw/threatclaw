//! skill-compliance-nis2 — Conformité NIS2 Art.21 mapping.
//!
//! Lit les findings existants et les mappe vers les 10 articles de NIS2 Art.21.
//! Calcule un score de conformité par article. Pas d'outil externe.

wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::Serialize;

struct SkillComplianceNis2;
export!(SkillComplianceNis2);

#[derive(Serialize)]
struct Nis2Report {
    overall_score: f64,
    articles: Vec<ArticleScore>,
}

#[derive(Serialize)]
struct ArticleScore {
    id: String,
    name: String,
    score: f64,
    max_score: f64,
    findings_count: u32,
    status: String,
}

const NIS2_ARTICLES: &[(&str, &str, &[&str])] = &[
    ("art21_2a", "Analyse des risques et sécurité SI", &["vulnerability", "scanning", "risk"]),
    ("art21_2b", "Gestion des incidents", &["alert", "incident", "soc", "sigma"]),
    ("art21_2c", "Continuité d'activité", &["backup", "disaster", "recovery"]),
    ("art21_2d", "Sécurité chaîne d'approvisionnement", &["supply", "vendor", "dependency", "sbom"]),
    ("art21_2e", "Sécurité réseaux et SI", &["network", "firewall", "port", "tls", "ssl"]),
    ("art21_2f", "Gestion des vulnérabilités", &["cve", "patch", "update", "vulnerability"]),
    ("art21_2g", "Formation cybersécurité", &["phishing", "awareness", "training"]),
    ("art21_2h", "Cryptographie", &["crypto", "encryption", "tls", "certificate"]),
    ("art21_2i", "RH et contrôle d'accès", &["access", "user", "password", "mfa", "ad"]),
    ("art21_2j", "MFA et communications sécurisées", &["mfa", "2fa", "signal", "encrypted"]),
];

impl Guest for SkillComplianceNis2 {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-compliance-nis2: starting");

        // Fetch findings from ThreatClaw API
        let resp = match host::http_request("GET", "http://localhost:3000/api/tc/findings?limit=200", "{}", None, Some(10000)) {
            Ok(r) => r,
            Err(e) => return Response { output: None, error: Some(format!("Cannot fetch findings: {e}")) },
        };

        let body = String::from_utf8_lossy(&resp.body);
        let data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let findings = data["findings"].as_array().cloned().unwrap_or_default();

        let mut articles = Vec::new();
        let mut total_score = 0.0;

        for (id, name, keywords) in NIS2_ARTICLES {
            // Count findings matching this article's keywords
            let matching: Vec<&serde_json::Value> = findings.iter().filter(|f| {
                let title = f["title"].as_str().unwrap_or("").to_lowercase();
                let desc = f["description"].as_str().unwrap_or("").to_lowercase();
                let cat = f["category"].as_str().unwrap_or("").to_lowercase();
                keywords.iter().any(|kw| title.contains(kw) || desc.contains(kw) || cat.contains(kw))
            }).collect();

            let critical = matching.iter().filter(|f| f["severity"].as_str() == Some("critical")).count();
            let high = matching.iter().filter(|f| f["severity"].as_str() == Some("high")).count();
            let resolved = matching.iter().filter(|f| f["status"].as_str() == Some("resolved")).count();

            // Score: start at 100, subtract per unresolved finding
            let penalty = (critical * 20 + high * 10 + (matching.len() - resolved) * 5) as f64;
            let score = (100.0 - penalty).max(0.0).min(100.0);

            let status = if score >= 80.0 { "managed" }
                else if score >= 60.0 { "defined" }
                else if score >= 40.0 { "developing" }
                else { "initial" };

            total_score += score;
            articles.push(ArticleScore {
                id: id.to_string(),
                name: name.to_string(),
                score,
                max_score: 100.0,
                findings_count: matching.len() as u32,
                status: status.to_string(),
            });
        }

        let overall = total_score / NIS2_ARTICLES.len() as f64;

        // Submit overall score as metric
        let metric = serde_json::json!({
            "skill_id": "skill-compliance-nis2", "title": format!("Score NIS2 global: {overall:.0}%"),
            "severity": "info", "asset": "compliance", "source": "nis2-mapping", "category": "compliance",
        });
        let body_bytes = serde_json::to_vec(&metric).unwrap_or_default();
        let _ = host::http_request("POST", "http://localhost:3000/api/tc/findings", "{}", Some(&body_bytes), Some(10000));

        let report = Nis2Report { overall_score: overall, articles };
        Response { output: Some(serde_json::to_string(&report).unwrap_or_default()), error: None }
    }

    fn schema() -> String {
        serde_json::json!({ "type": "object", "properties": {} }).to_string()
    }

    fn description() -> String {
        "Conformité NIS2 — mappe les findings vers les 10 articles de la directive 2022/2555 Art.21. Calcule un score de maturité par article.".to_string()
    }
}
