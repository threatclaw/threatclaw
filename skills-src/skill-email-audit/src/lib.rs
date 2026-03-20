//! skill-email-audit — Audit sécurité email (SPF/DKIM/DMARC)
//!
//! Skill officiel ThreatClaw en Rust/WASM.
//! Vérifie les enregistrements DNS de sécurité email pour les domaines configurés.
//! Aucun outil externe nécessaire — requêtes DNS via l'API HTTP de résolveurs publics.

wit_bindgen::generate!({
    world: "sandboxed-tool",
    path: "../../wit",
});

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::{Deserialize, Serialize};

struct SkillEmailAudit;

export!(SkillEmailAudit);

#[derive(Deserialize)]
struct Params {
    domains: Vec<String>,
}

#[derive(Serialize)]
struct EmailAuditResult {
    domain: String,
    spf: DnsCheckResult,
    dmarc: DnsCheckResult,
    findings: Vec<Finding>,
}

#[derive(Serialize)]
struct DnsCheckResult {
    found: bool,
    record: Option<String>,
    secure: bool,
    issues: Vec<String>,
}

#[derive(Serialize)]
struct Finding {
    title: String,
    severity: String,
    asset: String,
    description: String,
}

impl Guest for SkillEmailAudit {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-email-audit: starting");

        let params: Params = match serde_json::from_str(&req.params) {
            Ok(p) => p,
            Err(e) => return Response {
                output: None,
                error: Some(format!("Invalid params: {e}")),
            },
        };

        if params.domains.is_empty() {
            return Response {
                output: None,
                error: Some("No domains specified".to_string()),
            };
        }

        let mut all_results = Vec::new();

        for domain in &params.domains {
            host::log(host::LogLevel::Info, &format!("Checking {domain}"));

            let spf = check_spf(domain);
            let dmarc = check_dmarc(domain);

            let mut findings = Vec::new();

            // SPF findings
            if !spf.found {
                findings.push(Finding {
                    title: format!("SPF manquant sur {domain}"),
                    severity: "high".to_string(),
                    asset: domain.clone(),
                    description: "Aucun enregistrement SPF trouvé. Les emails peuvent être usurpés.".to_string(),
                });
            } else if !spf.secure {
                for issue in &spf.issues {
                    findings.push(Finding {
                        title: format!("SPF faible sur {domain}"),
                        severity: "medium".to_string(),
                        asset: domain.clone(),
                        description: issue.clone(),
                    });
                }
            }

            // DMARC findings
            if !dmarc.found {
                findings.push(Finding {
                    title: format!("DMARC manquant sur {domain}"),
                    severity: "high".to_string(),
                    asset: domain.clone(),
                    description: "Aucun enregistrement DMARC trouvé. Pas de politique anti-spoofing.".to_string(),
                });
            } else if !dmarc.secure {
                for issue in &dmarc.issues {
                    findings.push(Finding {
                        title: format!("DMARC faible sur {domain}"),
                        severity: "medium".to_string(),
                        asset: domain.clone(),
                        description: issue.clone(),
                    });
                }
            }

            // Push findings to ThreatClaw API
            for finding in &findings {
                let body = serde_json::json!({
                    "skill_id": "skill-email-audit",
                    "title": finding.title,
                    "severity": finding.severity,
                    "asset": finding.asset,
                    "source": "dns",
                    "category": "compliance",
                    "description": finding.description,
                });

                let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

                match host::http_request(
                    "POST",
                    "http://localhost:3000/api/tc/findings",
                    "{}",
                    Some(&body_bytes),
                    Some(10000),
                ) {
                    Ok(_) => host::log(host::LogLevel::Info, &format!("Finding submitted: {}", finding.title)),
                    Err(e) => host::log(host::LogLevel::Warn, &format!("Failed to submit finding: {e}")),
                }
            }

            all_results.push(EmailAuditResult {
                domain: domain.clone(),
                spf,
                dmarc,
                findings,
            });
        }

        let output = serde_json::to_string(&all_results).unwrap_or_default();
        host::log(host::LogLevel::Info, &format!("skill-email-audit: complete, {} domains checked", all_results.len()));

        Response {
            output: Some(output),
            error: None,
        }
    }

    fn schema() -> String {
        serde_json::json!({
            "type": "object",
            "properties": {
                "domains": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Domaines à auditer (ex: ['example.com', 'corp.fr'])"
                }
            },
            "required": ["domains"]
        }).to_string()
    }

    fn description() -> String {
        "Audit sécurité email — vérifie les enregistrements SPF, DKIM et DMARC des domaines configurés. Détecte les configurations faibles ou manquantes.".to_string()
    }
}

/// Check SPF record via DNS-over-HTTPS (Cloudflare).
fn check_spf(domain: &str) -> DnsCheckResult {
    let url = format!("https://cloudflare-dns.com/dns-query?name={domain}&type=TXT");

    let response = match host::http_request("GET", &url, "{\"Accept\": \"application/dns-json\"}", None, Some(5000)) {
        Ok(r) => r,
        Err(e) => {
            host::log(host::LogLevel::Warn, &format!("DNS query failed for {domain}: {e}"));
            return DnsCheckResult { found: false, record: None, secure: false, issues: vec!["DNS query failed".to_string()] };
        }
    };

    let body = String::from_utf8_lossy(&response.body);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();

    let mut spf_record = None;
    if let Some(answers) = data["Answer"].as_array() {
        for answer in answers {
            if let Some(txt) = answer["data"].as_str() {
                let clean = txt.trim_matches('"');
                if clean.starts_with("v=spf1") {
                    spf_record = Some(clean.to_string());
                    break;
                }
            }
        }
    }

    match spf_record {
        None => DnsCheckResult { found: false, record: None, secure: false, issues: vec![] },
        Some(record) => {
            let mut issues = Vec::new();
            let mut secure = true;

            if record.contains("+all") {
                issues.push("SPF policy '+all' autorise tous les serveurs — pas de protection".to_string());
                secure = false;
            }
            if record.contains("~all") {
                issues.push("SPF policy '~all' (softfail) — les emails usurpés passent en soft-reject".to_string());
                secure = false;
            }
            if !record.contains("-all") && !record.contains("+all") && !record.contains("~all") {
                issues.push("SPF ne se termine pas par '-all' — politique incomplète".to_string());
                secure = false;
            }

            DnsCheckResult { found: true, record: Some(record), secure, issues }
        }
    }
}

/// Check DMARC record via DNS-over-HTTPS.
fn check_dmarc(domain: &str) -> DnsCheckResult {
    let url = format!("https://cloudflare-dns.com/dns-query?name=_dmarc.{domain}&type=TXT");

    let response = match host::http_request("GET", &url, "{\"Accept\": \"application/dns-json\"}", None, Some(5000)) {
        Ok(r) => r,
        Err(e) => {
            host::log(host::LogLevel::Warn, &format!("DMARC DNS query failed for {domain}: {e}"));
            return DnsCheckResult { found: false, record: None, secure: false, issues: vec!["DNS query failed".to_string()] };
        }
    };

    let body = String::from_utf8_lossy(&response.body);
    let data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();

    let mut dmarc_record = None;
    if let Some(answers) = data["Answer"].as_array() {
        for answer in answers {
            if let Some(txt) = answer["data"].as_str() {
                let clean = txt.trim_matches('"');
                if clean.starts_with("v=DMARC1") {
                    dmarc_record = Some(clean.to_string());
                    break;
                }
            }
        }
    }

    match dmarc_record {
        None => DnsCheckResult { found: false, record: None, secure: false, issues: vec![] },
        Some(record) => {
            let mut issues = Vec::new();
            let mut secure = true;

            if record.contains("p=none") {
                issues.push("DMARC policy 'none' — pas de protection active contre le spoofing".to_string());
                secure = false;
            }
            if !record.contains("rua=") {
                issues.push("DMARC sans adresse de rapport (rua) — pas de visibilité sur les échecs".to_string());
            }

            DnsCheckResult { found: true, record: Some(record), secure, issues }
        }
    }
}
