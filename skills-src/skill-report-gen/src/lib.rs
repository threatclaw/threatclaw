//! skill-report-gen — Génération de rapports sécurité HTML en français.
//!
//! Lit les findings, alertes et métriques depuis l'API ThreatClaw et génère un rapport HTML.

wit_bindgen::generate!({ world: "sandboxed-tool", path: "../../wit" });

use exports::near::agent::tool::{Guest, Request, Response};
use near::agent::host;
use serde::Deserialize;

struct SkillReportGen;
export!(SkillReportGen);

#[derive(Deserialize)]
struct Params {
    report_type: Option<String>,
    company_name: Option<String>,
}

impl Guest for SkillReportGen {
    fn execute(req: Request) -> Response {
        host::log(host::LogLevel::Info, "skill-report-gen: starting");

        let params: Params = serde_json::from_str(&req.params).unwrap_or(Params { report_type: None, company_name: None });
        let company = params.company_name.unwrap_or_else(|| "Entreprise".to_string());
        let report_type = params.report_type.unwrap_or_else(|| "monthly".to_string());

        // Fetch metrics
        let metrics_resp = host::http_request("GET", "http://localhost:3000/api/tc/metrics", "{}", None, Some(10000));
        let metrics: serde_json::Value = metrics_resp.ok()
            .and_then(|r| serde_json::from_slice(&r.body).ok())
            .unwrap_or_default();
        let m = &metrics["metrics"];

        // Fetch findings
        let findings_resp = host::http_request("GET", "http://localhost:3000/api/tc/findings?limit=50", "{}", None, Some(10000));
        let findings: serde_json::Value = findings_resp.ok()
            .and_then(|r| serde_json::from_slice(&r.body).ok())
            .unwrap_or_default();
        let findings_list = findings["findings"].as_array().cloned().unwrap_or_default();

        let now = host::now_millis();
        let date = format!("Rapport généré le {}", now / 1000);

        // Generate HTML report
        let html = format!(r#"<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport Sécurité — {company}</title>
    <style>
        body {{ font-family: 'Inter', sans-serif; max-width: 800px; margin: 0 auto; padding: 40px; color: #2a1a10; }}
        h1 {{ color: #903020; border-bottom: 2px solid #903020; padding-bottom: 8px; }}
        h2 {{ color: #5a3a2a; margin-top: 32px; }}
        .metric {{ display: inline-block; text-align: center; margin: 16px; padding: 16px 24px; border: 1px solid #ddd; border-radius: 8px; }}
        .metric .value {{ font-size: 32px; font-weight: 800; }}
        .metric .label {{ font-size: 12px; color: #907060; text-transform: uppercase; }}
        .critical {{ color: #903020; }}
        .high {{ color: #906020; }}
        .medium {{ color: #5a6a4a; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #eee; font-size: 13px; }}
        th {{ background: #f5f0eb; font-weight: 700; text-transform: uppercase; font-size: 11px; color: #907060; }}
        .footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #ddd; font-size: 11px; color: #907060; }}
    </style>
</head>
<body>
    <h1>Rapport Sécurité — {company}</h1>
    <p style="color: #907060; font-size: 12px;">{date} · Type: {report_type} · Généré par ThreatClaw</p>

    <h2>Résumé</h2>
    <div>
        <div class="metric"><div class="value critical">{crit}</div><div class="label">Critiques</div></div>
        <div class="metric"><div class="value high">{high}</div><div class="label">Hautes</div></div>
        <div class="metric"><div class="value medium">{med}</div><div class="label">Moyennes</div></div>
        <div class="metric"><div class="value">{alerts}</div><div class="label">Alertes SOC</div></div>
    </div>

    <h2>Findings ({total})</h2>
    <table>
        <tr><th>Sévérité</th><th>Titre</th><th>Asset</th><th>Source</th></tr>
        {rows}
    </table>

    <div class="footer">
        <p>Ce rapport a été généré automatiquement par ThreatClaw.</p>
        <p>Conformité : NIS2 (Directive 2022/2555) · ISO 27001:2022</p>
    </div>
</body>
</html>"#,
            company = company,
            date = date,
            report_type = report_type,
            crit = m["findings_critical"].as_u64().unwrap_or(0),
            high = m["findings_high"].as_u64().unwrap_or(0),
            med = m["findings_medium"].as_u64().unwrap_or(0),
            alerts = m["alerts_total"].as_u64().unwrap_or(0),
            total = findings_list.len(),
            rows = findings_list.iter().take(30).map(|f| format!(
                "<tr><td class=\"{}\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                f["severity"].as_str().unwrap_or(""),
                f["severity"].as_str().unwrap_or("?"),
                f["title"].as_str().unwrap_or(""),
                f["asset"].as_str().unwrap_or(""),
                f["source"].as_str().unwrap_or(""),
            )).collect::<Vec<_>>().join("\n        "),
        );

        host::log(host::LogLevel::Info, &format!("Report generated: {} findings", findings_list.len()));
        Response { output: Some(html), error: None }
    }

    fn schema() -> String {
        serde_json::json!({
            "type": "object",
            "properties": {
                "report_type": { "type": "string", "enum": ["monthly", "weekly", "nis2", "executive"], "default": "monthly" },
                "company_name": { "type": "string", "default": "Entreprise" }
            }
        }).to_string()
    }

    fn description() -> String { "Génération de rapports sécurité HTML en français — mensuel, hebdomadaire, NIS2, brief exécutif.".to_string() }
}
