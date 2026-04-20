//! NIST AI Risk Management Framework 1.0 (janvier 2023, mise à jour 2025).
//!
//! Structuré en 4 fonctions interdépendantes :
//!   - GOVERN  : politiques, rôles, responsabilités, culture
//!   - MAP     : inventaire et contexte des systèmes IA
//!   - MEASURE : métriques, tests, évaluations des risques IA
//!   - MANAGE  : traitement des risques (mitigate / accept / avoid / transfer)
//!
//! La révision 2025 nomme **explicitement shadow AI** dans l'inventaire
//! obligatoire (MAP) — c'est un argument fort côté communication US.
//!
//! Référence : NIST AI 100-1 (Jan 2023) + profile updates 2025.

use super::{
    ArticleScore, ComplianceInput, ComplianceReport, matches_any_keyword, maturity_label,
    score_from_hits,
};

pub fn evaluate(input: &ComplianceInput<'_>) -> ComplianceReport {
    let articles: Vec<ArticleScore> = FUNCTIONS.iter().map(|f| score_function(f, input)).collect();

    let total: i32 = articles.iter().map(|a| a.score).sum();
    let overall = if articles.is_empty() {
        100
    } else {
        total / articles.len() as i32
    };

    let gaps: Vec<String> = articles
        .iter()
        .filter(|a| a.score < 50)
        .map(|a| a.id.clone())
        .collect();

    let critical_findings = input
        .findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("critical"))
        .count() as i32;

    ComplianceReport {
        framework: "nist_ai_rmf".into(),
        framework_label: "NIST AI RMF 1.0 (2025)".into(),
        overall_score: overall,
        maturity_label: maturity_label(overall).into(),
        articles,
        gaps,
        total_findings: input.findings.len() as i32,
        critical_findings,
    }
}

struct Function {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    keywords: &'static [&'static str],
    action: &'static str,
}

const FUNCTIONS: &[Function] = &[
    Function {
        id: "GOVERN",
        title: "Govern — policies, roles, culture",
        description: "Politiques IA, responsabilités, conformité réglementaire, culture sécurité.",
        keywords: &[
            "ai policy",
            "ai governance",
            "ai_governance",
            "ai_usage_policy",
            "governance",
            "gouvernance",
            "compliance",
            "conformité",
            "accountability",
            "responsabilité",
            "oversight",
            "supervision",
        ],
        action: "Définir les rôles (RSSI + Data Protection Officer) et la politique IA organisationnelle",
    },
    Function {
        id: "MAP",
        title: "Map — AI system inventory & context",
        description: "Inventaire des systèmes IA (incluant SHADOW AI nommément depuis révision 2025).",
        keywords: &[
            "inventory",
            "inventaire",
            "shadow ai",
            "shadow_ai",
            "ai.shadow",
            "ai_usage_policy",
            "chatgpt",
            "claude",
            "gemini",
            "mistral",
            "copilot",
            "ollama",
            "llm",
            "asset",
            "third-party",
            "tiers",
        ],
        action: "Compléter l'inventaire IA (déclarées + détectées en shadow) avec contexte d'usage",
    },
    Function {
        id: "MEASURE",
        title: "Measure — metrics, testing, evaluation",
        description: "Mesure des risques IA : bais, robustesse, explicabilité, sécurité, confidentialité.",
        keywords: &[
            "test",
            "evaluation",
            "évaluation",
            "metric",
            "métrique",
            "benchmark",
            "bias",
            "biais",
            "robustness",
            "robustesse",
            "adversarial",
            "explainability",
            "ai_risk_assessment",
            "impact assessment",
            "red team",
            "garak",
        ],
        action: "Mettre en place des mesures de risque IA (benchmarks adversariaux, red-teaming Garak)",
    },
    Function {
        id: "MANAGE",
        title: "Manage — risk treatment & response",
        description: "Traitement des risques IA (mitigate, accept, avoid, transfer) + incident response.",
        keywords: &[
            "mitigate",
            "mitigation",
            "atténuation",
            "remediation",
            "remédiation",
            "accept",
            "transfer",
            "hitl",
            "human in the loop",
            "approval",
            "approbation",
            "incident response",
            "réponse incident",
            "ai_usage_policy",
        ],
        action: "Définir les seuils d'acceptation + activer HITL sur les actions IA sensibles",
    },
];

fn score_function(func: &Function, input: &ComplianceInput<'_>) -> ArticleScore {
    let mut critical = 0i32;
    let mut high = 0i32;
    let mut medium = 0i32;
    let mut relevant = 0i32;

    for f in input.findings {
        let title = f.title.as_str();
        let desc = f.description.as_deref().unwrap_or("");
        let category = f.category.as_deref().unwrap_or("");
        let skill = f.skill_id.as_str();
        if matches_any_keyword(&[title, desc, category, skill], func.keywords) {
            relevant += 1;
            match f.severity.to_lowercase().as_str() {
                "critical" => critical += 1,
                "high" => high += 1,
                "medium" => medium += 1,
                _ => {}
            }
        }
    }

    let score = if relevant == 0 {
        50
    } else {
        score_from_hits(critical, high, medium)
    };

    let top_recommendation = if relevant > 0 {
        Some(func.action.to_string())
    } else {
        None
    };

    ArticleScore {
        id: func.id.to_string(),
        title: func.title.to_string(),
        description: func.description.to_string(),
        score,
        relevant_findings: relevant,
        critical_hits: critical,
        high_hits: high,
        medium_hits: medium,
        top_recommendation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::threatclaw_store::FindingRecord;

    fn fake_finding(severity: &str, title: &str, category: &str) -> FindingRecord {
        FindingRecord {
            id: 1,
            skill_id: "test".into(),
            title: title.into(),
            description: None,
            severity: severity.into(),
            status: "open".into(),
            category: Some(category.into()),
            asset: None,
            source: None,
            metadata: serde_json::json!({}),
            detected_at: "2026-04-20T10:00:00Z".into(),
            resolved_at: None,
            resolved_by: None,
        }
    }

    #[test]
    fn empty_input_yields_50_on_4_functions() {
        let input = ComplianceInput {
            findings: &[],
            alerts: &[],
            assets: &[],
        };
        let report = evaluate(&input);
        assert_eq!(report.articles.len(), 4);
        assert_eq!(report.overall_score, 50);
    }

    #[test]
    fn shadow_ai_finding_hits_map_function() {
        let findings = vec![fake_finding(
            "medium",
            "Shadow AI — ChatGPT via api.openai.com",
            "AI_USAGE_POLICY",
        )];
        let input = ComplianceInput {
            findings: &findings,
            alerts: &[],
            assets: &[],
        };
        let report = evaluate(&input);
        let map = report.articles.iter().find(|a| a.id == "MAP").unwrap();
        assert!(
            map.relevant_findings >= 1,
            "Shadow AI must hit MAP per 2025 revision (explicit inventory control)"
        );
    }
}
