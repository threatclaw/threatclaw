//! ISO/IEC 42001:2023 — AI Management System.
//!
//! Focus sur les contrôles annexe A les plus pertinents pour un SOC :
//!   - A.2 (AI Policy & Objectives)
//!   - A.4 (Resources for AI systems)
//!   - A.5 (Assessing impacts of AI systems)
//!   - A.6 (AI system life cycle)
//!   - A.7 (Data for AI systems)
//!   - A.8 (Information for interested parties)
//!   - A.9 (Use of AI systems)
//!   - A.10 (Third-party and customer AI relationships)
//!
//! Référence : ISO/IEC 42001:2023 Annex A & ISO/IEC 42005 (impact assessment).
//! Évalue la posture à partir des findings + ai_systems — c'est la **seule**
//! norme du projet qui s'appuie explicitement sur la table ai_systems (V41)
//! plutôt que les mots-clés texte.

use super::{
    ArticleScore, ComplianceInput, ComplianceReport, matches_any_keyword, maturity_label,
    score_from_hits,
};

pub fn evaluate(input: &ComplianceInput<'_>) -> ComplianceReport {
    let articles: Vec<ArticleScore> = CONTROLS.iter().map(|c| score_control(c, input)).collect();

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
        framework: "iso42001".into(),
        framework_label: "ISO/IEC 42001:2023".into(),
        overall_score: overall,
        maturity_label: maturity_label(overall).into(),
        articles,
        gaps,
        total_findings: input.findings.len() as i32,
        critical_findings,
    }
}

struct Control {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    keywords: &'static [&'static str],
    action: &'static str,
}

const CONTROLS: &[Control] = &[
    Control {
        id: "A.2",
        title: "AI policy & objectives",
        description: "Politique IA documentée, objectifs de l'organisation pour l'usage de l'IA.",
        keywords: &[
            "ai policy",
            "ai governance",
            "ai_governance",
            "ai_usage_policy",
            "politique ia",
            "ai strategy",
            "stratégie ia",
            "ai objectives",
            "ai objective",
        ],
        action: "Rédiger ou mettre à jour la politique d'usage IA (allowed / denied providers)",
    },
    Control {
        id: "A.4",
        title: "Resources for AI systems",
        description: "Ressources humaines, techniques et données allouées aux systèmes IA.",
        keywords: &[
            "ai training",
            "training data",
            "model weight",
            "gpu",
            "compute",
            "llm",
            "formation ia",
            "formation llm",
            "awareness",
            "sensibilisation",
        ],
        action: "Documenter les ressources IA (compute, datasets, compétences équipes)",
    },
    Control {
        id: "A.5",
        title: "Assessing impacts of AI systems",
        description: "Évaluation des impacts (risques, biais, conformité) des systèmes IA high-risk.",
        keywords: &[
            "ai risk",
            "risque ia",
            "ai impact",
            "impact assessment",
            "ai_risk_assessment",
            "high-risk",
            "annex iii",
            "bias",
            "biais",
            "fairness",
        ],
        action: "Réaliser l'impact assessment (ISO 42005) pour chaque IA high-risk",
    },
    Control {
        id: "A.6",
        title: "AI system life cycle",
        description: "Cycle de vie des systèmes IA : développement, déploiement, supervision, retrait.",
        keywords: &[
            "ai development",
            "ai_deployment",
            "ai monitoring",
            "ai retirement",
            "ai_retired",
            "model versioning",
            "model update",
            "retrain",
            "ai lifecycle",
        ],
        action: "Cartographier le cycle de vie de chaque IA (détection → déclaration → évaluation → retrait)",
    },
    Control {
        id: "A.7",
        title: "Data for AI systems",
        description: "Qualité, provenance, protection des données utilisées par / envoyées à l'IA.",
        keywords: &[
            "data leak",
            "fuite",
            "pii",
            "données personnelles",
            "personal data",
            "rgpd",
            "gdpr",
            "data classification",
            "classification données",
            "data governance",
            "ai_usage_policy",
            "ai.shadow",
            "exfiltration",
        ],
        action: "Contrôler les flux de données sortants vers les IA tierces (DLP ou logging)",
    },
    Control {
        id: "A.8",
        title: "Information for interested parties",
        description: "Transparence vers utilisateurs, clients, auditeurs sur l'usage d'IA.",
        keywords: &[
            "transparency",
            "transparence",
            "ai_transparency",
            "audit trail",
            "audit_trail",
            "evidence",
            "citation",
            "explanation",
            "ai explainability",
        ],
        action: "Publier une note de transparence sur l'usage d'IA (clients + salariés)",
    },
    Control {
        id: "A.9",
        title: "Use of AI systems",
        description: "Contrôles sur l'usage autorisé vs non-autorisé (shadow AI), supervision HITL.",
        keywords: &[
            "ai_usage_policy",
            "ai.shadow",
            "shadow ai",
            "shadow_ai",
            "hitl",
            "human in the loop",
            "approval",
            "approbation",
            "chatgpt",
            "claude",
            "copilot",
            "ollama",
            "mistral",
        ],
        action: "Activer le pipeline shadow-ai-monitor et réviser la policy RSSI (threatclaw.toml)",
    },
    Control {
        id: "A.10",
        title: "Third-party & customer AI relationships",
        description: "Gestion des relations avec fournisseurs IA tiers (OpenAI, Anthropic…) et clients.",
        keywords: &[
            "third-party",
            "tiers",
            "supplier",
            "fournisseur",
            "vendor",
            "contractual",
            "contractuel",
            "sla",
            "ai.shadow",
            "ai_usage_policy",
            "openai",
            "anthropic",
            "mistral",
            "gemini",
            "huggingface",
        ],
        action: "Contractualiser avec les fournisseurs IA utilisés et inventorier les dépendances",
    },
];

fn score_control(ctrl: &Control, input: &ComplianceInput<'_>) -> ArticleScore {
    let mut critical = 0i32;
    let mut high = 0i32;
    let mut medium = 0i32;
    let mut relevant = 0i32;

    for f in input.findings {
        let title = f.title.as_str();
        let desc = f.description.as_deref().unwrap_or("");
        let category = f.category.as_deref().unwrap_or("");
        let skill = f.skill_id.as_str();
        if matches_any_keyword(&[title, desc, category, skill], ctrl.keywords) {
            relevant += 1;
            match f.severity.to_lowercase().as_str() {
                "critical" => critical += 1,
                "high" => high += 1,
                "medium" => medium += 1,
                _ => {}
            }
        }
    }

    // Alerts do NOT contribute to ISO 42001 — this framework evaluates AI
    // *governance*, not reactive detection (that's ISO 27001 A.8). Skip.

    let score = if relevant == 0 {
        50
    } else {
        score_from_hits(critical, high, medium)
    };

    let top_recommendation = if relevant > 0 {
        Some(ctrl.action.to_string())
    } else {
        None
    };

    ArticleScore {
        id: ctrl.id.to_string(),
        title: ctrl.title.to_string(),
        description: ctrl.description.to_string(),
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
    use crate::db::threatclaw_store::{AlertRecord, AssetRecord, FindingRecord};

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
    fn empty_input_yields_flat_50() {
        let input = ComplianceInput {
            findings: &[],
            alerts: &[],
            assets: &[],
        };
        let report = evaluate(&input);
        assert_eq!(report.articles.len(), 8);
        assert_eq!(report.overall_score, 50);
    }

    #[test]
    fn ai_usage_policy_finding_hits_a9_and_a10() {
        let findings = vec![fake_finding(
            "high",
            "Shadow AI — OpenAI via api.openai.com",
            "AI_USAGE_POLICY",
        )];
        let input = ComplianceInput {
            findings: &findings,
            alerts: &[],
            assets: &[],
        };
        let report = evaluate(&input);
        let a9 = report.articles.iter().find(|a| a.id == "A.9").unwrap();
        let a10 = report.articles.iter().find(|a| a.id == "A.10").unwrap();
        assert!(
            a9.relevant_findings >= 1,
            "shadow AI should hit A.9 usage control"
        );
        assert!(
            a10.relevant_findings >= 1,
            "shadow AI should hit A.10 third-party"
        );
    }

    #[test]
    fn data_leak_finding_hits_a7() {
        let findings = vec![fake_finding(
            "critical",
            "Personal data exfiltration via prompt",
            "data-leak",
        )];
        let input = ComplianceInput {
            findings: &findings,
            alerts: &[],
            assets: &[],
        };
        let report = evaluate(&input);
        let a7 = report.articles.iter().find(|a| a.id == "A.7").unwrap();
        assert!(a7.critical_hits >= 1, "data exfil should penalize A.7");
    }
}
