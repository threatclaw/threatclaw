//! NIS2 Art.21 §2 (a → j) — 10 mandatory security measures.
//!
//! Source : Directive (EU) 2022/2555, transposée en France par la loi du
//! 30 avril 2025 (décret 2025-NIS2). Mapping keywords extrait du skill Python
//! `skills/_future/skill-compliance-nis2/src/main.py`.

use super::{
    matches_any_keyword, maturity_label, score_from_hits, ArticleScore, ComplianceInput,
    ComplianceReport,
};

/// Evaluate NIS2 compliance from current findings / alerts / assets.
pub fn evaluate(input: &ComplianceInput<'_>) -> ComplianceReport {
    let articles: Vec<ArticleScore> = ARTICLES
        .iter()
        .map(|a| score_article(a, input))
        .collect();

    // Weight all articles equally (10 measures are all mandatory in NIS2).
    let total: i32 = articles.iter().map(|a| a.score).sum();
    let overall = if articles.is_empty() { 100 } else { total / articles.len() as i32 };

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
        framework: "nis2".into(),
        framework_label: "NIS2 Art.21 §2".into(),
        overall_score: overall,
        maturity_label: maturity_label(overall).into(),
        articles,
        gaps,
        total_findings: input.findings.len() as i32,
        critical_findings,
    }
}

// ── Article definitions ────────────────────────────────────

struct Article {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    keywords: &'static [&'static str],
    /// Short template used to build a recommendation string when hits > 0.
    action: &'static str,
}

const ARTICLES: &[Article] = &[
    Article {
        id: "art21_2a",
        title: "Analyse des risques et sécurité des SI",
        description: "Politiques d'analyse des risques et sécurité des systèmes d'information.",
        keywords: &[
            "risk", "risque", "policy", "politique", "asset", "actif",
            "vulnerability", "vulnérabilité", "cve", "cvss", "inventory", "inventaire",
            "classification", "posture", "scan",
        ],
        action: "Étendre l'analyse de risques et corriger les vulnérabilités critiques identifiées",
    },
    Article {
        id: "art21_2b",
        title: "Gestion des incidents",
        description: "Procédures et outils de détection, analyse, confinement et réponse.",
        keywords: &[
            "incident", "alert", "alerte", "sigma", "soc", "detection", "triage",
            "response", "réponse", "siem", "correlation", "monitoring", "intrusion",
        ],
        action: "Formaliser les procédures de réponse et tester les playbooks",
    },
    Article {
        id: "art21_2c",
        title: "Continuité des activités et gestion de crise",
        description: "Sauvegardes, reprise après sinistre, gestion de crise.",
        keywords: &[
            "backup", "sauvegarde", "continuity", "continuité", "restore", "restauration",
            "recovery", "reprise", "disaster", "crisis", "crise", "pca", "pra",
            "rpo", "rto", "resilience", "résilience", "availability", "disponibilité",
        ],
        action: "Tester la restauration des sauvegardes et documenter le PCA/PRA",
    },
    Article {
        id: "art21_2d",
        title: "Sécurité de la chaîne d'approvisionnement",
        description: "Évaluation des fournisseurs, clauses contractuelles, gestion des dépendances tierces.",
        keywords: &[
            "supplier", "fournisseur", "supply chain", "approvisionnement", "dependency",
            "dépendance", "third-party", "tiers", "vendor", "sbom", "library",
            "package", "component", "composant", "open source", "ai.shadow", "ai_usage_policy",
        ],
        action: "Cartographier les fournisseurs IA/SaaS et évaluer leur posture sécurité",
    },
    Article {
        id: "art21_2e",
        title: "Sécurité dans l'acquisition, développement et maintenance",
        description: "Développement sécurisé, patch management, configuration sécurisée.",
        keywords: &[
            "development", "développement", "code", "application", "patch", "update",
            "configuration", "hardening", "durcissement", "sast", "dast", "pentest",
            "vulnerability", "vulnérabilité", "remediation",
        ],
        action: "Prioriser le patch management sur les CVE critiques et exploitables (KEV)",
    },
    Article {
        id: "art21_2f",
        title: "Évaluation de l'efficacité des mesures",
        description: "Indicateurs, audits, tests d'intrusion, amélioration continue.",
        keywords: &[
            "audit", "efficacité", "effectiveness", "kpi", "metric", "métrique",
            "benchmark", "compliance", "conformité", "review", "improvement",
            "amélioration", "dashboard", "tableau de bord",
        ],
        action: "Mettre en place un tableau de bord KPI sécurité et un cycle d'audit annuel",
    },
    Article {
        id: "art21_2g",
        title: "Cyberhygiène et formation",
        description: "Sensibilisation, formation cybersécurité, hygiène numérique.",
        keywords: &[
            "phishing", "hameçonnage", "awareness", "sensibilisation", "training",
            "formation", "password", "mot de passe", "hygiene", "hygiène",
            "social engineering", "ingénierie sociale", "email", "courriel",
        ],
        action: "Déployer un programme de sensibilisation et une campagne phishing trimestrielle",
    },
    Article {
        id: "art21_2h",
        title: "Cryptographie et chiffrement",
        description: "Politique de chiffrement, gestion des clés, TLS/PKI.",
        keywords: &[
            "encryption", "chiffrement", "cryptography", "cryptographie", "certificate",
            "certificat", "ssl", "tls", "https", "pki", "key", "clé", "secret",
            "hash", "signature", "kms", "hsm",
        ],
        action: "Rotation des secrets, renouvellement TLS et inventaire PKI",
    },
    Article {
        id: "art21_2i",
        title: "Ressources humaines et contrôle d'accès",
        description: "Gestion des identités, revue des accès, moindre privilège.",
        keywords: &[
            "access", "accès", "identity", "identité", "iam", "privilege", "privilège",
            "rbac", "role", "rôle", "user", "utilisateur", "account", "compte",
            "authorization", "autorisation", "permission", "darkweb", "credential",
            "leak", "fuite", "compromis", "exposed",
        ],
        action: "Effectuer une revue des accès privilégiés et révoquer les comptes orphelins",
    },
    Article {
        id: "art21_2j",
        title: "Authentification multi-facteur et communications sécurisées",
        description: "MFA obligatoire, communications vocales/vidéo/texte sécurisées.",
        keywords: &[
            "mfa", "multi-factor", "multi-facteur", "2fa", "authentication",
            "authentification", "otp", "totp", "fido", "sso", "single sign-on",
            "biometric", "biométrique", "zero trust",
        ],
        action: "Imposer la MFA sur tous les comptes privilégiés et accès externes",
    },
];

fn score_article(article: &Article, input: &ComplianceInput<'_>) -> ArticleScore {
    let mut critical = 0i32;
    let mut high = 0i32;
    let mut medium = 0i32;
    let mut relevant = 0i32;

    for f in input.findings {
        let title = f.title.as_str();
        let desc = f.description.as_deref().unwrap_or("");
        let category = f.category.as_deref().unwrap_or("");
        let skill = f.skill_id.as_str();
        if matches_any_keyword(&[title, desc, category, skill], article.keywords) {
            relevant += 1;
            match f.severity.to_lowercase().as_str() {
                "critical" => critical += 1,
                "high" => high += 1,
                "medium" => medium += 1,
                _ => {}
            }
        }
    }

    // Alerts contribute too (for art21_2b mainly) — count critical-level alerts as high
    for a in input.alerts {
        let title = a.title.as_str();
        if matches_any_keyword(&[title], article.keywords) {
            match a.level.to_lowercase().as_str() {
                "critical" => high += 1, // alerts are volatile — softer weight than findings
                "high" => medium += 1,
                _ => {}
            }
            relevant += 1;
        }
    }

    // Bonus: if NO finding at all matches, article scores 100 (no evidence of issues)
    // but also no evidence of coverage — flag with score 50 instead to avoid false confidence
    let score = if relevant == 0 {
        50
    } else {
        score_from_hits(critical, high, medium)
    };

    let top_recommendation = if relevant > 0 {
        Some(article.action.to_string())
    } else {
        None
    };

    ArticleScore {
        id: article.id.to_string(),
        title: article.title.to_string(),
        description: article.description.to_string(),
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
    fn empty_input_yields_flat_50_with_10_articles() {
        let input = ComplianceInput {
            findings: &[],
            alerts: &[],
            assets: &[],
        };
        let report = evaluate(&input);
        assert_eq!(report.articles.len(), 10);
        assert_eq!(report.overall_score, 50); // each article 50 (no evidence)
    }

    #[test]
    fn critical_patch_finding_penalizes_art21_2e() {
        // art21_2e keywords include "patch" + "vulnerability" + "remediation"
        let findings = vec![fake_finding(
            "critical",
            "Missing critical patch — vulnerability CVE-2024-1234",
            "vuln-scan",
        )];
        let alerts: Vec<AlertRecord> = vec![];
        let assets: Vec<AssetRecord> = vec![];
        let input = ComplianceInput {
            findings: &findings,
            alerts: &alerts,
            assets: &assets,
        };
        let report = evaluate(&input);
        let art_e = report.articles.iter().find(|a| a.id == "art21_2e").unwrap();
        assert!(art_e.score < 90, "expected penalty on art21_2e, got {}", art_e.score);
        assert_eq!(art_e.critical_hits, 1);
        assert!(art_e.top_recommendation.is_some());
    }

    #[test]
    fn ai_usage_policy_finding_maps_to_supply_chain() {
        let findings = vec![fake_finding("high", "Shadow AI: ChatGPT usage", "AI_USAGE_POLICY")];
        let alerts: Vec<AlertRecord> = vec![];
        let assets: Vec<AssetRecord> = vec![];
        let input = ComplianceInput {
            findings: &findings,
            alerts: &alerts,
            assets: &assets,
        };
        let report = evaluate(&input);
        let art_d = report.articles.iter().find(|a| a.id == "art21_2d").unwrap();
        assert!(art_d.relevant_findings >= 1, "shadow AI should map to supply chain art21_2d");
    }
}
