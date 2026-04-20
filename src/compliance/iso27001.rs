//! ISO/IEC 27001:2022 — Annex A high-level categories (A.5 → A.8).
//!
//! La 2022 revision regroupe 93 contrôles en 4 thèmes. On évalue au niveau
//! thème (pas contrôle individuel) — suffisant pour un score macro et un
//! export PDF ISO 27001 niveau entreprise. Granularité 93-contrôles à ajouter
//! en v1.3 si nécessaire (roadmap governance).
//!
//! Référence : ISO/IEC 27001:2022 Annex A & ISO/IEC 27002:2022.

use super::{
    matches_any_keyword, maturity_label, score_from_hits, ArticleScore, ComplianceInput,
    ComplianceReport,
};

pub fn evaluate(input: &ComplianceInput<'_>) -> ComplianceReport {
    let articles: Vec<ArticleScore> = CATEGORIES
        .iter()
        .map(|c| score_category(c, input))
        .collect();

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
        framework: "iso27001".into(),
        framework_label: "ISO/IEC 27001:2022".into(),
        overall_score: overall,
        maturity_label: maturity_label(overall).into(),
        articles,
        gaps,
        total_findings: input.findings.len() as i32,
        critical_findings,
    }
}

struct Category {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    keywords: &'static [&'static str],
    action: &'static str,
}

const CATEGORIES: &[Category] = &[
    Category {
        id: "A.5",
        title: "Organizational controls",
        description: "Politiques, rôles, responsabilités, gestion fournisseurs, classification.",
        keywords: &[
            "policy", "politique", "role", "rôle", "responsibility", "responsabilité",
            "supplier", "fournisseur", "classification", "governance", "gouvernance",
            "third-party", "tiers", "vendor", "ai.shadow", "ai_usage_policy",
            "ai_governance", "compliance", "conformité",
        ],
        action: "Documenter les politiques de sécurité et inventorier les IA tierces",
    },
    Category {
        id: "A.6",
        title: "People controls",
        description: "Sensibilisation, formation, départs, confidentialité, gestion RH.",
        keywords: &[
            "phishing", "hameçonnage", "awareness", "sensibilisation", "training",
            "formation", "onboarding", "offboarding", "hr", "rh", "confidentiality",
            "confidentialité", "ndar", "nda", "clearance",
        ],
        action: "Renforcer la sensibilisation et le cycle de vie des accès utilisateurs",
    },
    Category {
        id: "A.7",
        title: "Physical controls",
        description: "Sécurité physique, zones, équipements, câblage, élimination des supports.",
        keywords: &[
            "physical", "physique", "badge", "biometric", "biométrique", "camera",
            "caméra", "vidéo", "surveillance", "alarm", "alarme", "datacenter",
            "zone", "secure area", "équipement",
        ],
        action: "Audit des contrôles d'accès physique et inventaire des équipements",
    },
    Category {
        id: "A.8",
        title: "Technological controls",
        description: "Endpoint, réseau, chiffrement, backup, logs, supervision, gestion des vulnérabilités.",
        keywords: &[
            "endpoint", "network", "réseau", "encryption", "chiffrement", "tls",
            "ssl", "vpn", "firewall", "pare-feu", "backup", "sauvegarde", "log",
            "logging", "siem", "monitoring", "supervision", "vulnerability",
            "vulnérabilité", "cve", "patch", "edr", "ids", "ips", "mfa",
            "authentication", "authentification", "anomaly", "anomalie",
            "exfiltration", "intrusion", "malware", "ransomware", "c2",
            "ransomware", "ddos", "phishing",
        ],
        action: "Réduire les vulnérabilités critiques et renforcer la détection",
    },
];

fn score_category(cat: &Category, input: &ComplianceInput<'_>) -> ArticleScore {
    let mut critical = 0i32;
    let mut high = 0i32;
    let mut medium = 0i32;
    let mut relevant = 0i32;

    for f in input.findings {
        let title = f.title.as_str();
        let desc = f.description.as_deref().unwrap_or("");
        let category = f.category.as_deref().unwrap_or("");
        let skill = f.skill_id.as_str();
        if matches_any_keyword(&[title, desc, category, skill], cat.keywords) {
            relevant += 1;
            match f.severity.to_lowercase().as_str() {
                "critical" => critical += 1,
                "high" => high += 1,
                "medium" => medium += 1,
                _ => {}
            }
        }
    }

    for a in input.alerts {
        let title = a.title.as_str();
        if matches_any_keyword(&[title], cat.keywords) {
            match a.level.to_lowercase().as_str() {
                "critical" => high += 1,
                "high" => medium += 1,
                _ => {}
            }
            relevant += 1;
        }
    }

    let score = if relevant == 0 {
        50 // no evidence of coverage
    } else {
        score_from_hits(critical, high, medium)
    };

    let top_recommendation = if relevant > 0 {
        Some(cat.action.to_string())
    } else {
        None
    };

    ArticleScore {
        id: cat.id.to_string(),
        title: cat.title.to_string(),
        description: cat.description.to_string(),
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
    fn empty_input_yields_50_on_each_category() {
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
    fn ransomware_alert_hits_a8() {
        let findings: Vec<FindingRecord> = vec![];
        let alerts = vec![AlertRecord {
            id: 1,
            rule_id: "win-ransom".into(),
            level: "critical".into(),
            title: "Ransomware encrypt detected".into(),
            status: "open".into(),
            hostname: None,
            source_ip: None,
            username: None,
            matched_at: "2026-04-20T10:00:00Z".into(),
            matched_fields: None,
        }];
        let assets: Vec<AssetRecord> = vec![];
        let input = ComplianceInput {
            findings: &findings,
            alerts: &alerts,
            assets: &assets,
        };
        let report = evaluate(&input);
        let a8 = report.articles.iter().find(|a| a.id == "A.8").unwrap();
        assert!(a8.relevant_findings >= 1);
    }

    #[test]
    fn ai_usage_policy_hits_a5_organizational() {
        let findings = vec![fake_finding("medium", "Shadow AI ChatGPT", "AI_USAGE_POLICY")];
        let alerts: Vec<AlertRecord> = vec![];
        let assets: Vec<AssetRecord> = vec![];
        let input = ComplianceInput {
            findings: &findings,
            alerts: &alerts,
            assets: &assets,
        };
        let report = evaluate(&input);
        let a5 = report.articles.iter().find(|a| a.id == "A.5").unwrap();
        assert!(a5.relevant_findings >= 1);
    }
}
