//! Compliance scoring — maps findings/alerts/assets to regulatory frameworks.
//!
//! Native Rust replacement for the Python `skills/_future/skill-compliance-*`
//! stubs. Pure functions — no DB I/O, no async. Callers pass in the data they
//! already have (via `ThreatClawStore::list_findings` etc.) and receive a
//! structured score + gap analysis.
//!
//! Frameworks covered:
//!   - NIS2 Directive 2022/2555 Art.21 §2 (10 sub-points a→j) — `nis2`
//!   - ISO/IEC 27001:2022 Annex A high-level categories (A.5 → A.8) — `iso27001`
//!
//! Roadmap (internal/governance-roadmap.md):
//!   - v1.3 : add `eu_ai_act`, `iso42001`, `nist_ai_rmf` modules following the
//!     same pattern (pure fn over findings → score + gaps).

use serde::{Deserialize, Serialize};

use crate::db::threatclaw_store::{AlertRecord, AssetRecord, FindingRecord};

pub mod iso27001;
pub mod nis2;

/// Score structure reused across frameworks — one instance per article/control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArticleScore {
    pub id: String,
    pub title: String,
    pub description: String,
    /// 0..=100. Higher = more compliant / fewer gaps.
    pub score: i32,
    /// Findings that contributed to penalty on this article.
    pub relevant_findings: i32,
    pub critical_hits: i32,
    pub high_hits: i32,
    pub medium_hits: i32,
    /// Short human-readable action ("apply patches", "rotate secrets", ...)
    pub top_recommendation: Option<String>,
}

/// Full report for one framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework: String,       // "nis2" | "iso27001" | ...
    pub framework_label: String, // "NIS2 Art.21" | "ISO/IEC 27001:2022" | ...
    pub overall_score: i32,      // weighted avg of article scores
    pub maturity_label: String,  // "Initial" → "Optimisé"
    pub articles: Vec<ArticleScore>,
    pub gaps: Vec<String>,        // article IDs with score < 50
    pub total_findings: i32,      // input count
    pub critical_findings: i32,
}

/// Convert numeric score to human maturity label (CMMI-inspired).
pub fn maturity_label(score: i32) -> &'static str {
    match score {
        s if s >= 85 => "Optimisé",
        s if s >= 70 => "Mesuré",
        s if s >= 55 => "Défini",
        s if s >= 35 => "Géré",
        _ => "Initial",
    }
}

/// Shared scoring arithmetic : starts at 100, subtracts weighted severity penalties,
/// clamped to [0, 100]. Called by each framework module after counting hits.
pub fn score_from_hits(critical: i32, high: i32, medium: i32) -> i32 {
    let penalty = critical * 15 + high * 8 + medium * 3;
    (100 - penalty).clamp(0, 100)
}

/// Case-insensitive substring check on a list of fields at once.
pub fn matches_any_keyword(haystacks: &[&str], keywords: &[&str]) -> bool {
    for hay in haystacks {
        let h = hay.to_lowercase();
        for kw in keywords {
            if h.contains(&kw.to_lowercase()) {
                return true;
            }
        }
    }
    false
}

/// Snapshot of all input data compliance modules need.
/// Avoids recomputing filter/count across multiple framework evaluations.
pub struct ComplianceInput<'a> {
    pub findings: &'a [FindingRecord],
    pub alerts: &'a [AlertRecord],
    pub assets: &'a [AssetRecord],
}

/// Dispatch table — evaluate all registered frameworks at once.
pub fn evaluate_all(input: &ComplianceInput<'_>) -> Vec<ComplianceReport> {
    vec![nis2::evaluate(input), iso27001::evaluate(input)]
}
