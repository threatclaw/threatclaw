//! Priority Score — the ThreatClaw scoring engine.
//!
//! Combines CVSS + CISA KEV + EPSS into a single priority decision.
//! This is what makes ThreatClaw smarter than raw CVSS scoring:
//!
//! CVSS 9.8 + KEV + EPSS 0.95 → CRITICAL IMMEDIATE
//! CVSS 9.8 + no KEV + EPSS 0.02 → High (theoretically severe but not exploited)
//! CVSS 5.5 + no KEV + EPSS 0.94 → CRITICAL (low CVSS but actively targeted)
//! CVSS 3.0 + no KEV + EPSS 0.01 → Low (ignore)

use serde::{Deserialize, Serialize};

/// ThreatClaw priority level (replaces raw CVSS severity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ThreatPriority {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Enrichment data for priority computation.
#[derive(Debug, Clone, Serialize)]
pub struct PriorityInput {
    pub cvss_score: f64,
    pub in_kev: bool,
    pub epss_score: f64,
    pub greynoise_noise: bool,
    pub greynoise_malicious: bool,
    pub threatfox_hits: usize,
}

/// Priority computation result with explanation.
#[derive(Debug, Clone, Serialize)]
pub struct PriorityResult {
    pub priority: ThreatPriority,
    pub score: f64,          // 0-100 composite score
    pub reason: String,      // Human-readable explanation
    pub adjustments: Vec<String>, // List of adjustments applied
}

/// Compute the ThreatClaw priority score.
/// This is the core intelligence of the product.
pub fn compute_priority(input: &PriorityInput) -> PriorityResult {
    let mut score = input.cvss_score * 10.0; // Base: CVSS 0-10 → 0-100
    let mut adjustments = vec![];

    // ── CISA KEV — always Critical ──
    if input.in_kev {
        score = score.max(95.0);
        adjustments.push("CISA KEV: CVE activement exploitée → CRITICAL".into());
    }

    // ── EPSS — probability of exploitation ──
    if input.epss_score > 0.9 {
        score = score.max(90.0);
        adjustments.push(format!("EPSS {:.0}%: très forte probabilité d'exploitation 30j → CRITICAL", input.epss_score * 100.0));
    } else if input.epss_score > 0.7 {
        score += 15.0;
        adjustments.push(format!("EPSS {:.0}%: forte probabilité → +15 points", input.epss_score * 100.0));
    } else if input.epss_score < 0.05 && input.cvss_score >= 9.0 {
        score -= 20.0;
        adjustments.push(format!("EPSS {:.1}%: CVSS élevé mais faible probabilité réelle → -20 points", input.epss_score * 100.0));
    }

    // ── GreyNoise — noise reduction ──
    if input.greynoise_noise {
        score -= 10.0;
        adjustments.push("GreyNoise: scanner de masse bénin → -10 points".into());
    }
    if input.greynoise_malicious {
        score += 15.0;
        adjustments.push("GreyNoise: attaque ciblée confirmée → +15 points".into());
    }

    // ── ThreatFox — known IoC ──
    if input.threatfox_hits > 0 {
        score += 10.0;
        adjustments.push(format!("ThreatFox: {} IoC(s) associé(s) → +10 points", input.threatfox_hits));
    }

    let score = score.clamp(0.0, 100.0);

    // ── Final priority decision ──
    let priority = if input.in_kev {
        ThreatPriority::Critical
    } else if score >= 80.0 {
        ThreatPriority::Critical
    } else if score >= 55.0 {
        ThreatPriority::High
    } else if score >= 30.0 {
        ThreatPriority::Medium
    } else {
        ThreatPriority::Low
    };

    let reason = if adjustments.is_empty() {
        format!("CVSS {:.1} → {}", input.cvss_score, priority)
    } else {
        format!("CVSS {:.1} + {} ajustement(s) → {} (score: {:.0})", input.cvss_score, adjustments.len(), priority, score)
    };

    PriorityResult { priority, score, reason, adjustments }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kev_always_critical() {
        let result = compute_priority(&PriorityInput {
            cvss_score: 5.0, in_kev: true, epss_score: 0.1,
            greynoise_noise: false, greynoise_malicious: false, threatfox_hits: 0,
        });
        assert_eq!(result.priority, ThreatPriority::Critical);
    }

    #[test]
    fn test_high_epss_escalates() {
        let result = compute_priority(&PriorityInput {
            cvss_score: 5.5, in_kev: false, epss_score: 0.95,
            greynoise_noise: false, greynoise_malicious: false, threatfox_hits: 0,
        });
        assert_eq!(result.priority, ThreatPriority::Critical);
    }

    #[test]
    fn test_high_cvss_low_epss_downgraded() {
        let result = compute_priority(&PriorityInput {
            cvss_score: 9.8, in_kev: false, epss_score: 0.02,
            greynoise_noise: false, greynoise_malicious: false, threatfox_hits: 0,
        });
        assert_eq!(result.priority, ThreatPriority::High); // Not Critical despite CVSS 9.8
    }

    #[test]
    fn test_greynoise_reduces_noise() {
        let noisy = compute_priority(&PriorityInput {
            cvss_score: 6.0, in_kev: false, epss_score: 0.3,
            greynoise_noise: true, greynoise_malicious: false, threatfox_hits: 0,
        });
        let targeted = compute_priority(&PriorityInput {
            cvss_score: 6.0, in_kev: false, epss_score: 0.3,
            greynoise_noise: false, greynoise_malicious: true, threatfox_hits: 0,
        });
        assert!(noisy.score < targeted.score);
    }

    #[test]
    fn test_low_everything() {
        let result = compute_priority(&PriorityInput {
            cvss_score: 2.0, in_kev: false, epss_score: 0.01,
            greynoise_noise: false, greynoise_malicious: false, threatfox_hits: 0,
        });
        assert_eq!(result.priority, ThreatPriority::Low);
    }
}
