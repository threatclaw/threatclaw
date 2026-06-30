//! Prioritised exposure score — the per-ASSET cross of software vulnerabilities
//! (Grype) × CISA KEV × EPSS × asset criticality × network exposure.
//!
//! This is the missing join the IE never computed: Grype produces per-package
//! `software-vuln` findings (each already carrying CVSS, an `exploited_in_wild`
//! KEV flag and an EPSS score), but nothing rolled them up to an asset-level
//! risk that the RBA / dashboard could act on. [`compute_exposure`] turns the
//! worst-case factors of an asset into a single explainable 0-100 score; the
//! caller persists it (sortable in the asset list) AND emits a risk_event when
//! it's notable so the existing RBA pipeline escalates it to an incident.
//!
//! Pure and deterministic — no DB, no clock — so it unit-tests like
//! [`super::priority_score`] and [`crate::agent::path_risk::compute_path_score`].
//! See ADR-018 (CVSS+KEV+EPSS scoring).

/// The worst-case vulnerability posture of one asset, distilled from its
/// `software-vuln` findings plus its inventory attributes.
#[derive(Debug, Clone, PartialEq)]
pub struct ExposureInput {
    /// Highest CVSS base score across the asset's vulnerabilities (0-10).
    pub max_cvss: f64,
    /// Any CVE on the asset is in CISA KEV (actively exploited in the wild).
    pub in_kev: bool,
    /// Highest EPSS probability across the asset's CVEs (0.0-1.0).
    pub epss_max: f64,
    /// Asset criticality label: `critical` | `high` | `medium` | `low`.
    pub criticality: String,
    /// Asset is internet-facing (e.g. carries the `public_ip` system tag).
    pub exposed: bool,
}

/// Result of [`compute_exposure`]: a 0-100 score, a severity bucket aligned with
/// the rest of the product (`LOW`..`CRITICAL`), and a human breakdown of what
/// drove it (surfaced in the asset detail + the incident the RBA may raise).
#[derive(Debug, Clone, PartialEq)]
pub struct ExposureResult {
    pub score: u8,
    pub severity: &'static str,
    pub breakdown: Vec<String>,
}

/// Rank a criticality label (case-insensitive). Unknown → medium (1).
fn crit_rank(criticality: &str) -> u8 {
    match criticality.trim().to_ascii_lowercase().as_str() {
        "critical" => 3,
        "high" => 2,
        "low" => 0,
        _ => 1, // medium / unknown
    }
}

/// Map a 0-100 exposure score to the product's severity vocabulary.
fn severity_for(score: u8) -> &'static str {
    match score {
        85..=100 => "CRITICAL",
        65..=84 => "HIGH",
        40..=64 => "MEDIUM",
        _ => "LOW",
    }
}

/// Compute an asset's prioritised exposure score (0-100) from its worst-case
/// vulnerability factors. Deterministic and bounded.
///
/// Doctrine encoded:
/// - **KEV dominates**: an actively-exploited CVE floors the score high — a low
///   CVSS bug that's being exploited in the wild is still urgent.
/// - **EPSS** weights real-world exploitation probability on top.
/// - **Exposure** (internet-facing) amplifies any real vulnerability — the same
///   bug on a DMZ host outranks one on an isolated internal box.
/// - **Criticality** scales the whole thing: a critical asset amplifies, a
///   low-criticality one dampens.
pub fn compute_exposure(input: &ExposureInput) -> ExposureResult {
    let cvss = input.max_cvss.clamp(0.0, 10.0);
    let epss = input.epss_max.clamp(0.0, 1.0);
    let has_vuln = cvss > 0.0 || input.in_kev;

    let mut breakdown = Vec::new();

    // CVSS contributes up to 80 points; KEV/EPSS/exposure/criticality top it up.
    let mut score = cvss * 8.0;
    if cvss > 0.0 {
        breakdown.push(format!("CVSS {cvss:.1}"));
    }

    // KEV — actively exploited never sits low.
    if input.in_kev {
        score = score.max(75.0) + 10.0;
        breakdown.push("CISA KEV (exploité activement)".to_string());
    }

    // EPSS — probability of exploitation in the next 30 days.
    if epss >= 0.5 {
        score += 12.0;
        breakdown.push(format!("EPSS {:.0}% (forte probabilité)", epss * 100.0));
    } else if epss >= 0.1 {
        score += 6.0;
        breakdown.push(format!("EPSS {:.0}%", epss * 100.0));
    }

    // Network exposure amplifies a real vulnerability.
    if input.exposed && has_vuln {
        score += 12.0;
        breakdown.push("exposé sur Internet".to_string());
    }

    // Asset criticality scales the result.
    let (mult, label): (f64, &str) = match crit_rank(&input.criticality) {
        3 => (1.15, "asset critique"),
        2 => (1.07, "asset important"),
        0 => (0.85, "asset à faible criticité"),
        _ => (1.0, ""),
    };
    score *= mult;
    if !label.is_empty() {
        breakdown.push(label.to_string());
    }

    let score = score.round().clamp(0.0, 100.0) as u8;
    ExposureResult {
        score,
        severity: severity_for(score),
        breakdown,
    }
}

/// Whether an exposure result is notable enough to push into the RBA pipeline
/// (→ an incident the RSSI acts on). A KEV-exploited CVE on an exposed asset, or
/// any HIGH/CRITICAL exposure, qualifies. Keeps low-signal vuln noise out of the
/// incident queue (those stay as findings, visible in the asset detail).
pub fn is_notable(input: &ExposureInput, result: &ExposureResult) -> bool {
    (input.in_kev && input.exposed) || result.score >= 65
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(max_cvss: f64, in_kev: bool, epss_max: f64, criticality: &str, exposed: bool) -> ExposureInput {
        ExposureInput {
            max_cvss,
            in_kev,
            epss_max,
            criticality: criticality.to_string(),
            exposed,
        }
    }

    #[test]
    fn kev_exposed_critical_is_critical() {
        // The "drop everything" case: actively exploited, internet-facing, crown jewel.
        let r = compute_exposure(&input(9.8, true, 0.97, "critical", true));
        assert_eq!(r.severity, "CRITICAL");
        assert!(r.score >= 95, "got {}", r.score);
        assert!(r.breakdown.iter().any(|b| b.contains("KEV")));
        assert!(r.breakdown.iter().any(|b| b.contains("Internet")));
    }

    #[test]
    fn kev_floors_score_even_with_low_cvss() {
        // A low-CVSS bug that is exploited in the wild must not read as low risk.
        let r = compute_exposure(&input(3.5, true, 0.2, "medium", false));
        assert!(r.score >= 70, "KEV must floor high, got {}", r.score);
        assert_ne!(r.severity, "LOW");
    }

    #[test]
    fn high_cvss_no_kev_is_high_not_critical() {
        let r = compute_exposure(&input(8.5, false, 0.05, "medium", false));
        assert_eq!(r.severity, "HIGH");
    }

    #[test]
    fn low_cvss_low_crit_internal_is_low() {
        let r = compute_exposure(&input(3.0, false, 0.01, "low", false));
        assert_eq!(r.severity, "LOW");
        assert!(r.score < 40, "got {}", r.score);
    }

    #[test]
    fn exposure_only_counts_with_a_real_vuln() {
        // No vuln at all → exposure must not invent risk.
        let bare = compute_exposure(&input(0.0, false, 0.0, "critical", true));
        assert_eq!(bare.score, 0);
        assert!(bare.breakdown.iter().all(|b| !b.contains("Internet")));
    }

    #[test]
    fn epss_increases_score_monotonically() {
        let lo = compute_exposure(&input(7.0, false, 0.0, "medium", false)).score;
        let mid = compute_exposure(&input(7.0, false, 0.2, "medium", false)).score;
        let hi = compute_exposure(&input(7.0, false, 0.9, "medium", false)).score;
        assert!(lo <= mid && mid <= hi, "{lo} <= {mid} <= {hi}");
    }

    #[test]
    fn criticality_scales_the_same_vuln() {
        let v = |c: &str| compute_exposure(&input(7.0, false, 0.3, c, true)).score;
        assert!(v("low") < v("medium"));
        assert!(v("medium") < v("high"));
        assert!(v("high") <= v("critical"));
    }

    #[test]
    fn score_is_bounded_and_unknown_criticality_is_medium() {
        let maxed = compute_exposure(&input(10.0, true, 1.0, "critical", true));
        assert!(maxed.score <= 100);
        // unknown criticality behaves like medium
        assert_eq!(
            compute_exposure(&input(7.0, false, 0.3, "bogus", false)).score,
            compute_exposure(&input(7.0, false, 0.3, "medium", false)).score
        );
    }

    #[test]
    fn is_notable_gates_the_rba_pipeline() {
        // KEV + exposed → notable even if the raw score were modest.
        let i = input(4.0, true, 0.1, "medium", true);
        let r = compute_exposure(&i);
        assert!(is_notable(&i, &r));
        // a quiet internal low-CVSS bug is not notable (stays a finding only).
        let q = input(4.0, false, 0.02, "low", false);
        let qr = compute_exposure(&q);
        assert!(!is_notable(&q, &qr));
    }
}
