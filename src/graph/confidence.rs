//! Confidence Scoring — dynamic contextual score based on graph relationships.
//!
//! Computes a STIX 2.1 compatible confidence score (0-100) for an alert
//! by traversing graph connections: enrichment sources, historical sightings,
//! CVE presence, time-of-day anomaly, and multi-source corroboration.
//!
//! The more independent sources agree, the higher the confidence.

use crate::db::Database;
use crate::graph::threat_graph::query;
use serde::Serialize;
use serde_json::json;

/// Confidence score result with breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct ConfidenceScore {
    /// Final score 0-100 (STIX 2.1 compatible).
    pub score: u8,
    /// Score level as string.
    pub level: &'static str,
    /// Per-source contribution breakdown.
    pub breakdown: Vec<ScoreComponent>,
    /// Number of corroborating sources.
    pub source_count: usize,
    /// Corroboration bonus applied.
    pub corroboration_bonus: f64,
}

/// Individual score component from one source.
#[derive(Debug, Clone, Serialize)]
pub struct ScoreComponent {
    pub source: String,
    pub weight: f64,
    pub raw_value: f64,
    pub weighted_score: f64,
    pub detail: String,
}

impl ConfidenceScore {
    fn level_from_score(score: u8) -> &'static str {
        match score {
            0..=29 => "low",
            30..=69 => "medium",
            70..=89 => "high",
            90..=100 => "confirmed",
            _ => "unknown",
        }
    }
}

/// Compute confidence score for an IP-based alert.
///
/// Factors (weights sum to 1.0):
/// - GreyNoise classification (0.20): malicious=1.0, unknown=0.5, benign=0.0
/// - CrowdSec/AbuseIPDB reputation (0.20): normalized threat score
/// - Historical attacks in graph (0.20): more attacks = higher confidence
/// - CVE on target asset (0.15): exploit path exists
/// - EPSS on related CVEs (0.10): probability of exploitation
/// - Time anomaly (0.10): attacks at unusual hours
/// - KEV status (0.05): known exploited = boost
pub async fn compute_ip_confidence(
    store: &dyn Database,
    ip_addr: &str,
    target_asset: Option<&str>,
    alert_hour: Option<u32>,
) -> ConfidenceScore {
    let esc = |s: &str| s.replace('\'', "\\'");
    let mut components = vec![];
    let mut total: f64 = 0.0;

    // 1. GreyNoise classification (weight: 0.20)
    let gn_results = query(
        store,
        &format!(
            "MATCH (ip:IP {{addr: '{}'}}) RETURN ip.classification",
            esc(ip_addr)
        ),
    )
    .await;

    let gn_class = gn_results
        .first()
        .and_then(|r| r["ip.classification"].as_str())
        .unwrap_or("unknown");

    let gn_raw = match gn_class {
        "malicious" => 1.0,
        "unknown" => 0.5,
        "benign" => 0.0,
        _ => 0.3,
    };
    let gn_weighted = gn_raw * 0.20;
    total += gn_weighted;
    components.push(ScoreComponent {
        source: "greynoise".into(),
        weight: 0.20,
        raw_value: gn_raw,
        weighted_score: gn_weighted,
        detail: format!("classification={}", gn_class),
    });

    // 2. Historical attacks from this IP (weight: 0.20)
    let attack_results = query(
        store,
        &format!(
            "MATCH (ip:IP {{addr: '{}'}})-[att:ATTACKS]->(a:Asset) RETURN count(att)",
            esc(ip_addr)
        ),
    )
    .await;

    let attack_count = attack_results
        .first()
        .and_then(|r| r["count(att)"].as_i64())
        .unwrap_or(0);

    let hist_raw = match attack_count {
        0 => 0.1,
        1..=3 => 0.4,
        4..=10 => 0.7,
        _ => 1.0,
    };
    let hist_weighted = hist_raw * 0.20;
    total += hist_weighted;
    components.push(ScoreComponent {
        source: "graph_history".into(),
        weight: 0.20,
        raw_value: hist_raw,
        weighted_score: hist_weighted,
        detail: format!("{} attacks recorded", attack_count),
    });

    // 3. IP country/ASN reputation (weight: 0.20)
    let geo_results = query(
        store,
        &format!(
            "MATCH (ip:IP {{addr: '{}'}}) RETURN ip.country, ip.asn",
            esc(ip_addr)
        ),
    )
    .await;

    let country = geo_results
        .first()
        .and_then(|r| r["ip.country"].as_str())
        .unwrap_or("");

    // High-risk countries (common attack origins) get higher score
    let geo_raw = match country.to_uppercase().as_str() {
        "CN" | "RU" | "KP" | "IR" => 0.8,
        "BR" | "IN" | "VN" | "ID" | "PK" => 0.5,
        "US" | "DE" | "NL" | "GB" | "FR" => 0.2,
        "" => 0.4, // unknown = suspicious
        _ => 0.3,
    };
    let geo_weighted = geo_raw * 0.20;
    total += geo_weighted;
    components.push(ScoreComponent {
        source: "geolocation".into(),
        weight: 0.20,
        raw_value: geo_raw,
        weighted_score: geo_weighted,
        detail: if country.is_empty() {
            "unknown country".into()
        } else {
            format!("country={}", country)
        },
    });

    // 4. CVE on target asset (weight: 0.15)
    let cve_raw = if let Some(asset) = target_asset {
        let cve_results = query(
            store,
            &format!(
                "MATCH (c:CVE)-[:AFFECTS]->(a:Asset {{id: '{}'}}) RETURN c.cvss, c.in_kev",
                esc(asset)
            ),
        )
        .await;

        if cve_results.is_empty() {
            0.1
        } else {
            let max_cvss = cve_results
                .iter()
                .filter_map(|r| r["c.cvss"].as_f64())
                .fold(0.0_f64, f64::max);
            let has_kev = cve_results
                .iter()
                .any(|r| r["c.in_kev"].as_bool() == Some(true));

            let base = (max_cvss / 10.0).min(1.0);
            if has_kev { (base + 0.2).min(1.0) } else { base }
        }
    } else {
        0.0
    };
    let cve_weighted = cve_raw * 0.15;
    total += cve_weighted;
    components.push(ScoreComponent {
        source: "cve_exposure".into(),
        weight: 0.15,
        raw_value: cve_raw,
        weighted_score: cve_weighted,
        detail: format!("target={}", target_asset.unwrap_or("none")),
    });

    // 5. EPSS on related CVEs (weight: 0.10)
    let epss_raw =
        if let Some(asset) = target_asset {
            let epss_results = query(store, &format!(
            "MATCH (c:CVE)-[:AFFECTS]->(a:Asset {{id: '{}'}}) WHERE c.epss > 0 RETURN c.epss",
            esc(asset)
        )).await;

            epss_results
                .iter()
                .filter_map(|r| r["c.epss"].as_f64())
                .fold(0.0_f64, f64::max)
                .min(1.0)
        } else {
            0.0
        };
    let epss_weighted = epss_raw * 0.10;
    total += epss_weighted;
    components.push(ScoreComponent {
        source: "epss".into(),
        weight: 0.10,
        raw_value: epss_raw,
        weighted_score: epss_weighted,
        detail: format!("max_epss={:.3}", epss_raw),
    });

    // 6. Time anomaly (weight: 0.10)
    let hour = alert_hour.unwrap_or(12);
    let time_raw = match hour {
        0..=5 => 0.9,   // 00h-05h = very suspicious
        22..=23 => 0.7, // 22h-23h = suspicious
        6..=8 => 0.3,   // early morning
        _ => 0.1,       // business hours = normal
    };
    let time_weighted = time_raw * 0.10;
    total += time_weighted;
    components.push(ScoreComponent {
        source: "time_anomaly".into(),
        weight: 0.10,
        raw_value: time_raw,
        weighted_score: time_weighted,
        detail: format!("hour={}", hour),
    });

    // 7. KEV boost (weight: 0.05)
    let kev_raw =
        if let Some(asset) = target_asset {
            let kev_results = query(store, &format!(
            "MATCH (c:CVE {{in_kev: true}})-[:AFFECTS]->(a:Asset {{id: '{}'}}) RETURN count(c)",
            esc(asset)
        )).await;
            let kev_count = kev_results
                .first()
                .and_then(|r| r["count(c)"].as_i64())
                .unwrap_or(0);
            if kev_count > 0 { 1.0 } else { 0.0 }
        } else {
            0.0
        };
    let kev_weighted = kev_raw * 0.05;
    total += kev_weighted;
    components.push(ScoreComponent {
        source: "cisa_kev".into(),
        weight: 0.05,
        raw_value: kev_raw,
        weighted_score: kev_weighted,
        detail: format!("kev={}", kev_raw > 0.0),
    });

    // Corroboration bonus: more diverse sources with high signal = bonus
    let active_sources = components.iter().filter(|c| c.raw_value > 0.3).count();
    let corroboration_bonus = match active_sources {
        0..=1 => 0.0,
        2 => 0.05,
        3 => 0.10,
        4..=5 => 0.15,
        _ => 0.20,
    };
    total += corroboration_bonus;

    // Cap at 100
    let final_score = ((total * 100.0).round() as u8).min(100);

    ConfidenceScore {
        score: final_score,
        level: ConfidenceScore::level_from_score(final_score),
        breakdown: components,
        source_count: active_sources,
        corroboration_bonus,
    }
}

/// Compute confidence for a CVE-based alert.
pub async fn compute_cve_confidence(
    store: &dyn Database,
    cve_id: &str,
    target_asset: Option<&str>,
) -> ConfidenceScore {
    let esc = |s: &str| s.replace('\'', "\\'");
    let mut components = vec![];
    let mut total: f64 = 0.0;

    // 1. CVSS score (weight: 0.30)
    let cve_results = query(
        store,
        &format!(
            "MATCH (c:CVE {{id: '{}'}}) RETURN c.cvss, c.epss, c.in_kev",
            esc(cve_id)
        ),
    )
    .await;

    let cvss = cve_results
        .first()
        .and_then(|r| r["c.cvss"].as_f64())
        .unwrap_or(0.0);
    let cvss_raw = (cvss / 10.0).min(1.0);
    let cvss_weighted = cvss_raw * 0.30;
    total += cvss_weighted;
    components.push(ScoreComponent {
        source: "cvss".into(),
        weight: 0.30,
        raw_value: cvss_raw,
        weighted_score: cvss_weighted,
        detail: format!("cvss={:.1}", cvss),
    });

    // 2. EPSS (weight: 0.25)
    let epss = cve_results
        .first()
        .and_then(|r| r["c.epss"].as_f64())
        .unwrap_or(0.0);
    let epss_weighted = epss * 0.25;
    total += epss_weighted;
    components.push(ScoreComponent {
        source: "epss".into(),
        weight: 0.25,
        raw_value: epss,
        weighted_score: epss_weighted,
        detail: format!("epss={:.3}", epss),
    });

    // 3. KEV (weight: 0.25)
    let in_kev = cve_results
        .first()
        .and_then(|r| r["c.in_kev"].as_bool())
        .unwrap_or(false);
    let kev_raw = if in_kev { 1.0 } else { 0.0 };
    let kev_weighted = kev_raw * 0.25;
    total += kev_weighted;
    components.push(ScoreComponent {
        source: "cisa_kev".into(),
        weight: 0.25,
        raw_value: kev_raw,
        weighted_score: kev_weighted,
        detail: format!("in_kev={}", in_kev),
    });

    // 4. Asset criticality (weight: 0.20)
    let asset_raw = if let Some(asset) = target_asset {
        let asset_results = query(
            store,
            &format!(
                "MATCH (a:Asset {{id: '{}'}}) RETURN a.criticality",
                esc(asset)
            ),
        )
        .await;
        let criticality = asset_results
            .first()
            .and_then(|r| r["a.criticality"].as_str())
            .unwrap_or("medium");
        match criticality {
            "critical" => 1.0,
            "high" => 0.7,
            "medium" => 0.4,
            "low" => 0.1,
            _ => 0.4,
        }
    } else {
        0.3
    };
    let asset_weighted = asset_raw * 0.20;
    total += asset_weighted;
    components.push(ScoreComponent {
        source: "asset_criticality".into(),
        weight: 0.20,
        raw_value: asset_raw,
        weighted_score: asset_weighted,
        detail: format!("target={}", target_asset.unwrap_or("none")),
    });

    let active_sources = components.iter().filter(|c| c.raw_value > 0.3).count();
    let corroboration_bonus = match active_sources {
        0..=1 => 0.0,
        2 => 0.05,
        3 => 0.10,
        _ => 0.15,
    };
    total += corroboration_bonus;

    let final_score = ((total * 100.0).round() as u8).min(100);

    ConfidenceScore {
        score: final_score,
        level: ConfidenceScore::level_from_score(final_score),
        breakdown: components,
        source_count: active_sources,
        corroboration_bonus,
    }
}

/// Format confidence score for notification/display.
pub fn format_confidence(score: &ConfidenceScore) -> String {
    let mut out = format!("Confiance: {}/100 ({})\n", score.score, score.level);
    out.push_str(&format!("Sources corroborantes: {}", score.source_count));
    if score.corroboration_bonus > 0.0 {
        out.push_str(&format!(
            " (+{:.0}% bonus)",
            score.corroboration_bonus * 100.0
        ));
    }
    out.push('\n');
    for c in &score.breakdown {
        out.push_str(&format!(
            "  {} ({:.0}%): {:.0}/100 — {}\n",
            c.source,
            c.weight * 100.0,
            c.weighted_score * 100.0,
            c.detail
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_level() {
        assert_eq!(ConfidenceScore::level_from_score(10), "low");
        assert_eq!(ConfidenceScore::level_from_score(50), "medium");
        assert_eq!(ConfidenceScore::level_from_score(80), "high");
        assert_eq!(ConfidenceScore::level_from_score(95), "confirmed");
    }

    #[test]
    fn test_format_confidence() {
        let score = ConfidenceScore {
            score: 75,
            level: "high",
            breakdown: vec![ScoreComponent {
                source: "greynoise".into(),
                weight: 0.20,
                raw_value: 1.0,
                weighted_score: 0.20,
                detail: "classification=malicious".into(),
            }],
            source_count: 3,
            corroboration_bonus: 0.10,
        };
        let formatted = format_confidence(&score);
        assert!(formatted.contains("75/100"));
        assert!(formatted.contains("high"));
        assert!(formatted.contains("greynoise"));
    }
}
