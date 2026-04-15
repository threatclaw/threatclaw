//! C2 Beacon timing detection. See ADR-005.
//!
//! Detects regular communication patterns typical of C2 implants.
//! Uses 4 statistical scores inspired by RITA (Real Intelligence Threat Analytics):
//! 1. Coefficient of Variation (CV) — regularity of intervals
//! 2. Skew — asymmetry of interval distribution
//! 3. MADM — Median Absolute Deviation of Median (robust to outliers)
//! 4. Bowley coefficient — shape of distribution (beacon vs human)
//!
//! Combined weighted score determines beacon confidence.
//! MITRE: T1071.001 (C2 Web Protocol), T1573.002 (Encrypted Channel)

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use std::collections::HashMap;

/// Beacon detection thresholds.
const MIN_CONNECTIONS: usize = 5; // Need at least 5 connections to detect a pattern
const MIN_INTERVAL_SECS: f64 = 5.0; // Ignore intervals < 5s (normal keep-alive)
const MAX_INTERVAL_SECS: f64 = 3600.0; // Ignore intervals > 1h (not beacon-like)

/// Combined score thresholds (0.0 = perfect beacon, 1.0 = random human).
const SCORE_CRITICAL: f64 = 0.15; // Combined < 0.15 = almost certainly beacon
const SCORE_HIGH: f64 = 0.30; // Combined < 0.30 = suspicious regularity

/// Individual score weights (must sum to 1.0).
const W_CV: f64 = 0.35; // Coefficient of variation — primary signal
const W_SKEW: f64 = 0.20; // Skew — asymmetry
const W_MADM: f64 = 0.25; // MADM — robust dispersion
const W_BOWLEY: f64 = 0.20; // Bowley — distribution shape

/// Result of a beacon scan cycle.
#[derive(Debug)]
pub struct BeaconScanResult {
    pub connections_analyzed: usize,
    pub flow_groups: usize,
    pub beacons_detected: usize,
    pub findings_created: usize,
}

/// A detected beacon candidate with full RITA-style scoring.
#[derive(Debug)]
struct BeaconCandidate {
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
    connection_count: usize,
    mean_interval: f64,
    // RITA scores (all normalized 0.0-1.0, lower = more beacon-like)
    cv: f64,
    skew: f64,
    madm: f64,
    bowley: f64,
    combined_score: f64,
    server_name: Option<String>,
}

/// Scan recent Zeek conn.log entries for C2 beacon timing patterns.
/// Runs every IE cycle (5 min) with a 60-minute lookback for timing analysis.
pub async fn scan_beacons(
    store: std::sync::Arc<dyn Database>,
    minutes_back: i64,
) -> BeaconScanResult {
    let mut result = BeaconScanResult {
        connections_analyzed: 0,
        flow_groups: 0,
        beacons_detected: 0,
        findings_created: 0,
    };

    // Query recent Zeek connection logs
    let logs = store
        .query_logs(minutes_back, None, Some("zeek.conn"), 5000)
        .await
        .unwrap_or_default();
    result.connections_analyzed = logs.len();

    if logs.len() < MIN_CONNECTIONS {
        return result;
    }

    // Group connections by (src_ip, dst_ip, dst_port)
    let mut flows: HashMap<(String, String, u16), Vec<f64>> = HashMap::new();
    // Track server names from SSL logs for enrichment
    let mut server_names: HashMap<(String, u16), String> = HashMap::new();

    for log in &logs {
        let src = log.data["id.orig_h"].as_str().unwrap_or("");
        let dst = log.data["id.resp_h"].as_str().unwrap_or("");
        let port = log.data["id.resp_p"].as_u64().unwrap_or(0) as u16;

        if src.is_empty() || dst.is_empty() || port == 0 {
            continue;
        }

        // Skip internal-to-internal (not C2-like) — only flag outbound or external
        if is_private(src) && is_private(dst) {
            continue;
        }
        // Skip DNS (port 53) and NTP (port 123) — naturally regular
        if port == 53 || port == 123 {
            continue;
        }

        // Extract timestamp as epoch float
        let ts = log.data["ts"].as_f64().unwrap_or(0.0);
        if ts == 0.0 {
            continue;
        }

        flows
            .entry((src.to_string(), dst.to_string(), port))
            .or_default()
            .push(ts);

        // Capture server_name if available (from conn+ssl correlation)
        if let Some(sni) = log.data["server_name"].as_str() {
            server_names.insert((dst.to_string(), port), sni.to_string());
        }
    }

    result.flow_groups = flows.len();

    // Analyze each flow for beacon patterns
    for ((src, dst, port), mut timestamps) in flows {
        if timestamps.len() < MIN_CONNECTIONS {
            continue;
        }

        // Sort timestamps chronologically
        timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Compute intervals between successive connections
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| w[1] - w[0])
            .filter(|&i| i >= MIN_INTERVAL_SECS && i <= MAX_INTERVAL_SECS)
            .collect();

        if intervals.len() < MIN_CONNECTIONS - 1 {
            continue;
        }

        // Compute all 4 RITA scores
        let cv = compute_cv(&intervals);
        let skew = compute_skew(&intervals);
        let madm = compute_madm(&intervals);
        let bowley = compute_bowley(&intervals);

        // Combined weighted score
        let combined = W_CV * cv + W_SKEW * skew + W_MADM * madm + W_BOWLEY * bowley;

        if combined < SCORE_HIGH {
            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            let server_name = server_names.get(&(dst.clone(), port)).cloned();
            let candidate = BeaconCandidate {
                src_ip: src,
                dst_ip: dst,
                dst_port: port,
                connection_count: timestamps.len(),
                mean_interval: mean,
                cv,
                skew,
                madm,
                bowley,
                combined_score: combined,
                server_name,
            };
            create_beacon_finding(store.as_ref(), &candidate).await;
            result.beacons_detected += 1;
            result.findings_created += 1;
        }
    }

    if result.beacons_detected > 0 {
        tracing::warn!(
            "NDR-BEACON: {} flows analyzed, {} beacons detected",
            result.flow_groups,
            result.beacons_detected
        );
    }

    result
}

// ── RITA Statistical Scores ──
// All scores are normalized to 0.0-1.0 where 0.0 = perfect beacon pattern.
// Algorithms replicated from RITA v5 (GPLv3 — algorithms are facts, not copyrightable).

/// 1. Coefficient of Variation: stddev / mean.
/// Perfect beacon: CV ≈ 0 (identical intervals).
/// Human traffic: CV > 0.5 (random intervals).
fn compute_cv(intervals: &[f64]) -> f64 {
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return 1.0;
    }
    let variance = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / n;
    let cv = variance.sqrt() / mean;
    cv.min(1.0) // Clamp to 0-1
}

/// 2. Skew: asymmetry of the distribution.
/// Perfect beacon: skew ≈ 0 (symmetric).
/// Jittered beacon: slight positive skew (long tail from occasional delays).
/// Normalized to 0-1 range via absolute value and clamping.
fn compute_skew(intervals: &[f64]) -> f64 {
    let n = intervals.len() as f64;
    if n < 3.0 {
        return 0.5;
    }
    let mean = intervals.iter().sum::<f64>() / n;
    let variance = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();
    if stddev <= 0.0 {
        return 0.0;
    } // All intervals identical = beacon
    let skewness = intervals
        .iter()
        .map(|i| ((i - mean) / stddev).powi(3))
        .sum::<f64>()
        / n;
    // Normalize: |skew| / 2, clamped to 0-1
    // Low |skew| = symmetric = beacon-like
    (skewness.abs() / 2.0).min(1.0)
}

/// 3. MADM: Median Absolute Deviation of Median.
/// Robust measure of dispersion (resistant to outliers, unlike stddev).
/// Perfect beacon: MADM ≈ 0 (all intervals near median).
/// Normalized by dividing by median.
fn compute_madm(intervals: &[f64]) -> f64 {
    let mut sorted = intervals.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = percentile(&sorted, 50.0);
    if median <= 0.0 {
        return 1.0;
    }
    // Compute absolute deviations from median
    let mut deviations: Vec<f64> = sorted.iter().map(|i| (i - median).abs()).collect();
    deviations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = percentile(&deviations, 50.0);
    // Normalize: MAD / median, clamped to 0-1
    (mad / median).min(1.0)
}

/// 4. Bowley coefficient (quartile skewness).
/// Uses quartiles instead of mean/stddev — robust to outliers.
/// Formula: (Q1 + Q3 - 2*Q2) / (Q3 - Q1)
/// Perfect beacon: Bowley ≈ 0 (symmetric quartiles).
/// Range: -1 to 1, normalized to 0-1 via absolute value.
fn compute_bowley(intervals: &[f64]) -> f64 {
    let mut sorted = intervals.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    if sorted.len() < 4 {
        return 0.5;
    }

    let q1 = percentile(&sorted, 25.0);
    let q2 = percentile(&sorted, 50.0);
    let q3 = percentile(&sorted, 75.0);

    let iqr = q3 - q1;
    if iqr <= 0.0 {
        return 0.0;
    } // All quartiles equal = beacon

    let bowley = (q1 + q3 - 2.0 * q2) / iqr;
    // Normalize: |bowley| is already 0-1 range
    bowley.abs().min(1.0)
}

/// Compute percentile using linear interpolation.
fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = (pct / 100.0) * (sorted.len() - 1) as f64;
    let lower = idx.floor() as usize;
    let upper = idx.ceil() as usize;
    if lower == upper || upper >= sorted.len() {
        sorted[lower.min(sorted.len() - 1)]
    } else {
        let frac = idx - lower as f64;
        sorted[lower] * (1.0 - frac) + sorted[upper] * frac
    }
}

/// Create a finding for a detected beacon.
async fn create_beacon_finding(store: &dyn Database, beacon: &BeaconCandidate) {
    let severity = if beacon.combined_score < SCORE_CRITICAL {
        "CRITICAL"
    } else {
        "HIGH"
    };
    let confidence = if beacon.combined_score < SCORE_CRITICAL {
        "très élevée"
    } else {
        "élevée"
    };

    let sni_info = beacon.server_name.as_deref().unwrap_or("inconnu");

    let title = format!(
        "Beacon C2 détecté: {} → {}:{} (intervalle {:.0}s, score {:.3})",
        beacon.src_ip, beacon.dst_ip, beacon.dst_port, beacon.mean_interval, beacon.combined_score
    );

    let description = format!(
        "Communication régulière détectée entre {} et {}:{} (SNI: {}).\n\
         \n\
         - {} connexions en fenêtre d'analyse\n\
         - Intervalle moyen: {:.1} secondes\n\
         - Score combiné: {:.3} (seuil HIGH: {}, CRITICAL: {})\n\
         - Confiance: {}\n\
         \n\
         Scores RITA détaillés:\n\
         - CV (régularité): {:.3}\n\
         - Skew (asymétrie): {:.3}\n\
         - MADM (dispersion robuste): {:.3}\n\
         - Bowley (forme distribution): {:.3}\n\
         \n\
         Un trafic réseau aussi régulier est typique d'un beacon C2 \
         (Cobalt Strike, Sliver, Meterpreter). Le trafic humain normal \
         a un score combiné > 0.5. Un score de {:.3} indique une communication automatisée.\n\
         \n\
         Action recommandée: vérifier le processus source sur la machine, \
         analyser le trafic réseau, isoler si confirmé.",
        beacon.src_ip,
        beacon.dst_ip,
        beacon.dst_port,
        sni_info,
        beacon.connection_count,
        beacon.mean_interval,
        beacon.combined_score,
        SCORE_HIGH,
        SCORE_CRITICAL,
        confidence,
        beacon.cv,
        beacon.skew,
        beacon.madm,
        beacon.bowley,
        beacon.combined_score,
    );

    let _ = store
        .insert_finding(&crate::db::threatclaw_store::NewFinding {
            skill_id: "ndr-beacon".into(),
            title,
            description: Some(description),
            severity: severity.into(),
            category: Some("c2-detection".into()),
            asset: Some(beacon.src_ip.clone()),
            source: Some("Beacon timing analysis (RITA 4-score)".into()),
            metadata: Some(serde_json::json!({
                "src_ip": beacon.src_ip,
                "dst_ip": beacon.dst_ip,
                "dst_port": beacon.dst_port,
                "server_name": beacon.server_name,
                "connection_count": beacon.connection_count,
                "mean_interval_sec": beacon.mean_interval,
                "score_cv": beacon.cv,
                "score_skew": beacon.skew,
                "score_madm": beacon.madm,
                "score_bowley": beacon.bowley,
                "score_combined": beacon.combined_score,
                "detection": "beacon-timing-rita",
                "mitre": ["T1071.001", "T1573.002"]
            })),
        })
        .await;
}

/// Check if an IP is in a private/internal range.
fn is_private(ip: &str) -> bool {
    crate::agent::ip_classifier::is_non_routable(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cv_perfect_beacon() {
        // All intervals identical = CV 0
        let intervals = vec![60.0, 60.0, 60.0, 60.0, 60.0];
        assert!(compute_cv(&intervals) < 0.01);
    }

    #[test]
    fn test_cv_jittered_beacon() {
        // Small jitter = low CV
        let intervals = vec![60.0, 61.0, 59.0, 60.5, 59.5, 60.2];
        let cv = compute_cv(&intervals);
        assert!(cv < 0.05, "jittered CV: {}", cv);
    }

    #[test]
    fn test_cv_human_traffic() {
        // Irregular = high CV
        let intervals = vec![5.0, 120.0, 30.0, 300.0, 15.0, 600.0];
        let cv = compute_cv(&intervals);
        assert!(cv > 0.5, "human CV: {}", cv);
    }

    #[test]
    fn test_skew_symmetric() {
        let intervals = vec![60.0, 60.0, 60.0, 60.0, 60.0];
        assert!(compute_skew(&intervals) < 0.01);
    }

    #[test]
    fn test_madm_beacon() {
        let intervals = vec![60.0, 60.0, 60.0, 60.0, 60.0];
        assert!(compute_madm(&intervals) < 0.01);
    }

    #[test]
    fn test_madm_outlier_resistant() {
        // One outlier should not blow up MADM (unlike stddev)
        let intervals = vec![60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 500.0];
        let madm = compute_madm(&intervals);
        assert!(madm < 0.1, "MADM with outlier: {}", madm);
    }

    #[test]
    fn test_bowley_symmetric() {
        let intervals = vec![58.0, 59.0, 60.0, 61.0, 62.0];
        let bowley = compute_bowley(&intervals);
        assert!(bowley < 0.2, "bowley symmetric: {}", bowley);
    }

    #[test]
    fn test_combined_perfect_beacon() {
        let intervals = vec![60.0, 60.0, 60.0, 60.0, 60.0];
        let combined = W_CV * compute_cv(&intervals)
            + W_SKEW * compute_skew(&intervals)
            + W_MADM * compute_madm(&intervals)
            + W_BOWLEY * compute_bowley(&intervals);
        assert!(
            combined < SCORE_CRITICAL,
            "perfect beacon combined: {}",
            combined
        );
    }

    #[test]
    fn test_combined_human_traffic() {
        let intervals = vec![5.0, 120.0, 30.0, 300.0, 15.0, 600.0, 45.0];
        let combined = W_CV * compute_cv(&intervals)
            + W_SKEW * compute_skew(&intervals)
            + W_MADM * compute_madm(&intervals)
            + W_BOWLEY * compute_bowley(&intervals);
        assert!(combined > SCORE_HIGH, "human combined: {}", combined);
    }

    #[test]
    fn test_percentile() {
        let sorted = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((percentile(&sorted, 50.0) - 3.0).abs() < 0.01);
        assert!((percentile(&sorted, 25.0) - 2.0).abs() < 0.01);
        assert!((percentile(&sorted, 75.0) - 4.0).abs() < 0.01);
    }
}
