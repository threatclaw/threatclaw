//! C2 Beacon timing detection. See ADR-005.

use std::collections::HashMap;
use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// Beacon detection thresholds.
const MIN_CONNECTIONS: usize = 5;        // Need at least 5 connections to detect a pattern
const CV_THRESHOLD: f64 = 0.20;          // Coefficient of variation < 0.20 = suspicious regularity
const CV_CRITICAL: f64 = 0.10;           // CV < 0.10 = almost certainly a beacon
const MIN_INTERVAL_SECS: f64 = 5.0;      // Ignore intervals < 5s (normal keep-alive)
const MAX_INTERVAL_SECS: f64 = 3600.0;   // Ignore intervals > 1h (not beacon-like)

/// Result of a beacon scan cycle.
#[derive(Debug)]
pub struct BeaconScanResult {
    pub connections_analyzed: usize,
    pub flow_groups: usize,
    pub beacons_detected: usize,
    pub findings_created: usize,
}

/// A detected beacon candidate.
#[derive(Debug)]
struct BeaconCandidate {
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
    connection_count: usize,
    mean_interval: f64,
    cv: f64,
    server_name: Option<String>,
}

/// Scan recent Zeek conn.log entries for C2 beacon timing patterns.
/// Runs every IE cycle (5 min).
pub async fn scan_beacons(
    store: std::sync::Arc<dyn Database>,
    minutes_back: i64,
) -> BeaconScanResult {
    let mut result = BeaconScanResult {
        connections_analyzed: 0, flow_groups: 0,
        beacons_detected: 0, findings_created: 0,
    };

    // Query recent Zeek connection logs
    let logs = store.query_logs(minutes_back, None, Some("zeek.conn"), 5000).await.unwrap_or_default();
    result.connections_analyzed = logs.len();

    if logs.len() < MIN_CONNECTIONS { return result; }

    // Group connections by (src_ip, dst_ip, dst_port)
    let mut flows: HashMap<(String, String, u16), Vec<f64>> = HashMap::new();
    // Track server names from SSL logs for enrichment
    let mut server_names: HashMap<(String, u16), String> = HashMap::new();

    for log in &logs {
        let src = log.data["id.orig_h"].as_str().unwrap_or("");
        let dst = log.data["id.resp_h"].as_str().unwrap_or("");
        let port = log.data["id.resp_p"].as_u64().unwrap_or(0) as u16;

        if src.is_empty() || dst.is_empty() || port == 0 { continue; }

        // Skip internal-to-internal (not C2-like) — only flag outbound or external
        if is_private(src) && is_private(dst) { continue; }
        // Skip DNS (port 53) and NTP (port 123) — naturally regular
        if port == 53 || port == 123 { continue; }

        // Extract timestamp as epoch float
        let ts = log.data["ts"].as_f64().unwrap_or(0.0);
        if ts == 0.0 { continue; }

        flows.entry((src.to_string(), dst.to_string(), port))
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
        if timestamps.len() < MIN_CONNECTIONS { continue; }

        // Sort timestamps chronologically
        timestamps.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Compute intervals between successive connections
        let intervals: Vec<f64> = timestamps.windows(2)
            .map(|w| w[1] - w[0])
            .filter(|&i| i >= MIN_INTERVAL_SECS && i <= MAX_INTERVAL_SECS)
            .collect();

        if intervals.len() < MIN_CONNECTIONS - 1 { continue; }

        // Compute mean and standard deviation
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean < MIN_INTERVAL_SECS { continue; }

        let variance = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let stddev = variance.sqrt();

        // Coefficient of variation
        let cv = if mean > 0.0 { stddev / mean } else { 1.0 };

        if cv < CV_THRESHOLD {
            let server_name = server_names.get(&(dst.clone(), port)).cloned();
            let candidate = BeaconCandidate {
                src_ip: src, dst_ip: dst, dst_port: port,
                connection_count: timestamps.len(),
                mean_interval: mean, cv,
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
            result.flow_groups, result.beacons_detected
        );
    }

    result
}

/// Create a finding for a detected beacon.
async fn create_beacon_finding(store: &dyn Database, beacon: &BeaconCandidate) {
    let severity = if beacon.cv < CV_CRITICAL { "CRITICAL" } else { "HIGH" };
    let confidence = if beacon.cv < CV_CRITICAL { "très élevée" } else { "élevée" };

    let sni_info = beacon.server_name.as_deref().unwrap_or("inconnu");

    let title = format!(
        "Beacon C2 détecté: {} → {}:{} (intervalle {:.0}s, CV={:.3})",
        beacon.src_ip, beacon.dst_ip, beacon.dst_port, beacon.mean_interval, beacon.cv
    );

    let description = format!(
        "Communication régulière détectée entre {} et {}:{} (SNI: {}).\n\
         \n\
         - {} connexions en fenêtre d'analyse\n\
         - Intervalle moyen: {:.1} secondes\n\
         - Coefficient de variation: {:.3} (seuil: {})\n\
         - Confiance: {}\n\
         \n\
         Un trafic réseau aussi régulier est typique d'un beacon C2 \
         (Cobalt Strike, Sliver, Meterpreter). Le trafic humain normal \
         a un CV > 0.5. Un CV de {:.3} indique une communication automatisée.\n\
         \n\
         Action recommandée: vérifier le processus source sur la machine, \
         analyser le trafic réseau, isoler si confirmé.",
        beacon.src_ip, beacon.dst_ip, beacon.dst_port, sni_info,
        beacon.connection_count,
        beacon.mean_interval,
        beacon.cv, CV_THRESHOLD,
        confidence,
        beacon.cv,
    );

    let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
        skill_id: "ndr-beacon".into(),
        title,
        description: Some(description),
        severity: severity.into(),
        category: Some("c2-detection".into()),
        asset: Some(beacon.src_ip.clone()),
        source: Some("Beacon timing analysis".into()),
        metadata: Some(serde_json::json!({
            "src_ip": beacon.src_ip,
            "dst_ip": beacon.dst_ip,
            "dst_port": beacon.dst_port,
            "server_name": beacon.server_name,
            "connection_count": beacon.connection_count,
            "mean_interval_sec": beacon.mean_interval,
            "coefficient_of_variation": beacon.cv,
            "detection": "beacon-timing",
            "mitre": ["T1071.001", "T1573.002"]  // C2 over HTTPS + Encrypted Channel
        })),
    }).await;
}

/// Check if an IP is in a private range.
fn is_private(ip: &str) -> bool {
    ip.starts_with("10.") || ip.starts_with("192.168.") ||
    ip.starts_with("172.16.") || ip.starts_with("172.17.") ||
    ip.starts_with("172.18.") || ip.starts_with("172.19.") ||
    ip.starts_with("172.2") || ip.starts_with("172.30.") ||
    ip.starts_with("172.31.") || ip.starts_with("127.") ||
    ip.starts_with("169.254.")
}
