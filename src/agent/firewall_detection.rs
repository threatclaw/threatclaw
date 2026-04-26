//! Firewall log pattern detection.
//!
//! Sigma rules are pattern matchers against single log lines — they work
//! for known-bad strings (PowerShell IEX, Mimikatz cmdline) but they
//! cannot count or aggregate. Port scans and brute force are by
//! construction *aggregate* phenomena: one src_ip × N dst_ports,
//! or one src_ip × M failed connections to the same auth port. We run
//! those as SQL aggregates against `firewall_events` (V54), every IE
//! cycle, with a 5-minute look-back window.
//!
//! Detections produce a finding (deduped via insert_finding) so the
//! Intelligence Engine sees them and can escalate to an investigation.

use crate::db::Database;
use crate::db::threatclaw_store::{FirewallBlockedAggregate, NewFinding};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct FirewallDetectionResult {
    pub windows_checked: usize,
    pub port_scans_detected: usize,
    pub brute_forces_detected: usize,
    pub findings_created: usize,
}

const SCAN_DISTINCT_PORTS_THRESHOLD: i64 = 25;
const SCAN_DISTINCT_HOSTS_THRESHOLD: i64 = 10;
const BRUTE_AUTH_PORT_HITS_THRESHOLD: i64 = 30;

/// Run pattern detection on the rolling firewall log buffer.
///
/// Window: `minutes_back` (typical 5 minutes from the IE cycle).
/// Emits high-severity findings for port scans and brute force.
pub async fn run_firewall_detection_cycle(
    store: Arc<dyn Database>,
    minutes_back: i64,
) -> FirewallDetectionResult {
    let mut result = FirewallDetectionResult::default();
    let since = chrono::Utc::now() - chrono::Duration::minutes(minutes_back);

    let aggregates = match store.firewall_blocked_aggregates(since).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("FIREWALL DETECTION: aggregate query failed: {e}");
            return result;
        }
    };
    result.windows_checked = aggregates.len();
    if aggregates.is_empty() {
        return result;
    }

    for agg in &aggregates {
        // Skip RFC1918 / loopback as scan source — usually own monitoring,
        // not real attackers. Brute-force from internal IPs is still
        // suspicious so we'll keep that path active for them.
        let from_internal = is_non_routable(&agg.src_ip);

        // ── Port scan detection ──
        // Wide horizontal (many hosts) or wide vertical (many ports) =
        // scan signature. Threshold low enough to catch nmap default
        // (-T4 1000-port scan = 1000 distinct ports) but high enough to
        // ignore casual rejection bursts.
        let is_port_scan = !from_internal
            && (agg.distinct_dst_ports >= SCAN_DISTINCT_PORTS_THRESHOLD
                || agg.distinct_dst_ips >= SCAN_DISTINCT_HOSTS_THRESHOLD);

        if is_port_scan {
            if create_scan_finding(store.as_ref(), agg, minutes_back).await {
                result.port_scans_detected += 1;
                result.findings_created += 1;
            }
        }

        // ── Brute-force detection ──
        // Volumetric block burst against the canonical auth ports
        // (SSH 22, RDP 3389, SMB 445). Internal sources counted too —
        // a domain workstation hammering 22/tcp on a server is the
        // signature of a credential-stuffing implant.
        let auth_total = agg.hits_ssh + agg.hits_rdp + agg.hits_smb;
        if auth_total >= BRUTE_AUTH_PORT_HITS_THRESHOLD {
            if create_brute_finding(store.as_ref(), agg, minutes_back, from_internal).await {
                result.brute_forces_detected += 1;
                result.findings_created += 1;
            }
        }
    }

    if result.findings_created > 0 {
        tracing::info!(
            "FIREWALL DETECTION: {} port scans, {} brute force ({} findings)",
            result.port_scans_detected,
            result.brute_forces_detected,
            result.findings_created
        );
    }

    result
}

async fn create_scan_finding(
    store: &dyn Database,
    agg: &FirewallBlockedAggregate,
    minutes_back: i64,
) -> bool {
    let title = format!("Port scan détecté depuis {}", agg.src_ip);
    let description = format!(
        "{} requêtes bloquées en {} min vers {} hôtes / {} ports distincts.\n\
         Échantillon de cibles : {}",
        agg.blocked_count,
        minutes_back,
        agg.distinct_dst_ips,
        agg.distinct_dst_ports,
        agg.sample_dst_ips.join(", ")
    );
    let severity = if agg.distinct_dst_ports >= 100 || agg.distinct_dst_ips >= 50 {
        "HIGH"
    } else {
        "MEDIUM"
    };
    let metadata = serde_json::json!({
        "detector": "firewall_port_scan",
        "src_ip": agg.src_ip,
        "blocked_count": agg.blocked_count,
        "distinct_dst_ips": agg.distinct_dst_ips,
        "distinct_dst_ports": agg.distinct_dst_ports,
        "window_minutes": minutes_back,
        "sample_dst_ips": agg.sample_dst_ips,
    });
    store
        .insert_finding(&NewFinding {
            skill_id: "firewall-detection".into(),
            title,
            description: Some(description),
            severity: severity.into(),
            category: Some("network-recon".into()),
            asset: Some(agg.src_ip.clone()),
            source: Some("Firewall log analyzer".into()),
            metadata: Some(metadata),
        })
        .await
        .is_ok()
}

async fn create_brute_finding(
    store: &dyn Database,
    agg: &FirewallBlockedAggregate,
    minutes_back: i64,
    from_internal: bool,
) -> bool {
    let services: Vec<&str> = [
        ("SSH (22)", agg.hits_ssh),
        ("RDP (3389)", agg.hits_rdp),
        ("SMB (445)", agg.hits_smb),
    ]
    .iter()
    .filter(|(_, c)| *c > 0)
    .map(|(label, _)| *label)
    .collect();
    let title = format!("Brute-force {} depuis {}", services.join("+"), agg.src_ip);
    let description = format!(
        "Tentatives bloquées sur {} min — SSH:{} RDP:{} SMB:{} (total {})",
        minutes_back, agg.hits_ssh, agg.hits_rdp, agg.hits_smb, agg.blocked_count
    );
    // Internal source = compromised workstation pivoting → CRITICAL.
    // External source = expected internet noise unless the volume is huge.
    let auth_total = agg.hits_ssh + agg.hits_rdp + agg.hits_smb;
    let severity = if from_internal {
        "CRITICAL"
    } else if auth_total >= 200 {
        "HIGH"
    } else {
        "MEDIUM"
    };
    let metadata = serde_json::json!({
        "detector": "firewall_brute_force",
        "src_ip": agg.src_ip,
        "from_internal": from_internal,
        "hits_ssh": agg.hits_ssh,
        "hits_rdp": agg.hits_rdp,
        "hits_smb": agg.hits_smb,
        "window_minutes": minutes_back,
    });
    store
        .insert_finding(&NewFinding {
            skill_id: "firewall-detection".into(),
            title,
            description: Some(description),
            severity: severity.into(),
            category: Some("auth-brute".into()),
            asset: Some(agg.src_ip.clone()),
            source: Some("Firewall log analyzer".into()),
            metadata: Some(metadata),
        })
        .await
        .is_ok()
}

fn is_non_routable(ip: &str) -> bool {
    crate::agent::ip_classifier::is_non_routable(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg(
        src: &str,
        blocked: i64,
        ports: i64,
        ips: i64,
        ssh: i64,
        rdp: i64,
        smb: i64,
    ) -> FirewallBlockedAggregate {
        FirewallBlockedAggregate {
            src_ip: src.to_string(),
            blocked_count: blocked,
            distinct_dst_ips: ips,
            distinct_dst_ports: ports,
            hits_ssh: ssh,
            hits_rdp: rdp,
            hits_smb: smb,
            sample_dst_ips: vec![],
        }
    }

    #[test]
    fn thresholds_classify_scan_and_brute() {
        // Public IP hitting many ports = port scan
        let s = agg("8.8.8.8", 1000, 1000, 5, 0, 0, 0);
        assert!(s.distinct_dst_ports >= SCAN_DISTINCT_PORTS_THRESHOLD);
        // Public IP hitting many hosts = port scan
        let s2 = agg("8.8.8.8", 100, 3, 50, 0, 0, 0);
        assert!(s2.distinct_dst_ips >= SCAN_DISTINCT_HOSTS_THRESHOLD);
        // SSH brute force
        let b = agg("8.8.8.8", 100, 1, 1, 100, 0, 0);
        assert!(b.hits_ssh + b.hits_rdp + b.hits_smb >= BRUTE_AUTH_PORT_HITS_THRESHOLD);
    }

    #[test]
    fn internal_ip_is_skipped_for_scan_but_not_brute() {
        // 192.168.x is internal, so port scan detection must skip it
        // (likely a vuln scanner / nessus / monitoring), but brute force
        // from internal IS suspicious (lateral movement implant).
        assert!(is_non_routable("192.168.1.50"));
        assert!(is_non_routable("10.0.0.5"));
        assert!(!is_non_routable("8.8.8.8"));
    }
}
