//! TLS certificate anomaly scoring.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// TLS anomaly score thresholds.
const SCORE_HIGH: u32 = 50;       // Finding: HIGH
const SCORE_CRITICAL: u32 = 80;   // Finding: CRITICAL

/// Scoring rules.
const SCORE_SELF_SIGNED: u32 = 40;
const SCORE_EXPIRED: u32 = 30;
const SCORE_NO_SNI: u32 = 25;
const SCORE_SHORT_VALIDITY: u32 = 20;
const SCORE_VALIDATION_FAIL: u32 = 35;
const SCORE_OUTBOUND: u32 = 20;   // Bonus: outbound connection (from internal to external)

/// Result of a TLS scoring cycle.
#[derive(Debug)]
pub struct TlsScanResult {
    pub logs_checked: usize,
    pub anomalies_found: usize,
    pub findings_created: usize,
}

/// Individual anomaly flags for a TLS connection.
#[derive(Debug, Default)]
struct TlsAnomalies {
    score: u32,
    reasons: Vec<String>,
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
    server_name: String,
    validation_status: String,
    ja3: String,
}

/// Scan recent Zeek ssl.log entries for TLS certificate anomalies.
/// Runs every IE cycle (5 min).
pub async fn scan_tls(
    store: std::sync::Arc<dyn Database>,
    minutes_back: i64,
) -> TlsScanResult {
    let mut result = TlsScanResult { logs_checked: 0, anomalies_found: 0, findings_created: 0 };

    let logs = store.query_logs(minutes_back, None, Some("zeek.ssl"), 2000).await.unwrap_or_default();
    result.logs_checked = logs.len();

    if logs.is_empty() { return result; }

    // Dedup: one finding per (dst_ip, dst_port) per cycle
    let mut seen_dests = std::collections::HashSet::new();

    for log in &logs {
        let src = log.data["id.orig_h"].as_str().unwrap_or("");
        let dst = log.data["id.resp_h"].as_str().unwrap_or("");
        let port = log.data["id.resp_p"].as_u64().unwrap_or(0) as u16;

        if dst.is_empty() || port == 0 { continue; }

        let dedup_key = format!("{}:{}", dst, port);
        if seen_dests.contains(&dedup_key) { continue; }

        let mut anomaly = TlsAnomalies {
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            dst_port: port,
            server_name: log.data["server_name"].as_str().unwrap_or("").to_string(),
            validation_status: log.data["validation_status"].as_str().unwrap_or("").to_string(),
            ja3: log.data["ja3"].as_str().unwrap_or("").to_string(),
            ..Default::default()
        };

        // ── Rule 1: Self-signed certificate ──
        if anomaly.validation_status.contains("self signed") {
            anomaly.score += SCORE_SELF_SIGNED;
            anomaly.reasons.push("Certificat auto-signé".into());
        }

        // ── Rule 2: Expired certificate ──
        if anomaly.validation_status.contains("expired") {
            anomaly.score += SCORE_EXPIRED;
            anomaly.reasons.push("Certificat expiré".into());
        }

        // ── Rule 3: Validation failure (any other failure) ──
        let validation = &anomaly.validation_status;
        if !validation.is_empty() && validation != "ok" &&
           !validation.contains("self signed") && !validation.contains("expired") {
            anomaly.score += SCORE_VALIDATION_FAIL;
            anomaly.reasons.push(format!("Validation TLS échouée: {}", validation));
        }

        // ── Rule 4: Empty or missing SNI ──
        if anomaly.server_name.is_empty() && (port == 443 || port == 8443) {
            anomaly.score += SCORE_NO_SNI;
            anomaly.reasons.push("SNI absent sur connexion HTTPS".into());
        }

        // ── Rule 5: Short certificate validity ──
        // Zeek provides not_valid_before and not_valid_after
        if let (Some(before), Some(after)) = (
            log.data["not_valid_before"].as_str().or(log.data["certificate.not_valid_before"].as_str()),
            log.data["not_valid_after"].as_str().or(log.data["certificate.not_valid_after"].as_str()),
        ) {
            if let (Ok(start), Ok(end)) = (
                chrono::NaiveDateTime::parse_from_str(before, "%Y-%m-%dT%H:%M:%S"),
                chrono::NaiveDateTime::parse_from_str(after, "%Y-%m-%dT%H:%M:%S"),
            ) {
                let validity_days = (end - start).num_days();
                if validity_days > 0 && validity_days < 30 {
                    anomaly.score += SCORE_SHORT_VALIDITY;
                    anomaly.reasons.push(format!("Validité très courte: {} jours", validity_days));
                }
            }
        }

        // ── Bonus: Outbound connection (internal → external) ──
        if is_internal(src) && !is_internal(dst) {
            anomaly.score += SCORE_OUTBOUND;
            // Don't add as a separate reason — it's a multiplier
        }

        // ── Threshold check ──
        if anomaly.score >= SCORE_HIGH {
            seen_dests.insert(dedup_key);
            result.anomalies_found += 1;
            create_tls_finding(store.as_ref(), &anomaly, log.hostname.as_deref()).await;
            result.findings_created += 1;
        }
    }

    if result.anomalies_found > 0 {
        tracing::warn!(
            "NDR-TLS: {} logs checked, {} anomalies scored above threshold",
            result.logs_checked, result.anomalies_found
        );
    }

    result
}

/// Create a finding for a TLS anomaly.
async fn create_tls_finding(store: &dyn Database, anomaly: &TlsAnomalies, hostname: Option<&str>) {
    let severity = if anomaly.score >= SCORE_CRITICAL { "CRITICAL" } else { "HIGH" };
    let reasons_text = anomaly.reasons.join(", ");
    let sni = if anomaly.server_name.is_empty() { "absent" } else { &anomaly.server_name };

    let title = format!(
        "Certificat TLS suspect: {} (score {}/100)",
        if anomaly.server_name.is_empty() { format!("{}:{}", anomaly.dst_ip, anomaly.dst_port) }
        else { anomaly.server_name.clone() },
        anomaly.score
    );

    let description = format!(
        "Connexion TLS avec anomalies détectées.\n\
         \n\
         - Source: {} → Destination: {}:{}\n\
         - SNI: {}\n\
         - Validation: {}\n\
         - Score anomalie: {}/100\n\
         - Anomalies: {}\n\
         \n\
         Les certificats auto-signés sur des connexions sortantes, \
         les SNI manquants et les validations échouées sont des indicateurs \
         classiques d'infrastructure C2 ou de tunnels malveillants.",
        anomaly.src_ip, anomaly.dst_ip, anomaly.dst_port,
        sni,
        if anomaly.validation_status.is_empty() { "inconnue" } else { &anomaly.validation_status },
        anomaly.score,
        reasons_text,
    );

    let asset = hostname.unwrap_or(&anomaly.src_ip);

    let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
        skill_id: "ndr-tls".into(),
        title,
        description: Some(description),
        severity: severity.into(),
        category: Some("c2-detection".into()),
        asset: Some(asset.to_string()),
        source: Some("TLS certificate scoring".into()),
        metadata: Some(serde_json::json!({
            "src_ip": anomaly.src_ip,
            "dst_ip": anomaly.dst_ip,
            "dst_port": anomaly.dst_port,
            "server_name": anomaly.server_name,
            "validation_status": anomaly.validation_status,
            "ja3": anomaly.ja3,
            "anomaly_score": anomaly.score,
            "anomalies": anomaly.reasons,
            "detection": "tls-certificate-scoring",
            "mitre": ["T1573.002", "T1071.001"]  // Encrypted Channel, C2 Web
        })),
    }).await;
}

fn is_internal(ip: &str) -> bool {
    crate::agent::ip_classifier::is_non_routable(ip)
}
