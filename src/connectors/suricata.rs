//! Suricata Connector — ingest Suricata EVE JSON log.
//!
//! Suricata produces eve.json — a single JSON firehose with event types:
//! alert, dns, http, tls, flow, fileinfo, anomaly, dhcp, smtp, ssh, stats.
//! This connector reads eve.json and creates sigma alerts for IDS detections.

use crate::db::Database;
use crate::db::threatclaw_store::{ThreatClawStore, NewFinding};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuricataConfig {
    pub eve_json_path: String,  // e.g. "/var/log/suricata/eve.json"
}

#[derive(Debug, Clone, Serialize)]
pub struct SuricataSyncResult {
    pub events_processed: usize,
    pub alerts_created: usize,
    pub dns_events: usize,
    pub flow_events: usize,
    pub errors: Vec<String>,
}

pub async fn sync_suricata(store: &dyn Database, config: &SuricataConfig) -> SuricataSyncResult {
    let mut result = SuricataSyncResult {
        events_processed: 0, alerts_created: 0, dns_events: 0, flow_events: 0, errors: vec![],
    };

    let path = Path::new(&config.eve_json_path);
    if !path.exists() {
        result.errors.push(format!("Suricata eve.json not found: {}", config.eve_json_path));
        return result;
    }

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("Read eve.json: {}", e)); return result; }
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }

        let event: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        result.events_processed += 1;
        let event_type = event["event_type"].as_str().unwrap_or("");
        let src_ip = event["src_ip"].as_str().unwrap_or("");
        let dest_ip = event["dest_ip"].as_str().unwrap_or("");
        let now_str = chrono::Utc::now().to_rfc3339();
        let timestamp = event["timestamp"].as_str().unwrap_or(&now_str);

        match event_type {
            "alert" => {
                let signature = event["alert"]["signature"].as_str().unwrap_or("Unknown rule");
                let severity = event["alert"]["severity"].as_i64().unwrap_or(3);
                let sid = event["alert"]["signature_id"].as_i64().unwrap_or(0);
                let category = event["alert"]["category"].as_str().unwrap_or("");

                let level = match severity {
                    1 => "critical",
                    2 => "high",
                    3 => "medium",
                    _ => "low",
                };

                let title = format!("Suricata [{}]: {} (SID {})", category, signature, sid);

                if let Err(e) = store.insert_sigma_alert(
                    &format!("suricata-{}", sid), level, &title, dest_ip, Some(src_ip), None,
                ).await {
                    result.errors.push(format!("Insert alert: {}", e));
                } else {
                    result.alerts_created += 1;
                }

                // Also store as log for ML feature extraction
                let _ = store.insert_log("suricata.alert", dest_ip, &event, timestamp).await;
            }
            "dns" => {
                result.dns_events += 1;
                let _ = store.insert_log("suricata.dns", src_ip, &event, timestamp).await;
            }
            "flow" => {
                result.flow_events += 1;
                let _ = store.insert_log("suricata.flow", src_ip, &event, timestamp).await;

                // Detect large flows
                let bytes_toserver = event["flow"]["bytes_toserver"].as_i64().unwrap_or(0);
                if bytes_toserver > 50_000_000 && !crate::agent::ip_classifier::is_private(dest_ip) {
                    let title = format!("Suricata: large flow {} → {} ({:.1} MB)",
                        src_ip, dest_ip, bytes_toserver as f64 / 1_000_000.0);
                    let _ = store.insert_sigma_alert("suricata-large-flow", "high", &title, src_ip, Some(dest_ip), None).await;
                    result.alerts_created += 1;
                }
            }
            "tls" | "http" | "ssh" | "smtp" | "fileinfo" => {
                let _ = store.insert_log(&format!("suricata.{}", event_type), src_ip, &event, timestamp).await;
            }
            _ => {}
        }
    }

    tracing::info!(
        "SURICATA: {} events, {} alerts, {} DNS, {} flows",
        result.events_processed, result.alerts_created, result.dns_events, result.flow_events
    );

    result
}
