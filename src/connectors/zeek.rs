#![allow(unused_imports)]
//! Zeek Connector — ingest Zeek JSON logs for network metadata.
//!
//! Zeek produces structured JSON logs: conn.log, dns.log, http.log, ssl.log, ssh.log, etc.
//! This connector reads them from a directory (Docker volume or local path) and ingests into PostgreSQL.
//! Runs as a persistent skill — polls for new log entries every sync interval.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeekConfig {
    pub log_dir: String,            // e.g. "/opt/zeek/logs/current" or Docker volume
    #[serde(default = "default_interval")]
    pub sync_interval_minutes: u32,
}

fn default_interval() -> u32 { 5 }

#[derive(Debug, Clone, Serialize)]
pub struct ZeekSyncResult {
    pub conn_entries: usize,
    pub dns_entries: usize,
    pub http_entries: usize,
    pub ssl_entries: usize,
    pub ssh_entries: usize,
    pub alerts_created: usize,
    pub assets_discovered: usize,
    pub errors: Vec<String>,
}

/// Validate that a log path is within allowed directories and has no traversal.
fn validate_log_path(path: &str) -> Result<(), String> {
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("Invalid path: {}", e))?;
    let path_str = canonical.to_str().unwrap_or("");
    let allowed_prefixes = ["/opt/zeek/", "/var/log/", "/tmp/", "/srv/"];
    if !allowed_prefixes.iter().any(|p| path_str.starts_with(p)) {
        return Err(format!("Path {} is outside allowed directories", path_str));
    }
    if path_str.contains("..") {
        return Err("Path traversal detected".into());
    }
    Ok(())
}

pub async fn sync_zeek(store: &dyn Database, config: &ZeekConfig) -> ZeekSyncResult {
    let mut result = ZeekSyncResult {
        conn_entries: 0, dns_entries: 0, http_entries: 0,
        ssl_entries: 0, ssh_entries: 0,
        alerts_created: 0, assets_discovered: 0, errors: vec![],
    };

    // Validate path before accessing filesystem
    if let Err(e) = validate_log_path(&config.log_dir) {
        result.errors.push(format!("Zeek path validation failed: {}", e));
        return result;
    }

    let log_dir = Path::new(&config.log_dir);
    if !log_dir.exists() {
        result.errors.push(format!("Zeek log directory not found: {}", config.log_dir));
        return result;
    }

    // Process conn.log (network connections)
    let conn_path = log_dir.join("conn.log");
    if conn_path.exists() {
        match parse_zeek_json_log(&conn_path) {
            Ok(entries) => {
                for entry in &entries {
                    result.conn_entries += 1;
                    // Ingest as log
                    let src = entry["id.orig_h"].as_str().unwrap_or("");
                    let dst = entry["id.resp_h"].as_str().unwrap_or("");
                    let port = entry["id.resp_p"].as_i64().unwrap_or(0);
                    let _proto = entry["proto"].as_str().unwrap_or("tcp");
                    let duration = entry["duration"].as_f64().unwrap_or(0.0);
                    let orig_bytes = entry["orig_bytes"].as_i64().unwrap_or(0);
                    let _resp_bytes = entry["resp_bytes"].as_i64().unwrap_or(0);

                    let _ = store.insert_log("zeek.conn", dst, entry,
                        &entry["ts"].as_f64().map(|t| {
                            chrono::DateTime::from_timestamp(t as i64, 0)
                                .map(|dt| dt.to_rfc3339())
                                .unwrap_or_default()
                        }).unwrap_or_else(|| chrono::Utc::now().to_rfc3339())
                    ).await;

                    // Long connections (>1h) to external IPs = suspicious
                    if duration > 3600.0 && !crate::agent::ip_classifier::is_private(dst) {
                        let title = format!("Zeek: long connection {} → {}:{} ({:.0}min, {} bytes out)",
                            src, dst, port, duration / 60.0, orig_bytes);
                        let _ = store.insert_sigma_alert("zeek-long-conn", "medium", &title, src, Some(dst), None).await;
                        result.alerts_created += 1;
                    }

                    // Large data transfer to external (>50MB)
                    if orig_bytes > 50_000_000 && !crate::agent::ip_classifier::is_private(dst) {
                        let title = format!("Zeek: large upload {} → {} ({:.1} MB)",
                            src, dst, orig_bytes as f64 / 1_000_000.0);
                        let _ = store.insert_sigma_alert("zeek-large-upload", "high", &title, src, Some(dst), None).await;
                        result.alerts_created += 1;
                    }
                }
            }
            Err(e) => result.errors.push(format!("conn.log: {}", e)),
        }
    }

    // Process dns.log
    let dns_path = log_dir.join("dns.log");
    if dns_path.exists() {
        match parse_zeek_json_log(&dns_path) {
            Ok(entries) => {
                for entry in &entries {
                    result.dns_entries += 1;
                    let _query = entry["query"].as_str().unwrap_or("");
                    let src = entry["id.orig_h"].as_str().unwrap_or("");

                    let _ = store.insert_log("zeek.dns", src, entry,
                        &chrono::Utc::now().to_rfc3339()).await;
                }
            }
            Err(e) => result.errors.push(format!("dns.log: {}", e)),
        }
    }

    // Process ssl.log (TLS handshakes + JA4)
    let ssl_path = log_dir.join("ssl.log");
    if ssl_path.exists() {
        match parse_zeek_json_log(&ssl_path) {
            Ok(entries) => {
                for entry in &entries {
                    result.ssl_entries += 1;
                    let _ = store.insert_log("zeek.ssl",
                        entry["id.orig_h"].as_str().unwrap_or(""),
                        entry, &chrono::Utc::now().to_rfc3339()).await;

                    // Expired or self-signed certs
                    let validation = entry["validation_status"].as_str().unwrap_or("");
                    if validation.contains("expired") || validation.contains("self signed") {
                        let server = entry["server_name"].as_str().unwrap_or("unknown");
                        let title = format!("Zeek: SSL issue on {} — {}", server, validation);
                        let _ = store.insert_sigma_alert("zeek-ssl-issue", "medium", &title,
                            entry["id.resp_h"].as_str().unwrap_or(""), None, None).await;
                        result.alerts_created += 1;
                    }
                }
            }
            Err(e) => result.errors.push(format!("ssl.log: {}", e)),
        }
    }

    // Process ssh.log
    let ssh_path = log_dir.join("ssh.log");
    if ssh_path.exists() {
        match parse_zeek_json_log(&ssh_path) {
            Ok(entries) => {
                for entry in &entries {
                    result.ssh_entries += 1;
                    let _ = store.insert_log("zeek.ssh",
                        entry["id.resp_h"].as_str().unwrap_or(""),
                        entry, &chrono::Utc::now().to_rfc3339()).await;

                    // Failed SSH auth from external
                    let auth_success = entry["auth_success"].as_bool().unwrap_or(true);
                    let src = entry["id.orig_h"].as_str().unwrap_or("");
                    if !auth_success && !crate::agent::ip_classifier::is_private(src) {
                        let dst = entry["id.resp_h"].as_str().unwrap_or("");
                        let title = format!("Zeek: SSH auth failure {} → {}", src, dst);
                        let _ = store.insert_sigma_alert("zeek-ssh-fail", "medium", &title, dst, Some(src), None).await;
                        result.alerts_created += 1;
                    }
                }
            }
            Err(e) => result.errors.push(format!("ssh.log: {}", e)),
        }
    }

    // Process http.log
    let http_path = log_dir.join("http.log");
    if http_path.exists() {
        match parse_zeek_json_log(&http_path) {
            Ok(entries) => {
                for entry in &entries {
                    result.http_entries += 1;
                    let _ = store.insert_log("zeek.http",
                        entry["id.orig_h"].as_str().unwrap_or(""),
                        entry, &chrono::Utc::now().to_rfc3339()).await;
                }
            }
            Err(e) => result.errors.push(format!("http.log: {}", e)),
        }
    }

    // Discover assets from conn.log unique internal IPs
    // (done by the intelligence engine via sync_graph_from_db)

    tracing::info!(
        "ZEEK: conn={} dns={} ssl={} ssh={} http={} alerts={} errors={}",
        result.conn_entries, result.dns_entries, result.ssl_entries,
        result.ssh_entries, result.http_entries, result.alerts_created,
        result.errors.len()
    );

    result
}

/// Parse a Zeek JSON log file (one JSON object per line).
fn parse_zeek_json_log(path: &Path) -> Result<Vec<serde_json::Value>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {}", path.display(), e))?;

    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(v) => entries.push(v),
            Err(_) => continue, // Skip non-JSON lines (Zeek TSV headers)
        }
    }

    Ok(entries)
}
