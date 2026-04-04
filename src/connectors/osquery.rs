// See ADR-044: osquery-based endpoint visibility
//
// osquery (Apache 2.0, Linux Foundation) exposes the OS as SQL tables.
// This connector ingests osquery results (JSON logs) and:
// 1. Enriches assets with software inventory, OS, hardware
// 2. Feeds process network connections to Bloom filter / IE
// 3. Creates sigma alerts for suspicious process/file events
// 4. Provides features for ML behavioral analysis

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryConfig {
    pub log_path: Option<String>,
    pub webhook_mode: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsquerySyncResult {
    pub logs_processed: usize,
    pub assets_enriched: usize,
    pub software_items: usize,
    pub connections_checked: usize,
    pub alerts_created: usize,
    pub errors: Vec<String>,
}

// ── Software inventory ingestion ──

pub async fn ingest_software_inventory(
    store: &dyn Database,
    hostname: &str,
    entries: &[serde_json::Value],
) -> (usize, Vec<String>) {
    let mut count = 0usize;
    let mut software: Vec<serde_json::Value> = Vec::new();

    for entry in entries {
        let name = entry["name"].as_str().unwrap_or("").trim();
        let version = entry["version"].as_str().unwrap_or("").trim();
        if name.is_empty() { continue; }

        software.push(serde_json::json!({
            "name": name,
            "version": version,
            "source": "osquery",
            "detected_at": chrono::Utc::now().to_rfc3339(),
        }));
        count += 1;
    }

    if !software.is_empty() {
        if let Ok(Some(asset)) = store.find_asset_by_hostname(hostname).await {
            let _ = store.update_asset_software(&asset.id, &serde_json::Value::Array(software)).await;
        }
    }

    (count, vec![])
}

// ── Process network connections → IoC check ──

pub async fn check_process_connections(
    store: &dyn Database,
    hostname: &str,
    sockets: &[serde_json::Value],
) -> (usize, usize) {
    let mut checked = 0usize;
    let mut alerts = 0usize;
    let bloom = crate::agent::ioc_bloom::IOC_BLOOM.read().await;

    for sock in sockets {
        let remote_addr = sock["remote_address"].as_str().unwrap_or("");
        let remote_port = sock["remote_port"].as_str()
            .or_else(|| sock["remote_port"].as_u64().map(|_| ""))
            .unwrap_or("");
        let process_name = sock["name"].as_str()
            .or_else(|| sock["process_name"].as_str())
            .unwrap_or("unknown");
        let process_path = sock["path"].as_str()
            .or_else(|| sock["process_path"].as_str())
            .unwrap_or("");
        let state = sock["state"].as_str().unwrap_or("");

        if remote_addr.is_empty() || state != "ESTABLISHED" { continue; }
        if crate::agent::ip_classifier::is_non_routable(remote_addr) { continue; }

        checked += 1;

        // Check remote IP against Bloom filter
        let remote_lower = remote_addr.to_lowercase();
        if bloom.maybe_contains(&remote_lower) {
            // Bloom hit → verify and create alert
            let title = format!(
                "Connexion suspecte: {} ({}) → {}:{}",
                process_name, hostname, remote_addr, remote_port
            );
            let _ = store.insert_sigma_alert(
                "osquery-ioc-conn",
                "critical",
                &title,
                hostname,
                Some(remote_addr),
                None,
            ).await;
            alerts += 1;

            tracing::warn!(
                "OSQUERY: IoC connection! {} on {} → {}:{}",
                process_name, hostname, remote_addr, remote_port
            );
        }

        // Check for suspicious process paths
        if is_suspicious_path(process_path) {
            let title = format!(
                "Process suspect: {} ({}) depuis {}",
                process_name, hostname, process_path
            );
            let _ = store.insert_sigma_alert(
                "osquery-suspicious-process",
                "high",
                &title,
                hostname,
                Some(remote_addr),
                None,
            ).await;
            alerts += 1;
        }
    }

    (checked, alerts)
}

fn is_suspicious_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    path_lower.starts_with("/tmp/") ||
    path_lower.starts_with("/dev/shm/") ||
    path_lower.starts_with("/var/tmp/") ||
    path_lower.contains("\\temp\\") ||
    path_lower.contains("\\appdata\\local\\temp\\") ||
    path_lower.starts_with("/home/") && path_lower.contains("/.") // hidden file in home
}

// ── DNS cache → DGA detection + Bloom check ──

pub async fn check_dns_cache(
    store: &dyn Database,
    hostname: &str,
    dns_entries: &[serde_json::Value],
) -> (usize, usize) {
    let mut checked = 0usize;
    let mut alerts = 0usize;
    let bloom = crate::agent::ioc_bloom::IOC_BLOOM.read().await;

    for entry in dns_entries {
        let domain = entry["name"].as_str()
            .or_else(|| entry["domain"].as_str())
            .unwrap_or("").trim().to_lowercase();

        if domain.is_empty() || domain == "localhost" { continue; }
        checked += 1;

        // Check domain against Bloom filter (known malicious domains)
        if bloom.maybe_contains(&domain) {
            let title = format!("DNS résolution suspecte: {} sur {}", domain, hostname);
            let _ = store.insert_sigma_alert(
                "osquery-malicious-dns",
                "high",
                &title,
                hostname,
                None,
                None,
            ).await;
            alerts += 1;
        }
    }

    // Store DNS entries as logs for ML analysis (DGA detection)
    if !dns_entries.is_empty() {
        let batch = serde_json::json!({
            "source": "osquery-dns",
            "hostname": hostname,
            "domains": dns_entries.iter()
                .filter_map(|e| e["name"].as_str().or(e["domain"].as_str()))
                .collect::<Vec<_>>(),
        });
        let _ = store.insert_log(
            "osquery.dns",
            hostname,
            &batch,
            &chrono::Utc::now().to_rfc3339(),
        ).await;
    }

    (checked, alerts)
}

// ── Process events → kill chain detection ──

pub async fn check_process_events(
    store: &dyn Database,
    hostname: &str,
    events: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;

    for event in events {
        let path = event["path"].as_str().unwrap_or("");
        let parent = event["parent"].as_str()
            .or_else(|| event["parent_path"].as_str())
            .unwrap_or("");
        let cmdline = event["cmdline"].as_str().unwrap_or("");

        // Detect Office → shell (macro malware)
        if is_office_process(parent) && is_shell_process(path) {
            let title = format!(
                "Kill chain: {} a lancé {} sur {}",
                parent.rsplit('/').next().unwrap_or(parent),
                path.rsplit('/').next().unwrap_or(path),
                hostname
            );
            let _ = store.insert_sigma_alert(
                "osquery-office-shell",
                "critical",
                &title,
                hostname,
                None,
                None,
            ).await;
            alerts += 1;
        }

        // Detect download tools (wget/curl/certutil) spawned by unexpected parents
        if is_download_tool(path) && !is_expected_download_parent(parent) {
            let title = format!(
                "Téléchargement suspect: {} lancé par {} sur {}",
                path.rsplit('/').next().unwrap_or(path),
                parent.rsplit('/').next().unwrap_or(parent),
                hostname
            );
            let _ = store.insert_sigma_alert(
                "osquery-suspicious-download",
                "high",
                &title,
                hostname,
                None,
                None,
            ).await;
            alerts += 1;
        }

        // Detect execution from suspicious paths
        if is_suspicious_path(path) && !cmdline.is_empty() {
            let title = format!(
                "Exécution depuis path suspect: {} sur {}",
                path, hostname
            );
            let _ = store.insert_sigma_alert(
                "osquery-exec-suspicious-path",
                "high",
                &title,
                hostname,
                None,
                None,
            ).await;
            alerts += 1;
        }
    }

    alerts
}

fn is_office_process(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("winword") || p.contains("excel") || p.contains("powerpnt") ||
    p.contains("outlook") || p.contains("libreoffice") || p.contains("soffice")
}

fn is_shell_process(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("cmd.exe") || p.contains("powershell") || p.contains("pwsh") ||
    p.contains("/bin/sh") || p.contains("/bin/bash") || p.contains("wscript") ||
    p.contains("cscript") || p.contains("mshta")
}

fn is_download_tool(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("wget") || p.contains("curl") || p.contains("certutil") ||
    p.contains("bitsadmin") || p.contains("invoke-webrequest")
}

fn is_expected_download_parent(parent: &str) -> bool {
    let p = parent.to_lowercase();
    p.contains("apt") || p.contains("yum") || p.contains("dnf") || p.contains("pacman") ||
    p.contains("pip") || p.contains("npm") || p.contains("cargo") ||
    p.contains("update") || p.contains("upgrade") || p.is_empty()
}

// ── File events → FIM alerts ──

pub async fn check_file_events(
    store: &dyn Database,
    hostname: &str,
    events: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;

    for event in events {
        let target_path = event["target_path"].as_str()
            .or_else(|| event["path"].as_str())
            .unwrap_or("");
        let action = event["action"].as_str().unwrap_or("MODIFIED");

        if target_path.is_empty() { continue; }

        if is_critical_file(target_path) {
            let title = format!(
                "FIM: {} {} sur {}",
                target_path, action, hostname
            );
            let severity = if is_auth_file(target_path) { "critical" } else { "high" };
            let _ = store.insert_sigma_alert(
                "osquery-fim",
                severity,
                &title,
                hostname,
                None,
                None,
            ).await;
            alerts += 1;
        }
    }

    alerts
}

fn is_critical_file(path: &str) -> bool {
    let critical_paths = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
        "/etc/crontab", "/etc/hosts", "/etc/resolv.conf",
        "/root/.ssh/authorized_keys", "/root/.bashrc",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ];
    critical_paths.iter().any(|p| path.eq_ignore_ascii_case(p)) ||
    path.contains("/.ssh/authorized_keys") ||
    path.contains("/cron.d/") ||
    path.contains("/sudoers.d/")
}

fn is_auth_file(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("shadow") || p.contains("passwd") || p.contains("sudoers") ||
    p.contains("authorized_keys") || p.contains("\\sam")
}

// ── Webhook endpoint: process bulk osquery results ──

pub async fn process_osquery_webhook(
    store: &dyn Database,
    hostname: &str,
    body: &serde_json::Value,
) -> OsquerySyncResult {
    let mut result = OsquerySyncResult {
        logs_processed: 0, assets_enriched: 0, software_items: 0,
        connections_checked: 0, alerts_created: 0, errors: vec![],
    };

    // Process each query type from the batch
    if let Some(software) = body["software"].as_array() {
        let (count, _) = ingest_software_inventory(store, hostname, software).await;
        result.software_items = count;
        if count > 0 { result.assets_enriched += 1; }
    }

    if let Some(sockets) = body["process_open_sockets"].as_array() {
        let (checked, alerts) = check_process_connections(store, hostname, sockets).await;
        result.connections_checked = checked;
        result.alerts_created += alerts;
    }

    if let Some(dns) = body["dns_cache"].as_array() {
        let (checked, alerts) = check_dns_cache(store, hostname, dns).await;
        result.connections_checked += checked;
        result.alerts_created += alerts;
    }

    if let Some(proc_events) = body["process_events"].as_array() {
        result.alerts_created += check_process_events(store, hostname, proc_events).await;
    }

    if let Some(file_events) = body["file_events"].as_array() {
        result.alerts_created += check_file_events(store, hostname, file_events).await;
    }

    // OS info enrichment
    if let Some(os_info) = body.get("os_version") {
        if let Ok(Some(asset)) = store.find_asset_by_hostname(hostname).await {
            let os_str = format!("{} {}",
                os_info["name"].as_str().unwrap_or(""),
                os_info["version"].as_str().unwrap_or("")
            ).trim().to_string();
            if !os_str.is_empty() {
                // OS is updated via upsert_asset in the resolution pipeline
                result.assets_enriched += 1;
            }
        }
    }

    result.logs_processed = 1;

    if result.alerts_created > 0 || result.software_items > 0 {
        tracing::info!(
            "OSQUERY: {} from {} — {} software, {} connections, {} alerts",
            hostname, result.logs_processed, result.software_items,
            result.connections_checked, result.alerts_created
        );
    }

    result
}
