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

// ── Agent authentication ──
// See ADR-044: Communication agent → TC sécurisée
//
// Couche 1 : Webhook token HMAC (vérifié par webhook_ingest.rs avant d'arriver ici)
// Couche 2 : Agent ID vérifié contre la liste des agents enregistrés
// Couche 3 : TLS obligatoire (HTTPS entre l'agent et TC)
//
// L'agent s'enregistre au premier contact. TC stocke son ID + hostname.
// Les messages suivants sont vérifiés : agent_id doit matcher le hostname.

/// Verify agent identity. Returns true if agent is known or newly registered.
pub async fn verify_or_register_agent(
    store: &dyn Database,
    agent_id: &str,
    hostname: &str,
) -> bool {
    if agent_id.is_empty() {
        return true;
    } // Pas d'agent_id = mode webhook legacy

    let key = format!("agent_{}", agent_id);
    if let Ok(Some(registered)) = store.get_setting("_osquery_agents", &key).await {
        // Agent connu — vérifier que le hostname matche
        let registered_host = registered["hostname"].as_str().unwrap_or("");
        if registered_host != hostname && !registered_host.is_empty() {
            tracing::warn!(
                "OSQUERY: Agent {} hostname mismatch: registered={}, received={}",
                agent_id,
                registered_host,
                hostname
            );
            return false;
        }
        true
    } else {
        // Nouvel agent — enregistrer
        crate::connectors::log_db_write(
            "osquery:set_setting",
            store.set_setting(
                "_osquery_agents",
                &key,
                &serde_json::json!({
                    "hostname": hostname,
                    "registered_at": chrono::Utc::now().to_rfc3339(),
                    "last_seen": chrono::Utc::now().to_rfc3339(),
                }),
            ),
        )
        .await;
        tracing::info!("OSQUERY: New agent registered: {} ({})", agent_id, hostname);
        true
    }
}

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
        if name.is_empty() {
            continue;
        }

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
            crate::connectors::log_db_write(
                "osquery:update_asset_software",
                store.update_asset_software(&asset.id, &serde_json::Value::Array(software)),
            )
            .await;
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
        let remote_port = sock["remote_port"]
            .as_str()
            .or_else(|| sock["remote_port"].as_u64().map(|_| ""))
            .unwrap_or("");
        let process_name = sock["name"]
            .as_str()
            .or_else(|| sock["process_name"].as_str())
            .unwrap_or("unknown");
        let process_path = sock["path"]
            .as_str()
            .or_else(|| sock["process_path"].as_str())
            .unwrap_or("");
        let state = sock["state"].as_str().unwrap_or("");

        if remote_addr.is_empty() || state != "ESTABLISHED" {
            continue;
        }
        if crate::agent::ip_classifier::is_non_routable(remote_addr) {
            continue;
        }

        checked += 1;

        // Check remote IP against Bloom filter
        let remote_lower = remote_addr.to_lowercase();
        if bloom.maybe_contains(&remote_lower) {
            // Bloom hit → verify and create alert
            let title = format!(
                "Connexion suspecte: {} ({}) → {}:{}",
                process_name, hostname, remote_addr, remote_port
            );
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-ioc-conn",
                    "critical",
                    &title,
                    hostname,
                    Some(remote_addr),
                    None,
                ),
            )
            .await;
            alerts += 1;

            tracing::warn!(
                "OSQUERY: IoC connection! {} on {} → {}:{}",
                process_name,
                hostname,
                remote_addr,
                remote_port
            );
        }

        // Check for suspicious process paths
        if is_suspicious_path(process_path) {
            let title = format!(
                "Process suspect: {} ({}) depuis {}",
                process_name, hostname, process_path
            );
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-suspicious-process",
                    "high",
                    &title,
                    hostname,
                    Some(remote_addr),
                    None,
                ),
            )
            .await;
            alerts += 1;
        }
    }

    (checked, alerts)
}

fn is_suspicious_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    path_lower.starts_with("/tmp/")
        || path_lower.starts_with("/dev/shm/")
        || path_lower.starts_with("/var/tmp/")
        || path_lower.contains("\\temp\\")
        || path_lower.contains("\\appdata\\local\\temp\\")
        || path_lower.starts_with("/home/") && path_lower.contains("/.") // hidden file in home
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
        let domain = entry["name"]
            .as_str()
            .or_else(|| entry["domain"].as_str())
            .unwrap_or("")
            .trim()
            .to_lowercase();

        if domain.is_empty() || domain == "localhost" {
            continue;
        }
        checked += 1;

        // Check domain against Bloom filter (known malicious domains)
        if bloom.maybe_contains(&domain) {
            let title = format!("DNS résolution suspecte: {} sur {}", domain, hostname);
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-malicious-dns",
                    "high",
                    &title,
                    hostname,
                    None,
                    None,
                ),
            )
            .await;
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
        crate::connectors::log_db_write(
            "osquery:insert_log",
            store.insert_log(
                "osquery.dns",
                hostname,
                &batch,
                &chrono::Utc::now().to_rfc3339(),
            ),
        )
        .await;
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
        let parent = event["parent"]
            .as_str()
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
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-office-shell",
                    "critical",
                    &title,
                    hostname,
                    None,
                    None,
                ),
            )
            .await;
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
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-suspicious-download",
                    "high",
                    &title,
                    hostname,
                    None,
                    None,
                ),
            )
            .await;
            alerts += 1;
        }

        // Detect execution from suspicious paths
        if is_suspicious_path(path) && !cmdline.is_empty() {
            let title = format!("Exécution depuis path suspect: {} sur {}", path, hostname);
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-exec-suspicious-path",
                    "high",
                    &title,
                    hostname,
                    None,
                    None,
                ),
            )
            .await;
            alerts += 1;
        }
    }

    alerts
}

fn is_office_process(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("winword")
        || p.contains("excel")
        || p.contains("powerpnt")
        || p.contains("outlook")
        || p.contains("libreoffice")
        || p.contains("soffice")
}

fn is_shell_process(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("cmd.exe")
        || p.contains("powershell")
        || p.contains("pwsh")
        || p.contains("/bin/sh")
        || p.contains("/bin/bash")
        || p.contains("wscript")
        || p.contains("cscript")
        || p.contains("mshta")
}

fn is_download_tool(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("wget")
        || p.contains("curl")
        || p.contains("certutil")
        || p.contains("bitsadmin")
        || p.contains("invoke-webrequest")
}

fn is_expected_download_parent(parent: &str) -> bool {
    let p = parent.to_lowercase();
    p.contains("apt")
        || p.contains("yum")
        || p.contains("dnf")
        || p.contains("pacman")
        || p.contains("pip")
        || p.contains("npm")
        || p.contains("cargo")
        || p.contains("update")
        || p.contains("upgrade")
        || p.is_empty()
}

// ── File events → FIM alerts ──

pub async fn check_file_events(
    store: &dyn Database,
    hostname: &str,
    events: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;

    for event in events {
        let target_path = event["target_path"]
            .as_str()
            .or_else(|| event["path"].as_str())
            .unwrap_or("");
        let action = event["action"].as_str().unwrap_or("MODIFIED");

        if target_path.is_empty() {
            continue;
        }

        if is_critical_file(target_path) {
            let title = format!("FIM: {} {} sur {}", target_path, action, hostname);
            let severity = if is_auth_file(target_path) {
                "critical"
            } else {
                "high"
            };
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert("osquery-fim", severity, &title, hostname, None, None),
            )
            .await;
            alerts += 1;
        }
    }

    alerts
}

fn is_critical_file(path: &str) -> bool {
    let critical_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/root/.ssh/authorized_keys",
        "/root/.bashrc",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
    ];
    critical_paths.iter().any(|p| path.eq_ignore_ascii_case(p))
        || path.contains("/.ssh/authorized_keys")
        || path.contains("/cron.d/")
        || path.contains("/sudoers.d/")
}

fn is_auth_file(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("shadow")
        || p.contains("passwd")
        || p.contains("sudoers")
        || p.contains("authorized_keys")
        || p.contains("\\sam")
}

// ── Listening ports → new port = potential reverse shell ──

pub async fn check_listening_ports(
    store: &dyn Database,
    hostname: &str,
    ports: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;
    let suspicious_ports: &[u16] = &[4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345];

    for entry in ports {
        let port = entry["port"]
            .as_u64()
            .or_else(|| entry["port"].as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(0) as u16;
        let process = entry["name"]
            .as_str()
            .or_else(|| entry["process_name"].as_str())
            .unwrap_or("");
        let address = entry["address"].as_str().unwrap_or("0.0.0.0");

        if port == 0 {
            continue;
        }

        // Flag high ports bound to 0.0.0.0 with suspicious port numbers
        if suspicious_ports.contains(&port) && (address == "0.0.0.0" || address == "::") {
            let title = format!(
                "Port suspect en écoute: {}:{} ({}) sur {}",
                address, port, process, hostname
            );
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-suspicious-port",
                    "high",
                    &title,
                    hostname,
                    None,
                    None,
                ),
            )
            .await;
            alerts += 1;
        }
    }

    // Store all ports as log for baseline tracking (ML)
    if !ports.is_empty() {
        crate::connectors::log_db_write(
            "osquery:insert_log",
            store.insert_log(
                "osquery.ports",
                hostname,
                &serde_json::json!({"ports": ports}),
                &chrono::Utc::now().to_rfc3339(),
            ),
        )
        .await;
    }

    alerts
}

// ── Logged in users → anomaly detection ──

pub async fn check_logged_in_users(
    store: &dyn Database,
    hostname: &str,
    users: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;
    let hour = chrono::Utc::now().hour();

    for entry in users {
        let user = entry["user"]
            .as_str()
            .or_else(|| entry["username"].as_str())
            .unwrap_or("");
        let tty = entry["tty"].as_str().unwrap_or("");
        let host = entry["host"].as_str().unwrap_or("");
        let login_type = entry["type"].as_str().unwrap_or("");

        if user.is_empty() {
            continue;
        }

        // RDP/remote login outside business hours (before 7h or after 20h)
        let is_remote = !host.is_empty()
            && host != "localhost"
            && host != ":0"
            && !tty.contains("tty")
            && (login_type.contains("remote") || tty.contains("rdp") || !host.starts_with(":"));

        if is_remote && (hour < 7 || hour > 20) {
            let title = format!(
                "Connexion distante hors horaires: {} depuis {} sur {} ({}h UTC)",
                user, host, hostname, hour
            );
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-offhours-login",
                    "high",
                    &title,
                    hostname,
                    Some(host),
                    Some(user),
                ),
            )
            .await;
            alerts += 1;
        }
    }

    // Store for ML baseline (login patterns)
    if !users.is_empty() {
        crate::connectors::log_db_write(
            "osquery:insert_log",
            store.insert_log(
                "osquery.logins",
                hostname,
                &serde_json::json!({"users": users, "hour": hour}),
                &chrono::Utc::now().to_rfc3339(),
            ),
        )
        .await;
    }

    alerts
}

use chrono::Timelike;

// ── Scheduled tasks / crontab → persistence detection ──

pub async fn check_scheduled_tasks(
    store: &dyn Database,
    hostname: &str,
    tasks: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;

    for task in tasks {
        let name = task["name"].as_str().unwrap_or("");
        let path = task["path"]
            .as_str()
            .or_else(|| task["command"].as_str())
            .unwrap_or("");
        let enabled = task["enabled"].as_bool().unwrap_or(true);

        if !enabled || path.is_empty() {
            continue;
        }

        if is_suspicious_path(path) {
            let title = format!(
                "Tâche planifiée suspecte: {} → {} sur {}",
                name, path, hostname
            );
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-suspicious-task",
                    "critical",
                    &title,
                    hostname,
                    None,
                    None,
                ),
            )
            .await;
            alerts += 1;
        }
    }

    alerts
}

// ── Windows patches → missing updates ──

pub async fn ingest_patches(store: &dyn Database, hostname: &str, patches: &[serde_json::Value]) {
    if patches.is_empty() {
        return;
    }
    crate::connectors::log_db_write(
        "osquery:insert_log",
        store.insert_log(
            "osquery.patches",
            hostname,
            &serde_json::json!({"patches": patches, "count": patches.len()}),
            &chrono::Utc::now().to_rfc3339(),
        ),
    )
    .await;
}

// ── Windows security products → AV disabled detection ──

pub async fn check_security_products(
    store: &dyn Database,
    hostname: &str,
    products: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;

    let has_any_av = !products.is_empty();
    let all_disabled = products.iter().all(|p| {
        let state = p["state"]
            .as_str()
            .or_else(|| p["state_value"].as_str())
            .unwrap_or("");
        state.contains("OFF")
            || state.contains("disabled")
            || state.contains("outdated")
            || p["state"].as_u64().map(|v| v != 397568).unwrap_or(false) // 397568 = ON+UPDATED on Windows
    });

    if has_any_av && all_disabled {
        let names: Vec<&str> = products.iter().filter_map(|p| p["name"].as_str()).collect();
        let title = format!("Antivirus désactivé sur {}: {}", hostname, names.join(", "));
        crate::connectors::log_db_write(
            "osquery:insert_sigma_alert",
            store.insert_sigma_alert(
                "osquery-av-disabled",
                "critical",
                &title,
                hostname,
                None,
                None,
            ),
        )
        .await;
        alerts += 1;
    }

    if !has_any_av {
        let title = format!("Aucun antivirus détecté sur {}", hostname);
        crate::connectors::log_db_write(
            "osquery:insert_sigma_alert",
            store.insert_sigma_alert("osquery-no-av", "high", &title, hostname, None, None),
        )
        .await;
        alerts += 1;
    }

    alerts
}

// ── Docker containers → inventory ──

pub async fn ingest_docker_containers(
    store: &dyn Database,
    hostname: &str,
    containers: &[serde_json::Value],
) {
    if containers.is_empty() {
        return;
    }
    crate::connectors::log_db_write(
        "osquery:insert_log",
        store.insert_log(
            "osquery.docker",
            hostname,
            &serde_json::json!({"containers": containers, "count": containers.len()}),
            &chrono::Utc::now().to_rfc3339(),
        ),
    )
    .await;
}

// ���─ Interface details → enrich asset MAC/IP ──

pub async fn ingest_interfaces(
    store: &dyn Database,
    hostname: &str,
    interfaces: &[serde_json::Value],
) {
    for iface in interfaces {
        let mac = iface["mac"].as_str().unwrap_or("");
        let ip = iface["address"]
            .as_str()
            .or_else(|| iface["ip"].as_str())
            .unwrap_or("");

        if mac.is_empty() || mac == "00:00:00:00:00:00" {
            continue;
        }
        if ip.is_empty() || ip.starts_with("127.") || ip.starts_with("169.254.") {
            continue;
        }

        // Feed into asset resolution pipeline
        let discovered = crate::graph::asset_resolution::DiscoveredAsset {
            mac: Some(mac.to_string()),
            hostname: Some(hostname.to_string()),
            fqdn: None,
            ip: Some(ip.to_string()),
            os: None,
            ports: None,
            services: serde_json::json!([]),
            ou: None,
            vlan: None,
            vm_id: None,
            criticality: None,
            source: "osquery".into(),
        };
        let _ = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
    }
}

// ── Startup items → persistence detection ──

pub async fn check_startup_items(
    store: &dyn Database,
    hostname: &str,
    items: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;

    for item in items {
        let name = item["name"].as_str().unwrap_or("");
        let path = item["path"].as_str().unwrap_or("");
        let source = item["source"].as_str().unwrap_or("");

        if path.is_empty() {
            continue;
        }

        if is_suspicious_path(path) {
            let title = format!(
                "Startup suspect: {} → {} ({}) sur {}",
                name, path, source, hostname
            );
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-suspicious-startup",
                    "critical",
                    &title,
                    hostname,
                    None,
                    None,
                ),
            )
            .await;
            alerts += 1;
        }
    }

    alerts
}

// ── Authorized keys → SSH backdoor detection ──

pub async fn check_authorized_keys(
    store: &dyn Database,
    hostname: &str,
    keys: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;

    // Store for delta detection (new key added since last check)
    if !keys.is_empty() {
        crate::connectors::log_db_write(
            "osquery:insert_log",
            store.insert_log(
                "osquery.ssh_keys",
                hostname,
                &serde_json::json!({"keys_count": keys.len(), "keys": keys}),
                &chrono::Utc::now().to_rfc3339(),
            ),
        )
        .await;
    }

    for key in keys {
        let key_file = key["key_file"]
            .as_str()
            .or_else(|| key["path"].as_str())
            .unwrap_or("");
        // Alert on root authorized_keys (always suspicious if not expected)
        if key_file.contains("/root/") {
            let comment = key["comment"].as_str().unwrap_or("unknown");
            let title = format!("Clé SSH root détectée sur {}: {}", hostname, comment);
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-root-ssh-key",
                    "medium",
                    &title,
                    hostname,
                    None,
                    None,
                ),
            )
            .await;
            alerts += 1;
        }
    }

    alerts
}

// ── Browser extensions → malicious addon detection ──

pub async fn check_browser_extensions(
    store: &dyn Database,
    hostname: &str,
    extensions: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;

    for ext in extensions {
        let name = ext["name"].as_str().unwrap_or("");
        let identifier = ext["identifier"]
            .as_str()
            .or_else(|| ext["id"].as_str())
            .unwrap_or("");
        let from_webstore = ext["from_webstore"].as_str().unwrap_or("1");

        // Sideloaded extension (not from official store) = suspicious
        if from_webstore == "0" || from_webstore == "false" {
            let title = format!(
                "Extension navigateur sideloaded: {} ({}) sur {}",
                name, identifier, hostname
            );
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-sideloaded-ext",
                    "medium",
                    &title,
                    hostname,
                    None,
                    None,
                ),
            )
            .await;
            alerts += 1;
        }
    }

    alerts
}

// ── Users & groups → new admin detection ──

pub async fn check_users_groups(
    store: &dyn Database,
    hostname: &str,
    users: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;

    for user in users {
        let username = user["username"].as_str().unwrap_or("");
        let uid = user["uid"]
            .as_str()
            .or_else(|| user["uid"].as_u64().map(|_| ""))
            .unwrap_or("");
        let gid = user["gid"]
            .as_str()
            .or_else(|| user["gid"].as_u64().map(|_| ""))
            .unwrap_or("");
        let shell = user["shell"].as_str().unwrap_or("");
        let is_admin = user["is_admin"].as_bool().unwrap_or(false)
            || uid == "0"
            || gid == "0"
            || user["groupname"]
                .as_str()
                .map(|g| {
                    g.contains("admin")
                        || g.contains("sudo")
                        || g.contains("wheel")
                        || g.contains("Administrators")
                })
                .unwrap_or(false);

        if username.is_empty() {
            continue;
        }

        // User with UID 0 that isn't root = suspicious
        if uid == "0" && username != "root" {
            let title = format!("User non-root avec UID 0: {} sur {}", username, hostname);
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-uid0-nonroot",
                    "critical",
                    &title,
                    hostname,
                    None,
                    Some(username),
                ),
            )
            .await;
            alerts += 1;
        }

        // User with login shell in a suspicious path
        if !shell.is_empty() && is_suspicious_path(shell) {
            let title = format!(
                "User avec shell suspect: {} ({}) sur {}",
                username, shell, hostname
            );
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-suspicious-shell",
                    "high",
                    &title,
                    hostname,
                    None,
                    Some(username),
                ),
            )
            .await;
            alerts += 1;
        }
    }

    // Store full user list for delta detection
    if !users.is_empty() {
        crate::connectors::log_db_write(
            "osquery:insert_log",
            store.insert_log(
                "osquery.users",
                hostname,
                &serde_json::json!({"users": users}),
                &chrono::Utc::now().to_rfc3339(),
            ),
        )
        .await;
    }

    alerts
}

// ── Shared folders → exposed resources ──

pub async fn check_shared_folders(
    store: &dyn Database,
    hostname: &str,
    shares: &[serde_json::Value],
) {
    if shares.is_empty() {
        return;
    }
    // Store for inventory (not alerting by default — shares are normal in a PME)
    crate::connectors::log_db_write(
        "osquery:insert_log",
        store.insert_log(
            "osquery.shares",
            hostname,
            &serde_json::json!({"shares": shares, "count": shares.len()}),
            &chrono::Utc::now().to_rfc3339(),
        ),
    )
    .await;
}

// ── Webhook endpoint: process bulk osquery results ──

pub async fn process_osquery_webhook(
    store: &dyn Database,
    hostname: &str,
    body: &serde_json::Value,
) -> OsquerySyncResult {
    let mut result = OsquerySyncResult {
        logs_processed: 0,
        assets_enriched: 0,
        software_items: 0,
        connections_checked: 0,
        alerts_created: 0,
        errors: vec![],
    };

    // Verify agent identity (couche 2 — HMAC token is couche 1, checked by webhook_ingest)
    let agent_id = body["agent_id"].as_str().unwrap_or("");
    if !verify_or_register_agent(store, agent_id, hostname).await {
        result
            .errors
            .push("Agent identity verification failed".into());
        return result;
    }

    // Observe-and-enrol the asset on first sync. Without this hook a Windows
    // endpoint that runs the osquery agent never lands in the inventory: the
    // syslog path enrols Linux hosts as a side effect of fluent-bit forwarding
    // (see sigma_engine::enrol_observed_hostnames), but Windows agents push
    // straight through the osquery webhook with no syslog companion and so
    // skip every enrolment hook downstream. Match the syslog enrol shape so
    // the operator UI presents both OS families the same way; the OS hint
    // helps the dashboard pick the right icon and inventory filter.
    if let Ok(None) = store.find_asset_by_hostname(hostname).await {
        let os_hint = body["os"]
            .as_str()
            .or_else(|| body["agent_os"].as_str())
            .or_else(|| body["platform"].as_str())
            .map(|s| s.to_string());
        // Enrol through the single resolver (resolve_asset) so the host gets the
        // canonical id shared with the os_version enrichment below and every
        // other source — instead of a private `osquery-observed-*` id that would
        // duplicate. The osquery-agent subtype + tags come from
        // classification_for_source. Covers Windows agents with no syslog companion.
        let discovered = crate::graph::asset_resolution::DiscoveredAsset {
            mac: None,
            hostname: Some(hostname.to_string()),
            fqdn: None,
            ip: None,
            os: os_hint,
            ports: None,
            services: serde_json::json!([]),
            ou: None,
            vlan: None,
            vm_id: None,
            criticality: None,
            source: "osquery".into(),
        };
        let _ = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
        tracing::info!(
            target: "asset_enrolment",
            "OSQUERY: enrolled new asset for {} (source=osquery)",
            hostname
        );
    }

    // Update last_seen for this agent
    if !agent_id.is_empty() {
        let key = format!("agent_{}", agent_id);
        crate::connectors::log_db_write(
            "osquery:set_setting",
            store.set_setting(
                "_osquery_agents",
                &key,
                &serde_json::json!({
                    "hostname": hostname,
                    "last_seen": chrono::Utc::now().to_rfc3339(),
                }),
            ),
        )
        .await;
    }

    // Process each query type from the batch
    if let Some(software) = body["software"].as_array() {
        let (count, _) = ingest_software_inventory(store, hostname, software).await;
        result.software_items = count;
        if count > 0 {
            result.assets_enriched += 1;
            // Auto-CVE correlation: cross-reference software with NVD/KEV
            if let Ok(Some(asset)) = store.find_asset_by_hostname(hostname).await {
                let vuln_result = crate::enrichment::software_vuln::scan_asset_software(
                    store,
                    &asset.id,
                    &asset.name,
                    asset.os.as_deref().unwrap_or(""),
                    software,
                )
                .await;
                result.alerts_created += vuln_result.findings_created;
            }
        }
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
        // Store process events in logs table for Sigma engine matching
        // This enables PowerShell obfuscation rules and other process-based detections
        let now = chrono::Utc::now().to_rfc3339();
        for event in proc_events {
            crate::connectors::log_db_write(
                "osquery:insert_log",
                store.insert_log("osquery.process", hostname, event, &now),
            )
            .await;
            result.logs_processed += 1;
        }
    }

    if let Some(file_events) = body["file_events"].as_array() {
        result.alerts_created += check_file_events(store, hostname, file_events).await;
    }

    // ── Priorité 1 additions ──
    if let Some(ports) = body["listening_ports"].as_array() {
        result.alerts_created += check_listening_ports(store, hostname, ports).await;
    }
    if let Some(users) = body["logged_in_users"].as_array() {
        result.alerts_created += check_logged_in_users(store, hostname, users).await;
    }
    if let Some(tasks) = body["scheduled_tasks"]
        .as_array()
        .or_else(|| body["crontab"].as_array())
    {
        result.alerts_created += check_scheduled_tasks(store, hostname, tasks).await;
    }

    // ── Priorité 2 — inventaire ──
    if let Some(patches) = body["patches"].as_array() {
        ingest_patches(store, hostname, patches).await;
    }
    if let Some(products) = body["windows_security_products"].as_array() {
        result.alerts_created += check_security_products(store, hostname, products).await;
    }
    if let Some(containers) = body["docker_containers"].as_array() {
        ingest_docker_containers(store, hostname, containers).await;
    }
    if let Some(interfaces) = body["interface_details"].as_array() {
        ingest_interfaces(store, hostname, interfaces).await;
        result.assets_enriched += 1;
    }

    // ── Priorité 3 — persistance & backdoors ──
    if let Some(items) = body["startup_items"].as_array() {
        result.alerts_created += check_startup_items(store, hostname, items).await;
    }
    if let Some(keys) = body["authorized_keys"].as_array() {
        result.alerts_created += check_authorized_keys(store, hostname, keys).await;
    }
    if let Some(exts) = body["chrome_extensions"]
        .as_array()
        .or_else(|| body["firefox_addons"].as_array())
        .or_else(|| body["browser_extensions"].as_array())
    {
        result.alerts_created += check_browser_extensions(store, hostname, exts).await;
    }
    if let Some(users) = body["users"].as_array() {
        result.alerts_created += check_users_groups(store, hostname, users).await;
    }
    if let Some(shares) = body["shared_folders"].as_array() {
        check_shared_folders(store, hostname, shares).await;
    }

    // ── OS info enrichment via asset resolution ──
    if let Some(os_info) = body.get("os_version") {
        let os_name = os_info["name"].as_str().unwrap_or("");
        let os_version = os_info["version"].as_str().unwrap_or("");
        if !os_name.is_empty() {
            let discovered = crate::graph::asset_resolution::DiscoveredAsset {
                mac: None,
                hostname: Some(hostname.to_string()),
                fqdn: None,
                ip: None,
                os: Some(format!("{} {}", os_name, os_version).trim().to_string()),
                ports: None,
                services: serde_json::json!([]),
                ou: None,
                vlan: None,
                vm_id: None,
                criticality: None,
                source: "osquery".into(),
            };
            let _ = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
            result.assets_enriched += 1;
        }
    }

    result.logs_processed = 1;

    if let Some(events) = body["windows_security_events"].as_array() {
        let (ingested, alerts) = check_windows_security_events(store, hostname, events).await;
        result.logs_processed += ingested;
        result.alerts_created += alerts;
    }

    if let Some(events) = body["powershell_events"].as_array() {
        let (ingested, alerts) = check_powershell_events(store, hostname, events).await;
        result.logs_processed += ingested;
        result.alerts_created += alerts;
    }

    if let Some(events) = body["sysmon_events"].as_array() {
        let (ingested, alerts) = check_sysmon_events(store, hostname, events).await;
        result.logs_processed += ingested;
        result.alerts_created += alerts;
    }

    if result.alerts_created > 0 || result.software_items > 0 {
        tracing::info!(
            "OSQUERY: {} — {} software, {} connections, {} alerts",
            hostname,
            result.software_items,
            result.connections_checked,
            result.alerts_created
        );
    }

    result
}

// ── Windows Security event log → logs + sigma alerts ─────────────────────────
//
// osquery's `windows_eventlog` table returns rows with `data` as a JSON STRING
// that wraps the actual fields under an `EventData` key, e.g.:
//   "{\"EventData\":{\"TargetUserName\":\"alice\", ...}}"
// We parse defensively and unwrap `EventData` so callers can read field names
// directly (TargetUserName / IpAddress / etc.) without an extra hop.
fn parse_event_data(raw: &serde_json::Value) -> serde_json::Value {
    let parsed = match raw {
        serde_json::Value::String(s) => serde_json::from_str(s).unwrap_or(serde_json::json!({})),
        serde_json::Value::Object(_) => raw.clone(),
        _ => serde_json::json!({}),
    };
    parsed.get("EventData").cloned().unwrap_or(parsed)
}

fn extract_event_field<'a>(data: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    for k in keys {
        if let Some(v) = data.get(k).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn is_privileged_group_name(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("admin")
        || n.contains("domain admins")
        || n.contains("enterprise admins")
        || n.contains("backup operators")
        || n.contains("schema admins")
        || n.contains("account operators")
        || n.contains("remote desktop users")
        || n.contains("administrateurs")
        || n.contains("administrators")
}

/// — last-burst dedup.
///
/// The agent ships events from the last 6 min every 5 min, so the same
/// 4625 burst is in 2 consecutive batches. Without dedup we emit two
/// identical `osquery-win-failed-logon-burst` sigma alerts back to back,
/// the IE bundles all of them into one dossier with `alert_count` inflated,
/// and the dashboard shows duplicate cards.
///
/// We keep an in-memory map keyed by `(hostname, rule_id, target_user)`,
/// storing the latest event datetime that triggered an alert. Subsequent
/// batches must beat that timestamp by > 60s to re-fire. The map is process-
/// local so a restart starts fresh, which is fine: at worst we emit once per
/// restart per active burst, which is the desired behavior.
static LAST_BURST: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<(String, String, String), String>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn should_emit_burst(
    hostname: &str,
    rule_id: &str,
    target: &str,
    max_event_datetime: &str,
) -> bool {
    let key = (
        hostname.to_string(),
        rule_id.to_string(),
        target.to_lowercase(),
    );
    let mut guard = match LAST_BURST.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(), // poisoned mutex: take it anyway, dedup is best-effort
    };
    let last = guard.get(&key).cloned();
    // 60-second guard: a new burst must have at least one event after the last
    // recorded one. RFC3339 strings sort lexicographically by time, so we can
    // string-compare safely when both come from osquery.
    let should = match last {
        Some(ref prev) => max_event_datetime.as_bytes() > prev.as_bytes(),
        None => true,
    };
    if should {
        guard.insert(key, max_event_datetime.to_string());
    }
    should
}

/// Machine/service/system accounts that produce 4624 noise rather than a real
/// human-on-host identity signal. Lower-cased comparison.
fn is_noise_logon_account(user: &str) -> bool {
    let u = user.trim().to_lowercase();
    if u.is_empty() || u == "-" {
        return true;
    }
    if u.ends_with('$') {
        return true; // computer account (DOMAIN\HOST$)
    }
    matches!(
        u.as_str(),
        "system" | "local service" | "network service" | "anonymous logon" | "iusr"
    ) || u.starts_with("dwm-")
        || u.starts_with("umfd-")
}

/// Windows logon types that represent a human/admin actually using the host
/// (interactive, unlock, RDP, cached) — as opposed to the network/service/batch
/// firehose (types 3/4/5/8/9) that would flood the identity graph.
fn is_interactive_logon_type(logon_type: &str) -> bool {
    matches!(logon_type.trim(), "2" | "7" | "10" | "11")
}

/// Whether a 4624 success logon is worth recording as a `User-[:LOGGED_IN]->Asset`
/// identity edge (drives lateral-movement attack-path discovery).
fn should_record_logon(user: &str, logon_type: &str) -> bool {
    is_interactive_logon_type(logon_type) && !is_noise_logon_account(user)
}

pub async fn check_windows_security_events(
    store: &dyn Database,
    hostname: &str,
    events: &[serde_json::Value],
) -> (usize, usize) {
    let mut ingested = 0usize;
    let mut alerts = 0usize;

    // In-batch brute force tracking: count 4625 by target user, also keep
    // the latest event datetime so we can dedup against the previous batch.
    let mut failed_logon_counts: std::collections::HashMap<String, (u32, Option<String>, String)> =
        std::collections::HashMap::new();

    // Canonical asset id of this host, resolved once per batch, used to attach
    // LOGGED_IN identity edges to the SAME asset node the graph sync upserts and
    // the Intelligence Engine correlates under. Falls back to the deterministic
    // id (generate_asset_id semantics) when the asset is not yet enrolled.
    let host_asset_id = match store.find_asset_by_hostname(hostname).await {
        Ok(Some(a)) => a.id,
        _ => crate::graph::asset_resolution::sanitize_id(&hostname.to_lowercase()),
    };
    // De-dupe identity edges within the batch: one per distinct interactive user.
    let mut logon_recorded: std::collections::HashSet<String> = std::collections::HashSet::new();

    for event in events {
        let eventid = event["eventid"]
            .as_str()
            .or_else(|| event["eventid"].as_i64().map(|_| ""))
            .unwrap_or("");
        let eventid = if eventid.is_empty() {
            event["eventid"]
                .as_i64()
                .map(|i| i.to_string())
                .unwrap_or_default()
        } else {
            eventid.to_string()
        };

        let datetime = event["datetime"].as_str().unwrap_or("");
        let time = if datetime.is_empty() {
            chrono::Utc::now().to_rfc3339()
        } else {
            datetime.to_string()
        };

        let data = parse_event_data(&event["data"]);

        // Persist every event in `logs` so Sigma engine can match.
        let log_payload = serde_json::json!({
            "eventid": eventid,
            "channel": "Security",
            "provider": event["provider_name"].as_str().unwrap_or(""),
            "data": data,
        });
        if let Some(_id) = crate::connectors::log_db_write(
            "osquery:insert_log",
            store.insert_log("osquery.windows_security", hostname, &log_payload, &time),
        )
        .await
        {
            ingested += 1;
        }

        match eventid.as_str() {
            // Failed logon — accumulate for brute force, no per-event alert
            "4625" => {
                let target = extract_event_field(&data, &["TargetUserName", "SubjectUserName"])
                    .unwrap_or("unknown")
                    .to_lowercase();
                let src_ip = extract_event_field(&data, &["IpAddress", "WorkstationName"])
                    .map(|s| s.to_string());
                let evt_dt = datetime.to_string();
                let entry = failed_logon_counts.entry(target).or_insert((
                    0,
                    src_ip.clone(),
                    evt_dt.clone(),
                ));
                entry.0 += 1;
                if entry.1.is_none() {
                    entry.1 = src_ip;
                }
                // Track the latest event datetime in the burst so the dedup
                // helper (Fix 1.5) can compare against the previously emitted
                // burst.
                if evt_dt.as_bytes() > entry.2.as_bytes() {
                    entry.2 = evt_dt;
                }
            }
            // User account created
            "4720" => {
                let target = extract_event_field(&data, &["TargetUserName"]).unwrap_or("unknown");
                let actor = extract_event_field(&data, &["SubjectUserName"]).unwrap_or("unknown");
                let title = format!(
                    "Compte utilisateur créé: {} par {} sur {}",
                    target, actor, hostname
                );
                crate::connectors::log_db_write(
                    "osquery:insert_sigma_alert",
                    store.insert_sigma_alert(
                        "osquery-win-user-created",
                        "medium",
                        &title,
                        hostname,
                        None,
                        Some(target),
                    ),
                )
                .await;
                alerts += 1;
            }
            // User account deleted
            "4726" => {
                let target = extract_event_field(&data, &["TargetUserName"]).unwrap_or("unknown");
                let actor = extract_event_field(&data, &["SubjectUserName"]).unwrap_or("unknown");
                let title = format!(
                    "Compte utilisateur supprimé: {} par {} sur {}",
                    target, actor, hostname
                );
                crate::connectors::log_db_write(
                    "osquery:insert_sigma_alert",
                    store.insert_sigma_alert(
                        "osquery-win-user-deleted",
                        "medium",
                        &title,
                        hostname,
                        None,
                        Some(target),
                    ),
                )
                .await;
                alerts += 1;
            }
            // Member added to a security group (global=4732, universal=4756)
            "4732" | "4756" => {
                let group = extract_event_field(&data, &["TargetUserName"]).unwrap_or("unknown");
                let member_sid =
                    extract_event_field(&data, &["MemberSid", "MemberName"]).unwrap_or("unknown");
                let actor = extract_event_field(&data, &["SubjectUserName"]).unwrap_or("unknown");
                let priv_group = is_privileged_group_name(group);
                let level = if priv_group { "high" } else { "medium" };
                let title = if priv_group {
                    format!(
                        "Ajout au groupe privilégié {}: {} par {} sur {}",
                        group, member_sid, actor, hostname
                    )
                } else {
                    format!(
                        "Ajout au groupe {}: {} par {} sur {}",
                        group, member_sid, actor, hostname
                    )
                };
                crate::connectors::log_db_write(
                    "osquery:insert_sigma_alert",
                    store.insert_sigma_alert(
                        "osquery-win-group-membership-add",
                        level,
                        &title,
                        hostname,
                        None,
                        Some(actor),
                    ),
                )
                .await;
                alerts += 1;
            }
            // Audit log cleared — classic anti-forensic IOC
            "1102" => {
                let actor = extract_event_field(&data, &["SubjectUserName"]).unwrap_or("unknown");
                let title = format!(
                    "Journal d'audit Security effacé par {} sur {}",
                    actor, hostname
                );
                crate::connectors::log_db_write(
                    "osquery:insert_sigma_alert",
                    store.insert_sigma_alert(
                        "osquery-win-audit-log-cleared",
                        "critical",
                        &title,
                        hostname,
                        None,
                        Some(actor),
                    ),
                )
                .await;
                alerts += 1;
            }
            // Successful interactive logon → User-[:LOGGED_IN]->Asset identity
            // edge, the substrate for lateral-movement attack-path discovery.
            // Only interactive/RDP logons by real accounts (filters the
            // network/service firehose and machine accounts), de-duped per batch.
            "4624" => {
                let user = extract_event_field(&data, &["TargetUserName", "SubjectUserName"])
                    .unwrap_or("");
                let logon_type = extract_event_field(&data, &["LogonType"]).unwrap_or("");
                if should_record_logon(user, logon_type)
                    && logon_recorded.insert(user.to_lowercase())
                {
                    let src_ip =
                        extract_event_field(&data, &["IpAddress", "WorkstationName"]).unwrap_or("");
                    crate::graph::identity_graph::record_host_login(
                        store,
                        user,
                        &host_asset_id,
                        src_ip,
                        "windows",
                    )
                    .await;
                }
            }
            // Explicit-creds logon (4648) / special privileges (4672) — context only.
            "4648" | "4672" => {}
            _ => {}
        }
    }

    // Brute force aggregation: 3+ failed logons for the same target in this batch.
    // — skip emission if we already
    // emitted a burst whose latest event is at-or-after the current one (= same
    // window seen twice across consecutive sync cycles).
    for (target, (count, src_ip, max_dt)) in &failed_logon_counts {
        if *count >= 3 {
            if !should_emit_burst(hostname, "osquery-win-failed-logon-burst", target, max_dt) {
                // Already emitted for this burst — leave the dashboard alone.
                continue;
            }
            let level = if *count >= 10 { "high" } else { "medium" };
            let title = format!(
                "Brute force candidat: {} tentatives échouées sur {} (cible {})",
                count, hostname, target
            );
            crate::connectors::log_db_write(
                "osquery:insert_sigma_alert",
                store.insert_sigma_alert(
                    "osquery-win-failed-logon-burst",
                    level,
                    &title,
                    hostname,
                    src_ip.as_deref(),
                    Some(target),
                ),
            )
            .await;
            alerts += 1;
        }
    }

    (ingested, alerts)
}

// ── PowerShell events → logs + sigma alerts ──────────────────────────────────
//
// 4104 = Script Block Logging (requires GPO/registry to be enabled; off by
// default on stock Windows). When present, it's our best lens on what
// PowerShell actually executed, including obfuscated payloads after decoding.
// 4103 = Pipeline execution — kept as log only, too noisy to alert on directly.
fn is_suspicious_powershell(script: &str) -> Vec<&'static str> {
    let s = script.to_lowercase();
    let mut hits = vec![];
    if s.contains("iex(") || s.contains("iex ") || s.contains("invoke-expression") {
        hits.push("invoke-expression");
    }
    if s.contains("downloadstring")
        || s.contains("downloadfile")
        || s.contains("invoke-webrequest -uri")
    {
        hits.push("remote-download");
    }
    if s.contains("-encodedcommand") || s.contains(" -enc ") || s.contains(" -e ") {
        hits.push("encoded-command");
    }
    if s.contains("frombase64string") {
        hits.push("base64-decode");
    }
    if s.contains("lsass") || s.contains("mimikatz") || s.contains("sekurlsa") {
        hits.push("credential-theft");
    }
    if s.contains("amsi") && (s.contains("bypass") || s.contains("disable") || s.contains("patch"))
    {
        hits.push("amsi-bypass");
    }
    if s.contains("set-mppreference -disablerealtimemonitoring") {
        hits.push("defender-disable");
    }
    hits
}

pub async fn check_powershell_events(
    store: &dyn Database,
    hostname: &str,
    events: &[serde_json::Value],
) -> (usize, usize) {
    let mut ingested = 0usize;
    let mut alerts = 0usize;

    // PowerShell splits a large script across several 4104 events, and the split
    // boundary VARIES between runs (we saw part 1 at 12756 / 22434 / 22464 bytes
    // for three installs of the same script). Detecting on a single part is both
    // unstable for provenance (the hash differs per run) and unsound for detection
    // (a payload could be split across parts to dodge a per-part match). So we
    // ingest every event as-is, bucket the 4104 parts by ScriptBlockId, then
    // reassemble each block and detect on the WHOLE script.
    use std::collections::{BTreeMap, HashMap};
    // ScriptBlockId -> (MessageNumber -> part text, user)
    let mut blocks: HashMap<String, (BTreeMap<i64, String>, Option<String>)> = HashMap::new();

    for event in events {
        let eventid = event["eventid"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| event["eventid"].as_i64().map(|i| i.to_string()))
            .unwrap_or_default();
        let datetime = event["datetime"].as_str().unwrap_or("");
        let time = if datetime.is_empty() {
            chrono::Utc::now().to_rfc3339()
        } else {
            datetime.to_string()
        };
        let data = parse_event_data(&event["data"]);

        let log_payload = serde_json::json!({
            "eventid": eventid,
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "data": data,
        });
        if let Some(_id) = crate::connectors::log_db_write(
            "osquery:insert_log",
            store.insert_log("osquery.powershell", hostname, &log_payload, &time),
        )
        .await
        {
            ingested += 1;
        }

        if eventid == "4104" {
            let part = extract_event_field(&data, &["ScriptBlockText", "Path"])
                .unwrap_or("")
                .to_string();
            // Bucket by ScriptBlockId (groups the parts of one script). Fall back to
            // the part text itself when the id is missing, so an un-split block is
            // still handled as its own single-part block.
            let key = match extract_event_field(&data, &["ScriptBlockId"]) {
                Some(id) if !id.is_empty() => id.to_string(),
                _ => part.clone(),
            };
            let msg_num = data
                .get("MessageNumber")
                .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .unwrap_or(1);
            let user = extract_event_field(&data, &["UserId", "User"]).map(|s| s.to_string());
            let entry = blocks.entry(key).or_insert_with(|| (BTreeMap::new(), None));
            entry.0.insert(msg_num, part);
            if entry.1.is_none() {
                entry.1 = user;
            }
        }
    }

    // ── Pass 2: reassemble each block (MessageNumber order) and detect on the
    // whole script ──
    for (parts, user) in blocks.values() {
        let script: String = parts.values().map(String::as_str).collect();
        let hits = is_suspicious_powershell(&script);
        if hits.is_empty() {
            continue;
        }
        // Provenance exemption: never flag our own agent installer. The shared
        // registry matches the exact bytes of the REASSEMBLED installer (never
        // substrings), so a tampered script hashes differently and still alerts.
        if crate::agent::detection_provenance::is_self_generated(
            &script,
            crate::agent::detection_provenance::Channel::OsqueryPowershell,
        ) {
            continue;
        }
        // Dedup keyed on the reassembled script (stable across runs) so the same
        // script alerts once per 60-min window even as osquery re-feeds it.
        let fp = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            script.hash(&mut h);
            h.finish()
        };
        let dedup_key = format!("osquery-win-powershell-suspicious_{}_{:x}", hostname, fp);
        let recently_alerted =
            if let Ok(Some(prev)) = store.get_setting("_sigma_dedup", &dedup_key).await {
                prev["at"]
                    .as_str()
                    .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
                    .map(|ts| {
                        chrono::Utc::now().signed_duration_since(ts) < chrono::Duration::minutes(60)
                    })
                    .unwrap_or(false)
            } else {
                false
            };
        if recently_alerted {
            continue;
        }
        let snippet: String = script.chars().take(120).collect();
        let title = format!(
            "PowerShell suspect sur {} ({}): {}",
            hostname,
            hits.join(", "),
            snippet
        );
        crate::connectors::log_db_write(
            "osquery:insert_sigma_alert",
            store.insert_sigma_alert(
                "osquery-win-powershell-suspicious",
                "high",
                &title,
                hostname,
                None,
                user.as_deref(),
            ),
        )
        .await;
        let _ = store
            .set_setting(
                "_sigma_dedup",
                &dedup_key,
                &serde_json::json!({ "at": chrono::Utc::now().to_rfc3339() }),
            )
            .await;
        alerts += 1;
    }

    (ingested, alerts)
}

// ── Sysmon events → logs + sigma alerts ─────────────────────────────────────
//
// Sysmon (Microsoft Sysinternals) sits below the user-mode boundary and
// emits much richer telemetry than the built-in Security log: process
// create with hash + parent + cmdline (1), network connect (3), DLL load (7),
// CreateRemoteThread (8), ProcessAccess (10) — the gold for LSASS dumps —,
// FileCreate (11), RegistryEvent (13), DNS query (22).
//
// We persist every event in `logs` (tag `osquery.sysmon`) so the Sigma
// engine can match downstream rules, and emit direct sigma_alerts on the
// few patterns that are unambiguous IOCs from the event itself.
pub async fn check_sysmon_events(
    store: &dyn Database,
    hostname: &str,
    events: &[serde_json::Value],
) -> (usize, usize) {
    let mut ingested = 0usize;
    let mut alerts = 0usize;

    for event in events {
        let eventid = event["eventid"]
            .as_str()
            .map(|s| s.to_string())
            .or_else(|| event["eventid"].as_i64().map(|i| i.to_string()))
            .unwrap_or_default();
        let datetime = event["datetime"].as_str().unwrap_or("");
        let time = if datetime.is_empty() {
            chrono::Utc::now().to_rfc3339()
        } else {
            datetime.to_string()
        };
        let data = parse_event_data(&event["data"]);

        let log_payload = serde_json::json!({
            "eventid": eventid,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "data": data,
        });
        if let Some(_id) = crate::connectors::log_db_write(
            "osquery:insert_log",
            store.insert_log("osquery.sysmon", hostname, &log_payload, &time),
        )
        .await
        {
            ingested += 1;
        }

        match eventid.as_str() {
            // Process Create — alert on offensive tool signatures in cmdline
            "1" => {
                let image = extract_event_field(&data, &["Image"]).unwrap_or("");
                let cmdline = extract_event_field(&data, &["CommandLine"]).unwrap_or("");
                let parent = extract_event_field(&data, &["ParentImage"]).unwrap_or("");
                let user = extract_event_field(&data, &["User"]);
                let cmd_l = cmdline.to_lowercase();
                let image_l = image.to_lowercase();

                let mut tags = vec![];
                if cmd_l.contains("mimikatz")
                    || cmd_l.contains("sekurlsa")
                    || cmd_l.contains("invoke-mimikatz")
                {
                    tags.push("mimikatz");
                }
                if cmd_l.contains("bloodhound") || cmd_l.contains("sharphound") {
                    tags.push("ad-recon");
                }
                if image_l.contains("certutil.exe")
                    && (cmd_l.contains("-urlcache")
                        || cmd_l.contains("-decode")
                        || cmd_l.contains("-encode"))
                {
                    tags.push("certutil-living-off-the-land");
                }
                if image_l.contains("bitsadmin.exe") && cmd_l.contains("/transfer") {
                    tags.push("bitsadmin-download");
                }
                if image_l.contains("rundll32.exe") && cmd_l.contains("javascript:") {
                    tags.push("rundll32-js");
                }
                if image_l.contains("mshta.exe")
                    && (cmd_l.contains("http") || cmd_l.contains("javascript:"))
                {
                    tags.push("mshta-remote");
                }
                if image_l.contains("regsvr32.exe") && cmd_l.contains("scrobj.dll") {
                    tags.push("squiblydoo");
                }

                if !tags.is_empty() {
                    let title = format!(
                        "Outil offensif détecté sur {} ({}): {} (lancé par {})",
                        hostname,
                        tags.join(", "),
                        image.rsplit('\\').next().unwrap_or(image),
                        parent.rsplit('\\').next().unwrap_or(parent),
                    );
                    crate::connectors::log_db_write(
                        "osquery:insert_sigma_alert",
                        store.insert_sigma_alert(
                            "sysmon-offensive-tool",
                            "high",
                            &title,
                            hostname,
                            None,
                            user,
                        ),
                    )
                    .await;
                    alerts += 1;
                }
            }
            // ProcessAccess — credential theft pattern: any process opening lsass
            // with PROCESS_VM_READ (0x10) | PROCESS_QUERY_INFORMATION (0x400).
            // Sysmon already filters out common benign accessors via its config,
            // so anything that surfaces here is suspect.
            "10" => {
                let target = extract_event_field(&data, &["TargetImage"]).unwrap_or("");
                let source_image = extract_event_field(&data, &["SourceImage"]).unwrap_or("");
                let access = extract_event_field(&data, &["GrantedAccess"]).unwrap_or("");
                let user = extract_event_field(&data, &["User"]);

                if target.to_lowercase().contains("lsass.exe") {
                    let title = format!(
                        "Accès suspect à LSASS sur {} par {} (GrantedAccess={})",
                        hostname,
                        source_image.rsplit('\\').next().unwrap_or(source_image),
                        access,
                    );
                    crate::connectors::log_db_write(
                        "osquery:insert_sigma_alert",
                        store.insert_sigma_alert(
                            "sysmon-lsass-access",
                            "critical",
                            &title,
                            hostname,
                            None,
                            user,
                        ),
                    )
                    .await;
                    alerts += 1;
                }
            }
            // CreateRemoteThread (EID 8) — ingest as log only. Built-in
            // Windows components (Defender, MsMpEng, debuggers, AV
            // products) trigger this constantly with no malicious intent,
            // so alerting on every EID 8 floods the dashboard with false
            // positives. A proper Sigma rule with source-image + target-
            // image patterns can match downstream from the stored log.
            _ => {}
        }
    }

    (ingested, alerts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logon_filter_keeps_interactive_real_accounts() {
        assert!(should_record_logon("alice", "2")); // interactive
        assert!(should_record_logon("DOMAIN_admin", "10")); // RDP
        assert!(should_record_logon("bob", "7")); // unlock
        assert!(should_record_logon("carol", "11")); // cached interactive
    }

    #[test]
    fn logon_filter_drops_network_and_service_types() {
        // The network/service/batch firehose must not flood the identity graph.
        assert!(!should_record_logon("alice", "3")); // network (SMB/share)
        assert!(!should_record_logon("svc", "5")); // service
        assert!(!should_record_logon("alice", "4")); // batch
        assert!(!should_record_logon("alice", "8")); // network cleartext
        assert!(!should_record_logon("alice", "")); // unknown type
    }

    #[test]
    fn logon_filter_drops_machine_and_system_accounts() {
        assert!(!should_record_logon("WORKSTATION$", "2")); // computer account
        assert!(!should_record_logon("SYSTEM", "2"));
        assert!(!should_record_logon("Network Service", "10"));
        assert!(!should_record_logon("ANONYMOUS LOGON", "10"));
        assert!(!should_record_logon("DWM-1", "2"));
        assert!(!should_record_logon("UMFD-0", "2"));
        assert!(!should_record_logon("", "2"));
        assert!(!should_record_logon("-", "2"));
    }
}
