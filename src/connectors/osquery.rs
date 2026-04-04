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
    if agent_id.is_empty() { return true; } // Pas d'agent_id = mode webhook legacy

    let key = format!("agent_{}", agent_id);
    if let Ok(Some(registered)) = store.get_setting("_osquery_agents", &key).await {
        // Agent connu — vérifier que le hostname matche
        let registered_host = registered["hostname"].as_str().unwrap_or("");
        if registered_host != hostname && !registered_host.is_empty() {
            tracing::warn!("OSQUERY: Agent {} hostname mismatch: registered={}, received={}", agent_id, registered_host, hostname);
            return false;
        }
        true
    } else {
        // Nouvel agent — enregistrer
        let _ = store.set_setting("_osquery_agents", &key, &serde_json::json!({
            "hostname": hostname,
            "registered_at": chrono::Utc::now().to_rfc3339(),
            "last_seen": chrono::Utc::now().to_rfc3339(),
        })).await;
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

// ── Listening ports → new port = potential reverse shell ──

pub async fn check_listening_ports(
    store: &dyn Database,
    hostname: &str,
    ports: &[serde_json::Value],
) -> usize {
    let mut alerts = 0usize;
    let suspicious_ports: &[u16] = &[4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345];

    for entry in ports {
        let port = entry["port"].as_u64().or_else(|| entry["port"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0) as u16;
        let process = entry["name"].as_str().or_else(|| entry["process_name"].as_str()).unwrap_or("");
        let address = entry["address"].as_str().unwrap_or("0.0.0.0");

        if port == 0 { continue; }

        // Flag high ports bound to 0.0.0.0 with suspicious port numbers
        if suspicious_ports.contains(&port) && (address == "0.0.0.0" || address == "::") {
            let title = format!("Port suspect en écoute: {}:{} ({}) sur {}", address, port, process, hostname);
            let _ = store.insert_sigma_alert("osquery-suspicious-port", "high", &title, hostname, None, None).await;
            alerts += 1;
        }
    }

    // Store all ports as log for baseline tracking (ML)
    if !ports.is_empty() {
        let _ = store.insert_log("osquery.ports", hostname,
            &serde_json::json!({"ports": ports}),
            &chrono::Utc::now().to_rfc3339()).await;
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
        let user = entry["user"].as_str().or_else(|| entry["username"].as_str()).unwrap_or("");
        let tty = entry["tty"].as_str().unwrap_or("");
        let host = entry["host"].as_str().unwrap_or("");
        let login_type = entry["type"].as_str().unwrap_or("");

        if user.is_empty() { continue; }

        // RDP/remote login outside business hours (before 7h or after 20h)
        let is_remote = !host.is_empty() && host != "localhost" && host != ":0"
            && !tty.contains("tty") && (login_type.contains("remote") || tty.contains("rdp") || !host.starts_with(":"));

        if is_remote && (hour < 7 || hour > 20) {
            let title = format!("Connexion distante hors horaires: {} depuis {} sur {} ({}h UTC)", user, host, hostname, hour);
            let _ = store.insert_sigma_alert("osquery-offhours-login", "high", &title, hostname, Some(host), Some(user)).await;
            alerts += 1;
        }
    }

    // Store for ML baseline (login patterns)
    if !users.is_empty() {
        let _ = store.insert_log("osquery.logins", hostname,
            &serde_json::json!({"users": users, "hour": hour}),
            &chrono::Utc::now().to_rfc3339()).await;
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
        let path = task["path"].as_str().or_else(|| task["command"].as_str()).unwrap_or("");
        let enabled = task["enabled"].as_bool().unwrap_or(true);

        if !enabled || path.is_empty() { continue; }

        if is_suspicious_path(path) {
            let title = format!("Tâche planifiée suspecte: {} → {} sur {}", name, path, hostname);
            let _ = store.insert_sigma_alert("osquery-suspicious-task", "critical", &title, hostname, None, None).await;
            alerts += 1;
        }
    }

    alerts
}

// ── Windows patches → missing updates ──

pub async fn ingest_patches(
    store: &dyn Database,
    hostname: &str,
    patches: &[serde_json::Value],
) {
    if patches.is_empty() { return; }
    let _ = store.insert_log("osquery.patches", hostname,
        &serde_json::json!({"patches": patches, "count": patches.len()}),
        &chrono::Utc::now().to_rfc3339()).await;
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
        let state = p["state"].as_str().or_else(|| p["state_value"].as_str()).unwrap_or("");
        state.contains("OFF") || state.contains("disabled") || state.contains("outdated") ||
        p["state"].as_u64().map(|v| v != 397568).unwrap_or(false) // 397568 = ON+UPDATED on Windows
    });

    if has_any_av && all_disabled {
        let names: Vec<&str> = products.iter().filter_map(|p| p["name"].as_str()).collect();
        let title = format!("Antivirus désactivé sur {}: {}", hostname, names.join(", "));
        let _ = store.insert_sigma_alert("osquery-av-disabled", "critical", &title, hostname, None, None).await;
        alerts += 1;
    }

    if !has_any_av {
        let title = format!("Aucun antivirus détecté sur {}", hostname);
        let _ = store.insert_sigma_alert("osquery-no-av", "high", &title, hostname, None, None).await;
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
    if containers.is_empty() { return; }
    let _ = store.insert_log("osquery.docker", hostname,
        &serde_json::json!({"containers": containers, "count": containers.len()}),
        &chrono::Utc::now().to_rfc3339()).await;
}

// ���─ Interface details → enrich asset MAC/IP ──

pub async fn ingest_interfaces(
    store: &dyn Database,
    hostname: &str,
    interfaces: &[serde_json::Value],
) {
    for iface in interfaces {
        let mac = iface["mac"].as_str().unwrap_or("");
        let ip = iface["address"].as_str().or_else(|| iface["ip"].as_str()).unwrap_or("");

        if mac.is_empty() || mac == "00:00:00:00:00:00" { continue; }
        if ip.is_empty() || ip.starts_with("127.") || ip.starts_with("169.254.") { continue; }

        // Feed into asset resolution pipeline
        let discovered = crate::graph::asset_resolution::DiscoveredAsset {
            mac: Some(mac.to_string()),
            hostname: Some(hostname.to_string()),
            fqdn: None,
            ip: Some(ip.to_string()),
            os: None,
            ports: None,
            services: serde_json::json!([]),
            ou: None, vlan: None, vm_id: None,
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

        if path.is_empty() { continue; }

        if is_suspicious_path(path) {
            let title = format!("Startup suspect: {} → {} ({}) sur {}", name, path, source, hostname);
            let _ = store.insert_sigma_alert("osquery-suspicious-startup", "critical", &title, hostname, None, None).await;
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
        let _ = store.insert_log("osquery.ssh_keys", hostname,
            &serde_json::json!({"keys_count": keys.len(), "keys": keys}),
            &chrono::Utc::now().to_rfc3339()).await;
    }

    for key in keys {
        let key_file = key["key_file"].as_str().or_else(|| key["path"].as_str()).unwrap_or("");
        // Alert on root authorized_keys (always suspicious if not expected)
        if key_file.contains("/root/") {
            let comment = key["comment"].as_str().unwrap_or("unknown");
            let title = format!("Clé SSH root détectée sur {}: {}", hostname, comment);
            let _ = store.insert_sigma_alert("osquery-root-ssh-key", "medium", &title, hostname, None, None).await;
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
        let identifier = ext["identifier"].as_str().or_else(|| ext["id"].as_str()).unwrap_or("");
        let from_webstore = ext["from_webstore"].as_str().unwrap_or("1");

        // Sideloaded extension (not from official store) = suspicious
        if from_webstore == "0" || from_webstore == "false" {
            let title = format!("Extension navigateur sideloaded: {} ({}) sur {}", name, identifier, hostname);
            let _ = store.insert_sigma_alert("osquery-sideloaded-ext", "medium", &title, hostname, None, None).await;
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
        let uid = user["uid"].as_str().or_else(|| user["uid"].as_u64().map(|_| "")).unwrap_or("");
        let gid = user["gid"].as_str().or_else(|| user["gid"].as_u64().map(|_| "")).unwrap_or("");
        let shell = user["shell"].as_str().unwrap_or("");
        let is_admin = user["is_admin"].as_bool().unwrap_or(false) ||
            uid == "0" || gid == "0" ||
            user["groupname"].as_str().map(|g| g.contains("admin") || g.contains("sudo") || g.contains("wheel") || g.contains("Administrators")).unwrap_or(false);

        if username.is_empty() { continue; }

        // User with UID 0 that isn't root = suspicious
        if uid == "0" && username != "root" {
            let title = format!("User non-root avec UID 0: {} sur {}", username, hostname);
            let _ = store.insert_sigma_alert("osquery-uid0-nonroot", "critical", &title, hostname, None, Some(username)).await;
            alerts += 1;
        }

        // User with login shell in a suspicious path
        if !shell.is_empty() && is_suspicious_path(shell) {
            let title = format!("User avec shell suspect: {} ({}) sur {}", username, shell, hostname);
            let _ = store.insert_sigma_alert("osquery-suspicious-shell", "high", &title, hostname, None, Some(username)).await;
            alerts += 1;
        }
    }

    // Store full user list for delta detection
    if !users.is_empty() {
        let _ = store.insert_log("osquery.users", hostname,
            &serde_json::json!({"users": users}),
            &chrono::Utc::now().to_rfc3339()).await;
    }

    alerts
}

// ── Shared folders → exposed resources ──

pub async fn check_shared_folders(
    store: &dyn Database,
    hostname: &str,
    shares: &[serde_json::Value],
) {
    if shares.is_empty() { return; }
    // Store for inventory (not alerting by default — shares are normal in a PME)
    let _ = store.insert_log("osquery.shares", hostname,
        &serde_json::json!({"shares": shares, "count": shares.len()}),
        &chrono::Utc::now().to_rfc3339()).await;
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

    // Verify agent identity (couche 2 — HMAC token is couche 1, checked by webhook_ingest)
    let agent_id = body["agent_id"].as_str().unwrap_or("");
    if !verify_or_register_agent(store, agent_id, hostname).await {
        result.errors.push("Agent identity verification failed".into());
        return result;
    }

    // Update last_seen for this agent
    if !agent_id.is_empty() {
        let key = format!("agent_{}", agent_id);
        let _ = store.set_setting("_osquery_agents", &key, &serde_json::json!({
            "hostname": hostname,
            "last_seen": chrono::Utc::now().to_rfc3339(),
        })).await;
    }

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

    // ── Priorité 1 additions ──
    if let Some(ports) = body["listening_ports"].as_array() {
        result.alerts_created += check_listening_ports(store, hostname, ports).await;
    }
    if let Some(users) = body["logged_in_users"].as_array() {
        result.alerts_created += check_logged_in_users(store, hostname, users).await;
    }
    if let Some(tasks) = body["scheduled_tasks"].as_array().or_else(|| body["crontab"].as_array()) {
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
    if let Some(exts) = body["chrome_extensions"].as_array()
        .or_else(|| body["firefox_addons"].as_array())
        .or_else(|| body["browser_extensions"].as_array()) {
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
                fqdn: None, ip: None,
                os: Some(format!("{} {}", os_name, os_version).trim().to_string()),
                ports: None,
                services: serde_json::json!([]),
                ou: None, vlan: None, vm_id: None,
                criticality: None,
                source: "osquery".into(),
            };
            let _ = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
            result.assets_enriched += 1;
        }
    }

    result.logs_processed = 1;

    if result.alerts_created > 0 || result.software_items > 0 {
        tracing::info!(
            "OSQUERY: {} — {} software, {} connections, {} alerts",
            hostname, result.software_items,
            result.connections_checked, result.alerts_created
        );
    }

    result
}
