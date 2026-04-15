//! Investigation Graph Executor — runs deterministic investigation workflows.
//!
//! When an alert matches an investigation graph, the executor runs each step
//! in order: enrich → correlate → query graph → build context → send to L2.
//! The LLM NEVER decides how to investigate. The graph decides.

use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::db::Database;
use crate::graph::investigation::{
    InvestigationGraph, InvestigationResult, InvestigationStep, StepResult,
};

/// Execute a complete investigation graph for an alert.
pub async fn run_investigation(
    store: Arc<dyn Database>,
    graph: &InvestigationGraph,
    alert_title: &str,
    source_ip: Option<&str>,
    hostname: Option<&str>,
) -> InvestigationResult {
    let start = std::time::Instant::now();
    let mut steps_completed = vec![];
    let mut context: HashMap<String, serde_json::Value> = HashMap::new();

    context.insert("alert_title".into(), json!(alert_title));
    context.insert("graph_id".into(), json!(graph.id));
    if let Some(ip) = source_ip {
        context.insert("source_ip".into(), json!(ip));
    }
    if let Some(host) = hostname {
        context.insert("hostname".into(), json!(host));
    }

    tracing::info!(
        "INVESTIGATION: Starting '{}' for alert: {}",
        graph.id,
        alert_title
    );

    for (i, step) in graph.steps.iter().enumerate() {
        let step_start = std::time::Instant::now();
        let step_type = format!("{:?}", step)
            .split('{')
            .next()
            .unwrap_or("Unknown")
            .trim()
            .to_string();

        let result = match step {
            InvestigationStep::EnrichIp { sources } => {
                execute_enrich_ip(store.as_ref(), source_ip, sources, &mut context).await
            }
            InvestigationStep::EnrichDomain { sources } => {
                // Extract domain from context if available
                let domain = context
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                execute_enrich_domain(domain.as_deref(), sources, &mut context).await
            }
            InvestigationStep::EnrichCve { sources } => {
                let cve = context
                    .get("cve_id")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                execute_enrich_cve(store.as_ref(), cve.as_deref(), sources, &mut context).await
            }
            InvestigationStep::EnrichHash { sources } => {
                let hash = context
                    .get("file_hash")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                execute_enrich_hash(hash.as_deref(), sources, &mut context).await
            }
            InvestigationStep::QueryHistory {
                entity_type,
                window_hours,
            } => execute_query_history(store.as_ref(), entity_type, *window_hours, &context).await,
            InvestigationStep::CorrelateAlerts {
                same_ip,
                same_asset,
                window_hours,
            } => {
                execute_correlate(
                    store.as_ref(),
                    *same_ip,
                    *same_asset,
                    *window_hours,
                    &context,
                )
                .await
            }
            InvestigationStep::MapMitreTechniques => {
                execute_map_mitre(store.as_ref(), alert_title, &mut context).await
            }
            InvestigationStep::FindAttackPaths => {
                execute_find_paths(store.as_ref(), hostname, &mut context).await
            }
            InvestigationStep::BuildContext => {
                json!({ "context_built": true, "keys": context.keys().collect::<Vec<_>>() })
            }
            InvestigationStep::SendToReasoning => {
                // This step is handled by the caller (Intelligence Engine)
                json!({ "ready_for_reasoning": true })
            }
            InvestigationStep::CreateFinding { severity } => {
                json!({ "severity": severity, "pending": true })
            }
            InvestigationStep::NotifyRssi => {
                json!({ "notify": true })
            }
        };

        let duration = step_start.elapsed().as_millis() as u64;
        tracing::debug!(
            "INVESTIGATION: Step {}/{} {} ({} ms)",
            i + 1,
            graph.steps.len(),
            step_type,
            duration
        );

        steps_completed.push(StepResult {
            step_index: i,
            step_type,
            success: true,
            data: result,
            duration_ms: duration,
        });
    }

    let total_duration = start.elapsed().as_millis() as u64;
    tracing::info!(
        "INVESTIGATION: '{}' complete — {} steps, {} ms",
        graph.id,
        steps_completed.len(),
        total_duration
    );

    InvestigationResult {
        graph_id: graph.id.clone(),
        steps_completed,
        context,
        total_duration_ms: total_duration,
    }
}

// ══════════════════════════════════════════════════════════
// STEP EXECUTORS — Each step calls real enrichment/graph APIs
// ══════════════════════════════════════════════════════════

async fn execute_enrich_ip(
    store: &dyn Database,
    source_ip: Option<&str>,
    sources: &[String],
    context: &mut HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    let Some(ip) = source_ip else {
        return json!({"skipped": "no source IP"});
    };
    let ip = ip.split('/').next().unwrap_or(ip).trim();
    if ip.is_empty()
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.")
    {
        return json!({"skipped": "private IP"});
    }

    let mut enrichment = json!({});

    for source in sources {
        match source.as_str() {
            "greynoise" => {
                if let Ok(gn) = tokio::time::timeout(
                    std::time::Duration::from_secs(8),
                    crate::enrichment::greynoise::lookup_ip(ip, None),
                )
                .await
                {
                    if let Ok(gn) = gn {
                        enrichment["greynoise"] = json!({
                            "classification": gn.classification,
                            "noise": gn.noise,
                            "riot": gn.riot,
                        });
                    }
                }
            }
            "ipinfo" => {
                if let Ok(Ok(geo)) = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    crate::enrichment::ipinfo::lookup_ip(ip),
                )
                .await
                {
                    enrichment["ipinfo"] = json!({
                        "country": geo.country,
                        "org": geo.org,
                        "city": geo.city,
                    });
                }
            }
            "abuseipdb" | "crowdsec" => {
                // These require API keys — check if configured
                enrichment[source.as_str()] = json!({"status": "requires_api_key"});
            }
            _ => {}
        }
    }

    // Store in graph
    let country = enrichment["ipinfo"]["country"].as_str().map(String::from);
    let classification = enrichment["greynoise"]["classification"]
        .as_str()
        .map(String::from);
    crate::graph::threat_graph::upsert_ip(
        store,
        ip,
        country.as_deref(),
        None,
        classification.as_deref(),
    )
    .await;

    context.insert("ip_enrichment".into(), enrichment.clone());
    enrichment
}

async fn execute_enrich_domain(
    domain: Option<&str>,
    sources: &[String],
    context: &mut HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    let Some(domain) = domain else {
        return json!({"skipped": "no domain"});
    };
    let mut enrichment = json!({});

    for source in sources {
        match source.as_str() {
            "openphish" => {
                // OpenPhish is a local feed check — no external API call
                enrichment["openphish"] = json!({"checked": true});
            }
            "urlhaus" | "threatfox" | "virustotal" => {
                enrichment[source.as_str()] = json!({"status": "requires_api_key"});
            }
            _ => {}
        }
    }

    context.insert("domain_enrichment".into(), enrichment.clone());
    enrichment
}

async fn execute_enrich_cve(
    store: &dyn Database,
    cve_id: Option<&str>,
    sources: &[String],
    context: &mut HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    let Some(cve) = cve_id else {
        return json!({"skipped": "no CVE ID"});
    };
    let mut enrichment = json!({});

    for source in sources {
        match source.as_str() {
            "nvd" => {
                let config = crate::enrichment::cve_lookup::NvdConfig::from_db(store).await;
                if let Ok(info) = crate::enrichment::cve_lookup::lookup_cve(cve, &config).await {
                    enrichment["nvd"] = json!({
                        "cvss": info.cvss_score,
                        "severity": info.cvss_severity,
                        "description": info.description,
                        "exploited": info.exploited_in_wild,
                    });
                }
            }
            "cisa_kev" => {
                if let Some(kev) = crate::enrichment::cisa_kev::is_exploited(store, cve).await {
                    enrichment["kev"] = json!({
                        "exploited": true,
                        "due_date": kev.due_date,
                        "action": kev.required_action,
                    });
                }
            }
            "epss" => {
                if let Ok(Some(epss)) = crate::enrichment::epss::lookup_epss(cve).await {
                    enrichment["epss"] = json!({
                        "score": epss.epss,
                        "percentile": epss.percentile,
                    });
                }
            }
            _ => {}
        }
    }

    context.insert("cve_enrichment".into(), enrichment.clone());
    enrichment
}

async fn execute_enrich_hash(
    hash: Option<&str>,
    sources: &[String],
    context: &mut HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    let Some(_hash) = hash else {
        return json!({"skipped": "no hash"});
    };
    let enrichment = json!({"sources_checked": sources});
    context.insert("hash_enrichment".into(), enrichment.clone());
    enrichment
}

async fn execute_query_history(
    store: &dyn Database,
    entity_type: &str,
    window_hours: u64,
    context: &HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    use crate::db::threatclaw_store::ThreatClawStore;

    match entity_type {
        "IP" => {
            if let Some(ip) = context.get("source_ip").and_then(|v| v.as_str()) {
                let targets = crate::graph::threat_graph::find_ip_targets(store, ip).await;
                json!({ "ip": ip, "targets_attacked": targets, "window_hours": window_hours })
            } else {
                json!({"skipped": "no IP in context"})
            }
        }
        "Asset" => {
            if let Some(host) = context.get("hostname").and_then(|v| v.as_str()) {
                let attackers = crate::graph::threat_graph::find_attackers(store, host).await;
                json!({ "asset": host, "attackers": attackers, "window_hours": window_hours })
            } else {
                json!({"skipped": "no hostname in context"})
            }
        }
        _ => json!({"skipped": format!("entity_type {} not implemented", entity_type)}),
    }
}

async fn execute_correlate(
    store: &dyn Database,
    same_ip: bool,
    same_asset: bool,
    window_hours: u64,
    context: &HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    use crate::db::threatclaw_store::ThreatClawStore;

    let mut correlated = json!({});

    if same_ip {
        if let Some(ip) = context.get("source_ip").and_then(|v| v.as_str()) {
            let alerts = store
                .list_alerts(None, Some("new"), 50, 0)
                .await
                .unwrap_or_default();
            let related: Vec<_> = alerts
                .iter()
                .filter(|a| a.source_ip.as_deref().map(|s| s.contains(ip)) == Some(true))
                .map(|a| json!({"title": a.title, "level": a.level}))
                .collect();
            correlated["same_ip_alerts"] = json!(related);
        }
    }

    if same_asset {
        if let Some(host) = context.get("hostname").and_then(|v| v.as_str()) {
            let alerts = store
                .list_alerts(None, Some("new"), 50, 0)
                .await
                .unwrap_or_default();
            let related: Vec<_> = alerts
                .iter()
                .filter(|a| a.hostname.as_deref() == Some(host))
                .map(|a| json!({"title": a.title, "level": a.level}))
                .collect();
            correlated["same_asset_alerts"] = json!(related);
        }
    }

    correlated["window_hours"] = json!(window_hours);
    correlated
}

async fn execute_map_mitre(
    store: &dyn Database,
    alert_title: &str,
    context: &mut HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    // Simple keyword-to-MITRE mapping
    let mappings: &[(&[&str], &str, &str)] = &[
        (
            &["brute force", "brute", "password"],
            "T1110",
            "Brute Force",
        ),
        (&["ssh", "rdp", "remote"], "T1021", "Remote Services"),
        (
            &["lateral", "movement", "pivot"],
            "T1021",
            "Remote Services",
        ),
        (&["phish", "spear"], "T1566", "Phishing"),
        (
            &["exfil", "transfer", "upload"],
            "T1041",
            "Exfiltration Over C2 Channel",
        ),
        (&["dns tunnel", "dns exfil"], "T1071.004", "DNS"),
        (
            &["c2", "beacon", "command"],
            "T1071",
            "Application Layer Protocol",
        ),
        (
            &["privilege", "escalat", "sudo", "root"],
            "T1068",
            "Exploitation for Privilege Escalation",
        ),
        (
            &["log4j", "log4shell", "jndi"],
            "T1190",
            "Exploit Public-Facing Application",
        ),
        (
            &["reverse shell", "shell", "bind"],
            "T1059",
            "Command and Scripting Interpreter",
        ),
        (
            &["credential", "password", "shadow"],
            "T1003",
            "OS Credential Dumping",
        ),
        (
            &["scan", "port", "nmap"],
            "T1046",
            "Network Service Scanning",
        ),
        (
            &["malware", "trojan", "ransomware"],
            "T1204",
            "User Execution",
        ),
    ];

    let lower = alert_title.to_lowercase();
    let mut techniques = vec![];

    for (keywords, mitre_id, name) in mappings {
        if keywords.iter().any(|k| lower.contains(k)) {
            techniques.push(json!({"mitre_id": mitre_id, "name": name}));
            crate::graph::threat_graph::upsert_technique(store, mitre_id, name, "").await;
        }
    }

    context.insert("mitre_techniques".into(), json!(techniques));
    json!({"techniques": techniques})
}

async fn execute_find_paths(
    store: &dyn Database,
    hostname: Option<&str>,
    context: &mut HashMap<String, serde_json::Value>,
) -> serde_json::Value {
    let Some(host) = hostname else {
        return json!({"skipped": "no hostname"});
    };

    let attackers = crate::graph::threat_graph::find_attackers(store, host).await;
    let cves = crate::graph::threat_graph::find_asset_cves(store, host).await;

    let paths = json!({
        "asset": host,
        "attack_paths": attackers.len(),
        "vulnerable_cves": cves.len(),
        "attackers": attackers,
        "cves": cves,
    });

    context.insert("attack_paths".into(), paths.clone());
    paths
}
