//! Cloud-Assisted Intent Parser — uses Cloud LLM to understand RSSI commands.
//!
//! Flow:
//! 1. RSSI types natural language in Telegram/Mattermost
//! 2. Message sent to Cloud LLM (Claude/Mistral) — ONLY the text, no data
//! 3. Cloud returns a structured intent (JSON action plan)
//! 4. ThreatClaw executes the plan LOCALLY (graph, enrichment, scans)
//! 5. Results anonymized → Cloud reformulates in natural French
//! 6. Response sent back to RSSI
//!
//! RULE: The Cloud NEVER sees real IPs, hostnames, CVEs, or credentials.
//! The anonymizer strips everything before sending to Cloud.

use serde::{Deserialize, Serialize};

/// A parsed intent from the Cloud LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    /// What the RSSI wants to do.
    pub action: IntentAction,
    /// Extracted parameters (may be empty).
    pub params: IntentParams,
    /// Confidence that we understood correctly (0.0-1.0).
    pub confidence: f64,
    /// Original message for context.
    pub original_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentAction {
    /// "Show me the status" / "Comment va mon infra"
    Status,
    /// "Check this IP" / "C'est quoi cette IP"
    LookupIp { ip: String },
    /// "Block this IP" / "Bloque cette adresse"
    BlockIp { ip: String },
    /// "Scan the network" / "Scanne le réseau"
    ScanNetwork { target: String },
    /// "Show attack paths" / "Montre les chemins d'attaque"
    AttackPaths,
    /// "What's the blast radius of X" / "Si srv-prod est compromis"
    BlastRadius { asset: String },
    /// "Who is attacking us" / "Qui nous attaque"
    ThreatActors,
    /// "Show lateral movement" / "Y a du mouvement latéral"
    LateralMovement,
    /// "Generate NIS2 report" / "Rapport NIS2"
    ReportNis2,
    /// "Disable this account" / "Désactive ce compte"
    DisableAccount { username: String },
    /// "Show findings" / "Les vulnérabilités"
    ShowFindings { severity: Option<String> },
    /// "Show alerts" / "Les alertes"
    ShowAlerts,
    /// "Help" / "Aide"
    Help,
    /// Could not understand
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// Parse a natural language message into a structured intent.
/// Mode: "local" = L1 local LLM, "cloud" = Cloud API
pub async fn parse_intent(message: &str, mode: &str) -> Intent {
    // For now, use the local keyword-based parser (same as command_interpreter)
    // Cloud mode will call the Cloud LLM API
    let lower = message.to_lowercase();

    // Extract IP if present
    let ip = extract_ip(message);
    let asset = extract_asset(message);
    let username = extract_username(message);

    let (action, confidence) = if lower.contains("status") || lower.contains("comment va") || lower.contains("etat") {
        (IntentAction::Status, 0.9)
    } else if lower.contains("bloque") || lower.contains("block") || lower.contains("ban") {
        if let Some(ref ip) = ip {
            (IntentAction::BlockIp { ip: ip.clone() }, 0.9)
        } else {
            (IntentAction::BlockIp { ip: String::new() }, 0.5)
        }
    } else if lower.contains("scan") || lower.contains("scanne") {
        let target = extract_target(message).unwrap_or_else(|| "192.168.1.0/24".into());
        (IntentAction::ScanNetwork { target }, 0.8)
    } else if lower.contains("chemin") || lower.contains("attack path") || lower.contains("comment un attaquant") {
        (IntentAction::AttackPaths, 0.9)
    } else if lower.contains("blast") || lower.contains("impact") || lower.contains("compromis") || lower.contains("si.*tombe") {
        let a = asset.clone().unwrap_or_default();
        (IntentAction::BlastRadius { asset: a }, 0.8)
    } else if lower.contains("qui nous attaque") || lower.contains("acteur") || lower.contains("attaquant") || lower.contains("apt") {
        (IntentAction::ThreatActors, 0.9)
    } else if lower.contains("lateral") || lower.contains("mouvement") || lower.contains("pivot") {
        (IntentAction::LateralMovement, 0.9)
    } else if lower.contains("rapport") || lower.contains("nis2") || lower.contains("report") || lower.contains("comex") {
        (IntentAction::ReportNis2, 0.9)
    } else if lower.contains("desactiv") || lower.contains("disable") || lower.contains("verrouill") {
        let u = username.clone().unwrap_or_default();
        (IntentAction::DisableAccount { username: u }, 0.8)
    } else if lower.contains("finding") || lower.contains("vuln") || lower.contains("faille") {
        let sev = if lower.contains("critical") || lower.contains("critique") { Some("CRITICAL".into()) }
                  else if lower.contains("high") || lower.contains("haute") { Some("HIGH".into()) }
                  else { None };
        (IntentAction::ShowFindings { severity: sev }, 0.8)
    } else if lower.contains("alerte") || lower.contains("alert") || lower.contains("sigma") {
        (IntentAction::ShowAlerts, 0.8)
    } else if let Some(ref ip) = ip {
        // If we found an IP but no clear action, default to lookup
        (IntentAction::LookupIp { ip: ip.clone() }, 0.7)
    } else if lower.contains("aide") || lower.contains("help") || lower.contains("quoi") {
        (IntentAction::Help, 0.9)
    } else {
        (IntentAction::Unknown, 0.3)
    };

    Intent {
        action,
        params: IntentParams { ip, asset, username, severity: None, target: None },
        confidence,
        original_message: message.to_string(),
    }
}

/// Execute an intent locally and return the result as text.
pub async fn execute_intent(
    store: &dyn crate::db::Database,
    intent: &Intent,
) -> String {
    use crate::db::threatclaw_store::ThreatClawStore;

    match &intent.action {
        IntentAction::Status => {
            let findings = store.list_findings(None, Some("open"), None, 10, 0).await.unwrap_or_default();
            let alerts = store.list_alerts(None, Some("new"), 10, 0).await.unwrap_or_default();
            let stats = crate::graph::asset_resolution::asset_stats(store).await;
            let assets = stats["total_assets"].as_i64().unwrap_or(0);
            format!(
                "Situation actuelle :\n{} assets surveilles\n{} findings ouverts\n{} alertes actives",
                assets, findings.len(), alerts.len()
            )
        }

        IntentAction::LookupIp { ip } => {
            if ip.is_empty() { return "Quelle IP voulez-vous verifier ?".into(); }
            let attackers = crate::graph::threat_graph::find_ip_targets(store, ip).await;
            let score = crate::graph::confidence::compute_ip_confidence(store, ip, None, None).await;
            format!(
                "IP {} :\nConfiance menace : {}/100 ({})\nCibles attaquees : {}",
                ip, score.score, score.level, attackers.len()
            )
        }

        IntentAction::BlockIp { ip } => {
            if ip.is_empty() { return "Quelle IP bloquer ? (ex: bloque 185.220.101.42)".into(); }
            format!(
                "Action demandee : bloquer {} sur le firewall.\nConfirmez-vous ? (oui/non)\n\nNote : necessite un connecteur pfSense/OPNsense configure.",
                ip
            )
        }

        IntentAction::ScanNetwork { target } => {
            format!("Lancement scan nmap sur {} ...\nLes resultats seront dans Assets une fois le scan termine.", target)
        }

        IntentAction::AttackPaths => {
            let paths = crate::graph::attack_path::predict_attack_paths(store).await;
            if paths.paths.is_empty() {
                "Aucun chemin d'attaque detecte vers vos assets critiques.".into()
            } else {
                let mut msg = format!("{} chemins d'attaque detectes :\n", paths.total_paths);
                for (i, p) in paths.paths.iter().take(3).enumerate() {
                    msg.push_str(&format!("{}. {} → {} (risque: {}, exploitabilite: {}%)\n",
                        i + 1, p.entry_point, p.target, p.risk, p.exploitability as u32));
                }
                for r in &paths.top_recommendations {
                    msg.push_str(&format!("\nRecommandation : {}", r));
                }
                msg
            }
        }

        IntentAction::BlastRadius { asset } => {
            if asset.is_empty() { return "Quel asset ? (ex: blast radius de srv-prod-01)".into(); }
            let br = crate::graph::blast_radius::compute_blast_radius(store, asset).await;
            format!("{}\nScore impact : {:.0}/100\n{}", br.summary, br.impact_score, br.recommendation)
        }

        IntentAction::ThreatActors => {
            let actors = crate::graph::threat_actor::profile_threat_actors(store).await;
            if actors.actors.is_empty() {
                "Aucun acteur de menace profile pour le moment.".into()
            } else {
                let mut msg = format!("{} acteurs profiles :\n", actors.total_actors);
                for a in actors.actors.iter().take(3) {
                    msg.push_str(&format!("- {} ({})\n  Techniques: {}\n",
                        a.name, a.origin_country, a.techniques.join(", ")));
                    if let Some(ref apt) = a.apt_similarity {
                        if apt.similarity_score > 30 {
                            msg.push_str(&format!("  Ressemble a {} ({}%)\n", apt.apt_name, apt.similarity_score));
                        }
                    }
                }
                msg
            }
        }

        IntentAction::LateralMovement => {
            let lateral = crate::graph::lateral::detect_lateral_movement(store).await;
            if lateral.total_detections == 0 {
                "Aucun mouvement lateral detecte.".into()
            } else {
                format!("{} detection(s) :\n{}", lateral.total_detections, lateral.summary)
            }
        }

        IntentAction::ReportNis2 => {
            let report = crate::graph::supply_chain::generate_nis2_report(store).await;
            format!("Rapport NIS2 Article 21 genere.\n{}\nTelechargez-le depuis le dashboard > Intelligence > Rapport NIS2.",
                report["summary"].as_str().unwrap_or(""))
        }

        IntentAction::DisableAccount { username } => {
            if username.is_empty() { return "Quel compte desactiver ?".into(); }
            format!(
                "Action demandee : desactiver le compte '{}' dans Active Directory.\nConfirmez-vous ? (oui/non)\n\nNote : necessite un connecteur AD configure avec droits d'ecriture.",
                username
            )
        }

        IntentAction::ShowFindings { severity } => {
            let findings = store.list_findings(severity.as_deref(), Some("open"), None, 5, 0).await.unwrap_or_default();
            if findings.is_empty() {
                "Aucun finding ouvert.".into()
            } else {
                let mut msg = format!("{} findings ouverts :\n", findings.len());
                for f in findings.iter().take(5) {
                    msg.push_str(&format!("- [{}] {}\n", f.severity, f.title));
                }
                msg
            }
        }

        IntentAction::ShowAlerts => {
            let alerts = store.list_alerts(None, Some("new"), 5, 0).await.unwrap_or_default();
            if alerts.is_empty() {
                "Aucune alerte active.".into()
            } else {
                let mut msg = format!("{} alertes :\n", alerts.len());
                for a in alerts.iter().take(5) {
                    msg.push_str(&format!("- [{}] {}\n", a.level, a.title));
                }
                msg
            }
        }

        IntentAction::Help => {
            "Commandes disponibles :\n\
             - status / etat\n\
             - bloque [IP]\n\
             - scan [cible]\n\
             - chemins d'attaque\n\
             - blast radius [asset]\n\
             - acteurs de menace\n\
             - mouvement lateral\n\
             - rapport NIS2\n\
             - desactive [compte]\n\
             - findings / vulns\n\
             - alertes".into()
        }

        IntentAction::Unknown => {
            "Je n'ai pas compris. Tapez 'aide' pour voir les commandes disponibles.".into()
        }
    }
}

// ── Extractors ──

fn extract_ip(msg: &str) -> Option<String> {
    let re = regex::Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b").ok()?;
    re.find(msg).map(|m| m.as_str().to_string())
}

fn extract_asset(msg: &str) -> Option<String> {
    // Look for srv-xxx or PC-xxx patterns
    let re = regex::Regex::new(r"\b(srv-[\w-]+|pc-[\w-]+|dc-[\w-]+)\b").ok()?;
    re.find(&msg.to_lowercase()).map(|m| m.as_str().to_string())
}

fn extract_username(msg: &str) -> Option<String> {
    // Look for "compte xxx" or "user xxx" patterns
    let lower = msg.to_lowercase();
    for prefix in &["compte ", "user ", "utilisateur ", "desactive ", "disable "] {
        if let Some(pos) = lower.find(prefix) {
            let rest = &msg[pos + prefix.len()..];
            let username = rest.split_whitespace().next()?;
            if username.len() >= 2 && username.len() <= 64 {
                return Some(username.to_string());
            }
        }
    }
    None
}

fn extract_target(msg: &str) -> Option<String> {
    // Look for IP/subnet or hostname
    extract_ip(msg).or_else(|| extract_asset(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_parse_status() {
        let intent = parse_intent("comment va mon infra", "local").await;
        assert!(matches!(intent.action, IntentAction::Status));
    }

    #[tokio::test]
    async fn test_parse_lookup_ip() {
        let intent = parse_intent("c'est quoi cette IP 185.220.101.42", "local").await;
        assert!(matches!(intent.action, IntentAction::LookupIp { .. }));
        assert_eq!(intent.params.ip, Some("185.220.101.42".into()));
    }

    #[tokio::test]
    async fn test_parse_block() {
        let intent = parse_intent("bloque 10.0.0.5", "local").await;
        assert!(matches!(intent.action, IntentAction::BlockIp { .. }));
    }

    #[tokio::test]
    async fn test_parse_blast_radius() {
        let intent = parse_intent("si srv-prod-01 est compromis", "local").await;
        assert!(matches!(intent.action, IntentAction::BlastRadius { .. }));
        assert_eq!(intent.params.asset, Some("srv-prod-01".into()));
    }

    #[tokio::test]
    async fn test_parse_help() {
        let intent = parse_intent("aide", "local").await;
        assert!(matches!(intent.action, IntentAction::Help));
    }

    #[tokio::test]
    async fn test_parse_unknown() {
        let intent = parse_intent("bonjour", "local").await;
        assert!(matches!(intent.action, IntentAction::Unknown));
    }

    #[test]
    fn test_extract_ip() {
        assert_eq!(extract_ip("bloque 192.168.1.50"), Some("192.168.1.50".into()));
        assert_eq!(extract_ip("scan 10.0.0.0/24"), Some("10.0.0.0/24".into()));
        assert_eq!(extract_ip("pas d'ip ici"), None);
    }

    #[test]
    fn test_extract_asset() {
        assert_eq!(extract_asset("blast radius de srv-prod-01"), Some("srv-prod-01".into()));
        assert_eq!(extract_asset("check PC-COMPTA-03"), Some("pc-compta-03".into()));
    }
}
