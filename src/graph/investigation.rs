//! Investigation Graphs — deterministic investigation workflows.
//!
//! Each alert type has a predefined investigation path:
//! fixed steps → collect facts → send to L2 Reasoning.
//! Inspired by Qevlar AI's graph orchestration.
//!
//! The LLM never decides how to investigate.
//! The graph decides. The LLM only analyzes facts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single step in an investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InvestigationStep {
    /// Enrich an IP with external sources.
    EnrichIp { sources: Vec<String> },
    /// Enrich a domain.
    EnrichDomain { sources: Vec<String> },
    /// Enrich a CVE.
    EnrichCve { sources: Vec<String> },
    /// Enrich a file hash.
    EnrichHash { sources: Vec<String> },
    /// Query the graph for historical data.
    QueryHistory { entity_type: String, window_hours: u64 },
    /// Correlate with other alerts (same IP, same asset, same timeframe).
    CorrelateAlerts { same_ip: bool, same_asset: bool, window_hours: u64 },
    /// Map to MITRE ATT&CK techniques.
    MapMitreTechniques,
    /// Find attack paths in the graph.
    FindAttackPaths,
    /// Build the investigation context from all collected facts.
    BuildContext,
    /// Send to L2 Reasoning for analysis.
    SendToReasoning,
    /// Create a finding from the investigation.
    CreateFinding { severity: String },
    /// Notify the RSSI.
    NotifyRssi,
}

/// A complete investigation graph for a specific alert type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationGraph {
    pub id: String,
    pub name: String,
    pub description: String,
    pub trigger_pattern: String,
    pub steps: Vec<InvestigationStep>,
    pub estimated_duration_secs: u64,
}

/// Result of one investigation step.
#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub step_index: usize,
    pub step_type: String,
    pub success: bool,
    pub data: serde_json::Value,
    pub duration_ms: u64,
}

/// Complete investigation result.
#[derive(Debug, Clone, Serialize)]
pub struct InvestigationResult {
    pub graph_id: String,
    pub steps_completed: Vec<StepResult>,
    pub context: HashMap<String, serde_json::Value>,
    pub total_duration_ms: u64,
}

/// Get all predefined investigation graphs.
pub fn get_investigation_graphs() -> Vec<InvestigationGraph> {
    vec![
        InvestigationGraph {
            id: "ssh-brute-force".into(),
            name: "SSH Brute Force Investigation".into(),
            description: "Investigation complète d'une attaque brute force SSH".into(),
            trigger_pattern: "ssh.*brute|failed.*password|sshd".into(),
            steps: vec![
                InvestigationStep::EnrichIp { sources: vec!["greynoise".into(), "abuseipdb".into(), "ipinfo".into(), "crowdsec".into()] },
                InvestigationStep::QueryHistory { entity_type: "IP".into(), window_hours: 24 },
                InvestigationStep::CorrelateAlerts { same_ip: true, same_asset: true, window_hours: 1 },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding { severity: "auto".into() },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 30,
        },
        InvestigationGraph {
            id: "cve-critical".into(),
            name: "Critical CVE Investigation".into(),
            description: "Investigation d'une CVE critique détectée sur un asset".into(),
            trigger_pattern: "CVE-.*|cve.*critical".into(),
            steps: vec![
                InvestigationStep::EnrichCve { sources: vec!["nvd".into(), "cisa_kev".into(), "epss".into()] },
                InvestigationStep::QueryHistory { entity_type: "CVE".into(), window_hours: 168 },
                InvestigationStep::FindAttackPaths,
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding { severity: "auto".into() },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 15,
        },
        InvestigationGraph {
            id: "phishing-url".into(),
            name: "Phishing URL Investigation".into(),
            description: "Investigation d'une URL de phishing détectée dans les logs".into(),
            trigger_pattern: "phish|suspicious.*url|openphish".into(),
            steps: vec![
                InvestigationStep::EnrichDomain { sources: vec!["openphish".into(), "urlhaus".into(), "virustotal".into()] },
                InvestigationStep::EnrichIp { sources: vec!["greynoise".into(), "ipinfo".into()] },
                InvestigationStep::QueryHistory { entity_type: "Domain".into(), window_hours: 48 },
                InvestigationStep::CorrelateAlerts { same_ip: false, same_asset: true, window_hours: 24 },
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding { severity: "auto".into() },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 20,
        },
        InvestigationGraph {
            id: "c2-communication".into(),
            name: "C2 Communication Investigation".into(),
            description: "Investigation d'une communication vers un serveur C2 connu".into(),
            trigger_pattern: "c2|beacon|command.*control|dns.*tunnel".into(),
            steps: vec![
                InvestigationStep::EnrichIp { sources: vec!["threatfox".into(), "greynoise".into(), "ipinfo".into()] },
                InvestigationStep::EnrichDomain { sources: vec!["threatfox".into(), "urlhaus".into()] },
                InvestigationStep::QueryHistory { entity_type: "IP".into(), window_hours: 72 },
                InvestigationStep::CorrelateAlerts { same_ip: true, same_asset: true, window_hours: 24 },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding { severity: "CRITICAL".into() },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 25,
        },
        InvestigationGraph {
            id: "lateral-movement".into(),
            name: "Lateral Movement Investigation".into(),
            description: "Investigation d'un mouvement latéral détecté entre assets".into(),
            trigger_pattern: "lateral|pivot|ssh.*internal|rdp.*internal".into(),
            steps: vec![
                InvestigationStep::EnrichIp { sources: vec!["ipinfo".into()] },
                InvestigationStep::CorrelateAlerts { same_ip: true, same_asset: false, window_hours: 1 },
                InvestigationStep::QueryHistory { entity_type: "Asset".into(), window_hours: 24 },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding { severity: "CRITICAL".into() },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 30,
        },
        InvestigationGraph {
            id: "malware-hash".into(),
            name: "Malware Hash Investigation".into(),
            description: "Investigation d'un hash de fichier malveillant détecté".into(),
            trigger_pattern: "malware|hash|sha256|md5|trojan|ransomware".into(),
            steps: vec![
                InvestigationStep::EnrichHash { sources: vec!["malware_bazaar".into(), "virustotal".into()] },
                InvestigationStep::QueryHistory { entity_type: "Hash".into(), window_hours: 168 },
                InvestigationStep::CorrelateAlerts { same_ip: false, same_asset: true, window_hours: 24 },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding { severity: "CRITICAL".into() },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 15,
        },
        InvestigationGraph {
            id: "dns-exfiltration".into(),
            name: "DNS Exfiltration Investigation".into(),
            description: "Investigation d'une exfiltration de données via DNS tunneling".into(),
            trigger_pattern: "dns.*exfil|dns.*tunnel|base64.*dns|txt.*query".into(),
            steps: vec![
                InvestigationStep::EnrichDomain { sources: vec!["threatfox".into(), "openphish".into()] },
                InvestigationStep::EnrichIp { sources: vec!["greynoise".into(), "ipinfo".into()] },
                InvestigationStep::QueryHistory { entity_type: "Domain".into(), window_hours: 48 },
                InvestigationStep::CorrelateAlerts { same_ip: false, same_asset: true, window_hours: 4 },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding { severity: "CRITICAL".into() },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 20,
        },
    ]
}

/// Match an alert to the best investigation graph based on trigger patterns.
pub fn match_investigation_graph(alert_title: &str) -> Option<String> {
    let lower = alert_title.to_lowercase();
    // Order matters: more specific patterns first
    let graphs: &[(&str, &[&str])] = &[
        ("lateral-movement", &["lateral", "pivot", "movement"]),
        ("dns-exfiltration", &["dns exfil", "dns tunnel", "base64 dns"]),
        ("c2-communication", &["c2", "beacon", "command and control"]),
        ("ssh-brute-force", &["brute force", "brute", "failed password", "sshd"]),
        ("cve-critical", &["cve-", "critical"]),
        ("phishing-url", &["phish", "suspicious url", "openphish"]),
        ("malware-hash", &["malware", "trojan", "ransomware"]),
    ];

    for (graph_id, patterns) in graphs {
        if patterns.iter().any(|p| lower.contains(p)) {
            return Some(graph_id.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_investigation_graphs_count() {
        let graphs = get_investigation_graphs();
        assert_eq!(graphs.len(), 7);
    }

    #[test]
    fn test_match_graph() {
        assert_eq!(match_investigation_graph("SSH brute force from 185.x.x.x"), Some("ssh-brute-force".into()));
        assert_eq!(match_investigation_graph("CVE-2021-44228 Log4Shell"), Some("cve-critical".into()));
        assert_eq!(match_investigation_graph("Phishing URL detected"), Some("phishing-url".into()));
        assert_eq!(match_investigation_graph("C2 beacon every 60s"), Some("c2-communication".into()));
        assert_eq!(match_investigation_graph("Lateral movement SSH root"), Some("lateral-movement".into()));
        assert_eq!(match_investigation_graph("Malware hash detected"), Some("malware-hash".into()));
        assert_eq!(match_investigation_graph("DNS exfiltration base64"), Some("dns-exfiltration".into()));
        assert_eq!(match_investigation_graph("Normal log entry"), None);
    }
}
