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
    QueryHistory {
        entity_type: String,
        window_hours: u64,
    },
    /// Correlate with other alerts (same IP, same asset, same timeframe).
    CorrelateAlerts {
        same_ip: bool,
        same_asset: bool,
        window_hours: u64,
    },
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
                InvestigationStep::EnrichIp {
                    sources: vec![
                        "greynoise".into(),
                        "abuseipdb".into(),
                        "ipinfo".into(),
                        "crowdsec".into(),
                    ],
                },
                InvestigationStep::QueryHistory {
                    entity_type: "IP".into(),
                    window_hours: 24,
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: true,
                    same_asset: true,
                    window_hours: 1,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "auto".into(),
                },
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
                InvestigationStep::EnrichCve {
                    sources: vec!["nvd".into(), "cisa_kev".into(), "epss".into()],
                },
                InvestigationStep::QueryHistory {
                    entity_type: "CVE".into(),
                    window_hours: 168,
                },
                InvestigationStep::FindAttackPaths,
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "auto".into(),
                },
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
                InvestigationStep::EnrichDomain {
                    sources: vec!["openphish".into(), "urlhaus".into(), "virustotal".into()],
                },
                InvestigationStep::EnrichIp {
                    sources: vec!["greynoise".into(), "ipinfo".into()],
                },
                InvestigationStep::QueryHistory {
                    entity_type: "Domain".into(),
                    window_hours: 48,
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: false,
                    same_asset: true,
                    window_hours: 24,
                },
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "auto".into(),
                },
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
                InvestigationStep::EnrichIp {
                    sources: vec!["threatfox".into(), "greynoise".into(), "ipinfo".into()],
                },
                InvestigationStep::EnrichDomain {
                    sources: vec!["threatfox".into(), "urlhaus".into()],
                },
                InvestigationStep::QueryHistory {
                    entity_type: "IP".into(),
                    window_hours: 72,
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: true,
                    same_asset: true,
                    window_hours: 24,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "CRITICAL".into(),
                },
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
                InvestigationStep::EnrichIp {
                    sources: vec!["ipinfo".into()],
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: true,
                    same_asset: false,
                    window_hours: 1,
                },
                InvestigationStep::QueryHistory {
                    entity_type: "Asset".into(),
                    window_hours: 24,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "CRITICAL".into(),
                },
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
                InvestigationStep::EnrichHash {
                    sources: vec!["malware_bazaar".into(), "virustotal".into()],
                },
                InvestigationStep::QueryHistory {
                    entity_type: "Hash".into(),
                    window_hours: 168,
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: false,
                    same_asset: true,
                    window_hours: 24,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "CRITICAL".into(),
                },
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
                InvestigationStep::EnrichDomain {
                    sources: vec!["threatfox".into(), "openphish".into()],
                },
                InvestigationStep::EnrichIp {
                    sources: vec!["greynoise".into(), "ipinfo".into()],
                },
                InvestigationStep::QueryHistory {
                    entity_type: "Domain".into(),
                    window_hours: 48,
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: false,
                    same_asset: true,
                    window_hours: 4,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "CRITICAL".into(),
                },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 20,
        },
        // Roadmap réparation 2026-06-12 Fix 1.3 — Windows-specific workflows.
        // The pre-existing `ssh-brute-force` graph runs GreyNoise / AbuseIPDB
        // lookups that make no sense for local NTLM logons (source is
        // fe80::... link-local or a workstation name) and primes the LLM
        // with SSH context that triggers hallucinations on Windows brute
        // force. These four workflows replace it for the relevant rule_ids.
        InvestigationGraph {
            id: "win-bruteforce".into(),
            name: "Windows Brute Force Investigation".into(),
            description: "Brute force NTLM/Kerberos sur un hôte Windows".into(),
            trigger_pattern: "osquery-win-failed-logon-burst".into(),
            steps: vec![
                InvestigationStep::CorrelateAlerts {
                    same_ip: false,
                    same_asset: true,
                    window_hours: 1,
                },
                InvestigationStep::QueryHistory {
                    entity_type: "Asset".into(),
                    window_hours: 24,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "auto".into(),
                },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 15,
        },
        InvestigationGraph {
            id: "win-account-mgmt".into(),
            name: "Windows Account Management Investigation".into(),
            description:
                "Création / suppression de compte ou modification de groupe privilégié sur Windows"
                    .into(),
            trigger_pattern:
                "osquery-win-user-created|osquery-win-user-deleted|osquery-win-group-membership-add"
                    .into(),
            steps: vec![
                InvestigationStep::QueryHistory {
                    entity_type: "Asset".into(),
                    window_hours: 168,
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: false,
                    same_asset: true,
                    window_hours: 24,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "auto".into(),
                },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 15,
        },
        InvestigationGraph {
            id: "log-tampering".into(),
            name: "Audit Log Tampering Investigation".into(),
            description: "Effacement du journal d'audit Windows — IOC anti-forensique".into(),
            trigger_pattern: "osquery-win-audit-log-cleared".into(),
            steps: vec![
                InvestigationStep::QueryHistory {
                    entity_type: "Asset".into(),
                    window_hours: 168,
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: false,
                    same_asset: true,
                    window_hours: 24,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "CRITICAL".into(),
                },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 15,
        },
        InvestigationGraph {
            id: "win-offensive-tool".into(),
            name: "Windows Offensive Tool Investigation".into(),
            description:
                "PowerShell offensif ou outil de pentest détecté (Mimikatz, BloodHound, LOLBin)"
                    .into(),
            trigger_pattern: "osquery-win-powershell-suspicious|sysmon-offensive-tool".into(),
            steps: vec![
                InvestigationStep::QueryHistory {
                    entity_type: "Asset".into(),
                    window_hours: 24,
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: false,
                    same_asset: true,
                    window_hours: 4,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "HIGH".into(),
                },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 20,
        },
        InvestigationGraph {
            id: "credential-dump".into(),
            name: "Credential Dump Investigation".into(),
            description: "Accès suspect à LSASS ou indicateur de vol de credentials".into(),
            trigger_pattern: "sysmon-lsass-access".into(),
            steps: vec![
                InvestigationStep::QueryHistory {
                    entity_type: "Asset".into(),
                    window_hours: 24,
                },
                InvestigationStep::CorrelateAlerts {
                    same_ip: false,
                    same_asset: true,
                    window_hours: 4,
                },
                InvestigationStep::MapMitreTechniques,
                InvestigationStep::FindAttackPaths,
                InvestigationStep::BuildContext,
                InvestigationStep::SendToReasoning,
                InvestigationStep::CreateFinding {
                    severity: "CRITICAL".into(),
                },
                InvestigationStep::NotifyRssi,
            ],
            estimated_duration_secs: 20,
        },
    ]
}

/// Match an alert to the best investigation graph.
///
/// Roadmap réparation 2026-06-12 Fix 1.3 — `rule_id`-first matching.
/// The legacy implementation matched only on `alert_title.contains("brute")`
/// which routed every Windows NTLM brute force into the SSH workflow, with
/// downstream hallucinations on the LLM. Now we match by exact `rule_id`
/// prefix first (deterministic), then fall back to title keywords only for
/// legacy rules whose `rule_id` doesn't carry the relevant signal.
///
/// `rule_id` may be empty if the caller doesn't have it; the function still
/// works on title-only as a degraded mode.
pub fn match_investigation_graph(rule_id: &str, alert_title: &str) -> Option<String> {
    // Exact rule_id → workflow map. Keep this list aligned with the
    // `trigger_pattern` field of each InvestigationGraph (used by the test
    // suite) and with the rules emitted by `connectors/osquery.rs`.
    let rule_map: &[(&str, &str)] = &[
        // Windows agent rules (osquery + sysmon)
        ("osquery-win-failed-logon-burst", "win-bruteforce"),
        ("osquery-win-user-created", "win-account-mgmt"),
        ("osquery-win-user-deleted", "win-account-mgmt"),
        ("osquery-win-group-membership-add", "win-account-mgmt"),
        ("osquery-win-audit-log-cleared", "log-tampering"),
        ("osquery-win-powershell-suspicious", "win-offensive-tool"),
        ("sysmon-offensive-tool", "win-offensive-tool"),
        ("sysmon-lsass-access", "credential-dump"),
        // Legacy / cross-platform rules whose rule_id is already specific
        ("tc-ssh-brute", "ssh-brute-force"),
    ];
    let rule_id_lc = rule_id.to_lowercase();
    for (rid, gid) in rule_map {
        if rule_id_lc == *rid {
            return Some((*gid).to_string());
        }
    }

    // Fallback by title keywords for rules we haven't catalogued yet.
    // CRITICALLY: no bare "brute" / "brute force" / "failed password" entry
    // here — the SSH workflow must only catch alerts whose rule_id is
    // explicitly ssh-themed (above) to prevent the SSH-on-Windows mistake.
    let lower = alert_title.to_lowercase();
    let graphs: &[(&str, &[&str])] = &[
        ("lateral-movement", &["lateral", "pivot", "movement"]),
        (
            "dns-exfiltration",
            &["dns exfil", "dns tunnel", "base64 dns"],
        ),
        ("c2-communication", &["c2", "beacon", "command and control"]),
        ("ssh-brute-force", &["ssh brute", "sshd"]),
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
        // 7 legacy + 5 Windows-specific added by Roadmap réparation Fix 1.3
        assert_eq!(graphs.len(), 12);
    }

    #[test]
    fn test_match_graph_legacy_title_keywords() {
        assert_eq!(
            match_investigation_graph("", "ssh brute force from 185.x.x.x"),
            Some("ssh-brute-force".into())
        );
        assert_eq!(
            match_investigation_graph("", "CVE-2021-44228 Log4Shell"),
            Some("cve-critical".into())
        );
        assert_eq!(
            match_investigation_graph("", "Phishing URL detected"),
            Some("phishing-url".into())
        );
        assert_eq!(
            match_investigation_graph("", "C2 beacon every 60s"),
            Some("c2-communication".into())
        );
        assert_eq!(
            match_investigation_graph("", "Lateral movement SSH root"),
            Some("lateral-movement".into())
        );
        assert_eq!(
            match_investigation_graph("", "Malware hash detected"),
            Some("malware-hash".into())
        );
        assert_eq!(
            match_investigation_graph("", "DNS exfiltration base64"),
            Some("dns-exfiltration".into())
        );
        assert_eq!(match_investigation_graph("", "Normal log entry"), None);
    }

    #[test]
    fn test_match_graph_rule_id_first() {
        // Roadmap réparation Fix 1.3 — rule_id wins over title heuristics.
        // Windows NTLM brute force must NEVER route to ssh-brute-force.
        assert_eq!(
            match_investigation_graph(
                "osquery-win-failed-logon-burst",
                "Brute force candidat: 15 tentatives échouées sur SRV-CYBE06-001 (cible alice)"
            ),
            Some("win-bruteforce".into())
        );
        assert_eq!(
            match_investigation_graph("osquery-win-user-created", "Compte utilisateur créé"),
            Some("win-account-mgmt".into())
        );
        assert_eq!(
            match_investigation_graph("sysmon-lsass-access", "Accès suspect à LSASS"),
            Some("credential-dump".into())
        );
        assert_eq!(
            match_investigation_graph("osquery-win-audit-log-cleared", "Journal d'audit effacé"),
            Some("log-tampering".into())
        );
    }

    #[test]
    fn test_match_graph_brute_word_does_not_trigger_ssh_anymore() {
        // Pre-fix bug: title containing "brute force" routed to ssh-brute-force
        // regardless of platform. Post-fix: requires "ssh brute" or "sshd".
        assert_eq!(
            match_investigation_graph("unknown-rule", "Brute force candidat 15 tentatives"),
            None
        );
    }
}
