//! Incident Dossier — the contract between Intelligence Engine (stage 1) and ReAct Investigation (stage 2).
//!
//! When the IE detects a situation that warrants AI analysis, it builds an IncidentDossier
//! containing all pre-collected data (findings, enrichment, correlations, graph, ML scores)
//! and passes it to the investigation runner. The ReAct loop never works on raw events —
//! it always receives a pre-filtered, pre-enriched dossier.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::agent::intelligence_engine::{GraphIntelSummary, NotificationLevel};

// ── Enrichment types ──

/// IP reputation from GreyNoise, AbuseIPDB, CrowdSec, IPinfo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    pub ip: String,
    pub is_malicious: bool,
    pub classification: String, // "malicious", "benign", "noise", "unknown"
    pub source: String,         // "greynoise", "abuseipdb", "crowdsec"
    pub details: String,        // "Tor exit node, 847 reports"
}

/// CVE details from NVD + EPSS + CISA KEV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveDetail {
    pub cve_id: String,
    pub cvss_score: Option<f64>,
    pub epss_score: Option<f64>,
    pub is_kev: bool,
    pub description: String,
}

/// Threat intel match from ThreatFox, MalwareBazaar, URLhaus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelMatch {
    pub indicator: String,
    pub indicator_type: String, // "ip", "url", "hash", "domain"
    pub source: String,         // "threatfox", "malwarebazaar", "urlhaus"
    pub threat_type: String,    // "c2", "malware", "phishing"
    pub malware: Option<String>,
    pub confidence: u8,
}

// ── Correlation types ──

/// MITRE ATT&CK kill chain step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreStep {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub finding_id: i64,
}

/// Correlations detected by the Intelligence Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationBundle {
    pub kill_chain_detected: bool,
    pub kill_chain_steps: Vec<MitreStep>,
    pub active_attack: bool,
    pub known_exploits: Vec<String>,
    pub related_assets: Vec<String>,
    pub campaign_id: Option<String>,
}

/// Pre-collected enrichment from the IE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentBundle {
    pub ip_reputations: Vec<IpReputation>,
    pub cve_details: Vec<CveDetail>,
    pub threat_intel: Vec<ThreatIntelMatch>,
    pub enrichment_lines: Vec<String>,
}

/// ML scores from the ML engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlBundle {
    pub anomaly_score: f64,
    pub dga_domains: Vec<String>,
    pub behavioral_cluster: Option<i32>,
}

// ── Finding/Alert types for the dossier ──

/// Simplified finding extracted from DB for the dossier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DossierFinding {
    pub id: i64,
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub asset: Option<String>,
    pub source: Option<String>,
    /// Machine identifier of the skill that produced this finding
    /// (e.g. "ml-anomaly-detector"). Used by the graph dispatcher to
    /// route dossiers to CACAO graphs when no sigma_rule is set.
    pub skill_id: Option<String>,
    pub metadata: Value,
    pub detected_at: DateTime<Utc>,
}

/// Simplified sigma alert for the dossier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DossierAlert {
    pub id: i64,
    /// Machine identifier of the Sigma rule (e.g. "tc-ssh-brute").
    /// Used by the Investigation Graph dispatcher to match CACAO graph triggers.
    pub rule_id: String,
    /// Human-readable title of the rule (e.g. "SSH Brute Force — 12 failures").
    /// Used in prompts and logs. Falls back to rule_id when title is absent.
    pub rule_name: String,
    pub level: String,
    /// Source IP of the alert (e.g. external attacker IP for an IDS hit on
    /// the OPNsense gateway). Required by `dossier_enrichment::enrich_ip_reputations`
    /// to populate IP reputation lookups (Spamhaus, ThreatFox, GreyNoise) into
    /// the structured `EnrichmentBundle.ip_reputations` instead of leaving the
    /// L2 prompt with a bare `source_ip` it has to interpret without context.
    #[serde(default)]
    pub source_ip: Option<String>,
    pub matched_fields: Value,
    pub created_at: DateTime<Utc>,
    /// Username extracted from the alert, used to compute CEL signals
    /// (is_admin, is_service_acct) for Investigation Graph evaluation.
    #[serde(default)]
    pub username: Option<String>,
}

// ── The Dossier ──

/// Incident dossier: everything the IE has collected, ready for AI investigation.
#[derive(Debug, Clone, Serialize)]
pub struct IncidentDossier {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub primary_asset: String,
    pub findings: Vec<DossierFinding>,
    pub sigma_alerts: Vec<DossierAlert>,
    pub enrichment: EnrichmentBundle,
    pub correlations: CorrelationBundle,
    pub graph_intel: Option<GraphIntelSummary>,
    pub ml_scores: MlBundle,
    pub asset_score: f64,
    pub global_score: f64,
    pub notification_level: NotificationLevel,
    /// Phase C — list of skills the operator has configured + enabled.
    /// Injected into the LLM prompt so the model knows what it can ask
    /// for and — critically — what it CANNOT pretend to have consulted.
    /// Stops the "I checked Wazuh and saw…" hallucination when Wazuh
    /// isn't installed.
    #[serde(default)]
    pub connected_skills: Vec<String>,
    /// Phase C — pre-resolved graph context for the primary asset:
    /// criticality, lateral path count, linked CVEs, recent users.
    /// Cheaper than letting the LLM choose to query the graph, and
    /// consumed by the reconciler to downgrade an unsupported verdict.
    #[serde(default)]
    pub graph_context: Option<GraphAssetContext>,
}

/// Pre-resolved graph context for the primary asset. Fed into the L1/L2
/// prompts and consumed by the reconciler to downgrade a Confirmed
/// verdict when the graph says "isolated, no lateral path, no CVE" —
/// i.e. the LLM probably hallucinated a kill chain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphAssetContext {
    pub criticality: String,
    pub lateral_paths: u32,
    pub linked_cves: Vec<String>,
    pub recent_users: Vec<String>,
}

impl IncidentDossier {
    /// Count of CRITICAL + HIGH findings
    pub fn high_severity_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == "CRITICAL" || f.severity == "HIGH")
            .count()
    }

    /// All unique source IPs extracted from finding metadata
    pub fn source_ips(&self) -> Vec<String> {
        let mut ips = std::collections::HashSet::new();
        for f in &self.findings {
            if let Some(ip) = f.metadata.get("src_ip").and_then(|v| v.as_str()) {
                if !ip.is_empty() && ip != "null" {
                    ips.insert(ip.to_string());
                }
            }
        }
        ips.into_iter().collect()
    }

    /// Compact summary for logging
    pub fn summary(&self) -> String {
        format!(
            "Dossier {} — asset={} findings={} alerts={} score={:.0} level={:?}",
            &self.id.to_string()[..8],
            self.primary_asset,
            self.findings.len(),
            self.sigma_alerts.len(),
            self.asset_score,
            self.notification_level,
        )
    }
}
