//! Observation Collector — agrège les données de sécurité multi-sources.
//!
//! Collecte les findings, alertes, logs et métriques depuis la DB
//! pour les présenter au LLM dans un format structuré et sécurisé.

use serde::Serialize;

use crate::agent::tool_output_wrapper::wrap_tool_output;

/// Observation collectée depuis une source.
#[derive(Debug, Clone, Serialize)]
pub struct Observation {
    pub source: String,
    pub category: ObservationCategory,
    pub data: String,
    pub severity: Option<String>,
    pub count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationCategory {
    Finding,
    Alert,
    Log,
    Metric,
    Scan,
}

/// Collection d'observations prête pour le LLM.
#[derive(Debug, Clone)]
pub struct ObservationSet {
    pub observations: Vec<Observation>,
    pub summary: String,
}

impl ObservationSet {
    pub fn new() -> Self {
        Self {
            observations: Vec::new(),
            summary: String::new(),
        }
    }

    pub fn add(&mut self, obs: Observation) {
        self.observations.push(obs);
    }

    /// Génère le résumé textuel des observations.
    pub fn build_summary(&mut self) {
        let findings = self
            .observations
            .iter()
            .filter(|o| o.category == ObservationCategory::Finding)
            .count();
        let alerts = self
            .observations
            .iter()
            .filter(|o| o.category == ObservationCategory::Alert)
            .count();
        let critical = self
            .observations
            .iter()
            .filter(|o| o.severity.as_deref() == Some("critical"))
            .count();
        let high = self
            .observations
            .iter()
            .filter(|o| o.severity.as_deref() == Some("high"))
            .count();

        self.summary = format!(
            "{} observations: {} findings, {} alertes ({} critiques, {} hautes)",
            self.observations.len(),
            findings,
            alerts,
            critical,
            high
        );
    }

    /// Convertit toutes les observations en blocs XML wrappés pour le LLM.
    pub fn to_wrapped_blocks(&self) -> Vec<String> {
        self.observations
            .iter()
            .map(|obs| {
                let wrapped = wrap_tool_output(&obs.source, &obs.data);
                wrapped.content
            })
            .collect()
    }

    /// Convertit en texte brut pour le résumé (sans XML wrapping).
    pub fn to_summary_text(&self) -> String {
        let mut text = String::new();
        text.push_str(&format!("## Résumé: {}\n\n", self.summary));

        for obs in &self.observations {
            text.push_str(&format!(
                "- [{:?}] [{}] {}\n",
                obs.category,
                obs.severity.as_deref().unwrap_or("info"),
                truncate(&obs.data, 200),
            ));
        }

        text
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    pub fn len(&self) -> usize {
        self.observations.len()
    }
}

impl Default for ObservationSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Construit des observations depuis des findings bruts (format DB).
pub fn findings_to_observations(findings: &[serde_json::Value]) -> Vec<Observation> {
    findings
        .iter()
        .map(|f| Observation {
            source: f["source"].as_str().unwrap_or("unknown").to_string(),
            category: ObservationCategory::Finding,
            data: format!(
                "[{}] {} — {} ({})",
                f["severity"].as_str().unwrap_or("info"),
                f["title"].as_str().unwrap_or(""),
                f["asset"].as_str().unwrap_or(""),
                f["skill_id"].as_str().unwrap_or(""),
            ),
            severity: f["severity"].as_str().map(|s| s.to_string()),
            count: 1,
        })
        .collect()
}

/// Construit des observations depuis des alertes Sigma brutes.
pub fn alerts_to_observations(alerts: &[serde_json::Value]) -> Vec<Observation> {
    alerts
        .iter()
        .map(|a| Observation {
            source: "sigma".to_string(),
            category: ObservationCategory::Alert,
            data: format!(
                "[{}] {} — {} (rule: {})",
                a["level"].as_str().unwrap_or("info"),
                a["title"].as_str().unwrap_or(""),
                a["hostname"].as_str().unwrap_or(""),
                a["rule_id"].as_str().unwrap_or(""),
            ),
            severity: a["level"].as_str().map(|s| s.to_string()),
            count: 1,
        })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let end = s
            .char_indices()
            .take_while(|(i, _)| *i < max)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_set() {
        let set = ObservationSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_add_observations() {
        let mut set = ObservationSet::new();
        set.add(Observation {
            source: "nmap".to_string(),
            category: ObservationCategory::Finding,
            data: "Port 22 ouvert".to_string(),
            severity: Some("low".to_string()),
            count: 1,
        });
        set.add(Observation {
            source: "sigma".to_string(),
            category: ObservationCategory::Alert,
            data: "Brute force SSH".to_string(),
            severity: Some("critical".to_string()),
            count: 1,
        });

        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_build_summary() {
        let mut set = ObservationSet::new();
        set.add(Observation {
            source: "nuclei".to_string(),
            category: ObservationCategory::Finding,
            data: "CVE-2024-1234".to_string(),
            severity: Some("critical".to_string()),
            count: 1,
        });
        set.add(Observation {
            source: "sigma".to_string(),
            category: ObservationCategory::Alert,
            data: "SSH bruteforce".to_string(),
            severity: Some("high".to_string()),
            count: 1,
        });
        set.build_summary();

        assert!(set.summary.contains("2 observations"));
        assert!(set.summary.contains("1 findings"));
        assert!(set.summary.contains("1 alertes"));
        assert!(set.summary.contains("1 critiques"));
    }

    #[test]
    fn test_wrapped_blocks_contain_xml() {
        let mut set = ObservationSet::new();
        set.add(Observation {
            source: "nmap".to_string(),
            category: ObservationCategory::Finding,
            data: "22/tcp open ssh".to_string(),
            severity: None,
            count: 1,
        });

        let blocks = set.to_wrapped_blocks();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].contains("<tool_output"));
        assert!(blocks[0].contains("nmap"));
        assert!(blocks[0].contains("22/tcp open ssh"));
    }

    #[test]
    fn test_summary_text() {
        let mut set = ObservationSet::new();
        set.add(Observation {
            source: "nuclei".to_string(),
            category: ObservationCategory::Finding,
            data: "CVE found".to_string(),
            severity: Some("high".to_string()),
            count: 1,
        });
        set.build_summary();
        let text = set.to_summary_text();

        assert!(text.contains("Finding"));
        assert!(text.contains("high"));
        assert!(text.contains("CVE found"));
    }

    #[test]
    fn test_findings_to_observations() {
        let findings = vec![serde_json::json!({
            "title": "CVE-2024-1234",
            "severity": "critical",
            "asset": "192.168.1.10",
            "source": "nuclei",
            "skill_id": "skill-vuln-scan"
        })];

        let obs = findings_to_observations(&findings);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].category, ObservationCategory::Finding);
        assert_eq!(obs[0].severity, Some("critical".to_string()));
        assert!(obs[0].data.contains("CVE-2024-1234"));
    }

    #[test]
    fn test_alerts_to_observations() {
        let alerts = vec![serde_json::json!({
            "title": "Brute force SSH",
            "level": "critical",
            "hostname": "bastion-01",
            "rule_id": "sigma-001"
        })];

        let obs = alerts_to_observations(&alerts);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].category, ObservationCategory::Alert);
        assert!(obs[0].data.contains("Brute force SSH"));
    }

    #[test]
    fn test_truncate_short() {
        assert_eq!(truncate("hello", 100), "hello");
    }

    #[test]
    fn test_truncate_long() {
        let long = "a".repeat(300);
        let result = truncate(&long, 200);
        assert!(result.len() < 210);
        assert!(result.ends_with("..."));
    }
}
