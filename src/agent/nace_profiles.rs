//! NACE/NAF Threat Profiles — maps industry sector to threat model + compliance.
//!
//! When the client declares their sector (via company_profile), ThreatClaw
//! auto-configures: MITRE ATT&CK focus, compliance frameworks, expected asset types,
//! and alert priority adjustments.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatProfile {
    pub sector: String,
    pub label: String,
    /// MITRE ATT&CK techniques most relevant to this sector
    pub mitre_techniques: Vec<String>,
    /// Compliance frameworks that apply
    pub compliance: Vec<String>,
    /// Expected asset types in this sector
    pub expected_assets: Vec<String>,
    /// Alert categories that are HIGH priority for this sector
    pub high_priority_alerts: Vec<String>,
    /// Alert categories that are LOW priority (common false positives)
    pub low_priority_alerts: Vec<String>,
    /// Sensitivity multiplier (1.0 = normal)
    pub sensitivity: f64,
}

/// Get the threat profile for a sector.
pub fn get_profile(sector: &str) -> ThreatProfile {
    match sector {
        "healthcare" => ThreatProfile {
            sector: "healthcare".into(),
            label: "Santé / Médical".into(),
            mitre_techniques: vec![
                "T1486".into(), // Data encrypted for impact (ransomware)
                "T1557".into(), // Adversary-in-the-middle
                "T1078".into(), // Valid accounts
                "T1190".into(), // Exploit public-facing application
                "T1021".into(), // Remote services
                "T1048".into(), // Exfiltration over alternative protocol
            ],
            compliance: vec!["nis2".into(), "hipaa".into(), "hds".into(), "rgpd".into()],
            expected_assets: vec![
                "server".into(),
                "workstation".into(),
                "iot".into(),
                "printer".into(),
            ],
            high_priority_alerts: vec![
                "ransomware".into(),
                "data-exfiltration".into(),
                "unauthorized-access".into(),
                "iot-anomaly".into(),
            ],
            low_priority_alerts: vec!["port-scan".into()],
            sensitivity: 1.5,
        },
        "finance" => ThreatProfile {
            sector: "finance".into(),
            label: "Finance / Assurance".into(),
            mitre_techniques: vec![
                "T1566".into(), // Phishing
                "T1078".into(), // Valid accounts
                "T1110".into(), // Brute force
                "T1071".into(), // Application layer protocol (C2)
                "T1005".into(), // Data from local system
                "T1552".into(), // Unsecured credentials
            ],
            compliance: vec![
                "nis2".into(),
                "pci-dss".into(),
                "rgpd".into(),
                "dora".into(),
            ],
            expected_assets: vec!["server".into(), "workstation".into(), "network".into()],
            high_priority_alerts: vec![
                "credential-theft".into(),
                "data-exfiltration".into(),
                "fraud".into(),
                "unauthorized-access".into(),
            ],
            low_priority_alerts: vec![],
            sensitivity: 1.4,
        },
        "industry" => ThreatProfile {
            sector: "industry".into(),
            label: "Industrie / Manufacturing".into(),
            mitre_techniques: vec![
                "T0831".into(), // Manipulation of control (ICS)
                "T0855".into(), // Unauthorized command message (ICS)
                "T0821".into(), // Modify controller tasking (ICS)
                "T1190".into(), // Exploit public-facing application
                "T1021".into(), // Remote services
                "T1486".into(), // Data encrypted for impact
            ],
            compliance: vec!["nis2".into(), "iec-62443".into(), "rgpd".into()],
            expected_assets: vec![
                "server".into(),
                "workstation".into(),
                "ot".into(),
                "network".into(),
            ],
            high_priority_alerts: vec![
                "ot-anomaly".into(),
                "plc-access".into(),
                "ransomware".into(),
                "lateral-movement".into(),
            ],
            low_priority_alerts: vec!["web-scan".into()],
            sensitivity: 1.2,
        },
        "retail" => ThreatProfile {
            sector: "retail".into(),
            label: "Commerce / Retail".into(),
            mitre_techniques: vec![
                "T1566".into(), // Phishing
                "T1059".into(), // Command and scripting interpreter
                "T1190".into(), // Exploit public-facing application
                "T1071".into(), // Application layer protocol
                "T1005".into(), // Data from local system
                "T1486".into(), // Ransomware
            ],
            compliance: vec!["pci-dss".into(), "rgpd".into(), "nis2".into()],
            expected_assets: vec![
                "server".into(),
                "workstation".into(),
                "website".into(),
                "network".into(),
            ],
            high_priority_alerts: vec![
                "web-compromise".into(),
                "payment-fraud".into(),
                "data-exfiltration".into(),
                "magecart".into(),
            ],
            low_priority_alerts: vec![],
            sensitivity: 1.1,
        },
        "government" => ThreatProfile {
            sector: "government".into(),
            label: "Collectivité / Administration".into(),
            mitre_techniques: vec![
                "T1566".into(), // Phishing
                "T1078".into(), // Valid accounts
                "T1021".into(), // Remote services
                "T1486".into(), // Ransomware
                "T1048".into(), // Exfiltration
                "T1547".into(), // Boot or logon autostart execution
            ],
            compliance: vec![
                "nis2".into(),
                "rgpd".into(),
                "rgs".into(),
                "anssi-hygiene".into(),
            ],
            expected_assets: vec![
                "server".into(),
                "workstation".into(),
                "website".into(),
                "printer".into(),
            ],
            high_priority_alerts: vec![
                "ransomware".into(),
                "credential-theft".into(),
                "apt".into(),
                "data-exfiltration".into(),
            ],
            low_priority_alerts: vec![],
            sensitivity: 1.3,
        },
        "energy" => ThreatProfile {
            sector: "energy".into(),
            label: "Énergie".into(),
            mitre_techniques: vec![
                "T0831".into(), // Manipulation of control (ICS)
                "T0855".into(), // Unauthorized command message (ICS)
                "T1190".into(), // Exploit public-facing application
                "T1021".into(), // Remote services
                "T1486".into(), // Ransomware
                "T1059".into(), // Command scripting
            ],
            compliance: vec!["nis2".into(), "iec-62443".into(), "anssi-isc".into()],
            expected_assets: vec![
                "server".into(),
                "ot".into(),
                "network".into(),
                "workstation".into(),
            ],
            high_priority_alerts: vec![
                "ot-anomaly".into(),
                "scada-access".into(),
                "ransomware".into(),
                "lateral-movement".into(),
            ],
            low_priority_alerts: vec![],
            sensitivity: 1.4,
        },
        "transport" => ThreatProfile {
            sector: "transport".into(),
            label: "Transport / Logistique".into(),
            mitre_techniques: vec![
                "T1566".into(), // Phishing
                "T1486".into(), // Ransomware
                "T1078".into(), // Valid accounts
                "T1190".into(), // Exploit public-facing
                "T1071".into(), // C2 application layer
            ],
            compliance: vec!["nis2".into(), "rgpd".into()],
            expected_assets: vec![
                "server".into(),
                "workstation".into(),
                "mobile".into(),
                "iot".into(),
            ],
            high_priority_alerts: vec![
                "ransomware".into(),
                "gps-spoofing".into(),
                "fleet-anomaly".into(),
            ],
            low_priority_alerts: vec![],
            sensitivity: 1.2,
        },
        "education" => ThreatProfile {
            sector: "education".into(),
            label: "Éducation".into(),
            mitre_techniques: vec![
                "T1566".into(), // Phishing
                "T1486".into(), // Ransomware
                "T1078".into(), // Valid accounts
                "T1059".into(), // Command scripting
            ],
            compliance: vec!["rgpd".into(), "nis2".into()],
            expected_assets: vec![
                "server".into(),
                "workstation".into(),
                "website".into(),
                "printer".into(),
            ],
            high_priority_alerts: vec!["ransomware".into(), "data-exfiltration".into()],
            low_priority_alerts: vec!["port-scan".into(), "web-scan".into()],
            sensitivity: 1.0,
        },
        "services" | _ => ThreatProfile {
            sector: sector.to_string(),
            label: "Services / Autre".into(),
            mitre_techniques: vec![
                "T1566".into(), // Phishing
                "T1486".into(), // Ransomware
                "T1078".into(), // Valid accounts
                "T1190".into(), // Exploit public-facing
                "T1021".into(), // Remote services
            ],
            compliance: vec!["rgpd".into(), "nis2".into()],
            expected_assets: vec!["server".into(), "workstation".into(), "website".into()],
            high_priority_alerts: vec!["ransomware".into(), "credential-theft".into()],
            low_priority_alerts: vec![],
            sensitivity: 1.0,
        },
    }
}

/// Get all available sector profiles.
pub fn list_profiles() -> Vec<ThreatProfile> {
    [
        "healthcare",
        "finance",
        "industry",
        "retail",
        "government",
        "energy",
        "transport",
        "education",
        "services",
    ]
    .iter()
    .map(|s| get_profile(s))
    .collect()
}

/// Check if a MITRE technique is relevant for the given sector.
pub fn is_technique_relevant(sector: &str, technique_id: &str) -> bool {
    let profile = get_profile(sector);
    profile.mitre_techniques.contains(&technique_id.to_string())
}

/// Check if an alert category is high priority for the given sector.
pub fn is_high_priority(sector: &str, alert_category: &str) -> bool {
    let profile = get_profile(sector);
    profile
        .high_priority_alerts
        .iter()
        .any(|c| alert_category.contains(c))
}

/// Get compliance frameworks for a sector.
pub fn get_compliance(sector: &str) -> Vec<String> {
    get_profile(sector).compliance
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthcare_profile() {
        let p = get_profile("healthcare");
        assert_eq!(p.sector, "healthcare");
        assert!(p.compliance.contains(&"hipaa".to_string()));
        assert!(p.sensitivity > 1.0);
        assert!(p.mitre_techniques.contains(&"T1486".to_string())); // Ransomware
    }

    #[test]
    fn test_industry_has_ics() {
        let p = get_profile("industry");
        assert!(p.mitre_techniques.contains(&"T0831".to_string())); // ICS technique
        assert!(p.compliance.contains(&"iec-62443".to_string()));
    }

    #[test]
    fn test_technique_relevance() {
        assert!(is_technique_relevant("healthcare", "T1486")); // Ransomware
        assert!(is_technique_relevant("industry", "T0831")); // ICS manipulation
        assert!(!is_technique_relevant("retail", "T0831")); // Not ICS
    }

    #[test]
    fn test_high_priority() {
        assert!(is_high_priority("healthcare", "ransomware-detected"));
        assert!(is_high_priority("industry", "plc-access-unauthorized"));
        assert!(!is_high_priority("education", "gps-spoofing"));
    }

    #[test]
    fn test_list_profiles() {
        let profiles = list_profiles();
        assert_eq!(profiles.len(), 9);
    }

    #[test]
    fn test_unknown_sector() {
        let p = get_profile("unknown_sector");
        assert_eq!(p.sensitivity, 1.0);
        assert!(p.compliance.contains(&"rgpd".to_string()));
    }
}
